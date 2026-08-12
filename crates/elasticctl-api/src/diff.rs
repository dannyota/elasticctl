//! Field-level drift between a desired local state and a live remote state.
//!
//! NDJSON on disk is not readable by eye, so this is the human view of a
//! change; `git diff` stays the fidelity record.

use crate::model::Rule;
use crate::normalize::comparable;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FieldChange {
    pub field: String,
    pub before: Value,
    pub after: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum Change {
    Added {
        rule_id: String,
        name: String,
    },
    Modified {
        rule_id: String,
        name: String,
        fields: Vec<FieldChange>,
    },
    Unchanged {
        rule_id: String,
    },
    /// Present remotely, absent locally. Reported so the operator can see it,
    /// never acted on: `push` does not delete.
    RemoteOnly {
        rule_id: String,
        name: String,
    },
}

impl Change {
    pub fn rule_id(&self) -> &str {
        match self {
            Change::Added { rule_id, .. }
            | Change::Modified { rule_id, .. }
            | Change::Unchanged { rule_id }
            | Change::RemoteOnly { rule_id, .. } => rule_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Drift {
    pub changes: Vec<Change>,
}

/// Compare two normalized rules field by field. A field absent on one side
/// reads as `null`, so an addition and a removal are both visible.
fn field_changes(before: &Rule, after: &Rule) -> Vec<FieldChange> {
    let (b, a) = (before.as_map(), after.as_map());
    let mut keys: Vec<&String> = b.keys().chain(a.keys()).collect();
    keys.sort();
    keys.dedup();

    keys.into_iter()
        .filter_map(|k| {
            let bv = b.get(k).cloned().unwrap_or(Value::Null);
            let av = a.get(k).cloned().unwrap_or(Value::Null);
            (bv != av).then(|| FieldChange {
                field: k.clone(),
                before: bv,
                after: av,
            })
        })
        .collect()
}

impl Drift {
    pub fn compute(local: &[Rule], remote: &[Rule]) -> Drift {
        // BTreeMap keeps the output ordered by rule_id, so a report generated
        // twice from the same inputs is byte-identical.
        let index = |rules: &[Rule]| -> BTreeMap<String, Rule> {
            rules
                .iter()
                .filter_map(|r| r.rule_id().ok().map(|id| (id.to_string(), comparable(r))))
                .collect()
        };
        let (local, remote) = (index(local), index(remote));

        let mut changes = Vec::new();
        let mut ids: Vec<&String> = local.keys().chain(remote.keys()).collect();
        ids.sort();
        ids.dedup();

        for id in ids {
            match (local.get(id), remote.get(id)) {
                (Some(l), None) => changes.push(Change::Added {
                    rule_id: id.clone(),
                    name: l.name().to_string(),
                }),
                (None, Some(r)) => changes.push(Change::RemoteOnly {
                    rule_id: id.clone(),
                    name: r.name().to_string(),
                }),
                (Some(l), Some(r)) => {
                    let fields = field_changes(r, l);
                    if fields.is_empty() {
                        changes.push(Change::Unchanged {
                            rule_id: id.clone(),
                        });
                    } else {
                        changes.push(Change::Modified {
                            rule_id: id.clone(),
                            name: l.name().to_string(),
                            fields,
                        });
                    }
                }
                (None, None) => unreachable!("an id came from one of the two maps"),
            }
        }

        Drift { changes }
    }

    /// The changes `push` will act on. `RemoteOnly` is deliberately excluded:
    /// local absence is not a delete instruction.
    pub fn actionable(&self) -> Vec<&Change> {
        self.changes
            .iter()
            .filter(|c| matches!(c, Change::Added { .. } | Change::Modified { .. }))
            .collect()
    }

    /// Clean means nothing differs at all, including remote-only rules — those
    /// are drift even though they will not be acted on.
    pub fn is_clean(&self) -> bool {
        self.changes
            .iter()
            .all(|c| matches!(c, Change::Unchanged { .. }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(id: &str, name: &str, risk: i64) -> Rule {
        Rule::from_value(json!({
            "rule_id": id, "name": name, "type": "query", "risk_score": risk,
            "severity": "low"
        }))
        .unwrap()
    }

    #[test]
    fn identical_sets_are_clean() {
        let a = vec![rule("x", "X", 21)];
        let d = Drift::compute(&a, &a);
        assert!(d.is_clean());
        assert!(d.actionable().is_empty());
    }

    #[test]
    fn a_local_only_rule_is_added() {
        let d = Drift::compute(&[rule("x", "X", 21)], &[]);
        assert!(
            matches!(&d.changes[0], Change::Added { rule_id, name } if rule_id == "x" && name == "X")
        );
        assert_eq!(d.actionable().len(), 1);
    }

    #[test]
    fn a_remote_only_rule_is_reported_but_not_actionable() {
        let d = Drift::compute(&[], &[rule("x", "X", 21)]);
        assert!(matches!(&d.changes[0], Change::RemoteOnly { rule_id, .. } if rule_id == "x"));
        assert!(
            d.actionable().is_empty(),
            "push must never delete a remote rule"
        );
        assert!(
            !d.is_clean(),
            "drift exists even though nothing will be applied"
        );
    }

    #[test]
    fn a_changed_field_is_reported_with_before_and_after() {
        let d = Drift::compute(&[rule("x", "X", 99)], &[rule("x", "X", 21)]);
        let Change::Modified { fields, .. } = &d.changes[0] else {
            panic!("expected Modified, got {:?}", d.changes[0]);
        };
        assert_eq!(fields.len(), 1, "only the field that changed is reported");
        assert_eq!(fields[0].field, "risk_score");
        assert_eq!(fields[0].before, json!(21));
        assert_eq!(fields[0].after, json!(99));
    }

    #[test]
    fn multiple_changed_fields_are_reported_in_key_order() {
        let d = Drift::compute(&[rule("x", "Renamed", 99)], &[rule("x", "X", 21)]);
        let Change::Modified { fields, .. } = &d.changes[0] else {
            panic!("expected Modified")
        };
        let names: Vec<&str> = fields.iter().map(|f| f.field.as_str()).collect();
        assert_eq!(names, vec!["name", "risk_score"]);
    }

    #[test]
    fn a_field_added_locally_shows_null_as_its_before_value() {
        let mut local = rule("x", "X", 21);
        local.as_map_mut().insert("note".into(), json!("hello"));
        let d = Drift::compute(&[local], &[rule("x", "X", 21)]);
        let Change::Modified { fields, .. } = &d.changes[0] else {
            panic!("expected Modified")
        };
        assert_eq!(fields[0].field, "note");
        assert_eq!(fields[0].before, json!(null));
        assert_eq!(fields[0].after, json!("hello"));
    }

    // The property Task 7 exists to guarantee, asserted end to end.
    #[test]
    fn volatile_fields_never_produce_drift() {
        let mut remote = rule("x", "X", 21);
        remote
            .as_map_mut()
            .insert("id".into(), json!("server-uuid"));
        remote
            .as_map_mut()
            .insert("updated_at".into(), json!("2026-08-12T00:00:00Z"));
        remote.as_map_mut().insert("version".into(), json!(7));
        assert!(Drift::compute(&[rule("x", "X", 21)], &[remote]).is_clean());
    }

    #[test]
    fn omitted_server_defaults_never_produce_drift() {
        let mut remote = rule("x", "X", 21);
        remote.as_map_mut().insert("max_signals".into(), json!(100));
        remote.as_map_mut().insert("to".into(), json!("now"));
        assert!(Drift::compute(&[rule("x", "X", 21)], &[remote]).is_clean());
    }

    #[test]
    fn changes_are_ordered_by_rule_id_so_reports_are_stable() {
        let local = vec![rule("c", "C", 1), rule("a", "A", 1), rule("b", "B", 1)];
        let d = Drift::compute(&local, &[]);
        let ids: Vec<&str> = d.changes.iter().map(Change::rule_id).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }
}
