//! Field-level drift between desired local and live remote states.
//!
//! This report makes NDJSON changes readable. `git diff` remains the fidelity
//! record.

use crate::model::Rule;
use crate::normalize::comparable;
use elasticctl_core::{Error, ErrorKind, Result};
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
    /// Present remotely but absent locally. Reported but not acted on because
    /// `push` does not delete rules.
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

/// Compare normalized rules field by field. An absent field is `null`, so
/// additions and removals are visible.
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
    pub fn compute(local: &[Rule], remote: &[Rule]) -> Result<Drift> {
        // `BTreeMap` orders by `rule_id`, making repeated reports byte-identical.
        let index = |rules: &[Rule], side: &str| -> Result<BTreeMap<String, Rule>> {
            let mut map = BTreeMap::new();
            for (idx, r) in rules.iter().enumerate() {
                let id = r.rule_id().map_err(|_| {
                    Error::new(
                        ErrorKind::Error,
                        format!(
                            "{} rule at position {} has an unreadable rule_id",
                            side, idx
                        ),
                    )
                })?;
                if map.insert(id.to_string(), comparable(r)).is_some() {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        format!(
                            "{} has two rules with rule_id \"{}\"; rule_id must be unique",
                            side, id
                        ),
                    ));
                }
            }
            Ok(map)
        };
        let (local, remote) = (index(local, "local")?, index(remote, "remote")?);

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

        Ok(Drift { changes })
    }

    /// Changes `push` will act on. `RemoteOnly` is excluded because local
    /// absence does not instruct a delete.
    pub fn actionable(&self) -> Vec<&Change> {
        self.changes
            .iter()
            .filter(|c| matches!(c, Change::Added { .. } | Change::Modified { .. }))
            .collect()
    }

    /// No differences, including remote-only rules. They are drift even though
    /// `push` does not act on them.
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
        let d = Drift::compute(&a, &a).unwrap();
        assert!(d.is_clean());
        assert!(d.actionable().is_empty());
    }

    #[test]
    fn a_local_only_rule_is_added() {
        let d = Drift::compute(&[rule("x", "X", 21)], &[]).unwrap();
        assert!(
            matches!(&d.changes[0], Change::Added { rule_id, name } if rule_id == "x" && name == "X")
        );
        assert_eq!(d.actionable().len(), 1);
    }

    #[test]
    fn a_remote_only_rule_is_reported_but_not_actionable() {
        let d = Drift::compute(&[], &[rule("x", "X", 21)]).unwrap();
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
        let d = Drift::compute(&[rule("x", "X", 99)], &[rule("x", "X", 21)]).unwrap();
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
        let d = Drift::compute(&[rule("x", "Renamed", 99)], &[rule("x", "X", 21)]).unwrap();
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
        let d = Drift::compute(&[local], &[rule("x", "X", 21)]).unwrap();
        let Change::Modified { fields, .. } = &d.changes[0] else {
            panic!("expected Modified")
        };
        assert_eq!(fields[0].field, "note");
        assert_eq!(fields[0].before, json!(null));
        assert_eq!(fields[0].after, json!("hello"));
    }

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
        assert!(
            Drift::compute(&[rule("x", "X", 21)], &[remote])
                .unwrap()
                .is_clean()
        );
    }

    #[test]
    fn omitted_server_defaults_never_produce_drift() {
        let mut remote = rule("x", "X", 21);
        remote.as_map_mut().insert("max_signals".into(), json!(100));
        remote.as_map_mut().insert("to".into(), json!("now"));
        assert!(
            Drift::compute(&[rule("x", "X", 21)], &[remote])
                .unwrap()
                .is_clean()
        );
    }

    #[test]
    fn changes_are_ordered_by_rule_id_so_reports_are_stable() {
        let local = vec![rule("c", "C", 1), rule("a", "A", 1), rule("b", "B", 1)];
        let d = Drift::compute(&local, &[]).unwrap();
        let ids: Vec<&str> = d.changes.iter().map(Change::rule_id).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn a_local_rule_with_non_string_rule_id_produces_an_error() {
        let err = Drift::compute(
            // `from_value` rejects this, but transparent `Deserialize` does
            // not. This reproduces the case `Drift::compute` must handle.
            &[serde_json::from_value::<Rule>(json!({
                "rule_id": 123, "name": "X", "type": "query", "risk_score": 21,
                "severity": "low"
            }))
            .unwrap()],
            &[],
        );
        assert!(err.is_err());
        let err = err.unwrap_err();
        assert_eq!(err.kind, ErrorKind::Error);
        assert!(err.message.contains("local"));
        assert!(err.message.contains("position"));
        assert!(err.message.contains("unreadable rule_id"));
    }

    #[test]
    fn a_remote_rule_with_non_string_rule_id_produces_an_error() {
        let err = Drift::compute(
            &[],
            // `from_value` rejects this, but transparent `Deserialize` does
            // not. This reproduces the case `Drift::compute` must handle.
            &[serde_json::from_value::<Rule>(json!({
                "rule_id": 123, "name": "X", "type": "query", "risk_score": 21,
                "severity": "low"
            }))
            .unwrap()],
        );
        assert!(err.is_err());
        let err = err.unwrap_err();
        assert_eq!(err.kind, ErrorKind::Error);
        assert!(err.message.contains("remote"));
        assert!(err.message.contains("position"));
        assert!(err.message.contains("unreadable rule_id"));
    }

    #[test]
    fn duplicate_local_rule_ids_produce_a_conflict_error() {
        let err = Drift::compute(&[rule("x", "X", 21), rule("x", "X", 99)], &[]);
        assert!(err.is_err());
        let err = err.unwrap_err();
        assert_eq!(err.kind, ErrorKind::Conflict);
        assert!(err.message.contains("local"));
        assert!(err.message.contains("\"x\""));
        assert!(err.message.contains("rule_id must be unique"));
    }

    #[test]
    fn duplicate_remote_rule_ids_produce_a_conflict_error() {
        let err = Drift::compute(&[], &[rule("x", "X", 21), rule("x", "X", 99)]);
        assert!(err.is_err());
        let err = err.unwrap_err();
        assert_eq!(err.kind, ErrorKind::Conflict);
        assert!(err.message.contains("remote"));
        assert!(err.message.contains("\"x\""));
        assert!(err.message.contains("rule_id must be unique"));
    }
}
