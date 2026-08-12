//! Deterministic rule forms.
//!
//! `canonical` is what `pull` writes: volatile fields removed, keys ordered,
//! nothing invented. `comparable` is what `diff` compares: `canonical` plus
//! server defaults filled in. They stay separate because writing filled
//! defaults to disk would bloat every file with values the author never chose.

use crate::model::{Rule, VOLATILE_FIELDS, server_defaults};
use serde_json::{Map, Value};

/// Remove the server-owned fields that change on every write.
pub fn strip_volatile(rule: &mut Rule) {
    let map = rule.as_map_mut();
    for field in VOLATILE_FIELDS {
        map.remove(field);
    }
}

/// Add the fields the server would fill on create, without touching anything
/// the author set explicitly.
pub fn fill_defaults(rule: &mut Rule) {
    let map = rule.as_map_mut();
    for (k, v) in server_defaults() {
        map.entry(k).or_insert(v);
    }
}

/// `serde_json::Map` preserves insertion order under the `preserve_order`
/// feature and sorts otherwise. Rebuild explicitly so ordering does not depend
/// on which features a downstream crate happens to enable.
fn sort_value(value: &Value) -> Value {
    match value {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(k.clone(), sort_value(&m[k]));
            }
            Value::Object(out)
        }
        // Array order is meaningful in a rule (tags, index patterns, threat
        // mappings), so it is preserved rather than sorted.
        Value::Array(a) => Value::Array(a.iter().map(sort_value).collect()),
        other => other.clone(),
    }
}

/// The on-disk form.
pub fn canonical(rule: &Rule) -> Rule {
    let mut out = rule.clone();
    strip_volatile(&mut out);
    let sorted = sort_value(&Value::Object(out.as_map().clone()));
    Rule::from_value(sorted).expect("rule_id survives normalization")
}

/// The comparison form.
pub fn comparable(rule: &Rule) -> Rule {
    let mut out = rule.clone();
    strip_volatile(&mut out);
    fill_defaults(&mut out);
    let sorted = sort_value(&Value::Object(out.as_map().clone()));
    Rule::from_value(sorted).expect("rule_id survives normalization")
}

/// Stable ordering for file output and diff reporting. Rules without a
/// readable `rule_id` sort last rather than panicking.
pub fn sort_rules(rules: &mut [Rule]) {
    rules.sort_by(|a, b| {
        let (x, y) = (
            a.rule_id().unwrap_or("\u{7f}"),
            b.rule_id().unwrap_or("\u{7f}"),
        );
        x.cmp(y)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pulled() -> Rule {
        // Shape of a rule as it comes back from the API.
        Rule::from_value(json!({
            "rule_id": "abc", "name": "a rule", "type": "query", "risk_score": 21,
            "id": "6b796e42-99fa-4296-8dc1-a693dd455dd0",
            "created_at": "2026-08-12T17:49:01.682Z", "created_by": "key-id",
            "updated_at": "2026-08-12T17:49:01.682Z", "updated_by": "key-id",
            "revision": 0, "version": 1,
            "max_signals": 100, "to": "now"
        }))
        .unwrap()
    }

    fn hand_authored() -> Rule {
        // What an engineer actually writes: no volatile fields, no defaults.
        Rule::from_value(json!({
            "rule_id": "abc", "name": "a rule", "type": "query", "risk_score": 21
        }))
        .unwrap()
    }

    #[test]
    fn strip_volatile_removes_all_seven_measured_fields() {
        let mut r = pulled();
        strip_volatile(&mut r);
        for f in VOLATILE_FIELDS {
            assert!(!r.as_map().contains_key(f), "{f} should have been stripped");
        }
        assert_eq!(r.rule_id().unwrap(), "abc", "identity must survive");
        assert_eq!(
            r.as_map()["max_signals"],
            json!(100),
            "non-volatile fields stay"
        );
    }

    #[test]
    fn strip_volatile_is_idempotent() {
        let mut once = pulled();
        strip_volatile(&mut once);
        let mut twice = once.clone();
        strip_volatile(&mut twice);
        assert_eq!(once, twice);
    }

    #[test]
    fn fill_defaults_adds_only_absent_fields() {
        let mut r = hand_authored();
        fill_defaults(&mut r);
        assert_eq!(r.as_map()["max_signals"], json!(100));
        assert_eq!(r.as_map()["to"], json!("now"));
        assert_eq!(
            r.as_map()["risk_score"],
            json!(21),
            "an author's value is never replaced"
        );
    }

    #[test]
    fn fill_defaults_never_overwrites_an_explicit_value() {
        let mut r = Rule::from_value(json!({"rule_id": "abc", "max_signals": 5000})).unwrap();
        fill_defaults(&mut r);
        assert_eq!(r.as_map()["max_signals"], json!(5000));
    }

    #[test]
    fn canonical_sorts_keys_so_output_is_deterministic() {
        let a = Rule::from_value(json!({"rule_id": "x", "zeta": 1, "alpha": 2})).unwrap();
        let b = Rule::from_value(json!({"rule_id": "x", "alpha": 2, "zeta": 1})).unwrap();
        let (ca, cb) = (canonical(&a), canonical(&b));
        assert_eq!(ca, cb, "key order must not affect the canonical form");
        let keys: Vec<&String> = ca.as_map().keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn canonical_sorts_nested_object_keys_too() {
        let r = Rule::from_value(json!({
            "rule_id": "x", "rule_source": {"zeta": 1, "alpha": 2}
        }))
        .unwrap();
        let c = canonical(&r);
        let nested = c.as_map()["rule_source"].as_object().unwrap();
        let keys: Vec<&String> = nested.keys().collect();
        assert_eq!(keys, vec!["alpha", "zeta"]);
    }

    #[test]
    fn canonical_does_not_invent_defaults() {
        let c = canonical(&hand_authored());
        assert!(
            !c.as_map().contains_key("max_signals"),
            "pull must not bloat files"
        );
    }

    // The property the whole state engine rests on.
    #[test]
    fn a_pulled_rule_and_its_hand_authored_equivalent_compare_equal() {
        assert_eq!(
            comparable(&pulled()),
            comparable(&hand_authored()),
            "a sparse local file must not read as drift against its remote counterpart"
        );
    }

    #[test]
    fn a_real_difference_still_compares_unequal() {
        let mut changed = hand_authored();
        changed.as_map_mut().insert("risk_score".into(), json!(99));
        assert_ne!(comparable(&pulled()), comparable(&changed));
    }

    #[test]
    fn sort_rules_orders_by_rule_id() {
        let mk = |id: &str| Rule::from_value(json!({"rule_id": id})).unwrap();
        let mut rules = vec![mk("c"), mk("a"), mk("b")];
        sort_rules(&mut rules);
        let ids: Vec<&str> = rules.iter().map(|r| r.rule_id().unwrap()).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }
}
