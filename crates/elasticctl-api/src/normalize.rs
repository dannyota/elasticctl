//! Deterministic rule forms.
//!
//! `canonical` is what `pull` writes: volatile fields removed and keys sorted.
//! `comparable` is what `diff` compares: `canonical` plus server defaults.
//! They remain separate so `pull` does not write defaults the author omitted.

use crate::model::{
    COMMENT_VOLATILE_FIELDS, ExceptionItem, ExceptionList, ITEM_VOLATILE_FIELDS,
    LIST_VOLATILE_FIELDS, Rule, VOLATILE_FIELDS, server_defaults,
};
use serde_json::{Map, Value};

/// Remove the server-owned fields that change on every write.
pub fn strip_volatile(rule: &mut Rule) {
    let map = rule.as_map_mut();
    for field in VOLATILE_FIELDS {
        map.remove(field);
    }
}

/// Remove the volatile pointer from every exception reference.
///
/// Spec 4.5: `id` is required on create and validated by nothing, while export
/// and import both match on `list_id`. Identity is `list_id` plus
/// `namespace_type`; `push` re-resolves `id` against the target stack.
pub fn strip_exception_ids(rule: &mut Rule) {
    if let Some(Value::Array(refs)) = rule.as_map_mut().get_mut("exceptions_list") {
        for r in refs.iter_mut() {
            if let Value::Object(m) = r {
                m.remove("id");
            }
        }
    }
}

/// Add fields the server fills on create without overwriting explicit values.
pub fn fill_defaults(rule: &mut Rule) {
    let map = rule.as_map_mut();
    for (k, v) in server_defaults() {
        map.entry(k).or_insert(v);
    }
}

/// Recursively sort object keys for deterministic output.
///
/// `serde_json::Map` uses `BTreeMap` by default. This workspace enables
/// `preserve_order`, which retains insertion order, so rebuild the map to make
/// the output order explicit.
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
        // Array order is meaningful for tags, index patterns, and threat
        // mappings, so preserve it.
        Value::Array(a) => Value::Array(a.iter().map(sort_value).collect()),
        other => other.clone(),
    }
}

/// The on-disk form.
pub fn canonical(rule: &Rule) -> Rule {
    let mut out = rule.clone();
    strip_volatile(&mut out);
    strip_exception_ids(&mut out);
    let sorted = sort_value(&Value::Object(out.as_map().clone()));
    Rule::from_value(sorted).expect("rule_id survives normalization")
}

/// The comparison form.
pub fn comparable(rule: &Rule) -> Rule {
    let mut out = rule.clone();
    strip_volatile(&mut out);
    strip_exception_ids(&mut out);
    fill_defaults(&mut out);
    let sorted = sort_value(&Value::Object(out.as_map().clone()));
    Rule::from_value(sorted).expect("rule_id survives normalization")
}

/// The on-disk form of an exception-list container.
pub fn canonical_list(list: &ExceptionList) -> ExceptionList {
    let mut out = list.clone();
    for field in LIST_VOLATILE_FIELDS {
        out.as_map_mut().remove(field);
    }
    let sorted = sort_value(&Value::Object(out.as_map().clone()));
    ExceptionList::from_value(sorted).expect("list_id survives normalization")
}

/// The on-disk form of an exception item.
pub fn canonical_item(item: &ExceptionItem) -> ExceptionItem {
    let mut out = item.clone();
    for field in ITEM_VOLATILE_FIELDS {
        out.as_map_mut().remove(field);
    }
    // Comments carry server-minted fields too (spec 7.7). Skip non-object
    // entries the way `exception_refs` skips malformed reference entries.
    if let Some(Value::Array(comments)) = out.as_map_mut().get_mut("comments") {
        for c in comments.iter_mut() {
            if let Value::Object(m) = c {
                for field in COMMENT_VOLATILE_FIELDS {
                    m.remove(field);
                }
            }
        }
    }
    let sorted = sort_value(&Value::Object(out.as_map().clone()));
    ExceptionItem::from_value(sorted).expect("item_id survives normalization")
}

/// Sort rules for stable file output and diff reports. Rules with unreadable
/// `rule_id` values sort last.
pub fn sort_rules(rules: &mut [Rule]) {
    rules.sort_by(|a, b| {
        let (x, y) = (
            a.rule_id().unwrap_or("\u{7f}"),
            b.rule_id().unwrap_or("\u{7f}"),
        );
        x.cmp(y)
    });
}

/// Sort exception-list containers for stable file output and diff reports.
/// Lists with unreadable `list_id` values sort last.
pub fn sort_lists(lists: &mut [ExceptionList]) {
    lists.sort_by(|a, b| {
        let (x, y) = (
            (a.namespace_type(), a.list_id().unwrap_or("\u{7f}")),
            (b.namespace_type(), b.list_id().unwrap_or("\u{7f}")),
        );
        x.cmp(&y)
    });
}

/// Sort exception items for stable file output and diff reports. Items with
/// unreadable identities sort last.
pub fn sort_items(items: &mut [ExceptionItem]) {
    items.sort_by(|a, b| {
        let (x, y) = (
            (
                a.list_id().unwrap_or("\u{7f}"),
                a.item_id().unwrap_or("\u{7f}"),
            ),
            (
                b.list_id().unwrap_or("\u{7f}"),
                b.item_id().unwrap_or("\u{7f}"),
            ),
        );
        x.cmp(&y)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pulled() -> Rule {
        // A rule returned by the API.
        Rule::from_value(json!({
            "rule_id": "abc", "name": "a rule", "type": "query", "risk_score": 21,
            "id": "6b796e42-99fa-4296-8dc1-a693dd455dd0",
            "created_at": "2026-08-12T17:49:01.682Z", "created_by": "key-id",
            "updated_at": "2026-08-12T17:49:01.682Z", "updated_by": "key-id",
            "revision": 0, "version": 1,
            "execution_summary": {"last_execution": {"date": "2026-08-13T03:00:20.804Z"}},
            "max_signals": 100, "to": "now"
        }))
        .unwrap()
    }

    fn hand_authored() -> Rule {
        // A hand-authored rule has no volatile fields or defaults.
        Rule::from_value(json!({
            "rule_id": "abc", "name": "a rule", "type": "query", "risk_score": 21
        }))
        .unwrap()
    }

    #[test]
    fn strip_volatile_removes_all_eight_measured_fields() {
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

    // The state engine relies on this property.
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

    #[test]
    fn array_order_is_preserved_not_sorted() {
        let r = Rule::from_value(json!({
            "rule_id": "x",
            "tags": ["zebra", "alpha", "middle"],
            "index": ["logs-b-*", "logs-a-*"],
            "threat": [{"z": 1}, {"a": 2}]
        }))
        .unwrap();
        let c = canonical(&r);
        let tags = c.as_map()["tags"].as_array().unwrap();
        let tag_strs: Vec<&str> = tags.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(
            tag_strs,
            vec!["zebra", "alpha", "middle"],
            "tag order must be preserved"
        );
        let index = c.as_map()["index"].as_array().unwrap();
        let index_strs: Vec<&str> = index.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(
            index_strs,
            vec!["logs-b-*", "logs-a-*"],
            "index order must be preserved"
        );
        let threat = c.as_map()["threat"].as_array().unwrap();
        let first_key = threat[0].as_object().unwrap().keys().next().unwrap();
        assert_eq!(
            first_key, "z",
            "array element order preserved, keys sorted within"
        );
    }

    #[test]
    fn sort_rules_puts_unreadable_rule_id_last_without_panicking() {
        // Transparent `Deserialize` can create this; `from_value` rejects it.
        let bad: Rule = serde_json::from_value(json!({"rule_id": 123})).unwrap();
        let good_c = Rule::from_value(json!({"rule_id": "c"})).unwrap();
        let good_a = Rule::from_value(json!({"rule_id": "a"})).unwrap();
        let mut rules = vec![good_c, bad, good_a];
        sort_rules(&mut rules);
        assert_eq!(rules[0].rule_id().unwrap(), "a");
        assert_eq!(rules[1].rule_id().unwrap(), "c");
        assert!(rules[2].rule_id().is_err(), "unreadable id sorts last");
    }

    #[test]
    fn canonical_is_idempotent() {
        let r = Rule::from_value(json!({
            "rule_id": "x", "tags": ["z", "a"], "nested": {"z": 1, "a": 2}
        }))
        .unwrap();
        let once = canonical(&r);
        let twice = canonical(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn comparable_is_idempotent() {
        let r = Rule::from_value(json!({
            "rule_id": "x", "name": "test", "type": "query", "risk_score": 10
        }))
        .unwrap();
        let once = comparable(&r);
        let twice = comparable(&once);
        assert_eq!(once, twice);
    }

    /// Spec 4.5. Identity is `list_id`; `id` is a pointer resolved at push time.
    #[test]
    fn canonical_strips_the_exception_pointer_but_keeps_the_reference() {
        let r = Rule::from_value(json!({
            "rule_id": "x",
            "exceptions_list": [{
                "id": "3724d409-4c0f-4630-a1ef-706499730808",
                "list_id": "shared", "type": "detection", "namespace_type": "single"
            }]
        }))
        .unwrap();
        let c = canonical(&r);
        let refs = c.as_map()["exceptions_list"].as_array().unwrap();
        assert!(
            refs[0].get("id").is_none(),
            "the volatile pointer is stripped"
        );
        assert_eq!(refs[0]["list_id"], json!("shared"), "identity survives");
        assert_eq!(refs[0]["namespace_type"], json!("single"));
    }

    /// The bug this closes: a rule promoted between stacks carries a pointer to an
    /// object that does not exist on the target.
    #[test]
    fn two_stacks_ids_for_one_list_do_not_read_as_drift() {
        let mk = |id: &str| {
            Rule::from_value(json!({
                "rule_id": "x",
                "exceptions_list": [{"id": id, "list_id": "shared",
                                     "type": "detection", "namespace_type": "single"}]
            }))
            .unwrap()
        };
        assert_eq!(
            comparable(&mk("id-on-dev")),
            comparable(&mk("id-on-prod")),
            "the same list on two stacks must not read as drift"
        );
    }

    #[test]
    fn strip_exception_ids_strips_every_reference_not_just_the_first() {
        let c = canonical(
            &Rule::from_value(json!({
                "rule_id": "x",
                "exceptions_list": [
                    {"id": "id-1", "list_id": "one"},
                    {"id": "id-2", "list_id": "two"}
                ]
            }))
            .unwrap(),
        );
        let refs = c.as_map()["exceptions_list"].as_array().unwrap();
        assert_eq!(refs.len(), 2);
        for entry in refs {
            assert!(
                entry.get("id").is_none(),
                "every reference loses its pointer"
            );
        }
        assert_eq!(refs[0]["list_id"], json!("one"));
        assert_eq!(refs[1]["list_id"], json!("two"));
    }

    #[test]
    fn a_rule_with_no_exceptions_is_untouched() {
        let r = Rule::from_value(json!({"rule_id": "x", "name": "X"})).unwrap();
        assert_eq!(canonical(&r).as_map().get("exceptions_list"), None);
    }

    #[test]
    fn strip_exception_ids_is_idempotent() {
        let mut r = Rule::from_value(json!({
            "rule_id": "x",
            "exceptions_list": [{"id": "a", "list_id": "l"}]
        }))
        .unwrap();
        strip_exception_ids(&mut r);
        let once = r.clone();
        strip_exception_ids(&mut r);
        assert_eq!(once, r);
    }

    #[test]
    fn strip_exception_ids_skips_non_objects_and_absent_ids() {
        let mut r = Rule::from_value(json!({
            "rule_id": "x",
            "exceptions_list": ["not an object", {"list_id": "already stripped"}]
        }))
        .unwrap();
        strip_exception_ids(&mut r); // must not panic
        let refs = r.as_map()["exceptions_list"].as_array().unwrap();
        assert_eq!(
            refs[0],
            json!("not an object"),
            "non-object entries are left alone"
        );
        assert_eq!(
            refs[1],
            json!({"list_id": "already stripped"}),
            "an absent id is a no-op"
        );
    }

    #[test]
    fn canonical_list_strips_every_measured_volatile_field() {
        let l = ExceptionList::from_value(json!({
            "list_id": "l", "name": "L", "id": "server-id", "_version": "WzUsMV0=",
            "tie_breaker_id": "tb", "version": 3,
            "created_at": "2026-08-13T23:38:39.519Z", "created_by": "452295856",
            "updated_at": "2026-08-13T23:38:39.519Z", "updated_by": "452295856",
            "meta": {"zeta": 1, "alpha": 2},
            "os_types": ["linux", "windows"]
        }))
        .unwrap();
        let c = canonical_list(&l);
        for f in LIST_VOLATILE_FIELDS {
            assert!(!c.as_map().contains_key(f), "{f} should have been stripped");
        }
        assert_eq!(c.list_id().unwrap(), "l", "identity must survive");
        let nested = c.as_map()["meta"].as_object().unwrap();
        let keys: Vec<&String> = nested.keys().collect();
        assert_eq!(keys, vec!["alpha", "zeta"], "nested keys are sorted");
        let os = c.as_map()["os_types"].as_array().unwrap();
        let os_strs: Vec<&str> = os.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(
            os_strs,
            vec!["linux", "windows"],
            "array order is preserved"
        );
    }

    #[test]
    fn canonical_item_strips_every_measured_volatile_field() {
        let i = ExceptionItem::from_value(json!({
            "item_id": "i", "list_id": "l", "name": "I", "id": "server-id",
            "_version": "WzUsMV0=", "tie_breaker_id": "tb",
            "created_at": "2026-08-13T23:38:39.519Z", "created_by": "452295856",
            "updated_at": "2026-08-13T23:38:39.519Z", "updated_by": "452295856",
            "meta": {"zeta": 1, "alpha": 2},
            "entries": [{"z": 1}, {"a": 2}]
        }))
        .unwrap();
        let c = canonical_item(&i);
        for f in ITEM_VOLATILE_FIELDS {
            assert!(!c.as_map().contains_key(f), "{f} should have been stripped");
        }
        assert_eq!(c.item_id().unwrap(), "i", "identity must survive");
        let nested = c.as_map()["meta"].as_object().unwrap();
        let keys: Vec<&String> = nested.keys().collect();
        assert_eq!(keys, vec!["alpha", "zeta"], "nested keys are sorted");
        let entries = c.as_map()["entries"].as_array().unwrap();
        let first_key = entries[0].as_object().unwrap().keys().next().unwrap();
        assert_eq!(
            first_key, "z",
            "array element order preserved, keys sorted within"
        );
    }

    #[test]
    fn canonical_item_strips_volatile_fields_inside_comments() {
        let i = ExceptionItem::from_value(json!({
            "item_id": "i", "list_id": "l",
            "comments": [{
                "id": "0b025f61-b0b9-4658-83cf-cbb581ad2358",
                "comment": "first note",
                "created_at": "2026-08-14T04:49:54.101Z",
                "created_by": "452295856"
            }]
        }))
        .unwrap();
        let c = canonical_item(&i);
        let comments = c.as_map()["comments"].as_array().unwrap();
        let first = comments[0].as_object().unwrap();
        for f in COMMENT_VOLATILE_FIELDS {
            assert!(!first.contains_key(f), "{f} should have been stripped");
        }
        assert_eq!(
            comments[0]["comment"],
            json!("first note"),
            "the author's text survives"
        );
    }

    #[test]
    fn sort_lists_orders_by_namespace_then_list_id() {
        let mk = |ns: &str, id: &str| {
            ExceptionList::from_value(json!({"list_id": id, "namespace_type": ns})).unwrap()
        };
        let mut lists = vec![mk("agnostic", "b"), mk("single", "a"), mk("agnostic", "a")];
        sort_lists(&mut lists);
        let order: Vec<(&str, &str)> = lists
            .iter()
            .map(|l| (l.namespace_type(), l.list_id().unwrap()))
            .collect();
        assert_eq!(
            order,
            vec![("agnostic", "a"), ("agnostic", "b"), ("single", "a")]
        );
    }

    #[test]
    fn sort_items_orders_by_list_then_item_id() {
        let mk = |list: &str, item: &str| {
            ExceptionItem::from_value(json!({"list_id": list, "item_id": item})).unwrap()
        };
        let mut items = vec![mk("b", "2"), mk("a", "2"), mk("b", "1")];
        sort_items(&mut items);
        let order: Vec<(&str, &str)> = items
            .iter()
            .map(|i| (i.list_id().unwrap(), i.item_id().unwrap()))
            .collect();
        assert_eq!(order, vec![("a", "2"), ("b", "1"), ("b", "2")]);
    }

    #[test]
    fn sort_lists_puts_unreadable_list_id_last_without_panicking() {
        // Transparent `Deserialize` can create this; `from_value` rejects it.
        let bad: ExceptionList =
            serde_json::from_value(json!({"namespace_type": "single"})).unwrap();
        let good_c =
            ExceptionList::from_value(json!({"list_id": "c", "namespace_type": "single"})).unwrap();
        let good_a =
            ExceptionList::from_value(json!({"list_id": "a", "namespace_type": "single"})).unwrap();
        let mut lists = vec![good_c, bad, good_a];
        sort_lists(&mut lists);
        assert_eq!(lists[0].list_id().unwrap(), "a");
        assert_eq!(lists[1].list_id().unwrap(), "c");
        assert!(lists[2].list_id().is_err(), "unreadable list_id sorts last");
    }

    #[test]
    fn sort_items_puts_unreadable_list_id_last_without_panicking() {
        // Transparent `Deserialize` can create this; `from_value` rejects it.
        let bad: ExceptionItem = serde_json::from_value(json!({"item_id": "i"})).unwrap();
        let good_c = ExceptionItem::from_value(json!({"list_id": "c", "item_id": "i"})).unwrap();
        let good_a = ExceptionItem::from_value(json!({"list_id": "a", "item_id": "i"})).unwrap();
        let mut items = vec![good_c, bad, good_a];
        sort_items(&mut items);
        assert_eq!(items[0].list_id().unwrap(), "a");
        assert_eq!(items[1].list_id().unwrap(), "c");
        assert!(items[2].list_id().is_err(), "unreadable list_id sorts last");
    }
}
