//! `elasticctl-api` depends on `serde_json` directly, and CLI table and CSV
//! column order requires `serde_json::Map` insertion order.
//!
//! The workspace root declares `preserve_order`, so every package has the same
//! map semantics. This test fails if the feature stops being unified.

#[test]
fn map_iterates_in_insertion_order_not_alphabetical() {
    let mut map = serde_json::Map::new();
    map.insert("zeta".to_string(), serde_json::json!(1));
    map.insert("alpha".to_string(), serde_json::json!(2));

    let keys: Vec<&str> = map.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        vec!["zeta", "alpha"],
        "expected insertion order, got {keys:?}"
    );
}
