//! `elasticctl-api` depends on `serde_json` directly (not only through
//! `elasticctl-core`), and the CLI's table/CSV column order depends on
//! `serde_json::Map` preserving insertion order rather than sorting keys.
//!
//! That behaviour comes from the `preserve_order` feature, declared once in
//! the workspace root so every crate gets the same map semantics regardless
//! of which package a given `cargo` invocation selects — `cargo test -p
//! elasticctl-api` must see the same ordering as `cargo test --workspace`.
//! This test fails loudly if the feature ever stops being unified.

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
