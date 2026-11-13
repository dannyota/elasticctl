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
