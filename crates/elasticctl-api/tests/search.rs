use elasticctl_api::search::esql;
use serde_json::json;

#[test]
fn decodes_a_sync_esql_response() {
    let body = json!({
        "took": 39,
        "is_partial": false,
        "columns": [
            {"name": "seq", "type": "long"},
            {"name": "message", "type": "text"}
        ],
        "values": [[1, "hello 1"], [2, "hello 2"]]
    });
    let decoded = esql::decode(&body).expect("decode");
    assert_eq!(decoded.columns.len(), 2);
    assert_eq!(decoded.columns[0].name, "seq");
    assert_eq!(decoded.columns[0].r#type, "long");
    assert_eq!(decoded.values.len(), 2);
    assert_eq!(decoded.values[0][0], json!(1));
    assert!(!decoded.is_partial);
}

#[test]
fn rejects_a_response_without_columns() {
    let body = json!({"values": [[1]]});
    let err = esql::decode(&body).expect_err("must fail");
    assert!(
        err.to_envelope()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("decoding esql response")
    );
}
