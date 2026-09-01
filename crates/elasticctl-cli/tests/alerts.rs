use assert_cmd::Command;
use serde_json::json;
use std::fs;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

fn write_config(dir: &std::path::Path, uri: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    fs::write(
        &path,
        format!(
            r#"
current = "default"
[profiles.default]
kibana_url = "{uri}"
es_url = "{uri}"
api_key = "essu_test"
space = "default"
verify = true
timeout_secs = 5
"#
        ),
    )
    .unwrap();
    path
}

#[tokio::test]
async fn alerts_list_renders_source_rows_and_meta_on_request() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [
                {"_id": "a1", "_source": {
                    "kibana.alert.rule.name": "Alpha",
                    "kibana.alert.severity": "high",
                    "kibana.alert.workflow_status": "open"}}
            ]}
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["alerts", "list"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows[0]["kibana.alert.rule.name"], json!("Alpha"));
    assert!(rows[0].get("_id").is_none(), "meta is opt-in");

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["alerts", "list", "--with-meta"])
        .output()
        .unwrap();
    let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows[0]["_id"], json!("a1"));
}

#[tokio::test]
async fn alerts_get_merges_the_id_into_the_document() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [
                {"_id": "a1", "_source": {"kibana.alert.rule.name": "Alpha"}}
            ]}
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["alerts", "get", "a1"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["_id"], json!("a1"));
    assert_eq!(doc["kibana.alert.rule.name"], json!("Alpha"));
}
