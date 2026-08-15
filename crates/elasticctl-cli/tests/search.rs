use assert_cmd::Command;
use serde_json::json;
use std::fs;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

fn write_config(dir: &std::path::Path, es_url: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    fs::write(
        &path,
        format!(
            r#"
current = "default"
[profiles.default]
kibana_url = "{es_url}"
es_url = "{es_url}"
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
async fn search_esql_renders_columns_as_a_table() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/_query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "columns": [{"name": "seq", "type": "long"}],
            "values": [[1], [2]],
            "is_partial": false
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["search", "esql", "FROM x | LIMIT 2"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("seq"));
    assert!(stdout.contains("1"));
}
