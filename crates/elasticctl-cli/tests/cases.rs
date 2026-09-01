use assert_cmd::Command;
use serde_json::json;
use std::fs;
use wiremock::matchers::{method, path, query_param};
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

fn case_body(id: &str, status: &str) -> serde_json::Value {
    json!({
        "id": id, "version": "WzEsMV0=", "title": "Suspicious activity",
        "status": status, "severity": "high", "tags": ["t1"],
        "created_at": "2026-01-01T00:00:00.000Z", "totalComment": 1
    })
}

#[tokio::test]
async fn cases_list_renders_compact_rows_and_passes_filters() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .and(query_param("status", "open"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cases": [case_body("c1", "open")], "page": 1, "per_page": 100, "total": 1
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["cases", "list", "--status", "open"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows[0]["id"], json!("c1"));
    assert_eq!(rows[0]["title"], json!("Suspicious activity"));
    assert_eq!(rows[0]["comments"], json!(1));
    assert!(
        rows[0].get("version").is_none(),
        "the compact row hides plumbing fields"
    );
}

#[tokio::test]
async fn cases_get_returns_the_full_case() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("GET"))
        .and(path("/api/cases/c1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c1", "open")))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["cases", "get", "c1"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["id"], json!("c1"));
    assert_eq!(
        doc["version"],
        json!("WzEsMV0="),
        "get returns the full case, version included"
    );
}

/// `cases list --out` must match `alerts list --out` and `search dsl --out`:
/// JSONL by default, and `--limit` respected during export, not just the
/// bounded peek.
#[tokio::test]
async fn cases_list_out_writes_jsonl_by_default_and_honors_limit() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    let out_path = dir.path().join("results.ndjson");

    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cases": [case_body("c1", "open"), case_body("c2", "open")],
            "page": 1, "per_page": 100, "total": 2
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["cases", "list", "--out"])
        .arg(&out_path)
        .args(["--limit", "1"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = fs::read_to_string(&out_path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "{text}");
    assert!(
        lines[0].starts_with('{') && lines[0].ends_with('}'),
        "{text}"
    );
    assert!(lines[0].contains("\"id\":\"c1\""), "{text}");
}
