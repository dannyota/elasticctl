use assert_cmd::Command;
use serde_json::json;
use std::fs;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config_for(dir: &std::path::Path, uri: &str) -> std::path::PathBuf {
    let p = dir.join("config.toml");
    fs::write(&p, format!(
        "current = \"default\"\n\n[profiles.default]\nkibana_url = \"{uri}\"\napi_key = \"essu_t\"\nspace = \"default\"\nverify = true\ntimeout_secs = 5\n"
    )).unwrap();
    p
}

async fn previewing_server(logs: serde_json::Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/preview"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"previewId": "pv-1", "logs": logs})),
        )
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn preview_of_a_local_file_reports_the_preview_id() {
    let server = previewing_server(json!([{"errors": [], "warnings": []}])).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("r.yaml");
    fs::write(
        &src,
        "- rule_id: abc\n  name: A\n  type: query\n  query: '*:*'\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "preview", "--json", "--config"])
        .arg(&cfg)
        .arg(src.to_str().unwrap())
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["preview_id"], "pv-1");
    assert_eq!(v["errors"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn warnings_from_every_log_entry_are_collected() {
    let server = previewing_server(json!([
        {"errors": [], "warnings": ["Unable to find matching indices for logs-*"]},
        {"errors": [], "warnings": ["second warning"]}
    ]))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("r.yaml");
    fs::write(
        &src,
        "- rule_id: abc\n  name: A\n  type: query\n  query: '*:*'\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "preview", "--json", "--config"])
        .arg(&cfg)
        .arg(src.to_str().unwrap())
        .output()
        .unwrap();

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let warnings = v["warnings"].as_array().unwrap();
    assert_eq!(
        warnings.len(),
        2,
        "warnings from every invocation must surface"
    );
}

#[tokio::test]
async fn errors_are_reported_without_failing_the_command() {
    // A rule that cannot run is a finding, not a CLI failure.
    let server = previewing_server(json!([{"errors": ["bad query syntax"], "warnings": []}])).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("r.yaml");
    fs::write(
        &src,
        "- rule_id: abc\n  name: A\n  type: query\n  query: '*:*'\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "preview", "--json", "--config"])
        .arg(&cfg)
        .arg(src.to_str().unwrap())
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "a rule error is a result, not a CLI failure"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["errors"][0], "bad query syntax");
}

#[tokio::test]
async fn preview_never_prints_a_dry_run_banner() {
    // It writes no alerts, so it must not be guarded.
    let server = previewing_server(json!([{"errors": [], "warnings": []}])).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("r.yaml");
    fs::write(
        &src,
        "- rule_id: abc\n  name: A\n  type: query\n  query: '*:*'\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "preview", "--config"])
        .arg(&cfg)
        .arg(src.to_str().unwrap())
        .output()
        .unwrap();

    assert!(!String::from_utf8_lossy(&out.stderr).contains("DRY RUN"));
}
