use assert_cmd::Command;
use std::fs;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A known key lets the test verify that stderr never exposes it.
const API_KEY: &str = "essu_debug_secret_key_12345";

fn config_for(dir: &std::path::Path, uri: &str) -> std::path::PathBuf {
    let p = dir.join("config.toml");
    fs::write(
        &p,
        format!(
            "current = \"default\"\n\n[profiles.default]\nkibana_url = \"{uri}\"\napi_key = \"{API_KEY}\"\nspace = \"default\"\nverify = true\ntimeout_secs = 5\n"
        ),
    )
    .unwrap();
    p
}

async fn exporting_server() -> MockServer {
    let server = MockServer::start().await;
    let body = concat!(
        r#"{"rule_id":"a","name":"Alpha"}"#,
        "\n",
        r#"{"exported_count":1,"exported_rules_count":1,"missing_rules_count":0}"#,
        "\n"
    );
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_export"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn debug_logs_the_request_line_and_redacts_the_api_key() {
    let server = exporting_server().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let out_file = dir.path().join("rules.ndjson");

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "export", "--debug", "--config"])
        .arg(&cfg)
        .arg("--out")
        .arg(&out_file)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("[debug] POST"),
        "stderr must carry the request line: {stderr}"
    );
    assert!(
        stderr.contains("/api/detection_engine/rules/_export"),
        "stderr must carry the URL: {stderr}"
    );
    assert!(
        !stderr.contains(API_KEY),
        "the API key must never appear in debug output: {stderr}"
    );
}

#[tokio::test]
async fn debug_logs_a_line_before_the_request_is_sent() {
    // Log before sending so a hung request still leaves a useful trace.
    let server = exporting_server().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let out_file = dir.path().join("rules.ndjson");

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "export", "--debug", "--config"])
        .arg(&cfg)
        .arg("--out")
        .arg(&out_file)
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("[debug] -> POST"),
        "stderr must carry a pre-send line: {stderr}"
    );
    let sent = stderr.find("[debug] -> POST").unwrap();
    let answered = stderr.find("[debug] POST").unwrap();
    assert!(
        sent < answered,
        "the pre-send line must precede the response line: {stderr}"
    );
}

#[tokio::test]
async fn debug_logs_the_connection_error_branch() {
    // Port 1 should refuse immediately, exercising the error path with no HTTP
    // status—the path that previously produced no --debug output.
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), "http://127.0.0.1:1");

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "export", "--debug", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("[debug] -> POST"),
        "the attempt must be logged: {stderr}"
    );
    assert!(
        stderr.contains("-> connection error"),
        "the failure branch must be logged: {stderr}"
    );
    assert!(
        !stderr.contains(API_KEY),
        "the API key must never appear in debug output: {stderr}"
    );
}

#[tokio::test]
async fn without_debug_stderr_has_no_debug_lines() {
    let server = exporting_server().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let out_file = dir.path().join("rules.ndjson");

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "export", "--config"])
        .arg(&cfg)
        .arg("--out")
        .arg(&out_file)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("[debug]"),
        "stderr must carry no debug lines without --debug"
    );
}
