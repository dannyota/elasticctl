use assert_cmd::Command;
use std::fs;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A distinctive key so the test can prove it never appears in stderr.
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
