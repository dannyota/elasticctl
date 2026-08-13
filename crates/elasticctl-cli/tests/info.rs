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

async fn stack(build_flavor: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.5.1", "build_flavor": build_flavor}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/spaces/space"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "default", "name": "Default"},
            {"id": "soc", "name": "SOC"}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/_license"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "license": {"status": "active", "type": "platinum"}
        })))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn info_reports_the_probed_spaces_and_license_tier() {
    let server = stack("traditional").await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["info", "--json", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["license_tier"], "platinum");
    assert_eq!(v["spaces"], json!(["default", "soc"]));
    assert_eq!(v["space"], "default", "the configured space still shows");
}

#[tokio::test]
async fn info_reports_a_null_license_tier_on_serverless() {
    // Serverless has no license tier. Return null even though this mock
    // provides one; info must not request it.
    let server = stack("serverless").await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["info", "--json", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["license_tier"], serde_json::Value::Null);
    assert_eq!(v["spaces"], json!(["default", "soc"]));
}

/// `doctor` and `config test` read capabilities but do not report spaces or a
/// license tier. They must not request those endpoints.
#[tokio::test]
async fn doctor_does_not_probe_spaces_or_the_license() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.6.0", "build_flavor": "serverless"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/spaces/space"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(0)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["doctor", "--json", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    // Wiremock checks the `expect(0)` when the mock is dropped.
}
