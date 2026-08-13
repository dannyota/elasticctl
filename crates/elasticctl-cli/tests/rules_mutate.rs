use assert_cmd::Command;
use std::fs;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config_for(dir: &std::path::Path, uri: &str) -> std::path::PathBuf {
    let p = dir.join("config.toml");
    fs::write(
        &p,
        format!(
            "current = \"default\"\n\n[profiles.default]\nkibana_url = \"{uri}\"\napi_key = \"essu_t\"\nspace = \"default\"\nverify = true\ntimeout_secs = 5\n"
        ),
    )
    .unwrap();
    p
}

async fn server_with_one_rule() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "rule_id": "abc", "name": "Alpha", "type": "query", "enabled": true
        })))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn a_dry_run_previews_on_stderr_and_changes_nothing() {
    let server = server_with_one_rule().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "disable", "abc", "--json", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "a preview is a success, not a failure"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("[DRY RUN]"), "{err}");
    assert!(err.contains("Pass --yes to apply."), "{err}");
    assert!(
        err.contains("Alpha"),
        "the preview must name the affected rule: {err}"
    );

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["applied"], false);

    // The decisive assertion: no bulk action reached the server.
    let hits = server.received_requests().await.unwrap();
    assert!(
        !hits.iter().any(|r| r.url.path().contains("_bulk_action")),
        "a dry run must not send a mutation"
    );
}

#[tokio::test]
async fn the_preview_banner_names_the_profile_and_host() {
    let server = server_with_one_rule().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "disable", "abc", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("profile: default"), "{err}");
    assert!(err.contains("space: default"), "{err}");
}

#[tokio::test]
async fn yes_applies_the_bulk_action_and_reports_the_outcome() {
    let server = server_with_one_rule().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_bulk_action"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "attributes": {"summary": {"succeeded": 1, "failed": 0, "skipped": 0, "total": 1}}
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "disable", "abc", "--yes", "--json", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();

    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.starts_with("Applying:"), "{err}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["applied"], true);
    assert_eq!(v["succeeded"], 1);
}

#[tokio::test]
async fn an_unresolvable_selector_fails_before_any_mutation() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(serde_json::json!({"message": "nope"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "page": 1, "perPage": 100, "total": 0, "data": []
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "disable", "ghost", "--yes", "--json", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(v["error"]["kind"], "not_found");
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.url.path().contains("_bulk_action")),
        "resolution must fail before anything mutates"
    );
}
