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
    assert_eq!(
        v["total"], 1,
        "dry run and apply must share one count field"
    );

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

/// `set_enabled` serves both `enable` and `disable` from one `enabled` flag,
/// but the guard path string differs between them — and the assert is live,
/// not `cfg(test)`, so a wrong path on the enable arm would panic a real user
/// running `rules enable`. The disable apply test cannot catch that typo, so
/// enable is driven through the same apply path here.
#[tokio::test]
async fn yes_enables_a_rule_through_the_same_apply_path_as_disable() {
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
        .args(["rules", "enable", "abc", "--yes", "--json", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.starts_with("Applying:"), "{err}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["applied"], true);
    assert_eq!(v["succeeded"], 1);
}

/// A bulk action's summary reports `failed` as a count, not a per-item list,
/// but a positive count is exactly as much a partial failure as a non-empty
/// `deleted`'s `failed` list — the exit code must reflect it. The operator
/// still needs the full summary, so stdout must carry it even though the
/// process exits non-zero.
#[tokio::test]
async fn a_bulk_action_partial_failure_exits_non_zero_but_still_reports_the_summary() {
    let server = server_with_one_rule().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_bulk_action"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "attributes": {"summary": {"succeeded": 0, "failed": 1, "skipped": 0, "total": 1}}
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

    assert_eq!(
        out.status.code(),
        Some(1),
        "a bulk action reporting a failed count must not exit 0: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("the operator must still get the report, not just the code");
    assert_eq!(v["applied"], true);
    assert_eq!(v["succeeded"], 0);
    assert_eq!(v["failed"], 1);
    assert_eq!(v["total"], 1);
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

async fn server_with_three_rules() -> MockServer {
    let server = MockServer::start().await;
    for (id, name) in [("r1", "One"), ("r2", "Two"), ("r3", "Three")] {
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules"))
            .and(query_param("rule_id", id))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "rule_id": id, "name": name, "type": "query", "enabled": true
            })))
            .mount(&server)
            .await;
    }
    server
}

/// `delete` removes rules one at a time. If rule 2 of 3 fails, the loop must
/// not stop there: rule 3 must still be attempted, and the payload must name
/// exactly which rules survived and which did not — rather than an early `?`
/// return silently dropping everything already deleted.
#[tokio::test]
async fn delete_continues_past_a_per_rule_failure_and_reports_every_outcome() {
    let server = server_with_three_rules().await;

    Mock::given(method("DELETE"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "r1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "rule_id": "r1", "name": "One", "type": "query", "enabled": true
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "r2"))
        .respond_with(
            ResponseTemplate::new(409).set_body_json(serde_json::json!({"message": "locked"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "r3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "rule_id": "r3", "name": "Three", "type": "query", "enabled": true
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args([
            "rules", "delete", "r1", "r2", "r3", "--yes", "--json", "--config",
        ])
        .arg(&cfg)
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(1),
        "a partial failure must not exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["applied"], true);
    assert_eq!(v["total"], 3);

    let deleted: Vec<&str> = v["deleted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["rule_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        deleted,
        vec!["r1", "r3"],
        "rules 1 and 3 must be reported as deleted"
    );

    let failed = v["failed"].as_array().unwrap();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0]["rule_id"], "r2");
    assert!(
        failed[0]["error"].as_str().unwrap().contains("locked"),
        "{v}"
    );

    // Prove the loop did not stop at the first failure: all three DELETEs
    // reached the server, not just the one before the failure.
    let hits = server.received_requests().await.unwrap();
    let delete_count = hits
        .iter()
        .filter(|r| r.method.as_str() == "DELETE")
        .count();
    assert_eq!(
        delete_count, 3,
        "rule 3 must still be attempted after rule 2 fails"
    );
}

#[tokio::test]
async fn delete_of_every_rule_succeeding_has_an_empty_failed_list_and_exits_zero() {
    let server = server_with_three_rules().await;
    for id in ["r1", "r2", "r3"] {
        Mock::given(method("DELETE"))
            .and(path("/api/detection_engine/rules"))
            .and(query_param("rule_id", id))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "rule_id": id, "name": "x", "type": "query", "enabled": true
            })))
            .mount(&server)
            .await;
    }

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args([
            "rules", "delete", "r1", "r2", "r3", "--yes", "--json", "--config",
        ])
        .arg(&cfg)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["applied"], true);
    assert!(v["failed"].as_array().unwrap().is_empty());
    assert_eq!(v["deleted"].as_array().unwrap().len(), 3);
    assert_eq!(v["total"], 3);
}
