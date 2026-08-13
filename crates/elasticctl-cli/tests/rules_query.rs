//! End-to-end coverage for `rules list` and `rules get` against a mock
//! Kibana. The detection-engine calls themselves are already covered in
//! `elasticctl-api`'s wiremock suite; these tests exercise the CLI wiring on
//! top: argument parsing, selector resolution, and the conflict/not-found
//! surface an operator actually sees.

use assert_cmd::Command;
use serde_json::json;
use std::fs;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

fn write_config(dir: &std::path::Path, kibana_url: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    fs::write(
        &path,
        format!(
            r#"
current = "default"

[profiles.default]
kibana_url = "{kibana_url}"
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

fn rule_json(id: &str, name: &str) -> serde_json::Value {
    json!({"rule_id": id, "name": name, "type": "query", "risk_score": 21, "enabled": true})
}

#[tokio::test]
async fn rules_list_prints_the_summarized_rules() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 100, "total": 1, "data": [rule_json("a", "Alpha")]
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &server.uri());
    let out = bin()
        .args(["rules", "list", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[0]["rule_id"], "a");
    assert_eq!(v[0]["name"], "Alpha");
}

#[tokio::test]
async fn rules_list_rejects_enabled_and_disabled_together() {
    let dir = tempfile::tempdir().unwrap();
    // A config that would fail if ever loaded, proving the check happens
    // before any config resolution or network call.
    let config = dir.path().join("absent.toml");
    let out = bin()
        .args([
            "rules",
            "list",
            "--json",
            "--enabled",
            "--disabled",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value =
        serde_json::from_slice(&out.stderr).expect("error envelope on stderr");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("mutually exclusive")
    );
}

#[tokio::test]
async fn rules_get_resolves_a_rule_id_directly() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_json("abc", "A rule")))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &server.uri());
    let out = bin()
        .args(["rules", "get", "abc", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["rule_id"], "abc");
}

#[tokio::test]
async fn rules_get_falls_back_to_an_exact_name_match() {
    let server = MockServer::start().await;
    // The selector is not a rule_id: a direct lookup misses...
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "A rule"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "not found"})))
        .mount(&server)
        .await;
    // ...so the CLI searches by name...
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 100, "total": 1, "data": [rule_json("abc", "A rule")]
        })))
        .mount(&server)
        .await;
    // ...then fetches the resolved rule_id.
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_json("abc", "A rule")))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &server.uri());
    let out = bin()
        .args(["rules", "get", "A rule", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["rule_id"], "abc");
}

#[tokio::test]
async fn rules_get_of_an_ambiguous_name_is_a_conflict_naming_every_candidate() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "Duplicate"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "not found"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 100, "total": 2,
            "data": [rule_json("a", "Duplicate"), rule_json("b", "Duplicate")]
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &server.uri());
    let out = bin()
        .args(["rules", "get", "Duplicate", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value =
        serde_json::from_slice(&out.stderr).expect("error envelope on stderr");
    assert_eq!(v["error"]["kind"], "conflict");
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(msg.contains('a') && msg.contains('b'), "{msg}");
}

/// The rule_id lookup can fail for reasons other than "no such rule" (an
/// expired credential, a revoked key). Only a 404 should trigger the
/// fall-back to a name search; any other failure must propagate as-is, not
/// be swallowed into a misleading "no rule named X".
#[tokio::test]
async fn rules_get_propagates_a_non_404_failure_from_the_rule_id_lookup() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "abc"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "unauthorized"})))
        .mount(&server)
        .await;
    // No mock for _find: if the 401 were misclassified as not_found and the
    // code fell back to a name search, this test would fail with a
    // connection/mock-mismatch error rather than a clean "auth" assertion,
    // making a regression here obvious rather than silently passing.

    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &server.uri());
    let out = bin()
        .args(["rules", "get", "abc", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value =
        serde_json::from_slice(&out.stderr).expect("error envelope on stderr");
    assert_eq!(v["error"]["kind"], "auth");
}

/// `to_rule_id` tries the selector as a rule_id first. Pin that precedence:
/// when a selector is simultaneously a valid rule_id for one rule and the
/// exact display name of a different rule, the rule_id match must win.
#[tokio::test]
async fn rules_get_prefers_a_direct_rule_id_hit_over_a_colliding_display_name() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "dup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_json("dup", "Rule A")))
        .mount(&server)
        .await;
    // A rule whose *name* collides with the other rule's rule_id. If the
    // implementation ever preferred a name search, this decoy would be
    // returned instead — and the `.expect(0)` below would also fail the
    // test outright, since the direct hit must mean this is never queried.
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 100, "total": 1, "data": [rule_json("b", "dup")]
        })))
        .expect(0)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &server.uri());
    let out = bin()
        .args(["rules", "get", "dup", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["rule_id"], "dup");
    assert_eq!(
        v["name"], "Rule A",
        "the direct rule_id hit must win over the colliding name: {v}"
    );
}
