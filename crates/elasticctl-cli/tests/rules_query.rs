//! End-to-end tests for `rules list` and `rules get` against mock Kibana.
//! API calls are covered in `elasticctl-api`; these tests cover CLI parsing,
//! selector resolution, and conflict or not-found errors.

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
async fn rules_list_forwards_search_as_a_parenthesized_filter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 100, "total": 1, "data": [rule_json("a", "PowerShell")]
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &server.uri());
    let out = bin()
        .args([
            "rules",
            "list",
            "--search",
            "PowerShell",
            "--json",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let requests = server.received_requests().await.unwrap();
    let find = requests
        .iter()
        .find(|request| request.url.path() == "/api/detection_engine/rules/_find")
        .unwrap();
    let query: std::collections::BTreeMap<_, _> = find.url.query_pairs().into_owned().collect();
    assert_eq!(
        query["filter"],
        "(alert.attributes.name: \"*PowerShell*\" OR alert.attributes.tags: \"PowerShell\")"
    );
}

#[test]
fn rules_list_rejects_an_empty_search() {
    let dir = tempfile::tempdir().unwrap();
    // A missing config proves clap rejects the empty value before config loading.
    let config = dir.path().join("absent.toml");
    let out = bin()
        .args(["rules", "list", "--search", "", "--config"])
        .arg(&config)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2), "clap exits 2 on a usage error");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--search"), "{stderr}");
}

#[test]
fn rules_list_rejects_search_and_filter_together() {
    let dir = tempfile::tempdir().unwrap();
    // A missing config proves clap rejects the conflict before config loading.
    let config = dir.path().join("absent.toml");
    let out = bin()
        .args([
            "rules", "list", "--search", "x", "--filter", "y", "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2), "clap exits 2 on a usage error");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--search"), "{stderr}");
    assert!(stderr.contains("--filter"), "{stderr}");
}

#[tokio::test]
async fn rules_list_rejects_enabled_and_disabled_together() {
    let dir = tempfile::tempdir().unwrap();
    // This missing config proves validation runs before config loading or I/O.
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
    // The direct rule_id lookup misses.
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "A rule"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "not found"})))
        .mount(&server)
        .await;
    // The CLI then searches by name.
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 100, "total": 1, "data": [rule_json("abc", "A rule")]
        })))
        .mount(&server)
        .await;
    // Finally, it fetches the resolved rule_id.
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

/// Only a 404 from the rule_id lookup should trigger a name search. Other
/// failures, such as an unauthorized response, must propagate unchanged.
#[tokio::test]
async fn rules_get_propagates_a_non_404_failure_from_the_rule_id_lookup() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "abc"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "unauthorized"})))
        .mount(&server)
        .await;
    // No _find mock: a mistaken fallback would fail before the auth assertion.

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

/// `to_rule_id` must prefer a direct rule_id match over a matching display
/// name.
#[tokio::test]
async fn rules_get_prefers_a_direct_rule_id_hit_over_a_colliding_display_name() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "dup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_json("dup", "Rule A")))
        .mount(&server)
        .await;
    // This decoy must never be queried when the direct rule_id lookup hits.
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
