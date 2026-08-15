//! Wire-level source routing for commands whose defaults differ by command.

use assert_cmd::Command;
use serde_json::{Value, json};
use std::fs;
use wiremock::matchers::{body_partial_json, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config_for(dir: &std::path::Path, uri: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    fs::write(&path, format!(
        "current = \"default\"\n\n[profiles.default]\nkibana_url = \"{uri}\"\napi_key = \"essu_t\"\nspace = \"default\"\nverify = true\ntimeout_secs = 5\n"
    )).unwrap();
    path
}

fn remote_rule(id: &str, immutable: bool) -> Value {
    json!({
        "rule_id": id, "name": format!("Rule {id}"), "type": "query", "query": "*:*",
        "severity": "low", "risk_score": 21, "immutable": immutable,
        "id": "server-uuid", "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z", "created_by": "someone",
        "updated_by": "someone", "revision": 0, "version": 1
    })
}

fn find_body(rule: Value) -> Value {
    json!({"page": 1, "perPage": 10000, "total": 1, "data": [rule]})
}

async fn mount_capability_probe(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.5.1", "build_flavor": "traditional"}
        })))
        .expect(1)
        .mount(server)
        .await;
}

fn run(args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(args)
        .output()
        .unwrap()
}

/// The state default must be visible on the wire, not inferred from output.
#[tokio::test]
async fn state_pull_defaults_to_the_custom_immutable_filter() {
    let server = MockServer::start().await;
    mount_capability_probe(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.params.immutable: false",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(find_body(remote_rule("custom", false))),
        )
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");

    let out = run(&[
        "state".as_ref(),
        "pull".as_ref(),
        "--config".as_ref(),
        config.as_os_str(),
        "--dir".as_ref(),
        state.as_os_str(),
        "--json".as_ref(),
    ]);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `--source all` removes the default source filter instead of translating it
/// into a wider KQL expression.
#[tokio::test]
async fn state_pull_source_all_sends_no_source_filter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param_is_missing("filter"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(find_body(remote_rule("prebuilt", true))),
        )
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");

    let out = run(&[
        "state".as_ref(),
        "pull".as_ref(),
        "--source".as_ref(),
        "all".as_ref(),
        "--config".as_ref(),
        config.as_os_str(),
        "--dir".as_ref(),
        state.as_os_str(),
        "--json".as_ref(),
    ]);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Rules list keeps its all-source default but forwards an explicit prebuilt
/// source clause exactly.
#[tokio::test]
async fn rules_list_source_prebuilt_sends_the_measured_kql() {
    let server = MockServer::start().await;
    mount_capability_probe(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.params.immutable: true",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(find_body(remote_rule("prebuilt", true))),
        )
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path(), &server.uri());

    let out = run(&[
        "rules".as_ref(),
        "list".as_ref(),
        "--source".as_ref(),
        "prebuilt".as_ref(),
        "--config".as_ref(),
        config.as_os_str(),
        "--json".as_ref(),
    ]);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// An explicit customized export resolves IDs using its measured KQL before
/// posting its intentionally scoped export body.
#[tokio::test]
async fn rules_export_source_customized_sends_the_measured_kql() {
    let server = MockServer::start().await;
    mount_capability_probe(&server).await;
    let rule = remote_rule("customized", true);
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.params.ruleSource.isCustomized: true",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(find_body(rule.clone())))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_export"))
        .and(body_partial_json(
            json!({"objects": [{"rule_id": "customized"}]}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "{}\n{{\"exported_count\":1,\"exported_rules_count\":1,\"missing_rules_count\":0}}\n",
            serde_json::to_string(&rule).unwrap()
        )))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path(), &server.uri());

    let out = run(&[
        "rules".as_ref(),
        "export".as_ref(),
        "--source".as_ref(),
        "customized".as_ref(),
        "--config".as_ref(),
        config.as_os_str(),
        "--json".as_ref(),
    ]);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// An explicit selector replaces the state default source scope, so a
/// prebuilt rule remains selectable by `state pull` without `--source all`.
#[tokio::test]
async fn a_state_pull_selector_overrides_the_custom_source_default() {
    let server = MockServer::start().await;
    let rule = remote_rule("prebuilt", true);
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "prebuilt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.params.ruleId: \"prebuilt\"",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(find_body(rule)))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");

    let out = run(&[
        "state".as_ref(),
        "pull".as_ref(),
        "--config".as_ref(),
        config.as_os_str(),
        "--dir".as_ref(),
        state.as_os_str(),
        "--json".as_ref(),
        "prebuilt".as_ref(),
    ]);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
