use assert_cmd::Command;
use serde_json::{Value, json};
use std::fs;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config_for(dir: &std::path::Path, uri: &str) -> std::path::PathBuf {
    let p = dir.join("config.toml");
    fs::write(&p, format!(
        "current = \"default\"\n\n[profiles.default]\nkibana_url = \"{uri}\"\napi_key = \"essu_t\"\nspace = \"default\"\nverify = true\ntimeout_secs = 5\n"
    )).unwrap();
    p
}

fn remote_rule(id: &str, risk: i64) -> Value {
    json!({
        "rule_id": id, "name": format!("Rule {id}"), "type": "query", "query": "*:*",
        "severity": "low", "risk_score": risk,
        "id": "server-uuid", "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z", "created_by": "someone",
        "updated_by": "someone", "revision": 0, "version": 1
    })
}

fn write_local(state: &std::path::Path, id: &str, risk: i64) {
    let rules = state.join("rules");
    fs::create_dir_all(&rules).unwrap();
    let body = json!({
        "rule_id": id, "name": format!("Rule {id}"), "type": "query",
        "query": "*:*", "severity": "low", "risk_score": risk
    });
    fs::write(
        rules.join(format!("{id}.ndjson")),
        format!("{}\n", serde_json::to_string(&body).unwrap()),
    )
    .unwrap();
}

async fn server_with(rules: Vec<Value>) -> MockServer {
    let server = MockServer::start().await;
    let total = rules.len();

    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.5.1", "build_flavor": "traditional"}
        })))
        .mount(&server)
        .await;

    for rule in &rules {
        let id = rule["rule_id"].as_str().unwrap().to_string();
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules"))
            .and(query_param("rule_id", id))
            .respond_with(ResponseTemplate::new(200).set_body_json(rule.clone()))
            .mount(&server)
            .await;
    }

    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 10000, "total": total, "data": rules
        })))
        .mount(&server)
        .await;
    server
}

fn run(args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(args)
        .output()
        .unwrap()
}

#[tokio::test]
async fn a_scoped_diff_asks_the_server_for_only_the_selected_rule() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.params.ruleId: \"a\"",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 10000, "total": 1, "data": [remote_rule("a", 21)]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");
    write_local(&state, "a", 21);
    write_local(&state, "b", 73);

    let out = run(&[
        "state".as_ref(),
        "diff".as_ref(),
        "--config".as_ref(),
        cfg.as_os_str(),
        "--dir".as_ref(),
        state.as_os_str(),
        "--json".as_ref(),
        "a".as_ref(),
    ]);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["local"], 1, "the local side must be narrowed too");
    assert_eq!(v["selected"], 1);
    assert_eq!(v["local_total"], 2, "the unscoped local count is reported");
}

#[tokio::test]
async fn a_local_only_rule_is_selectable_by_name_before_it_exists_remotely() {
    let server = server_with(vec![]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");
    write_local(&state, "fresh", 42);

    let out = run(&[
        "state".as_ref(),
        "diff".as_ref(),
        "--config".as_ref(),
        cfg.as_os_str(),
        "--dir".as_ref(),
        state.as_os_str(),
        "--json".as_ref(),
        "Rule fresh".as_ref(),
    ]);

    assert!(
        out.status.success(),
        "a local-only rule must resolve by name: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["selected"], 1);
    assert_eq!(v["local"], 1);
}

#[tokio::test]
async fn the_push_banner_names_the_selection() {
    let server = server_with(vec![]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");
    write_local(&state, "a", 21);
    write_local(&state, "b", 73);

    let out = run(&[
        "state".as_ref(),
        "push".as_ref(),
        "--config".as_ref(),
        cfg.as_os_str(),
        "--dir".as_ref(),
        state.as_os_str(),
        "a".as_ref(),
    ]);

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("selection: 1 of 2 local rules"),
        "the banner must say the run was scoped: {text}"
    );
    assert!(
        text.contains("[DRY RUN]"),
        "a scoped push is still a dry run by default: {text}"
    );
}

#[tokio::test]
async fn the_push_banner_names_the_search_selection() {
    let server = server_with(vec![]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");
    write_local(&state, "a", 21);
    write_local(&state, "b", 73);

    let out = run(&[
        "state".as_ref(),
        "push".as_ref(),
        "--config".as_ref(),
        cfg.as_os_str(),
        "--dir".as_ref(),
        state.as_os_str(),
        "--search".as_ref(),
        "Rule a".as_ref(),
    ]);

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("selection: 1 of 2 local rules"),
        "the banner must say the run was scoped by search: {text}"
    );
    assert!(
        text.contains("[DRY RUN]"),
        "a search-scoped push is still a dry run by default: {text}"
    );
}

#[tokio::test]
async fn an_unscoped_run_reports_no_selection_fields() {
    let server = server_with(vec![remote_rule("a", 21)]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");
    write_local(&state, "a", 21);

    let out = run(&[
        "state".as_ref(),
        "diff".as_ref(),
        "--config".as_ref(),
        cfg.as_os_str(),
        "--dir".as_ref(),
        state.as_os_str(),
        "--json".as_ref(),
    ]);

    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v.get("selected").is_none() && v.get("local_total").is_none(),
        "an unscoped run must not grow fields: {v}"
    );
}

#[tokio::test]
async fn a_selector_matching_nothing_is_refused() {
    let server = server_with(vec![]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");
    write_local(&state, "a", 21);

    let out = run(&[
        "state".as_ref(),
        "diff".as_ref(),
        "--config".as_ref(),
        cfg.as_os_str(),
        "--dir".as_ref(),
        state.as_os_str(),
        "ghost".as_ref(),
    ]);

    assert!(!out.status.success(), "an unmatched selector must fail");
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("ghost"),
        "the refusal must name the selector: {text}"
    );
}

#[tokio::test]
async fn a_scoped_pull_resolves_a_rule_id_against_the_stack() {
    let server = server_with(vec![remote_rule("a", 21)]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");

    let out = run(&[
        "state".as_ref(),
        "pull".as_ref(),
        "--config".as_ref(),
        cfg.as_os_str(),
        "--dir".as_ref(),
        state.as_os_str(),
        "--json".as_ref(),
        "a".as_ref(),
    ]);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(state.join("rules").join("a.ndjson").exists());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["pulled"], 1);
    assert_eq!(v["selected"], 1);
}

#[tokio::test]
async fn a_scoped_pull_resolves_a_display_name_against_the_stack() {
    let server = server_with(vec![remote_rule("a", 21)]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");

    let out = run(&[
        "state".as_ref(),
        "pull".as_ref(),
        "--config".as_ref(),
        cfg.as_os_str(),
        "--dir".as_ref(),
        state.as_os_str(),
        "--json".as_ref(),
        "Rule a".as_ref(),
    ]);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(state.join("rules").join("a.ndjson").exists());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["pulled"], 1);
    assert_eq!(v["selected"], 1);
}

#[tokio::test]
async fn a_search_scoped_pull_writes_only_the_matching_rule() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "(alert.attributes.name: \"*Rule a*\" OR alert.attributes.tags: \"Rule a\")",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 10000, "total": 1, "data": [remote_rule("a", 21)]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.params.ruleId: \"a\"",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 10000, "total": 1, "data": [remote_rule("a", 21)]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");

    let out = run(&[
        "state".as_ref(),
        "pull".as_ref(),
        "--config".as_ref(),
        cfg.as_os_str(),
        "--dir".as_ref(),
        state.as_os_str(),
        "--json".as_ref(),
        "--search".as_ref(),
        "Rule a".as_ref(),
    ]);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(state.join("rules").join("a.ndjson").exists());
    assert!(
        !state.join("rules").join("b.ndjson").exists(),
        "the non-matching rule must not be pulled"
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["pulled"], 1);
    assert_eq!(v["selected"], 1);
}

#[tokio::test]
async fn a_search_scoped_diff_reports_only_the_matching_rule() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "(alert.attributes.name: \"*Rule a*\" OR alert.attributes.tags: \"Rule a\")",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 10000, "total": 1, "data": [remote_rule("a", 21)]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.params.ruleId: \"a\"",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 10000, "total": 1, "data": [remote_rule("a", 21)]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");
    write_local(&state, "a", 99);
    write_local(&state, "b", 999);

    let out = run(&[
        "state".as_ref(),
        "diff".as_ref(),
        "--config".as_ref(),
        cfg.as_os_str(),
        "--dir".as_ref(),
        state.as_os_str(),
        "--json".as_ref(),
        "--search".as_ref(),
        "Rule a".as_ref(),
    ]);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["selected"], 1);
    assert_eq!(v["local"], 1, "the local side must be narrowed too");
    assert_eq!(v["local_total"], 2, "the unscoped local count is reported");
    assert_eq!(v["clean"], false);
    let changes = v["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 1, "only the matching rule may drift: {v}");
    assert_eq!(changes[0]["rule_id"], "a");
    assert!(
        changes.iter().all(|c| c["rule_id"] != "b"),
        "the non-matching rule must not be reported as drift: {v}"
    );
}
