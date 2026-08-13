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

fn remote_rule(id: &str, risk: i64) -> serde_json::Value {
    json!({
        "rule_id": id, "name": format!("Rule {id}"), "type": "query", "query": "*:*",
        "severity": "low", "risk_score": risk,
        "id": "server-uuid", "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
        "created_by": "someone", "updated_by": "someone", "revision": 0, "version": 1
    })
}

async fn server_with(rules: Vec<serde_json::Value>) -> MockServer {
    let server = MockServer::start().await;
    let total = rules.len();
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 100, "total": total, "data": rules
        })))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn pull_writes_one_file_per_rule_without_volatile_fields() {
    let server = server_with(vec![remote_rule("a", 21), remote_rule("b", 73)]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");

    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["state", "pull", "--config"])
        .arg(&cfg)
        .arg("--dir")
        .arg(&state)
        .assert()
        .success();

    let a = state.join("rules").join("a.ndjson");
    assert!(a.exists(), "one file per rule, named by rule_id");
    assert!(state.join("rules").join("b.ndjson").exists());
    let body = fs::read_to_string(&a).unwrap();
    assert!(
        !body.contains("server-uuid"),
        "volatile id must not be written: {body}"
    );
    assert!(!body.contains("created_at"), "{body}");
}

// `safe_filename` maps every character outside [A-Za-z0-9_-] to '_', which
// correctly closes path traversal but means distinct rule ids can collide on
// one filename. An unnoticed collision would silently drop a rule from the
// local mirror while `pulled` kept counting both — the same class of
// authoring conflict `Drift::compute` already refuses to paper over for a
// duplicate rule_id.
#[tokio::test]
async fn pull_reports_a_conflict_when_two_rule_ids_sanitise_to_the_same_filename() {
    let server = server_with(vec![remote_rule("a/b", 21), remote_rule("a_b", 73)]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["state", "pull", "--config"])
        .arg(&cfg)
        .arg("--dir")
        .arg(&state)
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(err["error"]["kind"], "conflict");
    let msg = err["error"]["message"].as_str().unwrap();
    assert!(msg.contains("a/b"), "{msg}");
    assert!(msg.contains("a_b"), "{msg}");
}

#[tokio::test]
async fn pull_writes_distinct_files_when_sanitised_names_do_not_collide() {
    let server = server_with(vec![remote_rule("a.one", 21), remote_rule("b.two", 73)]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");

    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["state", "pull", "--config"])
        .arg(&cfg)
        .arg("--dir")
        .arg(&state)
        .assert()
        .success();

    assert!(state.join("rules").join("a_one.ndjson").exists());
    assert!(state.join("rules").join("b_two.ndjson").exists());
}

#[tokio::test]
async fn pull_twice_produces_identical_files() {
    let server = server_with(vec![remote_rule("a", 21)]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");
    let file = state.join("rules").join("a.ndjson");

    let run = || {
        Command::cargo_bin("elasticctl")
            .unwrap()
            .args(["state", "pull", "--config"])
            .arg(&cfg)
            .arg("--dir")
            .arg(&state)
            .assert()
            .success();
        fs::read_to_string(&file).unwrap()
    };
    assert_eq!(run(), run(), "pull must be deterministic");
}

#[tokio::test]
async fn diff_is_clean_immediately_after_a_pull() {
    // The property the whole state engine rests on.
    let server = server_with(vec![remote_rule("a", 21)]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");

    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["state", "pull", "--config"])
        .arg(&cfg)
        .arg("--dir")
        .arg(&state)
        .assert()
        .success();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["state", "diff", "--json", "--config"])
        .arg(&cfg)
        .arg("--dir")
        .arg(&state)
        .output()
        .unwrap();

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["clean"], true, "a fresh pull must show no drift: {v}");
}

#[tokio::test]
async fn diff_reports_an_edited_field_with_before_and_after() {
    let server = server_with(vec![remote_rule("a", 21)]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");

    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["state", "pull", "--config"])
        .arg(&cfg)
        .arg("--dir")
        .arg(&state)
        .assert()
        .success();

    let file = state.join("rules").join("a.ndjson");
    let edited = fs::read_to_string(&file)
        .unwrap()
        .replace("\"risk_score\":21", "\"risk_score\":99");
    fs::write(&file, edited).unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["state", "diff", "--json", "--config"])
        .arg(&cfg)
        .arg("--dir")
        .arg(&state)
        .output()
        .unwrap();

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["clean"], false);
    let change = &v["changes"][0];
    assert_eq!(change["change"], "modified");
    assert_eq!(change["fields"][0]["field"], "risk_score");
    assert_eq!(change["fields"][0]["before"], 21);
    assert_eq!(change["fields"][0]["after"], 99);
}

#[tokio::test]
async fn a_rule_only_on_the_server_is_reported_but_never_deleted() {
    // The no-delete guarantee, asserted end to end.
    let server = server_with(vec![remote_rule("a", 21)]).await;
    Mock::given(method("DELETE"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"rule_id": "a"})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");
    fs::create_dir_all(state.join("rules")).unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["state", "push", "--yes", "--json", "--config"])
        .arg(&cfg)
        .arg("--dir")
        .arg(&state)
        .output()
        .unwrap();

    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["created"], 0);
    assert_eq!(v["updated"], 0);
    assert_eq!(v["skipped_remote_only"], 1);
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.method.as_str() == "DELETE"),
        "push must never issue a delete"
    );
}

#[tokio::test]
async fn push_dry_run_previews_and_sends_no_mutation() {
    let server = server_with(vec![]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");
    fs::create_dir_all(state.join("rules")).unwrap();
    fs::write(
        state.join("rules").join("new.ndjson"),
        "{\"rule_id\":\"new\",\"name\":\"New\",\"type\":\"query\",\"query\":\"*:*\"}\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["state", "push", "--json", "--config"])
        .arg(&cfg)
        .arg("--dir")
        .arg(&state)
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("[DRY RUN]"));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["applied"], false);
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.method.as_str() == "POST"),
        "a dry run must not create anything"
    );
}

// `report.rs`'s own doc comment says the report exists to record what was
// *proposed*, not only what was applied. Before this fix, entries for
// Added/Modified changes were only pushed inside `if applying`, so a dry-run
// `--report` recorded nothing but `skipped_remote_only`, and a script running
// `state push --json` had no field-level way to learn how many changes were
// pending short of scraping the stderr preview.
#[tokio::test]
async fn push_dry_run_report_includes_pending_creates_and_updates() {
    let server = server_with(vec![remote_rule("existing", 10)]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");
    fs::create_dir_all(state.join("rules")).unwrap();
    // Differs from the remote only in risk_score: a pending update.
    fs::write(
        state.join("rules").join("existing.ndjson"),
        "{\"rule_id\":\"existing\",\"name\":\"Rule existing\",\"type\":\"query\",\"query\":\"*:*\",\"severity\":\"low\",\"risk_score\":55}\n",
    )
    .unwrap();
    // Absent remotely: a pending create.
    fs::write(
        state.join("rules").join("newone.ndjson"),
        "{\"rule_id\":\"newone\",\"name\":\"New\",\"type\":\"query\",\"query\":\"*:*\"}\n",
    )
    .unwrap();
    let report = dir.path().join("report.json");

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["state", "push", "--json", "--config"])
        .arg(&cfg)
        .arg("--dir")
        .arg(&state)
        .arg("--report")
        .arg(&report)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["applied"], false);
    assert_eq!(v["pending"], 2);
    assert_eq!(v["created"], 0);
    assert_eq!(v["updated"], 0);

    let r: serde_json::Value = serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
    let entries = r["entries"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        2,
        "both pending changes must be recorded, not just applied ones"
    );
    assert!(entries.iter().all(|e| e["applied"] == false));
    let actions: std::collections::BTreeSet<&str> = entries
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(
        actions,
        std::collections::BTreeSet::from(["create", "update"])
    );

    assert!(
        !server.received_requests().await.unwrap().iter().any(|r| {
            let m = r.method.as_str();
            m == "POST" || m == "PUT"
        }),
        "a dry run must not mutate anything"
    );
}

#[tokio::test]
async fn push_writes_a_change_report_with_before_and_after() {
    let server = server_with(vec![]).await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rule_id": "new", "name": "New", "type": "query", "id": "srv"
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");
    fs::create_dir_all(state.join("rules")).unwrap();
    fs::write(
        state.join("rules").join("new.ndjson"),
        "{\"rule_id\":\"new\",\"name\":\"New\",\"type\":\"query\",\"query\":\"*:*\"}\n",
    )
    .unwrap();
    let report = dir.path().join("report.json");

    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["state", "push", "--yes", "--config"])
        .arg(&cfg)
        .arg("--dir")
        .arg(&state)
        .arg("--report")
        .arg(&report)
        .assert()
        .success();

    let r: serde_json::Value = serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(r["applied"], true);
    assert_eq!(r["profile"], "default");
    let entry = &r["entries"][0];
    assert_eq!(entry["rule_id"], "new");
    assert_eq!(entry["action"], "create");
    assert_eq!(entry["applied"], true);
    assert!(
        entry["before"].is_null(),
        "a created rule has no before state"
    );
    assert!(!entry["after"].is_null());
}

// NOTE: the brief's draft of this test asserted `.assert().success()` here,
// i.e. exit code 0, even though both rules fail to apply. That contradicts
// the partial-failure convention `render::exit_code_for_value` exists to
// enforce (see rules::delete and rules::set_enabled, and the commits titled
// "Fix rules delete discarding progress on a per-rule failure" and "Fix
// bulk-action partial failures exiting 0"): a mutating command whose payload
// carries a positive `failed` count must exit 1, or a script checking only
// the exit code misses a fully-failed push. `push`'s summary reports
// `"failed": <count>` for exactly this reason, and this test now asserts the
// exit code that convention implies, matching the sibling test
// `delete_continues_past_a_per_rule_failure_and_reports_every_outcome` in
// rules_mutate.rs. The report file assertions are unchanged from the brief.
#[tokio::test]
async fn one_failing_rule_does_not_abort_the_rest() {
    let server = server_with(vec![]).await;
    // Every create fails; both rules must still be attempted and reported.
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(
            ResponseTemplate::new(409).set_body_json(json!({"message": "already exists"})),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let state = dir.path().join("state");
    fs::create_dir_all(state.join("rules")).unwrap();
    for id in ["one", "two"] {
        fs::write(
            state.join("rules").join(format!("{id}.ndjson")),
            format!("{{\"rule_id\":\"{id}\",\"name\":\"{id}\",\"type\":\"query\"}}\n"),
        )
        .unwrap();
    }
    let report = dir.path().join("report.json");

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["state", "push", "--yes", "--json", "--config"])
        .arg(&cfg)
        .arg("--dir")
        .arg(&state)
        .arg("--report")
        .arg(&report)
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(1),
        "a fully-failed push must not exit 0: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    let r: serde_json::Value = serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
    let entries = r["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "both rules must be attempted");
    assert!(entries.iter().all(|e| e["applied"] == false));
    assert!(
        entries
            .iter()
            .all(|e| e["error"].as_str().unwrap().contains("already exists"))
    );
}
