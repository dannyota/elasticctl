use assert_cmd::Command;
use serde_json::json;
use std::fs;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

fn write_config(dir: &std::path::Path, uri: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    fs::write(
        &path,
        format!(
            r#"
current = "default"
[profiles.default]
kibana_url = "{uri}"
es_url = "{uri}"
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

#[tokio::test]
async fn alerts_list_renders_source_rows_and_meta_on_request() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [
                {"_id": "a1", "_source": {
                    "kibana.alert.rule.name": "Alpha",
                    "kibana.alert.severity": "high",
                    "kibana.alert.workflow_status": "open"}}
            ]}
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["alerts", "list"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows[0]["kibana.alert.rule.name"], json!("Alpha"));
    assert!(rows[0].get("_id").is_none(), "meta is opt-in");

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["alerts", "list", "--with-meta"])
        .output()
        .unwrap();
    let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows[0]["_id"], json!("a1"));
}

#[tokio::test]
async fn alerts_get_merges_the_id_into_the_document() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [
                {"_id": "a1", "_source": {"kibana.alert.rule.name": "Alpha"}}
            ]}
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["alerts", "get", "a1"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["_id"], json!("a1"));
    assert_eq!(doc["kibana.alert.rule.name"], json!("Alpha"));
}

/// Finding 2: `alerts get`'s document is the raw `_source`, which can
/// legitimately carry a top-level `failed` key from the source event (not
/// elasticctl's own report convention). `render::exit_code_for_value` must
/// not be applied to it, or an alert whose event happens to log `"failed":
/// 2` would print correctly but exit 1.
#[tokio::test]
async fn alerts_get_does_not_derive_its_exit_code_from_the_alert_document() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [
                {"_id": "a1", "_source": {
                    "kibana.alert.rule.name": "Alpha",
                    "failed": 2}}
            ]}
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["alerts", "get", "a1"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "the source's own `failed` field must not drive the exit code: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["failed"], json!(2));
}

fn one_open_alert() -> serde_json::Value {
    json!({"hits": {"total": {"value": 1, "relation": "eq"}, "hits": [
        {"_id": "a1", "_source": {
            "kibana.alert.rule.name": "Suspicious PowerShell",
            "kibana.alert.workflow_status": "open"}}
    ]}})
}

#[tokio::test]
async fn a_close_dry_run_previews_on_stderr_and_changes_nothing() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(one_open_alert()))
        .mount(&server)
        .await;
    // No mock for signals/status: a dry run that POSTs there fails the test
    // with a 404-driven non-zero exit.

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["alerts", "close", "a1"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "a preview is a success: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("[DRY RUN]"), "{err}");
    assert!(err.contains("Close 1 alert"), "{err}");
    assert!(err.contains("open -> closed"), "{err}");
    assert!(err.contains("Pass --yes to apply."), "{err}");
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["applied"], json!(false));
}

#[tokio::test]
async fn a_close_with_yes_applies_and_reports_counts() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(one_open_alert()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1, "updated": 1, "version_conflicts": 0, "noops": 0, "failures": []
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json", "--yes"])
        .args(["alerts", "close", "a1", "--reason", "false_positive"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Applying: Close 1 alert"), "{err}");
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["applied"], json!(true));
    assert_eq!(report["updated"], json!(1));
}

#[tokio::test]
async fn a_query_close_previews_count_and_sample() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 42, "relation": "eq"}, "hits": [
                {"_id": "a1", "_source": {
                    "kibana.alert.rule.name": "Alpha",
                    "kibana.alert.severity": "high",
                    "@timestamp": "2026-08-30T21:14:02Z"}}
            ]}
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args([
            "alerts",
            "close",
            "--query",
            r#"{"term":{"kibana.alert.rule.rule_id":"r-1"}}"#,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Close alerts matching query"), "{err}");
    assert!(err.contains("matched now: 42"), "{err}");
    assert!(err.contains("advisory"), "{err}");
}

/// Both forms at once must be rejected by `clap`'s `conflicts_with`; neither
/// form is now a `clap`-level `required_unless_present` refusal (exit 2,
/// usage text), not the adapter's own message (finding 1).
#[tokio::test]
async fn ids_and_query_are_mutually_exclusive_and_one_is_required() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), "http://127.0.0.1:1");

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["alerts", "close", "a1", "--query", "{}"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "both forms at once must be refused");

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["alerts", "close"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "neither form must be refused by clap: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--query") || err.to_ascii_lowercase().contains("alert_ids"),
        "{err}"
    );
}

#[tokio::test]
async fn tag_and_assign_dry_runs_preview_edits() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(one_open_alert()))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args([
            "alerts", "tag", "a1", "--add", "triaged", "--remove", "noise",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Tag 1 alert"), "{err}");
    assert!(err.contains("+triaged") && err.contains("-noise"), "{err}");

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["alerts", "assign", "a1", "--add", "uid:u_1"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Assign 1 alert"), "{err}");
    assert!(err.contains("add uid:u_1 -> u_1"), "{err}");
}

/// `ack` and `open` dispatch different status values from main.rs; a
/// copy-paste swap in the dispatched status would silently preview the
/// wrong verb in the banner while still exiting 0.
#[tokio::test]
async fn ack_and_open_dry_runs_preview_the_correct_verb() {
    for (subcommand, expected) in [("ack", "Acknowledge 1 alert"), ("open", "Open 1 alert")] {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(dir.path(), &server.uri());
        Mock::given(method("POST"))
            .and(path("/api/detection_engine/signals/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(one_open_alert()))
            .mount(&server)
            .await;
        // No mock for signals/status: a dry run that POSTs there fails the
        // test with a 404-driven non-zero exit.

        let out = bin()
            .args(["--config", cfg.to_str().unwrap(), "--json"])
            .args(["alerts", subcommand, "a1"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{subcommand}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(expected), "{subcommand}: {err}");
    }
}

/// `--conflicts` names a version-conflict policy for the server-side
/// update-by-query the `--query` form runs; explicit ids resolve and
/// transition individually, so passing it there must be refused, not
/// silently ignored (it would otherwise apply the opposite of `proceed` with
/// no diagnostic, since `status_by_ids` sends no `conflicts` key at all).
#[tokio::test]
async fn conflicts_is_rejected_on_ids_and_applied_on_query() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), "http://127.0.0.1:1");

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["alerts", "close", "a1", "--conflicts", "proceed"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "an explicit --conflicts on the ids form must be refused"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--conflicts") && err.contains("--query"),
        "{err}"
    );

    let server = MockServer::start().await;
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 42, "relation": "eq"}, "hits": [
                {"_id": "a1", "_source": {"kibana.alert.rule.name": "Alpha"}}
            ]}
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/status"))
        .and(body_partial_json(json!({"conflicts": "proceed"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 42, "updated": 42, "version_conflicts": 0, "noops": 0, "failures": []
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json", "--yes"])
        .args([
            "alerts",
            "close",
            "--query",
            r#"{"term":{"kibana.alert.rule.rule_id":"r-1"}}"#,
            "--conflicts",
            "proceed",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["applied"], json!(true));
    assert_eq!(report["updated"], json!(42));
}

/// Finding 12: `--limit`'s help text says "default 100" unconditionally,
/// but that default only applies to the bounded peek — the `--out` export
/// path is uncapped unless `--limit` is passed explicitly. The help text
/// must not claim a default that does not hold on that path.
#[test]
fn alerts_list_help_does_not_claim_a_universal_default_limit() {
    let out = bin().args(["alerts", "list", "--help"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("default 100"),
        "the --out path is uncapped, not defaulted to 100: {text}"
    );
}

/// `alerts list --out` must match `search dsl --out`: JSONL by default, and
/// `--limit` respected during export, not just the bounded peek.
#[tokio::test]
async fn alerts_list_out_writes_jsonl_by_default_and_honors_limit() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    let out_path = dir.path().join("results.ndjson");

    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 2, "relation": "eq"}, "hits": [
                {"_id": "a1", "_source": {"kibana.alert.rule.name": "Alpha"}},
                {"_id": "a2", "_source": {"kibana.alert.rule.name": "Beta"}}
            ]}
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["alerts", "list", "--out"])
        .arg(&out_path)
        .args(["--limit", "1"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = fs::read_to_string(&out_path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "{text}");
    assert!(
        lines[0].starts_with('{') && lines[0].ends_with('}'),
        "{text}"
    );
    assert!(
        lines[0].contains("\"kibana.alert.rule.name\":\"Alpha\""),
        "{text}"
    );
}
