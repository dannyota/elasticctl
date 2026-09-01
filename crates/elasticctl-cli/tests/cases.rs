use assert_cmd::Command;
use serde_json::json;
use std::fs;
use wiremock::matchers::{method, path, query_param};
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

fn case_body(id: &str, status: &str) -> serde_json::Value {
    json!({
        "id": id, "version": "WzEsMV0=", "title": "Suspicious activity",
        "status": status, "severity": "high", "tags": ["t1"],
        "created_at": "2026-01-01T00:00:00.000Z", "totalComment": 1
    })
}

/// Finding 12: same as alerts list — `--limit`'s help text must not claim a
/// universal default that does not hold on the uncapped `--out` path.
#[test]
fn cases_list_help_does_not_claim_a_universal_default_limit() {
    let out = bin().args(["cases", "list", "--help"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("default 100"),
        "the --out path is uncapped, not defaulted to 100: {text}"
    );
    assert!(
        text.contains("--out is uncapped"),
        "the help says so positively, not just by omission: {text}"
    );
}

#[tokio::test]
async fn cases_list_renders_compact_rows_and_passes_filters() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .and(query_param("status", "open"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cases": [case_body("c1", "open")], "page": 1, "per_page": 100, "total": 1
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["cases", "list", "--status", "open"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows[0]["id"], json!("c1"));
    assert_eq!(rows[0]["title"], json!("Suspicious activity"));
    assert_eq!(rows[0]["comments"], json!(1));
    assert!(
        rows[0].get("version").is_none(),
        "the compact row hides plumbing fields"
    );
}

#[tokio::test]
async fn cases_get_returns_the_full_case() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("GET"))
        .and(path("/api/cases/c1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c1", "open")))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["cases", "get", "c1"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["id"], json!("c1"));
    assert_eq!(
        doc["version"],
        json!("WzEsMV0="),
        "get returns the full case, version included"
    );
}

/// `cases list --out` must match `alerts list --out` and `search dsl --out`:
/// JSONL by default, and `--limit` respected during export, not just the
/// bounded peek.
#[tokio::test]
async fn cases_list_out_writes_jsonl_by_default_and_honors_limit() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    let out_path = dir.path().join("results.ndjson");

    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cases": [case_body("c1", "open"), case_body("c2", "open")],
            "page": 1, "per_page": 100, "total": 2
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["cases", "list", "--out"])
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
    assert!(lines[0].contains("\"id\":\"c1\""), "{text}");
}

#[tokio::test]
async fn a_delete_dry_run_names_titles_and_changes_nothing() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("GET"))
        .and(path("/api/cases/c1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c1", "open")))
        .mount(&server)
        .await;
    // No DELETE mock: a dry run that reaches the route fails the test.

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["cases", "delete", "c1"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("[DRY RUN]"), "{err}");
    assert!(err.contains("Delete 1 case permanently"), "{err}");
    assert!(
        err.contains("Suspicious activity"),
        "the preview names the title: {err}"
    );
    assert!(err.contains("Pass --yes to apply."), "{err}");
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["applied"], json!(false));
}

/// The same case id passed twice must collapse to one resolved case: the
/// dry-run stub reports the resolved count the preview names, not the raw
/// argv count (finding I1).
#[tokio::test]
async fn a_close_dry_run_with_a_duplicate_id_reports_the_resolved_count() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("GET"))
        .and(path("/api/cases/c1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c1", "open")))
        .expect(1)
        .mount(&server)
        .await;
    // The `.expect(1)` above proves `c1 c1` deduplicates before resolution.
    // No PATCH mock: a dry run that reaches the route fails the test.

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["cases", "close", "c1", "c1"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("[DRY RUN]"), "{err}");
    assert!(err.contains("Close 1 case"), "{err}");
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["applied"], json!(false));
    assert_eq!(
        report["total"],
        json!(1),
        "the stub must match the preview's resolved count, not the raw argv count: {report}"
    );
}

#[tokio::test]
async fn a_close_with_yes_patches_the_fetched_version() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("GET"))
        .and(path("/api/cases/c1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c1", "open")))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/api/cases"))
        .and(wiremock::matchers::body_json(json!({
            "cases": [{"id": "c1", "version": "WzEsMV0=", "status": "closed"}]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([case_body("c1", "closed")])))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json", "--yes"])
        .args(["cases", "close", "c1"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Applying: Close 1 case"), "{err}");
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["applied"], json!(true));
    assert_eq!(report["updated"], json!(1));
    assert_eq!(report["failed"], json!(0));
}

#[tokio::test]
async fn create_and_comment_and_attach_dry_runs_preview() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("GET"))
        .and(path("/api/cases/c1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c1", "open")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [
                {"_id": "a1", "_index": "idx-a",
                 "_source": {"kibana.alert.rule.name": "Alpha", "kibana.alert.rule.uuid": "ru-1",
                             "kibana.alert.workflow_status": "open"}}
            ]}
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args([
            "cases",
            "create",
            "--title",
            "Incident 7",
            "--assignee",
            "uid:u_9",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Create case 'Incident 7'"), "{err}");
    assert!(err.contains("assign uid:u_9 -> u_9"), "{err}");

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["cases", "comment", "c1", "--message", "checked the host"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Comment on case 'Suspicious activity'"),
        "{err}"
    );

    let out = bin()
        .args(["--config", cfg.to_str().unwrap(), "--json"])
        .args(["cases", "attach", "c1", "--alert", "a1"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Attach 1 alert to case 'Suspicious activity'"),
        "{err}"
    );
}
