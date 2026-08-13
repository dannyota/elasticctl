use assert_cmd::Command;
use std::fs;
use wiremock::matchers::{method, path};
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

/// Serves an export whose rule carries volatile fields and unsorted keys.
async fn exporting_server() -> MockServer {
    let server = MockServer::start().await;
    let body = concat!(
        r#"{"zeta":1,"rule_id":"b","name":"Beta","id":"srv-2","updated_at":"2026-01-01T00:00:00Z"}"#,
        "\n",
        r#"{"zeta":1,"rule_id":"a","name":"Alpha","id":"srv-1","updated_at":"2026-01-01T00:00:00Z"}"#,
        "\n",
        r#"{"exported_count":2,"exported_rules_count":2,"missing_rules_count":0}"#,
        "\n"
    );
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_export"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn export_writes_ndjson_without_volatile_fields() {
    let server = exporting_server().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let out_file = dir.path().join("rules.ndjson");

    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "export", "--config"])
        .arg(&cfg)
        .arg("--out")
        .arg(&out_file)
        .assert()
        .success();

    let body = fs::read_to_string(&out_file).unwrap();
    assert_eq!(
        body.lines().count(),
        2,
        "the trailer is not written back out"
    );
    assert!(
        !body.contains("\"id\":"),
        "volatile id must be stripped: {body}"
    );
    assert!(
        !body.contains("updated_at"),
        "volatile timestamps must be stripped: {body}"
    );
}

#[tokio::test]
async fn export_is_deterministic_across_runs() {
    let server = exporting_server().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let run = |name: &str| {
        let f = dir.path().join(name);
        Command::cargo_bin("elasticctl")
            .unwrap()
            .args(["rules", "export", "--config"])
            .arg(&cfg)
            .arg("--out")
            .arg(&f)
            .assert()
            .success();
        fs::read_to_string(&f).unwrap()
    };

    assert_eq!(
        run("one.ndjson"),
        run("two.ndjson"),
        "two exports must be byte-identical"
    );
}

#[tokio::test]
async fn export_orders_rules_by_rule_id() {
    let server = exporting_server().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let f = dir.path().join("rules.ndjson");

    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "export", "--config"])
        .arg(&cfg)
        .arg("--out")
        .arg(&f)
        .assert()
        .success();

    let body = fs::read_to_string(&f).unwrap();
    let first: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
    assert_eq!(
        first["rule_id"], "a",
        "rules must be sorted by rule_id, not server order"
    );
}

#[tokio::test]
async fn export_yaml_carries_the_same_rules() {
    let server = exporting_server().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let f = dir.path().join("rules.yaml");

    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "export", "--format-file", "yaml", "--config"])
        .arg(&cfg)
        .arg("--out")
        .arg(&f)
        .assert()
        .success();

    let rules = elasticctl_api::codec::decode_yaml(&fs::read_to_string(&f).unwrap()).unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].rule_id().unwrap(), "a");
}

/// A confirmation report, not the rule content, is what belongs on stdout
/// once `--out` has already taken the real file: the report is JSON, not
/// ndjson, and must never point back at some other command's `_export`-only
/// path.
#[tokio::test]
async fn export_with_out_reports_the_count_and_path_without_reprinting_the_file() {
    let server = exporting_server().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let out_file = dir.path().join("rules.ndjson");

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "export", "--json", "--config"])
        .arg(&cfg)
        .arg("--out")
        .arg(&out_file)
        .output()
        .unwrap();
    assert!(out.status.success());

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["exported"], 2);
    assert_eq!(v["path"], out_file.display().to_string());

    // The decisive assertion: the report on stdout must not have clobbered
    // the file --out was actually pointed at.
    let body = fs::read_to_string(&out_file).unwrap();
    assert_eq!(
        body.lines().count(),
        2,
        "the report must not overwrite the exported file: {body}"
    );
}

#[tokio::test]
async fn export_without_out_prints_the_file_body_to_stdout() {
    let server = exporting_server().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "export", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(out.status.success());

    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(!text.contains("updated_at"), "{text}");
}

/// The exported rule content is the payload, not a report. `--format csv`
/// (and every other report format) must not re-encode it — CSV/table column
/// derivation keys off object fields, so a plain string would silently empty.
#[tokio::test]
async fn export_without_out_bypasses_the_report_format_pipeline() {
    let server = exporting_server().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "export", "--format", "csv", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(
        text.lines().all(|l| l.starts_with('{')),
        "stdout must carry NDJSON, not a CSV report: {text}"
    );
    assert!(text.contains("rule_id"), "{text}");
}

/// `--json` governs how a command's *report* is rendered. `rules export`
/// without `--out` has no report — its stdout is the file — so `--json` must
/// not wrap it. Wrapping would make `rules export --json > rules.ndjson`
/// produce a file Kibana cannot import.
#[tokio::test]
async fn export_without_out_emits_raw_ndjson_even_under_json() {
    let server = exporting_server().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "export", "--json", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.lines().count(), 2, "one line per rule: {text}");
    for line in text.lines() {
        let v: serde_json::Value =
            serde_json::from_str(line).expect("every line must be one rule object");
        assert!(v.get("rule_id").is_some(), "{line}");
    }
    assert!(
        !text.contains("\"ndjson\""),
        "the body must not be wrapped in an envelope: {text}"
    );
}

/// The bytes must not depend on the report format at all.
#[tokio::test]
async fn export_to_stdout_is_identical_under_every_report_format() {
    let server = exporting_server().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let run = |extra: &[&str]| {
        let mut cmd = Command::cargo_bin("elasticctl").unwrap();
        cmd.args(["rules", "export", "--config"]).arg(&cfg);
        cmd.args(extra);
        let out = cmd.output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };

    let plain = run(&[]);
    assert_eq!(plain, run(&["--json"]));
    assert_eq!(plain, run(&["--format", "yaml"]));
    assert_eq!(plain, run(&["--format", "csv"]));
}

/// `--format-file` is the flag that does own the on-disk shape, and it still
/// does when the file goes to stdout.
#[tokio::test]
async fn export_to_stdout_honours_format_file_not_format() {
    let server = exporting_server().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args([
            "rules",
            "export",
            "--format-file",
            "yaml",
            "--json",
            "--config",
        ])
        .arg(&cfg)
        .output()
        .unwrap();

    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let rules = elasticctl_api::codec::decode_yaml(&text).expect("stdout must be the YAML file");
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].rule_id().unwrap(), "a");
}

#[tokio::test]
async fn import_is_guarded_and_sends_nothing_on_a_dry_run() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("in.ndjson");
    fs::write(
        &src,
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\"}\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "import", "--json", "--config"])
        .arg(&cfg)
        .arg("--path")
        .arg(&src)
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
            .any(|r| r.url.path().contains("_import")),
        "a dry run must not upload"
    );
}

#[tokio::test]
async fn import_dry_run_reports_total_not_a_differently_named_count() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("in.ndjson");
    fs::write(
        &src,
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\"}\n{\"rule_id\":\"b\",\"name\":\"B\",\"type\":\"query\"}\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "import", "--json", "--config"])
        .arg(&cfg)
        .arg("--path")
        .arg(&src)
        .output()
        .unwrap();

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        v["total"], 2,
        "dry run and apply must share one count field: {v}"
    );
}

#[tokio::test]
async fn yes_uploads_the_ndjson_and_reports_the_outcome() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true, "success_count": 1, "rules_count": 1, "errors": []
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("in.ndjson");
    fs::write(
        &src,
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\"}\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "import", "--yes", "--json", "--config"])
        .arg(&cfg)
        .arg("--path")
        .arg(&src)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["applied"], true);
    assert_eq!(v["succeeded"], 1);
    assert_eq!(v["total"], 1);
    assert!(v["failed"].as_array().unwrap().is_empty());

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let content_type = requests[0]
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        content_type.starts_with("multipart/form-data"),
        "{content_type}"
    );
}

/// Kibana's import response reports per-rule errors, not a `failed` array or
/// count directly. A partial failure must still trip the shared exit-code
/// convention (`render::exit_code_for_value`) rather than reporting success
/// while silently dropping which rules failed.
#[tokio::test]
async fn a_partial_import_failure_exits_non_zero_and_names_the_failed_rule() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "success_count": 1,
            "rules_count": 2,
            "errors": [
                {"rule_id": "b", "error": {"status_code": 409, "message": "already exists"}}
            ]
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("in.ndjson");
    fs::write(
        &src,
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\"}\n{\"rule_id\":\"b\",\"name\":\"B\",\"type\":\"query\"}\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "import", "--yes", "--json", "--config"])
        .arg(&cfg)
        .arg("--path")
        .arg(&src)
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(1),
        "a partial import failure must not exit 0: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("the operator must still get the report, not just the code");
    assert_eq!(v["applied"], true);
    assert_eq!(v["succeeded"], 1);
    assert_eq!(v["total"], 2);
    let failed = v["failed"].as_array().unwrap();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0]["rule_id"], "b");
}
