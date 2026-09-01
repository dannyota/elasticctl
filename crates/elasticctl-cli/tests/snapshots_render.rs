//! Rendered output is a contract. The original baselines were committed before
//! the 0.2 retrofit, so they guarded the move into `-api`.
//!
//! If a snapshot fails, rendered output changed. Fix the code. Do not accept
//! the new snapshot unless the spec changed in the same commit.

use assert_cmd::Command;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

mod common;
use common::{config_for, profile_args};
use elasticctl_api_test_support::MockStack;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The rules `with_rules` seeds, in the `elasticctl-sample` marker style every
/// live test uses.
fn sample_rules() -> Vec<Value> {
    vec![
        json!({
            "rule_id": "elasticctl-sample-a",
            "name": "elasticctl sample A",
            "type": "query",
            "language": "kuery",
            "query": "event.category:process",
            "index": ["logs-*"],
            "severity": "low",
            "risk_score": 21,
            "enabled": true,
            "tags": ["elasticctl-sample"]
        }),
        json!({
            "rule_id": "elasticctl-sample-b",
            "name": "elasticctl sample B",
            "type": "query",
            "language": "kuery",
            "query": "event.category:network",
            "index": ["logs-*"],
            "severity": "high",
            "risk_score": 73,
            "enabled": false,
            "tags": ["elasticctl-sample"]
        }),
    ]
}

/// Representative report-rendering commands and formats.
/// `rules export` without `--out` is excluded on purpose: its stdout is the
/// rule file, not a report (spec 6.2), and `tests/rules_io.rs` covers it.
const CASES: &[(&str, &[&str])] = &[
    ("rules_list_table", &["rules", "list"]),
    ("rules_list_json", &["rules", "list", "--json"]),
    ("rules_list_csv", &["rules", "list", "--format", "csv"]),
    ("rules_list_jsonl", &["rules", "list", "--format", "jsonl"]),
    (
        "rules_list_fields",
        &["rules", "list", "--fields", "rule_id,name"],
    ),
    (
        "rules_get_json",
        &["rules", "get", "elasticctl-sample-a", "--json"],
    ),
    (
        "rules_validate_json",
        &["rules", "validate", "--path", "FIXTURE_RULE_FILE", "--json"],
    ),
    ("info_json", &["info", "--json"]),
    ("doctor_json", &["doctor", "--json"]),
    (
        "state_diff_json",
        &["state", "diff", "--dir", "FIXTURE_DIR", "--json"],
    ),
    (
        "state_diff_scoped_json",
        &[
            "state",
            "diff",
            "elasticctl-sample-a",
            "--dir",
            "FIXTURE_DIR",
            "--json",
        ],
    ),
];

/// The mock server binds an ephemeral port, which would change every run. Pin
/// it so `info` and `doctor` snapshots do not read as drift.
const PORT_FILTER: (&str, &str) = (r"127\.0\.0\.1:\d+", "127.0.0.1:<port>");

/// Replace the path placeholders with their real values.
fn substitute(arg: &str, mirror: &Path, rule_file: &Path) -> String {
    match arg {
        "FIXTURE_DIR" => mirror.to_string_lossy().into_owned(),
        "FIXTURE_RULE_FILE" => rule_file.to_string_lossy().into_owned(),
        other => other.to_string(),
    }
}

/// Write the sample rules into a `rules/` directory so `state diff` compares
/// an equal local and remote state and reports a clean diff.
fn fixture_mirror(rules: &[Value]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    for rule in rules {
        let id = rule["rule_id"].as_str().unwrap();
        std::fs::write(
            rules_dir.join(format!("{id}.ndjson")),
            format!("{}\n", serde_json::to_string(rule).unwrap()),
        )
        .unwrap();
    }
    dir
}

/// Write one sparse rule so `rules validate` reports a non-empty
/// `defaults_applied`.
fn fixture_rule_file(dir: &Path) -> PathBuf {
    let path = dir.join("sparse.ndjson");
    std::fs::write(
        &path,
        "{\"rule_id\":\"elasticctl-sample-sparse\",\"name\":\"elasticctl sample sparse\",\"type\":\"query\"}\n",
    )
    .unwrap();
    path
}

#[tokio::test]
async fn rendered_output_is_stable() {
    let dir = tempfile::tempdir().unwrap();
    let mirror = fixture_mirror(&sample_rules());
    let rule_file = fixture_rule_file(dir.path());
    let stack = MockStack::with_rules(sample_rules()).await;

    for (name, args) in CASES {
        let out = Command::cargo_bin("elasticctl")
            .unwrap()
            .args(profile_args(dir.path(), &stack))
            .args(
                args.iter()
                    .map(|a| substitute(a, mirror.path(), &rule_file)),
            )
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let rendered = String::from_utf8(out.stdout).unwrap();
        insta::with_settings!({filters => vec![PORT_FILTER]}, {
            insta::assert_snapshot!(*name, rendered);
        });
    }
}

/// Two alert hits with overlapping-but-unequal dotted `kibana.alert.*` key
/// sets: `a1` carries `reason`, which `a2` lacks; `a2` carries
/// `workflow_tags`, which `a1` lacks. `render::table`'s column set comes
/// from the *first* row only (`columns()` in `render.rs`), so this pins two
/// things at once: a later row's missing key renders as a blank cell, and a
/// later row's *extra* key never gets a column at all — it silently drops
/// from the table output. `--json` renders every hit's full `_source`
/// regardless, so the two formats' snapshots are the contrast that shows the
/// table behavior is table-specific, not a data problem.
///
/// Hand-built wiremock bodies, matching this suite's alerts/cases CLI test
/// convention (`crates/elasticctl-cli/tests/alerts.rs`), not `MockStack`:
/// `alerts list` needs no capability probe, so the plain
/// `signals/search` mock is enough.
fn alert_hits_with_uneven_keys() -> Value {
    json!({
        "hits": {
            "total": {"value": 2, "relation": "eq"},
            "hits": [
                {"_id": "a1", "_source": {
                    "kibana.alert.rule.name": "Suspicious PowerShell Execution",
                    "kibana.alert.severity": "high",
                    "kibana.alert.workflow_status": "open",
                    "kibana.alert.reason": "powershell.exe spawned an encoded command"
                }},
                {"_id": "a2", "_source": {
                    "kibana.alert.rule.name": "Rare DNS Tunnel",
                    "kibana.alert.severity": "medium",
                    "kibana.alert.workflow_status": "acknowledged",
                    "kibana.alert.workflow_tags": ["triaged"]
                }}
            ]
        }
    })
}

#[tokio::test]
async fn alerts_list_table_and_json_render_uneven_keys_differently() {
    for (name, args) in [
        (
            "alerts_list_table",
            ["alerts", "list", "--format", "table"].as_slice(),
        ),
        ("alerts_list_json", ["alerts", "list", "--json"].as_slice()),
    ] {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_for(dir.path(), &server.uri());
        Mock::given(method("POST"))
            .and(path("/api/detection_engine/signals/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(alert_hits_with_uneven_keys()))
            .mount(&server)
            .await;

        let out = Command::cargo_bin("elasticctl")
            .unwrap()
            .args(["--config", cfg.to_str().unwrap()])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let rendered = String::from_utf8(out.stdout).unwrap();
        insta::assert_snapshot!(name, rendered);
    }
}

/// Two cases with an unequal optional-field set (one carries `severity` and
/// a comment count, the other neither) over `cases list --format table`.
/// `case_row` inserts its optional fields conditionally and `render::columns`
/// derives the column set from the first row alone, so the columns here are
/// exactly the first case's keys: `severity`/`comments`/`created_at` appear
/// because case 1 carries them, and `updated_at` is absent because case 1
/// does not — a second case's extra optional would not add a column at all.
/// The snapshot pins that current behavior; it is not immunity to a dropped
/// column.
#[tokio::test]
async fn cases_list_table_renders_two_cases_with_uneven_optional_fields() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cases": [
                {"id": "c1", "version": "WzEsMV0=", "title": "Suspicious activity",
                 "status": "open", "severity": "high", "tags": ["triage"],
                 "totalComment": 2, "created_at": "2026-08-30T21:14:02.000Z"},
                {"id": "c2", "version": "WzIsMV0=", "title": "Follow-up review",
                 "status": "closed", "tags": []}
            ],
            "page": 1, "per_page": 100, "total": 2
        })))
        .mount(&server)
        .await;

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["cases", "list", "--format", "table"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rendered = String::from_utf8(out.stdout).unwrap();
    insta::assert_snapshot!("cases_list_table", rendered);
}

/// Verify that the request recorder observes writes and ignores reads.
#[tokio::test]
async fn the_harness_records_a_write_and_ignores_a_read() {
    let stack = MockStack::with_rules(vec![]).await;

    // A read issues only GETs, none of which are writes.
    elasticctl_api::rules::find_all(stack.transport(), &Default::default())
        .await
        .unwrap();
    assert!(stack.write_paths().await.is_empty(), "a GET is not a write");

    // A write is recorded even though no mock answers it: the server logs the
    // request regardless of the 404 it returns.
    let _ = stack
        .transport()
        .post(
            "/api/detection_engine/rules",
            Some(&json!({"rule_id": "x"})),
        )
        .await;
    assert_eq!(
        stack.write_paths().await,
        vec!["POST /api/detection_engine/rules".to_string()],
        "a POST must be recorded"
    );
}
