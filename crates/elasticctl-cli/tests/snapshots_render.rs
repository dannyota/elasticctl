//! Rendered output is a contract. These snapshots exist so the 0.2 retrofit
//! can prove it did not change anything a user sees.
//!
//! If a snapshot fails, the retrofit changed output. Fix the code. Do not
//! accept the new snapshot unless the spec changed in the same commit.

use assert_cmd::Command;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

mod common;
use common::profile_args;
use elasticctl_api_test_support::MockStack;

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

/// Every command that renders a report, in every format that reaches render.
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

/// Without this, every "issued no write" assertion in later tasks could pass
/// by recording nothing at all. It must show the recorder sees writes and
/// ignores reads.
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
