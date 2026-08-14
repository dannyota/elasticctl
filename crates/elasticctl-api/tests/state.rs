//! The state engine's contract, independent of the CLI.

use elasticctl_api::state::{self, StackIdentity};
use elasticctl_api_test_support::MockStack;
use serde_json::json;
use std::path::Path;

fn identity() -> StackIdentity {
    StackIdentity {
        profile: "test".into(),
        host: "kb.example.com".into(),
        space: "default".into(),
    }
}

fn write_local_rule(dir: &Path, id: &str, body: &str) {
    let rules = dir.join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(rules.join(format!("{id}.ndjson")), body).unwrap();
}

/// A stack seeded with one remote rule that the local mirror does not contain,
/// so the test's local rule reads as a planned create.
async fn mock_stack_with_one_rule() -> MockStack {
    MockStack::with_rules(vec![json!({
        "rule_id": "seed",
        "name": "Seed",
        "type": "query",
    })])
    .await
}

/// The dry-run default is structural: planning must not mutate.
#[tokio::test]
async fn plan_push_sends_no_write_request() {
    let stack = mock_stack_with_one_rule().await;
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "a",
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\"}\n",
    );

    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
        .await
        .unwrap();

    assert_eq!(plan.summary.pending, 1, "the create is planned");
    assert!(!plan.summary.applied, "planning is not applying");
    assert!(
        stack.write_requests().await.is_empty(),
        "plan_push must issue no POST, PUT, PATCH, or DELETE"
    );
    assert_eq!(
        plan.report.profile, "test",
        "the report carries the profile"
    );
    assert_eq!(plan.report.host, "kb.example.com");
    assert_eq!(plan.report.space, "default");
}

/// An Added change applies as one create request.
#[tokio::test]
async fn apply_push_issues_a_create_for_an_added_rule() {
    let stack = MockStack::with_rules(vec![]).await;
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "a",
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\"}\n",
    );

    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
        .await
        .unwrap();
    assert_eq!(plan.summary.pending, 1);

    state::apply_push(stack.transport(), plan).await.unwrap();

    assert_eq!(
        stack.write_paths().await,
        vec!["POST /api/detection_engine/rules".to_string()],
        "an Added change issues one create request"
    );
}

/// A Modified change applies as one update request.
#[tokio::test]
async fn apply_push_issues_an_update_for_a_modified_rule() {
    let stack = MockStack::with_rules(vec![json!({
        "rule_id": "a",
        "name": "A",
        "type": "query",
        "risk_score": 21,
        "severity": "low",
    })])
    .await;
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "a",
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\",\"risk_score\":99,\"severity\":\"low\"}\n",
    );

    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
        .await
        .unwrap();
    assert_eq!(plan.summary.pending, 1);

    state::apply_push(stack.transport(), plan).await.unwrap();

    assert_eq!(
        stack.write_paths().await,
        vec!["PUT /api/detection_engine/rules".to_string()],
        "a Modified change issues one update request"
    );
}

/// Push never deletes: a remote-only rule is reported but not written.
#[tokio::test]
async fn apply_push_issues_no_request_for_a_remote_only_rule() {
    let stack = MockStack::with_rules(vec![json!({
        "rule_id": "remote",
        "name": "Remote",
        "type": "query",
    })])
    .await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("rules")).unwrap();

    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
        .await
        .unwrap();
    assert_eq!(plan.summary.skipped_remote_only, 1);

    state::apply_push(stack.transport(), plan).await.unwrap();

    assert!(
        stack.write_requests().await.is_empty(),
        "push never deletes a remote-only rule"
    );
}

/// A per-rule failure lands in that entry's error and the loop continues.
#[tokio::test]
async fn apply_push_records_a_per_rule_failure_and_continues() {
    let stack = MockStack::with_rules(vec![]).await;
    let dir = tempfile::tempdir().unwrap();
    for id in ["a", "b"] {
        write_local_rule(
            dir.path(),
            id,
            &format!("{{\"rule_id\":\"{id}\",\"name\":\"{id}\",\"type\":\"query\"}}\n"),
        );
    }

    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
        .await
        .unwrap();
    assert_eq!(plan.summary.pending, 2);

    let applied = state::apply_push(stack.transport(), plan).await.unwrap();

    // The mock answers no POST, so each create fails; both must be attempted.
    assert_eq!(
        stack.write_paths().await.len(),
        2,
        "the loop must continue after a per-rule failure"
    );
    assert_eq!(applied.summary.failed, 2);
    assert!(
        applied.summary.pending == 0,
        "nothing is left pending after apply"
    );
    assert!(
        applied.report.entries.iter().all(|e| e.error.is_some()),
        "every failed create records an error"
    );
}
