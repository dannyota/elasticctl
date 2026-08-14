//! The state engine's contract, independent of the CLI.

use elasticctl_api::state;
use elasticctl_api_test_support::MockStack;
use serde_json::json;

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
    std::fs::create_dir_all(dir.path().join("rules")).unwrap();
    std::fs::write(
        dir.path().join("rules/a.ndjson"),
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\"}\n",
    )
    .unwrap();

    let plan = state::plan_push(stack.transport(), dir.path(), &[], None)
        .await
        .unwrap();

    assert_eq!(plan.summary.pending, 1, "the create is planned");
    assert!(!plan.summary.applied, "planning is not applying");
    assert!(
        stack.write_requests().await.is_empty(),
        "plan_push must issue no POST, PUT, PATCH, or DELETE"
    );
}
