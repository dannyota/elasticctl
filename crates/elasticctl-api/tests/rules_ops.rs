//! The rules orchestration's contract, independent of the CLI.

use elasticctl_api::rules_ops;
use elasticctl_api_test_support::MockStack;
use serde_json::json;

async fn mock_stack_with_one_rule() -> MockStack {
    MockStack::with_rules(vec![json!({
        "rule_id": "a",
        "name": "Alpha",
        "type": "query",
        "enabled": true,
    })])
    .await
}

/// Planning a disable must not disable anything.
#[tokio::test]
async fn plan_set_enabled_sends_no_write_request() {
    let stack = mock_stack_with_one_rule().await;
    let plan = rules_ops::plan_set_enabled(stack.transport(), &["a".into()], false)
        .await
        .unwrap();
    assert_eq!(plan.targets, vec!["a".to_string()]);
    assert!(
        stack.write_requests().await.is_empty(),
        "planning must issue no write request"
    );
}

/// Planning a delete must not delete anything.
#[tokio::test]
async fn plan_delete_sends_no_write_request() {
    let stack = mock_stack_with_one_rule().await;
    let plan = rules_ops::plan_delete(stack.transport(), &["a".into()])
        .await
        .unwrap();
    assert_eq!(plan.targets, vec!["a".to_string()]);
    assert!(
        stack.write_requests().await.is_empty(),
        "planning must issue no write request"
    );
}

/// Planning an import with `--skip-existing` reads which rules already exist
/// (a GET) but must not write, and must name what would be skipped and leave
/// the skipped rule out of the upload payload.
#[tokio::test]
async fn plan_import_sends_no_write_request_and_names_skips() {
    let stack = mock_stack_with_one_rule().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.ndjson");
    std::fs::write(
        &path,
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\"}\n\
         {\"rule_id\":\"b\",\"name\":\"B\",\"type\":\"query\"}\n",
    )
    .unwrap();

    let plan = rules_ops::plan_import(Some(stack.transport()), &path, false, true)
        .await
        .unwrap();

    assert_eq!(plan.total, 2);
    assert_eq!(plan.preview.targets, vec!["b".to_string()]);
    assert_eq!(plan.skipped.len(), 1);
    assert_eq!(plan.skipped[0]["rule_id"], "a");
    assert!(
        !plan.ndjson.contains("\"rule_id\":\"a\""),
        "a skipped rule must not be uploaded: {}",
        plan.ndjson
    );
    assert!(
        stack.write_requests().await.is_empty(),
        "planning must issue no write request"
    );
}

/// An import whose rules all already exist must not upload anything. The
/// empty NDJSON is reached through the all-skipped path, not passed by hand.
#[tokio::test]
async fn apply_import_of_an_all_skipped_file_uploads_nothing() {
    let stack = mock_stack_with_one_rule().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.ndjson");
    std::fs::write(
        &path,
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\"}\n",
    )
    .unwrap();

    let plan = rules_ops::plan_import(Some(stack.transport()), &path, false, true)
        .await
        .unwrap();
    assert!(plan.ndjson.is_empty(), "the only rule already exists");
    assert_eq!(plan.skipped.len(), 1);

    let report = rules_ops::apply_import(stack.transport(), &plan.ndjson, false)
        .await
        .unwrap();
    assert_eq!(report.succeeded, json!(0));
    assert_eq!(report.failed, json!([]));
    assert!(
        stack.write_requests().await.is_empty(),
        "an all-skipped import must not upload"
    );
}
