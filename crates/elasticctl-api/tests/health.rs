//! The stack-derived `doctor` checks.

use elasticctl_api::health::{self, Status};
use elasticctl_api_test_support::MockStack;

/// Measured fact 21: the data streams do not exist by default, and an
/// exception entry of type `list` cannot work without them.
#[tokio::test]
async fn doctor_reports_the_value_list_index_as_absent() {
    let stack = MockStack::with_value_lists_absent().await;
    let r = health::doctor(stack.transport()).await.unwrap();
    let check = r
        .checks
        .iter()
        .find(|c| c.name == "value_list_index")
        .unwrap();
    // Three-valued: absent data streams are a warning, not a failure. Nothing
    // is broken — the exception entries that need them simply cannot work
    // until `POST /api/lists/index` runs.
    assert_eq!(check.status, Status::Warn);
    assert!(
        check.detail.contains("POST /api/lists/index"),
        "the check must say how to fix it: {}",
        check.detail
    );
}

/// The check reads the route's body, not just its status: a bootstrapped stack
/// reports both indexes and the check passes cleanly.
#[tokio::test]
async fn doctor_reports_the_value_list_index_as_bootstrapped() {
    let stack = MockStack::with_value_lists_bootstrapped().await;
    let r = health::doctor(stack.transport()).await.unwrap();
    let check = r
        .checks
        .iter()
        .find(|c| c.name == "value_list_index")
        .unwrap();
    assert_eq!(check.status, Status::Ok);
}

/// A successful but malformed index response is a failed health check, not
/// evidence that the streams have not been bootstrapped.
#[tokio::test]
async fn doctor_reports_a_malformed_value_list_index_as_failed() {
    let stack = MockStack::with_value_list_index(serde_json::json!({
        "list_index": true
    }))
    .await;
    let r = health::doctor(stack.transport()).await.unwrap();
    let check = r
        .checks
        .iter()
        .find(|c| c.name == "value_list_index")
        .unwrap();
    assert_eq!(check.status, Status::Fail);
    assert!(check.detail.contains("list_item_index"), "{}", check.detail);
}

/// A valid baseline identity passes the auth check cleanly.
#[tokio::test]
async fn doctor_reports_the_baseline_identity_as_ok() {
    let stack = MockStack::with_rules(vec![]).await;
    let r = health::doctor(stack.transport()).await.unwrap();
    let check = r.checks.iter().find(|c| c.name == "auth").unwrap();
    assert_eq!(check.status, Status::Ok);
}

/// A successful but malformed identity response is a failed auth check, not an
/// "unknown" realm that hides the broken response.
#[tokio::test]
async fn doctor_reports_a_malformed_identity_as_failed() {
    let stack = MockStack::with_identity(serde_json::json!({
        "username": "elastic"
    }))
    .await;
    let r = health::doctor(stack.transport()).await.unwrap();
    let check = r.checks.iter().find(|c| c.name == "auth").unwrap();
    assert_eq!(check.status, Status::Fail);
    assert!(
        check.detail.contains("authentication_realm.type"),
        "{}",
        check.detail
    );
}

/// An empty realm string is as broken as a missing one: it must fail, not
/// report an empty realm as a valid authentication source.
#[tokio::test]
async fn doctor_reports_an_empty_identity_realm_as_failed() {
    let stack = MockStack::with_identity(serde_json::json!({
        "username": "elastic",
        "authentication_realm": {"type": ""}
    }))
    .await;
    let r = health::doctor(stack.transport()).await.unwrap();
    let check = r.checks.iter().find(|c| c.name == "auth").unwrap();
    assert_eq!(check.status, Status::Fail);
    assert!(
        check.detail.contains("authentication_realm.type"),
        "{}",
        check.detail
    );
}
