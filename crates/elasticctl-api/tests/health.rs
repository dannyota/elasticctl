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
