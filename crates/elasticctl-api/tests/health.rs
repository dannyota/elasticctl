use elasticctl_api::health::{self, Status};
use elasticctl_api_test_support::MockStack;

#[tokio::test]
async fn doctor_reports_the_value_list_index_as_absent() {
    let stack = MockStack::with_value_lists_absent().await;
    let r = health::doctor(stack.transport()).await.unwrap();
    let check = r
        .checks
        .iter()
        .find(|c| c.name == "value_list_index")
        .unwrap();
    assert_eq!(check.status, Status::Warn);
    assert!(
        check.detail.contains("POST /api/lists/index"),
        "the check must say how to fix it: {}",
        check.detail
    );
}

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

#[tokio::test]
async fn doctor_reports_the_baseline_identity_as_ok() {
    let stack = MockStack::with_rules(vec![]).await;
    let r = health::doctor(stack.transport()).await.unwrap();
    let check = r.checks.iter().find(|c| c.name == "auth").unwrap();
    assert_eq!(check.status, Status::Ok);
}

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

#[tokio::test]
async fn doctor_ignores_malformed_api_key_but_planners_reject_it() {
    let body = serde_json::json!({"username":"review-user","authentication_realm":{"type":"native"},"api_key":{"id":7}});
    let malformed = MockStack::with_identity(body.clone()).await;
    let mut baseline_body = body;
    baseline_body.as_object_mut().unwrap().remove("api_key");
    let baseline = MockStack::with_identity(baseline_body).await;
    let mut expected = health::doctor(baseline.transport()).await.unwrap();
    expected.checks[0].detail = malformed.transport().kibana_url().to_string();
    assert_eq!(
        health::doctor(malformed.transport()).await.unwrap(),
        expected
    );
    let error = health::credential_identity(malformed.transport())
        .await
        .unwrap_err();
    assert_eq!(error.kind, elasticctl_core::ErrorKind::Http);
    assert!(error.message.contains("api_key.id"));
}
