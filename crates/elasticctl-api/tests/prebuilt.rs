//! The prebuilt vertical's contract, independent of the CLI.

use elasticctl_api::prebuilt;
use elasticctl_api_test_support::MockStack;
use serde_json::json;

/// Measured 2026-08-14, verbatim.
const STATUS_BODY: &str = r#"{"rules_custom_installed":0,"rules_installed":2066,
"rules_not_installed":0,"rules_not_updated":0,"timelines_installed":10,
"timelines_not_installed":0,"timelines_not_updated":0}"#;

async fn mock_prebuilt_status(body: &str, customized: u64) -> MockStack {
    MockStack::with_prebuilt_status(serde_json::from_str(body).unwrap(), customized).await
}

async fn mock_prebuilt_install() -> MockStack {
    MockStack::with_prebuilt_install(
        json!({
            "rules_custom_installed": 0,
            "rules_installed": 2000,
            "rules_not_installed": 11,
            "rules_not_updated": 4,
            "timelines_installed": 10,
            "timelines_not_installed": 0,
            "timelines_not_updated": 0
        }),
        0,
        json!({
            "rules_installed": 11,
            "rules_updated": 4,
            "timelines_installed": 1,
            "timelines_updated": 2
        }),
    )
    .await
}

/// The `customized` count is read from a filtered `_find`. This assertion does
/// not depend on the mock honouring that filter: `MockStack`'s `_find` serves
/// whatever `customized` it was seeded with, for any query.
#[tokio::test]
async fn status_maps_the_measured_body() {
    let stack = mock_prebuilt_status(STATUS_BODY, 0).await;
    let s = prebuilt::status(stack.transport()).await.unwrap();
    assert_eq!(s.installed, 2066);
    assert_eq!(s.not_installed, 0);
    assert_eq!(s.not_updated, 0);
    assert_eq!(s.custom_installed, 0);
    assert_eq!(s.customized, 0);
    assert_eq!(s.timelines_installed, 10);
    assert_eq!(s.timelines_not_installed, 0);
    assert_eq!(s.timelines_not_updated, 0);
}

/// Spec 4.6: the preview is client-computed because the route has no dry_run.
#[tokio::test]
async fn the_install_preview_names_both_counts_and_writes_nothing() {
    let body = r#"{"rules_custom_installed":0,"rules_installed":2000,
"rules_not_installed":11,"rules_not_updated":4,"timelines_installed":10,
"timelines_not_installed":0,"timelines_not_updated":0}"#;
    let stack = mock_prebuilt_status(body, 0).await;
    let (plan, _) = prebuilt::plan_install(stack.transport()).await.unwrap();

    let text = plan.preview_details.join(" ");
    assert!(
        text.contains("11"),
        "the preview must name installs: {text}"
    );
    assert!(
        text.contains('4'),
        "and updates, which happen in the same call: {text}"
    );
    assert!(
        stack.write_requests().await.is_empty(),
        "planning must issue no write request"
    );
}

/// The release's one trap: a status with nothing missing but rules outdated
/// must not preview as "nothing to do". Both counts are named, always.
#[tokio::test]
async fn the_preview_names_updates_even_when_nothing_is_missing() {
    let body = r#"{"rules_custom_installed":0,"rules_installed":2066,
"rules_not_installed":0,"rules_not_updated":11,"timelines_installed":10,
"timelines_not_installed":0,"timelines_not_updated":0}"#;
    let stack = mock_prebuilt_status(body, 0).await;
    let (plan, _) = prebuilt::plan_install(stack.transport()).await.unwrap();

    assert_eq!(
        plan.preview_action,
        "Install 0 missing and update 11 outdated prebuilt rule(s)"
    );
}

/// Spec 4.6: one verb, because the route is one call that does both.
#[tokio::test]
async fn install_issues_exactly_one_put() {
    let stack = mock_prebuilt_install().await;
    let outcome = prebuilt::apply_install(stack.transport()).await.unwrap();
    assert!(outcome.applied);
    assert_eq!(outcome.rules_installed, 11);
    assert_eq!(outcome.rules_updated, 4);
    assert_eq!(outcome.timelines_installed, 1);
    assert_eq!(outcome.timelines_updated, 2);

    let writes = stack.write_paths().await;
    assert_eq!(writes.len(), 1, "{writes:?}");
    assert!(writes[0].ends_with("/api/detection_engine/rules/prepackaged"));
}
