//! The prebuilt vertical's contract, independent of the CLI.

use std::collections::BTreeMap;

use elasticctl_api::prebuilt;
use elasticctl_api_test_support::MockStack;
use elasticctl_core::ErrorKind;
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
/// not depend on the mock honoring that filter: `MockStack`'s `_find` serves
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

#[tokio::test]
async fn status_rejects_each_missing_or_non_numeric_measured_counter() {
    let valid: serde_json::Value = serde_json::from_str(STATUS_BODY).unwrap();
    for field in [
        "rules_installed",
        "rules_custom_installed",
        "rules_not_installed",
        "rules_not_updated",
        "timelines_installed",
        "timelines_not_installed",
        "timelines_not_updated",
    ] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        let stack = MockStack::with_prebuilt_status(missing, 0).await;
        let err = prebuilt::status(stack.transport()).await.unwrap_err();
        assert_eq!(err.kind, ErrorKind::Http, "missing {field}: {err}");
        assert!(
            err.message
                .contains("/api/detection_engine/rules/prepackaged/_status")
                && err.message.contains(field),
            "missing {field}: {err}"
        );

        let mut mistyped = valid.clone();
        mistyped[field] = json!("not a number");
        let stack = MockStack::with_prebuilt_status(mistyped, 0).await;
        let err = prebuilt::status(stack.transport()).await.unwrap_err();
        assert_eq!(err.kind, ErrorKind::Http, "mistyped {field}: {err}");
        assert!(
            err.message
                .contains("/api/detection_engine/rules/prepackaged/_status")
                && err.message.contains(field),
            "mistyped {field}: {err}"
        );
    }
}

#[tokio::test]
async fn malformed_status_wins_over_the_dependent_customized_count_request() {
    let mut malformed: serde_json::Value = serde_json::from_str(STATUS_BODY).unwrap();
    malformed.as_object_mut().unwrap().remove("rules_installed");
    let stack = MockStack::with_prebuilt_status_and_failing_find(malformed).await;

    let err = prebuilt::status(stack.transport()).await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Http);
    assert!(
        err.message
            .contains("/api/detection_engine/rules/prepackaged/_status")
            && err.message.contains("rules_installed"),
        "{err}"
    );

    let requests = stack.requests().await;
    assert_eq!(requests.len(), 1, "{requests:#?}");
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].path,
        "/api/detection_engine/rules/prepackaged/_status"
    );
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

#[tokio::test]
async fn install_rejects_each_missing_or_non_numeric_measured_counter() {
    let status: serde_json::Value = serde_json::from_str(STATUS_BODY).unwrap();
    let valid = json!({
        "rules_installed": 11,
        "rules_updated": 4,
        "timelines_installed": 1,
        "timelines_updated": 2
    });
    for field in [
        "rules_installed",
        "rules_updated",
        "timelines_installed",
        "timelines_updated",
    ] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        let stack = MockStack::with_prebuilt_install(status.clone(), 0, missing).await;
        let err = prebuilt::apply_install(stack.transport())
            .await
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Http, "missing {field}: {err}");
        assert!(
            err.message
                .contains("/api/detection_engine/rules/prepackaged")
                && err.message.contains(field),
            "missing {field}: {err}"
        );

        let mut mistyped = valid.clone();
        mistyped[field] = json!("not a number");
        let stack = MockStack::with_prebuilt_install(status.clone(), 0, mistyped).await;
        let err = prebuilt::apply_install(stack.transport())
            .await
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Http, "mistyped {field}: {err}");
        assert!(
            err.message
                .contains("/api/detection_engine/rules/prepackaged")
                && err.message.contains(field),
            "mistyped {field}: {err}"
        );
    }
}

#[tokio::test]
async fn prebuilt_requests_have_the_measured_methods_paths_queries_and_null_body() {
    let stack = mock_prebuilt_install().await;
    prebuilt::status(stack.transport()).await.unwrap();
    prebuilt::apply_install(stack.transport()).await.unwrap();

    let requests = stack.requests().await;
    assert_eq!(requests.len(), 3, "{requests:#?}");

    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].path,
        "/api/detection_engine/rules/prepackaged/_status"
    );
    assert!(requests[0].query.is_empty());

    assert_eq!(requests[1].method, "GET");
    assert_eq!(requests[1].path, "/api/detection_engine/rules/_find");
    assert_eq!(
        requests[1].query,
        BTreeMap::from([
            (
                "filter".to_string(),
                "alert.attributes.params.ruleSource.isCustomized: true".to_string(),
            ),
            ("page".to_string(), "1".to_string()),
            ("per_page".to_string(), "1".to_string()),
        ])
    );

    assert_eq!(requests[2].method, "PUT");
    assert_eq!(requests[2].path, "/api/detection_engine/rules/prepackaged");
    assert!(requests[2].query.is_empty());
    assert_eq!(requests[2].body, serde_json::Value::Null);
    assert_eq!(requests[2].body_text, "null");
}
