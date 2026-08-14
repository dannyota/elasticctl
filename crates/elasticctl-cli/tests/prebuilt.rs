//! The prebuilt commands end to end: argument handling, the guard, and render.

use assert_cmd::Command;
use elasticctl_api_test_support::MockStack;
use serde_json::json;

mod common;
use common::profile_args;

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

/// `status` reports every measured field, including the customized count read
/// from a filtered `_find`.
#[tokio::test]
async fn status_reports_every_measured_count() {
    let stack = MockStack::with_prebuilt_status(
        json!({
            "rules_custom_installed": 0,
            "rules_installed": 2066,
            "rules_not_installed": 5,
            "rules_not_updated": 7,
            "timelines_installed": 10,
            "timelines_not_installed": 1,
            "timelines_not_updated": 2
        }),
        3,
    )
    .await;
    let dir = tempfile::tempdir().unwrap();

    let out = bin()
        .args(profile_args(dir.path(), &stack))
        .args(["rules", "prebuilt", "status", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["installed"], 2066);
    assert_eq!(v["not_installed"], 5);
    assert_eq!(v["not_updated"], 7);
    assert_eq!(v["custom_installed"], 0);
    assert_eq!(v["customized"], 3);
    assert_eq!(v["timelines_installed"], 10);
    assert_eq!(v["timelines_not_installed"], 1);
    assert_eq!(v["timelines_not_updated"], 2);
}

/// Without `--yes`, `install` previews on stderr and issues no write.
#[tokio::test]
async fn install_dry_run_previews_both_counts_and_writes_nothing() {
    let stack = MockStack::with_prebuilt_status(
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
    )
    .await;
    let dir = tempfile::tempdir().unwrap();

    let out = bin()
        .args(profile_args(dir.path(), &stack))
        .args(["rules", "prebuilt", "install", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("[DRY RUN]"), "{err}");
    assert!(err.contains("11"), "the preview must name installs: {err}");
    assert!(err.contains("4"), "and updates, in the same call: {err}");

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["applied"], false);
    assert!(
        stack.write_paths().await.is_empty(),
        "a dry run must not write"
    );
}

/// With `--yes`, `install` issues exactly one PUT and reports its counts.
#[tokio::test]
async fn install_apply_issues_one_put_and_reports_the_outcome() {
    let stack = MockStack::with_prebuilt_install(
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
    .await;
    let dir = tempfile::tempdir().unwrap();

    let out = bin()
        .args(profile_args(dir.path(), &stack))
        .args(["rules", "prebuilt", "install", "--yes", "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.starts_with("Applying:"), "{err}");

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["applied"], true);
    assert_eq!(v["rules_installed"], 11);
    assert_eq!(v["rules_updated"], 4);
    assert_eq!(v["timelines_installed"], 1);
    assert_eq!(v["timelines_updated"], 2);

    let writes = stack.write_paths().await;
    assert_eq!(writes.len(), 1, "{writes:?}");
    assert!(writes[0].ends_with("/api/detection_engine/rules/prepackaged"));
}
