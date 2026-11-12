use elasticctl_api::state::{self, StackIdentity};
use elasticctl_api::{Format, RuleSource};
use elasticctl_api_test_support::MockStack;
use elasticctl_core::ErrorKind;
use std::path::Path;

fn make_entry(mirror: &Path, kind: &str) {
    let entry = mirror.join("value-lists");
    match kind {
        "directory" => std::fs::create_dir(&entry).unwrap(),
        "file" => std::fs::write(&entry, b"contents").unwrap(),
        #[cfg(unix)]
        "symlink" => std::os::unix::fs::symlink("missing-target", &entry).unwrap(),
        _ => unreachable!(),
    }
}

async fn refuses(operation: &str, kind: &str) {
    let stack = MockStack::new().await;
    let root = tempfile::tempdir().unwrap();
    let mirror = root.path().join("mirror");
    std::fs::create_dir(&mirror).unwrap();
    make_entry(&mirror, kind);
    let identity = StackIdentity {
        profile: "test".into(),
        host: "localhost".into(),
        space: "default".into(),
    };
    let error = match operation {
        "diff" => state::diff(
            stack.transport(),
            &mirror,
            &[],
            None,
            None,
            RuleSource::Custom,
        )
        .await
        .unwrap_err(),
        "push" => state::plan_push(
            stack.transport(),
            &mirror,
            &[],
            None,
            None,
            RuleSource::Custom,
            &identity,
        )
        .await
        .unwrap_err(),
        "pull" => state::pull(
            stack.transport(),
            &mirror,
            Format::Ndjson,
            &[],
            None,
            None,
            RuleSource::Custom,
        )
        .await
        .unwrap_err(),
        _ => unreachable!(),
    };
    assert_eq!(
        error.kind,
        ErrorKind::Unsupported,
        "{operation} {kind}: {error}"
    );
    assert_eq!(
        error.message,
        "this mirror holds value-lists/, which needs elasticctl 0.10 or later"
    );
    assert!(
        stack.requests().await.is_empty(),
        "{operation} {kind} sent a request"
    );
    let parent: Vec<_> = std::fs::read_dir(root.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(parent, ["mirror"]);
    let entries: Vec<_> = std::fs::read_dir(&mirror)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries, ["value-lists"]);
}

macro_rules! refusal_test {
    ($name:ident, $operation:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() {
            refuses($operation, $kind).await;
        }
    };
}
refusal_test!(diff_directory, "diff", "directory");
refusal_test!(diff_file, "diff", "file");
refusal_test!(push_directory, "push", "directory");
refusal_test!(push_file, "push", "file");
refusal_test!(pull_directory, "pull", "directory");
refusal_test!(pull_file, "pull", "file");
#[cfg(unix)]
refusal_test!(diff_dangling_symlink, "diff", "symlink");
#[cfg(unix)]
refusal_test!(push_dangling_symlink, "push", "symlink");
#[cfg(unix)]
refusal_test!(pull_dangling_symlink, "pull", "symlink");

/// A mirror whose entries cannot be inspected is not treated as a mirror
/// without `value-lists/`: the guard fails closed before any request or file.
#[cfg(unix)]
#[tokio::test]
async fn unreadable_mirror_fails_closed() {
    use std::os::unix::fs::PermissionsExt;
    for operation in ["diff", "push", "pull"] {
        let stack = MockStack::new().await;
        let root = tempfile::tempdir().unwrap();
        let mirror = root.path().join("mirror");
        std::fs::create_dir(&mirror).unwrap();
        std::fs::set_permissions(&mirror, std::fs::Permissions::from_mode(0o600)).unwrap();
        if std::fs::symlink_metadata(mirror.join("value-lists")).is_ok()
            || std::fs::symlink_metadata(mirror.join("value-lists"))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        {
            // Permissions are not enforced here (for example, as root).
            std::fs::set_permissions(&mirror, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let identity = StackIdentity {
            profile: "test".into(),
            host: "localhost".into(),
            space: "default".into(),
        };
        let error = match operation {
            "diff" => state::diff(
                stack.transport(),
                &mirror,
                &[],
                None,
                None,
                RuleSource::Custom,
            )
            .await
            .unwrap_err(),
            "push" => state::plan_push(
                stack.transport(),
                &mirror,
                &[],
                None,
                None,
                RuleSource::Custom,
                &identity,
            )
            .await
            .unwrap_err(),
            _ => state::pull(
                stack.transport(),
                &mirror,
                Format::Ndjson,
                &[],
                None,
                None,
                RuleSource::Custom,
            )
            .await
            .unwrap_err(),
        };
        std::fs::set_permissions(&mirror, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(error.kind, ErrorKind::Error, "{operation}: {error}");
        assert!(
            error
                .message
                .starts_with("checking the mirror for value-lists/: "),
            "{operation}: {error}"
        );
        assert!(
            stack.requests().await.is_empty(),
            "{operation} sent a request"
        );
        let parent: Vec<_> = std::fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(parent, ["mirror"], "{operation} created a file");
        assert_eq!(std::fs::read_dir(&mirror).unwrap().count(), 0);
    }
}
