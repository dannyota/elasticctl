use elasticctl_api::{RuleSource, state, value_lists as vl};
use serde_json::json;
use std::path::Path;
use wiremock::MockServer;

fn write_pair(root: &Path, id: &str) {
    let directory = root.join("value-lists");
    std::fs::create_dir_all(&directory).unwrap();
    let stem = vl::file_stem(id);
    std::fs::write(
        directory.join(format!("{stem}.yaml")),
        format!("id: {id:?}\ntype: keyword\nname: Synthetic\ndescription: Synthetic\n"),
    )
    .unwrap();
    std::fs::write(directory.join(format!("{stem}.txt")), b"b\r\na\r\na\r\n").unwrap();
}

#[test]
fn mirror_reads_long_non_ascii_case_and_device_ids_with_bounded_distinct_stems() {
    let dir = tempfile::tempdir().unwrap();
    let ids = [
        "A".into(),
        "a".into(),
        "con".into(),
        "nul.txt".into(),
        "é".repeat(100),
        "a".repeat(512),
    ];
    for id in &ids {
        write_pair(dir.path(), id);
    }
    let mirror = state::read_mirror(dir.path()).unwrap();
    assert!(mirror.has_value_lists);
    assert_eq!(mirror.value_lists.len(), ids.len());
    let mut stems = std::collections::BTreeSet::new();
    for pair in mirror.value_lists {
        assert!(ids.contains(&pair.container.id));
        assert!(pair.stem.len() <= 64);
        assert!(stems.insert(pair.stem.to_lowercase()));
        assert_eq!(pair.values, ["a".into(), "b".into()].into());
    }
}

#[tokio::test]
async fn either_half_missing_refuses_diff_and_push_before_any_request() {
    for extension in ["yaml", "txt"] {
        let dir = tempfile::tempdir().unwrap();
        write_pair(dir.path(), "safe");
        std::fs::remove_file(dir.path().join(format!("value-lists/safe.{extension}"))).unwrap();
        let server = MockServer::start().await;
        let t = elasticctl_core::Transport::new(&elasticctl_core::Profile {
            kibana_url: server.uri(),
            es_url: None,
            api_key: Some("synthetic".into()),
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 2,
        })
        .unwrap();
        let error = state::diff(&t, dir.path(), &[], None, None, RuleSource::Custom)
            .await
            .unwrap_err();
        assert!(error.message.contains("missing"));
        let identity = state::StackIdentity {
            profile: "test".into(),
            host: "example.invalid".into(),
            space: "default".into(),
        };
        let error = state::plan_push(
            &t,
            dir.path(),
            &[],
            None,
            None,
            RuleSource::Custom,
            &identity,
        )
        .await
        .unwrap_err();
        assert!(error.message.contains("missing"));
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}

#[test]
fn mirror_rejects_an_invalid_pair_and_mismatched_stem() {
    for (file, body) in [
        (
            "safe.yaml",
            "id: different\ntype: keyword\nname: Synthetic\ndescription: Synthetic\n",
        ),
        ("safe.txt", "\0"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        write_pair(dir.path(), "safe");
        std::fs::write(dir.path().join("value-lists").join(file), body).unwrap();
        assert!(state::read_mirror(dir.path()).is_err());
    }
}

#[test]
fn mirror_rejects_a_file_root_and_directory_entry() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("value-lists"), "invalid").unwrap();
    assert!(
        state::read_mirror(dir.path())
            .unwrap_err()
            .message
            .contains("not a real directory")
    );
    std::fs::remove_file(dir.path().join("value-lists")).unwrap();
    std::fs::create_dir_all(dir.path().join("value-lists/safe.txt")).unwrap();
    assert!(
        state::read_mirror(dir.path())
            .unwrap_err()
            .message
            .contains("not a regular file")
    );
}

#[cfg(unix)]
#[test]
fn mirror_rejects_symlink_roots_and_both_pair_halves() {
    use std::os::unix::fs::symlink;
    let outside = tempfile::tempdir().unwrap();
    write_pair(outside.path(), "safe");
    for target in [
        "value-lists",
        "value-lists/safe.yaml",
        "value-lists/safe.txt",
    ] {
        let dir = tempfile::tempdir().unwrap();
        if target != "value-lists" {
            write_pair(dir.path(), "safe");
            std::fs::remove_file(dir.path().join(target)).unwrap();
        }
        symlink(outside.path().join(target), dir.path().join(target)).unwrap();
        assert!(state::read_mirror(dir.path()).is_err());
    }
}

#[test]
fn mirror_without_value_lists_has_the_legacy_presence_flag() {
    let dir = tempfile::tempdir().unwrap();
    let mirror = state::read_mirror(dir.path()).unwrap();
    assert!(!mirror.has_value_lists);
    assert!(mirror.value_lists.is_empty());
    assert_eq!(
        serde_json::to_value(vl::file_stem("safe")).unwrap(),
        json!("safe")
    );
}
