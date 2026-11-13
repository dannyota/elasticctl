use super::*;
use crate::value_lists::{Container, LocalPair, ValueListType};
use serde_json::json;

#[test]
fn pull_collects_every_value_rule_and_exception_collision_before_writing() {
    for existing in [false, true] {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("mirror");
        if existing {
            std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("sentinel"), "unchanged").unwrap();
        }
        let lock = acquire_pull(&root).unwrap();
        let rules = ["rule/a", "rule?a", "rule:a"].map(|id| {
            Rule::from_value(json!({"rule_id": id, "name": id, "type": "query"})).unwrap()
        });
        let exceptions = ["exception/a", "exception?a", "exception:a"]
            .map(|id| {
                let list = ExceptionList::from_value(json!({
                    "list_id": id, "name": id, "type": "detection", "namespace_type": "single"
                }))
                .unwrap();
                (list.key().unwrap(), (list, vec![]))
            })
            .into();
        let values = ["A", "a-559aead08264"].map(|id| LocalPair {
            stem: crate::value_lists::file_stem(id),
            container: Container {
                id: id.into(),
                name: id.into(),
                description: "Synthetic".into(),
                list_type: ValueListType::Keyword,
                meta: None,
            },
            values: ["value".into()].into(),
        });
        let error = write_mirror(&lock, &rules, &exceptions, &values, Format::Yaml).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        for pair in [
            "\"A\" and \"a-559aead08264\"",
            "\"rule/a\" and \"rule?a\"",
            "\"rule/a\" and \"rule:a\"",
            "\"rule?a\" and \"rule:a\"",
            "\"exception/a (single)\" and \"exception:a (single)\"",
            "\"exception/a (single)\" and \"exception?a (single)\"",
            "\"exception:a (single)\" and \"exception?a (single)\"",
        ] {
            assert!(
                error.message.contains(pair),
                "missing {pair}: {}",
                error.message
            );
        }
        assert!(error.message.starts_with("7 filename collision(s)"));
        if existing {
            assert_eq!(
                std::fs::read_to_string(root.join("sentinel")).unwrap(),
                "unchanged"
            );
            assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        } else {
            assert!(!root.exists());
        }
    }
}
