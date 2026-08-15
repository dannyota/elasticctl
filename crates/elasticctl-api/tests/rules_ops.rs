//! The rules orchestration's contract, independent of the CLI.

use elasticctl_api::model::Rule;
use elasticctl_api::{codec, rules_ops};
use elasticctl_api_test_support::MockStack;
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

/// A success body missing its required counters must not read as "nothing
/// succeeded": that would silently drop a partial upload.
#[tokio::test]
async fn malformed_import_response_is_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true
        })))
        .mount(&server)
        .await;

    let transport = Transport::new(&Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .unwrap();

    let err = rules_ops::apply_import(&transport, "{\"rule_id\":\"a\"}\n", false)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Http);
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

/// Rules export produces a bundle: the rule plus the exception container and
/// item it needs on the target stack. Dropping either exception line on import
/// leaves the server with a rule whose reference cannot be resolved.
#[tokio::test]
async fn plan_import_preserves_the_full_ndjson_rule_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.ndjson");
    std::fs::write(
        &path,
        concat!(
            r#"{"rule_id":"new","name":"New","type":"query","exceptions_list":[{"list_id":"l","namespace_type":"single","type":"detection"}]}"#,
            "\n",
            r#"{"list_id":"l","name":"L","type":"detection","namespace_type":"single"}"#,
            "\n",
            r#"{"item_id":"i","list_id":"l","name":"I","type":"simple","namespace_type":"single","entries":[]}"#,
            "\n",
            r#"{"list_id":"unreferenced","name":"Unreferenced","type":"detection","namespace_type":"single"}"#,
            "\n",
            r#"{"item_id":"unreferenced-item","list_id":"unreferenced","name":"Unreferenced item","type":"simple","namespace_type":"single","entries":[]}"#,
            "\n"
        ),
    )
    .unwrap();

    let plan = rules_ops::plan_import(None, &path, false, false)
        .await
        .unwrap();
    let uploaded = codec::decode_bundle(&plan.ndjson).unwrap();

    assert_eq!(uploaded.rules.len(), 1);
    assert_eq!(uploaded.lists.len(), 1, "the list must reach rules import");
    assert_eq!(uploaded.items.len(), 1, "the item must reach rules import");
    assert_eq!(uploaded.lists[0].list_id().unwrap(), "l");
    assert_eq!(uploaded.items[0].item_id().unwrap(), "i");
}

/// `rules import` is guarded as a rule mutation. An exception-only bundle has
/// no rule target for the guard to preview, so it must not become an unguarded
/// exception write merely because it is valid NDJSON.
#[tokio::test]
async fn plan_import_drops_an_exception_only_ndjson_bundle() {
    let stack = MockStack::new().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("exceptions-only.ndjson");
    std::fs::write(
        &path,
        concat!(
            r#"{"list_id":"orphan","name":"Orphan","type":"detection","namespace_type":"single"}"#,
            "\n",
            r#"{"item_id":"orphan-item","list_id":"orphan","name":"Orphan item","type":"simple","namespace_type":"single","entries":[]}"#,
            "\n"
        ),
    )
    .unwrap();

    let plan = rules_ops::plan_import(None, &path, false, false)
        .await
        .unwrap();
    assert!(plan.preview.targets.is_empty());
    assert!(
        plan.ndjson.is_empty(),
        "an exception-only bundle has no guarded rule import target"
    );

    let report = rules_ops::apply_import(stack.transport(), &plan.ndjson, false)
        .await
        .unwrap();
    assert_eq!(report.succeeded, json!(0));
    assert!(
        stack.write_requests().await.is_empty(),
        "an exception-only plan must not write"
    );
}

/// State files intentionally omit volatile exception pointers. Before rules
/// import crosses the wire, every readable list reference needs a syntactically
/// valid placeholder so Kibana can re-resolve it to the target container.
#[tokio::test]
async fn plan_import_adds_upload_only_exception_pointer_placeholders() {
    let rule = Rule::from_value(json!({
        "rule_id": "pointer-free",
        "name": "Pointer free",
        "type": "query",
        "exceptions_list": [
            {"list_id": "missing", "namespace_type": "single", "type": "detection"},
            {"list_id": "non-string", "namespace_type": "single", "type": "detection", "id": 7},
            {"list_id": "stale", "namespace_type": "single", "type": "detection", "id": "old-id"},
            {"id": 9},
            {"list_id": 4, "id": 5},
            "not an exception reference"
        ]
    }))
    .unwrap();
    let ndjson = format!("{}\n", serde_json::to_string(&rule).unwrap());
    let yaml = codec::encode_yaml(&[rule]).unwrap();

    for (name, body) in [("pointer-free.ndjson", ndjson), ("pointer-free.yaml", yaml)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        std::fs::write(&path, &body).unwrap();

        let plan = rules_ops::plan_import(None, &path, false, false)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            body,
            "planning must not write upload-only pointers back to {name}"
        );

        let uploaded = codec::decode_bundle(&plan.ndjson).unwrap();
        let references = uploaded.rules[0].as_map()["exceptions_list"]
            .as_array()
            .unwrap();
        assert_eq!(
            references[0]["id"], "00000000-0000-0000-0000-000000000000",
            "a missing pointer needs an upload-only placeholder"
        );
        assert_eq!(
            references[1]["id"], "00000000-0000-0000-0000-000000000000",
            "a non-string pointer must become a valid placeholder"
        );
        assert_eq!(
            references[2]["id"], "00000000-0000-0000-0000-000000000000",
            "a stale pointer is replaced by the deterministic upload placeholder"
        );
        assert_eq!(references[3], json!({"id": 9}));
        assert_eq!(references[4], json!({"list_id": 4, "id": 5}));
        assert_eq!(references[5], json!("not an exception reference"));
    }
}

/// A skipped rule must not bring its exception objects along for the upload.
/// The remaining rule still needs its own list and item, so filtering by a
/// list id alone would be unsafe when namespaces differ.
#[tokio::test]
async fn plan_import_skip_existing_keeps_only_dependencies_of_uploaded_rules() {
    let stack = mock_stack_with_one_rule().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.ndjson");
    std::fs::write(
        &path,
        concat!(
            r#"{"rule_id":"a","name":"Existing","type":"query","exceptions_list":[{"list_id":"shared","namespace_type":"single","type":"detection"}]}"#,
            "\n",
            r#"{"rule_id":"b","name":"New","type":"query","exceptions_list":[{"list_id":"shared","namespace_type":"agnostic","type":"detection"}]}"#,
            "\n",
            r#"{"list_id":"shared","name":"Single","type":"detection","namespace_type":"single"}"#,
            "\n",
            r#"{"item_id":"single-item","list_id":"shared","name":"Single item","type":"simple","namespace_type":"single","entries":[]}"#,
            "\n",
            r#"{"list_id":"shared","name":"Agnostic","type":"detection","namespace_type":"agnostic"}"#,
            "\n",
            r#"{"item_id":"agnostic-item","list_id":"shared","name":"Agnostic item","type":"simple","namespace_type":"agnostic","entries":[]}"#,
            "\n"
        ),
    )
    .unwrap();

    let plan = rules_ops::plan_import(Some(stack.transport()), &path, false, true)
        .await
        .unwrap();
    let uploaded = codec::decode_bundle(&plan.ndjson).unwrap();

    assert_eq!(plan.preview.targets, vec!["b"]);
    assert_eq!(uploaded.rules.len(), 1);
    assert_eq!(uploaded.rules[0].rule_id().unwrap(), "b");
    assert_eq!(uploaded.lists.len(), 1);
    assert_eq!(uploaded.lists[0].namespace_type(), "agnostic");
    assert_eq!(uploaded.items.len(), 1);
    assert_eq!(uploaded.items[0].item_id().unwrap(), "agnostic-item");
    assert!(
        stack.write_requests().await.is_empty(),
        "planning must not upload the surviving bundle"
    );
}
