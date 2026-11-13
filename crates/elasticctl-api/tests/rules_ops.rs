use elasticctl_api::model::Rule;
use elasticctl_api::rules::{RuleFilter, RuleSource};
use elasticctl_api::{codec, rules_ops};
use elasticctl_api_test_support::MockStack;
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::json;
use wiremock::matchers::{method, path, query_param};
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

#[tokio::test]
async fn get_one_rereads_a_rule_whose_rule_id_differs_from_the_selector() {
    let server = MockServer::start().await;
    for (query, name) in [(r"r\\n", "Escaped lookup"), (r"r\n", "Stored rule")] {
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules"))
            .and(query_param("rule_id", query))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"rule_id": r"r\n", "name": name})),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
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

    let rule = rules_ops::get_one(&transport, r"r\\n").await.unwrap();
    assert_eq!(rule.name(), "Stored rule");
}

#[tokio::test]
async fn list_page_reads_one_bounded_page_ordered_by_name() {
    let rules = ["e", "d", "c", "b", "a"]
        .iter()
        .map(|id| json!({"rule_id": id, "name": id.to_uppercase(), "type": "query"}))
        .collect();
    let stack = MockStack::with_rules(rules).await;
    let page = rules_ops::list_page(stack.transport(), &RuleFilter::default(), 2)
        .await
        .unwrap();

    let names: Vec<&str> = page.rules.iter().map(|r| r.name()).collect();
    assert_eq!(names, ["A", "B"]);
    assert_eq!(page.total, 5);
    let finds: Vec<_> = stack
        .requests()
        .await
        .into_iter()
        .filter(|r| r.path == "/api/detection_engine/rules/_find")
        .collect();
    assert_eq!(finds.len(), 1);
    for (key, value) in [
        ("page", "1"),
        ("per_page", "2"),
        ("sort_field", "name"),
        ("sort_order", "asc"),
    ] {
        assert_eq!(finds[0].query.get(key).map(String::as_str), Some(value));
    }
}

#[tokio::test]
async fn list_page_proves_the_source_partition_on_an_empty_source_page() {
    let custom = RuleFilter {
        source: RuleSource::Custom,
        ..Default::default()
    };
    let refused = MockStack::with_source_totals(0, 2, 3).await;
    let err = rules_ops::list_page(refused.transport(), &custom, 50)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Unsupported);

    let partitioned = MockStack::with_source_totals(0, 2, 2).await;
    let page = rules_ops::list_page(partitioned.transport(), &custom, 50)
        .await
        .unwrap();
    assert!(page.rules.is_empty());
    assert_eq!(page.total, 0);
    let finds = partitioned
        .requests()
        .await
        .into_iter()
        .filter(|r| r.path == "/api/detection_engine/rules/_find")
        .count();
    assert_eq!(finds, 4);
}

fn find_server_transport(server: &MockServer) -> Transport {
    Transport::new(&Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .unwrap()
}

async fn serve_find(server: &MockServer, rows: usize, per_page: u64, total: u64) {
    let data: Vec<_> = (0..rows)
        .map(|i| json!({"rule_id": format!("r{i}"), "name": format!("R{i}")}))
        .collect();
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": per_page, "total": total, "data": data
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn list_page_refuses_only_a_short_page() {
    for (rows, per_page, total, ok) in [
        (2, 3, 5, false),
        (2, 10, 5, false),
        (3, 3, 5, true),
        (3, 10, 5, true),
        (2, 3, 2, true),
        (2, 1000, 2, true),
    ] {
        let server = MockServer::start().await;
        serve_find(&server, rows, per_page, total).await;
        let result =
            rules_ops::list_page(&find_server_transport(&server), &RuleFilter::default(), 3).await;
        match result {
            Ok(page) => {
                assert!(ok, "rows={rows} perPage={per_page} total={total}");
                assert_eq!((page.rules.len(), page.total), (rows, total));
            }
            Err(err) => {
                assert!(!ok, "rows={rows} perPage={per_page} total={total}: {err:?}");
                assert_eq!(err.kind, ErrorKind::Http);
            }
        }
    }
}
