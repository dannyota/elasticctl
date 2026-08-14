//! The exception-list endpoint wrappers' contract, independent of the CLI.

use elasticctl_api::codec::Format;
use elasticctl_api::exceptions::{self, ListFilter};
use elasticctl_api::model::{ExceptionItem, ExceptionList, ListKey};
use elasticctl_api_test_support::MockStack;
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn mock_exception_lists(n: usize) -> MockStack {
    MockStack::with_exception_lists(n).await
}

async fn mock_exception_items(n: usize) -> MockStack {
    MockStack::with_exception_items(n).await
}

fn profile(uri: &str) -> Profile {
    Profile {
        kibana_url: uri.to_string(),
        es_url: None,
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    }
}

fn transport(server: &MockServer) -> Transport {
    Transport::new(&profile(&server.uri())).unwrap()
}

fn list_json(i: usize) -> Value {
    json!({
        "id": format!("id-l{i}"),
        "list_id": format!("l{i}"),
        "type": "detection",
        "name": format!("list l{i}"),
        "namespace_type": "single",
        "tags": ["sample"]
    })
}

fn item_json(i: usize) -> Value {
    json!({
        "id": format!("id-i{i}"),
        "item_id": format!("i{i}"),
        "list_id": "l",
        "type": "simple",
        "name": format!("item {i}"),
        "namespace_type": "single",
        "entries": []
    })
}

#[tokio::test]
async fn find_lists_reads_the_data_array_and_total() {
    let stack = mock_exception_lists(2).await;
    let found = exceptions::find_lists(stack.transport(), &ListFilter::default())
        .await
        .unwrap();
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].list_id().unwrap(), "l0");
}

/// A malformed `_find` envelope must not look like an empty success: an
/// export or mirror built from it would silently omit every list.
#[tokio::test]
async fn find_lists_rejects_every_missing_or_mistyped_envelope_field() {
    for (body, field) in [
        (json!({"page": 1, "per_page": 1, "total": 0}), "data"),
        (json!({"data": [], "per_page": 1, "total": 0}), "page"),
        (json!({"data": [], "page": 1, "total": 0}), "per_page"),
        (json!({"data": [], "page": 1, "per_page": 1}), "total"),
        (
            json!({"data": {}, "page": 1, "per_page": 1, "total": 0}),
            "data",
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/exception_lists/_find"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let err = exceptions::find_lists(&transport(&server), &ListFilter::default())
            .await
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Http);
        assert!(err.message.contains(field), "{}", err.message);
    }
}

/// A page that returns more objects than the server's total cannot be a
/// complete read; accepting it hides a contradictory response.
#[tokio::test]
async fn find_items_rejects_a_page_that_returns_more_than_total() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/items/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [item_json(0), item_json(1)],
            "page": 1,
            "per_page": 2,
            "total": 1,
        })))
        .mount(&server)
        .await;

    let err = exceptions::find_items(
        &transport(&server),
        &ListKey {
            list_id: "l".into(),
            namespace_type: "single".into(),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Http);
}

/// The empty-filter 400 (spec 7.7): `filter=` with no clauses is a KQL syntax
/// error, so an unfiltered find omits the parameter entirely. A populated find
/// sends the measured `exception-list.attributes.*` KQL.
#[tokio::test]
async fn find_lists_omits_an_empty_filter_and_sends_a_populated_one() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [], "page": 1, "per_page": 100, "total": 0
        })))
        .mount(&server)
        .await;
    let t = transport(&server);

    exceptions::find_lists(&t, &ListFilter::default())
        .await
        .unwrap();
    exceptions::find_lists(
        &t,
        &ListFilter {
            list_type: Some("detection".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let reqs = server.received_requests().await.unwrap();
    let filters: Vec<Option<String>> = reqs
        .iter()
        .map(|r| {
            r.url
                .query_pairs()
                .find(|(k, _)| k.as_ref() == "filter")
                .map(|(_, v)| v.into_owned())
        })
        .collect();
    assert_eq!(
        filters[0], None,
        "an unfiltered find must omit filter=, not send it empty"
    );
    assert_eq!(
        filters[1].as_deref(),
        Some("exception-list.attributes.type: \"detection\""),
        "the populated filter uses the measured prefix and quotes the value"
    );
}

/// A container that exists only in the `agnostic` namespace must not resolve
/// against a `single` key. Spec 4.5: namespace_type is part of identity.
#[tokio::test]
async fn resolve_ids_keys_on_namespace_as_well_as_list_id() {
    let stack = mock_exception_lists(0).await;
    let map = exceptions::resolve_ids(
        stack.transport(),
        &[ListKey {
            list_id: "l".into(),
            namespace_type: "agnostic".into(),
        }],
    )
    .await
    .unwrap();
    assert!(
        map.is_empty(),
        "an absent list is absent, never a placeholder"
    );
}

/// Paging is not optional: a list with more items than one page must return
/// all of them or a mirror silently drops exceptions.
#[tokio::test]
async fn find_items_reads_every_page() {
    let stack = mock_exception_items(250).await; // the mock caps per_page below this
    let items = exceptions::find_items(
        stack.transport(),
        &ListKey {
            list_id: "l".into(),
            namespace_type: "single".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(items.len(), 250, "a short read is a silent data loss");
}

/// Missing keys stay absent so callers can distinguish them from live keys
/// mapped to ids.
#[tokio::test]
async fn resolve_ids_maps_live_keys_to_ids_and_omits_absent_keys() {
    let stack = mock_exception_lists(1).await; // only l0 exists
    let map = exceptions::resolve_ids(
        stack.transport(),
        &[
            ListKey {
                list_id: "l0".into(),
                namespace_type: "single".into(),
            },
            ListKey {
                list_id: "missing".into(),
                namespace_type: "single".into(),
            },
        ],
    )
    .await
    .unwrap();

    assert_eq!(map.len(), 1, "the absent key must not appear");
    assert_eq!(
        map.get(&ListKey {
            list_id: "l0".into(),
            namespace_type: "single".into(),
        })
        .map(String::as_str),
        Some("id-l0"),
        "a live key maps to its container id"
    );
}

/// Spec 4.5: the same `list_id` in two namespaces are two objects. A container
/// that exists only in `single` must not resolve under an `agnostic` key.
#[tokio::test]
async fn resolve_ids_does_not_cross_namespaces() {
    let stack = mock_exception_lists(1).await; // l0 exists only in `single`
    let map = exceptions::resolve_ids(
        stack.transport(),
        &[
            ListKey {
                list_id: "l0".into(),
                namespace_type: "single".into(),
            },
            ListKey {
                list_id: "l0".into(),
                namespace_type: "agnostic".into(),
            },
        ],
    )
    .await
    .unwrap();

    assert_eq!(map.len(), 1, "the agnostic key has no live container");
    assert!(
        map.contains_key(&ListKey {
            list_id: "l0".into(),
            namespace_type: "single".into(),
        }),
        "only the single key resolves"
    );
}

#[tokio::test]
async fn get_list_reads_a_container_by_list_id_and_namespace() {
    let stack = mock_exception_lists(1).await;
    let list = exceptions::get_list(
        stack.transport(),
        &ListKey {
            list_id: "l0".into(),
            namespace_type: "single".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(list.list_id().unwrap(), "l0");
    assert_eq!(list.namespace_type(), "single");
}

/// A create posts the container and strips server-minted volatile fields, the
/// way `rules::create` does. A stale `id` must not be re-sent as identity.
#[tokio::test]
async fn create_list_posts_the_container_and_strips_volatile_fields() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/exception_lists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_json(0)))
        .mount(&server)
        .await;
    let t = transport(&server);

    let input = ExceptionList::from_value(json!({
        "list_id": "l0", "type": "detection", "name": "L",
        "id": "stale", "_version": "WzEsMV0=", "namespace_type": "single"
    }))
    .unwrap();

    let created = exceptions::create_list(&t, &input).await.unwrap();
    assert_eq!(created.list_id().unwrap(), "l0");

    let body: Value = server.received_requests().await.unwrap()[0]
        .body_json()
        .unwrap();
    assert!(
        body.get("id").is_none(),
        "the volatile id is stripped: {body}"
    );
    assert!(
        body.get("_version").is_none(),
        "the volatile _version is stripped: {body}"
    );
    assert_eq!(body["list_id"], "l0", "identity survives");
}

/// Measured: `PUT /api/exception_lists` updates by `list_id` alone; no `id` is
/// required. The wrapper must not send one.
#[tokio::test]
async fn update_list_puts_by_list_id_without_an_id() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/exception_lists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_json(0)))
        .mount(&server)
        .await;
    let t = transport(&server);

    let input = ExceptionList::from_value(json!({
        "list_id": "l0", "type": "detection", "name": "L", "id": "stale"
    }))
    .unwrap();

    let updated = exceptions::update_list(&t, &input).await.unwrap();
    assert_eq!(updated.list_id().unwrap(), "l0");

    let body: Value = server.received_requests().await.unwrap()[0]
        .body_json()
        .unwrap();
    assert!(
        body.get("id").is_none(),
        "PUT resolves by list_id, no id: {body}"
    );
    assert_eq!(body["list_id"], "l0");
}

#[tokio::test]
async fn delete_list_deletes_by_list_id_and_namespace() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/exception_lists"))
        .and(query_param("list_id", "l0"))
        .and(query_param("namespace_type", "single"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_json(0)))
        .mount(&server)
        .await;
    let t = transport(&server);

    let deleted = exceptions::delete_list(
        &t,
        &ListKey {
            list_id: "l0".into(),
            namespace_type: "single".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(deleted.list_id().unwrap(), "l0");
}

#[tokio::test]
async fn create_item_posts_the_item() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/exception_lists/items"))
        .respond_with(ResponseTemplate::new(200).set_body_json(item_json(0)))
        .mount(&server)
        .await;
    let t = transport(&server);

    let input = ExceptionItem::from_value(json!({
        "item_id": "i0", "list_id": "l", "type": "simple", "name": "I",
        "id": "stale", "namespace_type": "single"
    }))
    .unwrap();

    let created = exceptions::create_item(&t, &input).await.unwrap();
    assert_eq!(created.item_id().unwrap(), "i0");

    let body: Value = server.received_requests().await.unwrap()[0]
        .body_json()
        .unwrap();
    assert!(
        body.get("id").is_none(),
        "the volatile id is stripped: {body}"
    );
    assert_eq!(body["item_id"], "i0", "identity survives");
}

/// Measured: `PUT /api/exception_lists/items` updates by `item_id` alone.
#[tokio::test]
async fn update_item_puts_by_item_id_without_an_id() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/exception_lists/items"))
        .respond_with(ResponseTemplate::new(200).set_body_json(item_json(0)))
        .mount(&server)
        .await;
    let t = transport(&server);

    let input = ExceptionItem::from_value(json!({
        "item_id": "i0", "list_id": "l", "type": "simple", "name": "I", "id": "stale"
    }))
    .unwrap();

    let updated = exceptions::update_item(&t, &input).await.unwrap();
    assert_eq!(updated.item_id().unwrap(), "i0");

    let body: Value = server.received_requests().await.unwrap()[0]
        .body_json()
        .unwrap();
    assert!(
        body.get("id").is_none(),
        "PUT resolves by item_id, no id: {body}"
    );
}

#[tokio::test]
async fn delete_item_deletes_by_item_id_and_namespace() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/exception_lists/items"))
        .and(query_param("item_id", "i0"))
        .and(query_param("namespace_type", "single"))
        .respond_with(ResponseTemplate::new(200).set_body_json(item_json(0)))
        .mount(&server)
        .await;
    let t = transport(&server);

    let deleted = exceptions::delete_item(&t, "i0", "single").await.unwrap();
    assert_eq!(deleted.item_id().unwrap(), "i0");
}

/// Measured fact E: the export route requires the volatile `id` and rejects
/// `list_id` alone with a 400. `export_lists` must resolve each key to its live
/// `id` and pass both, without changing what identity means.
#[tokio::test]
async fn export_lists_resolves_ids_and_passes_them_to_the_export_route() {
    let server = MockServer::start().await;
    // get_list resolves l0 -> id-l0.
    Mock::given(method("GET"))
        .and(path("/api/exception_lists"))
        .and(query_param("list_id", "l0"))
        .and(query_param("namespace_type", "single"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_json(0)))
        .mount(&server)
        .await;
    // The export route carries both the volatile id and the stable identity.
    Mock::given(method("POST"))
        .and(path("/api/exception_lists/_export"))
        .and(query_param("id", "id-l0"))
        .and(query_param("list_id", "l0"))
        .and(query_param("namespace_type", "single"))
        .and(query_param("include_expired_exceptions", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "{}\n{}\n{{\"exported_exception_list_count\":1,\"exported_exception_list_item_count\":1,\"missing_exception_lists\":[],\"missing_exception_list_items\":[]}}\n",
            list_json(0),
            item_json(0)
        )))
        .mount(&server)
        .await;
    let t = transport(&server);

    let out = exceptions::export_lists(
        &t,
        &[ListKey {
            list_id: "l0".into(),
            namespace_type: "single".into(),
        }],
    )
    .await
    .unwrap();

    assert!(
        out.body.contains("\"list_id\""),
        "the export body is NDJSON: {}",
        out.body
    );
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 2, "one resolve GET then one export POST");
    let pairs: Vec<(String, String)> = reqs[1]
        .url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert!(
        pairs.contains(&("id".into(), "id-l0".into())),
        "the volatile id is fetched and passed: {pairs:?}"
    );
    assert!(
        pairs.contains(&("list_id".into(), "l0".into())),
        "the stable list_id travels alongside: {pairs:?}"
    );
}

/// A list can disappear after selection and ID resolution. The trailer is the
/// authoritative outcome, so its missing entry must keep the stable key.
#[tokio::test]
async fn export_reports_a_list_deleted_after_id_resolution() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists"))
        .and(query_param("list_id", "l0"))
        .and(query_param("namespace_type", "single"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_json(0)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/exception_lists/_export"))
        .respond_with(ResponseTemplate::new(200).set_body_string(concat!(
            r#"{"exported_exception_list_count":0,"exported_exception_list_item_count":0,"missing_exception_lists":[{"reason":"deleted"}],"missing_exception_list_items":[]}"#,
            "\n"
        )))
        .mount(&server)
        .await;

    let out = exceptions::export_op(
        &transport(&server),
        &["l0".to_string()],
        None,
        Some("single"),
        Format::Ndjson,
    )
    .await
    .unwrap();

    assert_eq!(out.exported, 0);
    assert_eq!(out.missing[0]["list_id"], "l0");
    assert_eq!(out.missing[0]["namespace_type"], "single");
}

/// The only trustworthy statement of an export's outcome is its final trailer.
/// A 200 containing data lines but no trailer is not a completed export.
#[tokio::test]
async fn export_rejects_a_200_without_a_valid_trailer() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists"))
        .and(query_param("list_id", "l0"))
        .and(query_param("namespace_type", "single"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_json(0)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/exception_lists/_export"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("{}\n", list_json(0))))
        .mount(&server)
        .await;

    let err = exceptions::export_lists(
        &transport(&server),
        &[ListKey {
            list_id: "l0".into(),
            namespace_type: "single".into(),
        }],
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind, ErrorKind::Http);
    assert!(err.message.contains("export trailer"), "{}", err.message);
}

/// A key with no live container is refused, not silently dropped: a short
/// export reported as a success is the failure spec 4.3 refuses.
#[tokio::test]
async fn export_lists_refuses_a_missing_key_and_names_it() {
    let server = MockServer::start().await;
    // No list mocks: get_list for "missing" answers 404, so nothing resolves.
    let t = transport(&server);

    let err = exceptions::export_lists(
        &t,
        &[ListKey {
            list_id: "missing".into(),
            namespace_type: "single".into(),
        }],
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind, ErrorKind::NotFound);
    assert!(err.message.contains("missing"), "{}", err.message);
}

/// `[live, missing]` must refuse rather than return the live key's body: a
/// partial success is the case most likely to slip through.
#[tokio::test]
async fn export_lists_refuses_a_partial_export() {
    let server = MockServer::start().await;
    // Only l0 resolves.
    Mock::given(method("GET"))
        .and(path("/api/exception_lists"))
        .and(query_param("list_id", "l0"))
        .and(query_param("namespace_type", "single"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_json(0)))
        .mount(&server)
        .await;
    let t = transport(&server);

    let err = exceptions::export_lists(
        &t,
        &[
            ListKey {
                list_id: "l0".into(),
                namespace_type: "single".into(),
            },
            ListKey {
                list_id: "missing".into(),
                namespace_type: "single".into(),
            },
        ],
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind, ErrorKind::NotFound);
    assert!(
        err.message.contains("missing") && !err.message.contains("l0"),
        "the error names the missing key, not the live one: {}",
        err.message
    );
    // Both resolve GETs ran, but no export POST was issued for the live key.
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 2, "two resolve GETs, no export POST");
    assert!(reqs.iter().all(|r| r.method.as_str() == "GET"));
}

/// Name every missing key at once, the way the mirror names every colliding
/// filename pair: one refusal per run beats a re-run per missing key.
#[tokio::test]
async fn export_lists_names_every_missing_key() {
    let server = MockServer::start().await;
    let t = transport(&server);

    let err = exceptions::export_lists(
        &t,
        &[
            ListKey {
                list_id: "a".into(),
                namespace_type: "single".into(),
            },
            ListKey {
                list_id: "b".into(),
                namespace_type: "agnostic".into(),
            },
        ],
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind, ErrorKind::NotFound);
    assert!(err.message.contains("a (single)"), "{}", err.message);
    assert!(err.message.contains("b (agnostic)"), "{}", err.message);
}

#[tokio::test]
async fn import_lists_posts_to_the_import_route() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/exception_lists/_import"))
        .and(query_param("overwrite", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true, "success_count": 1, "errors": []
        })))
        .mount(&server)
        .await;
    let t = transport(&server);

    let out = exceptions::import_lists(&t, "{\"list_id\":\"l0\"}", true)
        .await
        .unwrap();
    assert_eq!(out["success"], true);
}

/// `--skip-existing` drops an existing container and every item inside it, and
/// keeps a new container and its items. Spec 4.4: the dry run is honest about
/// what would be created and what would be skipped.
#[tokio::test]
async fn plan_import_op_skips_an_existing_container_and_its_items() {
    let stack = MockStack::with_exception_lists(1).await; // l0 exists
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("bundle.ndjson");
    std::fs::write(
        &src,
        concat!(
            "{\"list_id\":\"l0\",\"type\":\"detection\",\"name\":\"L0\",\"namespace_type\":\"single\"}\n",
            "{\"item_id\":\"i0\",\"list_id\":\"l0\",\"type\":\"simple\",\"name\":\"I0\",\"namespace_type\":\"single\"}\n",
            "{\"list_id\":\"l9\",\"type\":\"detection\",\"name\":\"L9\",\"namespace_type\":\"single\"}\n",
            "{\"item_id\":\"i9\",\"list_id\":\"l9\",\"type\":\"simple\",\"name\":\"I9\",\"namespace_type\":\"single\"}\n",
        ),
    )
    .unwrap();

    let plan = exceptions::plan_import_op(Some(stack.transport()), &src, false, true)
        .await
        .unwrap();

    assert_eq!(plan.total, 4, "lists and items are both counted in-file");
    assert_eq!(plan.skipped.len(), 1, "the existing container is skipped");
    assert_eq!(plan.skipped[0]["list_id"], "l0");

    let bundle = elasticctl_api::codec::decode_bundle(&plan.ndjson).unwrap();
    assert_eq!(bundle.lists.len(), 1, "only the new container is kept");
    assert_eq!(bundle.lists[0].list_id().unwrap(), "l9");
    assert_eq!(
        bundle.items.len(),
        1,
        "the skipped container's item is dropped"
    );
    assert_eq!(bundle.items[0].list_id().unwrap(), "l9");
}

/// An item whose list_id is unreadable has no home. `from_value` validates only
/// item_id, so this is reachable; it must be refused, not uploaded with an
/// empty home (spec 5.2).
#[tokio::test]
async fn plan_import_op_refuses_an_item_without_a_readable_list_id() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("bundle.ndjson");
    std::fs::write(
        &src,
        "{\"item_id\":\"i0\",\"type\":\"simple\",\"name\":\"I0\",\"namespace_type\":\"single\"}\n",
    )
    .unwrap();

    let err = exceptions::plan_import_op(None, &src, false, false)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Error);
    assert!(err.message.contains("list_id"), "{}", err.message);
}

/// An items-only file is the natural way to add exceptions to a container that
/// already exists. The preview must count the items, not report a zero-object
/// mutation (spec 6.1).
#[tokio::test]
async fn plan_import_op_counts_items_in_the_preview() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("items.ndjson");
    std::fs::write(
        &src,
        concat!(
            "{\"item_id\":\"i0\",\"list_id\":\"l0\",\"type\":\"simple\",\"name\":\"I0\",\"namespace_type\":\"single\"}\n",
            "{\"item_id\":\"i1\",\"list_id\":\"l0\",\"type\":\"simple\",\"name\":\"I1\",\"namespace_type\":\"single\"}\n",
        ),
    )
    .unwrap();

    let plan = exceptions::plan_import_op(None, &src, false, false)
        .await
        .unwrap();
    assert_eq!(plan.total, 2, "items count toward the in-file total");
    assert!(
        plan.preview.preview_action.contains("2 item(s)"),
        "the preview must name the items: {}",
        plan.preview.preview_action
    );
    assert_eq!(plan.preview.targets.len(), 2, "pending counts the items");
}
