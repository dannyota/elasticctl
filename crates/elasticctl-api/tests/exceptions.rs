//! The exception-list endpoint wrappers' contract, independent of the CLI.

use elasticctl_api::exceptions::{self, ListFilter};
use elasticctl_api::model::{ExceptionItem, ExceptionList, ListKey};
use elasticctl_api_test_support::MockStack;
use elasticctl_core::{Profile, Transport};
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

/// The map distinguishes "exists here with this id" from "does not exist here";
/// Tasks 11 and 12 rely on that distinction, so an absent key is absent rather
/// than mapped to a placeholder.
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
            "{}\n{}\n",
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
        out.contains("\"list_id\""),
        "the export body is NDJSON: {out}"
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

/// A key with no live container has nothing to export and is skipped rather
/// than exported under a placeholder id.
#[tokio::test]
async fn export_lists_skips_a_key_without_a_live_container() {
    let server = MockServer::start().await;
    // No list mocks: get_list for "missing" answers 404, so nothing resolves.
    let t = transport(&server);

    let out = exceptions::export_lists(
        &t,
        &[ListKey {
            list_id: "missing".into(),
            namespace_type: "single".into(),
        }],
    )
    .await
    .unwrap();

    assert!(out.is_empty(), "nothing to export, no request to _export");
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "only the resolving GET was issued");
    assert_eq!(reqs[0].url.path(), "/api/exception_lists");
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
