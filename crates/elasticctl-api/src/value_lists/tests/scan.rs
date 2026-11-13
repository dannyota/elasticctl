use super::super::*;
use super::reads::{FLAVORS, fixture};
use crate::model::{ExceptionItem, ListKey};

#[test]
fn top_level_list_entries_keep_the_consumer_identity_field_operator_and_list_type() {
    for flavor in FLAVORS {
        let f = fixture(flavor, "exception_item_create");
        let body = f["response"].clone();
        let item = ExceptionItem::from_value(body.clone()).unwrap();
        let key = ListKey {
            list_id: body["list_id"].as_str().unwrap().into(),
            namespace_type: body["namespace_type"].as_str().unwrap().into(),
        };
        let refs = item_references(&key, &item).unwrap();
        assert_eq!(refs.len(), 2);
        for (reference, entry) in refs.iter().zip(body["entries"].as_array().unwrap()) {
            assert_eq!(reference.container, key);
            assert_eq!(reference.item_id, body["item_id"].as_str().unwrap());
            assert_eq!(reference.field, entry["field"].as_str().unwrap());
            assert_eq!(reference.list_id, entry["list"]["id"].as_str().unwrap());
            assert_eq!(
                reference.list_type.to_string(),
                entry["list"]["type"].as_str().unwrap()
            );
        }
        assert_eq!(refs[0].operator, ReferenceOperator::Included);
        assert_eq!(refs[1].operator, ReferenceOperator::Excluded);
    }
}

#[test]
fn unreadable_list_entries_never_become_an_empty_reference_set() {
    let body = fixture(FLAVORS[0], "exception_item_create")["response"].clone();
    let key = ListKey {
        list_id: body["list_id"].as_str().unwrap().into(),
        namespace_type: body["namespace_type"].as_str().unwrap().into(),
    };
    for pointer in [
        "/entries/0/list/id",
        "/entries/0/list/type",
        "/entries/0/field",
        "/entries/0/operator",
        "/entries",
        "/namespace_type",
    ] {
        let mut malformed = body.clone();
        *malformed.pointer_mut(pointer).unwrap() = serde_json::Value::Null;
        let item = ExceptionItem::from_value(malformed).unwrap();
        assert!(item_references(&key, &item).is_err(), "{pointer}");
    }
}

#[test]
fn a_scan_refuses_an_advertised_total_beyond_the_window_before_paging() {
    let mut page = serde_json::json!({"page": 1, "per_page": 10000, "total": 10001, "data": []});
    assert!(super::super::scan::decode_scan_page(&page).is_err());
    page["total"] = serde_json::json!(1);
    assert!(super::super::scan::decode_scan_page(&page).is_err());
    page["total"] = serde_json::json!(0);
    page["page"] = serde_json::json!(2);
    assert!(super::super::scan::decode_scan_page(&page).is_err());
}

use super::reads::{response, transport};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer};

pub(super) async fn scan_single(server: &MockServer, flavor: &str, container_status: u16) {
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(response(&fixture(flavor, "status"), 200))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/_find"))
        .and(query_param("namespace_type", "single"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "10000"))
        .respond_with(response(&fixture(flavor, "exception_lists_find"), 200))
        .expect(1)
        .mount(server)
        .await;
    let list = fixture(flavor, "exception_create");
    let id = list["response"]["list_id"].as_str().unwrap();
    Mock::given(method("GET"))
        .and(path("/api/exception_lists"))
        .and(query_param("list_id", id))
        .and(query_param("namespace_type", "single"))
        .respond_with(response(&list, container_status))
        .expect(1)
        .mount(server)
        .await;
    if container_status == 200 {
        Mock::given(method("GET"))
            .and(path("/api/exception_lists/items/_find"))
            .and(query_param("namespace_type", "single"))
            .and(query_param("list_id", id))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "10000"))
            .respond_with(response(&fixture(flavor, "exception_items_find"), 200))
            .expect(1)
            .mount(server)
            .await;
    }
}

#[tokio::test]
async fn a_namespace_scan_collects_included_and_excluded_consumers_without_a_selection_filter() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        scan_single(&server, flavor, 200).await;
        let mut refs = Vec::new();
        super::super::scan::scan_namespace(&transport(&server), "single", &mut refs)
            .await
            .unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].operator, ReferenceOperator::Included);
        assert_eq!(refs[1].operator, ReferenceOperator::Excluded);
        let f = fixture(flavor, "exception_items_find");
        let item = &f["response"]["data"][0];
        for (reference, entry) in refs.iter().zip(item["entries"].as_array().unwrap()) {
            assert_eq!(
                reference.container.list_id,
                item["list_id"].as_str().unwrap()
            );
            assert_eq!(
                reference.container.namespace_type,
                item["namespace_type"].as_str().unwrap()
            );
            assert_eq!(reference.item_id, item["item_id"].as_str().unwrap());
            assert_eq!(reference.field, entry["field"].as_str().unwrap());
            assert_eq!(reference.list_id, entry["list"]["id"].as_str().unwrap());
            assert_eq!(
                reference.list_type.to_string(),
                entry["list"]["type"].as_str().unwrap()
            );
        }
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 4);
        for request in &requests {
            let query_count = match request.url.path() {
                "/api/status" => 0,
                "/api/exception_lists/_find" => 3,
                "/api/exception_lists" => 2,
                "/api/exception_lists/items/_find" => 4,
                route => panic!("unexpected request {route}"),
            };
            assert_eq!(request.url.query_pairs().count(), query_count);
        }
        assert!(
            requests
                .iter()
                .all(|request| !request.url.query_pairs().any(|(key, _)| key == "filter"))
        );
        assert!(
            requests
                .iter()
                .all(|request| request.method == "GET" && request.body.is_empty())
        );
    }
}

#[tokio::test]
async fn scanned_repeated_reference_refuses_a_value_change_before_writes() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        scan_single(&server, flavor, 200).await;
        let mut refs = Vec::new();
        super::super::scan::scan_namespace(&transport(&server), "single", &mut refs)
            .await
            .unwrap();
        let before = super::plan::remote(flavor);
        let mut local = super::plan::pair(&before);
        let unchanged = plan_list(local.clone(), Some(before.clone()), &refs, &[]).unwrap();
        assert!(unchanged.adds.is_empty());
        assert!(unchanged.removes.is_empty());
        assert_eq!(unchanged.installed.len(), 2);
        local.values.pop_first();
        let error = plan_list(local, Some(before), &refs, &[]).unwrap_err();
        assert_eq!(error.kind, elasticctl_core::ErrorKind::Conflict);
        assert!(error.message.contains("referenced more than once"));
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method == "GET" && request.body.is_empty())
        );
    }
}

#[tokio::test]
async fn unreadable_container_or_second_namespace_never_returns_a_partial_scan() {
    for container_status in [200, 403] {
        let flavor = FLAVORS[0];
        let server = MockServer::start().await;
        scan_single(&server, flavor, container_status).await;
        if container_status == 200 {
            Mock::given(method("GET"))
                .and(path("/api/exception_lists/_find"))
                .and(query_param("namespace_type", "agnostic"))
                .respond_with(response(&fixture(flavor, "import_wrong_extension"), 403))
                .expect(1)
                .mount(&server)
                .await;
        }
        let error = scan_references(&transport(&server)).await.unwrap_err();
        assert_eq!(error.kind, elasticctl_core::ErrorKind::Permission);
        assert_eq!(error.http_status, Some(403));
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method == "GET")
        );
    }
}
