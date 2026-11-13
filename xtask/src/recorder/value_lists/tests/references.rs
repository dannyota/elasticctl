use super::*;
use serde_json::Value;

async fn reference_scan(items: Vec<Value>, namespace: &'static str) {
    let (server, _) = stack(Stack::default()).await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/_find"))
        .respond_with(move |r: &Request| {
            let selected = r.url.query_pairs().any(|(k, v)| k == "namespace_type" && v == namespace);
            response(200, if selected {
                json!({"total": 1, "data": [{"id": "ordinary-container", "list_id": "ordinary-list"}]})
            } else { json!({"total": 0, "data": []}) })
        })
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/items/_find"))
        .and(wiremock::matchers::query_param("list_id", "ordinary-list"))
        .and(wiremock::matchers::query_param("namespace_type", namespace))
        .and(wiremock::matchers::query_param("per_page", "100"))
        .respond_with(move |r: &Request| {
            let later = r.url.query_pairs().any(|(k, v)| k == "page" && v == "2");
            response(
                200,
                json!({"total": 2, "data": if later { items.clone() } else {
                    vec![json!({"item_id": "ordinary-item", "entries": []})]
                }}),
            )
        })
        .with_priority(1)
        .mount(&server)
        .await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    let error = run(&mut session, None, std::future::pending::<()>)
        .await
        .err()
        .unwrap();
    for id in [
        "ordinary-list",
        "referencing-item",
        "elasticctl-live-vl-record",
    ] {
        assert!(error.message.contains(id), "{}", error.message);
    }
    assert!(!session.baseline_checked);
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
}

#[tokio::test]
async fn preflight_refuses_installed_list_reference_without_writes() {
    reference_scan(
        vec![json!({"item_id": "referencing-item", "entries": [{
            "type": "list", "field": "source.ip", "operator": "included",
            "list": {"id": "elasticctl-live-vl-record", "type": "ip_range"}
        }]})],
        "single",
    )
    .await;
}

#[tokio::test]
async fn preflight_refuses_nested_list_reference_without_writes() {
    reference_scan(
        vec![json!({"item_id": "referencing-item", "entries": [{
            "type": "nested", "field": "process", "entries": [{
                "type": "list", "field": "source.ip", "operator": "included",
                "list": {"id": "elasticctl-live-vl-record", "type": "ip_range"}
            }]
        }]})],
        "agnostic",
    )
    .await;
}

#[tokio::test]
async fn preflight_refuses_incomplete_or_undecodable_item_pages() {
    for failure in [
        "missing_total",
        "missing_data",
        "empty_page",
        "changed_total",
        "unbounded",
        "unreadable",
        "bad_list",
        "bad_nested",
        "bad_entry",
    ] {
        let (server, _) = stack(Stack::default()).await;
        Mock::given(method("GET"))
            .and(path("/api/exception_lists/_find"))
            .respond_with(response(
                200,
                json!({"total": 1, "data": [{
                    "id": "ordinary-container", "list_id": "ordinary-list"
                }]}),
            ))
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/exception_lists/items/_find"))
            .respond_with(move |r: &Request| {
                let later = r.url.query_pairs().any(|(k, v)| k == "page" && v != "1");
                let item = json!({"item_id": "ordinary-item", "entries": []});
                let body = match failure {
                    "missing_total" => json!({"data": []}),
                    "missing_data" => json!({"total": 0}),
                    "empty_page" => json!({"total": 1, "data": []}),
                    "changed_total" => json!({"total": if later {2} else {3}, "data": [item]}),
                    "unbounded" => json!({"total": 101, "data": [item]}),
                    "bad_list" => json!({"total": 1, "data": [{"item_id": "ordinary-item", "entries": [{"type": "list"}]}]}),
                    "bad_nested" => json!({"total": 1, "data": [{"item_id": "ordinary-item", "entries": [{"type": "nested", "entries": null}]}]}),
                    "bad_entry" => json!({"total": 1, "data": [{"item_id": "ordinary-item", "entries": [null]}]}),
                    _ => return response(503, json!({})),
                };
                response(200, body)
            })
            .with_priority(1)
            .mount(&server).await;
        let t = transport(&server);
        let mut session = Session::new(&t, fast());
        assert!(
            run(&mut session, None, std::future::pending::<()>)
                .await
                .is_err(),
            "{failure}"
        );
        assert!(!session.baseline_checked, "{failure}");
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method == "GET"),
            "{failure}"
        );
    }
}
