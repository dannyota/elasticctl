use super::*;
use serde_json::json;

#[test]
fn fixture_preserves_versions_and_scrubs_identity() {
    let mut evidence = Evidence::default();
    evidence.response(
        "probe",
        json!({
            "_version": "WzEsMV0=", "nested": [{"_version": "WzIsMV0="}],
            "created_by": "private-user", "updated_by": "private-user",
            "tie_breaker_id": "private-tie", "id": "private-item",
            "created_at": "2026-11-12T02:00:00Z", "updated_at": "2026-11-12T03:00:00Z",
            "api_key": "private-key"
        }),
    );
    let recorded = &evidence.fixtures[0];
    let body = &recorded.document["response"];
    assert_eq!(body["_version"], "WzEsMV0=");
    assert_eq!(body["nested"][0]["_version"], "WzIsMV0=");
    let encoded = recorded.document.to_string();
    assert!(!encoded.contains("private-"));
    assert!(!encoded.contains("2026-11-12"));
}

use elasticctl_core::{Profile, Transport};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn transport(server: &MockServer) -> Transport {
    Transport::new(&Profile {
        kibana_url: server.uri(),
        es_url: Some(server.uri()),
        api_key: Some("test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 1,
    })
    .unwrap()
}

fn fast() -> Timing {
    Timing {
        budget: Duration::from_millis(40),
        interval: Duration::from_millis(2),
    }
}

async fn page(server: &MockServer, route: &str, body: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn marker_refusal_names_all_ids_and_sends_zero_writes() {
    for (lists, exceptions) in [
        (json!([{"id": "elasticctl-live-vl-old"}]), json!([])),
        (
            json!([]),
            json!([{"id": "elasticctl-live-vl-old-exception", "list_id": "elasticctl-live-vl-old-list"}]),
        ),
    ] {
        let server = MockServer::start().await;
        page(
            &server,
            "/api/status",
            json!({"version": {"number": "1", "build_flavor": "traditional"}}),
        )
        .await;
        page(
            &server,
            "/api/lists/index",
            json!({"list_index": true, "list_item_index": true}),
        )
        .await;
        page(
            &server,
            "/api/lists/_find",
            json!({"total": lists.as_array().unwrap().len(), "data": lists}),
        )
        .await;
        page(
            &server,
            "/api/exception_lists/_find",
            json!({"total": exceptions.as_array().unwrap().len(), "data": exceptions}),
        )
        .await;
        page(
            &server,
            "/api/exception_lists/items/_find",
            json!({"total": 0, "data": []}),
        )
        .await;
        page(&server, "/.items-default/_search", json!({"timed_out": false,
            "_shards": {"failed": 0}, "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}})).await;
        let t = transport(&server);
        let mut session = Session::new(&t, fast());
        let error = run(&mut session, None, std::future::pending::<()>)
            .await
            .err()
            .unwrap();
        assert!(error.message.contains("elasticctl-live-vl-old"));
        assert!(error.message.contains("Manual remediation"));
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| request.method == "GET"));
        assert!(session.evidence.fixtures.iter().all(|f| {
            f.document
                .get("response")
                .is_none_or(|b| b.get("data").is_none())
        }));
    }
}

#[tokio::test]
async fn settle_waits_for_expected_total_and_times_out_even_on_slow_reads() {
    for slow in [false, true] {
        let server = MockServer::start().await;
        let mut response = ResponseTemplate::new(200).set_body_json(json!({"total": 0}));
        if slow {
            response = response.set_delay(Duration::from_secs(1));
        }
        Mock::given(method("GET"))
            .and(path("/api/lists/items/_find"))
            .respond_with(response)
            .mount(&server)
            .await;
        let t = transport(&server);
        let start = tokio::time::Instant::now();
        let error = steps::settle(&mut Session::new(&t, fast()), LIST, 2)
            .await
            .unwrap_err();
        assert!(error.message.contains("settle timed out"));
        assert!(start.elapsed() < Duration::from_millis(500));
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method == "GET")
        );
    }
}

#[tokio::test]
async fn settle_does_not_accept_a_stable_but_incomplete_total() {
    let server = MockServer::start().await;
    let reads = Arc::new(Mutex::new(0));
    let counter = reads.clone();
    Mock::given(method("GET"))
        .and(path("/api/lists/items/_find"))
        .respond_with(move |_: &Request| {
            let mut count = counter.lock().unwrap();
            *count += 1;
            ResponseTemplate::new(200)
                .set_body_json(json!({"total": if *count < 4 { 0 } else { 2 }}))
        })
        .mount(&server)
        .await;
    let t = transport(&server);
    let mut session = Session::new(
        &t,
        Timing {
            budget: Duration::from_secs(1),
            ..fast()
        },
    );
    steps::settle(&mut session, LIST, 2).await.unwrap();
    assert!(*reads.lock().unwrap() >= 5);
}

#[tokio::test]
async fn restore_requires_absent_before_non_lab_and_empty_final_inventory() {
    for (absent, flavor, total, deletes) in [
        (true, "serverless", 0, 1),
        (true, "ech", 0, 1),
        (false, "ech", 0, 0),
        (true, "traditional", 0, 0),
        (true, "ech", 1, 0),
    ] {
        let server = MockServer::start().await;
        page(
            &server,
            "/api/lists/_find",
            json!({"total": total, "data": []}),
        )
        .await;
        Mock::given(method("DELETE"))
            .and(path("/api/lists/index"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/lists/index"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({})))
            .mount(&server)
            .await;
        let t = transport(&server);
        let mut session = Session::new(&t, fast());
        session.before_absent = absent;
        session.init_attempted = true;
        session.evidence.flavor = flavor.to_string();
        cleanup::restore(&mut session).await.unwrap();
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.iter().filter(|r| r.method == "DELETE").count(),
            deletes
        );
        if deletes == 1 {
            assert!(
                requests[0]
                    .url
                    .query_pairs()
                    .any(|(k, v)| k == "per_page" && v == "1")
            );
            assert_eq!(
                session.evidence.fixtures.last().unwrap().name,
                "index_restored"
            );
        }
    }
}

#[tokio::test]
async fn restore_fails_closed_on_missing_total_or_missing_404() {
    for total in [None, Some(0)] {
        let server = MockServer::start().await;
        page(
            &server,
            "/api/lists/_find",
            total.map_or(json!({}), |n| json!({"total": n})),
        )
        .await;
        page(&server, "/api/lists/index", json!({"list_index": true})).await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;
        let t = transport(&server);
        let mut session = Session::new(&t, fast());
        session.before_absent = true;
        session.init_attempted = true;
        session.evidence.flavor = "ech".into();
        assert!(cleanup::restore(&mut session).await.is_err());
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.method == "DELETE")
                .count(),
            usize::from(total.is_some())
        );
    }
}

#[test]
fn fixture_scrubs_hosts_ids_users_timestamps_and_cursors_without_changing_export() {
    let mut evidence = Evidence::new(vec!["private.invalid:9243".into()]);
    evidence.response(
        "identity",
        json!({
            "id": "list-server-id", "tie_breaker_id": "tie-server-id",
            "created_by": "private-user", "updated_by": "private-user",
            "created_at": "2026-11-12", "updated_at": "2026-11-12",
            "url": "https://private.invalid:9243/app", "cursor": "server-cursor",
            "_version": "WzEsMV0=",
            "data": [{"id": "item-server-id", "_version": "WzIsMV0="}],
            "references": [{"id": "exception-server-id", "item_id": ITEM, "list_id": EXCEPTION}]
        }),
    );
    let body = &evidence.fixtures[0].document["response"];
    assert_eq!(body["tie_breaker_id"], "REDACTED");
    assert_eq!(body["created_by"], "REDACTED");
    assert_eq!(body["updated_by"], "REDACTED");
    assert_eq!(
        body["created_at"],
        crate::recorder::markers::ALERT_FIXTURE_TIMESTAMP
    );
    assert_eq!(
        body["updated_at"],
        crate::recorder::markers::ALERT_FIXTURE_TIMESTAMP
    );
    assert!(
        body["id"]
            .as_str()
            .unwrap()
            .starts_with("elasticctl-fixture-")
    );
    assert!(
        body["data"][0]["id"]
            .as_str()
            .unwrap()
            .starts_with("elasticctl-fixture-")
    );
    assert!(
        body["references"][0]["id"]
            .as_str()
            .unwrap()
            .starts_with("elasticctl-fixture-")
    );
    assert_eq!(body["_version"], "WzEsMV0=");
    assert_eq!(body["data"][0]["_version"], "WzIsMV0=");
    assert_eq!(body["cursor"], "elasticctl-fixture-cursor");
    assert_eq!(body["url"], "https://REDACTED.example.invalid/app");
    let text = "z\na-a\nz\na\n";
    evidence.response("export", json!(text));
    assert_eq!(evidence.fixtures[1].document["response"], text);
    evidence.http_response(
        "error",
        415,
        json!({"message": "private-user private.invalid:9243"}),
    );
    assert!(
        !evidence.fixtures[2]
            .document
            .to_string()
            .contains("private")
    );
}

mod stack;
use stack::{Stack, response, stack};

#[tokio::test]
async fn full_pass_uses_cursor_multipart_single_writes_and_preserves_export_order() {
    let (server, state) = stack(Stack::default()).await;
    let t = transport(&server);
    let mut session = Session::new(
        &t,
        Timing {
            budget: Duration::from_secs(2),
            ..fast()
        },
    );
    let recording = run(&mut session, Some("ech".into()), std::future::pending::<()>)
        .await
        .unwrap();
    assert!(recording.dir.ends_with("ech-9.5.1/value_lists"));
    let names: Vec<_> = recording.fixtures.iter().map(|f| f.name).collect();
    assert_eq!(
        names,
        vec![
            "status",
            "index_before",
            "initialize",
            "index_after",
            "container_create",
            "container_read",
            "container_patch",
            "container_patch_stale",
            "container_put_type_ignored",
            "items_find_first",
            "items_find_next",
            "items_export",
            "items_import",
            "items_import_settled",
            "items_delete_id",
            "items_delete_id_absent",
            "spellings_create",
            "lists_find_first",
            "lists_find_next",
            "exception_create",
            "exception_item_create",
            "container_delete_referenced",
            "container_delete",
            "import_too_large",
            "import_wrong_extension",
            "import_absent_list",
            "export_spellings",
            "index_delete",
            "index_restored"
        ]
    );
    assert_eq!(
        recording
            .fixtures
            .iter()
            .find(|f| f.name == "export_spellings")
            .unwrap()
            .document["response"],
        "2001:db8::/32\n10.0.0.1-2001:db8::1\n10.0.0.7/24\n2001:DB8:0:0::1-2001:DB8:0:0::1\n"
    );
    for name in ["lists_find_first", "lists_find_next"] {
        let document = &recording
            .fixtures
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .document;
        assert!(
            document["response"]["data"][0]["id"]
                .as_str()
                .unwrap()
                .starts_with("elasticctl-fixture-")
        );
        assert_eq!(document["response"]["cursor"], "elasticctl-fixture-cursor");
    }
    let referenced = &recording
        .fixtures
        .iter()
        .find(|f| f.name == "container_delete_referenced")
        .unwrap()
        .document["response"];
    assert_eq!(referenced["status_code"], 409);
    assert!(
        referenced["message"]["error"]["references"][0]["exception_item"]["item_id"]
            .as_str()
            .unwrap()
            .starts_with("elasticctl-fixture-")
    );
    {
        let state = state.lock().unwrap();
        assert!(!state.bootstrapped);
        assert!(state.lists.is_empty());
        assert!(state.exception.is_none());
        assert!(state.item.is_none());
    }
    let requests = server.received_requests().await.unwrap();
    let imports: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path().ends_with("/_import"))
        .collect();
    assert_eq!(imports.len(), 4);
    for request in imports {
        assert!(
            request
                .url
                .query_pairs()
                .any(|(k, v)| k == "refresh" && v == "wait_for")
        );
        assert!(
            String::from_utf8_lossy(&request.body)
                .contains("name=\"file\"; filename=\"elasticctl-live-vl.")
        );
    }
    let item_deletes: Vec<_> = requests
        .iter()
        .filter(|r| r.method == "DELETE" && r.url.path() == "/api/lists/items")
        .collect();
    let ids: Vec<_> = item_deletes
        .iter()
        .map(|r| {
            assert!(!r.url.query_pairs().any(|(k, _)| k == "value"));
            r.url
                .query_pairs()
                .find(|(k, _)| k == "id")
                .unwrap()
                .1
                .into_owned()
        })
        .collect();
    assert_eq!(
        ids,
        [
            format!("{LIST}-item-0"),
            format!("{LIST}-item-1"),
            format!("{LIST}-item-0")
        ]
    );
    for request in requests.iter().filter(|r| r.method == "DELETE") {
        assert!(!request.url.as_str().contains("References"));
        assert!(
            request.url.path() == "/api/lists/index"
                || request
                    .url
                    .query_pairs()
                    .any(|(k, v)| matches!(k.as_ref(), "id" | "list_id" | "item_id")
                        && v.starts_with(PREFIX))
        );
    }
    assert_eq!(requests.iter().filter(|r| r.method == "PATCH").count(), 2);
    let text = serde_json::to_string(
        &recording
            .fixtures
            .iter()
            .map(|f| &f.document)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    for private in [
        "server-exception-id",
        "server-exception-item-id",
        "server-import-",
        "real-cursor",
        &session.nonce,
    ] {
        assert!(!text.contains(private), "leaked {private}");
    }
    let dir = std::env::temp_dir().join(format!(
        "value-list-refusals-{}-{}",
        std::process::id(),
        server.address().port()
    ));
    write_recording(Recording {
        dir: dir.clone(),
        ..recording
    })
    .unwrap();
    for (name, status, message) in [
        ("container_patch_stale", 409, "stale version"),
        ("import_too_large", 413, "file too large"),
        ("import_wrong_extension", 415, "unsupported extension"),
        ("import_absent_list", 409, "list does not exist"),
    ] {
        let document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join(format!("{name}.json"))).unwrap())
                .unwrap();
        assert_eq!(document["http_status"], status, "{name}");
        assert_eq!(
            document["response"],
            json!({
                "status_code": status, "message": message, "created_by": "REDACTED"
            }),
            "{name}"
        );
        assert!(document.get("error").is_none(), "{name}");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn cleanup_after_failure_uses_exact_ids_in_dependency_order_and_verifies_absence() {
    let (server, state) = stack(Stack {
        fail: Some("reference"),
        ..Default::default()
    })
    .await;
    let t = transport(&server);
    let mut session = Session::new(
        &t,
        Timing {
            budget: Duration::from_secs(1),
            ..fast()
        },
    );
    assert!(
        run(&mut session, Some("ech".into()), std::future::pending::<()>)
            .await
            .is_err()
    );
    let requests = server.received_requests().await.unwrap();
    let deletes: Vec<_> = requests
        .iter()
        .filter(|r| r.method == "DELETE" && r.url.path() != "/api/lists/items")
        .map(|r| {
            (
                r.url.path().to_string(),
                r.url.query().unwrap_or("").to_string(),
            )
        })
        .collect();
    assert!(deletes[0].0.ends_with("exception_lists/items"));
    assert!(deletes[0].1.contains(ITEM));
    assert_eq!(deletes[1].0, "/api/exception_lists");
    assert!(deletes[1].1.contains(EXCEPTION));
    assert_eq!(deletes[2], ("/api/lists".into(), format!("id={RANGES}")));
    assert_eq!(deletes[3], ("/api/lists".into(), format!("id={LIST}")));
    for (index, request) in requests
        .iter()
        .enumerate()
        .filter(|(_, r)| r.method == "DELETE" && r.url.path() != "/api/lists/items")
    {
        let next = &requests[index + 1];
        assert_eq!(next.method, "GET");
        assert_eq!(next.url.path(), request.url.path());
    }
    assert!(state.lock().unwrap().lists.is_empty());
    assert!(!state.lock().unwrap().bootstrapped);
}

#[tokio::test]
async fn cleanup_failure_is_reported_and_prevents_restore_and_fixture_output() {
    let (server, _) = stack(Stack {
        fail: Some("create"),
        cleanup_refuses: true,
        ..Default::default()
    })
    .await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    let error = run(&mut session, Some("ech".into()), std::future::pending::<()>)
        .await
        .err()
        .unwrap();
    assert!(error.message.contains("cleanup failed"));
    assert!(!session.evidence.fixtures.is_empty());
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| !(r.method == "DELETE" && r.url.path() == "/api/lists/index"))
    );
}

#[tokio::test]
async fn lab_flow_unavailable_uses_fallback_and_keeps_indices() {
    let (server, state) = stack(Stack {
        flow_unavailable: true,
        ..Default::default()
    })
    .await;
    let t = transport(&server);
    let mut session = Session::new(
        &t,
        Timing {
            budget: Duration::from_secs(2),
            ..fast()
        },
    );
    let recording = run(
        &mut session,
        Some("traditional".into()),
        std::future::pending::<()>,
    )
    .await
    .unwrap();
    assert!(
        recording
            .fixtures
            .iter()
            .any(|f| f.name == "initialize_fallback")
    );
    assert!(state.lock().unwrap().bootstrapped);
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| !(r.method == "DELETE" && r.url.path() == "/api/lists/index"))
    );
}

#[tokio::test]
async fn cleanup_refuses_a_replaced_object_and_never_deletes_by_prefix() {
    let mut state = Stack::default();
    state.lists.insert(
        LIST.into(),
        json!({"id": LIST, "meta": {"marker": MARKER, "recorder_nonce": "another-run"}}),
    );
    let (server, _) = stack(state).await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    session.baseline_checked = true;
    session.lists.push(LIST);
    assert!(
        cleanup::finish(&mut session)
            .await
            .unwrap_err()
            .message
            .contains("ownership changed")
    );
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
async fn cleanup_rechecks_after_delete_and_reports_a_survivor() {
    let server = MockServer::start().await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    page(
        &server,
        "/api/lists",
        json!({"id": LIST, "meta": {"marker": MARKER, "recorder_nonce": session.nonce}}),
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path("/api/lists"))
        .respond_with(response(200, json!({})))
        .mount(&server)
        .await;
    let error = cleanup::delete_owned(
        &mut session,
        &format!("/api/lists?id={LIST}"),
        LIST,
        false,
        false,
    )
    .await
    .unwrap_err();
    assert!(error.message.contains("verification still found"));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[1].method, "DELETE");
    assert!(requests[2..].iter().all(|request| request.method == "GET"));
}

#[tokio::test]
async fn preflight_checks_later_cursor_pages_and_both_exception_namespaces() {
    let server = MockServer::start().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let captured = seen.clone();
    Mock::given(method("GET")).respond_with(move |r: &Request| {
        captured.lock().unwrap().push(r.url.to_string());
        let query: std::collections::BTreeMap<_, _> = r.url.query_pairs().into_owned().collect();
        if r.url.path() == "/.items-default/_search" {
            response(200, json!({"timed_out": false, "_shards": {"failed": 0},
                "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}))
        } else if r.url.path() == "/api/lists/_find" {
            if query.get("page").map(String::as_str) == Some("1") {
                response(200, json!({"total": 2, "data": [{"id": "unrelated"}], "cursor": "cursor1"}))
            } else if query.get("page").map(String::as_str) == Some("2") && query.get("cursor").map(String::as_str) == Some("cursor1") {
                response(200, json!({"total": 2, "data": [{"id": "elasticctl-live-vl-later"}]}))
            } else { response(400, json!({})) }
        } else if r.url.path() == "/api/exception_lists/_find" && query.get("namespace_type").map(String::as_str) == Some("agnostic") {
            response(200, json!({"total": 1, "data": [{"id": "elasticctl-live-vl-agnostic-id", "list_id": "elasticctl-live-vl-agnostic-list"}]}))
        } else { response(200, json!({"total": 0, "data": []})) }
    }).mount(&server).await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    let error = inventory::require_clear(&mut session).await.unwrap_err();
    for id in [
        "elasticctl-live-vl-later",
        "elasticctl-live-vl-agnostic-id",
        "elasticctl-live-vl-agnostic-list",
    ] {
        assert!(error.message.contains(id));
    }
    assert_eq!(seen.lock().unwrap().len(), 6);
}

#[tokio::test]
async fn cleanup_waits_for_a_create_whose_response_was_lost() {
    let (server, state) = stack(Stack {
        fail: Some("late_create"),
        ..Default::default()
    })
    .await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    assert!(
        run(&mut session, Some("ech".into()), std::future::pending::<()>)
            .await
            .is_err()
    );
    assert!(
        state.lock().unwrap().lists.is_empty(),
        "late create must be removed by its exact id"
    );
    assert!(!state.lock().unwrap().bootstrapped);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.method == "POST" && r.url.path() == "/api/lists")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.method == "DELETE" && r.url.path() == "/api/lists")
            .count(),
        1
    );
}

#[tokio::test]
async fn cleanup_clears_a_definitely_refused_create_and_removes_its_parents() {
    let (server, state) = stack(Stack {
        fail: Some("reference_rejected"),
        ..Default::default()
    })
    .await;
    let t = transport(&server);
    let mut session = Session::new(
        &t,
        Timing {
            budget: Duration::from_secs(1),
            ..fast()
        },
    );
    assert!(
        run(&mut session, Some("ech".into()), std::future::pending::<()>)
            .await
            .is_err()
    );
    let state = state.lock().unwrap();
    assert!(state.lists.is_empty());
    assert!(state.exception.is_none());
    assert!(!state.bootstrapped);
}

mod regressions;

mod references;

mod privacy;

mod review;

mod timeouts;

#[tokio::test]
async fn cleanup_retries_delayed_items_and_reports_permanent_items() {
    for (reads, succeeds) in [(2, true), (usize::MAX, false)] {
        let (server, state) = stack(Stack {
            bootstrapped: true,
            deleted_item_reads: reads,
            ..Default::default()
        })
        .await;
        let t = transport(&server);
        let mut session = Session::new(
            &t,
            Timing {
                budget: Duration::from_millis(200),
                ..fast()
            },
        );
        session.baseline_checked = true;
        session.before_absent = true;
        session.init_attempted = true;
        session.evidence.flavor = "ech".into();
        session.lists.push(LIST);
        {
            let mut state = state.lock().unwrap();
            state.lists.insert(
                LIST.into(),
                json!({"id": LIST, "meta": {"marker": MARKER, "recorder_nonce": session.nonce}}),
            );
            state.values.insert(
                LIST.into(),
                vec![json!({"id": "orphan-one"}), json!({"id": "orphan-two"})],
            );
        }
        let result = cleanup::finish(&mut session).await;
        if succeeds {
            result.unwrap();
            assert!(!state.lock().unwrap().bootstrapped);
        } else {
            let error = result.unwrap_err();
            assert!(
                error
                    .message
                    .contains("orphan-one (list_id=elasticctl-live-vl-record)")
            );
            assert!(
                error
                    .message
                    .contains("orphan-two (list_id=elasticctl-live-vl-record)")
            );
            assert!(state.lock().unwrap().bootstrapped);
            assert!(
                !server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .any(|r| r.method == "DELETE" && r.url.path() == "/api/lists/index")
            );
        }
    }
}

#[tokio::test]
async fn unexpected_status_names_step_without_body() {
    let (server, _) = stack(Stack {
        fail: Some("bad_status"),
        ..Default::default()
    })
    .await;
    let t = transport(&server);
    let mut session = Session::new(
        &t,
        Timing {
            budget: Duration::from_secs(2),
            ..fast()
        },
    );
    let error = run(&mut session, Some("ech".into()), std::future::pending::<()>)
        .await
        .err()
        .unwrap();
    assert!(
        error
            .message
            .contains("container_patch_stale: expected HTTP 409, received 400"),
        "{}",
        error.message
    );
    assert!(!error.message.contains("private-body"));
}

#[tokio::test]
async fn pages_must_match_export_and_duplicate_ids() {
    for (fail, expected) in [
        ("wrong_page", "items_export"),
        ("wrong_item_id", "items_delete_id"),
    ] {
        let (server, _) = stack(Stack {
            fail: Some(fail),
            ..Default::default()
        })
        .await;
        let t = transport(&server);
        let mut session = Session::new(
            &t,
            Timing {
                budget: Duration::from_secs(2),
                ..fast()
            },
        );
        let error = run(&mut session, Some("ech".into()), std::future::pending::<()>)
            .await
            .err()
            .unwrap();
        assert!(error.message.contains(expected), "{}", error.message);
        assert!(
            !server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|r| r.method == "DELETE" && r.url.path() == "/api/lists/items")
        );
    }
}

#[tokio::test]
async fn absent_item_delete_requires_404_and_names_step() {
    for status in [400, 500, 503] {
        let (server, state) = stack(Stack::default()).await;
        let calls = Arc::new(Mutex::new(0));
        let count = calls.clone();
        Mock::given(method("DELETE"))
            .and(path("/api/lists/items"))
            .respond_with(move |r: &Request| {
                let mut n = count.lock().unwrap();
                *n += 1;
                if *n < 3 {
                    let id = r.url.query_pairs().find(|(k, _)| k == "id").unwrap().1;
                    state
                        .lock()
                        .unwrap()
                        .values
                        .get_mut(LIST)
                        .unwrap()
                        .retain(|v| v["id"] != id.as_ref());
                }
                response(
                    if *n == 3 { status } else { 200 },
                    json!({"message": "private-body"}),
                )
            })
            .with_priority(1)
            .mount(&server)
            .await;
        let t = transport(&server);
        let mut session = Session::new(
            &t,
            Timing {
                budget: Duration::from_secs(2),
                ..fast()
            },
        );
        let error = run(&mut session, Some("ech".into()), std::future::pending::<()>)
            .await
            .err()
            .unwrap();
        assert!(
            error.message.contains(&format!(
                "items_delete_id_absent: expected HTTP 404, received {status}"
            )),
            "{}",
            error.message
        );
        assert!(!error.message.contains("private-body"));
    }
}

#[tokio::test]
async fn cleanup_preserves_orphans_after_audit_errors() {
    let (server, state) = stack(Stack {
        bootstrapped: true,
        ..Default::default()
    })
    .await;
    let calls = Arc::new(Mutex::new(0));
    Mock::given(method("GET"))
        .and(path("/.items-default/_search"))
        .respond_with(move |_: &Request| {
            let mut n = calls.lock().unwrap();
            *n += 1;
            if *n == 1 {
                response(200, json!({"timed_out": false, "_shards": {"failed": 0}, "hits": {"total": {"value": 2, "relation": "eq"}, "hits": [
                    {"_id": "orphan-one", "_source": {"list_id": LIST}},
                    {"_id": "orphan-two", "_source": {"list_id": LIST}}
                ]}}))
            } else {
                response(400, json!({"message": "private-body"}))
            }
        })
        .with_priority(1).mount(&server).await;
    let t = transport(&server);
    let mut session = Session::new(
        &t,
        Timing {
            budget: Duration::from_millis(200),
            ..fast()
        },
    );
    session.baseline_checked = true;
    session.before_absent = true;
    session.init_attempted = true;
    session.evidence.flavor = "ech".into();
    let error = cleanup::finish(&mut session).await.unwrap_err();
    assert!(error.message.contains("orphan-one"), "{}", error.message);
    assert!(error.message.contains("orphan-two"), "{}", error.message);
    assert!(error.message.contains("status=400"), "{}", error.message);
    assert!(state.lock().unwrap().bootstrapped);
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.method == "DELETE" && r.url.path() == "/api/lists/index")
    );
}
