use super::*;

async fn refused_write(verb: &str, route: &str) {
    let (server, state) = stack(Stack::default()).await;
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(response(400, json!({"message": "write refused"})))
        .with_priority(1)
        .mount(&server)
        .await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    let error = run(&mut session, Some("ech".into()), std::future::pending::<()>)
        .await
        .err()
        .unwrap();
    assert!(state.lock().unwrap().lists.is_empty(), "{}", error.message);
    assert!(!state.lock().unwrap().bootstrapped);
    assert!(session.pending_imports.is_empty());
    assert!(
        !error.message.contains("cleanup failed"),
        "{}",
        error.message
    );
    if verb == "DELETE" {
        assert_eq!(
            error.message,
            "items_delete_id: expected HTTP 200, received 400"
        );
    } else {
        assert_eq!(error.http_status, Some(400));
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.method == verb && r.url.path() == route)
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
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.method == "DELETE" && r.url.path() == "/api/lists/index")
            .count(),
        1
    );
}

#[tokio::test]
async fn refused_item_write_deletes_owned_list_and_restores() {
    refused_write("POST", "/api/lists/items").await;
}

#[tokio::test]
async fn refused_import_deletes_owned_list_and_restores() {
    refused_write("POST", "/api/lists/items/_import").await;
}

#[tokio::test]
async fn refused_item_delete_deletes_owned_list_and_restores() {
    refused_write("DELETE", "/api/lists/items").await;
}

async fn written(recording: Recording, port: u16) -> std::collections::BTreeMap<String, Vec<u8>> {
    let dir = std::env::temp_dir().join(format!("value-list-review-{port}"));
    write_recording(Recording {
        dir: dir.clone(),
        ..recording
    })
    .unwrap();
    let files = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_str().unwrap().to_string(),
                std::fs::read(path).unwrap(),
            )
        })
        .collect();
    std::fs::remove_dir_all(dir).unwrap();
    files
}

async fn inventory_recording(
    ids: &[&str],
    identities: bool,
) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut initial = Stack {
        bootstrapped: true,
        ..Default::default()
    };
    if !ids.is_empty() {
        for &id in ids {
            initial.lists.insert(id.into(), json!({"id": id}));
        }
    }
    let (server, state) = stack(initial).await;
    if identities {
        let containers = state.clone();
        Mock::given(method("GET")).and(path("/api/exception_lists/_find"))
            .and(wiremock::matchers::query_param("per_page", "100"))
            .respond_with(move |r: &Request| {
                let mut rows = if r.url.query_pairs().any(|(k, _)| k == "filter") { vec![] } else { vec![json!({"id": "unrelated-container", "list_id": "unrelated-list", "created_by": "10"})] };
                if !r.url.query_pairs().any(|(k, v)| k == "namespace_type" && v == "agnostic") {
                    rows.extend(containers.lock().unwrap().exception.iter().cloned());
                }
                response(200, json!({"total": rows.len(), "data": rows}))
            }).with_priority(1).mount(&server).await;
        let items = state.clone();
        Mock::given(method("GET")).and(path("/api/exception_lists/items/_find"))
            .and(wiremock::matchers::query_param("per_page", "100"))
            .respond_with(move |r: &Request| {
                let mut rows = if r.url.query_pairs().any(|(k, v)| k == "per_page" && v == "10") { vec![] } else { vec![json!({"id": "unrelated-item", "item_id": "unrelated-item", "created_by": "10", "entries": []})] };
                rows.extend(items.lock().unwrap().item.iter().cloned());
                response(200, json!({"total": rows.len(), "data": rows}))
            }).with_priority(1).mount(&server).await;
    }
    let t = transport(&server);
    let mut session = Session::new(
        &t,
        Timing {
            budget: Duration::from_secs(1),
            ..fast()
        },
    );
    let recording = run(&mut session, Some("ech".into()), std::future::pending::<()>)
        .await
        .unwrap();
    written(recording, server.address().port()).await
}

#[tokio::test]
async fn unrelated_inventory_cannot_change_fixture_bytes() {
    let ordinary = inventory_recording(&[], false).await;
    let unrelated = inventory_recording(&["10", "0", "1"], true).await;
    let changed: Vec<_> = ordinary
        .keys()
        .filter(|name| ordinary[*name] != unrelated[*name])
        .collect();
    assert!(
        changed.is_empty(),
        "inventory changed fixtures: {changed:?}"
    );
}

#[tokio::test]
async fn bootstrap_refusals_keep_real_scrubbed_response_bodies() {
    for (flavor, status) in [("ech", 404), ("traditional", 404), ("traditional", 405)] {
        let (server, state) = stack(Stack {
            flow_unavailable: flavor == "traditional",
            ..Default::default()
        })
        .await;
        let refusal = json!({"statusCode": 404, "error": "Not Found", "created_by": "private-operator",
            "message": "User private-operator cannot read elasticctl-live-vl-absent"});
        let body = refusal.clone();
        Mock::given(method("GET"))
            .and(path("/api/lists/index"))
            .respond_with(move |_: &Request| {
                if state.lock().unwrap().bootstrapped {
                    response(200, json!({"list_index": true, "list_item_index": true}))
                } else {
                    response(404, body.clone())
                }
            })
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/security_solution/initialize"))
            .and(move |_: &Request| flavor == "traditional")
            .respond_with(response(status, refusal))
            .with_priority(1)
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
        let recording = run(
            &mut session,
            Some(flavor.into()),
            std::future::pending::<()>,
        )
        .await
        .unwrap();
        let files = written(recording, server.address().port()).await;
        for name in if flavor == "ech" {
            ["index_before", "index_restored"]
        } else {
            ["index_before", "initialize_unavailable"]
        } {
            let document: serde_json::Value =
                serde_json::from_slice(&files[&format!("{name}.json")]).unwrap();
            assert_eq!(
                document["http_status"],
                if name == "initialize_unavailable" {
                    status
                } else {
                    404
                },
                "{name}: {document}"
            );
            assert_eq!(
                document["response"],
                json!({"statusCode": 404, "error": "Not Found", "created_by": "REDACTED",
                "message": "User REDACTED cannot read REDACTED"}),
                "{name}: {document}"
            );
        }
    }
}

#[tokio::test]
async fn uncertain_writes_keep_pending_totals_and_block_restore() {
    for (verb, route) in [
        ("POST", "/api/lists/items"),
        ("POST", "/api/lists/items/_import"),
        ("DELETE", "/api/lists/items"),
    ] {
        for status in [408, 503] {
            let (server, state) = stack(Stack::default()).await;
            Mock::given(method(verb))
                .and(path(route))
                .respond_with(response(status, json!({"message": "uncertain write"})))
                .with_priority(1)
                .mount(&server)
                .await;
            let t = transport(&server);
            let mut session = Session::new(&t, fast());
            let error = run(&mut session, Some("ech".into()), std::future::pending::<()>)
                .await
                .err()
                .unwrap();
            assert!(
                error.message.contains("cleanup failed"),
                "{verb} {route} {status}: {}",
                error.message
            );
            assert_eq!(
                session.pending_imports[LIST],
                Some(if verb == "DELETE" {
                    3
                } else if route.ends_with("_import") {
                    4
                } else {
                    1
                })
            );
            let state = state.lock().unwrap();
            assert!(state.lists.contains_key(LIST));
            assert!(state.bootstrapped);
        }
    }
}

#[tokio::test]
async fn server_error_delete_can_settle_on_known_total_and_restore() {
    let (server, state) = stack(Stack::default()).await;
    let changed = state.clone();
    Mock::given(method("DELETE"))
        .and(path("/api/lists/items"))
        .respond_with(move |r: &Request| {
            let id = r
                .url
                .query_pairs()
                .find(|(k, _)| k == "id")
                .unwrap()
                .1
                .into_owned();
            changed
                .lock()
                .unwrap()
                .values
                .get_mut(LIST)
                .unwrap()
                .retain(|v| v["id"] != id);
            response(503, json!({"message": "answer lost after delete"}))
        })
        .with_priority(1)
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
    let error = run(&mut session, Some("ech".into()), std::future::pending::<()>)
        .await
        .err()
        .unwrap();
    assert_eq!(error.http_status, Some(503));
    assert!(
        !error.message.contains("cleanup failed"),
        "{}",
        error.message
    );
    assert!(state.lock().unwrap().lists.is_empty());
    assert!(!state.lock().unwrap().bootstrapped);
    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "DELETE" && r.url.path() == "/api/lists/items")
            .count(),
        1
    );
}

#[tokio::test]
async fn unrelated_inventory_id_cannot_rewrite_ip_values() {
    assert_eq!(
        inventory_recording(&[], false).await,
        inventory_recording(&["10"], false).await
    );
}

#[tokio::test]
async fn unrelated_inventory_identity_cannot_rewrite_ip_values() {
    assert_eq!(
        inventory_recording(&[], false).await,
        inventory_recording(&[], true).await
    );
}

#[tokio::test]
async fn unrelated_short_inventory_ids_cannot_rewrite_fixtures() {
    assert_eq!(
        inventory_recording(&[], false).await,
        inventory_recording(&["0", "1"], false).await
    );
}

#[tokio::test]
async fn initialize_501_stays_pending_and_still_audits_cleanup() {
    let (server, state) = stack(Stack::default()).await;
    Mock::given(method("POST"))
        .and(path("/api/security_solution/initialize"))
        .respond_with(response(501, json!({"message": "not implemented"})))
        .with_priority(1)
        .mount(&server)
        .await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    let error = run(
        &mut session,
        Some("traditional".into()),
        std::future::pending::<()>,
    )
    .await
    .err()
    .unwrap();
    assert!(error.message.contains("received 501"));
    assert!(session.pending_init);
    assert!(
        error.message.contains("pending initialize"),
        "{}",
        error.message
    );
    assert!(
        session
            .evidence
            .fixtures
            .iter()
            .all(|f| !matches!(f.name, "initialize_unavailable" | "initialize_fallback"))
    );
    assert!(state.lock().unwrap().lists.is_empty());
    assert!(!state.lock().unwrap().bootstrapped);
    let requests = server.received_requests().await.unwrap();
    let initialization = requests.iter().position(|r| r.method == "POST").unwrap();
    assert!(
        requests[initialization + 1..]
            .iter()
            .all(|r| r.method == "GET")
    );
    assert_eq!(
        requests[initialization + 1..]
            .iter()
            .filter(|r| r.url.path() == "/api/exception_lists/_find")
            .count(),
        2
    );
    assert!(
        requests[initialization + 1..]
            .iter()
            .any(|r| r.url.path() == "/.items-default/_search")
    );
}
