use super::*;

#[tokio::test]
async fn missing_es_url_refuses_before_any_request() {
    let server = MockServer::start().await;
    let t = Transport::new(&Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 1,
    })
    .unwrap();
    let mut session = Session::new(&t, fast());
    let error = run(&mut session, None, std::future::pending::<()>)
        .await
        .err()
        .unwrap();
    assert!(error.message.starts_with("usage:"), "{}", error.message);
    assert!(error.message.contains("ELASTICCTL_ES_URL"));
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(session.evidence.fixtures.is_empty());
}

#[tokio::test]
async fn unexpected_refusal_status_fails_without_resending() {
    for patch in [false, true] {
        for status in [400, 503] {
            let (server, state) = stack(Stack::default()).await;
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = calls.clone();
            Mock::given(method(if patch { "PATCH" } else { "POST" }))
                .and(path(if patch {
                    "/api/lists"
                } else {
                    "/api/lists/items/_import"
                }))
                .and(move |request: &Request| {
                    if patch {
                        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0
                    } else {
                        String::from_utf8_lossy(&request.body).contains(".json\"")
                    }
                })
                .respond_with(response(status, json!({"message": "unexpected refusal"})))
                .with_priority(1)
                .mount(&server)
                .await;
            let t = transport(&server);
            let mut session = Session::new(
                &t,
                Timing {
                    budget: Duration::from_millis(150),
                    ..fast()
                },
            );
            let error = run(&mut session, Some("ech".into()), std::future::pending::<()>)
                .await
                .err()
                .unwrap();
            let unresolved = !patch && status == 503;
            assert_eq!(
                error.message.contains("cleanup failed"),
                unresolved,
                "{}",
                error.message
            );
            if status == 400 {
                assert!(error.message.contains("expected HTTP"), "{}", error.message);
            } else if !unresolved {
                assert_eq!(error.http_status, Some(503));
            } else {
                assert!(error.message.contains(RANGES));
                assert!(error.message.contains("after the import settles"));
            }
            let requests = server.received_requests().await.unwrap();
            if patch {
                assert_eq!(requests.iter().filter(|r| r.method == "PATCH").count(), 2);
            } else {
                assert_eq!(
                    requests
                        .iter()
                        .filter(|r| {
                            r.url.path().ends_with("/_import")
                                && String::from_utf8_lossy(&r.body).contains(".json\"")
                        })
                        .count(),
                    1
                );
                let settled = requests.iter().any(|r| {
                    r.url.path() == "/api/lists/items/_find"
                        && r.url
                            .query_pairs()
                            .any(|(k, v)| k == "list_id" && v == RANGES)
                });
                assert!(!settled, "unknown import totals cannot be settled by reads");
            }
            let name = if patch {
                "container_patch_stale"
            } else {
                "import_wrong_extension"
            };
            assert!(session.evidence.fixtures.iter().all(|f| f.name != name));
            let state = state.lock().unwrap();
            assert_eq!(state.lists.is_empty(), !unresolved);
            assert_eq!(state.bootstrapped, unresolved);
        }
    }
}

async fn uncertain_delete(delayed: bool) {
    let mut errors = Vec::new();
    let server = MockServer::start().await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    page(
        &server,
        "/api/lists",
        json!({"id": LIST, "meta": {
            "marker": MARKER, "recorder_nonce": session.nonce
        }}),
    )
    .await;
    let mut answer = response(503, json!({}));
    if delayed {
        answer = answer.set_delay(Duration::from_secs(2));
    }
    Mock::given(method("DELETE"))
        .and(path("/api/lists"))
        .respond_with(answer)
        .mount(&server)
        .await;
    for _ in 0..2 {
        let error = cleanup::delete_owned(
            &mut session,
            &format!("/api/lists?id={LIST}"),
            LIST,
            false,
            false,
        )
        .await
        .unwrap_err();
        errors.push(error);
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.iter().filter(|r| r.method == "DELETE").count(), 1);
    assert!(requests.iter().filter(|r| r.method == "GET").count() > 2);
    assert!(errors.iter().all(|error| error.message.contains(LIST)));
}

#[tokio::test]
async fn failed_cleanup_delete_is_polled_and_never_resent() {
    uncertain_delete(false).await;
}

#[tokio::test]
async fn timed_out_cleanup_delete_is_polled_and_never_resent() {
    uncertain_delete(true).await;
}

#[tokio::test]
async fn uncertain_cleanup_delete_can_settle_by_reads() {
    let server = MockServer::start().await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    let nonce = session.nonce.clone();
    let reads = Arc::new(Mutex::new(0));
    let count = reads.clone();
    Mock::given(method("GET"))
        .and(path("/api/lists"))
        .respond_with(move |_: &Request| {
            let mut count = count.lock().unwrap();
            *count += 1;
            if *count < 4 {
                response(
                    200,
                    json!({"id": LIST, "meta": {
                        "marker": MARKER, "recorder_nonce": nonce
                    }}),
                )
            } else {
                response(404, json!({}))
            }
        })
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .respond_with(response(503, json!({})))
        .mount(&server)
        .await;
    cleanup::delete_owned(
        &mut session,
        &format!("/api/lists?id={LIST}"),
        LIST,
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(*reads.lock().unwrap(), 4);
}

#[tokio::test]
async fn cleanup_rejects_stable_total_below_import_target() {
    let (server, state) = stack(Stack::default()).await;
    let importing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sent = importing.clone();
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_import"))
        .respond_with(move |_: &Request| {
            sent.store(true, std::sync::atomic::Ordering::SeqCst);
            response(200, json!({}))
        })
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/lists/items/_find"))
        .and(move |_: &Request| importing.load(std::sync::atomic::Ordering::SeqCst))
        .respond_with(response(200, json!({"total": 2, "data": []})))
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
        "{}",
        error.message
    );
    assert!(error.message.contains(LIST), "{}", error.message);
    assert!(state.lock().unwrap().lists.contains_key(LIST));
    let requests = server.received_requests().await.unwrap();
    assert!(
        !requests
            .iter()
            .any(|r| r.method == "DELETE" && r.url.path() == "/api/lists")
    );
    assert!(!requests.iter().any(restore_read));
}

fn restore_read(request: &Request) -> bool {
    request.url.path() == "/api/lists/_find"
        && !request.url.query_pairs().any(|(key, _)| key == "filter")
        && request
            .url
            .query_pairs()
            .any(|(key, value)| key == "per_page" && value == "1")
}

async fn unresolved_refusal_import(failure: &'static str, unowned: bool) {
    let (server, state) = stack(Stack::default()).await;
    let target = if failure == "absent_import" {
        ABSENT
    } else {
        RANGES
    };
    let changed = state.clone();
    let release = Arc::new(tokio::sync::Notify::new());
    let completed = Arc::new(tokio::sync::Notify::new());
    let release_import = release.clone();
    let import_completed = completed.clone();
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_import"))
        .and(move |r: &Request| {
            if failure == "absent_import" {
                r.url
                    .query_pairs()
                    .any(|(k, v)| k == "list_id" && v == ABSENT)
            } else {
                String::from_utf8_lossy(&r.body).contains(".json\"")
            }
        })
        .respond_with(move |_: &Request| {
            if unowned {
                changed
                    .lock()
                    .unwrap()
                    .lists
                    .insert(target.into(), json!({"id": target}));
            }
            if target == ABSENT {
                let changed = changed.clone();
                let release = release_import.clone();
                let completed = import_completed.clone();
                tokio::spawn(async move {
                    release.notified().await;
                    changed
                        .lock()
                        .unwrap()
                        .values
                        .entry(target.into())
                        .or_default()
                        .push(json!({"id": "late-item", "list_id": target}));
                    completed.notify_one();
                });
            }
            response(200, json!({}))
        })
        .with_priority(1)
        .mount(&server)
        .await;
    let t = transport(&server);
    let mut session = Session::new(
        &t,
        Timing {
            budget: Duration::from_millis(150),
            ..fast()
        },
    );
    let error = run(&mut session, Some("ech".into()), std::future::pending::<()>)
        .await
        .err()
        .unwrap();
    if target == ABSENT {
        release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), completed.notified())
            .await
            .unwrap();
    }
    assert!(
        error.message.contains("unexpectedly succeeded"),
        "{}",
        error.message
    );
    assert!(
        error.message.contains("cleanup failed"),
        "{}",
        error.message
    );
    assert!(error.message.contains(target), "{}", error.message);
    assert!(
        error
            .message
            .contains("remove it by exact id after the import settles"),
        "{}",
        error.message
    );
    let requests = server.received_requests().await.unwrap();
    assert!(requests.iter().all(|r| !(r.method == "DELETE"
        && (r.url.path() == "/api/lists/index"
            || r.url.query_pairs().any(|(k, v)| k == "id" && v == target)))));
    assert!(!requests.iter().any(restore_read));
    let state = state.lock().unwrap();
    assert!(state.bootstrapped, "unresolved import must block restore");
    if unowned {
        assert_eq!(state.lists[target], json!({"id": target}));
    } else if target == ABSENT {
        assert!(!state.lists.contains_key(ABSENT));
    }
    if target == ABSENT {
        assert_eq!(state.values[target][0]["id"], "late-item");
    }
}

#[tokio::test]
async fn wrong_extension_import_stays_unresolved() {
    unresolved_refusal_import("wrong_extension", false).await;
}

#[tokio::test]
async fn absent_import_without_parent_stays_unresolved() {
    unresolved_refusal_import("absent_import", false).await;
}

#[tokio::test]
async fn absent_import_with_unowned_parent_stays_unresolved() {
    unresolved_refusal_import("absent_import", true).await;
}

#[tokio::test]
async fn preflight_refuses_orphan_marker_items_without_writes() {
    let mut initial = Stack {
        bootstrapped: true,
        ..Default::default()
    };
    initial.values.insert(
        ABSENT.into(),
        vec![json!({"id": "orphan-server-id", "list_id": ABSENT})],
    );
    let (server, _) = stack(initial).await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    let error = run(&mut session, None, std::future::pending::<()>)
        .await
        .err()
        .unwrap();
    assert!(
        error.message.contains(ABSENT) && error.message.contains("orphan-server-id"),
        "{}",
        error.message
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

async fn interrupt_case(during_cleanup: bool, twice: bool) {
    let (server, state) = stack(Stack::default()).await;
    let t = transport(&server);
    let mut session = Session::new(
        &t,
        Timing {
            budget: Duration::from_millis(150),
            ..fast()
        },
    );
    if during_cleanup {
        Mock::given(method("POST"))
            .and(path("/api/lists/items/_export"))
            .and(wiremock::matchers::query_param("list_id", RANGES))
            .respond_with(response(400, json!({})))
            .with_priority(1)
            .mount(&server)
            .await;
    }
    let route = if during_cleanup {
        "/api/lists"
    } else {
        "/api/lists/items"
    };
    let verb = if during_cleanup { "DELETE" } else { "POST" };
    let trigger = Arc::new(tokio::sync::Notify::new());
    let notify = trigger.clone();
    Mock::given(method(verb))
        .and(path(route))
        .and(move |r: &Request| {
            !during_cleanup || r.url.query_pairs().any(|(k, v)| k == "id" && v == RANGES)
        })
        .respond_with(move |_: &Request| {
            notify.notify_one();
            response(503, json!({})).set_delay(Duration::from_millis(100))
        })
        .with_priority(1)
        .mount(&server)
        .await;
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = calls.clone();
    let error = run(&mut session, Some("ech".into()), move || {
        let trigger = trigger.clone();
        let call = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async move {
            if call == 0 || (during_cleanup && call == 1) {
                trigger.notified().await;
            } else if twice {
                tokio::time::sleep(Duration::from_millis(5)).await;
            } else {
                std::future::pending::<()>().await;
            }
        }
    })
    .await
    .err()
    .unwrap();
    if twice {
        assert!(
            error.message.contains("cleanup interrupted"),
            "{}",
            error.message
        );
        assert!(
            error
                .message
                .contains(if during_cleanup { RANGES } else { LIST }),
            "{}",
            error.message
        );
    } else if !during_cleanup {
        assert!(
            error.message.contains("cleanup failed"),
            "{}",
            error.message
        );
        assert!(error.message.contains(LIST), "{}", error.message);
        assert!(state.lock().unwrap().lists.contains_key(LIST));
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method != "DELETE")
        );
    } else {
        let requests = server.received_requests().await.unwrap();
        let last_delete = requests
            .iter()
            .rposition(|r| r.method == "DELETE" && r.url.path() == "/api/lists")
            .unwrap();
        let audit = &requests[last_delete + 1..];
        assert!(
            audit
                .iter()
                .filter(|r| r.url.path() == "/api/exception_lists/_find")
                .count()
                >= 2,
            "final audit missing: {}",
            error.message
        );
        assert!(
            audit
                .iter()
                .any(|r| r.url.path() == "/.items-default/_search")
        );
        if !during_cleanup {
            assert!(state.lock().unwrap().lists.is_empty());
        }
    }
}

#[tokio::test]
async fn interrupted_item_write_blocks_delete_and_restore() {
    interrupt_case(false, false).await;
}

#[tokio::test]
async fn first_interrupt_during_cleanup_still_finishes_audit() {
    interrupt_case(true, false).await;
}

#[tokio::test]
async fn second_interrupt_during_cleanup_names_survivors() {
    interrupt_case(true, true).await;
}

#[tokio::test]
async fn second_interrupt_after_recording_interrupt_names_survivors() {
    interrupt_case(false, true).await;
}

#[tokio::test]
async fn list_find_rejects_wrong_total_and_missing_cursor() {
    for body in [
        json!({"total": 3, "data": [{"id": LIST}], "cursor": "cursor"}),
        json!({"total": 2, "data": [{"id": LIST}]}),
    ] {
        let (server, _) = stack(Stack::default()).await;
        Mock::given(method("GET"))
            .and(path("/api/lists/_find"))
            .and(|request: &Request| request.url.query_pairs().any(|(k, _)| k == "filter"))
            .respond_with(response(200, body))
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
            error.message.contains("lists_find_first"),
            "{}",
            error.message
        );
    }
}

#[tokio::test]
async fn list_find_transport_and_decode_failures_name_the_step() {
    for (page, template) in [
        (
            "1",
            ResponseTemplate::new(503).set_body_string("private-body"),
        ),
        (
            "1",
            ResponseTemplate::new(200).set_body_string("private-body{"),
        ),
        (
            "2",
            ResponseTemplate::new(503).set_body_string("private-body"),
        ),
    ] {
        let (server, _) = stack(Stack::default()).await;
        Mock::given(method("GET"))
            .and(path("/api/lists/_find"))
            .and(move |request: &Request| {
                request.url.query_pairs().any(|(k, _)| k == "filter")
                    && request
                        .url
                        .query_pairs()
                        .any(|(k, v)| k == "page" && v == page)
            })
            .respond_with(template)
            .with_priority(1)
            .mount(&server)
            .await;
        let t = transport(&server);
        let mut session = Session::new(&t, fast());
        let error = run(&mut session, Some("ech".into()), std::future::pending::<()>)
            .await
            .err()
            .unwrap();
        let step = if page == "1" {
            "lists_find_first"
        } else {
            "lists_find_next"
        };
        assert!(error.message.contains(step), "{}", error.message);
        assert!(!error.message.contains("private-body"), "{}", error.message);
    }
}

#[tokio::test]
async fn new_recordings_reject_unexpected_values() {
    for (fail, step) in [
        ("agnostic_nonempty", "exception_lists_find_agnostic"),
        ("delete_duplicate", "items_export_after_delete"),
        ("import_missing_range", "contain_export_imported"),
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
        assert!(error.message.contains(step), "{}", error.message);
    }
}
