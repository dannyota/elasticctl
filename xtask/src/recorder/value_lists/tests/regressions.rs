use super::*;

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

async fn refusal_import(failure: &'static str) {
    let (server, state) = stack(Stack {
        fail: Some(failure),
        ..Default::default()
    })
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
    assert!(
        error.message.contains("unexpectedly succeeded"),
        "{}",
        error.message
    );
    {
        let state = state.lock().unwrap();
        assert!(
            !state.imported_pending,
            "import must settle before deleting its parent"
        );
        assert!(
            state.values.values().all(Vec::is_empty),
            "orphan items remain"
        );
        assert!(state.lists.is_empty());
    }
    let id = if failure == "absent_import" {
        ABSENT
    } else {
        RANGES
    };
    let requests = server.received_requests().await.unwrap();
    let import = requests
        .iter()
        .rposition(|r| r.url.path().ends_with("/_import"))
        .unwrap();
    assert!(
        requests[import + 1..]
            .iter()
            .filter(|r| r.method == "GET")
            .any(|r| r.url.query_pairs().any(|(k, v)| k == "list_id" && v == id))
    );
}

#[tokio::test]
async fn wrong_extension_import_settles_before_parent_delete() {
    refusal_import("wrong_extension").await;
}

#[tokio::test]
async fn absent_import_is_registered_and_settles_before_parent_delete() {
    refusal_import("absent_import").await;
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
    let route = if during_cleanup {
        "/api/lists"
    } else {
        "/api/lists/items"
    };
    let verb = if during_cleanup { "DELETE" } else { "POST" };
    // Notify from the request after ownership has been registered.
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
    } else {
        let requests = server.received_requests().await.unwrap();
        let last_delete = requests
            .iter()
            .rposition(|r| r.method == "DELETE" && r.url.path() == "/api/lists")
            .unwrap();
        let audit = &requests[last_delete + 1..];
        assert_eq!(
            audit
                .iter()
                .filter(|r| r.url.path() == "/api/exception_lists/_find")
                .count(),
            2,
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
async fn interrupt_during_recording_still_finishes_cleanup_and_audit() {
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
