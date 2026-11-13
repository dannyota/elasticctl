use super::*;

async fn timed_out_create(route: &'static str, id: &'static str, settle: bool) {
    let (server, state) = stack(Stack::default()).await;
    let queued = Arc::new(Mutex::new(None));
    let sent = queued.clone();
    Mock::given(method("POST"))
        .and(path(route))
        .respond_with(move |request: &Request| {
            *sent.lock().unwrap() = Some(serde_json::from_slice(&request.body).unwrap());
            response(408, json!({"message": "write timed out"}))
        })
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    let pending = queued.clone();
    let changed = state.clone();
    let reads = Arc::new(Mutex::new(0));
    let count = reads.clone();
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(move |_: &Request| {
            let mut count = count.lock().unwrap();
            *count += 1;
            if !settle || *count == 1 {
                return response(404, json!({}));
            }
            let mut state = changed.lock().unwrap();
            if let Some(body) = pending.lock().unwrap().take() {
                match id {
                    LIST => {
                        state.lists.insert(id.into(), body);
                    }
                    EXCEPTION => state.exception = Some(body),
                    ITEM => state.item = Some(body),
                    _ => unreachable!(),
                }
            }
            let current = match id {
                LIST => state.lists.get(id),
                EXCEPTION => state.exception.as_ref(),
                ITEM => state.item.as_ref(),
                _ => unreachable!(),
            };
            current.map_or(response(404, json!({})), |body| response(200, body.clone()))
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
    let error = steps::record(&mut session, Some("ech".into()))
        .await
        .unwrap_err();
    assert_eq!(error.http_status, Some(408));
    assert!(session.pending_creates.contains(id), "408 must retain {id}");
    let recorded = server.received_requests().await.unwrap().len();
    let cleanup = cleanup::finish(&mut session).await;
    let requests = server.received_requests().await.unwrap();
    let requests = &requests[recorded..];
    if settle {
        cleanup.unwrap();
        assert!(
            *reads.lock().unwrap() >= 3,
            "wait for create, then verify delete"
        );
        let first_delete = requests.iter().position(|r| r.method == "DELETE").unwrap();
        assert!(
            requests[..first_delete]
                .iter()
                .filter(|r| r.url.path() == route && r.method == "GET")
                .count()
                >= 2
        );
        let state = state.lock().unwrap();
        assert!(state.lists.is_empty() && state.exception.is_none() && state.item.is_none());
        assert!(!state.bootstrapped);
    } else {
        assert!(cleanup.unwrap_err().message.contains("pending create"));
        assert!(session.pending_creates.contains(id));
        assert!(requests.iter().all(|r| r.method != "DELETE"
            || (r.url.path() == "/api/lists"
                && (id == EXCEPTION
                    || r.url.query_pairs().any(|(k, v)| k == "id" && v == RANGES)))));
        assert!(state.lock().unwrap().bootstrapped);
        assert!(
            queued.lock().unwrap().is_some(),
            "late create remains unresolved"
        );
        if id == ITEM {
            assert!(state.lock().unwrap().lists.contains_key(LIST));
            assert!(state.lock().unwrap().exception.is_some());
        }
        let body = queued.lock().unwrap().take().unwrap();
        let mut state = state.lock().unwrap();
        match id {
            LIST => {
                state.lists.insert(id.into(), body);
            }
            EXCEPTION => state.exception = Some(body),
            ITEM => state.item = Some(body),
            _ => unreachable!(),
        }
    }
}

#[tokio::test]
async fn list_create_408_waits_for_late_completion() {
    for settle in [true, false] {
        timed_out_create("/api/lists", LIST, settle).await;
    }
}

#[tokio::test]
async fn exception_create_408_waits_for_late_completion() {
    for settle in [true, false] {
        timed_out_create("/api/exception_lists", EXCEPTION, settle).await;
    }
}

#[tokio::test]
async fn exception_item_create_408_waits_for_late_completion() {
    for settle in [true, false] {
        timed_out_create("/api/exception_lists/items", ITEM, settle).await;
    }
}

#[tokio::test]
async fn refusal_import_408_keeps_parent_for_late_completion() {
    let (server, state) = stack(Stack::default()).await;
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_import"))
        .and(|r: &Request| String::from_utf8_lossy(&r.body).contains(".json\""))
        .respond_with(response(408, json!({"message": "import timed out"})))
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    let error = steps::record(&mut session, Some("ech".into()))
        .await
        .unwrap_err();
    assert!(
        error
            .message
            .contains("import_wrong_extension: expected HTTP 415, received 408")
    );
    assert_eq!(session.pending_imports.get(RANGES), Some(&None));
    let recorded = server.received_requests().await.unwrap().len();
    assert!(
        cleanup::finish(&mut session)
            .await
            .unwrap_err()
            .message
            .contains("pending import")
    );
    {
        let mut state = state.lock().unwrap();
        state
            .values
            .entry(RANGES.into())
            .or_default()
            .push(json!({"id": "late-item", "list_id": RANGES}));
        assert!(state.lists.contains_key(RANGES));
        assert!(state.bootstrapped);
    }
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests[recorded..]
            .iter()
            .filter(|r| r.method == "DELETE")
            .all(|r| r.url.path() == "/api/lists"
                && r.url.query_pairs().any(|(k, v)| k == "id" && v == CONTAIN))
    );
}
