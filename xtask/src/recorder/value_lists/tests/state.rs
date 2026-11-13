use super::*;

#[tokio::test]
async fn preflight_refuses_marker_rule_before_any_write() {
    let (server, _) = stack(Stack {
        bootstrapped: true,
        ..Default::default()
    })
    .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(response(
            200,
            json!({"total": 1, "data": [{"rule_id": "elasticctl-live-vl-rule"}]}),
        ))
        .with_priority(1)
        .mount(&server)
        .await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    let error = inventory::require_clear(&mut session).await.unwrap_err();
    assert!(error.message.contains("elasticctl-live-vl-rule"));
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
async fn full_pass_has_state_cli_cleanup_recordings() {
    let (server, _) = stack(Stack::default()).await;
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
    for name in [
        "state_rule_r",
        "state_rule_q",
        "state_items_coreferenced",
        "export_dash_201",
        "cli_lists_all",
        "cleanup_items_audit",
    ] {
        assert!(
            recording.fixtures.iter().any(|f| f.name == name),
            "missing {name}"
        );
    }
}

#[tokio::test]
async fn unsafe_rule_body_is_refused_before_send() {
    let (server, _) = stack(Stack::default()).await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    for body in [
        json!({"rule_id": RULE, "enabled": true, "tags": [MARKER, session.nonce]}),
        json!({"rule_id": RULE, "enabled": false, "tags": [MARKER, "other-session"]}),
    ] {
        assert!(
            objects::create(&mut session, RULE, objects::Object::Rule, body, None)
                .await
                .is_err()
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn reference_guard_refuses_empty_large_incomplete_and_unowned_lists() {
    for (count, rows, owned, kind) in [
        (0, 0, true, "ip_range"),
        (201, 201, true, "ip_range"),
        (2, 1, true, "ip_range"),
        (1, 1, false, "ip_range"),
        (1, 1, true, "keyword"),
    ] {
        let (server, state) = stack(Stack {
            bootstrapped: true,
            ..Default::default()
        })
        .await;
        let t = transport(&server);
        let mut session = Session::new(&t, fast());
        state.lock().unwrap().lists.insert(CONTAIN.into(), json!({"id": CONTAIN, "type": kind,
            "meta": {"marker": MARKER, "recorder_nonce": if owned {session.nonce.as_str()} else {"other"}}}));
        Mock::given(method("GET")).and(path("/api/lists/items/_find"))
            .respond_with(response(200, json!({"total": count, "data": (0..rows).map(|n| json!({"id": format!("{CONTAIN}-{n}"), "value": "10.0.0.1-10.0.0.1"})).collect::<Vec<_>>() })))
            .with_priority(1).mount(&server).await;
        assert!(
            objects::item(
                &mut session,
                "guard",
                EXCEPTION,
                "single",
                json!([objects::entry(CONTAIN, "ip_range", "source.ip", "included")])
            )
            .await
            .is_err()
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
}

#[tokio::test]
async fn list_type_swap_refuses_live_references_and_pending_writes() {
    for pending in [true, false] {
        let (server, _) = stack(Stack::default()).await;
        let t = transport(&server);
        let mut session = Session::new(&t, fast());
        if pending {
            session.pending_imports.insert(CONTAIN.into(), Some(2));
        } else {
            session.objects.insert(
                "elasticctl-live-vl-included".into(),
                objects::Object::Item {
                    list: EXCEPTION,
                    namespace: "single",
                },
            );
        }
        assert!(
            state_values::delete_list(&mut session, CONTAIN)
                .await
                .is_err()
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn cleanup_requires_nonce_for_rules_and_both_agnostic_object_types() {
    for (id, object) in [
        (RULE, objects::Object::Rule),
        (
            OUTSIDE,
            objects::Object::Container {
                namespace: "agnostic",
            },
        ),
        (
            "elasticctl-live-vl-coreferenced",
            objects::Object::Item {
                list: OUTSIDE,
                namespace: "agnostic",
            },
        ),
    ] {
        let (server, _) = stack(Stack {
            bootstrapped: true,
            ..Default::default()
        })
        .await;
        let t = transport(&server);
        let mut session = Session::new(&t, fast());
        session.baseline_checked = true;
        session.before_absent = true;
        session.init_attempted = true;
        session.objects.insert(id.into(), object.clone());
        let body = json!({"rule_id": RULE, "enabled": false, "list_id": OUTSIDE,
            "item_id": "elasticctl-live-vl-coreferenced", "namespace_type": "agnostic", "tags": [MARKER,"other-session"]});
        Mock::given(method("GET"))
            .and(path(object.path(id).split('?').next().unwrap()))
            .respond_with(response(200, body))
            .with_priority(1)
            .mount(&server)
            .await;
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
}

#[tokio::test]
async fn pending_rule_and_agnostic_writes_are_sent_once_and_block_restore() {
    for (id, object, body) in [
        (
            RULE,
            objects::Object::Rule,
            json!({"rule_id": RULE, "enabled": false}),
        ),
        (
            OUTSIDE,
            objects::Object::Container {
                namespace: "agnostic",
            },
            json!({"list_id": OUTSIDE,"namespace_type":"agnostic"}),
        ),
        (
            "elasticctl-live-vl-coreferenced",
            objects::Object::Item {
                list: OUTSIDE,
                namespace: "agnostic",
            },
            json!({"item_id":"elasticctl-live-vl-coreferenced", "list_id":OUTSIDE,"namespace_type":"agnostic"}),
        ),
    ] {
        for status in [408, 503] {
            let (server, _) = stack(Stack {
                bootstrapped: true,
                ..Default::default()
            })
            .await;
            let t = transport(&server);
            let mut session = Session::new(&t, fast());
            session.baseline_checked = true;
            session.before_absent = true;
            session.init_attempted = true;
            let endpoint = object.path(id).split('?').next().unwrap().to_string();
            Mock::given(method("POST"))
                .and(path(&endpoint))
                .respond_with(response(status, json!({"message":"private-body"})))
                .with_priority(1)
                .expect(1)
                .mount(&server)
                .await;
            let mut body = body.clone();
            body["tags"] = json!([MARKER, session.nonce]);
            assert!(
                objects::create(&mut session, id, object.clone(), body, None)
                    .await
                    .is_err()
            );
            assert!(session.pending_creates.contains(id));
            let error = cleanup::finish(&mut session).await.unwrap_err();
            assert!(error.message.contains(id));
            assert!(
                server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .all(|r| r.method != "DELETE")
            );
        }
    }
}

#[test]
fn new_item_and_export_payloads_survive_numeric_identity_scrubbing() {
    for name in [
        "items_v_1000",
        "items_c_1000",
        "items_c_union_1000",
        "cleanup_items_empty",
    ] {
        let mut evidence = Evidence::default();
        evidence.response(
            name,
            json!({"created_by":"10", "data":[{"value":"10.0.0.1/32"}], "message":"user 10"}),
        );
        assert_eq!(
            evidence.fixtures[0].document["response"]["data"][0]["value"],
            "10.0.0.1/32"
        );
        assert_eq!(
            evidence.fixtures[0].document["response"]["message"],
            "user REDACTED"
        );
    }
    for name in [
        "export_empty",
        "export_dash_200",
        "export_dash_201",
        "export_p_spellings",
        "export_s_two_spellings",
        "export_c_union",
    ] {
        let mut evidence = Evidence::default();
        evidence.observe(&json!({"created_by":"10"}));
        evidence.response(name, json!("10.0.0.1-10.0.0.1\n"));
        assert_eq!(
            evidence.fixtures[0].document["response"],
            "10.0.0.1-10.0.0.1\n"
        );
    }
}

#[tokio::test]
async fn graph_correlations_layouts_and_filtered_requests_are_preserved() {
    let (server, _) = stack(Stack::default()).await;
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
    let fixture = |name| {
        &recording
            .fixtures
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .document["response"]
    };
    let e = &fixture("exception_create")["id"];
    let o = &fixture("state_outside_get")["id"];
    assert_eq!(&fixture("state_rule_r")["exceptions_list"][0]["id"], e);
    assert_eq!(&fixture("state_rule_q")["exceptions_list"][0]["id"], e);
    assert_eq!(&fixture("state_rule_q")["exceptions_list"][1]["id"], o);
    assert_eq!(
        fixture("state_rule_q")["exceptions_list"][1]["namespace_type"],
        "agnostic"
    );
    for (name, count, sizes, operators) in [
        ("state_items_included", 1, vec![1], vec!["included"]),
        ("state_items_excluded", 1, vec![1], vec!["excluded"]),
        (
            "state_items_mixed",
            2,
            vec![1, 1],
            vec!["excluded", "included"],
        ),
        (
            "state_items_coreferenced",
            1,
            vec![3],
            vec!["included", "included", "included"],
        ),
        (
            "state_items_independent",
            3,
            vec![1, 1, 1],
            vec!["included", "included", "included"],
        ),
        ("state_items_empty", 0, vec![], vec![]),
        (
            "state_items_repeated_10000",
            1,
            vec![2],
            vec!["excluded", "included"],
        ),
    ] {
        let body = fixture(name);
        assert_eq!(body["total"], count, "{name}");
        assert_eq!(body["per_page"], 10000, "{name}");
        let rows = body["data"].as_array().unwrap();
        assert_eq!(
            rows.iter()
                .map(|r| r["entries"].as_array().unwrap().len())
                .collect::<Vec<_>>(),
            sizes,
            "{name}"
        );
        let mut actual = rows
            .iter()
            .flat_map(|r| r["entries"].as_array().unwrap())
            .map(|e| e["operator"].as_str().unwrap())
            .collect::<Vec<_>>();
        actual.sort_unstable();
        assert_eq!(actual, operators, "{name}");
    }
    let requests = server.received_requests().await.unwrap();
    for r in &requests {
        assert!(!r.url.query_pairs().any(|(k, _)| k == "sort_field"
            || (k == "value" && (r.method == "GET" || r.method == "DELETE"))));
        if r.method == "POST" && r.url.path() == "/api/detection_engine/rules" {
            let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
            assert_eq!(body["enabled"], false);
            assert!(
                body["tags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|t| t == &session.nonce)
            );
            assert!(body["tags"].as_array().unwrap().iter().any(|t| t == MARKER));
        }
    }
    for (route, key, value) in [
        (
            "/api/detection_engine/rules/_find",
            "filter",
            "alert.attributes.params.immutable: false AND alert.attributes.params.ruleId: elasticctl-live-vl-*",
        ),
        (
            "/api/detection_engine/rules/_find",
            "filter",
            "alert.attributes.params.ruleId: \"elasticctl-live-vl-rule\"",
        ),
        (
            "/api/exception_lists/_find",
            "filter",
            "exception-list-agnostic.attributes.list_id:elasticctl-live-vl-*",
        ),
        ("/api/lists/_find", "filter", "name:elasticctl-live-vl-*"),
    ] {
        assert!(
            requests.iter().any(|r| r.url.path() == route
                && r.url.query_pairs().any(|(k, v)| k == key && v == value))
        );
    }
    let text = serde_json::to_string(
        &recording
            .fixtures
            .iter()
            .map(|f| &f.document)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(!text.contains(&session.nonce));
    assert!(!text.contains("server-elasticctl-live-vl"));
}

#[tokio::test]
async fn cleanup_keeps_dependencies_when_a_rule_survives() {
    let (server, state) = stack(Stack {
        bootstrapped: true,
        ..Default::default()
    })
    .await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    session.baseline_checked = true;
    session.before_absent = true;
    session.init_attempted = true;
    session.lists.push(CONTAIN);
    session.exception = true;
    session.objects.insert(RULE.into(), objects::Object::Rule);
    session.objects.insert(
        OUTSIDE.into(),
        objects::Object::Container {
            namespace: "agnostic",
        },
    );
    session.objects.insert(
        "elasticctl-live-vl-coreferenced".into(),
        objects::Object::Item {
            list: OUTSIDE,
            namespace: "agnostic",
        },
    );
    {
        let mut state = state.lock().unwrap();
        state.rules.insert(
            RULE.into(),
            json!({"rule_id":RULE,"enabled":false,"tags":[MARKER,session.nonce]}),
        );
        state.lists.insert(CONTAIN.into(),json!({"id":CONTAIN,"name":CONTAIN,"meta":{"marker":MARKER,"recorder_nonce":session.nonce}}));
        state.containers.insert(OUTSIDE.into(),json!({"id":"outside-id","list_id":OUTSIDE,"namespace_type":"agnostic","tags":[MARKER,session.nonce]}));
        state.exception_items.insert("elasticctl-live-vl-coreferenced".into(),json!({"id":"outside-item-id","item_id":"elasticctl-live-vl-coreferenced","list_id":OUTSIDE,"namespace_type":"agnostic","tags":[MARKER,session.nonce],"entries":[objects::entry(CONTAIN,"ip_range","source.ip","included")]}));
        state.exception = Some(
            json!({"id":"inside-id","list_id":EXCEPTION,"namespace_type":"single","tags":[MARKER,session.nonce]}),
        );
        state.cleanup_refuses = true;
    }
    let error = cleanup::finish(&mut session).await.unwrap_err();
    assert!(error.message.contains(RULE));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.iter().filter(|r| r.method == "DELETE").count(), 1);
    assert!(requests.iter().filter(|r| r.method == "DELETE").all(|r| {
        r.url.path() == "/api/detection_engine/rules"
            && r.url
                .query_pairs()
                .any(|(k, v)| k == "rule_id" && v == RULE)
    }));
    assert!(state.lock().unwrap().bootstrapped);
}

#[tokio::test]
async fn preflight_refuses_marker_agnostic_item_under_unmarked_container() {
    let mut initial = Stack {
        bootstrapped: true,
        ..Default::default()
    };
    initial.containers.insert(
        "ordinary".into(),
        json!({"id":"ordinary-id","list_id":"ordinary","namespace_type":"agnostic"}),
    );
    initial.exception_items.insert("elasticctl-live-vl-old-item".into(),json!({"item_id":"elasticctl-live-vl-old-item","list_id":"ordinary","namespace_type":"agnostic", "entries":[{"type":"match","field":"host.name","operator":"included","value":"synthetic"}]}));
    let (server, _) = stack(initial).await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    let error = inventory::require_clear(&mut session).await.unwrap_err();
    assert!(error.message.contains("elasticctl-live-vl-old-item"));
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
async fn cleanup_keeps_lists_until_both_namespace_containers_are_absent() {
    for agnostic in [false, true] {
        let (server, state) = stack(Stack {
            bootstrapped: true,
            ..Default::default()
        })
        .await;
        let t = transport(&server);
        let mut session = Session::new(&t, fast());
        session.baseline_checked = true;
        session.before_absent = true;
        session.init_attempted = true;
        session.lists.push(CONTAIN);
        let id = if agnostic { OUTSIDE } else { EXCEPTION };
        if agnostic {
            session.objects.insert(
                OUTSIDE.into(),
                objects::Object::Container {
                    namespace: "agnostic",
                },
            );
        } else {
            session.exception = true;
        }
        {
            let mut state = state.lock().unwrap();
            let container = json!({"id":id,"list_id":id,"namespace_type":if agnostic {"agnostic"} else {"single"},"tags":[MARKER,session.nonce]});
            if agnostic {
                state.containers.insert(id.into(), container);
            } else {
                state.exception = Some(container);
            }
            state.lists.insert(CONTAIN.into(),json!({"id":CONTAIN,"name":CONTAIN,"meta":{"marker":MARKER,"recorder_nonce":session.nonce}}));
        }
        Mock::given(method("DELETE"))
            .and(path("/api/exception_lists"))
            .respond_with(response(400, json!({})))
            .with_priority(1)
            .mount(&server)
            .await;
        assert!(cleanup::finish(&mut session).await.is_err());
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.method == "DELETE")
                .all(|r| r.url.path() == "/api/exception_lists")
        );
        assert!(state.lock().unwrap().lists.contains_key(CONTAIN));
        assert!(state.lock().unwrap().bootstrapped);
    }
}

#[tokio::test]
async fn preflight_rejects_truncated_or_changing_rule_inventory() {
    for changing in [false, true] {
        let (server, _) = stack(Stack {
            bootstrapped: true,
            ..Default::default()
        })
        .await;
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/_find"))
            .respond_with(move |r: &Request| {
                if changing && r.url.query_pairs().any(|(k, v)| k == "page" && v == "1") {
                    response(200, json!({"total":2,"data":[{"rule_id":"ordinary"}]}))
                } else {
                    response(200, json!({"total":1,"data":[]}))
                }
            })
            .with_priority(1)
            .mount(&server)
            .await;
        let t = transport(&server);
        let mut session = Session::new(&t, fast());
        assert!(inventory::require_clear(&mut session).await.is_err());
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
async fn uncertain_initialize_waits_for_readiness_or_blocks_restore() {
    for settle in [false, true] {
        for status in [408, 503] {
            let (server, state) = stack(Stack::default()).await;
            let sent = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = sent.clone();
            Mock::given(method("POST"))
                .and(path("/api/security_solution/initialize"))
                .respond_with(move |_: &Request| {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    response(status, json!({"message":"private-body"}))
                })
                .with_priority(1)
                .expect(1)
                .mount(&server)
                .await;
            let reads = Arc::new(Mutex::new(0));
            let counter = reads.clone();
            let fake = state.clone();
            Mock::given(method("GET"))
                .and(path("/api/lists/index"))
                .respond_with(move |r: &Request| {
                    let mut n = counter.lock().unwrap();
                    if sent.load(std::sync::atomic::Ordering::SeqCst) {
                        *n += 1;
                        if settle && *n == 2 {
                            fake.lock().unwrap().bootstrapped = true;
                        }
                    }
                    fake.lock().unwrap().answer(r)
                })
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
            assert!(*reads.lock().unwrap() >= 2, "early 404 cannot settle init");
            let deletes = server
                .received_requests()
                .await
                .unwrap()
                .into_iter()
                .filter(|r| r.method == "DELETE" && r.url.path() == "/api/lists/index")
                .count();
            assert_eq!(deletes, usize::from(settle));
            assert_eq!(
                error.message.contains("cleanup failed"),
                !settle,
                "{}",
                error.message
            );
            assert!(!state.lock().unwrap().bootstrapped);
        }
    }
}

#[tokio::test]
async fn uncertain_index_restore_verifies_absence_without_replaying_delete() {
    let (server, state) = stack(Stack {
        bootstrapped: true,
        ..Default::default()
    })
    .await;
    let sent = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = sent.clone();
    Mock::given(method("DELETE"))
        .and(path("/api/lists/index"))
        .respond_with(move |_: &Request| {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            response(503, json!({"message":"private-body"}))
        })
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    let reads = Arc::new(Mutex::new(0));
    let counter = reads.clone();
    let fake = state.clone();
    Mock::given(method("GET"))
        .and(path("/api/lists/index"))
        .respond_with(move |r: &Request| {
            if sent.load(std::sync::atomic::Ordering::SeqCst) {
                let mut n = counter.lock().unwrap();
                *n += 1;
                if *n == 2 {
                    fake.lock().unwrap().bootstrapped = false;
                }
            }
            fake.lock().unwrap().answer(r)
        })
        .with_priority(1)
        .mount(&server)
        .await;
    let t = transport(&server);
    let mut session = Session::new(&t, fast());
    session.before_absent = true;
    session.init_attempted = true;
    let error = cleanup::restore(&mut session).await.unwrap_err();
    assert!(!error.message.contains("private-body"));
    assert!(*reads.lock().unwrap() >= 2);
    assert!(!state.lock().unwrap().bootstrapped);
}
