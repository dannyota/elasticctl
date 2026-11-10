#[path = "mutation_confirm_current.rs"]
mod common;
use serde_json::json;
#[tokio::test]
async fn accepted_write_and_replay() {
    let (s, mut h) = common::setup().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(common::fixture("rules_bulk_disable")),
        )
        .expect(1)
        .mount(&s)
        .await;
    let id = common::plan(&mut h).await;
    let q = common::question(&mut h, &id).await;
    let r=common::call(&mut h,"plan_apply",json!({"plan_id":id}),json!({"requestState":q["requestState"],"inputResponses":{"confirm":{"action":"accept","content":{"apply":true}}}})).await;
    assert_eq!(
        r["result"]["structuredContent"]["data"]["plan"]["state"], "applied",
        "{r}"
    );
    let r = common::call(&mut h, "plan_apply", json!({"plan_id":id}), json!({})).await;
    assert_eq!(r["result"]["structuredContent"]["data"]["replayed"], true);
    h.close_input();
    h.join().await.unwrap();
}
use std::time::Duration;
async fn accept(h: &mut common::Harness, id: &str, q: &serde_json::Value) -> serde_json::Value {
    common::call(h,"plan_apply",json!({"plan_id":id}),json!({"requestState":q["requestState"],"inputResponses":{"confirm":{"action":"accept","content":{"apply":true}}}})).await
}
#[tokio::test]
async fn write_status_classification_and_malformed_success() {
    for status in [200, 400, 403, 409, 429, 500, 503] {
        let (s, mut h) = common::setup().await;
        let body = if status == 200 {
            json!({"name":"name-sentinel"})
        } else {
            json!({"statusCode":status,"message":"name-sentinel","error":"error"})
        };
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(status).set_body_json(body))
            .expect(1)
            .mount(&s)
            .await;
        let id = common::plan(&mut h).await;
        let q = common::question(&mut h, &id).await;
        let r = accept(&mut h, &id, &q).await;
        let code = r["result"]["structuredContent"]["error"]["code"]
            .as_str()
            .unwrap();
        assert!(!r.to_string().contains("name-sentinel"));
        if status >= 500 || status == 200 {
            assert_eq!(code, "apply_outcome_unknown");
        } else {
            assert!(code.starts_with("elastic_"));
        }
        let r = common::call(&mut h, "plan_apply", json!({"plan_id":id}), json!({})).await;
        assert_eq!(
            r["result"]["structuredContent"]["data"]["plan"]["state"],
            if status >= 500 || status == 200 {
                "unknown"
            } else {
                "failed"
            }
        );
        h.close_input();
        h.join().await.unwrap();
    }
}
#[tokio::test]
async fn drift_and_identity_alias_at_both_checks() {
    for second in [false, true] {
        for identity in [false, true] {
            for alias in [false, true] {
                let target = if alias { "r\\n" } else { "r" };
                let (s, mut h) = common::setup_rule(Duration::from_secs(30), None, target).await;
                let planned = common::call(
                    &mut h,
                    "rules_set_enabled_plan",
                    json!({"selectors":[target],"enabled":false}),
                    json!({}),
                )
                .await;
                let id = planned["result"]["structuredContent"]["data"]["plan"]["plan_id"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let q = if second {
                    Some(common::question(&mut h, &id).await)
                } else {
                    None
                };
                if identity {
                    let mut body = common::fixture("authenticate");
                    body["username"] = json!("changed");
                    wiremock::Mock::given(wiremock::matchers::path("/_security/_authenticate"))
                        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(body))
                        .with_priority(1)
                        .mount(&s)
                        .await;
                } else {
                    let mut body = common::fixture("rules_get");
                    body["rule_id"] = json!(if alias { "r\n" } else { "r" });
                    body["name"] = json!("changed");
                    wiremock::Mock::given(wiremock::matchers::path("/api/detection_engine/rules"))
                        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(body))
                        .with_priority(1)
                        .mount(&s)
                        .await;
                }
                let r = if let Some(q) = q {
                    accept(&mut h, &id, &q).await
                } else {
                    common::call(&mut h, "plan_apply", json!({"plan_id":id}), json!({})).await
                };
                assert_eq!(
                    r["result"]["structuredContent"]["error"]["code"], "plan_stale",
                    "{r}"
                );
                assert!(
                    s.received_requests()
                        .await
                        .unwrap()
                        .iter()
                        .all(|r| r.method == "GET")
                );
                h.close_input();
                h.join().await.unwrap();
            }
        }
    }
}
#[tokio::test]
async fn pending_and_shutdown_keep_the_write_running() {
    for delay in [2, 7] {
        let (s, mut h) = common::setup_config(Duration::from_secs(1), None).await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(common::fixture("rules_bulk_disable"))
                    .set_delay(Duration::from_secs(delay)),
            )
            .expect(1)
            .mount(&s)
            .await;
        let id = common::plan(&mut h).await;
        let q = common::question(&mut h, &id).await;
        let r = accept(&mut h, &id, &q).await;
        assert_eq!(
            r["result"]["structuredContent"]["error"]["code"],
            "apply_pending"
        );
        let audit = h.audit.clone();
        h.close_input();
        let start = std::time::Instant::now();
        h.join().await.unwrap();
        let lines = audit.lock().unwrap();
        if delay == 2 {
            assert!(
                lines
                    .iter()
                    .any(|v| v["audit"]["event"] == "apply_finished")
            );
            assert!(start.elapsed() < Duration::from_secs(3));
        } else {
            assert!(start.elapsed() >= Duration::from_secs(5));
            assert!(start.elapsed() < Duration::from_secs(6));
            assert_eq!(
                lines
                    .iter()
                    .filter(|v| v["audit"]["event"] == "apply_interrupted")
                    .count(),
                1
            );
        }
    }
}
#[tokio::test]
async fn failed_reread_leaves_plan_open_and_short_bulk_is_incomplete() {
    let (s, mut h) = common::setup().await;
    let id = common::plan(&mut h).await;
    wiremock::Mock::given(wiremock::matchers::path("/_security/_authenticate"))
        .respond_with(
            wiremock::ResponseTemplate::new(403).set_body_json(json!({"message":"name-sentinel"})),
        )
        .with_priority(1)
        .up_to_n_times(1)
        .mount(&s)
        .await;
    let r = common::call(&mut h, "plan_apply", json!({"plan_id":id}), json!({})).await;
    assert_eq!(
        r["result"]["structuredContent"]["error"]["code"],
        "elastic_permission"
    );
    let r = common::call(&mut h, "plan_get", json!({"plan_id":id}), json!({})).await;
    assert_eq!(
        r["result"]["structuredContent"]["data"]["plan"]["state"],
        "open"
    );
    let mut bulk = common::fixture("rules_bulk_disable");
    bulk["attributes"]["summary"] = json!({"succeeded":0,"failed":0,"skipped":0,"total":0});
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(bulk))
        .mount(&s)
        .await;
    let q = common::question(&mut h, &id).await;
    let r = accept(&mut h, &id, &q).await;
    assert_eq!(
        r["result"]["structuredContent"]["data"]["outcome"]["failed"],
        1
    );
    assert_eq!(
        r["result"]["structuredContent"]["data"]["outcome"]["complete"],
        false
    );
    h.close_input();
    h.join().await.unwrap();
}
#[tokio::test]
async fn cancelling_checks_stops_write_and_cancelling_committed_write_keeps_outcome() {
    for committed in [false, true] {
        let (s, mut h) = common::setup().await;
        let id = common::plan(&mut h).await;
        let q = common::question(&mut h, &id).await;
        let guard = if !committed {
            Some(
                wiremock::Mock::given(wiremock::matchers::path("/_security/_authenticate"))
                    .respond_with(
                        wiremock::ResponseTemplate::new(200)
                            .set_body_json(common::fixture("authenticate"))
                            .set_delay(Duration::from_secs(2)),
                    )
                    .with_priority(1)
                    .mount_as_scoped(&s)
                    .await,
            )
        } else {
            None
        };
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(common::fixture("rules_bulk_disable"))
                    .set_delay(Duration::from_millis(300)),
            )
            .mount(&s)
            .await;
        let before = s.received_requests().await.unwrap().len();
        h.send_json(json!({"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}},"name":"plan_apply","arguments":{"plan_id":id},"requestState":q["requestState"],"inputResponses":{"confirm":{"action":"accept","content":{"apply":true}}}}})).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let requests = s.received_requests().await.unwrap();
                if (committed && requests.iter().any(|r| r.method == "POST"))
                    || (!committed && requests.len() > before)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        h.send_json(
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":50}}),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        drop(guard);
        let r = common::call(&mut h, "plan_get", json!({"plan_id":id}), json!({})).await;
        assert_eq!(r["id"], 1);
        assert_eq!(
            r["result"]["structuredContent"]["data"]["plan"]["state"],
            if committed { "applied" } else { "open" }
        );
        assert_eq!(
            s.received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.method == "POST")
                .count(),
            usize::from(committed)
        );
        h.close_input();
        h.join().await.unwrap();
    }
}
#[tokio::test]
async fn raw_closed_socket_and_transport_timeout_send_post_once() {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for timeout in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let posts = Arc::new(AtomicUsize::new(0));
        let captured = posts.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let responder = tokio::spawn(async move {
            let mut connection = 0;
            loop {
                connection += 1;
                let (mut stream, _) = listener.accept().await.unwrap();
                let posts = captured.clone();
                let requests = recorded.clone();
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    let mut byte = [0];
                    while !bytes.ends_with(b"\r\n\r\n") {
                        if stream.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        bytes.push(byte[0]);
                    }
                    let headers = String::from_utf8(bytes).unwrap();
                    requests
                        .lock()
                        .unwrap()
                        .push((connection, headers.lines().next().unwrap().to_owned()));
                    let length = headers
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|s| s.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    stream.read_exact(&mut vec![0; length]).await.unwrap();
                    if headers.starts_with("POST ") {
                        posts.fetch_add(1, Ordering::SeqCst);
                        if timeout {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        }
                        return;
                    }
                    let mut body = if headers.contains("/_security/_authenticate") {
                        common::fixture("authenticate")
                    } else {
                        common::fixture("rules_get")
                    };
                    if body.get("rule_id").is_some() {
                        body["rule_id"] = json!("r");
                    }
                    let body = body.to_string();
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
                });
            }
        });
        let target = elasticctl_core::Resolved {
            name: "test".into(),
            source: elasticctl_core::Source::Profile,
            profile: elasticctl_core::Profile {
                kibana_url: format!("http://{addr}"),
                es_url: Some(format!("http://{addr}")),
                api_key: Some("test-key".into()),
                username: None,
                password: None,
                space: "default".into(),
                verify: true,
                timeout_secs: 1,
            },
        };
        let options = elasticctl_mcp::ServerOptions {
            allow_mutations: elasticctl_mcp::MutationClasses::parse(["rules-toggle"]).unwrap(),
            ..Default::default()
        };
        let mut h = common::Harness::start(target, options, None);
        let id = common::plan(&mut h).await;
        let q = common::question(&mut h, &id).await;
        let r = accept(&mut h, &id, &q).await;
        assert_eq!(
            r["result"]["structuredContent"]["error"]["code"],
            "apply_outcome_unknown"
        );
        assert_eq!(
            r["result"]["structuredContent"]["error"]["kind"],
            if timeout { "timeout" } else { "connection" }
        );
        assert!(r["result"]["structuredContent"]["error"]["http_status"].is_null());
        let replay = common::call(&mut h, "plan_apply", json!({"plan_id":id}), json!({})).await;
        assert_eq!(
            replay["result"]["structuredContent"]["data"]["plan"]["state"],
            "unknown"
        );
        assert_eq!(
            replay["result"]["structuredContent"]["data"]["replayed"],
            true
        );
        h.close_input();
        h.join().await.unwrap();
        assert_eq!(posts.load(Ordering::SeqCst), 1);
        let requests = requests.lock().unwrap();
        let writes: Vec<_> = requests
            .iter()
            .filter(|(_, line)| !line.starts_with("GET "))
            .collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(
            writes[0].1,
            "POST /api/detection_engine/rules/_bulk_action HTTP/1.1"
        );
        assert!(
            requests
                .iter()
                .filter(|(_, line)| line.starts_with("GET "))
                .all(|(connection, _)| *connection != writes[0].0)
        );
        responder.abort();
    }
}
#[tokio::test]
async fn pending_call_later_returns_recorded_applied_view() {
    let (s, mut h) = common::setup_config(Duration::from_secs(1), None).await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(common::fixture("rules_bulk_disable"))
                .set_delay(Duration::from_secs(2)),
        )
        .expect(1)
        .mount(&s)
        .await;
    let id = common::plan(&mut h).await;
    let q = common::question(&mut h, &id).await;
    let r = accept(&mut h, &id, &q).await;
    assert_eq!(
        r["result"]["structuredContent"]["error"]["code"],
        "apply_pending"
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let r = common::call(&mut h, "plan_get", json!({"plan_id":id}), json!({})).await;
    assert_eq!(
        r["result"]["structuredContent"]["data"]["plan"]["state"],
        "applied"
    );
    h.close_input();
    h.join().await.unwrap();
}
