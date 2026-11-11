#[path = "mutation_confirm_current.rs"]
mod common;
#[tokio::test]
async fn missing_elicitation_refuses_before_reads() {
    let (s, mut h) = common::setup().await;
    let id = common::plan(&mut h).await;
    let count = s.received_requests().await.unwrap().len();
    let r=common::call(&mut h,"plan_apply",serde_json::json!({"plan_id":id}),serde_json::json!({"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}})).await;
    assert_eq!(
        r["result"]["structuredContent"]["error"]["code"],
        "confirmation_unavailable"
    );
    assert_eq!(s.received_requests().await.unwrap().len(), count);
    h.close_input();
    h.join().await.unwrap();
}
use serde_json::{Value, json};
use std::time::Duration;
static LEGACY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
async fn begin(h: &mut common::Harness, id: &str) -> Value {
    h.send_json(json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"plan_apply","arguments":{"plan_id":id}}})).await;
    let q = h.receive_json().await;
    assert_eq!(q["method"], "elicitation/create", "{q}");
    assert_eq!(q["params"]["mode"], "form");
    q
}
#[tokio::test]
async fn legacy_answer_rows_pending_reads_cancellation_and_timeout() {
    let _serial = LEGACY.lock().await;
    for (answer, expected) in [
        (
            json!({"action":"accept","content":{"apply":true}}),
            "applied",
        ),
        (json!({"action":"decline"}), "plan_declined"),
        (json!({"action":"cancel"}), "not_confirmed"),
        (
            json!({"action":"accept","content":{"apply":false}}),
            "not_confirmed",
        ),
        (json!({"error":true}), "not_confirmed"),
    ] {
        let (s, mut h) =
            common::setup_config(Duration::from_secs(30), Some(Duration::from_millis(500))).await;
        h.initialize(true).await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(common::fixture("rules_bulk_disable")),
            )
            .mount(&s)
            .await;
        let id = common::plan(&mut h).await;
        let q = begin(&mut h, &id).await;
        let r = common::call(&mut h, "plan_apply", json!({"plan_id":id}), json!({})).await;
        assert_eq!(
            r["result"]["structuredContent"]["error"]["code"],
            "confirmation_pending"
        );
        if answer.get("error").is_some() {
            h.send_json(json!({"jsonrpc":"2.0","id":q["id"],"error":{"code":-32603,"message":"name-sentinel"}})).await;
        } else {
            h.send_json(json!({"jsonrpc":"2.0","id":q["id"],"result":answer}))
                .await;
        }
        let r = h.receive_json().await;
        let data = &r["result"]["structuredContent"];
        if expected == "applied" {
            assert_eq!(data["data"]["plan"]["state"], expected, "{r}");
        } else {
            assert_eq!(data["error"]["code"], expected, "{r}");
        }
        if expected == "plan_declined" {
            assert_eq!(
                data["error"]["message"],
                "The plan was declined and closed."
            );
        }
        let r = common::call(&mut h, "name-sentinel", json!({}), json!({})).await;
        assert_eq!(r["error"]["message"], "Unknown MCP tool");
        h.close_input();
        h.join().await.unwrap();
    }
    let (_s, mut h) =
        common::setup_config(Duration::from_secs(30), Some(Duration::from_millis(200))).await;
    h.initialize(true).await;
    let id = common::plan(&mut h).await;
    begin(&mut h, &id).await;
    let r = h.receive_json().await;
    assert_eq!(
        r["result"]["structuredContent"]["error"]["code"],
        "confirmation_timeout"
    );
    let r = common::call(&mut h, "plan_get", json!({"plan_id":id}), json!({})).await;
    assert_eq!(
        r["result"]["structuredContent"]["data"]["plan"]["state"],
        "open"
    );
    begin(&mut h, &id).await;
    h.send_json(
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":10}}),
    )
    .await;
    let r = common::call(&mut h, "plan_get", json!({"plan_id":id}), json!({})).await;
    assert_eq!(r["id"], 1);
    assert_eq!(
        r["result"]["structuredContent"]["data"]["plan"]["state"],
        "open"
    );
    h.close_input();
    h.join().await.unwrap();
}
#[tokio::test]
async fn legacy_missing_form() {
    let (_s, mut h) = common::setup().await;
    h.initialize(false).await;
    let id = common::plan(&mut h).await;
    let r = common::call(&mut h, "plan_apply", json!({"plan_id":id}), json!({})).await;
    assert_eq!(
        r["result"]["structuredContent"]["error"]["code"],
        "confirmation_unavailable"
    );
    h.close_input();
    h.join().await.unwrap();
}
struct Scripted(serde_json::Value);
impl rmcp::ClientHandler for Scripted {
    fn get_info(&self) -> rmcp::model::ClientConfig {
        serde_json::from_value(json!({"protocolVersion":"2025-11-25","capabilities":{"elicitation":{"form":{}}},"clientInfo":{"name":"scripted","version":"0"}})).unwrap()
    }
    async fn create_elicitation(
        &self,
        request: rmcp::model::ElicitRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleClient>,
    ) -> Result<rmcp::model::ElicitResult, rmcp::ErrorData> {
        let v = serde_json::to_value(request).unwrap();
        assert_eq!(v["mode"], "form");
        serde_json::from_value(self.0.clone())
            .map_err(|_| rmcp::ErrorData::internal_error("scripted refusal", None))
    }
}
#[tokio::test]
async fn rmcp_both_protocols_scripted_answers() {
    use rmcp::{
        ClientLifecycleMode, ClientServiceExt, RoleClient,
        model::{CallToolRequestParams, CallToolResponse, ProtocolVersion},
        transport::async_rw::AsyncRwTransport,
    };
    let _serial = LEGACY.lock().await;
    for protocol in [ProtocolVersion::V_2025_11_25, ProtocolVersion::V_2026_07_28] {
        for answer in [
            json!({"action":"accept","content":{"apply":true}}),
            json!({"action":"decline"}),
            json!({"action":"cancel"}),
            json!({"error":true}),
        ] {
            let (s, mut unused) = common::setup().await;
            unused.close_input();
            unused.join().await.unwrap();
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .respond_with(
                    wiremock::ResponseTemplate::new(200)
                        .set_body_json(common::fixture("rules_bulk_disable")),
                )
                .mount(&s)
                .await;
            let target = elasticctl_core::Resolved {
                name: "test".into(),
                source: elasticctl_core::Source::Profile,
                profile: elasticctl_core::Profile {
                    kibana_url: s.uri(),
                    es_url: Some(s.uri()),
                    api_key: Some("test-key".into()),
                    username: None,
                    password: None,
                    space: "default".into(),
                    verify: true,
                    timeout_secs: 30,
                },
            };
            let options = elasticctl_mcp::ServerOptions {
                allow_mutations: elasticctl_mcp::MutationClasses::parse(["rules-toggle"]).unwrap(),
                ..Default::default()
            };
            let (cw, sr) = tokio::io::duplex(1048576);
            let (sw, cr) = tokio::io::duplex(1048576);
            let server = tokio::spawn(elasticctl_mcp::serve_io(target, options, sr, sw));
            let client = Scripted(answer.clone())
                .serve_with_lifecycle(
                    AsyncRwTransport::<RoleClient, _, _>::new_client(cr, cw),
                    if protocol == ProtocolVersion::V_2025_11_25 {
                        ClientLifecycleMode::Initialize
                    } else {
                        ClientLifecycleMode::Discover {
                            preferred_versions: vec![protocol.clone()],
                        }
                    },
                )
                .await
                .unwrap();
            let r = client
                .peer()
                .call_tool_once(
                    CallToolRequestParams::new("rules_set_enabled_plan").with_arguments(
                        json!({"selectors":["r"],"enabled":false})
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                )
                .await
                .unwrap();
            let CallToolResponse::Complete(r) = r else {
                panic!("plan result")
            };
            let id = r.structured_content.unwrap()["data"]["plan"]["plan_id"].clone();
            let r = client
                .peer()
                .call_tool_once(
                    CallToolRequestParams::new("plan_apply")
                        .with_arguments(json!({"plan_id":id}).as_object().unwrap().clone()),
                )
                .await
                .unwrap();
            let r = if let CallToolResponse::InputRequired(q) = r {
                let request = CallToolRequestParams::new("plan_apply")
                    .with_arguments(json!({"plan_id":id}).as_object().unwrap().clone())
                    .with_request_state(q.request_state.unwrap())
                    .with_input_responses(
                        [("confirm".into(), answer.clone())].into_iter().collect(),
                    );
                client.peer().call_tool_once(request).await.unwrap()
            } else {
                r
            };
            let CallToolResponse::Complete(r) = r else {
                panic!("apply result")
            };
            let data = r.structured_content.unwrap();
            if answer["action"] == "accept" {
                assert_eq!(data["data"]["plan"]["state"], "applied");
            } else {
                assert_eq!(
                    data["error"]["code"],
                    if answer["action"] == "decline" {
                        "plan_declined"
                    } else {
                        "not_confirmed"
                    }
                );
            }
            client.cancel().await.unwrap();
            server.await.unwrap().unwrap();
        }
    }
}

#[tokio::test]
async fn legacy_wait_releases_all_four_permits_for_blocked_reads() {
    let _serial = LEGACY.lock().await;
    let mut s = common::RawResponder::start().await;
    let mut h = s.harness(Duration::from_secs(30));
    h.initialize(true).await;
    let id = common::plan(&mut h).await;
    begin(&mut h, &id).await;
    s.gated.store(true, std::sync::atomic::Ordering::SeqCst);
    for n in 20..24 {
        h.send_json(json!({"jsonrpc":"2.0","id":n,"method":"tools/call","params":{"name":"rules_get","arguments":{"selector":"r"}}})).await;
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        for _ in 0..4 {
            s.arrived.recv().await.unwrap();
        }
    })
    .await
    .expect("all four upstream reads arrive before any release");
    s.release.add_permits(4);
    for _ in 0..4 {
        let r = h.receive_json().await;
        assert!((20..24).contains(&r["id"].as_u64().unwrap()), "{r}");
        assert_ne!(r["result"]["isError"], true, "{r}");
    }
    h.send_json(
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":10}}),
    )
    .await;
    let r = common::call(&mut h, "plan_get", json!({"plan_id":id}), json!({})).await;
    assert_eq!(
        r["result"]["structuredContent"]["data"]["plan"]["state"],
        "open"
    );
    assert!(
        s.requests
            .lock()
            .unwrap()
            .iter()
            .all(|(_, line)| line.starts_with("GET "))
    );
    h.close_input();
    h.join().await.unwrap();
}
