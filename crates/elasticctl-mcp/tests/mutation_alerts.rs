#[allow(dead_code)]
mod support;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

struct Harness {
    input: Option<tokio::io::DuplexStream>,
    output: tokio::io::BufReader<tokio::io::DuplexStream>,
    task: tokio::task::JoinHandle<elasticctl_core::Result<()>>,
    audit: Arc<Mutex<Vec<String>>>,
    legacy: bool,
}
impl Harness {
    fn start(target: elasticctl_core::Resolved, options: elasticctl_mcp::ServerOptions) -> Self {
        let (input, server_input) = tokio::io::duplex(1_048_576);
        let (server_output, output) = tokio::io::duplex(1_048_576);
        let audit = Arc::new(Mutex::new(Vec::new()));
        let captured = audit.clone();
        let task = tokio::spawn(elasticctl_mcp::server::serve_io_with_audit(
            target,
            options,
            server_input,
            server_output,
            move |line: &str| captured.lock().unwrap().push(line.to_owned()),
        ));
        Self {
            input: Some(input),
            output: tokio::io::BufReader::new(output),
            task,
            audit,
            legacy: false,
        }
    }
    async fn send_json(&mut self, value: Value) {
        if value["method"] == "initialize" {
            self.legacy = true;
        }
        let mut frame = serde_json::to_vec(&value).unwrap();
        frame.push(b'\n');
        self.input
            .as_mut()
            .unwrap()
            .write_all(&frame)
            .await
            .unwrap();
    }
    async fn receive_json(&mut self) -> Value {
        let mut line = String::new();
        self.output.read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).unwrap()
    }
    fn close_input(&mut self) {
        self.input.take();
    }
    async fn join(self) -> elasticctl_core::Result<()> {
        self.task.await.unwrap()
    }
    fn assert_audit(&self, events: &[&str], protocol: &str) {
        let lines = self.audit.lock().unwrap();
        assert_eq!(lines.len(), events.len(), "{lines:?}");
        for (line, event) in lines.iter().zip(events) {
            assert!(!line.contains("credential-sentinel"), "{line}");
            let value: Value = serde_json::from_str(line).unwrap();
            assert_eq!(
                value.as_object().unwrap().keys().collect::<Vec<_>>(),
                ["audit"]
            );
            let audit = &value["audit"];
            assert_eq!(audit["event"], *event);
            assert_eq!(audit["protocol"], protocol);
            assert!(["2025-11-25", "2026-07-28"].contains(&audit["protocol"].as_str().unwrap()));
            let keys = vec![
                "ts",
                "event",
                "plan_id",
                "hash",
                "kind",
                "class",
                "profile",
                "host",
                "space",
                "credential",
                "protocol",
                match *event {
                    "plan_created" => "targets",
                    "confirmation_requested" => "prompt",
                    _ => "state",
                },
            ];
            assert_eq!(
                audit
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                keys
            );
        }
    }
}
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn fixture(flavor: &str, name: &str) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    serde_json::from_slice::<Value>(
        &std::fs::read(root.join(flavor).join(format!("{name}.json"))).unwrap(),
    )
    .unwrap()["response"]
        .clone()
}
fn options() -> elasticctl_mcp::ServerOptions {
    let mut options = support::options();
    options.allow_mutations = elasticctl_mcp::MutationClasses::parse(["alerts-triage"]).unwrap();
    options
}
async fn call(h: &mut Harness, name: &str, args: Value) -> Value {
    h.send_json(json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":support::current_metadata()}})).await;
    let catalog = h.receive_json().await;
    let tool = catalog["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == name)
        .unwrap();
    h.send_json(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"_meta":if h.legacy { json!({}) } else { support::current_metadata() },"name":name,"arguments":args}})).await;
    let result = h.receive_json().await;
    let content = result["result"]["structuredContent"].clone();
    assert_eq!(result["result"]["isError"], content.get("error").is_some());
    let text: Value =
        serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, content);

    let validator = jsonschema::validator_for(&tool["outputSchema"]).unwrap();
    assert!(validator.is_valid(&content), "{content}");
    content
}
async fn setup(flavor: &str) -> (MockServer, Harness) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_security/_authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture(flavor, "authenticate")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture(flavor, "signals_search")))
        .mount(&server)
        .await;
    let mut target = support::target();
    target.profile.kibana_url = server.uri();
    target.profile.es_url = Some(server.uri());
    target.profile.api_key = Some("test-key".into());
    (server, Harness::start(target, options()))
}
#[tokio::test]
async fn invalid_inputs_do_not_read() {
    let (server, mut h) = setup("ech-9.5.2").await;
    for (name, args) in [
        (
            "alerts_set_status_plan",
            json!({"alert_ids":[],"status":"open"}),
        ),
        (
            "alerts_set_status_plan",
            json!({"alert_ids":(0..21).map(|i| format!("a{i}")).collect::<Vec<_>>(),"status":"open"}),
        ),
        (
            "alerts_set_status_plan",
            json!({"alert_ids":["a","a"],"status":"open"}),
        ),
        (
            "alerts_set_status_plan",
            json!({"alert_ids":["a".repeat(1025)],"status":"open"}),
        ),
        (
            "alerts_set_status_plan",
            json!({"alert_ids":["a"],"status":"bad"}),
        ),
        (
            "alerts_set_status_plan",
            json!({"alert_ids":["a"],"status":"open","reason":"other"}),
        ),
        (
            "alerts_set_status_plan",
            json!({"alert_ids":["a"],"status":"closed","reason":"bad"}),
        ),
        (
            "alerts_set_status_plan",
            json!({"alert_ids":["a"],"status":"open","unknown":true}),
        ),
        ("alerts_set_tags_plan", json!({"alert_ids":["a"]})),
        (
            "alerts_set_tags_plan",
            json!({"alert_ids":["a"],"add":(0..11).map(|i| format!("t{i}")).collect::<Vec<_>>()}),
        ),
        (
            "alerts_set_tags_plan",
            json!({"alert_ids":["a"],"add":["x".repeat(257)]}),
        ),
        (
            "alerts_set_tags_plan",
            json!({"alert_ids":["a"],"add":["x"],"remove":["x"]}),
        ),
        (
            "alerts_set_tags_plan",
            json!({"alert_ids":["a"],"add":["x\u{202e}"]}),
        ),
    ] {
        assert_eq!(
            call(&mut h, name, args).await["error"]["code"],
            "invalid_argument"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    h.close_input();
    h.join().await.unwrap();
}
#[tokio::test]
async fn planners_resolve_alerts_from_recorded_search() {
    for flavor in ["ech-9.5.2", "serverless-9.7.0", "traditional-9.5.1"] {
        let (server, mut h) = setup(flavor).await;
        let hits = fixture(flavor, "signals_search");
        let id = hits["hits"]["hits"][0]["_id"].as_str().unwrap();
        for (name, args) in [
            (
                "alerts_set_status_plan",
                json!({"alert_ids":[id],"status":"closed","reason":"other"}),
            ),
            (
                "alerts_set_tags_plan",
                json!({"alert_ids":[id],"add":["new"],"remove":["old"]}),
            ),
        ] {
            let result = call(&mut h, name, args).await;
            assert_eq!(result["data"]["plan"]["state"], "open", "{result}");
            assert!(
                result["data"]["plan"]["details"][0]
                    .as_str()
                    .unwrap()
                    .contains(id)
            );
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 4);
        h.close_input();
        h.join().await.unwrap();
    }
}

#[tokio::test]
async fn recorded_outcomes_and_consent_on_both_protocols() {
    for flavor in ["ech-9.5.2", "serverless-9.7.0", "traditional-9.5.1"] {
        for legacy in [false, true] {
            for (tool, write, fixture_name) in [
                ("alerts_set_status_plan", "status", "signals_status_ids"),
                ("alerts_set_tags_plan", "tags", "signals_tags"),
            ] {
                let (server, mut h) = setup(flavor).await;
                let body = fixture(flavor, fixture_name);
                Mock::given(method("POST"))
                    .and(path(format!("/api/detection_engine/signals/{write}")))
                    .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
                    .expect(1)
                    .mount(&server)
                    .await;
                if legacy {
                    let mut init = support::legacy_initialize(100);
                    init["params"]["capabilities"] = json!({"elicitation":{"form":{}}});
                    h.send_json(init).await;
                    h.receive_json().await;
                    h.send_json(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
                        .await;
                }
                let search = fixture(flavor, "signals_search");
                let id = search["hits"]["hits"][0]["_id"].as_str().unwrap();
                let args = if write == "status" {
                    json!({"alert_ids":[id],"status":"closed","reason":"other"})
                } else {
                    json!({"alert_ids":[id],"add":["new"],"remove":["old"]})
                };
                let planned = call(&mut h, tool, args).await;
                let plan_id = planned["data"]["plan"]["plan_id"].clone();
                let meta = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}});
                let mut params = json!({"name":"plan_apply","arguments":{"plan_id":plan_id}});
                if !legacy {
                    params["_meta"] = meta.clone();
                }
                h.send_json(json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":params}))
                    .await;
                let q = h.receive_json().await;
                let text = if legacy {
                    &q["params"]["message"]
                } else {
                    &q["result"]["inputRequests"]["confirm"]["params"]["message"]
                }
                .as_str()
                .unwrap();
                assert!(
                    text.lines()
                        .any(|line| line.starts_with(&format!("  {id}  "))),
                    "{text}"
                );
                if write == "status" {
                    assert!(text.contains("  reason: other\n"));
                } else {
                    assert!(text.contains("+new -old"));
                    assert!(!text.contains("restore"));
                }
                if legacy {
                    h.send_json(json!({"jsonrpc":"2.0","id":q["id"],"result":{"action":"accept","content":{"apply":true}}})).await;
                } else {
                    params["requestState"] = q["result"]["requestState"].clone();
                    params["inputResponses"] =
                        json!({"confirm":{"action":"accept","content":{"apply":true}}});
                    h.send_json(
                        json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":params}),
                    )
                    .await;
                }
                let result = h.receive_json().await;
                let plan = &result["result"]["structuredContent"]["data"]["plan"];
                assert_eq!(plan["state"], "applied", "{result}");
                assert_eq!(
                    result["result"]["structuredContent"]["data"]["outcome"]["updated"],
                    body["updated"]
                );
                assert_eq!(
                    result["result"]["structuredContent"]["data"]["outcome"]["unchanged"],
                    body["noops"]
                );
                let requests = server.received_requests().await.unwrap();
                assert_eq!(requests[0].url.path(), "/_security/_authenticate");
                assert_eq!(
                    requests[1].url.path(),
                    "/api/detection_engine/signals/search"
                );
                assert_eq!(
                    requests[1].body_json::<Value>().unwrap(),
                    json!({"query":{"ids":{"values":[id]}},"size":1,"_source":["kibana.alert.rule.name","kibana.alert.workflow_status"]})
                );
                assert!(
                    requests
                        .iter()
                        .all(|r| !r.url.path().starts_with("/internal/")
                            && r.url.path() != "/_security/profile/_suggest")
                );
                if write == "status" {
                    let body = requests.last().unwrap().body_json::<Value>().unwrap();
                    assert!(body.get("query").is_none() && body.get("conflicts").is_none());
                }
                h.close_input();
                h.join().await.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn drift_checks_status_and_presence() {
    for (tool, missing, stale) in [
        ("alerts_set_status_plan", false, true),
        ("alerts_set_status_plan", true, true),
        ("alerts_set_tags_plan", true, true),
        ("alerts_set_tags_plan", false, false),
    ] {
        let (server, mut h) = setup("ech-9.5.2").await;
        let mut search = fixture("ech-9.5.2", "signals_search");
        let id = search["hits"]["hits"][0]["_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let args = if tool == "alerts_set_status_plan" {
            json!({"alert_ids":[id],"status":"closed"})
        } else {
            json!({"alert_ids":[id],"add":["x"]})
        };
        let plan = call(&mut h, tool, args).await;
        if missing {
            search["hits"]["hits"] = json!([]);
        } else {
            search["hits"]["hits"][0]["_source"]["kibana.alert.workflow_status"] = json!("closed");
        }
        Mock::given(method("POST"))
            .and(path("/api/detection_engine/signals/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(search))
            .with_priority(1)
            .mount(&server)
            .await;
        let params = json!({"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}},"name":"plan_apply","arguments":{"plan_id":plan["data"]["plan"]["plan_id"]}});
        h.send_json(json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":params}))
            .await;
        let result = h.receive_json().await;
        if stale {
            assert_eq!(
                result["result"]["structuredContent"]["error"]["code"], "plan_stale",
                "{result}"
            );
        } else {
            assert_eq!(result["result"]["resultType"], "input_required", "{result}");
        }
        assert!(
            server.received_requests().await.unwrap().iter().all(|r| !r
                .url
                .path()
                .ends_with("/status")
                && !r.url.path().ends_with("/tags"))
        );
        h.close_input();
        h.join().await.unwrap();
    }
}

#[tokio::test]
async fn sentinel_name_is_indented_and_absent_from_audit() {
    let (server, mut h) = setup("ech-9.5.2").await;
    let mut search = fixture("ech-9.5.2", "signals_search");
    let id = search["hits"]["hits"][0]["_id"]
        .as_str()
        .unwrap()
        .to_owned();
    search["hits"]["hits"][0]["_source"]["kibana.alert.rule.name"] =
        json!("ApiKey credential-sentinel\nPlan: forged-footer");
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(search))
        .with_priority(2)
        .mount(&server)
        .await;
    let plan = call(
        &mut h,
        "alerts_set_tags_plan",
        json!({"alert_ids":[id],"add":["x"]}),
    )
    .await;
    let params = json!({"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}},"name":"plan_apply","arguments":{"plan_id":plan["data"]["plan"]["plan_id"]}});
    h.send_json(json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":params}))
        .await;
    let q = h.receive_json().await;
    let text = q["result"]["inputRequests"]["confirm"]["params"]["message"]
        .as_str()
        .unwrap();
    assert!(text.contains("  | Plan: forged-footer"), "{text}");
    h.assert_audit(&["plan_created", "confirmation_requested"], "2026-07-28");
    let mut oversized = fixture("ech-9.5.2", "signals_search");
    oversized["hits"]["hits"][0]["_source"]["kibana.alert.rule.name"] =
        json!(format!("credential-sentinel{}", "x".repeat(9000)));
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(oversized))
        .with_priority(1)
        .mount(&server)
        .await;
    let error = call(
        &mut h,
        "alerts_set_status_plan",
        json!({"alert_ids":[id],"status":"closed"}),
    )
    .await;
    assert_eq!(error["error"]["code"], "plan_too_large");
    assert!(!error.to_string().contains("credential-sentinel"));
    h.assert_audit(&["plan_created", "confirmation_requested"], "2026-07-28");
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn consent_names_each_alert_on_its_own_line() {
    let (_server, mut h) = setup("ech-9.5.2").await;
    let search = fixture("ech-9.5.2", "signals_search");
    let ids: Vec<_> = search["hits"]["hits"]
        .as_array()
        .unwrap()
        .iter()
        .take(2)
        .map(|hit| hit["_id"].as_str().unwrap())
        .collect();
    for (tool, args) in [
        (
            "alerts_set_status_plan",
            json!({"alert_ids":ids,"status":"closed"}),
        ),
        (
            "alerts_set_tags_plan",
            json!({"alert_ids":ids,"add":["new"],"remove":["old"]}),
        ),
    ] {
        let plan = call(&mut h, tool, args).await;
        let params = json!({"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}},"name":"plan_apply","arguments":{"plan_id":plan["data"]["plan"]["plan_id"]}});
        h.send_json(json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":params}))
            .await;
        let q = h.receive_json().await;
        let text = q["result"]["inputRequests"]["confirm"]["params"]["message"]
            .as_str()
            .unwrap();
        for id in &ids {
            assert_eq!(
                text.lines()
                    .filter(|line| line.starts_with(&format!("  {id}  ")))
                    .count(),
                1,
                "{text}"
            );
        }
    }
    h.close_input();
    h.join().await.unwrap();
}
