#![allow(dead_code)]
#[path = "support/mod.rs"]
mod support;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
pub struct Harness {
    pub input: Option<tokio::io::DuplexStream>,
    pub output: tokio::io::BufReader<tokio::io::DuplexStream>,
    pub task: tokio::task::JoinHandle<elasticctl_core::Result<()>>,
    pub audit: Arc<Mutex<Vec<Value>>>,
    pub legacy: bool,
}
impl Harness {
    pub fn start(
        t: elasticctl_core::Resolved,
        o: elasticctl_mcp::ServerOptions,
        wait: Option<std::time::Duration>,
    ) -> Self {
        let (input, si) = tokio::io::duplex(1048576);
        let (so, output) = tokio::io::duplex(1048576);
        let audit = Arc::new(Mutex::new(Vec::new()));
        let captured = audit.clone();
        let task = tokio::spawn(elasticctl_mcp::server::serve_io_with_audit(
            t,
            o,
            si,
            so,
            elasticctl_mcp::server::TestOptions {
                audit_writer: Box::new(move |line: &str| {
                    captured
                        .lock()
                        .unwrap()
                        .push(serde_json::from_str(line).unwrap())
                }),
                legacy_wait: wait,
            },
        ));
        Self {
            input: Some(input),
            output: tokio::io::BufReader::new(output),
            task,
            audit,
            legacy: false,
        }
    }
    pub async fn send_json(&mut self, v: Value) {
        self.input
            .as_mut()
            .unwrap()
            .write_all(format!("{v}\n").as_bytes())
            .await
            .unwrap();
    }
    pub async fn receive_json(&mut self) -> Value {
        loop {
            let mut line = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(15),
                self.output.read_line(&mut line),
            )
            .await
            .unwrap()
            .unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            if v.get("id").is_none() && v["method"] == "notifications/cancelled" {
                continue;
            }
            return v;
        }
    }

    pub fn close_input(&mut self) {
        self.input.take();
    }
    pub async fn join(self) -> elasticctl_core::Result<()> {
        self.task.await.unwrap()
    }
    pub async fn initialize(&mut self, form: bool) {
        self.send_json(json!({"jsonrpc":"2.0","id":90,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":if form{json!({"elicitation":{"form":{}}})}else{json!({})},"clientInfo":{"name":"test","version":"0"}}})).await;
        assert!(self.receive_json().await.get("result").is_some());
        self.send_json(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        self.legacy = true;
    }
}
pub fn fixture(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/traditional-9.5.1")
        .join(format!("{name}.json"));
    serde_json::from_slice::<Value>(&std::fs::read(p).unwrap()).unwrap()["response"].clone()
}
pub async fn setup() -> (MockServer, Harness) {
    setup_config(std::time::Duration::from_secs(30), None).await
}
pub async fn setup_config(
    timeout: std::time::Duration,
    wait: Option<std::time::Duration>,
) -> (MockServer, Harness) {
    setup_rule(timeout, wait, "r").await
}
pub async fn setup_rule(
    timeout: std::time::Duration,
    wait: Option<std::time::Duration>,
    rule_id: &str,
) -> (MockServer, Harness) {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_security/_authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture("authenticate")))
        .mount(&s)
        .await;
    let mut rule = fixture("rules_get");
    rule["rule_id"] = json!(rule_id);
    rule["name"] = json!("name-sentinel");
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule))
        .mount(&s)
        .await;
    let mut t = support::target();
    t.profile.kibana_url = s.uri();
    t.profile.es_url = Some(s.uri());
    t.profile.api_key = Some("test-key".into());
    let mut o = support::options();
    o.allow_mutations = elasticctl_mcp::MutationClasses::parse(["rules-toggle"]).unwrap();
    o.call_timeout = timeout;
    (s, Harness::start(t, o, wait))
}
pub async fn call(h: &mut Harness, name: &str, arguments: Value, extra: Value) -> Value {
    let meta = if h.legacy {
        json!({})
    } else {
        json!({"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}}})
    };
    h.send_json(json!({"jsonrpc":"2.0","id":99,"method":"tools/list","params":meta}))
        .await;
    let catalog = h.receive_json().await;
    let schema = catalog["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == name)
        .map(|t| t["outputSchema"].clone());
    let mut params = json!({"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}},"name":name,"arguments":arguments});
    if h.legacy {
        params.as_object_mut().unwrap().remove("_meta");
    }
    for (k, v) in extra.as_object().unwrap() {
        params[k] = v.clone();
    }
    h.send_json(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":params}))
        .await;
    let reply = h.receive_json().await;
    if let Some(content) = reply["result"].get("structuredContent") {
        assert!(
            jsonschema::validator_for(&schema.unwrap())
                .unwrap()
                .is_valid(content),
            "{reply}"
        );
    }
    reply
}
pub async fn plan(h: &mut Harness) -> String {
    let r = call(
        h,
        "rules_set_enabled_plan",
        json!({"selectors":["r"],"enabled":false}),
        json!({}),
    )
    .await;
    r["result"]["structuredContent"]["data"]["plan"]["plan_id"]
        .as_str()
        .unwrap()
        .into()
}
pub async fn question(h: &mut Harness, id: &str) -> Value {
    let before = call(h, "plan_get", json!({"plan_id":id}), json!({})).await;
    let r = call(h, "plan_apply", json!({"plan_id":id}), json!({})).await;
    assert_eq!(r["result"]["resultType"], "input_required", "{r}");
    let q = &r["result"];
    assert_eq!(
        q.as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["resultType", "inputRequests", "requestState"]
    );
    assert_eq!(
        q["inputRequests"]["confirm"]["params"]["requestedSchema"],
        json!({"type":"object","properties":{"apply":{"type":"boolean","title":"Apply this change","description":"True applies the change shown above. False keeps the dry run.","default":false}},"required":["apply"]})
    );
    assert_eq!(
        q["inputRequests"]["confirm"]["params"]["message"],
        question_text(&before, id)
    );
    q.clone()
}
pub fn question_text(before: &Value, id: &str) -> String {
    let p = &before["result"]["structuredContent"]["data"]["plan"];
    let target = &before["result"]["structuredContent"]["target"];
    format!(
        "elasticctl asks to apply: {}\nTarget: profile {} @ {}, space {}\n{}\nNote: Kibana runs each rule listed with the credential it already has. A rule that has none gets this server's credential ({}) when it is enabled, and then runs with that credential's privileges.\nPlan: {}\nHash: {}\nExpires in 15 min.\n\nSet \"Apply this change\" to true and accept to apply it.\nDecline, or leave it false, and nothing changes.",
        p["action"].as_str().unwrap(),
        target["profile"].as_str().unwrap(),
        target["host"].as_str().unwrap(),
        target["space"].as_str().unwrap(),
        p["details"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| format!("  {}", v.as_str().unwrap()))
            .collect::<Vec<_>>()
            .join("\n"),
        p["credential"].as_str().unwrap(),
        id,
        &p["hash"].as_str().unwrap()[..16]
    )
}

#[tokio::test]
async fn one_rule_question_first_three_lines() {
    let (_s, mut h) = setup().await;
    let id = plan(&mut h).await;
    let before = call(&mut h, "plan_get", json!({"plan_id":id}), json!({})).await;
    let p = &before["result"]["structuredContent"]["data"]["plan"];
    let target = &before["result"]["structuredContent"]["target"];
    assert_eq!(p["details"].as_array().unwrap().len(), 1);
    let q = call(&mut h, "plan_apply", json!({"plan_id":id}), json!({})).await;
    assert_eq!(q["result"]["resultType"], "input_required");
    let text = q["result"]["inputRequests"]["confirm"]["params"]["message"]
        .as_str()
        .unwrap();
    assert_eq!(
        text.lines().take(3).collect::<Vec<_>>(),
        [
            format!(
                "elasticctl asks to apply: {}",
                p["action"].as_str().unwrap()
            ),
            format!(
                "Target: profile {} @ {}, space {}",
                target["profile"].as_str().unwrap(),
                target["host"].as_str().unwrap(),
                target["space"].as_str().unwrap()
            ),
            format!("  {}", p["details"][0].as_str().unwrap()),
        ]
    );
    h.close_input();
    h.join().await.unwrap();
}
#[tokio::test]
async fn current_question_and_answers() {
    for answer in [
        json!({"action":"accept","content":{"apply":false}}),
        json!({"action":"accept"}),
        json!({"action":"accept","content":{"apply":"true"}}),
        json!({"action":"cancel"}),
        json!({"garbage":true}),
    ] {
        let (s, mut h) = setup().await;
        let id = plan(&mut h).await;
        let q = question(&mut h, &id).await;
        assert_eq!(
            q["inputRequests"]["confirm"]["params"]["requestedSchema"]["required"],
            json!(["apply"])
        );
        let r = call(
            &mut h,
            "plan_apply",
            json!({"plan_id":id}),
            json!({"requestState":q["requestState"],"inputResponses":{"confirm":answer}}),
        )
        .await;
        assert_eq!(
            r["result"]["structuredContent"]["error"]["code"], "not_confirmed",
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
#[tokio::test]
async fn handles_are_bound_single_use_and_prompts_bounded() {
    let (_s, mut h) = setup().await;
    let a = plan(&mut h).await;
    let b = plan(&mut h).await;
    let q = question(&mut h, &a).await;
    for (id, handle) in [
        (&b, q["requestState"].clone()),
        (&a, json!("cfm_wrong")),
        (&a, q["requestState"].clone()),
    ] {
        let r=call(&mut h,"plan_apply",json!({"plan_id":id}),json!({"requestState":handle,"inputResponses":{"confirm":{"action":"accept","content":{"apply":true}}}})).await;
        assert_eq!(
            r["result"]["structuredContent"]["error"]["code"],
            "not_confirmed"
        );
    }
    let q = question(&mut h, &a).await;
    let q2 = call(
        &mut h,
        "plan_apply",
        json!({"plan_id":a}),
        json!({"requestState":q["requestState"]}),
    )
    .await;
    assert_eq!(q2["result"]["resultType"], "input_required");
    assert_ne!(q["requestState"], q2["result"]["requestState"]);
    let r = call(&mut h, "plan_apply", json!({"plan_id":a}), json!({})).await;
    assert_eq!(
        r["result"]["structuredContent"]["error"]["code"],
        "plan_declined"
    );
    assert_eq!(
        h.audit
            .lock()
            .unwrap()
            .iter()
            .filter(|v| v["audit"]["event"] == "confirmation_requested")
            .count(),
        3
    );
    h.close_input();
    h.join().await.unwrap();
}
#[tokio::test]
async fn decline_closes_and_protocol_errors_stay_static() {
    let (_s, mut h) = setup().await;
    let id = plan(&mut h).await;
    let q = question(&mut h, &id).await;
    let r = call(
        &mut h,
        "plan_apply",
        json!({"plan_id":id}),
        json!({"requestState":q["requestState"],"inputResponses":{"confirm":{"action":"decline"}}}),
    )
    .await;
    assert_eq!(
        r["result"]["structuredContent"]["error"]["code"],
        "plan_declined"
    );
    assert_eq!(
        r["result"]["structuredContent"]["error"]["message"],
        "The plan was declined and closed."
    );
    let r = call(&mut h, "name-sentinel", json!({}), json!({})).await;
    assert_eq!(r["error"]["message"], "Unknown MCP tool");
    assert!(!r.to_string().contains("name-sentinel"));
    h.close_input();
    let start = std::time::Instant::now();
    h.join().await.unwrap();
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
}
#[tokio::test]
async fn concurrent_fourth_prompt_audits_one_closure() {
    let (s, mut h) = setup().await;
    let id = plan(&mut h).await;
    question(&mut h, &id).await;
    question(&mut h, &id).await;
    wiremock::Mock::given(wiremock::matchers::path("/_security/_authenticate"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(fixture("authenticate"))
                .set_delay(std::time::Duration::from_millis(100)),
        )
        .with_priority(1)
        .mount(&s)
        .await;
    for n in [50, 51] {
        h.send_json(json!({"jsonrpc":"2.0","id":n,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}},"name":"plan_apply","arguments":{"plan_id":id}}})).await;
    }
    let a = h.receive_json().await;
    let b = h.receive_json().await;
    assert!(
        [a.clone(), b.clone()]
            .iter()
            .any(|v| v["result"]["resultType"] == "input_required")
    );
    assert!(
        [a, b]
            .iter()
            .any(|v| v["result"]["structuredContent"]["error"]["code"] == "plan_declined")
    );
    assert_eq!(
        h.audit
            .lock()
            .unwrap()
            .iter()
            .filter(|v| v["audit"]["event"] == "plan_closed")
            .count(),
        1
    );
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn round_two_requires_current_form_capability_without_consuming_handle() {
    for capabilities in [json!({}), json!({"elicitation":{"url":{}}})] {
        let (s, mut h) = setup().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(fixture("rules_bulk_disable")))
            .expect(1)
            .mount(&s)
            .await;
        let id = plan(&mut h).await;
        let q = question(&mut h, &id).await;
        let count = s.received_requests().await.unwrap().len();
        let answer = json!({"requestState":q["requestState"],"inputResponses":{"confirm":{"action":"accept","content":{"apply":true}}}});
        let mut withdrawn = answer.clone();
        withdrawn["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":capabilities});
        let r = call(&mut h, "plan_apply", json!({"plan_id":id}), withdrawn).await;
        assert_eq!(
            r["result"]["structuredContent"]["error"]["code"], "confirmation_unavailable",
            "{r}"
        );
        assert_eq!(s.received_requests().await.unwrap().len(), count);
        let r = call(&mut h, "plan_get", json!({"plan_id":id}), json!({})).await;
        assert_eq!(
            r["result"]["structuredContent"]["data"]["plan"]["state"],
            "open"
        );
        assert_eq!(
            h.audit
                .lock()
                .unwrap()
                .iter()
                .filter(|v| v["audit"]["event"] == "confirmation_answered")
                .count(),
            1
        );
        let r = call(&mut h, "plan_apply", json!({"plan_id":id}), answer).await;
        assert_eq!(
            r["result"]["structuredContent"]["data"]["plan"]["state"], "applied",
            "{r}"
        );
        h.close_input();
        h.join().await.unwrap();
    }
}

pub struct RawResponder {
    pub target: elasticctl_core::Resolved,
    pub requests: Arc<Mutex<Vec<(usize, String)>>>,
    pub gated: Arc<std::sync::atomic::AtomicBool>,
    pub release: Arc<tokio::sync::Semaphore>,
    pub arrived: tokio::sync::mpsc::UnboundedReceiver<()>,
    close: tokio::sync::broadcast::Sender<()>,
    closed: tokio::sync::mpsc::UnboundedReceiver<usize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for RawResponder {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl RawResponder {
    pub async fn start() -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut target = support::target();
        target.profile.kibana_url = format!("http://{}", listener.local_addr().unwrap());
        target.profile.es_url = Some(target.profile.kibana_url.clone());
        target.profile.api_key = Some("test-key".into());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let gated = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate = gated.clone();
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let released = release.clone();
        let (arrival, arrived) = tokio::sync::mpsc::unbounded_channel();
        let (close, _) = tokio::sync::broadcast::channel(8);
        let closing = close.clone();
        let (closed_tx, closed) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            let mut connection = 0;
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                connection += 1;
                let requests = recorded.clone();
                let gate = gate.clone();
                let release = released.clone();
                let arrival = arrival.clone();
                let mut closing = closing.subscribe();
                let closed = closed_tx.clone();
                tasks.spawn(async move {
                    loop {
                        let mut bytes = Vec::new();
                        let read = async {
                            let mut byte = [0];
                            while !bytes.ends_with(b"\r\n\r\n") {
                                stream.read_exact(&mut byte).await?;
                                bytes.push(byte[0]);
                            }
                            Ok::<_, std::io::Error>(())
                        };
                        tokio::select! {
                            r = read => if r.is_err() { return; },
                            _ = closing.recv() => {
                                stream.shutdown().await.unwrap();
                                drop(stream);
                                closed.send(connection).unwrap();
                                return;
                            }
                        }
                        let headers = String::from_utf8(bytes).unwrap();
                        let line = headers.lines().next().unwrap().to_owned();
                        requests.lock().unwrap().push((connection, line.clone()));
                        let length = headers.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap())).unwrap_or(0);
                        stream.read_exact(&mut vec![0; length]).await.unwrap();
                        if line.starts_with("GET ") && gate.load(std::sync::atomic::Ordering::SeqCst) {
                            arrival.send(()).unwrap();
                            release.acquire().await.unwrap().forget();
                        }
                        let mut body = if line.starts_with("POST ") { fixture("rules_bulk_disable") }
                            else if line.contains("/_security/_authenticate") { fixture("authenticate") }
                            else { fixture("rules_get") };
                        if body.get("rule_id").is_some() { body["rule_id"] = json!("r"); }
                        let body = body.to_string();
                        if stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).as_bytes()).await.is_err() { return; }
                    }
                });
            }
        });
        Self {
            target,
            requests,
            gated,
            release,
            arrived,
            close,
            closed,
            task,
        }
    }
    pub async fn close_reads(&mut self) {
        self.close.send(()).unwrap();
        assert_eq!(self.closed.recv().await, Some(1));
    }
    pub fn harness(&self, timeout: std::time::Duration) -> Harness {
        let o = elasticctl_mcp::ServerOptions {
            call_timeout: timeout,
            allow_mutations: elasticctl_mcp::MutationClasses::parse(["rules-toggle"]).unwrap(),
            ..Default::default()
        };
        Harness::start(self.target.clone(), o, None)
    }
}
