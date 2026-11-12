#[path = "mutation_conformance/audit.rs"]
mod audit;
#[path = "mutation_conformance/protocol.rs"]
mod protocol;
#[path = "mutation_conformance/schemas.rs"]
mod schemas;
#[allow(dead_code)]
mod support;

use serde_json::{Value, json};
use std::time::Duration;
use support::Harness;
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path},
};

fn fixture(name: &str) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/traditional-9.5.1");
    serde_json::from_slice::<Value>(&std::fs::read(root.join(format!("{name}.json"))).unwrap())
        .unwrap()["response"]
        .clone()
}
fn target(s: &MockServer) -> elasticctl_core::Resolved {
    let mut t = support::target();
    t.profile.kibana_url = s.uri();
    t.profile.es_url = Some(s.uri());
    t.profile.api_key = Some("test-key".into());
    t
}
fn options() -> elasticctl_mcp::ServerOptions {
    elasticctl_mcp::ServerOptions {
        allow_mutations: elasticctl_mcp::MutationClasses::parse([
            "rules-toggle",
            "rules-create",
            "alerts-triage",
            "cases",
        ])
        .unwrap(),
        ..support::options()
    }
}
fn meta() -> Value {
    json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}})
}
fn params(name: &str, args: Value) -> Value {
    json!({"_meta":meta(),"name":name,"arguments":args})
}
async fn send(h: &mut Harness, id: u64, p: Value) {
    h.send_json(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":p}))
        .await;
}
async fn receive(h: &mut Harness) -> Value {
    tokio::time::timeout(Duration::from_secs(8), h.receive_json())
        .await
        .unwrap()
}
async fn call(h: &mut Harness, name: &str, args: Value) -> Value {
    send(h, 1, params(name, args)).await;
    receive(h).await
}
fn content(r: &Value) -> &Value {
    &r["result"]["structuredContent"]
}
fn data(r: &Value) -> &Value {
    &content(r)["data"]
}
fn code(r: &Value) -> &Value {
    &content(r)["error"]["code"]
}
async fn plan(h: &mut Harness) -> Value {
    let r = call(
        h,
        "rules_set_enabled_plan",
        json!({"selectors":["r"],"enabled":false}),
    )
    .await;
    assert_eq!(data(&r)["plan"]["state"], "open", "{r}");
    data(&r)["plan"].clone()
}
async fn question(h: &mut Harness, id: &Value) -> Value {
    let q = call(h, "plan_apply", json!({"plan_id":id})).await;
    assert_eq!(q["result"]["resultType"], "input_required", "{q}");
    q["result"].clone()
}
fn answer(id: &Value, q: &Value, answer: Value) -> Value {
    let mut p = params("plan_apply", json!({"plan_id":id}));
    p["requestState"] = q["requestState"].clone();
    p["inputResponses"] = json!({"confirm":answer});
    p
}
fn accept() -> Value {
    json!({"action":"accept","content":{"apply":true}})
}
async fn finish(mut h: Harness) {
    h.close_input();
    tokio::time::timeout(Duration::from_secs(8), h.join())
        .await
        .unwrap()
        .unwrap();
}
async fn stack() -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_security/_authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture("authenticate")))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(|r: &Request| {
            let id = r
                .url
                .query_pairs()
                .find(|(k, _)| k == "rule_id")
                .unwrap()
                .1
                .into_owned();
            if id == "new-rule" {
                return ResponseTemplate::new(404)
                    .set_body_json(json!({"status_code":404,"message":"not found"}));
            }
            let mut rule = fixture("rules_get");
            rule["rule_id"] = json!(id);
            ResponseTemplate::new(200).set_body_json(rule)
        })
        .mount(&s)
        .await;
    s
}
async fn setup() -> (MockServer, Harness) {
    let s = stack().await;
    let h = Harness::start(target(&s), options());
    (s, h)
}
fn write_body() -> Value {
    json!({"action":"disable","query":"alert.attributes.params.ruleId: \"r\""})
}
async fn write_mock(s: &MockServer, count: u64, status: u16) {
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_bulk_action"))
        .and(wiremock::matchers::body_json(write_body()))
        .respond_with(
            ResponseTemplate::new(status).set_body_json(if status == 200 {
                fixture("rules_bulk_disable")
            } else {
                json!({"statusCode":status,"error":"error","message":"refused"})
            }),
        )
        .expect(count)
        .mount(s)
        .await;
}
async fn assert_writes(s: &MockServer, expected: usize) {
    let requests = s.received_requests().await.unwrap();
    let writes: Vec<_> = requests.iter().filter(|r| r.method != "GET").collect();
    assert_eq!(writes.len(), expected, "{writes:?}");
    for r in writes {
        assert_eq!(r.method, "POST");
        assert_eq!(r.url.path(), "/api/detection_engine/rules/_bulk_action");
        assert_eq!(r.body_json::<Value>().unwrap(), write_body());
    }
}
