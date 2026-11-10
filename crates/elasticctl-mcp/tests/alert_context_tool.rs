//! `alert_context` through `serve_io`: input validation, the declared output
//! schema, projections, findings, size limits, cancellation, and deadlines.
#[allow(dead_code)]
mod support;

use elasticctl_core::{Profile, Resolved, Source};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use support::{Harness, current_metadata, options};
use tokio::time::{sleep, timeout};
use wiremock::{Mock, MockServer, Request, ResponseTemplate, matchers::any};

const DESCRIPTION: &str = "Triage context for one Elastic Security alert: the alert, the rule that fired it with its last execution, the rule's exception lists, cases that contain the alert, and the rule's alert volume in a time window. Read-only.";
const ALERT_ID: &str = "elasticctl-fixture-alert-1";
const SENTINEL: &str = "essu_c2VudGluZWwtY3JlZGVudGlhbC12YWx1ZQ";

fn recorded_file(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/serverless-9.7.0")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn fixture(name: &str) -> Value {
    let v = recorded_file(name)["response"].clone();
    assert!(!v.is_null(), "fixture {name} has a response");
    v
}
fn error_body() -> Value {
    recorded_file("data_view_not_found.json")["error"].clone()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Status,
    Alert,
    Rule,
    List,
    Count,
    Cases,
    Case,
    Activity,
    Other,
}
use Step::*;

fn body(req: &Request) -> Value {
    serde_json::from_slice(&req.body).unwrap_or(Value::Null)
}
fn step_of(req: &Request) -> Step {
    match (req.method.as_str(), req.url.path()) {
        ("GET", "/api/status") => Status,
        ("POST", "/api/detection_engine/signals/search") if body(req)["size"] == 0 => Activity,
        ("POST", "/api/detection_engine/signals/search") => Alert,
        ("GET", "/api/detection_engine/rules") => Rule,
        ("GET", "/api/exception_lists") => List,
        ("GET", "/api/exception_lists/items/_find") => Count,
        ("GET", p) if p.starts_with("/api/cases/alerts/") => Cases,
        ("GET", p) if p.starts_with("/api/cases/") => Case,
        _ => Other,
    }
}
/// The alert id a step-one search asks for.
fn asked_alert(req: &Request) -> String {
    body(req)["query"]["ids"]["values"][0]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn alert_page(edit: impl FnOnce(&mut Value)) -> Value {
    let mut page = fixture("signals_search_rule_activity.json");
    let mut hit = page["hits"]["hits"][0].clone();
    assert_eq!(hit["_id"], ALERT_ID);
    edit(&mut hit);
    page["hits"]["hits"] = json!([hit]);
    page["hits"]["total"]["value"] = json!(1);
    page.as_object_mut().unwrap().remove("aggregations");
    page
}
fn empty_alert_page() -> Value {
    let mut page = alert_page(|_| ());
    page["hits"]["hits"] = json!([]);
    page["hits"]["total"]["value"] = json!(0);
    page
}
fn activity() -> Value {
    let mut body = fixture("signals_search_rule_activity.json");
    body["hits"]["hits"] = json!([]);
    body
}
fn ok(body: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
}

/// Recorded answers for every step of the plan.
fn recorded(step: Step) -> ResponseTemplate {
    match step {
        Status => ok(fixture("status.json")),
        Alert => ok(alert_page(|_| ())),
        Rule => ok(fixture("rule_get_executed.json")),
        List => ok(fixture("exception_list_get.json")),
        Count => ok(fixture("exception_items_count.json")),
        Cases => ok(fixture("cases_by_alert.json")),
        Case => ok(fixture("case_get.json")),
        Activity => ok(activity()),
        Other => ResponseTemplate::new(404).set_body_json(error_body()),
    }
}

async fn stack(
    route: impl Fn(Step, &Request) -> Option<ResponseTemplate> + Send + Sync + 'static,
) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(move |req: &Request| {
            let step = step_of(req);
            route(step, req).unwrap_or_else(|| recorded(step))
        })
        .mount(&server)
        .await;
    server
}
async fn steps(server: &MockServer) -> Vec<Step> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(step_of)
        .filter(|s| *s != Status)
        .collect()
}

fn target_for(server: &MockServer) -> Resolved {
    Resolved {
        name: "test".to_string(),
        source: Source::Profile,
        profile: Profile {
            kibana_url: server.uri(),
            es_url: Some(server.uri()),
            api_key: Some("fake-auth-marker".to_string()),
            username: None,
            password: None,
            space: "default".to_string(),
            verify: true,
            timeout_secs: 30,
        },
    }
}

async fn send(h: &mut Harness, id: u64, arguments: Value) {
    h.send_json(json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"_meta": current_metadata(), "name": "alert_context", "arguments": arguments},
    }))
    .await;
}
async fn call(h: &mut Harness, id: u64, arguments: Value) -> Value {
    send(h, id, arguments).await;
    let reply = h.receive_json().await;
    assert_eq!(reply["id"], id);
    reply
}
async fn tool(h: &mut Harness) -> Value {
    h.send_json(json!({"jsonrpc":"2.0","id":900,"method":"tools/list","params":{"_meta":current_metadata()}}))
        .await;
    let reply = h.receive_json().await;
    reply["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "alert_context")
        .unwrap()
        .clone()
}
fn structured(reply: &Value) -> &Value {
    &reply["result"]["structuredContent"]
}
fn assert_text_copy(reply: &Value) {
    let text = reply["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(text).unwrap(),
        *structured(reply)
    );
}
fn assert_schema(schema: &Value, instance: &Value) {
    let validator = jsonschema::validator_for(schema).expect("output schema compiles");
    let errors = validator.iter_errors(instance).collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema rejected {instance}: {errors:?}");
}
fn keys(value: &Value) -> Vec<&str> {
    let mut k: Vec<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    k.sort();
    k
}

#[tokio::test]
async fn definition_declares_the_exact_description_and_closed_input() {
    let mut h = Harness::start(support::target(), options());
    let t = tool(&mut h).await;
    assert_eq!(t["description"], DESCRIPTION);
    let input = &t["inputSchema"];
    assert_eq!(input["type"], "object");
    assert_eq!(input["additionalProperties"], false);
    assert_eq!(input["required"], json!(["alert_id"]));
    assert_eq!(keys(&input["properties"]), ["alert_id", "since"]);
    assert_eq!(input["properties"]["alert_id"]["type"], "string");
    assert_eq!(input["properties"]["alert_id"]["maxLength"], 1024);
    assert_eq!(input["properties"]["since"]["default"], "24h");
    assert_eq!(t["outputSchema"]["type"], "object");
    assert_eq!(
        t["annotations"],
        json!({"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true})
    );
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn invalid_input_sends_no_request() {
    let server = stack(|_, _| None).await;
    let mut h = Harness::start(target_for(&server), options());
    let schema = tool(&mut h).await["outputSchema"].clone();
    let long = "x".repeat(1_025);
    let cases = [
        json!({}),
        json!({"alert_id": ""}),
        json!({"alert_id": "   "}),
        json!({"alert_id": "."}),
        json!({"alert_id": ".."}),
        json!({"alert_id": long}),
        json!({"alert_id": 7}),
        json!({"alert_id": null}),
        json!({"alert_id": "a", "since": "0h"}),
        json!({"alert_id": "a", "since": "24"}),
        json!({"alert_id": "a", "since": "h"}),
        json!({"alert_id": "a", "since": "10000d"}),
        json!({"alert_id": "a", "since": "now-1d"}),
        json!({"alert_id": "a", "since": "1H"}),
        json!({"alert_id": "a", "since": "24h "}),
        json!({"alert_id": "a", "since": ""}),
        json!({"alert_id": "a", "since": 24}),
        json!({"alert_id": "a", "unexpected": true}),
    ];
    for (i, arguments) in cases.into_iter().enumerate() {
        let reply = call(&mut h, i as u64 + 1, arguments.clone()).await;
        assert_eq!(reply["result"]["isError"], true, "{arguments}");
        assert_eq!(
            structured(&reply)["error"]["code"],
            "invalid_argument",
            "{arguments}"
        );
        assert_text_copy(&reply);
        assert_schema(&schema, structured(&reply));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn full_success_matches_the_schema_and_projection() {
    let server = stack(|_, _| None).await;
    let mut h = Harness::start(target_for(&server), options());
    let schema = tool(&mut h).await["outputSchema"].clone();
    let reply = call(&mut h, 1, json!({"alert_id": ALERT_ID})).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_text_copy(&reply);
    assert_schema(&schema, structured(&reply));
    assert_eq!(
        steps(&server).await,
        [Alert, Rule, List, Count, Cases, Case, Activity]
    );
    let out = structured(&reply);
    assert_eq!(keys(out), ["data", "page", "target"]);
    assert!(out["page"].is_null());
    let data = &out["data"];
    assert_eq!(
        keys(data),
        [
            "activity",
            "alert",
            "cases",
            "exceptions",
            "findings",
            "partial",
            "rule"
        ]
    );
    assert_eq!(data["alert"]["id"], ALERT_ID);
    assert_eq!(keys(&data["alert"]), ["id", "index", "source"]);
    assert_eq!(
        data["alert"]["source"]["kibana.alert.rule.rule_id"],
        "elasticctl-sample-alert-probe"
    );
    assert_eq!(data["rule"]["status"], "ok");
    let rule = &data["rule"]["value"];
    assert_eq!(rule["rule_id"], "elasticctl-sample-alert-probe");
    assert_eq!(rule["execution"]["status"], "succeeded");
    assert_eq!(rule["execution"]["status_order"], 0);
    assert_eq!(
        rule["execution"]["message"],
        "elasticctl-fixture-server-text"
    );
    assert_eq!(rule["execution"]["message_truncated"], false);
    assert_eq!(
        keys(&rule["execution"]["metrics"]),
        ["total_indexing_duration_ms", "total_search_duration_ms"]
    );
    assert_eq!(
        data["exceptions"],
        json!({"status":"ok","value":{"referenced":1,"truncated":false,"lists":[{
            "list_id":"elasticctl-sample-exceptions","namespace_type":"single","type":"detection",
            "status":"ok","name":"elasticctl sample exceptions","list_type":"detection","item_count":2}]}})
    );
    let cases = &data["cases"]["value"];
    assert_eq!(data["cases"]["status"], "ok");
    assert_eq!(
        (cases["total"].clone(), cases["truncated"].clone()),
        (json!(1), json!(false))
    );
    let row = &cases["cases"][0];
    assert_eq!(keys(row), ["case", "id", "status", "title"]);
    assert_eq!(row["id"], "elasticctl-fixture-case");
    assert_eq!(row["title"], "elasticctl sample case");
    assert_eq!(row["status"], "ok");
    assert_eq!(row["case"]["id"], "elasticctl-fixture-case");
    assert_eq!(row["case"]["status"], "open");
    assert_eq!(
        data["activity"],
        json!({"status":"ok","value":{"window":"24h","total":16,
            "by_status":{"open":5,"acknowledged":0,"closed":11,"other":0}}})
    );
    assert_eq!(data["partial"], false);
    assert_eq!(data["findings"], json!(["has_related_case"]));
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn partial_and_failure_match_the_schema() {
    let server = stack(|step, req| match step {
        Alert if asked_alert(req) == "absent" => Some(ok(empty_alert_page())),
        List => Some(ResponseTemplate::new(404).set_body_json(error_body())),
        Cases => Some(ResponseTemplate::new(403).set_body_json(error_body())),
        _ => None,
    })
    .await;
    let mut h = Harness::start(target_for(&server), options());
    let schema = tool(&mut h).await["outputSchema"].clone();

    let reply = call(&mut h, 1, json!({"alert_id": ALERT_ID, "since": "7d"})).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_text_copy(&reply);
    assert_schema(&schema, structured(&reply));
    let data = &structured(&reply)["data"];
    assert_eq!(data["partial"], true);
    assert_eq!(
        data["exceptions"]["value"]["lists"][0],
        json!({"list_id":"elasticctl-sample-exceptions","namespace_type":"single","type":"detection",
            "status":"unavailable","error":{"kind":"not_found","http_status":404,"code":"elastic_not_found",
            "message":"The selected resource was not found."}})
    );
    assert_eq!(keys(&data["cases"]), ["error", "status"]);
    assert_eq!(data["cases"]["status"], "unavailable");
    assert_eq!(data["cases"]["error"]["code"], "elastic_permission");
    assert_eq!(data["activity"]["value"]["window"], "7d");
    assert_eq!(data["findings"], json!(["exception_list_missing"]));
    assert_eq!(steps(&server).await, [Alert, Rule, List, Cases, Activity]);

    let reply = call(&mut h, 2, json!({"alert_id": "absent"})).await;
    assert_eq!(reply["result"]["isError"], true);
    assert_text_copy(&reply);
    assert_schema(&schema, structured(&reply));
    assert_eq!(keys(structured(&reply)), ["error", "target"]);
    assert_eq!(structured(&reply)["error"]["code"], "elastic_not_found");
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn skipped_parts_match_the_schema() {
    let server = stack(|step, req| match step {
        Alert if asked_alert(req) == "no-rule" => Some(ok(alert_page(|hit| {
            hit["_source"]
                .as_object_mut()
                .unwrap()
                .remove("kibana.alert.rule.rule_id")
                .unwrap();
        }))),
        Rule => Some(ResponseTemplate::new(404).set_body_json(error_body())),
        _ => None,
    })
    .await;
    let mut h = Harness::start(target_for(&server), options());
    let schema = tool(&mut h).await["outputSchema"].clone();
    for (id, alert_id, rule) in [
        (
            1,
            "no-rule",
            json!({"status":"skipped","skip_reason":"not_applicable"}),
        ),
        (
            2,
            ALERT_ID,
            json!({"status":"unavailable","error":{"kind":"not_found","http_status":404,
            "code":"elastic_not_found","message":"The selected resource was not found."}}),
        ),
    ] {
        let reply = call(&mut h, id, json!({"alert_id": alert_id})).await;
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        assert_text_copy(&reply);
        assert_schema(&schema, structured(&reply));
        let data = &structured(&reply)["data"];
        assert_eq!(data["rule"], rule);
        for part in ["exceptions", "activity"] {
            assert_eq!(
                data[part],
                json!({"status":"skipped","skip_reason":"dependency_unavailable"})
            );
        }
        assert_eq!(data["cases"]["status"], "ok");
    }
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn findings_follow_the_fixed_order() {
    let server = stack(|step, _| match step {
        Alert => Some(ok(alert_page(|hit| {
            hit["_source"]["kibana.alert.workflow_status"] = json!("acknowledged");
        }))),
        Rule => {
            let mut rule = fixture("rule_get_executed.json");
            rule["enabled"] = json!(false);
            rule["execution_summary"]["last_execution"]["status"] = json!("failed");
            Some(ok(rule))
        }
        List => Some(ResponseTemplate::new(404).set_body_json(error_body())),
        _ => None,
    })
    .await;
    let mut h = Harness::start(target_for(&server), options());
    let reply = call(&mut h, 1, json!({"alert_id": ALERT_ID})).await;
    assert_eq!(
        structured(&reply)["data"]["findings"],
        json!([
            "alert_not_open",
            "rule_disabled",
            "rule_last_execution_failed",
            "exception_list_missing",
            "has_related_case"
        ])
    );
    assert_eq!(structured(&reply)["data"]["partial"], true);
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn missing_rule_finding_precedes_the_case_finding() {
    let server = stack(|step, _| match step {
        Rule => Some(ResponseTemplate::new(404).set_body_json(error_body())),
        _ => None,
    })
    .await;
    let mut h = Harness::start(target_for(&server), options());
    let reply = call(&mut h, 1, json!({"alert_id": ALERT_ID})).await;
    assert_eq!(
        structured(&reply)["data"]["findings"],
        json!(["rule_missing", "has_related_case"])
    );
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn sentinels_outside_the_projection_are_absent() {
    let server = stack(|step, _| match step {
        Alert => Some(ok(alert_page(|hit| {
            let source = hit["_source"].as_object_mut().unwrap();
            source.insert("user.name".into(), json!(SENTINEL));
            source["kibana.alert.rule.parameters"]["description"] = json!(SENTINEL);
        }))),
        Rule => {
            let mut rule = fixture("rule_get_executed.json");
            rule["setup"] = json!(SENTINEL);
            // The message is returned by design; a sentinel past the cap is cut.
            rule["execution_summary"]["last_execution"]["message"] =
                json!(format!("{}{SENTINEL}", "m".repeat(2_048)));
            Some(ok(rule))
        }
        List => {
            let mut list = fixture("exception_list_get.json");
            list["description"] = json!(SENTINEL);
            Some(ok(list))
        }
        Cases => {
            let mut rows = fixture("cases_by_alert.json");
            rows[0]["description"] = json!(SENTINEL);
            Some(ok(rows))
        }
        Case => {
            let mut case = fixture("case_get.json");
            case["assignees"][0]["uid"] = json!(SENTINEL);
            case["connector"]["id"] = json!(SENTINEL);
            case["sentinel_extra"] = json!(SENTINEL);
            Some(ok(case))
        }
        _ => None,
    })
    .await;
    let mut h = Harness::start(target_for(&server), options());
    let reply = call(&mut h, 1, json!({"alert_id": ALERT_ID})).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    let data = &structured(&reply)["data"];
    let execution = &data["rule"]["value"]["execution"];
    assert_eq!(execution["message"], "m".repeat(2_048));
    assert_eq!(execution["message_truncated"], true);
    assert_eq!(data["cases"]["value"]["cases"][0]["status"], "ok");
    assert!(!reply.to_string().contains(SENTINEL), "{reply}");
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn sentinels_in_error_bodies_are_absent() {
    let sentinel_error = || {
        let mut body = error_body();
        body["message"] = json!(SENTINEL);
        body
    };
    let server = stack(move |step, _| match step {
        List => Some(ResponseTemplate::new(404).set_body_json(sentinel_error())),
        Cases => Some(ResponseTemplate::new(403).set_body_json(sentinel_error())),
        Activity => Some(ResponseTemplate::new(403).set_body_json(sentinel_error())),
        _ => None,
    })
    .await;
    let mut h = Harness::start(target_for(&server), options());
    let reply = call(&mut h, 1, json!({"alert_id": ALERT_ID})).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    let data = &structured(&reply)["data"];
    assert_eq!(data["cases"]["status"], "unavailable");
    assert_eq!(data["activity"]["status"], "unavailable");
    assert_eq!(
        data["exceptions"]["value"]["lists"][0]["status"],
        "unavailable"
    );
    assert!(!reply.to_string().contains(SENTINEL), "{reply}");
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn oversized_rule_is_result_too_large() {
    let server = stack(|step, _| match step {
        Rule => {
            let mut rule = fixture("rule_get_executed.json");
            rule["description"] = json!("d".repeat(300_000));
            Some(ok(rule))
        }
        _ => None,
    })
    .await;
    let mut h = Harness::start(target_for(&server), options());
    let schema = tool(&mut h).await["outputSchema"].clone();
    let reply = call(&mut h, 1, json!({"alert_id": ALERT_ID})).await;
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(structured(&reply)["error"]["code"], "result_too_large");
    assert!(structured(&reply).get("data").is_none());
    assert_schema(&schema, structured(&reply));
    h.close_input();
    h.join().await.unwrap();
}

/// Delay the third request of the plan, the first exception list read, and
/// hold any alert whose id starts with `held`.
async fn delayed_stack(list_delay: Duration, held_delay: Duration) -> MockServer {
    stack(move |step, req| match step {
        List => Some(recorded(List).set_delay(list_delay)),
        Alert if asked_alert(req).starts_with("held") => {
            Some(ok(empty_alert_page()).set_delay(held_delay))
        }
        _ => None,
    })
    .await
}
async fn wait_for(server: &MockServer, step: Step, count: usize) {
    timeout(Duration::from_secs(5), async {
        while steps(server).await.iter().filter(|s| **s == step).count() < count {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("expected requests arrive");
}

#[tokio::test]
async fn cancellation_on_the_third_request_frees_the_permit() {
    let server = delayed_stack(Duration::from_secs(2), Duration::from_secs(5)).await;
    let mut h = Harness::start(target_for(&server), options());
    send(&mut h, 1, json!({"alert_id": ALERT_ID})).await;
    wait_for(&server, List, 1).await;
    for id in 2..=4 {
        send(&mut h, id, json!({"alert_id": format!("held-{id}")})).await;
    }
    wait_for(&server, Alert, 4).await;
    let cancelled = Instant::now();
    h.send_json(json!({
        "jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": {"requestId": 1, "reason": "test", "_meta": current_metadata()},
    }))
    .await;
    sleep(Duration::from_millis(200)).await;
    // Three calls are held, so this one is admitted only with the freed permit.
    for (id, alert_id) in [(5, "."), (6, "..")] {
        let reply = call(&mut h, id, json!({"alert_id": alert_id})).await;
        assert_eq!(structured(&reply)["error"]["code"], "invalid_argument");
    }
    sleep(Duration::from_millis(2_500).saturating_sub(cancelled.elapsed())).await;
    assert_eq!(
        steps(&server).await,
        [Alert, Rule, List, Alert, Alert, Alert],
        "the cancelled call sent a later request"
    );
    for _ in 0..3 {
        let reply = timeout(Duration::from_secs(5), h.receive_json())
            .await
            .expect("held call answers");
        assert_ne!(reply["id"], 1, "the cancelled call answered");
        assert_eq!(structured(&reply)["error"]["code"], "elastic_not_found");
    }
    assert!(
        timeout(Duration::from_millis(300), h.receive_json())
            .await
            .is_err(),
        "the cancelled call answered"
    );
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn deadline_on_the_third_request_frees_the_permit() {
    let server = delayed_stack(Duration::from_secs(2), Duration::from_millis(300)).await;
    let mut opts = options();
    opts.call_timeout = Duration::from_secs(1);
    let mut h = Harness::start(target_for(&server), opts);
    let schema = tool(&mut h).await["outputSchema"].clone();
    let started = Instant::now();
    let reply = call(&mut h, 1, json!({"alert_id": ALERT_ID})).await;
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(structured(&reply)["error"]["code"], "deadline_exceeded");
    assert!(structured(&reply).get("data").is_none());
    assert_text_copy(&reply);
    assert_schema(&schema, structured(&reply));
    sleep(Duration::from_millis(2_500).saturating_sub(started.elapsed())).await;
    assert_eq!(
        steps(&server).await,
        [Alert, Rule, List],
        "the expired call sent a later request"
    );
    // Four concurrent calls are all admitted only when every permit is free.
    for id in 2..=5 {
        send(&mut h, id, json!({"alert_id": format!("held-{id}")})).await;
    }
    for _ in 0..4 {
        let reply = h.receive_json().await;
        assert_eq!(
            structured(&reply)["error"]["code"],
            "elastic_not_found",
            "{reply}"
        );
    }
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn malformed_rule_fields_preserve_alert_and_cases() {
    for (field, value) in [
        ("enabled", json!("false")),
        ("name", json!(7)),
        ("type", json!(7)),
        ("severity", json!(7)),
        ("risk_score", json!("7")),
        ("tags", json!([7])),
        ("description", json!(7)),
        ("language", json!(7)),
        ("query", json!(7)),
        ("index", json!([7])),
        ("from", json!(7)),
        ("interval", json!(7)),
        ("exceptions_list", json!([7])),
        ("exceptions_list", json!({})),
        ("exceptions_list", json!([{"list_id": 7}])),
        ("exceptions_list", json!([{"namespace_type": 7}])),
        ("exceptions_list", json!([{"type": 7}])),
    ] {
        let server = stack(move |step, _| {
            (step == Rule).then(|| {
                let mut rule = fixture("rule_get_executed.json");
                rule[field] = value.clone();
                ok(rule)
            })
        })
        .await;
        let mut h = Harness::start(target_for(&server), options());
        let schema = tool(&mut h).await["outputSchema"].clone();
        let reply = call(&mut h, 1, json!({"alert_id": ALERT_ID})).await;
        assert_eq!(reply["result"]["isError"], false, "{field}: {reply}");
        assert_schema(&schema, structured(&reply));
        let data = &structured(&reply)["data"];
        assert_eq!(data["alert"]["id"], ALERT_ID);
        assert_eq!(data["rule"]["status"], "unavailable");
        assert_eq!(data["rule"]["error"]["kind"], "http");
        for part in ["exceptions", "activity"] {
            assert_eq!(
                data[part],
                json!({"status":"skipped","skip_reason":"dependency_unavailable"})
            );
        }
        assert_eq!(data["cases"]["value"]["total"], 1);
        assert_eq!(data["partial"], true);
        assert_eq!(data["findings"], json!(["has_related_case"]));
        assert_eq!(steps(&server).await, [Alert, Rule, Cases, Case]);
        h.close_input();
        h.join().await.unwrap();
    }
}

mod failure_matrix {
    use super::{
        ALERT_ID, Harness, assert_schema, assert_text_copy, call, error_body, fixture, options,
        structured, tool,
    };
    use elasticctl_core::ErrorKind;
    use serde_json::{Value, json};
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Step {
        Alert,
        Rule,
        List,
        Count,
        Cases,
        Case,
        Activity,
        Other,
    }
    use Step::*;

    #[derive(Clone, Debug)]
    struct Req {
        method: String,
        target: String,
        body: Value,
    }
    impl Req {
        fn path(&self) -> &str {
            self.target.split('?').next().unwrap()
        }
        fn query(&self, key: &str) -> Option<String> {
            let q = self.target.split_once('?')?.1;
            q.split('&')
                .filter_map(|kv| kv.split_once('='))
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_owned())
        }
    }

    enum Act {
        Json(u16, Value),
        Drop,
        Hang,
        Oversized,
    }

    fn step_of(r: &Req) -> Option<Step> {
        Some(match (r.method.as_str(), r.path()) {
            ("GET", "/api/status") => return None,
            ("POST", "/api/detection_engine/signals/search") if r.body["size"] == 0 => Activity,
            ("POST", "/api/detection_engine/signals/search") => Alert,
            ("GET", "/api/detection_engine/rules") => Rule,
            ("GET", "/api/exception_lists") => List,
            ("GET", "/api/exception_lists/items/_find") => Count,
            ("GET", p) if p.starts_with("/api/cases/alerts/") => Cases,
            ("GET", p) if p.starts_with("/api/cases/") => Case,
            _ => Other,
        })
    }

    type Route = Arc<dyn Fn(Step, &Req) -> Act + Send + Sync>;
    type Log = Arc<Mutex<Vec<Req>>>;

    struct Stack {
        url: String,
        log: Log,
    }

    impl Stack {
        async fn start(route: impl Fn(Step, &Req) -> Act + Send + Sync + 'static) -> Stack {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let log: Log = Arc::default();
            let route: Route = Arc::new(route);
            let shared = Arc::clone(&log);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(serve(stream, Arc::clone(&route), Arc::clone(&shared)));
                }
            });
            Stack { url, log }
        }
        /// Every request in arrival order, without the cached capability probe.
        fn requests(&self) -> Vec<Req> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .filter(|r| step_of(r).is_some())
                .cloned()
                .collect()
        }
        fn steps(&self) -> Vec<Step> {
            self.requests().iter().filter_map(step_of).collect()
        }
    }

    async fn serve(mut stream: TcpStream, route: Route, log: Log) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let mut first = lines.next().unwrap().split(' ');
        let method = first.next().unwrap().to_owned();
        let target = first.next().unwrap().to_owned();
        let len = lines
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .map_or(0, |(_, v)| v.trim().parse::<usize>().unwrap());
        while buf.len() < head_end + len {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let body = serde_json::from_slice(&buf[head_end..head_end + len]).unwrap_or(Value::Null);
        let req = Req {
            method,
            target,
            body,
        };
        log.lock().unwrap().push(req.clone());
        let act = match step_of(&req) {
            None => Act::Json(200, fixture("status.json")),
            Some(step) => route(step, &req),
        };
        match act {
            Act::Json(status, body) => {
                let body = serde_json::to_vec(&body).unwrap();
                let head = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.flush().await;
            }
            Act::Oversized => {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 16777217\r\nconnection: close\r\n\r\n",
                    )
                    .await;
            }
            Act::Drop => drop(stream),
            Act::Hang => tokio::time::sleep(Duration::from_secs(30)).await,
        }
    }

    /// The recorded alert as a one-hit search page, with `edit` applied to it.
    fn alert_page(edit: impl FnOnce(&mut Value)) -> Value {
        let mut page = fixture("signals_search_rule_activity.json");
        let mut hit = page["hits"]["hits"][0].clone();
        assert_eq!(hit["_id"], ALERT_ID);
        edit(&mut hit);
        page["hits"]["hits"] = json!([hit]);
        page["hits"]["total"]["value"] = json!(1);
        page.as_object_mut().unwrap().remove("aggregations");
        page
    }
    /// The recorded rule with `n` exception references derived from its first.
    fn rule_with_refs(n: usize) -> Value {
        let mut rule = fixture("rule_get_executed.json");
        let first = rule["exceptions_list"][0].clone();
        rule["exceptions_list"] = json!(
            (0..n)
                .map(|i| {
                    let mut r = first.clone();
                    r["list_id"] = json!(format!("{}-{i}", first["list_id"].as_str().unwrap()));
                    r
                })
                .collect::<Vec<_>>()
        );
        rule
    }
    /// The recorded cases-by-alert answer with `n` rows derived from its first.
    fn case_refs(n: usize) -> Value {
        let row = fixture("cases_by_alert.json")[0].clone();
        json!(
            (0..n)
                .map(|i| {
                    let mut r = row.clone();
                    r["id"] = json!(format!("case-{i}"));
                    r["title"] = json!(format!("title-{i}"));
                    r
                })
                .collect::<Vec<_>>()
        )
    }
    fn case_detail(req: &Req) -> Value {
        let mut case = fixture("case_get.json");
        case["id"] = json!(req.path().trim_start_matches("/api/cases/"));
        case
    }
    /// The recorded activity answer as a `size: 0` search returns it.
    fn activity() -> Value {
        let mut body = fixture("signals_search_rule_activity.json");
        body["hits"]["hits"] = json!([]);
        body
    }

    /// Recorded answers for a rule with `refs` exception references and an
    /// alert in `cases` cases.
    fn recorded(refs: usize, cases: usize) -> impl Fn(Step, &Req) -> Act + Send + Sync + Clone {
        move |step, req| match step {
            Alert => Act::Json(200, alert_page(|_| ())),
            Rule => Act::Json(200, rule_with_refs(refs)),
            List => Act::Json(200, fixture("exception_list_get.json")),
            Count => Act::Json(200, fixture("exception_items_count.json")),
            Cases => Act::Json(200, case_refs(cases)),
            Case => Act::Json(200, case_detail(req)),
            Activity => Act::Json(200, activity()),
            Other => Act::Json(404, error_body()),
        }
    }

    fn target(s: &Stack) -> elasticctl_core::Resolved {
        let mut target = crate::support::target();
        target.profile.kibana_url = s.url.clone();
        target.profile.es_url = Some(s.url.clone());
        target.profile.timeout_secs = 1;
        target.profile.api_key = Some("test".into());
        target
    }

    #[tokio::test]
    async fn fatal_errors_at_each_step_return_failure_envelopes() {
        let plan = [Alert, Rule, List, Count, Cases, Case, Activity];
        for (at, failing) in plan.into_iter().enumerate() {
            for fatal in [ErrorKind::Auth, ErrorKind::Connection, ErrorKind::Timeout] {
                let base = recorded(1, 1);
                let s = Stack::start(move |step, req| {
                    if step != failing {
                        return base(step, req);
                    }
                    match fatal {
                        ErrorKind::Auth => Act::Json(401, error_body()),
                        ErrorKind::Connection => Act::Drop,
                        _ => Act::Hang,
                    }
                })
                .await;
                let mut h = Harness::start(target(&s), options());
                let schema = tool(&mut h).await["outputSchema"].clone();
                let reply = call(&mut h, 1, json!({"alert_id": ALERT_ID})).await;
                assert_eq!(reply["result"]["isError"], true, "{reply}");
                let out = structured(&reply);
                assert_eq!(out["error"]["kind"], fatal.as_str(), "{failing:?}");
                assert!(out.get("data").is_none());
                assert_schema(&schema, out);
                assert_text_copy(&reply);
                assert_eq!(s.steps(), plan[..=at]);
                h.close_input();
                h.join().await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn nonfatal_errors_at_each_part_return_partial_envelopes() {
        for failing in [Rule, List, Count, Cases, Case, Activity] {
            for (status, kind) in [
                (403, "permission"),
                (404, "not_found"),
                (409, "conflict"),
                (400, "http"),
                (200, "unsupported"),
                (201, "error"),
            ] {
                if status == 201 && !matches!(failing, Rule | List) {
                    continue;
                }
                let base = recorded(2, 2);
                let s = Stack::start(move |step, req| {
                    if step != failing
                        || (step == List || step == Count)
                            && !req.query("list_id").unwrap().ends_with("-0")
                        || step == Case && !req.path().ends_with("case-0")
                    {
                        return base(step, req);
                    }
                    if status == 201 {
                        let mut body = if failing == Rule {
                            rule_with_refs(2)
                        } else {
                            fixture("exception_list_get.json")
                        };
                        body.as_object_mut().unwrap().remove(if failing == Rule {
                            "rule_id"
                        } else {
                            "list_id"
                        });
                        Act::Json(200, body)
                    } else if status == 200 {
                        Act::Oversized
                    } else {
                        Act::Json(status, error_body())
                    }
                })
                .await;
                let mut h = Harness::start(target(&s), options());
                let schema = tool(&mut h).await["outputSchema"].clone();
                let reply = call(&mut h, 1, json!({"alert_id": ALERT_ID})).await;
                assert_eq!(
                    reply["result"]["isError"], false,
                    "{failing:?} {kind}: {reply}"
                );
                assert_schema(&schema, structured(&reply));
                assert_text_copy(&reply);
                let data = &structured(&reply)["data"];
                let part = match failing {
                    Rule => &data["rule"],
                    Cases => &data["cases"],
                    Activity => &data["activity"],
                    List | Count => &data["exceptions"]["value"]["lists"][0],
                    Case => &data["cases"]["value"]["cases"][0],
                    _ => unreachable!(),
                };
                assert_eq!(part["status"], "unavailable");
                assert_eq!(part["error"]["kind"], kind);
                assert_eq!(data["partial"], true);
                if failing == Rule {
                    for part in ["exceptions", "activity"] {
                        assert_eq!(
                            data[part],
                            json!({"status":"skipped","skip_reason":"dependency_unavailable"})
                        );
                    }
                }
                if matches!(failing, List | Count) {
                    assert_eq!(data["exceptions"]["value"]["lists"][1]["status"], "ok");
                }
                if failing == Case {
                    assert_eq!(data["cases"]["value"]["cases"][1]["status"], "ok");
                }
                let mut findings = Vec::new();
                if kind == "not_found" {
                    if failing == Rule {
                        findings.push("rule_missing");
                    }
                    if matches!(failing, List | Count) {
                        findings.push("exception_list_missing");
                    }
                }
                if failing != Cases {
                    findings.push("has_related_case");
                }
                assert_eq!(data["findings"], json!(findings));
                let expected = match failing {
                    Rule => vec![Alert, Rule, Cases, Case, Case],
                    List => vec![Alert, Rule, List, List, Count, Cases, Case, Case, Activity],
                    Cases => vec![Alert, Rule, List, Count, List, Count, Cases, Activity],
                    _ => vec![
                        Alert, Rule, List, Count, List, Count, Cases, Case, Case, Activity,
                    ],
                };
                assert_eq!(s.steps(), expected);
                h.close_input();
                h.join().await.unwrap();
            }
        }
    }
}
