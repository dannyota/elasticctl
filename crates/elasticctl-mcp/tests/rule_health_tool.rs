#[allow(dead_code)]
mod support;

use elasticctl_core::{Profile, Resolved, Source};
use serde_json::{Value, json};
use std::time::Duration;
use support::{Harness, current_metadata, options};
use tokio::time::{sleep, timeout};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

const SET: &str = "serverless-9.7.0";
const RULES: &str = "/api/detection_engine/rules";
const FIND: &str = "/api/detection_engine/rules/_find";
const SIGNALS: &str = "/api/detection_engine/signals/search";
const LISTS: &str = "/api/exception_lists";
const ITEMS: &str = "/api/exception_lists/items/_find";
const STATUS: &str = "/api/status";
const PROBE: &str = "elasticctl-sample-alert-probe";
const SENTINEL: &str = "elasticctl-sentinel-credential";
const DESCRIPTION: &str = "Health of one Elastic Security rule: its definition, last execution status and message, alert counts by workflow status with the five newest alerts in a time window, and its exception lists with item counts. Read-only.";
const ALERT_SOURCE_FIELDS: [&str; 8] = [
    "@timestamp",
    "kibana.alert.rule.rule_id",
    "kibana.alert.rule.name",
    "kibana.alert.severity",
    "kibana.alert.risk_score",
    "kibana.alert.workflow_status",
    "kibana.alert.reason",
    "kibana.alert.workflow_tags",
];

fn recorded_file(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(SET)
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn recorded(name: &str) -> Value {
    recorded_file(name)["response"].clone()
}

fn activity() -> Value {
    recorded("signals_search_rule_activity.json")
}

fn list_id(i: usize) -> String {
    let base = recorded("rule_get_executed.json")["exceptions_list"][0]["list_id"]
        .as_str()
        .unwrap()
        .to_owned();
    if i == 0 { base } else { format!("{base}-{i}") }
}

fn rule_with_lists(count: usize) -> Value {
    let mut rule = recorded("rule_get_executed.json");
    let template = rule["exceptions_list"][0].clone();
    rule["exceptions_list"] = (0..count)
        .map(|i| {
            let mut r = template.clone();
            r["list_id"] = json!(list_id(i));
            r
        })
        .collect();
    rule
}

fn quiet_activity() -> Value {
    let mut body = activity();
    body["hits"]["total"]["value"] = json!(0);
    body["hits"]["hits"] = json!([]);
    body["aggregations"]["status"]["buckets"] = json!([]);
    body
}

fn sentinel_error() -> Value {
    let mut body = recorded_file("case_conflict.json")["error"].clone();
    body["message"] = json!(SENTINEL);
    body
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

async fn stack(rule: Value, activity: Value) -> MockServer {
    let s = MockServer::start().await;
    for (verb, route, body) in [
        ("GET", STATUS, recorded("status.json")),
        ("POST", SIGNALS, activity),
        ("GET", LISTS, recorded("exception_list_get.json")),
        ("GET", ITEMS, recorded("exception_items_count.json")),
        ("GET", FIND, recorded("rules_find_sorted_page.json")),
    ] {
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&s)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(RULES))
        .and(query_param("rule_id", rule["rule_id"].as_str().unwrap()))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule))
        .mount(&s)
        .await;
    s
}

async fn override_route(
    s: &MockServer,
    verb: &str,
    route: &str,
    list: Option<&str>,
    response: ResponseTemplate,
) {
    let mock = Mock::given(method(verb)).and(path(route));
    let mock = match list {
        Some(id) => mock.and(query_param("list_id", id)),
        None => mock,
    };
    mock.respond_with(response).with_priority(1).mount(s).await;
}

async fn log(s: &MockServer) -> Vec<String> {
    s.received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() != STATUS)
        .map(|r| {
            let q = |k: &str| {
                r.url
                    .query_pairs()
                    .find(|(key, _)| key == k)
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default()
            };
            match r.url.path() {
                RULES => format!("rule {}", q("rule_id")),
                FIND => "find".into(),
                SIGNALS => "signals".into(),
                LISTS => format!("list {}", q("list_id")),
                ITEMS => format!("count {}", q("list_id")),
                other => format!("{} {other}", r.method),
            }
        })
        .collect()
}

async fn send_call(h: &mut Harness, id: u64, arguments: Value) {
    h.send_json(json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"_meta": current_metadata(), "name": "rule_health", "arguments": arguments},
    }))
    .await;
}

async fn call(h: &mut Harness, id: u64, arguments: Value) -> Value {
    send_call(h, id, arguments).await;
    let reply = h.receive_json().await;
    assert_eq!(reply["id"], id);
    assert_text_copy(&reply);
    reply
}

async fn definition(h: &mut Harness) -> Value {
    h.send_json(json!({"jsonrpc":"2.0","id":900,"method":"tools/list","params":{"_meta":current_metadata()}}))
        .await;
    let reply = h.receive_json().await;
    reply["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "rule_health")
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

#[tokio::test]
async fn definition_has_the_exact_description_and_closed_inputs() {
    let mut h = Harness::start(support::target(), options());
    let tool = definition(&mut h).await;
    assert_eq!(tool["description"], DESCRIPTION);
    let input = &tool["inputSchema"];
    let mut names = input["properties"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["selector", "since"]);
    assert_eq!(input["required"], json!(["selector"]));
    assert_eq!(input["additionalProperties"], false);
    assert_eq!(input["properties"]["since"]["default"], "24h");
    assert_eq!(
        tool["annotations"],
        json!({"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true})
    );
    assert_eq!(tool["outputSchema"]["type"], "object");
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn invalid_arguments_send_no_request() {
    let s = stack(rule_with_lists(1), activity()).await;
    let mut h = Harness::start(target_for(&s), options());
    let schema = definition(&mut h).await["outputSchema"].clone();
    let long = "x".repeat(1_025);
    let cases = [
        json!({}),
        json!({"selector": ""}),
        json!({"selector": " \t\n"}),
        json!({"selector": long}),
        json!({"selector": 7}),
        json!({"selector": null}),
        json!({"selector": PROBE, "unexpected": true}),
        json!({"selector": PROBE, "since": 24}),
        json!({"selector": PROBE, "since": "0h"}),
        json!({"selector": PROBE, "since": "24"}),
        json!({"selector": PROBE, "since": "h"}),
        json!({"selector": PROBE, "since": "10000d"}),
        json!({"selector": PROBE, "since": "now-1d"}),
        json!({"selector": PROBE, "since": "1H"}),
        json!({"selector": PROBE, "since": "24h "}),
    ];
    for (i, arguments) in cases.into_iter().enumerate() {
        let reply = call(&mut h, i as u64 + 1, arguments.clone()).await;
        assert_eq!(reply["result"]["isError"], true, "{arguments}");
        assert_eq!(
            structured(&reply)["error"]["code"],
            "invalid_argument",
            "{arguments}"
        );
        assert_schema(&schema, structured(&reply));
    }
    assert!(s.received_requests().await.unwrap().is_empty());
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn success_matches_the_schema_and_projects_every_part() {
    let s = stack(rule_with_lists(1), activity()).await;
    let mut h = Harness::start(target_for(&s), options());
    let schema = definition(&mut h).await["outputSchema"].clone();
    let reply = call(&mut h, 1, json!({"selector": PROBE})).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    let content = structured(&reply);
    assert_schema(&schema, content);
    assert_eq!(content["page"], Value::Null);
    let data = &content["data"];
    assert_eq!(data["rule"]["rule_id"], PROBE);
    let recorded_execution =
        &recorded("rule_get_executed.json")["execution_summary"]["last_execution"];
    let execution = &data["rule"]["execution"];
    assert_eq!(execution["status"], "succeeded");
    assert_eq!(execution["message"], recorded_execution["message"]);
    assert_eq!(execution["message_truncated"], false);
    let mut metrics = execution["metrics"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    metrics.sort();
    assert_eq!(
        metrics,
        ["total_indexing_duration_ms", "total_search_duration_ms"]
    );
    let alerts = &data["alerts"];
    assert_eq!(alerts["status"], "ok");
    assert_eq!(alerts["value"]["window"], "24h");
    assert_eq!(
        alerts["value"]["total"],
        activity()["hits"]["total"]["value"]
    );
    assert_eq!(
        alerts["value"]["by_status"],
        json!({"open": 5, "acknowledged": 0, "closed": 11, "other": 0})
    );
    assert_eq!(alerts["value"]["recent"].as_array().unwrap().len(), 5);
    let list = recorded("exception_list_get.json");
    assert_eq!(
        data["exceptions"],
        json!({"status": "ok", "value": {"referenced": 1, "truncated": false, "lists": [{
            "list_id": list_id(0), "namespace_type": "single", "type": "detection", "status": "ok",
            "name": list["name"], "list_type": list["type"],
            "item_count": recorded("exception_items_count.json")["total"],
        }]}})
    );
    assert_eq!(data["partial"], false);
    assert_eq!(data["findings"], json!([]));
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn partial_and_failure_results_match_the_schema() {
    let s = stack(rule_with_lists(1), activity()).await;
    override_route(
        &s,
        "POST",
        SIGNALS,
        None,
        ResponseTemplate::new(403).set_body_json(sentinel_error()),
    )
    .await;
    let mut h = Harness::start(target_for(&s), options());
    let schema = definition(&mut h).await["outputSchema"].clone();
    let reply = call(&mut h, 1, json!({"selector": PROBE})).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_schema(&schema, structured(&reply));
    let data = &structured(&reply)["data"];
    assert_eq!(data["alerts"]["status"], "unavailable");
    assert_eq!(data["alerts"]["error"]["code"], "elastic_permission");
    assert!(data["alerts"].get("value").is_none());
    assert_eq!(data["exceptions"]["status"], "ok");
    assert_eq!(data["partial"], true);
    assert!(!reply.to_string().contains(SENTINEL));
    h.close_input();
    h.join().await.unwrap();

    let s = stack(rule_with_lists(1), activity()).await;
    override_route(
        &s,
        "POST",
        SIGNALS,
        None,
        ResponseTemplate::new(401).set_body_json(sentinel_error()),
    )
    .await;
    let mut h = Harness::start(target_for(&s), options());
    let reply = call(&mut h, 2, json!({"selector": PROBE})).await;
    assert_eq!(reply["result"]["isError"], true);
    assert_schema(&schema, structured(&reply));
    assert_eq!(structured(&reply)["error"]["code"], "elastic_auth");
    assert!(structured(&reply).get("data").is_none());
    assert!(!reply.to_string().contains(SENTINEL));
    assert_eq!(log(&s).await, [format!("rule {PROBE}"), "signals".into()]);

    let reply = call(&mut h, 3, json!({"selector": "elasticctl-absent-rule"})).await;
    assert_eq!(reply["result"]["isError"], true);
    assert_schema(&schema, structured(&reply));
    assert_eq!(structured(&reply)["error"]["code"], "elastic_not_found");
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn never_run_rule_has_a_null_execution() {
    let never = recorded("rules_get.json");
    let selector = never["rule_id"].as_str().unwrap().to_owned();
    for enabled in [false, true] {
        let mut rule = never.clone();
        rule["enabled"] = json!(enabled);
        let s = stack(rule, activity()).await;
        let mut h = Harness::start(target_for(&s), options());
        let schema = definition(&mut h).await["outputSchema"].clone();
        let reply = call(&mut h, 1, json!({"selector": selector})).await;
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        assert_schema(&schema, structured(&reply));
        let data = &structured(&reply)["data"];
        let rule = data["rule"].as_object().unwrap();
        assert!(rule.contains_key("execution"));
        assert!(rule["execution"].is_null());
        let expected = if enabled {
            "never_executed"
        } else {
            "rule_disabled"
        };
        assert_eq!(data["findings"], json!([expected]));
        h.close_input();
        h.join().await.unwrap();
    }
}

#[tokio::test]
async fn recent_alerts_use_the_alerts_get_projection_and_stop_at_five() {
    let mut body = activity();
    let hits = body["hits"]["hits"].as_array().unwrap().clone();
    let mut more = hits.clone();
    for hit in hits.iter().take(2) {
        let mut extra = hit.clone();
        extra["_id"] = json!(format!("{}-extra", extra["_id"].as_str().unwrap()));
        more.push(extra);
    }
    body["hits"]["hits"] = json!(more);
    let s = stack(rule_with_lists(0), body).await;
    let mut h = Harness::start(target_for(&s), options());
    let reply = call(&mut h, 1, json!({"selector": PROBE})).await;
    let recent = structured(&reply)["data"]["alerts"]["value"]["recent"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(recent.len(), 5);
    for row in &recent {
        let row = row.as_object().unwrap();
        assert!(
            row.keys()
                .all(|k| ["id", "index", "source"].contains(&k.as_str()))
        );
        assert!(
            row["source"]
                .as_object()
                .unwrap()
                .keys()
                .all(|k| ALERT_SOURCE_FIELDS.contains(&k.as_str()))
        );
    }
    assert!(!reply.to_string().contains("kibana.alert.rule.parameters"));
    s.reset().await;
    Mock::given(method("POST"))
        .and(path(SIGNALS))
        .respond_with(ResponseTemplate::new(200).set_body_json(activity()))
        .mount(&s)
        .await;
    h.send_json(json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"_meta": current_metadata(), "name": "alerts_get", "arguments": {"alert_id": hits[0]["_id"]}},
    }))
    .await;
    let alert = h.receive_json().await;
    assert_eq!(structured(&alert)["data"], recent[0]);
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn long_execution_message_is_cut_and_flagged() {
    let message = "界".repeat(1_000);
    assert_eq!(message.len(), 3_000);
    let mut rule = rule_with_lists(0);
    rule["execution_summary"]["last_execution"]["message"] = json!(message);
    let s = stack(rule, activity()).await;
    let mut h = Harness::start(target_for(&s), options());
    let reply = call(&mut h, 1, json!({"selector": PROBE})).await;
    let execution = &structured(&reply)["data"]["rule"]["execution"];
    let cut = execution["message"].as_str().unwrap();
    assert!(cut.len() <= 2_048 && cut.len() > 2_040);
    assert!(message.starts_with(cut));
    assert_eq!(execution["message_truncated"], true);
    assert!(!reply.to_string().contains(&message));
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn findings_use_static_codes_in_the_fixed_order() {
    let mut all = rule_with_lists(1);
    all["enabled"] = json!(false);
    all["execution_summary"]["last_execution"]["status"] = json!("partial failure");
    all["execution_summary"]["last_execution"]["metrics"]["execution_gap_duration_s"] = json!(4);
    let mut failed = rule_with_lists(1);
    failed["execution_summary"]["last_execution"]["status"] = json!("failed");
    let mut unknown = rule_with_lists(1);
    unknown["execution_summary"]["last_execution"]["status"] = json!("elasticctl-unknown-status");
    let cases = [
        (
            all,
            quiet_activity(),
            true,
            json!([
                "rule_disabled",
                "last_execution_partial_failure",
                "execution_gap",
                "no_alerts_in_window",
                "exception_list_missing"
            ]),
        ),
        (failed, activity(), false, json!(["last_execution_failed"])),
        (unknown, activity(), false, json!([])),
    ];
    for (rule, body, missing, expected) in cases {
        let s = stack(rule, body).await;
        if missing {
            override_route(
                &s,
                "GET",
                LISTS,
                None,
                ResponseTemplate::new(404).set_body_json(sentinel_error()),
            )
            .await;
        }
        let mut h = Harness::start(target_for(&s), options());
        let reply = call(&mut h, 1, json!({"selector": PROBE})).await;
        assert_eq!(structured(&reply)["data"]["findings"], expected);
        assert!(!reply.to_string().contains(SENTINEL));
        h.close_input();
        h.join().await.unwrap();
    }
}

#[derive(Clone, Copy, Debug)]
enum Stage {
    Signals,
    SecondList,
}

impl Stage {
    fn label(self) -> String {
        match self {
            Stage::Signals => "signals".into(),
            Stage::SecondList => format!("list {}", list_id(1)),
        }
    }

    fn plan(self) -> Vec<String> {
        let mut out = vec![format!("rule {PROBE}"), "signals".into()];
        if let Stage::SecondList = self {
            out.extend([
                format!("list {}", list_id(0)),
                format!("count {}", list_id(0)),
                format!("list {}", list_id(1)),
            ]);
        }
        out
    }

    async fn delay(self, s: &MockServer, delay: Duration) {
        match self {
            Stage::Signals => {
                override_route(
                    s,
                    "POST",
                    SIGNALS,
                    None,
                    ResponseTemplate::new(200)
                        .set_body_json(activity())
                        .set_delay(delay),
                )
                .await
            }
            Stage::SecondList => {
                override_route(
                    s,
                    "GET",
                    LISTS,
                    Some(&list_id(1)),
                    ResponseTemplate::new(200)
                        .set_body_json(recorded("exception_list_get.json"))
                        .set_delay(delay),
                )
                .await
            }
        }
    }
}

async fn wait_for_stage(s: &MockServer, stage: Stage, count: usize) {
    for _ in 0..300 {
        if log(s).await.iter().filter(|l| **l == stage.label()).count() >= count {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("did not observe {count} {stage:?} requests");
}

async fn interrupt(stage: Stage, deadline: bool) {
    let s = stack(rule_with_lists(2), activity()).await;
    let delay = Duration::from_secs(if deadline { 2 } else { 1 });
    stage.delay(&s, delay).await;
    let mut opts = options();
    if deadline {
        opts.call_timeout = Duration::from_secs(1);
    }
    let mut h = Harness::start(target_for(&s), opts);
    let arguments = json!({"selector": PROBE});
    send_call(&mut h, 1, arguments.clone()).await;
    wait_for_stage(&s, stage, 1).await;
    if deadline {
        let reply = timeout(Duration::from_secs(3), h.receive_json())
            .await
            .expect("deadline failure arrives");
        assert_eq!(reply["id"], 1);
        assert_text_copy(&reply);
        assert_eq!(structured(&reply)["error"]["code"], "deadline_exceeded");
        assert!(structured(&reply).get("data").is_none());
        sleep(delay).await;
    } else {
        h.send_json(json!({
            "jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": 1, "reason": "test", "_meta": current_metadata()},
        }))
        .await;
        assert!(
            timeout(delay + Duration::from_millis(500), h.receive_json())
                .await
                .is_err(),
            "cancelled call emitted a response"
        );
    }
    assert_eq!(log(&s).await, stage.plan(), "{stage:?} later request");
    for id in 2..=5 {
        send_call(&mut h, id, arguments.clone()).await;
    }
    wait_for_stage(&s, stage, 5).await;
    for _ in 0..4 {
        let reply = timeout(Duration::from_secs(5), h.receive_json())
            .await
            .expect("held call replies");
        assert!((2..=5).contains(&reply["id"].as_u64().unwrap()), "{reply}");
        let code = &structured(&reply)["error"]["code"];
        assert_ne!(code, "busy");
        if deadline {
            assert_eq!(code, "deadline_exceeded");
        } else {
            assert_eq!(reply["result"]["isError"], false, "{reply}");
        }
    }
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn cancellation_during_the_activity_read_frees_the_permit() {
    interrupt(Stage::Signals, false).await;
}

#[tokio::test]
async fn cancellation_during_the_second_list_read_frees_the_permit() {
    interrupt(Stage::SecondList, false).await;
}

#[tokio::test]
async fn deadline_during_the_activity_read_frees_the_permit() {
    interrupt(Stage::Signals, true).await;
}

#[tokio::test]
async fn deadline_during_the_second_list_read_frees_the_permit() {
    interrupt(Stage::SecondList, true).await;
}

#[tokio::test]
async fn alert_projection_failure_preserves_rule_and_exceptions() {
    for total in [16, 0] {
        let mut body = activity();
        body["hits"]["hits"][0]["_source"]["kibana.alert.severity"] = json!(7);
        body["hits"]["total"]["value"] = json!(total);
        let mut rule = rule_with_lists(1);
        rule["enabled"] = json!(false);
        let s = stack(rule, body).await;
        let mut h = Harness::start(target_for(&s), options());
        let schema = definition(&mut h).await["outputSchema"].clone();
        let reply = call(&mut h, 1, json!({"selector": PROBE})).await;
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        assert_schema(&schema, structured(&reply));
        let data = &structured(&reply)["data"];
        assert_eq!(data["alerts"]["status"], "unavailable");
        assert_eq!(data["alerts"]["error"]["kind"], "http");
        assert_eq!(data["alerts"]["error"]["code"], "elastic_http");
        assert!(data["alerts"].get("value").is_none());
        assert_eq!(data["rule"]["rule_id"], PROBE);
        assert_eq!(data["rule"]["enabled"], false);
        assert_eq!(data["exceptions"]["status"], "ok");
        assert_eq!(
            data["exceptions"]["value"]["lists"][0]["item_count"],
            recorded("exception_items_count.json")["total"]
        );
        assert_eq!(data["partial"], true);
        assert_eq!(data["findings"], json!(["rule_disabled"]));
        assert_eq!(
            log(&s).await,
            [
                format!("rule {PROBE}"),
                "signals".into(),
                format!("list {}", list_id(0)),
                format!("count {}", list_id(0))
            ]
        );
        h.close_input();
        h.join().await.unwrap();
    }
}

#[tokio::test]
async fn successful_alerts_schema_requires_recent() {
    let s = stack(rule_with_lists(0), activity()).await;
    let mut h = Harness::start(target_for(&s), options());
    let schema = definition(&mut h).await["outputSchema"].clone();
    let reply = call(&mut h, 1, json!({"selector": PROBE})).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    let mut content = structured(&reply).clone();
    assert_schema(&schema, &content);
    content["data"]["alerts"]["value"]
        .as_object_mut()
        .unwrap()
        .remove("recent")
        .unwrap();
    assert!(
        !jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&content),
        "schema accepted alerts without recent"
    );
    h.close_input();
    h.join().await.unwrap();
}
