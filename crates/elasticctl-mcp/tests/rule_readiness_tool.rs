#[allow(dead_code)]
mod support;

use elasticctl_core::{Profile, Resolved, Source};
use serde_json::{Value, json};
use std::time::Duration;
use support::{Harness, current_metadata, options};
use tokio::time::{sleep, timeout};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path, query_param},
};

const SET: &str = "serverless-9.7.0";
const RULES: &str = "/api/detection_engine/rules";
const VIEWS: &str = "/api/data_views";
const POLICIES: &str = "/api/fleet/package_policies";
const PACKAGES: &str = "/api/fleet/epm/packages/";
const RESOLVE: &str = "/_resolve/index/";
const STATUS: &str = "/api/status";
const DESCRIPTION: &str = "Data readiness of one Elastic Security rule: whether each index pattern resolves to indices, aliases, or data streams (counts only), whether its data view exists, and whether its related Fleet integration packages are installed and used by an integration policy. Read-only.";
const SELECTOR_DESCRIPTION: &str = "Exact rule_id or display name. Must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.";
const FINDING_ORDER: [&str; 9] = [
    "rule_disabled",
    "no_index_source",
    "data_view_missing",
    "no_pattern_matches",
    "pattern_unresolved",
    "integration_not_installed",
    "integration_without_policy",
    "patterns_truncated",
    "integrations_truncated",
];

fn recording(name: &str) -> Value {
    let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(SET)
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(file).expect("recorded fixture"))
        .expect("fixture JSON")
}

fn response(name: &str) -> Value {
    recording(name)["response"].clone()
}

fn ok_json(body: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
}

fn error_status(status: u16, message: Option<&str>) -> ResponseTemplate {
    let mut error = recording("resolve_index_not_found.json")["error"].clone();
    error["http_status"] = json!(status);
    if let Some(message) = message {
        error["message"] = json!(message);
    }
    ResponseTemplate::new(status).set_body_json(error)
}

fn resolve_match() -> ResponseTemplate {
    ok_json(response("resolve_index_match.json"))
}

fn resolve_none() -> ResponseTemplate {
    ok_json(response("resolve_index_no_match.json"))
}

fn rule(index: Option<&[&str]>, data_view_id: Option<&str>, packages: &[&str]) -> Value {
    let mut rule = response("rule_get_executed.json");
    let template = rule["related_integrations"][0].clone();
    let map = rule.as_object_mut().unwrap();
    map.remove("index");
    map.remove("data_view_id");
    if let Some(index) = index {
        map.insert("index".into(), json!(index));
    }
    if let Some(id) = data_view_id {
        map.insert("data_view_id".into(), json!(id));
    }
    let related = packages
        .iter()
        .map(|package| {
            let mut entry = template.clone();
            entry["package"] = json!(package);
            entry
        })
        .collect::<Vec<_>>();
    map.insert("related_integrations".into(), json!(related));
    rule
}

fn rule_id(rule: &Value) -> String {
    rule["rule_id"].as_str().unwrap().to_owned()
}

fn policies(packages: &[&str]) -> Value {
    let mut body = response("integration_policies_list.json");
    let template = body["items"][0].clone();
    body["items"] = json!(
        packages
            .iter()
            .enumerate()
            .map(|(i, package)| {
                let mut row = template.clone();
                row["id"] = json!(format!("policy-{i}"));
                row["package"]["name"] = json!(package);
                row
            })
            .collect::<Vec<_>>()
    );
    body["total"] = json!(packages.len());
    body["page"] = json!(1);
    body["perPage"] = json!(1000);
    body
}

fn installed(name: &str) -> ResponseTemplate {
    let mut body = response("package_system.json");
    body["item"]["name"] = json!(name);
    ok_json(body)
}

fn not_installed(name: &str) -> ResponseTemplate {
    let mut body = response("package_not_installed.json");
    body["item"]["name"] = json!(name);
    ok_json(body)
}

fn segment<'a>(request: &'a Request, prefix: &str) -> Option<&'a str> {
    request
        .url
        .path()
        .strip_prefix(prefix)
        .filter(|rest| !rest.is_empty() && !rest.contains('/'))
}

fn target(uri: String) -> Resolved {
    Resolved {
        name: "test".to_string(),
        source: Source::Profile,
        profile: Profile {
            kibana_url: uri.clone(),
            es_url: Some(uri),
            api_key: Some("test-api-key".to_string()),
            username: None,
            password: None,
            space: "default".to_string(),
            verify: true,
            timeout_secs: 30,
        },
    }
}

type Answer = Box<dyn Fn(&str) -> ResponseTemplate + Send + Sync>;

async fn stack(body: &Value, patterns: Answer, packages: Answer, listed: &[&str]) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(STATUS))
        .respond_with(ok_json(response("status.json")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(RULES))
        .and(query_param("rule_id", rule_id(body)))
        .respond_with(ok_json(body.clone()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(VIEWS))
        .respond_with(ok_json(response("data_views_list.json")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(|r: &Request| segment(r, RESOLVE).is_some())
        .respond_with(move |r: &Request| patterns(segment(r, RESOLVE).unwrap()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(POLICIES))
        .respond_with(ok_json(policies(listed)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(|r: &Request| segment(r, PACKAGES).is_some())
        .respond_with(move |r: &Request| packages(segment(r, PACKAGES).unwrap()))
        .mount(&server)
        .await;
    server
}

fn call_frame(id: u64, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"_meta": current_metadata(), "name": "rule_readiness", "arguments": arguments},
    })
}

async fn call(harness: &mut Harness, id: u64, arguments: Value) -> Value {
    harness.send_json(call_frame(id, arguments)).await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], id);
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    assert_eq!(
        serde_json::from_str::<Value>(text).expect("text is JSON"),
        reply["result"]["structuredContent"],
        "text equals structured content"
    );
    reply
}

async fn tool_entry(harness: &mut Harness) -> Value {
    harness
        .send_json(json!({"jsonrpc":"2.0","id":900,"method":"tools/list","params":{"_meta":current_metadata()}}))
        .await;
    let reply = harness.receive_json().await;
    reply["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "rule_readiness")
        .expect("rule_readiness is listed")
        .clone()
}

fn assert_schema(schema: &Value, instance: &Value) {
    let validator = jsonschema::validator_for(schema).expect("output schema compiles");
    let errors = validator.iter_errors(instance).collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema rejected {instance}: {errors:?}");
}

async fn paths(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_owned())
        .filter(|p| p != STATUS)
        .collect()
}

fn findings(structured: &Value) -> Vec<String> {
    structured["data"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap().to_owned())
        .collect()
}

fn assert_ordered_once(found: &[String]) {
    let positions = found
        .iter()
        .map(|f| {
            FINDING_ORDER
                .iter()
                .position(|o| o == f)
                .expect("known code")
        })
        .collect::<Vec<_>>();
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{found:?}");
}

#[tokio::test]
async fn catalog_entry_declares_the_description_input_and_annotations() {
    let server = MockServer::start().await;
    let mut harness = Harness::start(target(server.uri()), options());
    let tool = tool_entry(&mut harness).await;
    assert_eq!(tool["description"], DESCRIPTION);
    let input = &tool["inputSchema"];
    assert_eq!(input["type"], "object");
    assert_eq!(input["additionalProperties"], false);
    assert_eq!(input["required"], json!(["selector"]));
    let selector = &input["properties"]["selector"];
    assert_eq!(selector["type"], "string");
    assert_eq!(selector["minLength"], 1);
    assert_eq!(selector["maxLength"], 1024);
    assert_eq!(selector["description"], SELECTOR_DESCRIPTION);
    assert_eq!(
        input["properties"].as_object().unwrap().len(),
        1,
        "selector is the only input"
    );
    assert_eq!(
        tool["annotations"],
        json!({"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true})
    );
    assert_eq!(tool["outputSchema"]["type"], "object");
    assert!(server.received_requests().await.unwrap().is_empty());
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn invalid_arguments_are_refused_with_no_request() {
    let server = MockServer::start().await;
    let mut harness = Harness::start(target(server.uri()), options());
    let schema = tool_entry(&mut harness).await["outputSchema"].clone();
    let long = "r".repeat(1025);
    for (id, arguments) in [
        json!({}),
        json!({"selector": ""}),
        json!({"selector": " "}),
        json!({"selector": "\t\n"}),
        json!({"selector": long}),
        json!({"selector": 7}),
        json!({"selector": null}),
        json!({"selector": ["rule"]}),
        json!({"selector": "rule", "index": "logs-*"}),
        json!({"selector": "rule", "target": "other"}),
    ]
    .into_iter()
    .enumerate()
    {
        let reply = call(&mut harness, id as u64 + 1, arguments.clone()).await;
        let structured = &reply["result"]["structuredContent"];
        assert_eq!(reply["result"]["isError"], true, "{arguments}");
        assert_eq!(
            structured["error"]["code"], "invalid_argument",
            "{arguments}"
        );
        assert_schema(&schema, structured);
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "invalid input made a request"
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn success_partial_and_failure_validate_against_the_output_schema() {
    let body = rule(Some(&["match-*", "none-*"]), None, &["system"]);
    let server = stack(
        &body,
        Box::new(|s: &str| {
            if s == "match-%2A" {
                resolve_match()
            } else {
                resolve_none()
            }
        }),
        Box::new(installed),
        &["system"],
    )
    .await;
    let mut harness = Harness::start(target(server.uri()), options());
    let schema = tool_entry(&mut harness).await["outputSchema"].clone();
    let reply = call(&mut harness, 1, json!({"selector": rule_id(&body)})).await;
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_schema(&schema, structured);
    let data = &structured["data"];
    assert_eq!(structured["page"], Value::Null);
    assert_eq!(
        data["rule"],
        json!({"rule_id": body["rule_id"], "name": body["name"], "type": body["type"], "enabled": true})
    );
    assert_eq!(data["index_source"], "index");
    assert_eq!(
        data["data_views"],
        json!({"status": "ok", "value": {"count": 1}})
    );
    assert_eq!(
        data["patterns"],
        json!({"status": "ok", "value": {"total": 2, "truncated": false, "rows": [
            {"pattern": "match-*", "state": "matches", "indices": 1, "aliases": 0, "data_streams": 0, "data_view_ids": []},
            {"pattern": "none-*", "state": "no_match", "indices": 0, "aliases": 0, "data_streams": 0, "data_view_ids": []},
        ]}})
    );
    assert_eq!(
        data["integrations"],
        json!({"status": "ok", "value": {"total": 1, "truncated": false, "rows": [
            {"package": "system", "version": body["related_integrations"][0]["version"], "status": "ok",
             "install_status": "installed", "installed_version": "3.5.0", "policies": 1},
        ]}})
    );
    assert_eq!(data["partial"], false);
    assert_eq!(data["findings"], json!([]));
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let body = rule(Some(&["denied-*"]), None, &["system", "gone"]);
    let server = stack(
        &body,
        Box::new(|_: &str| error_status(403, None)),
        Box::new(|s: &str| {
            if s == "gone" {
                error_status(404, None)
            } else {
                installed(s)
            }
        }),
        &["system"],
    )
    .await;
    Mock::given(method("GET"))
        .and(path(VIEWS))
        .respond_with(error_status(403, None))
        .with_priority(1)
        .mount(&server)
        .await;
    let mut harness = Harness::start(target(server.uri()), options());
    let reply = call(&mut harness, 2, json!({"selector": rule_id(&body)})).await;
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_schema(&schema, structured);
    let data = &structured["data"];
    assert_eq!(data["partial"], true);
    assert_eq!(data["data_views"]["status"], "unavailable");
    assert_eq!(data["data_views"]["error"]["code"], "elastic_permission");
    assert!(data["data_views"].get("value").is_none());
    let row = &data["patterns"]["value"]["rows"][0];
    assert_eq!(row["state"], "unresolved");
    assert_eq!(row["error"]["code"], "elastic_permission");
    assert_eq!(row["error"]["http_status"], 403);
    for absent in ["indices", "aliases", "data_streams", "data_view_ids"] {
        assert!(row.get(absent).is_none(), "{absent} on an unresolved row");
    }
    let gone = &data["integrations"]["value"]["rows"][1];
    assert_eq!(gone["status"], "unavailable");
    assert_eq!(gone["error"]["code"], "elastic_not_found");
    for absent in ["install_status", "installed_version", "policies"] {
        assert!(gone.get(absent).is_none(), "{absent} on an unavailable row");
    }
    assert_eq!(data["findings"], json!(["pattern_unresolved"]));
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(RULES))
        .respond_with(error_status(404, None))
        .mount(&server)
        .await;
    let mut found = response("rules_find.json");
    found["data"] = json!([]);
    found["total"] = json!(0);
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ok_json(found))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target(server.uri()), options());
    let reply = call(&mut harness, 3, json!({"selector": "absent rule"})).await;
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(reply["result"]["isError"], true);
    assert_schema(&schema, structured);
    assert_eq!(structured["error"]["code"], "elastic_not_found");
    assert!(structured.get("data").is_none());
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn names_from_responses_and_error_bodies_never_reach_the_output() {
    const SENTINEL: &str = "credential-sentinel-7f3a";
    let body = rule(Some(&["logs-*", "denied-*"]), None, &["system"]);
    let server = stack(
        &body,
        Box::new(|s: &str| {
            if s == "denied-%2A" {
                return error_status(403, Some(SENTINEL));
            }
            let mut resolved = response("resolve_index_match.json");
            let template = resolved["indices"][0].clone();
            let named = |suffix: &str| {
                let mut entry = template.clone();
                entry["name"] = json!(format!("{SENTINEL}-{suffix}"));
                entry
            };
            resolved["indices"] = json!([named("index")]);
            resolved["aliases"] = json!([named("alias")]);
            resolved["data_streams"] = json!([named("stream")]);
            ok_json(resolved)
        }),
        Box::new(|s: &str| {
            let mut status = response("package_system.json");
            status["item"]["name"] = json!(s);
            status["item"]["title"] = json!(SENTINEL);
            status["item"]["description"] = json!(SENTINEL);
            ok_json(status)
        }),
        &["system"],
    )
    .await;
    let mut harness = Harness::start(target(server.uri()), options());
    let reply = call(&mut harness, 1, json!({"selector": rule_id(&body)})).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    let rows = &reply["result"]["structuredContent"]["data"]["patterns"]["value"]["rows"];
    assert_eq!(rows[0]["indices"], 1);
    assert_eq!(rows[0]["aliases"], 1);
    assert_eq!(rows[0]["data_streams"], 1);
    let text = reply.to_string();
    assert!(!text.contains(SENTINEL), "a remote name escaped: {text}");
    let recorded_name = response("resolve_index_match.json")["indices"][0]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!text.contains(&recorded_name));
    let execution_message = body["execution_summary"]["last_execution"]["message"]
        .as_str()
        .unwrap();
    assert!(!text.contains(execution_message));
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn findings_appear_once_in_order_and_optional_fields_follow_the_row_state() {
    let names = (0..15).map(|i| format!("p{i}-*")).collect::<Vec<_>>();
    let mut index = vec!["-excluded-*", "-also-excluded-*", "..", "denied-*"];
    index.extend(names.iter().map(String::as_str));
    let packages = [
        "apache", "nginx", "system", "mysql", "redis", "kafka", "zeek", "auditd", "extra",
    ];
    let mut body = rule(Some(&index), None, &packages);
    body["enabled"] = json!(false);
    let server = stack(
        &body,
        Box::new(|s: &str| {
            if s == "denied-%2A" {
                error_status(403, None)
            } else {
                resolve_none()
            }
        }),
        Box::new(|s: &str| {
            if matches!(s, "apache" | "nginx") {
                not_installed(s)
            } else {
                installed(s)
            }
        }),
        &["system", "mysql", "redis", "kafka"],
    )
    .await;
    let mut harness = Harness::start(target(server.uri()), options());
    let schema = tool_entry(&mut harness).await["outputSchema"].clone();
    let reply = call(&mut harness, 1, json!({"selector": rule_id(&body)})).await;
    let structured = &reply["result"]["structuredContent"];
    assert_schema(&schema, structured);
    let found = findings(structured);
    assert_eq!(
        found,
        [
            "rule_disabled",
            "pattern_unresolved",
            "integration_not_installed",
            "integration_without_policy",
            "patterns_truncated",
            "integrations_truncated",
        ]
    );
    assert_ordered_once(&found);
    let data = &structured["data"];
    assert_eq!(data["partial"], true);
    let patterns = &data["patterns"]["value"];
    assert_eq!(
        (patterns["total"].as_u64(), patterns["truncated"].as_bool()),
        (Some(19), Some(true))
    );
    let rows = patterns["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 16);
    for row in &rows[..2] {
        assert_eq!(row["state"], "exclusion");
        for absent in ["indices", "aliases", "data_streams", "error"] {
            assert!(row.get(absent).is_none(), "{absent} on {row}");
        }
        assert_eq!(row["data_view_ids"], json!([]));
    }
    assert_eq!(rows[2]["state"], "unresolved");
    for absent in ["indices", "aliases", "data_streams", "error"] {
        assert!(rows[2].get(absent).is_none(), "{absent} on {}", rows[2]);
    }
    assert_eq!(rows[3]["state"], "unresolved");
    assert_eq!(rows[3]["error"]["code"], "elastic_permission");
    for absent in ["indices", "aliases", "data_streams"] {
        assert!(rows[3].get(absent).is_none(), "{absent} on {}", rows[3]);
    }
    assert!(
        rows[4..]
            .iter()
            .all(|r| r["state"] == "no_match" && r["indices"] == 0)
    );
    let integrations = &data["integrations"]["value"];
    assert_eq!(integrations["total"], 9);
    assert_eq!(integrations["truncated"], true);
    let package_rows = integrations["rows"].as_array().unwrap();
    assert_eq!(package_rows.len(), 8);
    assert_eq!(package_rows[0]["install_status"], "not_installed");
    assert!(package_rows[0].get("installed_version").is_none());
    assert_eq!(package_rows[2]["policies"], 1);
    assert_eq!(package_rows[6]["policies"], 0);
    let requests = paths(&server).await;
    assert_eq!(
        requests.iter().filter(|p| p.starts_with(RESOLVE)).count(),
        13
    );
    assert_eq!(
        requests.iter().filter(|p| p.starts_with(PACKAGES)).count(),
        8
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");

    for (index, data_view_id, expected) in [
        (None, None, vec!["no_index_source"]),
        (None, Some("absent-view"), vec!["data_view_missing"]),
        (
            Some(vec!["q0-*", "q1-*", "-q2-*"]),
            None,
            vec!["no_pattern_matches"],
        ),
    ] {
        let body = rule(index.as_deref(), data_view_id, &[]);
        let server = stack(
            &body,
            Box::new(|_: &str| resolve_none()),
            Box::new(installed),
            &[],
        )
        .await;
        let mut harness = Harness::start(target(server.uri()), options());
        let reply = call(&mut harness, 2, json!({"selector": rule_id(&body)})).await;
        let structured = &reply["result"]["structuredContent"];
        assert_schema(&schema, structured);
        assert_eq!(findings(structured), expected);
        assert_eq!(structured["data"]["partial"], false);
        if data_view_id.is_some() {
            assert_eq!(
                structured["data"]["data_views"]["value"]["rule_data_view"],
                json!({"id": "absent-view", "found": false})
            );
            assert_eq!(
                structured["data"]["patterns"],
                json!({"status": "skipped", "skip_reason": "dependency_unavailable"})
            );
        }
        if index.is_none() && data_view_id.is_none() {
            assert_eq!(structured["data"]["index_source"], "none");
            for part in ["data_views", "patterns"] {
                assert_eq!(
                    structured["data"][part],
                    json!({"status": "skipped", "skip_reason": "not_applicable"})
                );
            }
        }
        harness.close_input();
        harness.join().await.expect("clean EOF");
    }
}

fn router_rule() -> Value {
    let names = (0..8).map(|i| format!("r{i}-*")).collect::<Vec<_>>();
    let index = names.iter().map(String::as_str).collect::<Vec<_>>();
    rule(Some(&index), None, &["system"])
}

async fn router_stack(body: &Value, delay: Duration, held: Duration) -> MockServer {
    let server = stack(
        body,
        Box::new(move |s: &str| {
            if s == "r4-%2A" {
                resolve_none().set_delay(delay)
            } else {
                resolve_none()
            }
        }),
        Box::new(installed),
        &["system"],
    )
    .await;
    Mock::given(method("GET"))
        .and(path(RULES))
        .and(query_param("rule_id", "held"))
        .respond_with(error_status(404, None).set_delay(held))
        .mount(&server)
        .await;
    server
}

async fn wait_for(server: &MockServer, count: usize, filter: impl Fn(&wiremock::Request) -> bool) {
    timeout(Duration::from_secs(5), async {
        loop {
            let seen = server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| filter(r))
                .count();
            if seen >= count {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("expected requests arrive");
}

fn is_pattern(r: &wiremock::Request) -> bool {
    r.url.path().starts_with(RESOLVE)
}

async fn assert_four_permits_free(harness: &mut Harness, server: &MockServer, first_id: u64) {
    for id in first_id..first_id + 3 {
        harness
            .send_json(call_frame(id, json!({"selector": "held"})))
            .await;
    }
    wait_for(server, 3, |r| {
        r.url.path() == RULES && r.url.query().is_some_and(|q| q.contains("rule_id=held"))
    })
    .await;
    harness
        .send_json(call_frame(first_id + 3, json!({"unexpected": true})))
        .await;
    let mut replies = Vec::new();
    for _ in 0..4 {
        replies.push(
            timeout(Duration::from_secs(10), harness.receive_json())
                .await
                .expect("reply"),
        );
    }
    let fourth = replies
        .iter()
        .find(|r| r["id"] == first_id + 3)
        .expect("fourth call reply");
    assert_eq!(
        fourth["result"]["structuredContent"]["error"]["code"], "invalid_argument",
        "the fourth call was admitted"
    );
    for reply in &replies {
        assert_ne!(
            reply["result"]["structuredContent"]["error"]["code"],
            "busy"
        );
    }
}

#[tokio::test]
async fn cancelling_during_the_fifth_pattern_read_sends_nothing_later_and_frees_the_permit() {
    let body = router_rule();
    let server = router_stack(&body, Duration::from_secs(5), Duration::from_millis(500)).await;
    let mut harness = Harness::start(target(server.uri()), options());
    harness
        .send_json(call_frame(1, json!({"selector": rule_id(&body)})))
        .await;
    wait_for(&server, 5, is_pattern).await;
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 1, "reason": "test", "_meta": current_metadata()},
        }))
        .await;
    assert!(
        timeout(Duration::from_millis(600), harness.receive_json())
            .await
            .is_err(),
        "a cancelled call emitted a result"
    );
    let seen = paths(&server).await;
    assert_eq!(seen.iter().filter(|p| p.starts_with(RESOLVE)).count(), 5);
    assert_eq!(seen.last().unwrap(), &format!("{RESOLVE}r4-%2A"));
    assert!(
        !seen
            .iter()
            .any(|p| p == POLICIES || p.starts_with(PACKAGES))
    );
    assert_four_permits_free(&mut harness, &server, 10).await;
    let seen = paths(&server).await;
    assert_eq!(seen.iter().filter(|p| p.starts_with(RESOLVE)).count(), 5);
    assert!(
        !seen
            .iter()
            .any(|p| p == POLICIES || p.starts_with(PACKAGES))
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn a_deadline_during_the_fifth_pattern_read_returns_no_data_and_frees_the_permit() {
    let body = router_rule();
    let server = router_stack(&body, Duration::from_secs(3), Duration::from_secs(3)).await;
    let mut opts = options();
    opts.call_timeout = Duration::from_secs(1);
    let mut harness = Harness::start(target(server.uri()), opts);
    let schema = tool_entry(&mut harness).await["outputSchema"].clone();
    let reply = call(&mut harness, 1, json!({"selector": rule_id(&body)})).await;
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(structured["error"]["code"], "deadline_exceeded");
    assert!(structured.get("data").is_none());
    assert_schema(&schema, structured);
    sleep(Duration::from_millis(300)).await;
    let seen = paths(&server).await;
    assert_eq!(seen.iter().filter(|p| p.starts_with(RESOLVE)).count(), 5);
    assert!(
        !seen
            .iter()
            .any(|p| p == POLICIES || p.starts_with(PACKAGES))
    );
    assert_four_permits_free(&mut harness, &server, 10).await;
    let seen = paths(&server).await;
    assert_eq!(seen.iter().filter(|p| p.starts_with(RESOLVE)).count(), 5);
    assert!(
        !seen
            .iter()
            .any(|p| p == POLICIES || p.starts_with(PACKAGES))
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

const HELD_PACKAGE_READ: Duration = Duration::from_secs(8);
const PROMPT_REPLY: Duration = Duration::from_secs(4);

async fn large_package_stack() -> (MockServer, String) {
    let names = (0..100_000)
        .map(|i| format!("package_{i:06}"))
        .collect::<Vec<_>>();
    let packages = names.iter().map(String::as_str).collect::<Vec<_>>();
    let body = rule(None, None, &packages);
    assert!(serde_json::to_vec(&body).unwrap().len() < 16_777_216);
    let server = router_stack(&body, Duration::ZERO, HELD_PACKAGE_READ).await;
    Mock::given(path(POLICIES))
        .respond_with(ok_json(policies(&[])).set_delay(HELD_PACKAGE_READ))
        .with_priority(1)
        .mount(&server)
        .await;
    (server, rule_id(&body))
}

#[tokio::test]
async fn large_package_scan_cancellation_frees_the_permit_promptly() {
    let (server, selector) = large_package_stack().await;
    let mut harness = Harness::start(target(server.uri()), options());
    let started = std::time::Instant::now();
    harness
        .send_json(call_frame(1, json!({"selector": selector})))
        .await;
    wait_for(&server, 1, |r| r.url.path() == RULES).await;
    sleep(Duration::from_millis(100)).await;
    harness
        .send_json(json!({
            "jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": 1, "_meta": current_metadata()},
        }))
        .await;
    assert!(
        timeout(Duration::from_millis(100), harness.receive_json())
            .await
            .is_err()
    );
    assert!(
        started.elapsed() < PROMPT_REPLY,
        "package scan blocked cancellation"
    );
    assert_four_permits_free(&mut harness, &server, 10).await;
    assert!(!paths(&server).await.iter().any(|p| p.starts_with(PACKAGES)));
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn large_package_scan_deadline_frees_the_permit_promptly() {
    let (server, selector) = large_package_stack().await;
    let mut opts = options();
    opts.call_timeout = Duration::from_secs(1);
    let mut harness = Harness::start(target(server.uri()), opts);
    let started = std::time::Instant::now();
    let reply = call(&mut harness, 1, json!({"selector": selector})).await;
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(structured["error"]["code"], "deadline_exceeded");
    assert!(structured.get("data").is_none());
    assert!(
        started.elapsed() < PROMPT_REPLY,
        "package scan blocked deadline"
    );
    assert_four_permits_free(&mut harness, &server, 10).await;
    assert!(!paths(&server).await.iter().any(|p| p.starts_with(PACKAGES)));
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

async fn fatal_stack(
    failed_path: &'static str,
    kind: &'static str,
) -> (
    String,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    tokio::task::JoinHandle<()>,
    String,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("http://{}", listener.local_addr().unwrap());
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let requests = seen.clone();
    let body = rule(Some(&["a-*", "b-*"]), None, &["system", "nginx"]);
    let selector = rule_id(&body);
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let requests = requests.clone();
            let body = body.clone();
            tokio::spawn(async move {
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    if socket.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    header.push(byte[0]);
                }
                let header = String::from_utf8(header).unwrap();
                let route = header
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .split('?')
                    .next()
                    .unwrap();
                assert!(header.starts_with("GET "));
                requests.lock().unwrap().push(route.to_owned());
                if route == failed_path {
                    match kind {
                        "connection" => return,
                        "timeout" => {
                            sleep(Duration::from_secs(2)).await;
                            return;
                        }
                        _ => {}
                    }
                }
                let failed = route == failed_path;
                let value = if failed {
                    recording("resolve_index_not_found.json")["error"].clone()
                } else {
                    match route {
                        RULES => body,
                        STATUS => response("status.json"),
                        VIEWS => response("data_views_list.json"),
                        POLICIES => policies(&["system"]),
                        r if r.starts_with(RESOLVE) => response("resolve_index_no_match.json"),
                        r if r.starts_with(PACKAGES) => response("package_system.json"),
                        _ => panic!("unexpected route {route}"),
                    }
                };
                let bytes = serde_json::to_vec(&value).unwrap();
                let status = if failed { "401 Unauthorized" } else { "200 OK" };
                let header = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                let _ = socket.write_all(header.as_bytes()).await;
                let _ = socket.write_all(&bytes).await;
            });
        }
    });
    (uri, seen, task, selector)
}

#[tokio::test]
async fn fatal_kinds_at_every_part_return_no_data_or_later_requests() {
    let plan = [
        RULES,
        VIEWS,
        "/_resolve/index/a-%2A",
        "/_resolve/index/b-%2A",
        POLICIES,
        "/api/fleet/epm/packages/system",
        "/api/fleet/epm/packages/nginx",
    ];
    for failed in [
        VIEWS,
        "/_resolve/index/a-%2A",
        POLICIES,
        "/api/fleet/epm/packages/system",
    ] {
        for (kind, code) in [
            ("auth", "elastic_auth"),
            ("connection", "elastic_connection"),
            ("timeout", "elastic_timeout"),
        ] {
            let (uri, seen, task, selector) = fatal_stack(failed, kind).await;
            let mut resolved = target(uri);
            resolved.profile.timeout_secs = 1;
            let mut harness = Harness::start(resolved, options());
            let reply = call(&mut harness, 1, json!({"selector": selector})).await;
            let structured = &reply["result"]["structuredContent"];
            assert_eq!(
                reply["result"]["isError"], true,
                "{kind} at {failed}: {reply}"
            );
            assert_eq!(structured["error"]["kind"], kind, "{failed}: {reply}");
            assert_eq!(structured["error"]["code"], code, "{failed}: {reply}");
            assert!(structured.get("data").is_none());
            harness.close_input();
            harness.join().await.expect("clean EOF");
            let paths = seen
                .lock()
                .unwrap()
                .iter()
                .filter(|p| *p != STATUS)
                .cloned()
                .collect::<Vec<_>>();
            let end = plan.iter().position(|p| *p == failed).unwrap();
            assert_eq!(paths, plan[..=end], "{kind} at {failed}");
            task.abort();
        }
    }
}
