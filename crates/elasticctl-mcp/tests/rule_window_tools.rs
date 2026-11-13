#[allow(dead_code)]
mod support;

use elasticctl_api_test_support::MockStack;
use elasticctl_core::{Profile, Resolved, Source};
use serde_json::{Value, json};
use support::{Harness, current_metadata, options};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const FIND: &str = "/api/detection_engine/rules/_find";
const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/serverless-9.7.0/rules_find.json"
));
const TECHNIQUE_DESCRIPTION: &str = "MITRE ATT&CK technique or subtechnique id. When supplied, it must be T followed by four ASCII digits, such as T1059, or T, four ASCII digits, a period, and three ASCII digits, such as T1059.001.";
const TACTIC_DESCRIPTION: &str = "MITRE ATT&CK tactic id. When supplied, it must be TA followed by four ASCII digits, such as TA0002.";

fn target_for(uri: String) -> Resolved {
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

async fn call(harness: &mut Harness, id: u64, arguments: Value) -> Value {
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "_meta": current_metadata(),
                "name": "rules_list",
                "arguments": arguments,
            },
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], id);
    reply
}

async fn recorded_find_server() -> MockServer {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("rules_find fixture is JSON");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(FIND))
        .respond_with(ResponseTemplate::new(200).set_body_json(&fixture["response"]))
        .mount(&server)
        .await;
    server
}

fn resolve_local_ref<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    let mut resolved = schema;
    while let Some(reference) = resolved.get("$ref").and_then(Value::as_str) {
        resolved = root
            .pointer(reference.strip_prefix('#').expect("local schema reference"))
            .expect("reference resolves");
    }
    resolved
}

fn allows_type(root: &Value, schema: &Value, expected: &str) -> bool {
    let schema = resolve_local_ref(root, schema);
    match &schema["type"] {
        Value::String(value) if value == expected => true,
        Value::Array(values) if values.iter().any(|value| value == expected) => true,
        _ => schema["anyOf"].as_array().is_some_and(|branches| {
            branches
                .iter()
                .any(|branch| allows_type(root, branch, expected))
        }),
    }
}

fn string_branch<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    let schema = resolve_local_ref(root, schema);
    let direct = match &schema["type"] {
        Value::String(value) => value == "string",
        Value::Array(values) => values.iter().any(|value| value == "string"),
        _ => false,
    };
    if direct {
        return schema;
    }
    schema["anyOf"]
        .as_array()
        .expect("schema alternatives")
        .iter()
        .find(|branch| allows_type(root, branch, "string"))
        .map(|branch| string_branch(root, branch))
        .expect("string branch")
}

#[tokio::test]
async fn rules_list_declares_optional_threat_inputs_with_their_grammar() {
    let server = MockServer::start().await;
    let mut harness = Harness::start(target_for(server.uri()), options());
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": current_metadata()},
        }))
        .await;
    let reply = harness.receive_json().await;
    let tool = reply["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .find(|tool| tool["name"] == "rules_list")
        .expect("rules_list")
        .clone();
    let input = &tool["inputSchema"];
    for (field, description) in [
        ("technique", TECHNIQUE_DESCRIPTION),
        ("tactic", TACTIC_DESCRIPTION),
    ] {
        let property = &input["properties"][field];
        let string = string_branch(input, property);
        assert_eq!(string["description"], description, "{field}");
        assert_eq!(string["minLength"], 1, "{field}");
        assert_eq!(string["maxLength"], 1024, "{field}");
        assert!(allows_type(input, property, "null"), "{field} is optional");
        assert!(
            !input["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|name| name == field)),
            "{field} is not required"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn threat_inputs_become_kql_clauses_on_the_single_name_ordered_page() {
    let cases = [
        (
            json!({"technique": "T1059"}),
            "alert.attributes.params.threat.technique.id: \"T1059\"",
        ),
        (
            json!({"technique": "T1059.001"}),
            "alert.attributes.params.threat.technique.subtechnique.id: \"T1059.001\"",
        ),
        (
            json!({"tactic": "TA0002"}),
            "alert.attributes.params.threat.tactic.id: \"TA0002\"",
        ),
        (
            json!({"tag": "fixture", "technique": "T1059.001", "tactic": "TA0002", "limit": 7}),
            "alert.attributes.tags: \"fixture\" AND \
             alert.attributes.params.threat.technique.subtechnique.id: \"T1059.001\" AND \
             alert.attributes.params.threat.tactic.id: \"TA0002\"",
        ),
    ];
    for (id, (arguments, expected_filter)) in cases.into_iter().enumerate() {
        let server = recorded_find_server().await;
        let mut harness = Harness::start(target_for(server.uri()), options());
        let limit = arguments["limit"].as_u64().unwrap_or(50).to_string();
        let reply = call(&mut harness, id as u64 + 1, arguments).await;
        let structured = &reply["result"]["structuredContent"];
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        assert_eq!(
            structured["data"]["rules"][0]["rule_id"],
            "elasticctl-fixture-probe"
        );
        assert_eq!(structured["page"]["total"], 1);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "one page request");
        assert_eq!(requests[0].method.as_str(), "GET");
        assert_eq!(requests[0].url.path(), FIND);
        let query: std::collections::BTreeMap<String, String> =
            requests[0].url.query_pairs().into_owned().collect();
        assert_eq!(query["page"], "1");
        assert_eq!(query["per_page"], limit);
        assert_eq!(query["sort_field"], "name");
        assert_eq!(query["sort_order"], "asc");
        assert_eq!(query["filter"], expected_filter);
        harness.close_input();
        harness.join().await.expect("clean EOF");
    }
}

#[tokio::test]
async fn threat_inputs_outside_their_grammar_are_invalid_without_requests() {
    let server = recorded_find_server().await;
    let mut harness = Harness::start(target_for(server.uri()), options());
    let long = format!("T{}", "1".repeat(1024));
    assert_eq!(long.len(), 1025);
    let mut invalid = Vec::new();
    for field in ["technique", "tactic"] {
        for value in [
            "t1059",
            "T105",
            "T1059.1",
            "TA2",
            "ta0002",
            "",
            " ",
            " \n ",
            " T1059",
            "T1059 ",
            " TA0002",
            "TA0002\t",
            long.as_str(),
        ] {
            invalid.push(json!({ field: value }));
        }
    }
    invalid.push(json!({"technique": "TA0002"}));
    invalid.push(json!({"tactic": "T1059"}));
    invalid.push(json!({"technique": "T1059", "tactic": "TA2"}));
    invalid.push(json!({"technique": 1059}));
    invalid.push(json!({"tactic": ["TA0002"]}));
    for (id, arguments) in invalid.into_iter().enumerate() {
        let reply = call(&mut harness, id as u64 + 1, arguments.clone()).await;
        assert_eq!(reply["result"]["isError"], true, "{arguments}");
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"], "invalid_argument",
            "{arguments}"
        );
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "invalid threat inputs made requests"
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

async fn find_paths(stack: &MockStack) -> Vec<String> {
    stack
        .requests()
        .await
        .into_iter()
        .map(|request| {
            assert_eq!(request.method, "GET");
            request.path
        })
        .filter(|path| path != "/api/status")
        .collect()
}

#[tokio::test]
async fn an_empty_source_page_sends_four_requests_and_a_threat_filtered_one_sends_one() {
    for (arguments, finds) in [
        (json!({"source": "custom"}), 4),
        (json!({"source": "prebuilt"}), 4),
        (json!({"source": "custom", "technique": "T1059"}), 1),
        (json!({"source": "prebuilt", "tactic": "TA0002"}), 1),
        (json!({"source": "custom", "technique": "T1059.001"}), 1),
    ] {
        let stack = MockStack::with_source_totals(0, 0, 0).await;
        let mut harness = Harness::start(target_for(stack.uri()), options());
        let reply = call(&mut harness, 1, arguments.clone()).await;
        assert_eq!(reply["result"]["isError"], false, "{arguments}: {reply}");
        assert_eq!(
            reply["result"]["structuredContent"]["data"]["rules"],
            json!([])
        );
        assert_eq!(find_paths(&stack).await, vec![FIND; finds], "{arguments}");
        let probes = stack
            .requests()
            .await
            .iter()
            .filter(|request| request.path == "/api/status")
            .count();
        assert!(probes <= 1, "{arguments}: one cached capability probe");
        harness.close_input();
        harness.join().await.expect("clean EOF");
    }
}
