mod support;

use elasticctl_core::{Profile, Resolved, Source};
use serde_json::{Value, json};
use std::time::Duration;
use support::{EXPECTED_TOOL_NAMES, Harness, current_metadata, legacy_initialize, options, target};
use tokio::time::{sleep, timeout};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

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

async fn call(harness: &mut Harness, id: u64, name: &str, arguments: Value) -> Value {
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"_meta": current_metadata(), "name": name, "arguments": arguments},
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], id);
    reply
}

async fn send_call(harness: &mut Harness, id: u64, name: &str, arguments: Value) {
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"_meta": current_metadata(), "name": name, "arguments": arguments},
        }))
        .await;
}

fn alert_response(source: Value) -> Value {
    json!({
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [{"_id": "alert-1", "_index": ".alerts", "_source": source}]
        }
    })
}

fn case_response() -> Value {
    json!({
        "id": "case-1",
        "version": "private-version",
        "title": "Sample case",
        "status": "in-progress",
        "severity": "high",
        "tags": ["elasticctl-sample"],
        "description": "case description",
        "assignees": [{"uid": "private-assignee"}],
        "connector": {"id": "private-connector"},
        "totalComment": 3,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
        "extra": "private-extra"
    })
}

async fn current_tools(harness: &mut Harness, id: u64) -> Value {
    harness
        .send_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list",
            "params": {"_meta": current_metadata()},
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], id);
    reply["result"]["tools"].clone()
}

fn tool<'a>(tools: &'a Value, name: &str) -> &'a Value {
    tools
        .as_array()
        .expect("tools array")
        .iter()
        .find(|tool| tool["name"] == name)
        .expect("registered triage tool")
}

fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys = value
        .as_object()
        .expect("object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

fn expected_keys(fields: &[&str]) -> Vec<String> {
    let mut fields = fields
        .iter()
        .map(|field| (*field).to_string())
        .collect::<Vec<_>>();
    fields.sort();
    fields
}

fn resolve_local_ref<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    let mut resolved = schema;
    while let Some(reference) = resolved.get("$ref").and_then(Value::as_str) {
        resolved = root
            .pointer(reference.strip_prefix('#').expect("local schema reference"))
            .expect("local schema reference resolves");
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

fn branch_for_type<'a>(root: &'a Value, schema: &'a Value, expected: &str) -> &'a Value {
    let schema = resolve_local_ref(root, schema);
    if match &schema["type"] {
        Value::String(value) => value == expected,
        Value::Array(values) => values.iter().any(|value| value == expected),
        _ => false,
    } {
        return schema;
    }
    schema["anyOf"]
        .as_array()
        .expect("schema type branch")
        .iter()
        .find(|branch| allows_type(root, branch, expected))
        .map(|branch| branch_for_type(root, branch, expected))
        .expect("schema type branch")
}

fn root_branch<'a>(root: &'a Value, fields: &[&str]) -> &'a Value {
    root["anyOf"]
        .as_array()
        .expect("success and failure alternatives")
        .iter()
        .map(|branch| resolve_local_ref(root, branch))
        .find(|branch| {
            branch
                .get("properties")
                .is_some_and(|properties| sorted_keys(properties) == expected_keys(fields))
        })
        .expect("root alternative")
}

fn assert_schema_object(root: &Value, schema: &Value, fields: &[&str], required: &[&str]) {
    let schema = resolve_local_ref(root, schema);
    assert!(allows_type(root, schema, "object"));
    assert!(
        schema.get("additionalProperties").is_none(),
        "output objects retain schemars' open-object default"
    );
    assert_eq!(sorted_keys(&schema["properties"]), expected_keys(fields));
    let mut actual_required = schema["required"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .map(|value| value.as_str().expect("required field").to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    actual_required.sort();
    assert_eq!(actual_required, expected_keys(required));
}

fn assert_scalar(root: &Value, schema: &Value, kind: &str, nullable: bool) {
    assert!(allows_type(root, schema, kind), "expected {kind} field");
    assert_eq!(
        allows_type(root, schema, "null"),
        nullable,
        "{kind} nullability"
    );
}

fn assert_string_array(root: &Value, schema: &Value, nullable: bool) {
    let array = branch_for_type(root, schema, "array");
    assert!(allows_type(root, &array["items"], "string"));
    assert_eq!(allows_type(root, schema, "null"), nullable);
}

fn assert_case_row_schema(root: &Value, row: &Value) {
    for field in ["id", "status", "title"] {
        assert_scalar(root, &row["properties"][field], "string", false);
    }
    for field in ["created_at", "description", "severity", "updated_at"] {
        assert_scalar(root, &row["properties"][field], "string", true);
    }
    assert_string_array(root, &row["properties"]["tags"], false);
    assert_scalar(root, &row["properties"]["totalComment"], "integer", true);
}

fn assert_page_schema(root: &Value, schema: &Value) {
    assert!(allows_type(root, schema, "null"));
    let page = branch_for_type(root, schema, "object");
    assert_schema_object(
        root,
        page,
        &["has_more", "limit", "returned", "total", "truncated"],
        &["limit", "returned", "truncated"],
    );
    assert_scalar(root, &page["properties"]["limit"], "integer", false);
    assert_scalar(root, &page["properties"]["returned"], "integer", false);
    assert_scalar(root, &page["properties"]["total"], "integer", true);
    assert_scalar(root, &page["properties"]["has_more"], "boolean", true);
    assert_scalar(root, &page["properties"]["truncated"], "boolean", false);
}

fn assert_alert_source_schema(root: &Value, source: &Value) {
    assert_schema_object(
        root,
        source,
        &[
            "@timestamp",
            "kibana.alert.reason",
            "kibana.alert.risk_score",
            "kibana.alert.rule.name",
            "kibana.alert.rule.rule_id",
            "kibana.alert.severity",
            "kibana.alert.workflow_status",
            "kibana.alert.workflow_tags",
        ],
        &[],
    );
    for field in [
        "@timestamp",
        "kibana.alert.reason",
        "kibana.alert.rule.name",
        "kibana.alert.rule.rule_id",
        "kibana.alert.severity",
        "kibana.alert.workflow_status",
    ] {
        assert_scalar(root, &source["properties"][field], "string", true);
    }
    assert_scalar(
        root,
        &source["properties"]["kibana.alert.risk_score"],
        "number",
        true,
    );
    assert_string_array(
        root,
        &source["properties"]["kibana.alert.workflow_tags"],
        true,
    );
}

fn property<'a>(root: &'a Value, object: &'a Value, name: &str) -> &'a Value {
    resolve_local_ref(root, &object["properties"][name])
}

#[tokio::test]
async fn triage_catalog_exposes_the_four_read_only_inspection_tools() {
    let mut harness = Harness::start(target(), options());
    let tools = current_tools(&mut harness, 1).await;
    let names = tools
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();

    assert_eq!(names, EXPECTED_TOOL_NAMES);
    let annotations = json!({
        "readOnlyHint": true,
        "destructiveHint": false,
        "idempotentHint": true,
        "openWorldHint": true,
    });
    for (name, fields, required) in [
        ("alerts_get", vec!["alert_id"], vec!["alert_id"]),
        (
            "alerts_list",
            vec![
                "limit", "search", "severity", "since", "rule", "status", "tag",
            ],
            vec![],
        ),
        ("cases_get", vec!["id"], vec!["id"]),
        (
            "cases_list",
            vec!["limit", "search", "severity", "status", "tag"],
            vec![],
        ),
    ] {
        let definition = tool(&tools, name);
        let input = &definition["inputSchema"];
        assert_eq!(definition["annotations"], annotations, "{name}");
        assert_eq!(input["type"], "object", "{name}");
        assert_eq!(input["additionalProperties"], false, "{name}");
        assert_eq!(sorted_keys(&input["properties"]), expected_keys(&fields));
        assert_eq!(
            input["required"]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .map(|value| value.as_str().expect("required field"))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            required,
            "{name} required inputs"
        );
        let output = &definition["outputSchema"];
        assert_eq!(output["type"], "object", "{name}");
        assert_eq!(output["anyOf"].as_array().map(Vec::len), Some(2), "{name}");
        assert_schema_object(
            output,
            root_branch(output, &["target", "data", "page"]),
            &["target", "data", "page"],
            &["target", "data"],
        );
        assert_schema_object(
            output,
            root_branch(output, &["target", "error"]),
            &["target", "error"],
            &["target", "error"],
        );
        let success = root_branch(output, &["target", "data", "page"]);
        let target = property(output, success, "target");
        assert_schema_object(
            output,
            target,
            &["host", "profile", "space"],
            &["host", "profile", "space"],
        );
        for field in ["host", "profile", "space"] {
            assert_scalar(output, &target["properties"][field], "string", false);
        }
        let failure = root_branch(output, &["target", "error"]);
        let failure_target = property(output, failure, "target");
        assert_schema_object(
            output,
            failure_target,
            &["host", "profile", "space"],
            &["host", "profile", "space"],
        );
        for field in ["host", "profile", "space"] {
            assert_scalar(
                output,
                &failure_target["properties"][field],
                "string",
                false,
            );
        }
        let error = property(output, failure, "error");
        assert_schema_object(
            output,
            error,
            &["code", "http_status", "kind", "message"],
            &["code", "kind", "message"],
        );
        for field in ["code", "kind", "message"] {
            assert_scalar(output, &error["properties"][field], "string", false);
        }
        assert_scalar(output, &error["properties"]["http_status"], "integer", true);
    }
    for name in ["alerts_list", "cases_list"] {
        let input = &tool(&tools, name)["inputSchema"];
        assert_eq!(input["properties"]["limit"]["default"], 50, "{name}");
        assert_eq!(input["properties"]["limit"]["minimum"], 1, "{name}");
        assert_eq!(input["properties"]["limit"]["maximum"], 200, "{name}");
        assert_scalar(input, &input["properties"]["limit"], "integer", false);
    }
    for (name, field, values) in [
        (
            "alerts_list",
            "status",
            json!(["open", "acknowledged", "closed"]),
        ),
        (
            "cases_list",
            "status",
            json!(["open", "in-progress", "closed"]),
        ),
    ] {
        let input = &tool(&tools, name)["inputSchema"];
        assert_eq!(
            branch_for_type(input, &input["properties"][field], "string")["enum"],
            values
        );
        assert_scalar(input, &input["properties"][field], "string", true);
    }
    for (name, field) in [
        ("alerts_get", "alert_id"),
        ("alerts_list", "severity"),
        ("alerts_list", "rule"),
        ("alerts_list", "tag"),
        ("alerts_list", "since"),
        ("alerts_list", "search"),
        ("cases_get", "id"),
        ("cases_list", "severity"),
        ("cases_list", "tag"),
        ("cases_list", "search"),
    ] {
        let input = &tool(&tools, name)["inputSchema"];
        let string = branch_for_type(input, &input["properties"][field], "string");
        assert_eq!(string["minLength"], 1, "{name}.{field}");
        assert_eq!(string["maxLength"], 1024, "{name}.{field}");
        assert!(
            string["description"]
                .as_str()
                .is_some_and(|description| description.contains("non-whitespace text")
                    && description.contains("UTF-8 bytes")),
            "{name}.{field} description"
        );
        assert_eq!(
            allows_type(input, &input["properties"][field], "null"),
            !matches!(
                (name, field),
                ("alerts_get", "alert_id") | ("cases_get", "id")
            ),
            "{name}.{field} nullability"
        );
    }
    for (name, list_key, row_fields, row_required) in [
        (
            "alerts_list",
            "alerts",
            vec!["id", "index", "source"],
            vec!["id", "source"],
        ),
        (
            "cases_list",
            "cases",
            vec![
                "created_at",
                "description",
                "id",
                "severity",
                "status",
                "tags",
                "title",
                "totalComment",
                "updated_at",
            ],
            vec!["id", "status", "tags", "title"],
        ),
    ] {
        let output = &tool(&tools, name)["outputSchema"];
        let success = root_branch(output, &["target", "data", "page"]);
        let data = property(output, success, "data");
        assert_schema_object(output, data, &[list_key], &[list_key]);
        let rows = branch_for_type(output, &data["properties"][list_key], "array");
        assert!(!allows_type(output, &data["properties"][list_key], "null"));
        let row = resolve_local_ref(output, &rows["items"]);
        assert_schema_object(output, row, &row_fields, &row_required);
        match name {
            "alerts_list" => {
                assert_scalar(output, &row["properties"]["id"], "string", false);
                assert_scalar(output, &row["properties"]["index"], "string", true);
                assert!(!allows_type(output, &row["properties"]["source"], "null"));
                assert_alert_source_schema(output, property(output, row, "source"));
            }
            "cases_list" => assert_case_row_schema(output, row),
            _ => unreachable!("known triage list tool"),
        }
        assert_page_schema(output, &success["properties"]["page"]);
    }
    for (name, fields, required) in [
        (
            "alerts_get",
            vec!["id", "index", "source"],
            vec!["id", "source"],
        ),
        (
            "cases_get",
            vec![
                "created_at",
                "description",
                "id",
                "severity",
                "status",
                "tags",
                "title",
                "totalComment",
                "updated_at",
            ],
            vec!["id", "status", "tags", "title"],
        ),
    ] {
        let output = &tool(&tools, name)["outputSchema"];
        let success = root_branch(output, &["target", "data", "page"]);
        assert_schema_object(
            output,
            property(output, success, "data"),
            &fields,
            &required,
        );
        let data = property(output, success, "data");
        match name {
            "alerts_get" => {
                assert_scalar(output, &data["properties"]["id"], "string", false);
                assert_scalar(output, &data["properties"]["index"], "string", true);
                assert!(!allows_type(output, &data["properties"]["source"], "null"));
                assert_alert_source_schema(output, property(output, data, "source"));
            }
            "cases_get" => assert_case_row_schema(output, data),
            _ => unreachable!("known triage get tool"),
        }
        assert_page_schema(output, &success["properties"]["page"]);
    }
    let current = tools.clone();
    harness.close_input();
    harness.join().await.expect("clean EOF");
    let mut legacy = Harness::start(target(), options());
    legacy.send_json(legacy_initialize(2)).await;
    assert_eq!(legacy.receive_json().await["id"], 2);
    legacy
        .send_json(json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}))
        .await;
    assert_eq!(legacy.receive_json().await["result"]["tools"], current);
    legacy.close_input();
    legacy.join().await.expect("clean EOF");
}

#[tokio::test]
async fn alerts_project_only_selected_flat_and_nested_source_fields() {
    let server = MockServer::start().await;
    let flat = json!({
        "@timestamp": "2026-01-01T00:00:00Z",
        "kibana.alert.rule.rule_id": "rule-1",
        "kibana.alert.rule.name": "Sample rule",
        "kibana.alert.severity": "high",
        "kibana.alert.risk_score": 47.5,
        "kibana.alert.workflow_status": "acknowledged",
        "kibana.alert.reason": "matched",
        "kibana.alert.workflow_tags": ["elasticctl-sample"],
        "user.email": "private-email-marker",
        "kibana.alert.workflow_assignee_ids": ["private-assignee"],
        "id": "source-id-collision",
        "_index": "source-index-collision"
    });
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(alert_response(flat)))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(
        &mut harness,
        1,
        "alerts_list",
        json!({"status": "acknowledged"}),
    )
    .await;
    let data = &reply["result"]["structuredContent"]["data"]["alerts"][0];
    assert_eq!(data["id"], "alert-1");
    assert_eq!(
        data["source"]["kibana.alert.workflow_status"],
        "acknowledged"
    );
    assert!(data["source"].get("user.email").is_none());
    assert!(!reply.to_string().contains("private-email-marker"));
    assert!(!reply.to_string().contains("private-assignee"));
    assert!(!reply.to_string().contains("source-id-collision"));
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let nested_server = MockServer::start().await;
    let nested = json!({
        "@timestamp": "2026-01-01T00:00:00Z",
        "kibana": {"alert": {"rule": {"rule_id": "rule-1", "name": "Sample rule"}, "workflow_status": "acknowledged"}},
        "user": {"email": "private-nested-email"}
    });
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(alert_response(nested)))
        .mount(&nested_server)
        .await;
    let mut harness = Harness::start(target_for(&nested_server), options());
    let reply = call(
        &mut harness,
        2,
        "alerts_get",
        json!({"alert_id": "alert-1"}),
    )
    .await;
    let data = &reply["result"]["structuredContent"]["data"];
    assert_eq!(data["source"]["kibana.alert.rule.name"], "Sample rule");
    assert_eq!(
        data["source"]["kibana.alert.workflow_status"],
        "acknowledged"
    );
    assert!(!reply.to_string().contains("private-nested-email"));
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn case_tools_preserve_in_progress_and_omit_private_case_fields() {
    let server = MockServer::start().await;
    let case = case_response();
    Mock::given(method("GET"))
        .and(path("/api/cases/case-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(case.clone()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"cases": [case], "total": 1})),
        )
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let list = call(
        &mut harness,
        1,
        "cases_list",
        json!({"status": "in-progress"}),
    )
    .await;
    let case_data = &list["result"]["structuredContent"]["data"]["cases"][0];
    assert_eq!(case_data["status"], "in-progress");
    assert!(case_data.get("extra").is_none());
    assert!(case_data.get("assignees").is_none());
    assert!(case_data.get("version").is_none());
    assert!(!list.to_string().contains("private-connector"));
    let get = call(&mut harness, 2, "cases_get", json!({"id": "case-1"})).await;
    assert_eq!(get["result"]["structuredContent"]["data"]["id"], "case-1");
    assert!(!get.to_string().contains("private-extra"));
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn triage_inputs_reject_every_invalid_string_before_io() {
    let server = MockServer::start().await;
    let mut harness = Harness::start(target_for(&server), options());
    let invalid = [
        ("alerts_get", "alert_id"),
        ("alerts_list", "severity"),
        ("alerts_list", "rule"),
        ("alerts_list", "tag"),
        ("alerts_list", "since"),
        ("alerts_list", "search"),
        ("cases_get", "id"),
        ("cases_list", "severity"),
        ("cases_list", "tag"),
        ("cases_list", "search"),
    ];
    for (index, (tool, field)) in invalid.into_iter().enumerate() {
        for value in [
            json!(""),
            json!(" \t\n "),
            json!("x".repeat(1025)),
            json!("é".repeat(513)),
        ] {
            let reply = call(
                &mut harness,
                (index * 10) as u64,
                tool,
                json!({field: value}),
            )
            .await;
            assert_eq!(reply["result"]["isError"], true, "{tool}.{field}");
            assert_eq!(
                reply["result"]["structuredContent"]["error"]["code"],
                "invalid_argument"
            );
        }
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn triage_exact_byte_limits_accept_ascii_and_multibyte_selectors_before_io() {
    let server = MockServer::start().await;
    let mut harness = Harness::start(target_for(&server), options());
    let fields = [
        ("alerts_get", "alert_id"),
        ("alerts_list", "severity"),
        ("alerts_list", "rule"),
        ("alerts_list", "tag"),
        ("alerts_list", "since"),
        ("alerts_list", "search"),
        ("cases_get", "id"),
        ("cases_list", "severity"),
        ("cases_list", "tag"),
        ("cases_list", "search"),
    ];
    for (index, (tool, field)) in fields.into_iter().enumerate() {
        for value in ["x".repeat(1024), "é".repeat(512)] {
            let reply = call(
                &mut harness,
                (index * 10) as u64,
                tool,
                json!({field: value}),
            )
            .await;
            assert_ne!(
                reply["result"]["structuredContent"]["error"]["code"], "invalid_argument",
                "{tool}.{field} rejected a 1,024-byte value"
            );
        }
    }
    assert!(
        !server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn triage_optional_inputs_accept_explicit_null_through_the_router() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"hits": {"hits": []}})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"cases": [], "total": 0})))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    for (id, field) in ["status", "severity", "rule", "tag", "since", "search"]
        .into_iter()
        .enumerate()
    {
        let reply = call(
            &mut harness,
            id as u64 + 1,
            "alerts_list",
            json!({field: null}),
        )
        .await;
        assert_eq!(reply["result"]["isError"], false, "alerts_list.{field}");
    }
    for (id, field) in ["status", "severity", "tag", "search"]
        .into_iter()
        .enumerate()
    {
        let reply = call(
            &mut harness,
            id as u64 + 10,
            "cases_list",
            json!({field: null}),
        )
        .await;
        assert_eq!(reply["result"]["isError"], false, "cases_list.{field}");
    }
    assert_eq!(
        server.received_requests().await.expect("requests").len(),
        10
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn alert_and_case_filters_forward_the_typed_filter_contracts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"hits": {"hits": []}})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"cases": [], "total": 0})))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let alerts = call(
        &mut harness,
        1,
        "alerts_list",
        json!({"status": "acknowledged", "severity": "high", "tag": "elasticctl-sample", "since": "90m", "search": "needle", "limit": 7}),
    )
    .await;
    assert_eq!(alerts["result"]["isError"], false);
    assert_eq!(
        alerts["result"]["structuredContent"]["page"],
        json!({"limit": 7, "returned": 0, "total": null, "has_more": null, "truncated": false})
    );
    let cases = call(
        &mut harness,
        2,
        "cases_list",
        json!({"status": "in-progress", "severity": "critical", "tag": "elasticctl-sample", "search": "needle", "limit": 7}),
    )
    .await;
    assert_eq!(cases["result"]["isError"], false);
    assert_eq!(
        cases["result"]["structuredContent"]["page"],
        json!({"limit": 7, "returned": 0, "total": 0, "has_more": false, "truncated": false})
    );

    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 2);
    let alert_request = requests
        .iter()
        .find(|request| request.url.path() == "/api/detection_engine/signals/search")
        .expect("alerts request");
    assert_eq!(alert_request.method.as_str(), "POST");
    assert_eq!(
        serde_json::from_slice::<Value>(&alert_request.body).expect("JSON request"),
        json!({
            "query": {"bool": {"filter": [
                {"term": {"kibana.alert.workflow_status": "acknowledged"}},
                {"term": {"kibana.alert.severity": "high"}},
                {"term": {"kibana.alert.workflow_tags": "elasticctl-sample"}},
                {"range": {"@timestamp": {"gte": "now-90m"}}},
                {"bool": {"minimum_should_match": 1, "should": [
                    {"wildcard": {"kibana.alert.rule.name": {"value": "*needle*", "case_insensitive": true}}},
                    {"wildcard": {"kibana.alert.reason": {"value": "*needle*", "case_insensitive": true}}}
                ]}}
            ]}},
            "sort": [{"@timestamp": {"order": "desc"}}, {"kibana.alert.uuid": {"order": "asc"}}],
            "size": 8,
            "track_total_hits": true,
        })
    );
    let case_request = requests
        .iter()
        .find(|request| request.url.path() == "/api/cases/_find")
        .expect("cases request");
    assert_eq!(case_request.method.as_str(), "GET");
    let query = case_request.url.query_pairs().collect::<Vec<_>>();
    assert_eq!(
        query,
        vec![
            ("page".into(), "1".into()),
            ("perPage".into(), "100".into()),
            ("sortField".into(), "createdAt".into()),
            ("sortOrder".into(), "desc".into()),
            ("status".into(), "in-progress".into()),
            ("severity".into(), "critical".into()),
            ("tags".into(), "elasticctl-sample".into()),
            ("search".into(), "needle".into()),
            ("searchFields".into(), "title".into()),
            ("searchFields".into(), "description".into()),
        ]
    );
    assert!(requests.iter().all(|request| {
        !matches!(request.method.as_str(), "PUT" | "PATCH" | "DELETE")
            && !request.url.path().starts_with("/internal/")
            && !matches!(
                request.url.path(),
                "/api/detection_engine/signals/status"
                    | "/api/detection_engine/signals/tags"
                    | "/api/detection_engine/signals/assignees"
                    | "/api/cases/comments"
            )
    }));
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn alert_rule_filter_resolves_an_exact_rule_id_before_the_signals_search() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"rule_id": "rule-1", "name": "Sample rule"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"hits": {"hits": []}})))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(&mut harness, 1, "alerts_list", json!({"rule": "rule-1"})).await;
    assert_eq!(reply["result"]["isError"], false);
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method.as_str(), "GET");
    assert_eq!(requests[0].url.path(), "/api/detection_engine/rules");
    assert_eq!(requests[1].method.as_str(), "POST");
    assert_eq!(
        requests[1].url.path(),
        "/api/detection_engine/signals/search"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[1].body).expect("signals body"),
        json!({
            "query": {"bool": {"filter": [{"term": {"kibana.alert.rule.rule_id": "rule-1"}}]}},
            "sort": [{"@timestamp": {"order": "desc"}}, {"kibana.alert.uuid": {"order": "asc"}}],
            "size": 51,
            "track_total_hits": true,
        })
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn missing_alert_id_returns_not_found_without_data() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"hits": {"hits": []}})))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(
        &mut harness,
        1,
        "alerts_get",
        json!({"alert_id": "missing"}),
    )
    .await;
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["code"],
        "elastic_not_found"
    );
    assert!(reply["result"]["structuredContent"].get("data").is_none());
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method.as_str(), "POST");
    assert_eq!(
        requests[0].url.path(),
        "/api/detection_engine/signals/search"
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn alert_and_case_lists_preserve_cap_metadata() {
    let server = MockServer::start().await;
    let first_alert = json!({"@timestamp": "2026-01-01T00:00:00Z"});
    let second_alert = json!({"@timestamp": "2026-01-02T00:00:00Z"});
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {
                "total": {"value": 2, "relation": "eq"},
                "hits": [
                    {"_id": "alert-1", "_source": first_alert},
                    {"_id": "alert-2", "_source": second_alert}
                ]
            }
        })))
        .mount(&server)
        .await;
    let first_case = case_response();
    let mut second_case = case_response();
    second_case["id"] = json!("case-2");
    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"cases": [first_case, second_case], "total": 2})),
        )
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let alerts = call(&mut harness, 1, "alerts_list", json!({"limit": 1})).await;
    assert_eq!(
        alerts["result"]["structuredContent"]["data"]["alerts"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        alerts["result"]["structuredContent"]["page"],
        json!({"limit": 1, "returned": 1, "total": 2, "has_more": true, "truncated": true})
    );
    let cases = call(&mut harness, 2, "cases_list", json!({"limit": 1})).await;
    assert_eq!(
        cases["result"]["structuredContent"]["data"]["cases"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        cases["result"]["structuredContent"]["page"],
        json!({"limit": 1, "returned": 1, "total": 2, "has_more": true, "truncated": true})
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn malformed_triage_responses_and_missing_ids_are_classified_without_data() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"hits": {"hits": [{"_id": "alert-1", "_source": {"kibana.alert.risk_score": "wrong"}}]}})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/cases/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(
            json!({"statusCode": 404, "error": "Not Found", "message": "private-message"}),
        ))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let malformed = call(
        &mut harness,
        1,
        "alerts_get",
        json!({"alert_id": "alert-1"}),
    )
    .await;
    assert_eq!(malformed["result"]["isError"], true);
    assert_eq!(
        malformed["result"]["structuredContent"]["error"]["code"],
        "elastic_http"
    );
    assert!(
        malformed["result"]["structuredContent"]
            .get("data")
            .is_none()
    );
    let missing = call(&mut harness, 2, "cases_get", json!({"id": "missing"})).await;
    assert_eq!(missing["result"]["isError"], true);
    assert_eq!(
        missing["result"]["structuredContent"]["error"]["code"],
        "elastic_not_found"
    );
    assert!(!missing.to_string().contains("private-message"));
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn alert_rule_name_ambiguity_stops_before_the_signals_search() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(
                json!({"statusCode": 404, "error": "Not Found", "message": "missing"}),
            ),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"rule_id": "rule-1", "name": "Same name"},
                {"rule_id": "rule-2", "name": "Same name"}
            ],
            "total": 2,
            "page": 1,
            "perPage": 100,
        })))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(&mut harness, 1, "alerts_list", json!({"rule": "Same name"})).await;
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["code"],
        "elastic_conflict"
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
    assert!(
        requests
            .iter()
            .all(|request| request.url.path() != "/api/detection_engine/signals/search")
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn cancelling_a_delayed_alert_request_emits_no_result_or_later_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(300))
                .set_body_json(json!({"hits": {"hits": []}})),
        )
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    send_call(&mut harness, 1, "alerts_list", json!({})).await;
    timeout(Duration::from_secs(1), async {
        loop {
            if server.received_requests().await.expect("requests").len() == 1 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("delayed signals request starts");
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 1, "reason": "test", "_meta": current_metadata()},
        }))
        .await;
    assert!(
        timeout(Duration::from_millis(500), harness.receive_json())
            .await
            .is_err(),
        "cancelled alert call emitted a result"
    );
    assert_eq!(
        server.received_requests().await.expect("requests").len(),
        1,
        "cancelled alert call issued a later request"
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}
