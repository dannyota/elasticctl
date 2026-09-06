mod support;

use elasticctl_api_test_support::{MockStack, RecordedRequest};
use elasticctl_core::{Profile, Resolved, Source};
use elasticctl_mcp::ServerOptions;
use serde_json::{Value, json};
use support::{EXPECTED_TOOL_NAMES, Harness, current_metadata, options, target};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn target_for(stack: &MockStack) -> Resolved {
    let uri = stack.uri();
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

fn target_for_server(server: &MockServer) -> Resolved {
    Resolved {
        name: "test".to_string(),
        source: Source::Profile,
        profile: Profile {
            kibana_url: server.uri(),
            es_url: Some(server.uri()),
            api_key: Some("test-api-key".to_string()),
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
            "params": {
                "_meta": current_metadata(),
                "name": name,
                "arguments": arguments,
            },
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], id);
    reply
}

async fn legacy_call(harness: &mut Harness, id: u64, name: &str, arguments: Value) -> Value {
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], id);
    reply
}

async fn current_tools(harness: &mut Harness, id: u64) -> Value {
    harness
        .send_json(json!({
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
        .expect("registered rule tool")
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

fn assert_object_keys(value: &Value, fields: &[&str]) {
    assert_eq!(sorted_keys(value), expected_keys(fields));
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

fn schema_allows_type(root: &Value, schema: &Value, expected: &str) -> bool {
    let schema = resolve_local_ref(root, schema);
    match &schema["type"] {
        Value::String(value) if value == expected => true,
        Value::Array(values) if values.iter().any(|value| value == expected) => true,
        _ => schema["anyOf"].as_array().is_some_and(|branches| {
            branches
                .iter()
                .any(|branch| schema_allows_type(root, branch, expected))
        }),
    }
}

fn schema_branch_for_type<'a>(root: &'a Value, schema: &'a Value, expected: &str) -> &'a Value {
    let schema = resolve_local_ref(root, schema);
    let directly_allows_type = match &schema["type"] {
        Value::String(value) => value == expected,
        Value::Array(values) => values.iter().any(|value| value == expected),
        _ => false,
    };
    if directly_allows_type {
        return schema;
    }
    schema["anyOf"]
        .as_array()
        .expect("schema branch for expected type")
        .iter()
        .find(|branch| schema_allows_type(root, branch, expected))
        .map(|branch| schema_branch_for_type(root, branch, expected))
        .expect("expected type branch")
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
        .expect("actual root alternative")
}

fn property_schema<'a>(root: &'a Value, object: &'a Value, property: &str) -> &'a Value {
    resolve_local_ref(root, &object["properties"][property])
}

fn assert_schema_object(root: &Value, schema: &Value, fields: &[&str], required: &[&str]) {
    let schema = resolve_local_ref(root, schema);
    assert!(schema_allows_type(root, schema, "object"));
    assert_eq!(sorted_keys(&schema["properties"]), expected_keys(fields));
    let mut actual_required = schema["required"]
        .as_array()
        .map(|fields| {
            fields
                .iter()
                .map(|field| field.as_str().expect("required field").to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    actual_required.sort();
    assert_eq!(actual_required, expected_keys(required));
}

fn assert_failure_schema(schema: &Value, structured: &Value) {
    assert_object_keys(structured, &["target", "error"]);
    let failure = root_branch(schema, &["target", "error"]);
    assert_schema_object(schema, failure, &["target", "error"], &["target", "error"]);
    let error = property_schema(schema, failure, "error");
    assert_schema_object(
        schema,
        error,
        &["kind", "http_status", "code", "message"],
        &["kind", "code", "message"],
    );
    for key in ["kind", "code", "message"] {
        assert!(schema_allows_type(
            schema,
            &error["properties"][key],
            "string"
        ));
    }
    assert!(schema_allows_type(
        schema,
        &error["properties"]["http_status"],
        "null"
    ));
    assert!(schema_allows_type(
        schema,
        &error["properties"]["http_status"],
        "integer"
    ));
}

fn assert_page_schema(schema: &Value, page: &Value) {
    assert!(schema_allows_type(schema, page, "null"));
    let page = schema_branch_for_type(schema, page, "object");
    assert_schema_object(
        schema,
        page,
        &["limit", "returned", "total", "has_more", "truncated"],
        &["limit", "returned", "truncated"],
    );
    for key in ["limit", "returned"] {
        assert!(schema_allows_type(
            schema,
            &page["properties"][key],
            "integer"
        ));
    }
    assert!(schema_allows_type(
        schema,
        &page["properties"]["total"],
        "integer"
    ));
    assert!(schema_allows_type(
        schema,
        &page["properties"]["total"],
        "null"
    ));
    assert!(schema_allows_type(
        schema,
        &page["properties"]["has_more"],
        "boolean"
    ));
    assert!(schema_allows_type(
        schema,
        &page["properties"]["has_more"],
        "null"
    ));
    assert!(schema_allows_type(
        schema,
        &page["properties"]["truncated"],
        "boolean"
    ));
}

fn assert_success_schema(
    schema: &Value,
    structured: &Value,
    data_fields: &[&str],
    required_data_fields: &[&str],
    page: bool,
) {
    assert_object_keys(structured, &["target", "data", "page"]);
    assert_object_keys(&structured["target"], &["profile", "host", "space"]);
    assert_object_keys(&structured["data"], data_fields);
    let success = root_branch(schema, &["target", "data", "page"]);
    assert_schema_object(
        schema,
        success,
        &["target", "data", "page"],
        &["target", "data"],
    );
    let target = property_schema(schema, success, "target");
    assert_schema_object(
        schema,
        target,
        &["profile", "host", "space"],
        &["profile", "host", "space"],
    );
    for key in ["profile", "host", "space"] {
        assert!(schema_allows_type(
            schema,
            &target["properties"][key],
            "string"
        ));
    }
    let data = property_schema(schema, success, "data");
    assert_schema_object(schema, data, data_fields, required_data_fields);
    assert_page_schema(schema, &success["properties"]["page"]);
    if page {
        assert_object_keys(
            &structured["page"],
            &["limit", "returned", "total", "has_more", "truncated"],
        );
        assert!(structured["page"]["limit"].is_u64());
        assert!(structured["page"]["returned"].is_u64());
        assert!(structured["page"]["total"].is_u64());
        assert!(structured["page"]["has_more"].is_boolean());
        assert!(structured["page"]["truncated"].is_boolean());
    } else {
        assert_eq!(structured["page"], Value::Null);
    }
}

fn rule(id: impl Into<String>, name: impl Into<String>) -> Value {
    json!({
        "rule_id": id.into(),
        "name": name.into(),
        "type": "query",
        "enabled": false,
        "severity": "high",
        "risk_score": 42.75,
        "tags": ["elasticctl-sample"],
        "description": "operator-authored description",
        "language": "kuery",
        "query": "event.category: process",
        "index": ["logs-*"] ,
        "from": "now-5m",
        "interval": "5m",
        "exceptions_list": [{
            "id": "volatile-exception-id",
            "list_id": "sample-list",
            "namespace_type": "single",
            "type": "detection",
            "created_by": "identity-sentinel"
        }],
        "actions": [{"id": "secret-action-sentinel"}],
        "created_by": "identity-sentinel",
        "execution_summary": {"private": "execution-sentinel"}
    })
}

fn request_paths(requests: &[RecordedRequest]) -> Vec<(String, String)> {
    requests
        .iter()
        .map(|request| (request.method.clone(), request.path.clone()))
        .collect()
}

fn assert_only_gets(requests: &[RecordedRequest]) {
    assert!(
        requests.iter().all(|request| request.method == "GET"),
        "unexpected mutation request: {requests:#?}"
    );
    assert!(
        requests
            .iter()
            .all(|request| is_allowed_read_path(&request.path))
    );
}

fn is_allowed_read_path(path: &str) -> bool {
    matches!(
        path,
        "/api/status"
            | "/api/detection_engine/rules"
            | "/api/detection_engine/rules/_find"
            | "/api/detection_engine/rules/prepackaged/_status"
    )
}

#[tokio::test]
async fn rule_catalog_declares_closed_inputs_safe_schemas_and_static_annotations() {
    let mut harness = Harness::start(target(), options());
    let tools = current_tools(&mut harness, 1).await;
    let names = tools
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("name"))
        .collect::<Vec<_>>();
    assert_eq!(names, EXPECTED_TOOL_NAMES);

    let annotations = json!({
        "readOnlyHint": true,
        "destructiveHint": false,
        "idempotentHint": true,
        "openWorldHint": true,
    });
    for (name, description, fields, required) in [
        (
            "rules_get",
            "Inspect one rule by its exact rule_id or display name.",
            vec!["selector"],
            vec!["selector"],
        ),
        (
            "rules_list",
            "List read-only Elastic Security rules from the selected stack.",
            vec![
                "enabled",
                "limit",
                "rule_type",
                "search",
                "severity",
                "source",
                "tag",
            ],
            vec![],
        ),
        (
            "rules_prebuilt_status",
            "Inspect the installed, missing, outdated, and customized prebuilt-rule counts.",
            vec![],
            vec![],
        ),
    ] {
        let tool = tool(&tools, name);
        assert_eq!(tool["description"], description);
        assert_eq!(tool["annotations"], annotations);
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        if fields.is_empty() {
            assert!(
                tool["inputSchema"].get("properties").is_none()
                    || sorted_keys(&tool["inputSchema"]["properties"]).is_empty()
            );
        } else {
            assert_eq!(
                sorted_keys(&tool["inputSchema"]["properties"]),
                expected_keys(&fields)
            );
        }
        assert_eq!(
            tool["inputSchema"]["required"]
                .as_array()
                .map(|fields| fields
                    .iter()
                    .map(|field| field.as_str().unwrap())
                    .collect::<Vec<_>>())
                .unwrap_or_default(),
            required
        );
        assert_eq!(tool["outputSchema"]["type"], "object");
        assert_eq!(
            tool["outputSchema"]["anyOf"]
                .as_array()
                .expect("alternatives")
                .len(),
            2
        );
    }
    let source_schema = &tool(&tools, "rules_list")["inputSchema"]["properties"]["source"];
    assert_eq!(source_schema["default"], "all");
    assert_eq!(
        tool(&tools, "rules_list")["inputSchema"]["properties"]["limit"]["default"],
        50
    );
    assert_eq!(
        tool(&tools, "rules_list")["inputSchema"]["properties"]["limit"]["minimum"],
        1
    );
    assert_eq!(
        tool(&tools, "rules_list")["inputSchema"]["properties"]["limit"]["maximum"],
        200
    );
    assert_eq!(
        resolve_local_ref(&tool(&tools, "rules_list")["inputSchema"], source_schema)["enum"],
        json!(["custom", "customized", "prebuilt", "all"])
    );
    assert!(
        tool(&tools, "rules_list")["inputSchema"]["properties"]["rule_type"]
            .get("enum")
            .is_none()
    );
    assert!(
        tool(&tools, "rules_list")["inputSchema"]["properties"]["severity"]
            .get("enum")
            .is_none()
    );
    for (name, field, description, required) in [
        (
            "rules_get",
            "selector",
            "Exact rule_id or display name. Must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.",
            true,
        ),
        (
            "rules_list",
            "rule_type",
            "Exact rule-type filter. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.",
            false,
        ),
        (
            "rules_list",
            "severity",
            "Exact rule-severity filter. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.",
            false,
        ),
        (
            "rules_list",
            "tag",
            "Exact rule-tag filter. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.",
            false,
        ),
        (
            "rules_list",
            "search",
            "Rule display-name substring or exact-tag search. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.",
            false,
        ),
    ] {
        let input = &tool(&tools, name)["inputSchema"];
        let property = &input["properties"][field];
        let string = schema_branch_for_type(input, property, "string");
        assert_eq!(string["description"], description, "{name}.{field}");
        assert_eq!(string["minLength"], 1, "{name}.{field}");
        assert_eq!(string["maxLength"], 1024, "{name}.{field}");
        assert_eq!(
            input["required"]
                .as_array()
                .is_some_and(|fields| fields.iter().any(|value| value == field)),
            required,
            "{name}.{field} required"
        );
        assert_eq!(
            schema_allows_type(input, property, "null"),
            !required,
            "{name}.{field} nullability"
        );
    }

    let current = tools.clone();
    harness.close_input();
    harness.join().await.expect("clean EOF");
    let mut legacy = Harness::start(target(), options());
    legacy.send_json(support::legacy_initialize(2)).await;
    assert_eq!(legacy.receive_json().await["id"], 2);
    legacy
        .send_json(json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}))
        .await;
    assert_eq!(legacy.receive_json().await["result"]["tools"], current);
    legacy.close_input();
    legacy.join().await.expect("clean EOF");
}

#[tokio::test]
async fn rules_list_uses_complete_collection_before_the_requested_row_cap() {
    let stack = MockStack::with_rules(
        (0..201)
            .map(|index| rule(format!("rule-{index}"), format!("Rule {index}")))
            .collect(),
    )
    .await;
    let mut harness = Harness::start(target_for(&stack), options());
    let tools = current_tools(&mut harness, 1).await;
    let schema = tool(&tools, "rules_list")["outputSchema"].clone();
    let reply = call(&mut harness, 2, "rules_list", json!({})).await;
    let result = &reply["result"];
    let structured = &result["structuredContent"];
    assert_eq!(result["isError"], false);
    assert_success_schema(&schema, structured, &["rules"], &["rules"], true);
    let data = property_schema(
        &schema,
        root_branch(&schema, &["target", "data", "page"]),
        "data",
    );
    let rules = schema_branch_for_type(&schema, &data["properties"]["rules"], "array");
    let row = resolve_local_ref(&schema, &rules["items"]);
    assert_schema_object(
        &schema,
        row,
        &[
            "rule_id",
            "name",
            "type",
            "enabled",
            "severity",
            "risk_score",
            "tags",
        ],
        &["rule_id"],
    );
    for key in ["rule_id", "name", "type", "severity"] {
        assert!(schema_allows_type(
            &schema,
            &row["properties"][key],
            "string"
        ));
    }
    assert!(schema_allows_type(
        &schema,
        &row["properties"]["enabled"],
        "boolean"
    ));
    assert!(schema_allows_type(
        &schema,
        &row["properties"]["risk_score"],
        "number"
    ));
    let tags = schema_branch_for_type(&schema, &row["properties"]["tags"], "array");
    assert!(schema_allows_type(&schema, &tags["items"], "string"));
    assert_eq!(structured["page"]["limit"], 50);
    assert_eq!(structured["page"]["returned"], 50);
    assert_eq!(structured["page"]["total"], 201);
    assert_eq!(structured["page"]["truncated"], true);
    assert_eq!(structured["page"]["has_more"], true);
    assert_eq!(
        structured["data"]["rules"].as_array().expect("rows").len(),
        50
    );
    assert_eq!(structured["data"]["rules"][0]["risk_score"], json!(42.75));
    assert!(structured["data"]["rules"][0].get("actions").is_none());
    assert!(!reply.to_string().contains("secret-action-sentinel"));
    let requests = stack.requests().await;
    assert_only_gets(&requests);
    assert_eq!(
        request_paths(&requests),
        vec![(
            "GET".to_string(),
            "/api/detection_engine/rules/_find".to_string()
        )]
    );
    assert!(
        !requests[0].query.contains_key("filter"),
        "all omits source filter"
    );
    assert_eq!(
        requests[0].query.get("per_page"),
        Some(&"10000".to_string())
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn rules_list_preserves_string_filters_and_maps_each_source_scope() {
    let mut custom = rule("custom", "Custom");
    custom["immutable"] = json!(false);
    let mut prebuilt = rule("prebuilt", "Prebuilt");
    prebuilt["immutable"] = json!(true);
    let mut customized = rule("customized", "Customized");
    customized["immutable"] = json!(true);
    customized["rule_source"] = json!({"isCustomized": true});
    let stack = MockStack::with_rules(vec![custom, prebuilt, customized]).await;
    let mut harness = Harness::start(target_for(&stack), options());
    for (id, source, expected_filter) in [
        (1, "custom", "alert.attributes.params.immutable: false"),
        (
            2,
            "customized",
            "alert.attributes.params.ruleSource.isCustomized: true",
        ),
        (3, "prebuilt", "alert.attributes.params.immutable: true"),
    ] {
        let reply = call(
            &mut harness,
            id,
            "rules_list",
            json!({"source": source, "limit": 200}),
        )
        .await;
        assert_eq!(reply["result"]["isError"], false);
        assert_eq!(
            reply["result"]["structuredContent"]["page"]["truncated"],
            false
        );
        assert_eq!(
            reply["result"]["structuredContent"]["page"]["has_more"],
            false
        );
        let requests = stack.requests().await;
        assert_eq!(
            requests
                .last()
                .and_then(|request| request.query.get("filter")),
            Some(&expected_filter.to_string())
        );
    }
    let reply = call(
        &mut harness,
        4,
        "rules_list",
        json!({"rule_type": "future-rule-kind", "severity": "future-severity", "tag": "elasticctl-sample", "search": "猫"}),
    )
    .await;
    assert_eq!(reply["result"]["isError"], false);
    let requests = stack.requests().await;
    assert_only_gets(&requests);
    let filter = requests
        .last()
        .and_then(|request| request.query.get("filter"))
        .expect("filter query");
    assert!(filter.contains("future-rule-kind"));
    assert!(filter.contains("future-severity"));
    assert!(filter.contains("猫"));
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn rules_get_projects_only_safe_fields_and_matches_current_and_legacy_data() {
    let selector = "  selected-rule\t";
    let stack = MockStack::with_rules(vec![rule(selector, "Selected Rule")]).await;
    let mut harness = Harness::start(target_for(&stack), options());
    let tools = current_tools(&mut harness, 1).await;
    let schema = tool(&tools, "rules_get")["outputSchema"].clone();
    let current = call(&mut harness, 2, "rules_get", json!({"selector": selector})).await;
    let structured = &current["result"]["structuredContent"];
    assert_eq!(current["result"]["isError"], false);
    assert_success_schema(
        &schema,
        structured,
        &[
            "rule_id",
            "name",
            "type",
            "enabled",
            "severity",
            "risk_score",
            "tags",
            "description",
            "language",
            "query",
            "index",
            "from",
            "interval",
            "exceptions_list",
        ],
        &["rule_id"],
        false,
    );
    assert_eq!(structured["page"], Value::Null);
    assert_eq!(structured["data"]["rule_id"], selector);
    assert_eq!(structured["data"]["risk_score"], json!(42.75));
    assert_object_keys(
        &structured["data"]["exceptions_list"][0],
        &["list_id", "namespace_type", "type"],
    );
    for sentinel in [
        "volatile-exception-id",
        "secret-action-sentinel",
        "identity-sentinel",
        "execution-sentinel",
    ] {
        assert!(!current.to_string().contains(sentinel), "leaked {sentinel}");
    }
    let data = property_schema(
        &schema,
        root_branch(&schema, &["target", "data", "page"]),
        "data",
    );
    for key in [
        "rule_id",
        "name",
        "type",
        "severity",
        "description",
        "language",
        "query",
        "from",
        "interval",
    ] {
        assert!(schema_allows_type(
            &schema,
            &data["properties"][key],
            "string"
        ));
    }
    assert!(schema_allows_type(
        &schema,
        &data["properties"]["enabled"],
        "boolean"
    ));
    assert!(schema_allows_type(
        &schema,
        &data["properties"]["risk_score"],
        "number"
    ));
    let tags = schema_branch_for_type(&schema, &data["properties"]["tags"], "array");
    assert!(schema_allows_type(&schema, &tags["items"], "string"));
    let index = schema_branch_for_type(&schema, &data["properties"]["index"], "array");
    assert!(schema_allows_type(&schema, &index["items"], "string"));
    let exceptions =
        schema_branch_for_type(&schema, &data["properties"]["exceptions_list"], "array");
    let exception = resolve_local_ref(&schema, &exceptions["items"]);
    assert_schema_object(
        &schema,
        exception,
        &["list_id", "namespace_type", "type"],
        &[],
    );
    for key in ["list_id", "namespace_type", "type"] {
        assert!(schema_allows_type(
            &schema,
            &exception["properties"][key],
            "string"
        ));
    }
    let current_requests = stack.requests().await;
    assert_eq!(
        request_paths(&current_requests),
        vec![
            ("GET".to_string(), "/api/detection_engine/rules".to_string()),
            ("GET".to_string(), "/api/detection_engine/rules".to_string()),
        ]
    );
    assert!(current_requests.iter().all(|request| {
        request.query.get("rule_id") == Some(&selector.to_string())
            && request.path != "/api/detection_engine/rules/_find"
    }));
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let mut legacy = Harness::start(target_for(&stack), options());
    legacy.send_json(support::legacy_initialize(3)).await;
    assert_eq!(legacy.receive_json().await["id"], 3);
    let legacy_reply =
        legacy_call(&mut legacy, 4, "rules_get", json!({"selector": selector})).await;
    assert_eq!(legacy_reply["result"]["isError"], false);
    assert_eq!(legacy_reply["result"]["structuredContent"], *structured);
    legacy.close_input();
    legacy.join().await.expect("clean EOF");
    assert_only_gets(&stack.requests().await);
}

#[tokio::test]
async fn rules_get_omits_absent_or_null_optional_fields_and_preserves_a_fitting_unicode_query() {
    let mut sparse = json!({
        "rule_id": "sparse",
        "name": Value::Null,
        "description": Value::Null,
        "query": Value::Null,
        "exceptions_list": Value::Null
    });
    let fitting_query = "猫".repeat(80_000);
    let mut unicode = rule("unicode", "Unicode Rule");
    unicode["query"] = json!(fitting_query.clone());
    let stack = MockStack::with_rules(vec![sparse.take(), unicode]).await;
    let mut harness = Harness::start(target_for(&stack), options());
    let sparse_reply = call(&mut harness, 1, "rules_get", json!({"selector": "sparse"})).await;
    assert_eq!(sparse_reply["result"]["isError"], false);
    assert_object_keys(
        &sparse_reply["result"]["structuredContent"]["data"],
        &["rule_id"],
    );

    let unicode_reply = call(&mut harness, 2, "rules_get", json!({"selector": "unicode"})).await;
    assert_eq!(unicode_reply["result"]["isError"], false);
    assert_eq!(
        unicode_reply["result"]["structuredContent"]["data"]["query"],
        fitting_query
    );
    assert_only_gets(&stack.requests().await);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn rule_inputs_are_closed_and_validate_every_string_before_requests() {
    let stack = MockStack::with_rules(vec![rule("selected-rule", "Selected Rule")]).await;
    let mut harness = Harness::start(target_for(&stack), options());
    let invalid = [
        ("rules_get", json!({"selector": " \t "})),
        ("rules_get", json!({"selector": "x".repeat(1025)})),
        ("rules_get", json!({"selector": "é".repeat(513)})),
        ("rules_list", json!({"rule_type": " \n "})),
        ("rules_list", json!({"rule_type": "x".repeat(1025)})),
        ("rules_list", json!({"severity": " \n "})),
        ("rules_list", json!({"severity": "x".repeat(1025)})),
        ("rules_list", json!({"tag": " \n "})),
        ("rules_list", json!({"tag": "x".repeat(1025)})),
        ("rules_list", json!({"search": " \n "})),
        ("rules_list", json!({"search": "x".repeat(1025)})),
        ("rules_list", json!({"source": "unknown-source"})),
        ("rules_list", json!({"source": ["custom", "prebuilt"]})),
        ("rules_list", json!({"source": null})),
        ("rules_list", json!({"limit": null})),
        ("rules_list", json!({"limit": -1})),
        ("rules_list", json!({"limit": 1.5})),
        ("rules_list", json!({"limit": "1"})),
        ("rules_list", json!({"limit": 0})),
        ("rules_list", json!({"limit": 201})),
        ("rules_list", json!({"unknown": "private-input-sentinel"})),
        ("rules_prebuilt_status", json!({"unknown": true})),
    ];
    for (id, (name, arguments)) in invalid.into_iter().enumerate() {
        let reply = call(&mut harness, id as u64 + 1, name, arguments).await;
        assert_eq!(reply["result"]["isError"], true);
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"],
            "invalid_argument"
        );
        assert!(!reply.to_string().contains("private-input-sentinel"));
    }
    assert!(
        stack.requests().await.is_empty(),
        "invalid arguments made requests"
    );

    let exact_search = format!("{}x", "猫".repeat(341));
    assert_eq!(exact_search.len(), 1024);
    for (id, name, arguments) in vec![
        (34, "rules_list", json!({"enabled": null})),
        (35, "rules_list", json!({"rule_type": null})),
        (36, "rules_list", json!({"severity": null})),
        (37, "rules_list", json!({"tag": null})),
        (38, "rules_list", json!({"search": null})),
        (40, "rules_get", json!({"selector": "x".repeat(1024)})),
        (41, "rules_get", json!({"selector": "é".repeat(512)})),
        (42, "rules_list", json!({"rule_type": "x".repeat(1024)})),
        (43, "rules_list", json!({"severity": "é".repeat(512)})),
        (44, "rules_list", json!({"tag": "x".repeat(1024)})),
        (45, "rules_list", json!({"search": exact_search.clone()})),
    ] {
        let reply = call(&mut harness, id, name, arguments).await;
        assert_ne!(
            reply["result"]["structuredContent"]["error"]["code"],
            "invalid_argument"
        );
    }
    let requests = stack.requests().await;
    assert!(!requests.is_empty(), "valid boundaries made no requests");
    assert!(requests.iter().any(|request| {
        request
            .query
            .get("filter")
            .is_some_and(|filter| filter.contains(&exact_search))
    }));
    let enabled = call(&mut harness, 46, "rules_list", json!({"enabled": true})).await;
    assert_ne!(
        enabled["result"]["structuredContent"]["error"]["code"],
        "invalid_argument"
    );
    assert_eq!(
        stack
            .requests()
            .await
            .last()
            .and_then(|request| request.query.get("filter"))
            .map(String::as_str),
        Some("alert.attributes.enabled: true")
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn rules_get_keeps_exact_selector_ambiguity_and_empty_lists_truthful() {
    let stack = MockStack::with_rules(vec![rule("first", "Same"), rule("second", "Same")]).await;
    let mut harness = Harness::start(target_for(&stack), options());
    let reply = call(&mut harness, 1, "rules_get", json!({"selector": "Same"})).await;
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["kind"],
        "conflict"
    );
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["code"],
        "elastic_conflict"
    );
    assert_eq!(
        request_paths(&stack.requests().await),
        vec![
            ("GET".to_string(), "/api/detection_engine/rules".to_string()),
            (
                "GET".to_string(),
                "/api/detection_engine/rules/_find".to_string()
            ),
        ]
    );
    assert_only_gets(&stack.requests().await);
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let empty = MockStack::with_rules(vec![]).await;
    let mut harness = Harness::start(target_for(&empty), options());
    let reply = call(&mut harness, 2, "rules_list", json!({"limit": 200})).await;
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(reply["result"]["isError"], false);
    assert_eq!(structured["data"]["rules"], json!([]));
    assert_eq!(
        structured["page"],
        json!({"limit": 200, "returned": 0, "total": 0, "has_more": false, "truncated": false})
    );
    assert_only_gets(&empty.requests().await);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn source_partition_and_feature_failures_remain_errors_without_partial_rows() {
    let stack = MockStack::with_source_totals(0, 0, 1).await;
    let mut harness = Harness::start(target_for(&stack), options());
    let reply = call(&mut harness, 1, "rules_list", json!({"source": "custom"})).await;
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["code"],
        "elastic_unsupported"
    );
    assert!(reply["result"]["structuredContent"].get("data").is_none());
    assert_only_gets(&stack.requests().await);
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.5.0", "build_flavor": "traditional"}
        })))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for_server(&server), options());
    for (id, name, arguments) in [
        (2, "rules_list", json!({"source": "prebuilt"})),
        (3, "rules_prebuilt_status", json!({})),
    ] {
        let reply = call(&mut harness, id, name, arguments).await;
        assert_eq!(reply["result"]["isError"], true);
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["kind"],
            "unsupported"
        );
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"],
            "elastic_unsupported"
        );
    }
    let requests = server.received_requests().await.expect("request log");
    assert!(requests.iter().all(|request| request.method == "GET"));
    assert!(
        requests
            .iter()
            .all(|request| request.url.path() == "/api/status")
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn prebuilt_status_projects_counters_and_oversized_rule_results_fail_closed() {
    let status = json!({
        "rules_installed": 10,
        "rules_custom_installed": 2,
        "rules_not_installed": 3,
        "rules_not_updated": 4,
        "timelines_installed": 5,
        "timelines_not_installed": 6,
        "timelines_not_updated": 7,
        "private": "status-sentinel"
    });
    let stack = MockStack::with_prebuilt_status(status, 8).await;
    let mut harness = Harness::start(target_for(&stack), options());
    let tools = current_tools(&mut harness, 1).await;
    let schema = tool(&tools, "rules_prebuilt_status")["outputSchema"].clone();
    let reply = call(&mut harness, 2, "rules_prebuilt_status", json!({})).await;
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(reply["result"]["isError"], false);
    assert_success_schema(
        &schema,
        structured,
        &[
            "installed",
            "not_installed",
            "not_updated",
            "custom_installed",
            "customized",
            "timelines_installed",
            "timelines_not_installed",
            "timelines_not_updated",
        ],
        &[
            "installed",
            "not_installed",
            "not_updated",
            "custom_installed",
            "customized",
            "timelines_installed",
            "timelines_not_installed",
            "timelines_not_updated",
        ],
        false,
    );
    let data = property_schema(
        &schema,
        root_branch(&schema, &["target", "data", "page"]),
        "data",
    );
    for key in [
        "installed",
        "not_installed",
        "not_updated",
        "custom_installed",
        "customized",
        "timelines_installed",
        "timelines_not_installed",
        "timelines_not_updated",
    ] {
        assert!(schema_allows_type(
            &schema,
            &data["properties"][key],
            "integer"
        ));
    }
    for value in structured["data"]
        .as_object()
        .expect("counter object")
        .values()
    {
        assert!(value.is_u64());
    }
    assert_eq!(structured["data"]["customized"], 8);
    assert!(!reply.to_string().contains("status-sentinel"));
    assert_only_gets(&stack.requests().await);
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let mut oversized = rule("oversized", "x".repeat(262_145));
    oversized["description"] = json!("description-sentinel");
    let stack = MockStack::with_rules(vec![oversized]).await;
    let mut harness = Harness::start(target_for(&stack), ServerOptions::default());
    for (id, name, arguments) in [
        (3, "rules_list", json!({"limit": 1})),
        (4, "rules_get", json!({"selector": "oversized"})),
    ] {
        let reply = call(&mut harness, id, name, arguments).await;
        assert_eq!(reply["result"]["isError"], true);
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"],
            "result_too_large"
        );
        assert!(reply["result"]["structuredContent"].get("data").is_none());
    }
    assert_only_gets(&stack.requests().await);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn rules_list_byte_cap_keeps_one_complete_fitting_row_and_truthful_page_metadata() {
    let stack = MockStack::with_rules(vec![
        rule("first", "x".repeat(150_000)),
        rule("second", "y".repeat(150_000)),
    ])
    .await;
    let mut harness = Harness::start(target_for(&stack), options());
    let reply = call(&mut harness, 1, "rules_list", json!({"limit": 2})).await;
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(reply["result"]["isError"], false);
    assert_eq!(
        structured["data"]["rules"].as_array().expect("rows").len(),
        1
    );
    assert_eq!(structured["data"]["rules"][0]["rule_id"], "first");
    assert_eq!(
        structured["page"],
        json!({"limit": 2, "returned": 1, "total": 2, "has_more": true, "truncated": true})
    );
    assert_only_gets(&stack.requests().await);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn rule_api_failures_use_each_tool_schema_and_redact_remote_sentinels() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.5.1", "build_flavor": "traditional"}
        })))
        .mount(&server)
        .await;
    for route in [
        "/api/detection_engine/rules/_find",
        "/api/detection_engine/rules",
        "/api/detection_engine/rules/prepackaged/_status",
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "message": "private-credential remote-error-sentinel"
            })))
            .mount(&server)
            .await;
    }
    let mut harness = Harness::start(target_for_server(&server), options());
    let tools = current_tools(&mut harness, 1).await;
    for (id, name, arguments) in [
        (2, "rules_list", json!({})),
        (3, "rules_get", json!({"selector": "selected"})),
        (4, "rules_prebuilt_status", json!({})),
    ] {
        let schema = tool(&tools, name)["outputSchema"].clone();
        let reply = call(&mut harness, id, name, arguments).await;
        assert_eq!(reply["result"]["isError"], true);
        assert_failure_schema(&schema, &reply["result"]["structuredContent"]);
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["kind"],
            "permission"
        );
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"],
            "elastic_permission"
        );
        let text = reply["result"]["content"].as_array().expect("content")[0]["text"]
            .as_str()
            .expect("text");
        assert_eq!(
            serde_json::from_str::<Value>(text).expect("structured text"),
            reply["result"]["structuredContent"]
        );
        for sentinel in [
            "test-api-key",
            "private-credential",
            "remote-error-sentinel",
        ] {
            assert!(!reply.to_string().contains(sentinel), "leaked {sentinel}");
        }
    }
    let requests = server.received_requests().await.expect("request log");
    assert!(requests.iter().all(|request| request.method == "GET"));
    assert!(
        requests
            .iter()
            .all(|request| is_allowed_read_path(request.url.path()))
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}
