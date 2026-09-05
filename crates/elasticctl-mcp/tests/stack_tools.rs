mod support;

use elasticctl_core::{Profile, Resolved, Source};
use elasticctl_mcp::ServerOptions;
use serde_json::{Value, json};
use support::{EXPECTED_TOOL_NAMES, Harness, current_metadata, options, target};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn recorded(name: &str) -> Value {
    let body = match name {
        "authenticate" => include_str!("../../../tests/fixtures/ech-9.5.2/authenticate.json"),
        "license" => include_str!("../../../tests/fixtures/ech-9.5.2/license.json"),
        "rules_find" => include_str!("../../../tests/fixtures/ech-9.5.2/rules_find.json"),
        "spaces" => include_str!("../../../tests/fixtures/ech-9.5.2/spaces.json"),
        "status" => include_str!("../../../tests/fixtures/ech-9.5.2/status.json"),
        "serverless_status" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/status.json")
        }
        _ => panic!("unknown recorded response: {name}"),
    };
    serde_json::from_str::<Value>(body)
        .expect("recording parses")
        .get("response")
        .expect("recording has response")
        .clone()
}

async fn mount_recorded_absent_list_index(server: &MockServer, route: &str) {
    let recording: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/ech-9.5.2/lists_index.json"
    ))
    .expect("recording parses");
    let error = recording.get("error").expect("recording has error");
    Mock::given(method("GET"))
        .and(path(route.to_string()))
        .respond_with(
            ResponseTemplate::new(
                error["http_status"].as_u64().expect("recorded HTTP status") as u16
            )
            .set_body_json(json!({
                "statusCode": error["http_status"],
                "error": "Not Found",
                "message": error["message"],
            })),
        )
        .mount(server)
        .await;
}

fn target_for(server: &MockServer, api_key: Option<&str>) -> Resolved {
    let uri = server.uri();
    Resolved {
        name: "test".to_string(),
        source: Source::Profile,
        profile: Profile {
            kibana_url: uri.clone(),
            es_url: Some(uri),
            api_key: api_key.map(str::to_string),
            username: None,
            password: None,
            space: "default".to_string(),
            verify: true,
            timeout_secs: 30,
        },
    }
}

fn target_with_base_path(server: &MockServer, base_path: &str) -> Resolved {
    let mut target = target_for(server, Some("test-api-key"));
    let uri = server.uri();
    target.profile.kibana_url = format!("{uri}{base_path}");
    target.profile.es_url = Some(format!("{uri}{base_path}"));
    target
}

async fn mount_json(server: &MockServer, route: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path(route.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn mount_status(server: &MockServer, route: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path(route.to_string()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-found-handling-cluster", "test-cluster")
                .set_body_json(body),
        )
        .mount(server)
        .await;
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

async fn current_tools(harness: &mut Harness, id: u64) -> Value {
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list",
            "params": { "_meta": current_metadata() },
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], id);
    reply["result"]["tools"].clone()
}

async fn legacy_call(harness: &mut Harness, id: u64, name: &str, arguments: Value) -> Value {
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
            },
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], id);
    reply
}

fn tool<'a>(tools: &'a Value, name: &str) -> &'a Value {
    tools
        .as_array()
        .expect("tools is an array")
        .iter()
        .find(|tool| tool["name"] == name)
        .expect("registered stack tool")
}

fn keys(value: &Value) -> Vec<String> {
    let mut keys = value
        .as_object()
        .expect("value is an object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

fn expected_keys(fields: &[&str]) -> Vec<String> {
    let mut expected = fields
        .iter()
        .map(|field| (*field).to_string())
        .collect::<Vec<_>>();
    expected.sort();
    expected
}

fn assert_object_keys(value: &Value, fields: &[&str]) {
    assert_eq!(keys(value), expected_keys(fields));
}

fn resolve_local_ref<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    let mut resolved = schema;
    while let Some(reference) = resolved.get("$ref").and_then(Value::as_str) {
        let pointer = reference
            .strip_prefix('#')
            .expect("schema only uses local references");
        resolved = root.pointer(pointer).expect("local reference resolves");
    }
    resolved
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
                .is_some_and(|properties| keys(properties) == expected_keys(fields))
        })
        .unwrap_or_else(|| panic!("root anyOf did not declare properties {:?}", fields))
}

fn schema_properties(schema: &Value) -> &Value {
    schema.get("properties").expect("object properties")
}

fn assert_schema_object(root: &Value, schema: &Value, fields: &[&str], required_fields: &[&str]) {
    assert!(schema_allows_type(root, schema, "object"));
    assert_object_keys(schema_properties(schema), fields);
    schema_required(schema, required_fields);
}

fn property_schema<'a>(root: &'a Value, object: &'a Value, property: &str) -> &'a Value {
    resolve_local_ref(root, &schema_properties(object)[property])
}

fn schema_required(schema: &Value, fields: &[&str]) {
    let required = schema["required"].as_array().expect("required fields");
    let mut names = required
        .iter()
        .map(|field| field.as_str().expect("required name").to_string())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, expected_keys(fields));
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

fn assert_property_type(root: &Value, schema: &Value, property: &str, expected: &str) {
    assert!(
        schema_allows_type(root, property_schema(root, schema, property), expected),
        "{property} does not allow {expected}: {}",
        schema_properties(schema)[property]
    );
}

fn assert_success_schema(
    schema: &Value,
    structured: &Value,
    data_fields: &[&str],
    required_data_fields: &[&str],
) {
    assert_object_keys(structured, &["target", "data", "page"]);
    assert_object_keys(&structured["target"], &["profile", "host", "space"]);
    assert_object_keys(&structured["data"], data_fields);
    assert_eq!(structured["page"], Value::Null);

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
    for property in ["profile", "host", "space"] {
        assert_property_type(schema, target, property, "string");
    }
    assert!(schema_allows_type(
        schema,
        property_schema(schema, success, "page"),
        "null"
    ));

    let data = property_schema(schema, success, "data");
    assert_schema_object(schema, data, data_fields, required_data_fields);
}

fn assert_failure_schema(schema: &Value, structured: &Value) {
    assert_object_keys(structured, &["target", "error"]);
    assert_object_keys(&structured["target"], &["profile", "host", "space"]);
    assert_object_keys(
        &structured["error"],
        &["kind", "http_status", "code", "message"],
    );

    let failure = root_branch(schema, &["target", "error"]);
    assert_schema_object(schema, failure, &["target", "error"], &["target", "error"]);
    let target = property_schema(schema, failure, "target");
    assert_schema_object(
        schema,
        target,
        &["profile", "host", "space"],
        &["profile", "host", "space"],
    );
    let error = property_schema(schema, failure, "error");
    assert_schema_object(
        schema,
        error,
        &["kind", "http_status", "code", "message"],
        &["kind", "code", "message"],
    );
    for property in ["kind", "code", "message"] {
        assert_property_type(schema, error, property, "string");
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

async fn routes(server: &MockServer) -> Vec<(String, String)> {
    server
        .received_requests()
        .await
        .expect("request recording remains enabled")
        .into_iter()
        .map(|request| (request.method.to_string(), request.url.path().to_string()))
        .collect()
}

async fn mount_healthy_doctor_routes(server: &MockServer, prefix: &str, version: &str) {
    let mut status = recorded("status");
    status["version"]["number"] = json!(version);
    mount_status(server, &format!("{prefix}/api/status"), status).await;
    mount_json(
        server,
        &format!("{prefix}/_security/_authenticate"),
        recorded("authenticate"),
    )
    .await;
    mount_json(
        server,
        &format!("{prefix}/api/detection_engine/rules/_find"),
        recorded("rules_find"),
    )
    .await;
    mount_recorded_absent_list_index(server, &format!("{prefix}/api/lists/index")).await;
}

#[tokio::test]
async fn stack_catalog_has_closed_schemas_static_descriptions_and_read_only_annotations() {
    let mut harness = Harness::start(target(), options());
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": { "_meta": current_metadata() },
        }))
        .await;
    let reply = harness.receive_json().await;
    let tools = reply["result"]["tools"]
        .as_array()
        .expect("tools is an array");
    let names = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();
    assert_eq!(names, EXPECTED_TOOL_NAMES);
    let expected_tools = tools.clone();

    for (name, description) in [
        (
            "stack_doctor",
            "Run read-only health checks against the selected Elastic stack.",
        ),
        (
            "stack_info",
            "Inspect the selected Elastic stack version, flavor, license tier, and spaces.",
        ),
    ] {
        let tool = tools
            .iter()
            .find(|tool| tool["name"] == name)
            .expect("registered stack tool");
        assert_eq!(tool["description"], description);
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert!(tool["inputSchema"].get("properties").is_none());
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        assert_eq!(
            tool["annotations"],
            json!({
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": true,
            })
        );
        assert_eq!(
            tool["outputSchema"]["anyOf"]
                .as_array()
                .expect("success and failure alternatives")
                .len(),
            2
        );
        assert_eq!(tool["outputSchema"]["type"], "object");
    }

    harness.close_input();
    harness.join().await.expect("clean EOF");

    let mut legacy = Harness::start(target(), options());
    legacy.send_json(support::legacy_initialize(11)).await;
    assert_eq!(legacy.receive_json().await["id"], 11);
    legacy
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/list",
            "params": {},
        }))
        .await;
    let legacy_reply = legacy.receive_json().await;
    assert_eq!(legacy_reply["id"], 12);
    assert_eq!(
        legacy_reply["result"]["tools"],
        Value::Array(expected_tools)
    );
    legacy.close_input();
    legacy.join().await.expect("clean EOF");
}

#[tokio::test]
async fn stack_info_projects_recorded_data_and_only_uses_its_route_allowlist() {
    let server = MockServer::start().await;
    mount_status(&server, "/api/status", recorded("status")).await;
    mount_json(&server, "/api/spaces/space", recorded("spaces")).await;
    mount_json(&server, "/_license", recorded("license")).await;

    let mut harness = Harness::start(target_for(&server, Some("test-api-key")), options());
    let tools = current_tools(&mut harness, 1).await;
    let output_schema = tool(&tools, "stack_info")["outputSchema"].clone();
    let reply = call(&mut harness, 2, "stack_info", json!({})).await;
    let result = &reply["result"];
    assert_eq!(result["isError"], false);
    let structured = result["structuredContent"].clone();
    assert_success_schema(
        &output_schema,
        &structured,
        &["version", "flavor", "license", "spaces"],
        &["version", "flavor"],
    );
    let info_schema = property_schema(
        &output_schema,
        root_branch(&output_schema, &["target", "data", "page"]),
        "data",
    );
    for property in ["version", "flavor"] {
        assert_property_type(&output_schema, info_schema, property, "string");
    }
    for property in ["license", "spaces"] {
        assert!(schema_allows_type(
            &output_schema,
            &info_schema["properties"][property],
            "null"
        ));
    }
    assert_property_type(&output_schema, info_schema, "license", "string");
    assert_property_type(&output_schema, info_schema, "spaces", "array");
    let data = &result["structuredContent"]["data"];
    assert_eq!(
        data,
        &json!({
            "version": "9.5.2",
            "flavor": "elastic-cloud-hosted",
            "license": "enterprise",
            "spaces": ["default"],
        })
    );
    assert_eq!(result["structuredContent"]["page"], Value::Null);
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let mut legacy = Harness::start(target_for(&server, Some("test-api-key")), options());
    legacy.send_json(support::legacy_initialize(3)).await;
    assert_eq!(legacy.receive_json().await["id"], 3);
    let legacy_reply = legacy_call(&mut legacy, 4, "stack_info", json!({})).await;
    assert_eq!(legacy_reply["result"]["isError"], false);
    assert_eq!(legacy_reply["result"].get("resultType"), None);
    assert_eq!(legacy_reply["result"]["structuredContent"], structured);
    legacy.close_input();
    legacy.join().await.expect("clean EOF");

    assert_eq!(
        routes(&server).await,
        vec![
            ("GET".to_string(), "/api/status".to_string()),
            ("GET".to_string(), "/api/spaces/space".to_string()),
            ("GET".to_string(), "/_license".to_string()),
            ("GET".to_string(), "/api/status".to_string()),
            ("GET".to_string(), "/api/spaces/space".to_string()),
            ("GET".to_string(), "/_license".to_string()),
        ]
    );
}

#[tokio::test]
async fn stack_info_preserves_unknown_license_and_spaces_as_null() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(recorded("serverless_status")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/spaces/space"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "unknown"})))
        .mount(&server)
        .await;

    let mut harness = Harness::start(target_for(&server, Some("test-api-key")), options());
    let reply = call(&mut harness, 3, "stack_info", json!({})).await;
    assert_eq!(reply["result"]["isError"], false);
    let data = &reply["result"]["structuredContent"]["data"];
    assert_eq!(data["version"], "9.6.0");
    assert_eq!(data["flavor"], "serverless");
    assert_eq!(data["license"], Value::Null);
    assert_eq!(data["spaces"], Value::Null);
    assert_eq!(
        routes(&server).await,
        vec![
            ("GET".to_string(), "/api/status".to_string()),
            ("GET".to_string(), "/api/spaces/space".to_string()),
        ]
    );

    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn stack_doctor_preserves_check_statuses_without_leaking_details() {
    let server = MockServer::start().await;
    let prefix = "/private-sentinel";
    let mut status = recorded("status");
    status["version"]["number"] = json!("9.5.2");
    mount_status(&server, &format!("{prefix}/api/status"), status).await;

    let mut identity = recorded("authenticate");
    identity["username"] = json!("identity42");
    mount_json(
        &server,
        &format!("{prefix}/_security/_authenticate"),
        identity,
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("{prefix}/api/detection_engine/rules/_find")))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "message": "private-credential private-sentinel raw-error-marker"
        })))
        .mount(&server)
        .await;
    mount_recorded_absent_list_index(&server, &format!("{prefix}/api/lists/index")).await;

    let mut harness = Harness::start(target_with_base_path(&server, prefix), options());
    let tools = current_tools(&mut harness, 3).await;
    let output_schema = tool(&tools, "stack_doctor")["outputSchema"].clone();
    let reply = call(&mut harness, 4, "stack_doctor", json!({})).await;
    let result = &reply["result"];
    assert_eq!(result["isError"], false);
    assert_success_schema(
        &output_schema,
        &result["structuredContent"],
        &["ok", "checks"],
        &["ok", "checks"],
    );
    let doctor_schema = property_schema(
        &output_schema,
        root_branch(&output_schema, &["target", "data", "page"]),
        "data",
    );
    assert_property_type(&output_schema, doctor_schema, "ok", "boolean");
    assert_property_type(&output_schema, doctor_schema, "checks", "array");
    let checks_schema = property_schema(&output_schema, doctor_schema, "checks");
    let check_schema = resolve_local_ref(&output_schema, &checks_schema["items"]);
    assert_schema_object(
        &output_schema,
        check_schema,
        &["check", "status"],
        &["check", "status"],
    );
    assert_property_type(&output_schema, check_schema, "check", "string");
    assert_property_type(&output_schema, check_schema, "status", "string");
    assert_eq!(result["structuredContent"]["data"]["ok"], false);
    let checks = result["structuredContent"]["data"]["checks"]
        .as_array()
        .expect("checks is an array");
    assert_eq!(
        checks,
        &[
            json!({"check": "connectivity", "status": "ok"}),
            json!({"check": "flavor", "status": "ok"}),
            json!({"check": "auth", "status": "ok"}),
            json!({"check": "key_scope", "status": "ok"}),
            json!({"check": "rules_access", "status": "fail"}),
            json!({"check": "value_list_index", "status": "warn"}),
        ]
    );
    for check in checks {
        assert_object_keys(check, &["check", "status"]);
    }
    for sentinel in [
        "identity42",
        "private-credential",
        "private-sentinel",
        "raw-error-marker",
    ] {
        assert!(!reply.to_string().contains(sentinel), "leaked {sentinel}");
    }
    assert_eq!(
        routes(&server).await,
        vec![
            ("GET".to_string(), format!("{prefix}/api/status")),
            (
                "GET".to_string(),
                format!("{prefix}/_security/_authenticate")
            ),
            (
                "GET".to_string(),
                format!("{prefix}/api/detection_engine/rules/_find"),
            ),
            ("GET".to_string(), format!("{prefix}/api/lists/index")),
        ]
    );

    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn invalid_stack_arguments_are_rejected_without_constructing_a_transport() {
    let server = MockServer::start().await;
    let mut harness = Harness::start(target_for(&server, Some("test-api-key")), options());

    for (id, name) in [(5, "stack_info"), (6, "stack_doctor")] {
        let reply = call(&mut harness, id, name, json!({"unexpected": true})).await;
        assert_eq!(reply["result"]["isError"], true);
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"],
            "invalid_argument"
        );
        assert!(!reply.to_string().contains("unexpected"));
    }
    assert!(routes(&server).await.is_empty());

    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn stack_doctor_reports_missing_credentials_as_a_tool_error() {
    let server = MockServer::start().await;
    let mut harness = Harness::start(target_for(&server, None), options());
    let tools = current_tools(&mut harness, 6).await;
    let output_schema = tool(&tools, "stack_doctor")["outputSchema"].clone();
    let reply = call(&mut harness, 7, "stack_doctor", json!({})).await;
    assert_eq!(reply["result"]["isError"], true);
    assert_failure_schema(&output_schema, &reply["result"]["structuredContent"]);
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["kind"],
        "auth"
    );
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["code"],
        "elastic_auth"
    );
    assert!(routes(&server).await.is_empty());

    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn stack_info_maps_remote_failures_to_static_redacted_tool_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "message": "private-credential raw-error-marker"
        })))
        .mount(&server)
        .await;

    let mut harness = Harness::start(target_for(&server, Some("test-api-key")), options());
    let tools = current_tools(&mut harness, 8).await;
    let output_schema = tool(&tools, "stack_info")["outputSchema"].clone();
    let reply = call(&mut harness, 9, "stack_info", json!({})).await;
    let result = &reply["result"];
    let structured = &result["structuredContent"];
    assert_eq!(result["isError"], true);
    assert_failure_schema(&output_schema, structured);
    assert_eq!(
        structured,
        &json!({
            "target": {
                "profile": "test",
                "host": server.uri().trim_start_matches("http://"),
                "space": "default",
            },
            "error": {
                "kind": "permission",
                "http_status": 403,
                "code": "elastic_permission",
                "message": "The selected credential cannot read this data.",
            },
        })
    );
    let text = result["content"].as_array().expect("text content array")[0]["text"]
        .as_str()
        .expect("text content");
    assert_eq!(
        serde_json::from_str::<Value>(text).expect("text contains structured error JSON"),
        *structured
    );
    for sentinel in ["test-api-key", "private-credential", "raw-error-marker"] {
        assert!(!reply.to_string().contains(sentinel), "leaked {sentinel}");
    }
    assert_eq!(
        routes(&server).await,
        vec![("GET".to_string(), "/api/status".to_string())]
    );

    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn stack_info_maps_an_oversized_upstream_body_to_a_static_unsupported_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(16_777_217)))
        .mount(&server)
        .await;

    let mut harness = Harness::start(target_for(&server, Some("test-api-key")), options());
    let reply = call(&mut harness, 8, "stack_info", json!({})).await;
    let error = &reply["result"]["structuredContent"]["error"];
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(error["kind"], "unsupported");
    assert_eq!(error["http_status"], Value::Null);
    assert_eq!(error["code"], "elastic_unsupported");
    assert_eq!(
        error["message"],
        "The selected deployment does not support this operation."
    );
    assert_eq!(
        routes(&server).await,
        vec![("GET".to_string(), "/api/status".to_string())]
    );

    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn stack_diagnostics_remain_available_on_an_older_target() {
    let server = MockServer::start().await;
    mount_healthy_doctor_routes(&server, "", "9.5.0").await;
    mount_json(&server, "/api/spaces/space", recorded("spaces")).await;
    mount_json(&server, "/_license", recorded("license")).await;

    let mut harness = Harness::start(
        target_for(&server, Some("test-api-key")),
        ServerOptions::default(),
    );
    let doctor = call(&mut harness, 9, "stack_doctor", json!({})).await;
    assert_eq!(doctor["result"]["isError"], false);
    assert_eq!(doctor["result"]["structuredContent"]["data"]["ok"], true);

    let info = call(&mut harness, 10, "stack_info", json!({})).await;
    assert_eq!(info["result"]["isError"], false);
    assert_eq!(
        info["result"]["structuredContent"]["data"]["version"],
        "9.5.0"
    );
    assert!(info["result"]["structuredContent"].get("error").is_none());

    harness.close_input();
    harness.join().await.expect("clean EOF");
}
