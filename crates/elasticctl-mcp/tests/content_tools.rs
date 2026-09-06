mod support;

use elasticctl_core::{Profile, Resolved, Source};
use serde_json::{Value, json};
use std::{env, process::Command};
use support::{EXPECTED_TOOL_NAMES, Harness, current_metadata, legacy_initialize, options, target};
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
            api_key: Some("test-api-key".to_string()),
            username: None,
            password: None,
            space: "default".to_string(),
            verify: true,
            timeout_secs: 30,
        },
    }
}

fn target_for_uri(uri: String) -> Resolved {
    Resolved {
        name: "stderr-child".to_string(),
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

async fn mount_status(server: &MockServer, version: &str) {
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": version, "build_flavor": "traditional"}
        })))
        .mount(server)
        .await;
}

fn content(reply: &Value) -> &Value {
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    let structured = &reply["result"]["structuredContent"];
    let text: Value = serde_json::from_str(
        reply["result"]["content"][0]["text"]
            .as_str()
            .expect("text"),
    )
    .expect("JSON text");
    assert_eq!(text, *structured);
    structured
}

fn failure(reply: &Value) -> &Value {
    assert_eq!(reply["result"]["isError"], true);
    &reply["result"]["structuredContent"]
}

fn data_view(id: &str, title: &str, name: Option<&str>) -> Value {
    let mut view = json!({"id": id, "title": title});
    if let Some(name) = name {
        view["name"] = json!(name);
    }
    view
}

fn dashboard_row(id: &str, title: &str) -> Value {
    json!({"id": id, "data": {"title": title, "tags": ["marker"]}, "meta": {"private": "list-sentinel"}})
}

fn tool<'a>(tools: &'a [Value], name: &str) -> &'a Value {
    tools
        .iter()
        .find(|tool| tool["name"] == name)
        .expect("registered content tool")
}

fn keys(value: &Value) -> Vec<&str> {
    let mut keys = value
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys
}

fn resolve<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    let mut schema = schema;
    while let Some(reference) = schema["$ref"].as_str() {
        schema = root
            .pointer(reference.strip_prefix('#').expect("local reference"))
            .expect("reference resolves");
    }
    schema
}

fn allows(root: &Value, schema: &Value, kind: &str) -> bool {
    let schema = resolve(root, schema);
    schema["type"] == kind
        || schema["type"]
            .as_array()
            .is_some_and(|types| types.iter().any(|value| value == kind))
        || schema["anyOf"]
            .as_array()
            .is_some_and(|branches| branches.iter().any(|branch| allows(root, branch, kind)))
}

fn object<'a>(
    root: &'a Value,
    schema: &'a Value,
    expected: &[&str],
    required: &[&str],
) -> &'a Value {
    let schema = resolve(root, schema);
    assert!(allows(root, schema, "object"));
    assert!(
        schema.get("additionalProperties").is_none(),
        "typed objects retain schemars' open-object default"
    );
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(keys(&schema["properties"]), expected);
    let mut actual = schema["required"]
        .as_array()
        .map(|fields| {
            fields
                .iter()
                .map(|field| field.as_str().expect("field"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    actual.sort_unstable();
    let mut required = required.to_vec();
    required.sort_unstable();
    assert_eq!(actual, required);
    schema
}

fn success_schema(schema: &Value) -> &Value {
    schema["anyOf"]
        .as_array()
        .expect("output alternatives")
        .iter()
        .map(|branch| resolve(schema, branch))
        .find(|branch| branch["properties"].get("data").is_some())
        .expect("success output")
}

fn nullable(root: &Value, schema: &Value, kind: &str, expected: bool) {
    assert!(allows(root, schema, kind));
    assert_eq!(allows(root, schema, "null"), expected);
}

fn object_branch<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    let schema = resolve(root, schema);
    if allows(root, schema, "object")
        && (schema.get("properties").is_some() || schema.get("additionalProperties").is_some())
    {
        return schema;
    }
    schema["anyOf"]
        .as_array()
        .expect("object branch")
        .iter()
        .map(|branch| resolve(root, branch))
        .find(|branch| branch["type"] == "object")
        .expect("object branch")
}

fn array_branch<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    let schema = resolve(root, schema);
    if schema.get("items").is_some() && allows(root, schema, "array") {
        return schema;
    }
    schema["anyOf"]
        .as_array()
        .expect("array branch")
        .iter()
        .map(|branch| resolve(root, branch))
        .find(|branch| branch["type"] == "array")
        .expect("array branch")
}

async fn mount_data_views(server: &MockServer, data_views: Vec<Value>) {
    Mock::given(method("GET"))
        .and(path("/api/data_views"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view": data_views})))
        .mount(server)
        .await;
}

async fn mount_dashboard_search(server: &MockServer, data: Vec<Value>) {
    let total = data.len();
    Mock::given(method("GET"))
        .and(path("/api/dashboards"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": data, "meta": {"page": 1, "per_page": 1000, "total": total}
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn content_catalog_exposes_data_view_and_dashboard_inspection_tools() {
    let mut harness = Harness::start(target(), options());
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": current_metadata()},
        }))
        .await;
    let reply = harness.receive_json().await;
    let names = reply["result"]["tools"]
        .as_array()
        .expect("tool list")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();
    assert_eq!(names, EXPECTED_TOOL_NAMES);
    let tools = reply["result"]["tools"].as_array().expect("tool list");
    let annotations = json!({"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true});
    for (name, fields, required) in [
        ("data_views_list", vec!["limit", "search"], vec![]),
        ("data_views_get", vec!["selector"], vec!["selector"]),
        ("data_views_default_get", vec![], vec![]),
        ("dashboards_list", vec!["limit", "search", "tag"], vec![]),
        ("dashboards_get", vec!["selector"], vec!["selector"]),
    ] {
        let schema = &tool(tools, name)["inputSchema"];
        assert_eq!(tool(tools, name)["annotations"], annotations);
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        if fields.is_empty() {
            assert!(schema.get("properties").is_none());
        } else {
            assert_eq!(keys(&schema["properties"]), fields);
        }
        assert_eq!(
            schema["required"]
                .as_array()
                .map(|values| values
                    .iter()
                    .map(|value| value.as_str().expect("field"))
                    .collect::<Vec<_>>())
                .unwrap_or_default(),
            required
        );
    }
    for name in ["data_views_list", "dashboards_list"] {
        let schema = &tool(tools, name)["inputSchema"];
        nullable(schema, &schema["properties"]["limit"], "integer", false);
        assert_eq!(schema["properties"]["limit"]["default"], 50);
        assert_eq!(schema["properties"]["limit"]["minimum"], 1);
        assert_eq!(schema["properties"]["limit"]["maximum"], 200);
    }
    for (name, field, description) in [
        (
            "data_views_list",
            "search",
            "Data-view id, name, or title substring. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.",
        ),
        (
            "data_views_get",
            "selector",
            "Exact data-view id or exact data-view name. Must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.",
        ),
        (
            "dashboards_list",
            "search",
            "Dashboard title substring. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.",
        ),
        (
            "dashboards_list",
            "tag",
            "Exact dashboard tag. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.",
        ),
        (
            "dashboards_get",
            "selector",
            "Exact dashboard id or exact dashboard title. Must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.",
        ),
    ] {
        let property = &tool(tools, name)["inputSchema"]["properties"][field];
        let string = property["anyOf"]
            .as_array()
            .and_then(|values| values.iter().find(|value| value["type"] == "string"))
            .unwrap_or(property);
        assert_eq!(string["minLength"], 1);
        assert_eq!(string["maxLength"], 1024);
        assert_eq!(property["description"], description);
        nullable(
            &tool(tools, name)["inputSchema"],
            property,
            "string",
            !["data_views_get", "dashboards_get"].contains(&name),
        );
    }
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let mut legacy = Harness::start(target(), options());
    legacy.send_json(legacy_initialize(2)).await;
    assert_eq!(legacy.receive_json().await["id"], 2);
    legacy.close_input();
    legacy.join().await.expect("legacy clean EOF");
}

#[tokio::test]
async fn data_view_reads_use_typed_local_filter_and_safe_detail_projection() {
    let server = MockServer::start().await;
    mount_data_views(
        &server,
        vec![
            data_view("one", "Alpha", Some("Shared")),
            data_view("two", "Beta", Some("Other")),
        ],
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view": {
            "id": "one", "title": "Alpha", "name": "Shared", "timeFieldName": "@timestamp",
            "type": "rollup", "allowNoIndex": true, "allowHidden": false,
            "sourceFilters": [{"value": "keep"}], "fieldFormats": {"message": {"id": "string"}},
            "runtimeFieldMap": {"field": {"type": "keyword"}}, "fieldAttrs": {"field": {"count": 1}},
            "typeMeta": {"params": {"allowed": true}}, "fields": {"secret": "fields-sentinel"},
            "unknown": "unknown-sentinel"
        }})))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let list_reply = call(&mut harness, 1, "data_views_list", json!({"search": "sha"})).await;
    let list = content(&list_reply);
    assert_eq!(
        list["data"]["data_views"],
        json!([{"id": "one", "title": "Alpha", "name": "Shared"}])
    );
    assert_eq!(
        list["page"],
        json!({"limit": 50, "returned": 1, "total": 1, "has_more": false, "truncated": false})
    );
    let detail_reply = call(
        &mut harness,
        2,
        "data_views_get",
        json!({"selector": "one"}),
    )
    .await;
    let detail = content(&detail_reply);
    assert_eq!(detail["page"], Value::Null);
    assert_eq!(detail["data"]["data_view"]["id"], "one");
    assert_eq!(
        detail["data"]["data_view"]["fieldFormats"]["message"]["id"],
        "string"
    );
    let encoded = serde_json::to_string(detail).expect("serializes");
    assert!(!encoded.contains("fields-sentinel"));
    assert!(!encoded.contains("unknown-sentinel"));
    assert!(
        !detail_reply["result"]["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("fields-sentinel")
    );
    assert!(
        !detail_reply["result"]["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("unknown-sentinel")
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].url.path(), "/api/data_views");
    assert_eq!(requests[1].url.path(), "/api/data_views");
    assert_eq!(requests[2].url.path(), "/api/data_views/data_view/one");
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn exact_and_ambiguous_data_view_names_have_no_fallback_detail_request() {
    let server = MockServer::start().await;
    mount_data_views(
        &server,
        vec![
            data_view("one", "One", Some("same")),
            data_view("two", "Two", Some("same")),
        ],
    )
    .await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(
        &mut harness,
        1,
        "data_views_get",
        json!({"selector": "same"}),
    )
    .await;
    assert_eq!(failure(&reply)["error"]["code"], "elastic_conflict");
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/api/data_views");
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn exact_names_resolve_and_dashboard_titles_fail_when_ambiguous() {
    let server = MockServer::start().await;
    mount_data_views(&server, vec![data_view("one", "One", Some("named"))]).await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/one"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data_view": {"id": "one", "title": "One"}})),
        )
        .mount(&server)
        .await;
    mount_status(&server, "9.5.1").await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/Shared"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(
                json!({"statusCode": 404, "error": "Not Found", "message": "private"}),
            ),
        )
        .mount(&server)
        .await;
    mount_dashboard_search(
        &server,
        vec![
            dashboard_row("one", "Shared"),
            dashboard_row("two", "Shared"),
        ],
    )
    .await;
    let mut harness = Harness::start(target_for(&server), options());
    let named = call(
        &mut harness,
        1,
        "data_views_get",
        json!({"selector": "named"}),
    )
    .await;
    assert_eq!(content(&named)["data"]["data_view"]["id"], "one");
    let ambiguous = call(
        &mut harness,
        2,
        "dashboards_get",
        json!({"selector": "Shared"}),
    )
    .await;
    assert_eq!(failure(&ambiguous)["error"]["code"], "elastic_conflict");
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/api/dashboards/Shared")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/api/dashboards")
            .count(),
        1
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn default_data_view_preserves_null_and_rejects_malformed_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view_id": null})))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view_id": 7})))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let result_reply = call(&mut harness, 1, "data_views_default_get", json!({})).await;
    let result = content(&result_reply);
    assert_eq!(result["data"], json!({"id": null}));
    assert_eq!(result["page"], Value::Null);
    let malformed = call(&mut harness, 2, "data_views_default_get", json!({})).await;
    assert_eq!(failure(&malformed)["error"]["code"], "elastic_http");
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn selected_detail_wrong_types_fail_without_projecting_raw_maps() {
    let server = MockServer::start().await;
    mount_data_views(&server, vec![data_view("one", "One", None)]).await;
    Mock::given(method("GET")).and(path("/api/data_views/data_view/one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view": {"id": "one", "title": "One", "allowNoIndex": "wrong-type-sentinel"}}))).mount(&server).await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(
        &mut harness,
        1,
        "data_views_get",
        json!({"selector": "one"}),
    )
    .await;
    assert_eq!(failure(&reply)["error"]["code"], "elastic_http");
    assert!(!reply.to_string().contains("wrong-type-sentinel"));
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let dashboard = MockServer::start().await;
    mount_status(&dashboard, "9.5.1").await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/one"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id": "one", "data": ["wrong-type-sentinel"], "meta": {}})),
        )
        .mount(&dashboard)
        .await;
    let mut harness = Harness::start(target_for(&dashboard), options());
    let reply = call(
        &mut harness,
        2,
        "dashboards_get",
        json!({"selector": "one"}),
    )
    .await;
    assert_eq!(failure(&reply)["error"]["code"], "elastic_http");
    assert!(!reply.to_string().contains("wrong-type-sentinel"));
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn stderr_child_executes_content_reads() {
    let Ok(uri) = env::var("ELASTICCTL_MCP_STDERR_CHILD_URI") else {
        return;
    };
    let mut harness = Harness::start(target_for_uri(uri), options());
    let data = call(
        &mut harness,
        1,
        "data_views_get",
        json!({"selector": "one"}),
    )
    .await;
    let dashboard = call(
        &mut harness,
        2,
        "dashboards_get",
        json!({"selector": "one"}),
    )
    .await;
    assert_eq!(content(&data)["data"]["data_view"]["id"], "one");
    assert_eq!(content(&dashboard)["data"]["id"], "one");
    for (reply, sentinels) in [
        (&data, ["stderr-fields-sentinel", "stderr-unknown-sentinel"]),
        (
            &dashboard,
            ["stderr-meta-sentinel", "stderr-warning-sentinel"],
        ),
    ] {
        let copy = reply.to_string();
        for sentinel in sentinels {
            assert!(!copy.contains(sentinel));
        }
    }
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn excluded_content_sentinels_never_reach_a_real_child_stderr() {
    let server = MockServer::start().await;
    mount_data_views(&server, vec![data_view("one", "One", None)]).await;
    Mock::given(method("GET")).and(path("/api/data_views/data_view/one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view": {"id": "one", "title": "One", "fields": {"x": "stderr-fields-sentinel"}, "unknown": "stderr-unknown-sentinel"}}))).mount(&server).await;
    mount_status(&server, "9.5.1").await;
    Mock::given(method("GET")).and(path("/api/dashboards/one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "one", "data": {"title": "One"}, "meta": {"x": "stderr-meta-sentinel"}, "warnings": [{"message": "stderr-warning-sentinel"}]}))).up_to_n_times(2).mount(&server).await;
    let executable = env::current_exe().expect("test executable");
    let uri = server.uri();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(executable)
            .arg("stderr_child_executes_content_reads")
            .arg("--exact")
            .arg("--nocapture")
            .env("ELASTICCTL_MCP_STDERR_CHILD_URI", uri)
            .output()
            .expect("child starts")
    })
    .await
    .expect("child join");
    assert!(
        output.status.success(),
        "child stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for sentinel in [
        "stderr-fields-sentinel",
        "stderr-unknown-sentinel",
        "stderr-meta-sentinel",
        "stderr-warning-sentinel",
    ] {
        assert!(!stderr.contains(sentinel), "child stderr leaked {sentinel}");
    }
    let requests = server.received_requests().await.expect("requests");
    for route in [
        "/api/data_views",
        "/api/data_views/data_view/one",
        "/api/status",
        "/api/dashboards/one",
    ] {
        assert!(
            requests.iter().any(|request| request.url.path() == route),
            "missing {route}"
        );
    }
}

#[tokio::test]
async fn dashboard_reads_forward_tag_and_exclude_meta_and_warnings() {
    let server = MockServer::start().await;
    mount_status(&server, "9.5.1").await;
    mount_dashboard_search(&server, vec![dashboard_row("dashboard-1", "Overview")]).await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dashboard-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "dashboard-1", "data": {"title": "Overview", "panels": [{"url": "https://untrusted.invalid"}]},
            "meta": {"private": "meta-sentinel"}, "warnings": [{"message": "warning-sentinel"}]
        })))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let list_reply = call(
        &mut harness,
        1,
        "dashboards_list",
        json!({"tag": "marker", "search": "view"}),
    )
    .await;
    let list = content(&list_reply);
    assert_eq!(list["data"]["dashboards"][0]["id"], "dashboard-1");
    let detail_reply = call(
        &mut harness,
        2,
        "dashboards_get",
        json!({"selector": "dashboard-1"}),
    )
    .await;
    let detail = content(&detail_reply);
    assert_eq!(
        detail["data"],
        json!({"id": "dashboard-1", "data": {"title": "Overview", "panels": [{"url": "https://untrusted.invalid"}]}})
    );
    let encoded = serde_json::to_string(detail).expect("serializes");
    assert!(!encoded.contains("meta-sentinel"));
    assert!(!encoded.contains("warning-sentinel"));
    assert!(
        !detail_reply["result"]["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("meta-sentinel")
    );
    assert!(
        !detail_reply["result"]["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("warning-sentinel")
    );
    let requests = server.received_requests().await.expect("requests");
    let search = requests
        .iter()
        .find(|request| request.url.path() == "/api/dashboards")
        .expect("search request");
    assert_eq!(
        search
            .url
            .query_pairs()
            .find(|(key, _)| key == "query")
            .map(|(_, value)| value.into_owned()),
        Some("view".to_string())
    );
    assert_eq!(
        search
            .url
            .query_pairs()
            .find(|(key, _)| key == "tags")
            .map(|(_, value)| value.into_owned()),
        Some("marker".to_string())
    );
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].url.path(), "/api/status");
    assert_eq!(requests[1].url.path(), "/api/dashboards");
    assert_eq!(requests[2].url.path(), "/api/dashboards/dashboard-1");
    assert_eq!(requests[3].url.path(), "/api/dashboards/dashboard-1");
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn invalid_content_text_never_creates_a_transport() {
    let server = MockServer::start().await;
    let mut harness = Harness::start(target_for(&server), options());
    let invalid = vec![
        String::new(),
        " \t\n".to_string(),
        "x".repeat(1025),
        "é".repeat(513),
    ];
    let mut id = 1;
    for (tool, field) in [
        ("data_views_list", "search"),
        ("data_views_get", "selector"),
        ("dashboards_list", "search"),
        ("dashboards_list", "tag"),
        ("dashboards_get", "selector"),
    ] {
        for value in &invalid {
            let reply = call(&mut harness, id, tool, json!({field: value})).await;
            assert_eq!(failure(&reply)["error"]["code"], "invalid_argument");
            id += 1;
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
async fn inclusive_text_byte_limit_preserves_ascii_and_multibyte_values() {
    let values = ["x".repeat(1024), "é".repeat(512)];
    let server = MockServer::start().await;
    for value in &values {
        let encoded = value.replace('é', "%C3%A9");
        Mock::given(method("GET"))
            .and(path(format!("/api/data_views/data_view/{encoded}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data_view": {"id": value, "title": "One"}})),
            )
            .mount(&server)
            .await;
    }
    mount_data_views(
        &server,
        values
            .iter()
            .map(|value| data_view(value, "One", None))
            .collect(),
    )
    .await;
    let mut harness = Harness::start(target_for(&server), options());
    for (id, value) in values.iter().enumerate() {
        let list_reply = call(
            &mut harness,
            id as u64,
            "data_views_list",
            json!({"search": value}),
        )
        .await;
        let list = content(&list_reply);
        assert_eq!(
            list["data"]["data_views"],
            json!([{ "id": value, "title": "One" }])
        );
        let reply = call(
            &mut harness,
            id as u64 + 10,
            "data_views_get",
            json!({"selector": value}),
        )
        .await;
        assert_eq!(content(&reply)["data"]["data_view"]["id"], *value);
    }
    let requests = server.received_requests().await.expect("requests");
    for value in &values {
        assert!(requests.iter().any(|request| {
            request
                .url
                .as_str()
                .ends_with(&value.replace('é', "%C3%A9"))
        }));
    }
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/api/data_views")
            .count(),
        4
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = MockServer::start().await;
    mount_status(&server, "9.5.1").await;
    mount_dashboard_search(&server, vec![]).await;
    for value in &values {
        let encoded = value.replace('é', "%C3%A9");
        Mock::given(method("GET"))
            .and(path(format!("/api/dashboards/{encoded}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"id": value, "data": {"title": "One"}, "meta": {}})),
            )
            .up_to_n_times(2)
            .mount(&server)
            .await;
    }
    let mut harness = Harness::start(target_for(&server), options());
    for (id, value) in values.iter().enumerate() {
        content(
            &call(
                &mut harness,
                id as u64 + 20,
                "dashboards_list",
                json!({"search": value, "tag": value}),
            )
            .await,
        );
        let reply = call(
            &mut harness,
            id as u64 + 30,
            "dashboards_get",
            json!({"selector": value}),
        )
        .await;
        assert_eq!(content(&reply)["data"]["id"], *value);
    }
    let requests = server.received_requests().await.expect("requests");
    for value in &values {
        assert!(requests.iter().any(|request| {
            request
                .url
                .query_pairs()
                .any(|(key, actual)| key == "query" && actual == *value)
        }));
        assert!(requests.iter().any(|request| {
            request
                .url
                .query_pairs()
                .any(|(key, actual)| key == "tags" && actual == *value)
        }));
        assert!(requests.iter().any(|request| {
            request
                .url
                .as_str()
                .ends_with(&value.replace('é', "%C3%A9"))
        }));
    }
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn dashboard_floor_is_explicit_and_oversized_detail_is_not_truncated() {
    let unsupported = MockServer::start().await;
    mount_status(&unsupported, "9.5.0").await;
    let mut harness = Harness::start(target_for(&unsupported), options());
    let reply = call(&mut harness, 1, "dashboards_list", json!({})).await;
    assert_eq!(failure(&reply)["error"]["code"], "elastic_unsupported");
    assert_eq!(
        unsupported
            .received_requests()
            .await
            .expect("requests")
            .len(),
        1
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = MockServer::start().await;
    mount_data_views(&server, vec![data_view("one", "One", None)]).await;
    let oversized = json!({
        "data_view": {
            "id": "one",
            "title": "One",
            "fieldFormats": {"large": "x".repeat(262_145)}
        }
    });
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(oversized))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let too_large = call(
        &mut harness,
        2,
        "data_views_get",
        json!({"selector": "one"}),
    )
    .await;
    assert_eq!(failure(&too_large)["error"]["code"], "result_too_large");
    assert_eq!(server.received_requests().await.expect("requests").len(), 2);
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let dashboard = MockServer::start().await;
    mount_status(&dashboard, "9.5.1").await;
    Mock::given(method("GET")).and(path("/api/dashboards/one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "one", "data": {"title": "One", "panels": "x".repeat(262_145)}, "meta": {}})))
        .up_to_n_times(2).mount(&dashboard).await;
    let mut harness = Harness::start(target_for(&dashboard), options());
    let too_large = call(
        &mut harness,
        3,
        "dashboards_get",
        json!({"selector": "one"}),
    )
    .await;
    assert_eq!(failure(&too_large)["error"]["code"], "result_too_large");
    assert_eq!(
        dashboard.received_requests().await.expect("requests").len(),
        3
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn data_view_lists_drop_only_complete_rows_when_the_result_is_too_large() {
    let server = MockServer::start().await;
    mount_data_views(
        &server,
        vec![
            data_view("one", &"a".repeat(150_000), None),
            data_view("two", &"b".repeat(150_000), None),
        ],
    )
    .await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(&mut harness, 1, "data_views_list", json!({"limit": 2})).await;
    let result = content(&reply);
    assert_eq!(
        result["data"]["data_views"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(result["page"]["returned"], 1);
    assert_eq!(result["page"]["truncated"], true);
    assert_eq!(result["page"]["has_more"], true);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn content_output_schemas_match_the_declared_projections() {
    let mut harness = Harness::start(target(), options());
    harness.send_json(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": current_metadata()}})).await;
    let reply = harness.receive_json().await;
    let tools = reply["result"]["tools"].as_array().expect("tools");
    for name in [
        "data_views_list",
        "data_views_get",
        "data_views_default_get",
        "dashboards_list",
        "dashboards_get",
    ] {
        let schema = &tool(tools, name)["outputSchema"];
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["anyOf"].as_array().map(Vec::len), Some(2));
        let success = object(
            schema,
            success_schema(schema),
            &["data", "page", "target"],
            &["data", "target"],
        );
        let page = object_branch(schema, &success["properties"]["page"]);
        assert!(allows(schema, &success["properties"]["page"], "null"));
        object(
            schema,
            page,
            &["has_more", "limit", "returned", "total", "truncated"],
            &["limit", "returned", "truncated"],
        );
        nullable(schema, &page["properties"]["limit"], "integer", false);
        nullable(schema, &page["properties"]["returned"], "integer", false);
        nullable(schema, &page["properties"]["total"], "integer", true);
        nullable(schema, &page["properties"]["has_more"], "boolean", true);
        nullable(schema, &page["properties"]["truncated"], "boolean", false);
        let target = object(
            schema,
            &success["properties"]["target"],
            &["host", "profile", "space"],
            &["host", "profile", "space"],
        );
        for field in ["host", "profile", "space"] {
            nullable(schema, &target["properties"][field], "string", false);
        }
        let failure = schema["anyOf"]
            .as_array()
            .expect("alternatives")
            .iter()
            .map(|branch| resolve(schema, branch))
            .find(|branch| branch["properties"].get("error").is_some())
            .expect("failure");
        object(schema, failure, &["error", "target"], &["error", "target"]);
        let failure_target = object(
            schema,
            &failure["properties"]["target"],
            &["host", "profile", "space"],
            &["host", "profile", "space"],
        );
        for field in ["host", "profile", "space"] {
            nullable(
                schema,
                &failure_target["properties"][field],
                "string",
                false,
            );
        }
        let error = object(
            schema,
            &failure["properties"]["error"],
            &["code", "http_status", "kind", "message"],
            &["code", "kind", "message"],
        );
        for field in ["code", "kind", "message"] {
            nullable(schema, &error["properties"][field], "string", false);
        }
        nullable(schema, &error["properties"]["http_status"], "integer", true);
    }
    let list = &tool(tools, "data_views_list")["outputSchema"];
    let list_data = object(
        list,
        &success_schema(list)["properties"]["data"],
        &["data_views"],
        &["data_views"],
    );
    nullable(list, &list_data["properties"]["data_views"], "array", false);
    let row = object(
        list,
        &resolve(list, &list_data["properties"]["data_views"])["items"],
        &["id", "name", "timeFieldName", "title"],
        &["id", "title"],
    );
    for field in ["id", "title"] {
        nullable(list, &row["properties"][field], "string", false);
    }
    for field in ["name", "timeFieldName"] {
        nullable(list, &row["properties"][field], "string", true);
    }
    let detail = &tool(tools, "data_views_get")["outputSchema"];
    let detail_data = object(
        detail,
        &success_schema(detail)["properties"]["data"],
        &["data_view"],
        &["data_view"],
    );
    let view = object(
        detail,
        &detail_data["properties"]["data_view"],
        &[
            "allowHidden",
            "allowNoIndex",
            "fieldAttrs",
            "fieldFormats",
            "id",
            "name",
            "runtimeFieldMap",
            "sourceFilters",
            "timeFieldName",
            "title",
            "type",
            "typeMeta",
        ],
        &["id", "title"],
    );
    for field in ["id", "title"] {
        nullable(detail, &view["properties"][field], "string", false);
    }
    for field in ["name", "timeFieldName", "type"] {
        nullable(detail, &view["properties"][field], "string", true);
    }
    for field in ["allowHidden", "allowNoIndex"] {
        nullable(detail, &view["properties"][field], "boolean", true);
    }
    let source_filters = &view["properties"]["sourceFilters"];
    nullable(detail, source_filters, "array", true);
    assert_eq!(array_branch(detail, source_filters)["items"], true);
    for field in ["fieldAttrs", "fieldFormats", "runtimeFieldMap", "typeMeta"] {
        let map = &view["properties"][field];
        nullable(detail, map, "object", true);
        assert_eq!(object_branch(detail, map)["additionalProperties"], true);
    }
    let default_schema = &tool(tools, "data_views_default_get")["outputSchema"];
    let default_data = object(
        default_schema,
        &success_schema(default_schema)["properties"]["data"],
        &["id"],
        &["id"],
    );
    nullable(
        default_schema,
        &default_data["properties"]["id"],
        "string",
        true,
    );
    let dashboards = &tool(tools, "dashboards_list")["outputSchema"];
    let dashboard_data = object(
        dashboards,
        &success_schema(dashboards)["properties"]["data"],
        &["dashboards"],
        &["dashboards"],
    );
    nullable(
        dashboards,
        &dashboard_data["properties"]["dashboards"],
        "array",
        false,
    );
    let dashboard = object(
        dashboards,
        &resolve(dashboards, &dashboard_data["properties"]["dashboards"])["items"],
        &["description", "id", "tags", "title"],
        &["id", "title"],
    );
    for field in ["id", "title"] {
        nullable(dashboards, &dashboard["properties"][field], "string", false);
    }
    nullable(
        dashboards,
        &dashboard["properties"]["description"],
        "string",
        true,
    );
    let tags = &dashboard["properties"]["tags"];
    nullable(dashboards, tags, "array", true);
    nullable(
        dashboards,
        &array_branch(dashboards, tags)["items"],
        "string",
        false,
    );
    let dashboard_get = &tool(tools, "dashboards_get")["outputSchema"];
    let dashboard_get_data = object(
        dashboard_get,
        &success_schema(dashboard_get)["properties"]["data"],
        &["data", "id"],
        &["data", "id"],
    );
    nullable(
        dashboard_get,
        &dashboard_get_data["properties"]["id"],
        "string",
        false,
    );
    let data = &dashboard_get_data["properties"]["data"];
    nullable(dashboard_get, data, "object", false);
    assert_eq!(
        object_branch(dashboard_get, data)["additionalProperties"],
        true
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}
