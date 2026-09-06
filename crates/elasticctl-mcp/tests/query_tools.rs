#![allow(dead_code)]
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
            api_key: Some("test-api-key".to_string()),
            username: None,
            password: None,
            space: "default".to_string(),
            verify: true,
            timeout_secs: 30,
        },
    }
}

async fn call(
    harness: &mut Harness,
    id: u64,
    name: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    harness.send_json(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"_meta":current_metadata(),"name":name,"arguments":arguments}})).await;
    harness.receive_json().await
}

fn query_options() -> elasticctl_mcp::ServerOptions {
    let mut result = options();
    result.allow_query_tools = true;
    result
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
    assert_eq!(schema["type"], "object", "non-null typed object");
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
        .expect("object alternatives")
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
        .expect("array alternatives")
        .iter()
        .map(|branch| resolve(root, branch))
        .find(|branch| branch.get("items").is_some())
        .expect("array branch")
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

#[tokio::test]
async fn startup_opt_in_advertises_the_two_synchronous_query_tools() {
    let mut options = options();
    options.allow_query_tools = true;
    let mut harness = Harness::start(target(), options);
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": current_metadata()},
        }))
        .await;
    let reply = tokio::time::timeout(Duration::from_secs(1), harness.receive_json())
        .await
        .expect("opt-in MCP startup must serve catalog discovery");
    let names = reply["result"]["tools"]
        .as_array()
        .expect("tools list")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();
    assert!(names.contains(&"search_esql"));
    assert!(names.contains(&"search_dsl"));
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn query_catalog_input_schemas_are_closed_and_bounded() {
    let mut harness = Harness::start(target(), query_options());
    harness.send_json(json!({"jsonrpc":"2.0","id":60,"method":"tools/list","params":{"_meta":current_metadata()}})).await;
    let reply = harness.receive_json().await;
    let tools = reply["result"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 22);
    let names = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("name"))
        .collect::<Vec<_>>();
    let mut expected = EXPECTED_TOOL_NAMES.to_vec();
    expected.splice(18..18, ["search_dsl", "search_esql"]);
    assert_eq!(names, expected);
    assert_eq!(
        elasticctl_mcp::catalog::definitions()
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>(),
        EXPECTED_TOOL_NAMES
    );
    for tool in tools
        .iter()
        .filter(|tool| matches!(tool["name"].as_str(), Some("search_dsl" | "search_esql")))
    {
        assert_eq!(
            tool["annotations"],
            json!({"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true})
        );
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        assert_eq!(
            tool["inputSchema"]["properties"]["limit"]["type"],
            "integer"
        );
        assert_eq!(tool["inputSchema"]["properties"]["limit"]["default"], 50);
        assert_eq!(tool["inputSchema"]["properties"]["limit"]["minimum"], 1);
        assert_eq!(tool["inputSchema"]["properties"]["limit"]["maximum"], 200);
    }
    let esql = tools
        .iter()
        .find(|tool| tool["name"] == "search_esql")
        .expect("esql");
    assert_eq!(esql["inputSchema"]["required"], json!(["query"]));
    let mut esql_properties = esql["inputSchema"]["properties"]
        .as_object()
        .expect("properties")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    esql_properties.sort_unstable();
    assert_eq!(esql_properties, vec!["limit", "query"]);
    assert_eq!(esql["inputSchema"]["properties"]["query"]["type"], "string");
    assert_eq!(esql["inputSchema"]["properties"]["query"]["minLength"], 1);
    assert_eq!(
        esql["inputSchema"]["properties"]["query"]["maxLength"],
        65_536
    );
    assert_eq!(
        esql["inputSchema"]["properties"]["query"]["description"],
        "A complete ES|QL query that contains non-whitespace text, is at most 65,536 UTF-8 bytes, and is supplied unchanged before elasticctl appends its terminal limit."
    );
    let dsl = tools
        .iter()
        .find(|tool| tool["name"] == "search_dsl")
        .expect("dsl");
    assert_eq!(dsl["inputSchema"]["required"], json!(["index", "query"]));
    let mut dsl_properties = dsl["inputSchema"]["properties"]
        .as_object()
        .expect("properties")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    dsl_properties.sort_unstable();
    assert_eq!(
        dsl_properties,
        vec!["fields", "index", "limit", "query", "sort"]
    );
    assert_eq!(dsl["inputSchema"]["properties"]["index"]["type"], "string");
    assert_eq!(dsl["inputSchema"]["properties"]["index"]["minLength"], 1);
    assert_eq!(dsl["inputSchema"]["properties"]["index"]["maxLength"], 1024);
    assert_eq!(
        dsl["inputSchema"]["properties"]["index"]["description"],
        "A comma-separated, nonempty list of ASCII letter, digit, `.`, `_`, `-`, or `*` patterns. Components cannot be `.` or `..`; URL syntax and remote cluster prefixes are rejected. The supplied value contains non-whitespace text, is used unchanged, and is at most 1,024 UTF-8 bytes."
    );
    assert_eq!(dsl["inputSchema"]["properties"]["query"]["type"], "object");
    assert_eq!(
        dsl["inputSchema"]["properties"]["query"]["additionalProperties"],
        true
    );
    let fields = &dsl["inputSchema"]["properties"]["fields"];
    assert_eq!(
        fields["description"],
        "Optional `_source` field names. Each supplied value contains non-whitespace text, is at most 1,024 UTF-8 bytes, and is used unchanged."
    );
    assert_eq!(fields["type"], json!(["array", "null"]));
    assert_eq!(fields["maxItems"], 200);
    assert_eq!(fields["items"]["type"], "string");
    assert_eq!(fields["items"]["minLength"], 1);
    assert_eq!(fields["items"]["maxLength"], 1024);
    let sort = &dsl["inputSchema"]["properties"]["sort"];
    assert_eq!(sort["type"], json!(["array", "null"]));
    assert_eq!(sort["maxItems"], 20);
    let sort_items = resolve(&dsl["inputSchema"], &sort["items"]);
    assert_eq!(
        sort_items["anyOf"].as_array().map(Vec::len),
        Some(2),
        "{sort_items}"
    );
    let string_sort = sort_items["anyOf"]
        .as_array()
        .expect("sort alternatives")
        .iter()
        .find(|branch| branch["type"] == "string")
        .expect("string sort alternative");
    nullable(&dsl["inputSchema"], string_sort, "string", false);
    let object_sort = object_branch(&dsl["inputSchema"], sort_items);
    assert_eq!(object_sort["additionalProperties"], true);
    assert!(object_sort.get("properties").is_none());
    nullable(&dsl["inputSchema"], object_sort, "object", false);
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let mut legacy = Harness::start(target(), query_options());
    legacy.send_json(legacy_initialize(61)).await;
    assert_eq!(legacy.receive_json().await["id"], 61);
    legacy
        .send_json(json!({"jsonrpc":"2.0","id":62,"method":"tools/list","params":{}}))
        .await;
    let legacy_tools = legacy.receive_json().await["result"]["tools"]
        .as_array()
        .expect("legacy tools")
        .clone();
    for name in ["search_dsl", "search_esql"] {
        let current = tools
            .iter()
            .find(|tool| tool["name"] == name)
            .expect("current query tool");
        let legacy_tool = legacy_tools
            .iter()
            .find(|tool| tool["name"] == name)
            .expect("legacy query tool");
        assert_eq!(legacy_tool["inputSchema"], current["inputSchema"]);
        assert_eq!(legacy_tool["outputSchema"], current["outputSchema"]);
    }
    legacy.close_input();
    legacy.join().await.expect("legacy clean EOF");
}

#[tokio::test]
async fn query_catalog_output_schemas_match_the_typed_query_projections() {
    let mut harness = Harness::start(target(), query_options());
    harness.send_json(json!({"jsonrpc":"2.0","id":63,"method":"tools/list","params":{"_meta":current_metadata()}})).await;
    let reply = harness.receive_json().await;
    let tools = reply["result"]["tools"].as_array().expect("tools");
    for name in ["search_dsl", "search_esql"] {
        let schema = &tools
            .iter()
            .find(|tool| tool["name"] == name)
            .expect("query tool")["outputSchema"];
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["anyOf"].as_array().map(Vec::len), Some(2));
        let success = object(
            schema,
            success_schema(schema),
            &["data", "page", "target"],
            &["data", "target"],
        );
        let target = object(
            schema,
            &success["properties"]["target"],
            &["host", "profile", "space"],
            &["host", "profile", "space"],
        );
        for field in ["host", "profile", "space"] {
            nullable(schema, &target["properties"][field], "string", false);
        }
        nullable(schema, &success["properties"]["page"], "object", true);
        let page = object(
            schema,
            object_branch(schema, &success["properties"]["page"]),
            &["has_more", "limit", "returned", "total", "truncated"],
            &["limit", "returned", "truncated"],
        );
        nullable(schema, &page["properties"]["limit"], "integer", false);
        nullable(schema, &page["properties"]["returned"], "integer", false);
        nullable(schema, &page["properties"]["total"], "integer", true);
        nullable(schema, &page["properties"]["has_more"], "boolean", true);
        nullable(schema, &page["properties"]["truncated"], "boolean", false);
        let failure = schema["anyOf"]
            .as_array()
            .expect("output alternatives")
            .iter()
            .map(|branch| resolve(schema, branch))
            .find(|branch| branch["properties"].get("error").is_some())
            .expect("failure output");
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

    let esql = &tools
        .iter()
        .find(|tool| tool["name"] == "search_esql")
        .expect("ES|QL tool")["outputSchema"];
    let esql_data = object(
        esql,
        &success_schema(esql)["properties"]["data"],
        &["columns", "is_partial", "values"],
        &["columns", "is_partial", "values"],
    );
    let columns = array_branch(esql, &esql_data["properties"]["columns"]);
    nullable(esql, &esql_data["properties"]["columns"], "array", false);
    nullable(esql, &columns["items"], "object", false);
    let column = object(
        esql,
        &columns["items"],
        &["name", "type"],
        &["name", "type"],
    );
    nullable(esql, &column["properties"]["name"], "string", false);
    nullable(esql, &column["properties"]["type"], "string", false);
    let values = array_branch(esql, &esql_data["properties"]["values"]);
    nullable(esql, &esql_data["properties"]["values"], "array", false);
    nullable(esql, &values["items"], "array", false);
    let row = array_branch(esql, &values["items"]);
    assert_eq!(row["items"], true, "cells accept arbitrary JSON");
    nullable(
        esql,
        &esql_data["properties"]["is_partial"],
        "boolean",
        false,
    );

    let dsl = &tools
        .iter()
        .find(|tool| tool["name"] == "search_dsl")
        .expect("DSL tool")["outputSchema"];
    let dsl_data = object(
        dsl,
        &success_schema(dsl)["properties"]["data"],
        &["hits"],
        &["hits"],
    );
    let hits = array_branch(dsl, &dsl_data["properties"]["hits"]);
    nullable(dsl, &dsl_data["properties"]["hits"], "array", false);
    nullable(dsl, &hits["items"], "object", false);
    let hit = object(
        dsl,
        &hits["items"],
        &["id", "index", "score", "source"],
        &["source"],
    );
    nullable(dsl, &hit["properties"]["id"], "string", true);
    nullable(dsl, &hit["properties"]["index"], "string", true);
    nullable(dsl, &hit["properties"]["score"], "number", true);
    assert_eq!(
        hit["properties"]["source"], true,
        "source accepts arbitrary JSON"
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn query_tools_are_absent_and_unknown_without_startup_opt_in() {
    let mut harness = Harness::start(target(), options());
    harness.send_json(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":current_metadata()}})).await;
    let list = harness.receive_json().await;
    let names = list["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|tool| tool["name"].as_str().expect("name"))
        .collect::<Vec<_>>();
    assert_eq!(names, EXPECTED_TOOL_NAMES);
    for (id, name) in [(3, "search_esql"), (4, "search_dsl")] {
        let reply = call(&mut harness, id, name, json!({"enabled":true,"yes":true,"target":"https://example.test","query":"FROM logs-*","index":"logs-*"})).await;
        assert_eq!(reply["error"]["code"], -32601);
    }
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn opt_in_esql_forwards_one_bounded_sync_request_and_preserves_duplicate_columns() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/_query")).respond_with(ResponseTemplate::new(200).set_body_json(json!({
        "columns":[{"name":"dup","type":"keyword"},{"name":"dup","type":"long"}], "values":[["a",1],["b",2]], "is_partial":true
    }))).mount(&server).await;
    let mut harness = Harness::start(target_for(&server), query_options());
    let reply = call(
        &mut harness,
        5,
        "search_esql",
        json!({"query":"FROM logs-* // note","limit":1}),
    )
    .await;
    assert_eq!(reply["result"]["isError"], false);
    let result = &reply["result"]["structuredContent"];
    assert_eq!(result["data"]["columns"][0]["name"], "dup");
    assert_eq!(result["data"]["columns"][1]["name"], "dup");
    assert_eq!(result["data"]["values"], json!([["a", 1]]));
    assert_eq!(result["data"]["is_partial"], true);
    assert_eq!(
        result["page"],
        json!({"limit":1,"returned":1,"total":null,"has_more":true,"truncated":true})
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/_query");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[0].body).expect("body")["query"],
        "FROM logs-* // note\n| LIMIT 2"
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn dsl_constructs_only_the_permitted_body_and_keeps_source_separate_from_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/logs-*/_search")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"hits":{"hits":[{
        "_id":"id", "_index":"logs", "_score":1.5, "_source":{"id":"source-id","index":"source-index"}
    }]}}))).mount(&server).await;
    let mut harness = Harness::start(target_for(&server), query_options());
    let reply = call(&mut harness, 6, "search_dsl", json!({"index":"logs-*","query":{"term":{"event.kind":"event"}},"fields":["event.kind"],"sort":["@timestamp"]})).await;
    assert_eq!(reply["result"]["isError"], false);
    let hit = &reply["result"]["structuredContent"]["data"]["hits"][0];
    assert_eq!(hit["id"], "id");
    assert_eq!(hit["source"]["id"], "source-id");
    assert_eq!(
        reply["result"]["structuredContent"]["page"]["total"],
        serde_json::Value::Null
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).expect("body");
    assert_eq!(
        body,
        json!({"query":{"term":{"event.kind":"event"}},"size":51,"track_total_hits":false,"_source":["event.kind"],"sort":["@timestamp"]})
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn invalid_query_inputs_fail_before_network_io() {
    let server = MockServer::start().await;
    let mut harness = Harness::start(target_for(&server), query_options());
    let mut cases = vec![];
    for limit in [
        json!(0),
        json!(201),
        json!(null),
        json!("50"),
        json!(1.5),
        json!(-1),
    ] {
        cases.push(("search_esql", json!({"query":"FROM logs-*","limit":limit})));
        cases.push((
            "search_dsl",
            json!({"index":"logs-*","query":{},"limit":limit}),
        ));
    }
    for key in [
        "enabled", "yes", "target", "profile", "url", "file", "pit", "scroll", "async", "body",
    ] {
        let mut esql = json!({"query":"FROM logs-*"});
        esql[key] = json!({"x":"y"});
        cases.push(("search_esql", esql));
        let mut dsl = json!({"index":"logs-*","query":{}});
        dsl[key] = json!({"x":"y"});
        cases.push(("search_dsl", dsl));
    }
    let esql_multibyte = "é".repeat(32_768) + "x";
    assert_eq!(esql_multibyte.len(), 65_537);
    for query in [
        String::new(),
        " \t\n ".to_string(),
        "x".repeat(65_537),
        esql_multibyte,
    ] {
        cases.push(("search_esql", json!({"query":query})));
    }
    cases.push(("search_esql", json!({"query":null})));
    for index in [
        "",
        "logs,,other",
        ".",
        "..",
        "logs/path",
        "logs\\path",
        "logs%2fpath",
        "remote:logs",
        "logs?scroll=1m",
        "logs#fragment",
        "logs space",
        "猫",
        "https://logs",
        "@file",
        &"a".repeat(1_025),
    ] {
        cases.push(("search_dsl", json!({"index":index,"query":{}})));
    }
    for query in [json!(null), json!("query"), json!([]), json!(1)] {
        cases.push(("search_dsl", json!({"index":"logs-*","query":query})));
    }
    cases.push((
        "search_dsl",
        json!({"index":"logs-*","query":{},"fields":vec!["field"; 201]}),
    ));
    let field_multibyte = "é".repeat(512) + "x";
    assert_eq!(field_multibyte.len(), 1_025);
    for field in [
        json!(""),
        json!(" \t"),
        json!("x".repeat(1_025)),
        json!(field_multibyte),
        json!(1),
    ] {
        cases.push((
            "search_dsl",
            json!({"index":"logs-*","query":{},"fields":[field]}),
        ));
    }
    cases.push((
        "search_dsl",
        json!({"index":"logs-*","query":{},"sort":vec!["field"; 21]}),
    ));
    for sort in [json!(null), json!(1), json!([]), json!(true)] {
        cases.push((
            "search_dsl",
            json!({"index":"logs-*","query":{},"sort":[sort]}),
        ));
    }
    for (offset, (name, arguments)) in cases.into_iter().enumerate() {
        let id = 7 + offset as u64;
        let reply = call(&mut harness, id, name, arguments).await;
        assert_eq!(reply["result"]["isError"], true);
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"],
            "invalid_argument"
        );
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
async fn query_transports_do_not_retry_429_or_503_responses() {
    for (id, name, route, status, arguments) in [
        (
            13,
            "search_esql",
            "/_query",
            429,
            json!({"query":"FROM logs-*"}),
        ),
        (
            14,
            "search_esql",
            "/_query",
            503,
            json!({"query":"FROM logs-*"}),
        ),
        (
            15,
            "search_dsl",
            "/logs-*/_search",
            429,
            json!({"index":"logs-*","query":{}}),
        ),
        (
            16,
            "search_dsl",
            "/logs-*/_search",
            503,
            json!({"index":"logs-*","query":{}}),
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        let mut harness = Harness::start(target_for(&server), query_options());
        let reply = call(&mut harness, id, name, arguments).await;
        assert_eq!(reply["result"]["isError"], true);
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"],
            "elastic_http"
        );
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1, "{name} {status}");
        assert_eq!(requests[0].method.as_str(), "POST", "{name} {status}");
        assert_eq!(requests[0].url.path(), route, "{name} {status}");
        harness.close_input();
        harness.join().await.expect("clean EOF");
    }
}

#[tokio::test]
async fn esql_forwards_inference_text_without_source_rewriting() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/_query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"columns":[],"values":[]})))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), query_options());
    let query = "FROM logs-* | INFERENCE model_id WITH {\"prompt\": \"x\"}";
    let reply = call(&mut harness, 15, "search_esql", json!({"query":query})).await;
    assert_eq!(reply["result"]["isError"], false);
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[0].body).expect("body")["query"],
        format!("{query}\n| LIMIT 51")
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn cancelling_delayed_query_calls_emits_no_result_and_keeps_mcp_alive() {
    for (id, name, route, body) in [
        (
            17,
            "search_esql",
            "/_query",
            json!({"columns":[],"values":[]}),
        ),
        (
            18,
            "search_dsl",
            "/logs-*/_search",
            json!({"hits":{"hits":[]}}),
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(300))
                    .set_body_json(body),
            )
            .mount(&server)
            .await;
        let mut harness = Harness::start(target_for(&server), query_options());
        harness
            .send_json(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"_meta":current_metadata(),"name":name,"arguments": if name == "search_esql" { json!({"query":"FROM logs-*"}) } else { json!({"index":"logs-*","query":{}}) }}}))
            .await;
        timeout(Duration::from_secs(1), async {
            loop {
                if server.received_requests().await.expect("requests").len() == 1 {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("delayed query starts");
        harness.send_json(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":id,"reason":"test","_meta":current_metadata()}})).await;
        assert!(
            timeout(Duration::from_millis(500), harness.receive_json())
                .await
                .is_err(),
            "{name} emitted a cancelled result"
        );
        assert_eq!(
            server.received_requests().await.expect("requests").len(),
            1,
            "{name} made another request"
        );
        harness.send_json(json!({"jsonrpc":"2.0","id":id + 100,"method":"tools/list","params":{"_meta":current_metadata()}})).await;
        let list = timeout(Duration::from_secs(1), harness.receive_json())
            .await
            .expect("catalog reply");
        assert_eq!(list["id"], id + 100);
        assert!(list["result"]["tools"].is_array());
        harness.close_input();
        harness.join().await.expect("clean EOF");
    }
}

#[tokio::test]
async fn accepted_query_boundaries_forward_unchanged_bodies() {
    for (id, query, limit) in [
        (30, "x".repeat(65_536), 1),
        (31, "猫".repeat(21_845) + "x", 200),
    ] {
        assert_eq!(query.len(), 65_536);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/_query"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"columns":[],"values":[]})),
            )
            .mount(&server)
            .await;
        let mut harness = Harness::start(target_for(&server), query_options());
        let reply = call(
            &mut harness,
            id,
            "search_esql",
            json!({"query":query,"limit":limit}),
        )
        .await;
        assert_eq!(reply["result"]["isError"], false);
        assert_eq!(
            reply["result"]["content"][0]["text"],
            serde_json::to_string(&reply["result"]["structuredContent"]).expect("text")
        );
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method.as_str(), "POST");
        assert_eq!(requests[0].url.path(), "/_query");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[0].body).expect("body")["query"],
            format!("{query}\n| LIMIT {}", limit + 1)
        );
        harness.close_input();
        harness.join().await.expect("clean EOF");
    }
}

#[tokio::test]
async fn esql_preserves_an_earlier_limit_and_trailing_comment_before_its_bound() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/_query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"columns":[],"values":[]})))
        .mount(&server)
        .await;
    let query = "FROM logs-* | LIMIT 4 // keep this comment";
    let mut harness = Harness::start(target_for(&server), query_options());
    let reply = call(
        &mut harness,
        35,
        "search_esql",
        json!({"query":query,"limit":200}),
    )
    .await;
    assert_eq!(reply["result"]["isError"], false);
    assert_eq!(
        reply["result"]["content"][0]["text"],
        serde_json::to_string(&reply["result"]["structuredContent"]).expect("text")
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method.as_str(), "POST");
    assert_eq!(requests[0].url.path(), "/_query");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[0].body).expect("body")["query"],
        "FROM logs-* | LIMIT 4 // keep this comment\n| LIMIT 201"
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn esql_forwards_a_literal_at_file_query_and_normalizes_server_rejection() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/_query"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), query_options());
    let reply = call(
        &mut harness,
        36,
        "search_esql",
        json!({"query":"@file","limit":1}),
    )
    .await;
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["code"],
        "elastic_http"
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method.as_str(), "POST");
    assert_eq!(requests[0].url.path(), "/_query");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[0].body).expect("body")["query"],
        "@file\n| LIMIT 2"
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn dsl_accepted_boundaries_forward_the_exact_fixed_body() {
    let server = MockServer::start().await;
    let index = "a".repeat(1024);
    Mock::given(method("POST"))
        .and(path(format!("/{index}/_search")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"hits":{"hits":[]}})))
        .mount(&server)
        .await;
    let multibyte = "é".repeat(511) + "xx";
    assert_eq!(multibyte.len(), 1024);
    let mut fields = vec!["f".to_string(); 198];
    fields.push("a".repeat(1024));
    fields.push(multibyte.clone());
    let mut sort = Vec::new();
    for i in 0..10 {
        sort.push(json!(format!("field{i}")));
        sort.push(json!({format!("field{i}"): {"order":"asc","nested":{"x":[1]}}}));
    }
    let expected_fields = json!(fields.clone());
    let expected_sort = json!(sort.clone());
    let mut harness = Harness::start(target_for(&server), query_options());
    let reply = call(&mut harness, 32, "search_dsl", json!({"index":index,"query":{"bool":{"must":[{"term":{"x":"y"}}]}},"fields":fields,"sort":sort,"limit":200})).await;
    assert_eq!(reply["result"]["isError"], false);
    assert_eq!(
        reply["result"]["content"][0]["text"],
        serde_json::to_string(&reply["result"]["structuredContent"]).expect("text")
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method.as_str(), "POST");
    assert_eq!(requests[0].url.path(), format!("/{index}/_search"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[0].body).expect("body"),
        json!({"query":{"bool":{"must":[{"term":{"x":"y"}}]}},"size":201,"track_total_hits":false,"_source":expected_fields,"sort":expected_sort})
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn dsl_server_400_is_normalized_after_one_post() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/valid-error/_search"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), query_options());
    let reply = call(
        &mut harness,
        34,
        "search_dsl",
        json!({"index":"valid-error","query":{},"limit":1}),
    )
    .await;
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["code"],
        "elastic_http"
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/valid-error/_search");
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn query_projections_preserve_sparse_and_arbitrary_source_values() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/sources/_search")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"hits":{"total":{"value":9,"relation":"gte"},"hits":[{"_source":{"id":"source","index":"source-index"}},{"_id":"id","_index":"idx","_score":1.0,"_source":[1,{"x":true}]},{"_source":null},{"_source":"scalar"},{}]}}))).mount(&server).await;
    let mut harness = Harness::start(target_for(&server), query_options());
    let reply = call(
        &mut harness,
        40,
        "search_dsl",
        json!({"index":"sources","query":{},"limit":1}),
    )
    .await;
    assert_eq!(reply["result"]["isError"], false);
    let data = &reply["result"]["structuredContent"];
    assert_eq!(
        data["data"]["hits"][0],
        json!({"id":null,"index":null,"score":null,"source":{"id":"source","index":"source-index"}})
    );
    assert_eq!(
        data["page"],
        json!({"limit":1,"returned":1,"total":null,"has_more":true,"truncated":true})
    );
    assert_eq!(
        reply["result"]["content"][0]["text"],
        serde_json::to_string(data).expect("text")
    );
    let full = call(
        &mut harness,
        43,
        "search_dsl",
        json!({"index":"sources","query":{},"limit":5}),
    )
    .await;
    assert_eq!(
        full["result"]["structuredContent"]["data"]["hits"],
        json!([
            {"id":null,"index":null,"score":null,"source":{"id":"source","index":"source-index"}},
            {"id":"id","index":"idx","score":1.0,"source":[1,{"x":true}]},
            {"id":null,"index":null,"score":null,"source":null},
            {"id":null,"index":null,"score":null,"source":"scalar"},
            {"id":null,"index":null,"score":null,"source":null}
        ])
    );
    assert_eq!(
        full["result"]["structuredContent"]["page"],
        json!({"limit":5,"returned":5,"total":null,"has_more":null,"truncated":false})
    );
    assert_eq!(
        full["result"]["content"][0]["text"],
        serde_json::to_string(&full["result"]["structuredContent"]).expect("text")
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 2);
    for (request, size) in requests.iter().zip([2, 6]) {
        assert_eq!(request.method.as_str(), "POST");
        assert_eq!(request.url.path(), "/sources/_search");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request.body).expect("body"),
            json!({"query":{},"size":size,"track_total_hits":false})
        );
    }
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn short_query_results_keep_unknown_page_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/_query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"columns":[{"name":"x","type":"keyword"}],"values":[["x"]],"is_partial":true}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/short/_search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"hits":{"total":{"value":1,"relation":"eq"},"hits":[{"_source":"scalar"}]}}),
        ))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), query_options());
    let esql = call(
        &mut harness,
        41,
        "search_esql",
        json!({"query":"FROM short","limit":50}),
    )
    .await;
    assert_eq!(esql["result"]["isError"], false);
    assert_eq!(
        esql["result"]["structuredContent"]["data"]["is_partial"],
        true
    );
    assert_eq!(
        esql["result"]["structuredContent"]["page"],
        json!({"limit":50,"returned":1,"total":null,"has_more":null,"truncated":false})
    );
    assert_eq!(
        esql["result"]["content"][0]["text"],
        serde_json::to_string(&esql["result"]["structuredContent"]).expect("text")
    );
    let dsl = call(
        &mut harness,
        42,
        "search_dsl",
        json!({"index":"short","query":{},"limit":50}),
    )
    .await;
    assert_eq!(
        dsl["result"]["structuredContent"]["data"]["hits"][0]["source"],
        "scalar"
    );
    assert_eq!(
        dsl["result"]["structuredContent"]["page"],
        json!({"limit":50,"returned":1,"total":null,"has_more":null,"truncated":false})
    );
    assert_eq!(
        dsl["result"]["content"][0]["text"],
        serde_json::to_string(&dsl["result"]["structuredContent"]).expect("text")
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method.as_str(), "POST");
    assert_eq!(requests[0].url.path(), "/_query");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[0].body).expect("body"),
        json!({"query":"FROM short\n| LIMIT 51"})
    );
    assert_eq!(requests[1].method.as_str(), "POST");
    assert_eq!(requests[1].url.path(), "/short/_search");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[1].body).expect("body"),
        json!({"query":{},"size":51,"track_total_hits":false})
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn query_byte_caps_keep_only_complete_esql_rows_and_dsl_hits() {
    let server = MockServer::start().await;
    let value = "x".repeat(170_000);
    Mock::given(method("POST"))
        .and(path("/_query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"columns":[{"name":"dup","type":"keyword"}],"values":[[value],[value]]}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST")).and(path("/caps/_search")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"hits":{"hits":[{"_id":"one","_source":{"large":value}},{"_id":"two","_source":{"large":value}}]}}))).mount(&server).await;
    let mut harness = Harness::start(target_for(&server), query_options());
    let esql = call(
        &mut harness,
        50,
        "search_esql",
        json!({"query":"FROM caps"}),
    )
    .await;
    assert_eq!(
        esql["result"]["structuredContent"]["data"]["values"],
        json!([["x".repeat(170_000)]])
    );
    assert_eq!(
        esql["result"]["structuredContent"]["data"]["columns"],
        json!([{"name":"dup","type":"keyword"}])
    );
    assert_eq!(
        esql["result"]["structuredContent"]["page"],
        json!({"limit":50,"returned":1,"total":null,"has_more":true,"truncated":true})
    );
    assert_eq!(
        esql["result"]["content"][0]["text"],
        serde_json::to_string(&esql["result"]["structuredContent"]).expect("text")
    );
    let dsl = call(
        &mut harness,
        51,
        "search_dsl",
        json!({"index":"caps","query":{}}),
    )
    .await;
    assert_eq!(
        dsl["result"]["structuredContent"]["data"]["hits"],
        json!([{"id":"one","index":null,"score":null,"source":{"large":"x".repeat(170_000)}}])
    );
    assert_eq!(
        dsl["result"]["structuredContent"]["page"],
        json!({"limit":50,"returned":1,"total":null,"has_more":true,"truncated":true})
    );
    assert_eq!(
        dsl["result"]["content"][0]["text"],
        serde_json::to_string(&dsl["result"]["structuredContent"]).expect("text")
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method.as_str(), "POST");
    assert_eq!(requests[0].url.path(), "/_query");
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[0].body).expect("ES|QL body"),
        json!({"query":"FROM caps\n| LIMIT 51"})
    );
    assert_eq!(requests[1].method.as_str(), "POST");
    assert_eq!(requests[1].url.path(), "/caps/_search");
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[1].body).expect("DSL body"),
        json!({"query":{},"size":51,"track_total_hits":false})
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn query_byte_caps_reject_an_indivisible_esql_row_and_dsl_hit() {
    let server = MockServer::start().await;
    let value = "x".repeat(262_145);
    Mock::given(method("POST"))
        .and(path("/_query"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"columns":[{"name":"x","type":"keyword"}],"values":[[value]]}),
            ),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oversize/_search"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"hits":{"hits":[{"_source":{"large":value}}]}})),
        )
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), query_options());
    for (id, name, arguments) in [
        (52, "search_esql", json!({"query":"FROM oversize"})),
        (53, "search_dsl", json!({"index":"oversize","query":{}})),
    ] {
        let reply = call(&mut harness, id, name, arguments).await;
        assert_eq!(reply["result"]["isError"], true);
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"],
            "result_too_large"
        );
        assert_eq!(
            reply["result"]["content"][0]["text"],
            serde_json::to_string(&reply["result"]["structuredContent"]).expect("text")
        );
    }
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method.as_str(), "POST");
    assert_eq!(requests[0].url.path(), "/_query");
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[0].body).expect("ES|QL body"),
        json!({"query":"FROM oversize\n| LIMIT 51"})
    );
    assert_eq!(requests[1].method.as_str(), "POST");
    assert_eq!(requests[1].url.path(), "/oversize/_search");
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[1].body).expect("DSL body"),
        json!({"query":{},"size":51,"track_total_hits":false})
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}
