mod support;

use elasticctl_core::{Profile, Resolved, Source};
use serde_json::{Value, json};
use support::{EXPECTED_TOOL_NAMES, Harness, current_metadata, options, target};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
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

async fn stack() -> MockServer {
    stack_with_version("9.5.1").await
}

async fn stack_with_version(version: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": version, "build_flavor": "traditional"}
        })))
        .mount(&server)
        .await;
    server
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

async fn tools(harness: &mut Harness) -> Value {
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": current_metadata()},
        }))
        .await;
    harness.receive_json().await["result"]["tools"].clone()
}

fn tool<'a>(tools: &'a Value, name: &str) -> &'a Value {
    tools
        .as_array()
        .expect("tools array")
        .iter()
        .find(|tool| tool["name"] == name)
        .expect("exception tool is registered")
}

fn list(id: &str, namespace: Option<&str>) -> Value {
    let mut value = json!({
        "list_id": id,
        "name": "sample name",
        "description": "sample description",
        "type": "detection",
        "tags": ["elasticctl-sample"],
        "created_by": "container-sentinel",
    });
    if let Some(namespace) = namespace {
        value["namespace_type"] = json!(namespace);
    }
    value
}

fn item(id: &str) -> Value {
    json!({
        "item_id": id,
        "name": "sample item",
        "description": "sample item description",
        "entries": [{"field": "host.name", "operator": "included", "value": "sentinel"}, 17, null],
        "os_types": ["linux"],
        "tags": ["elasticctl-sample"],
        "list_id": "hidden-parent-sentinel",
        "namespace_type": "hidden-parent-sentinel",
        "type": "simple",
        "created_by": "item-sentinel",
    })
}

async fn mount_find(server: &MockServer, namespace: &str, data: Vec<Value>) {
    let total = data.len();
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/_find"))
        .and(query_param("namespace_type", namespace))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": data, "page": 1, "per_page": 10000, "total": total,
        })))
        .mount(server)
        .await;
}

async fn mount_get_list(server: &MockServer, id: &str, namespace: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path("/api/exception_lists"))
        .and(query_param("list_id", id))
        .and(query_param("namespace_type", namespace))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn mount_items(server: &MockServer, id: &str, namespace: &str, items: Vec<Value>) {
    let total = items.len();
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/items/_find"))
        .and(query_param("list_id", id))
        .and(query_param("namespace_type", namespace))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": items, "page": 1, "per_page": 10000, "total": total,
        })))
        .mount(server)
        .await;
}

fn names(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|value| value["name"].as_str().expect("tool name"))
        .collect()
}

fn resolved<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    let mut schema = schema;
    while let Some(reference) = schema["$ref"].as_str() {
        schema = root
            .pointer(reference.strip_prefix('#').expect("local ref"))
            .expect("resolved local ref");
    }
    schema
}

fn root_success(schema: &Value) -> &Value {
    schema["anyOf"]
        .as_array()
        .expect("output union")
        .iter()
        .map(|branch| resolved(schema, branch))
        .find(|branch| branch["properties"].get("data").is_some())
        .expect("success branch")
}

fn root_failure(schema: &Value) -> &Value {
    schema["anyOf"]
        .as_array()
        .expect("output union")
        .iter()
        .map(|branch| resolved(schema, branch))
        .find(|branch| branch["properties"].get("error").is_some())
        .expect("failure branch")
}

fn object_keys(value: &Value) -> Vec<String> {
    let mut keys = value
        .as_object()
        .expect("object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

fn expected_keys(keys: &[&str]) -> Vec<String> {
    let mut keys = keys
        .iter()
        .map(|key| (*key).to_string())
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

fn assert_schema_object(schema: &Value, value: &Value, fields: &[&str], required: &[&str]) {
    let value = resolved(schema, value);
    assert!(allows_type(schema, value, "object"));
    assert_eq!(object_keys(&value["properties"]), expected_keys(fields));
    let mut actual = value["required"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    actual.sort();
    assert_eq!(actual, expected_keys(required));
}

fn allows_type(root: &Value, schema: &Value, wanted: &str) -> bool {
    let schema = resolved(root, schema);
    match &schema["type"] {
        Value::String(value) => value == wanted,
        Value::Array(values) => values.iter().any(|value| value == wanted),
        _ => schema["anyOf"].as_array().is_some_and(|branches| {
            branches
                .iter()
                .any(|branch| allows_type(root, branch, wanted))
        }),
    }
}

fn nullable_object_branch<'a>(schema: &'a Value, value: &'a Value) -> &'a Value {
    resolved(schema, value)["anyOf"]
        .as_array()
        .expect("nullable alternatives")
        .iter()
        .map(|branch| resolved(schema, branch))
        .find(|branch| branch.get("properties").is_some())
        .expect("object branch")
}

fn assert_optional_scalar(schema: &Value, object: &Value, field: &str, kind: &str) {
    let field = &object["properties"][field];
    assert!(allows_type(schema, field, kind), "{field:?} allows {kind}");
    assert!(allows_type(schema, field, "null"), "{field:?} allows null");
}

fn assert_optional_string_array(schema: &Value, object: &Value, field: &str) {
    let value = &object["properties"][field];
    assert!(allows_type(schema, value, "array"));
    assert!(allows_type(schema, value, "null"));
    let value = resolved(schema, value);
    assert!(allows_type(schema, &value["items"], "string"));
}

fn assert_success_envelope(schema: &Value, data_fields: &[&str], data_required: &[&str]) {
    let success = root_success(schema);
    assert_schema_object(
        schema,
        success,
        &["data", "page", "target"],
        &["data", "target"],
    );
    let target = resolved(schema, &success["properties"]["target"]);
    assert_schema_object(
        schema,
        target,
        &["host", "profile", "space"],
        &["host", "profile", "space"],
    );
    for field in ["host", "profile", "space"] {
        assert!(allows_type(schema, &target["properties"][field], "string"));
    }
    let page = nullable_object_branch(schema, &success["properties"]["page"]);
    assert_schema_object(
        schema,
        page,
        &["has_more", "limit", "returned", "total", "truncated"],
        &["limit", "returned", "truncated"],
    );
    for (field, kind) in [
        ("limit", "integer"),
        ("returned", "integer"),
        ("truncated", "boolean"),
    ] {
        assert!(allows_type(schema, &page["properties"][field], kind));
    }
    for (field, kind) in [("total", "integer"), ("has_more", "boolean")] {
        assert!(allows_type(schema, &page["properties"][field], kind));
        assert!(allows_type(schema, &page["properties"][field], "null"));
    }
    let data = resolved(schema, &success["properties"]["data"]);
    assert_schema_object(schema, data, data_fields, data_required);
}

fn assert_result_text_matches_structured(reply: &Value) {
    let text: Value = serde_json::from_str(
        reply["result"]["content"][0]["text"]
            .as_str()
            .expect("text result"),
    )
    .expect("text JSON");
    assert_eq!(text, reply["result"]["structuredContent"]);
}

fn assert_read_paths(requests: &[wiremock::Request], allowed: &[&str]) {
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
    assert!(
        requests
            .iter()
            .all(|request| allowed.contains(&request.url.path()))
    );
}

fn query(request: &wiremock::Request, key: &str) -> Option<String> {
    request
        .url
        .query_pairs()
        .find(|(actual, _)| actual == key)
        .map(|(_, value)| value.into_owned())
}

fn assert_get_route(
    requests: &[wiremock::Request],
    path: &str,
    count: usize,
    query_pairs: &[(&str, &str)],
) {
    let matching = requests
        .iter()
        .filter(|request| request.url.path() == path)
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), count, "{path} request count");
    for request in matching {
        for (key, value) in query_pairs {
            assert_eq!(query(request, key).as_deref(), Some(*value), "{path} {key}");
        }
    }
}

#[tokio::test]
async fn exception_catalog_has_closed_inputs_and_typed_safe_outputs() {
    let mut harness = Harness::start(target(), options());
    let catalog = tools(&mut harness).await;
    assert_eq!(names(&catalog), EXPECTED_TOOL_NAMES);
    let annotations = json!({
        "readOnlyHint": true, "destructiveHint": false,
        "idempotentHint": true, "openWorldHint": true,
    });
    for (name, properties, required) in [
        (
            "exceptions_list",
            vec!["limit", "list_type", "namespace", "search", "tag"],
            vec![],
        ),
        (
            "exceptions_get",
            vec!["limit", "list_id", "namespace"],
            vec!["list_id"],
        ),
    ] {
        let tool = tool(&catalog, name);
        assert_eq!(tool["annotations"], annotations);
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        let mut actual = tool["inputSchema"]["properties"]
            .as_object()
            .expect("properties")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        actual.sort();
        let mut expected = properties.into_iter().map(String::from).collect::<Vec<_>>();
        expected.sort();
        assert_eq!(actual, expected);
        assert_eq!(
            tool["inputSchema"]["required"]
                .as_array()
                .map_or(vec![], |v| v
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect::<Vec<_>>()),
            required
        );
        assert_eq!(tool["inputSchema"]["properties"]["limit"]["default"], 50);
        assert_eq!(tool["inputSchema"]["properties"]["limit"]["minimum"], 1);
        assert_eq!(tool["inputSchema"]["properties"]["limit"]["maximum"], 200);
        assert_eq!(tool["outputSchema"]["type"], "object");
        assert_eq!(tool["outputSchema"]["anyOf"].as_array().unwrap().len(), 2);
    }
    for name in ["exceptions_list", "exceptions_get"] {
        let schema = &tool(&catalog, name)["inputSchema"];
        let namespace = resolved(schema, &schema["properties"]["namespace"]);
        let namespace = namespace["anyOf"]
            .as_array()
            .expect("nullable namespace alternatives")
            .iter()
            .map(|branch| resolved(schema, branch))
            .find(|branch| branch.get("enum").is_some())
            .expect("namespace enum branch");
        assert_eq!(namespace["enum"], json!(["single", "agnostic"]));
    }
    for (name, field, description, required) in [
        (
            "exceptions_get",
            "list_id",
            "Exact exception-list identifier (list_id). Must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.",
            true,
        ),
        (
            "exceptions_list",
            "list_type",
            "Exact exception-list type filter. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.",
            false,
        ),
        (
            "exceptions_list",
            "tag",
            "Exact exception-list tag filter. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.",
            false,
        ),
        (
            "exceptions_list",
            "search",
            "Exception-list display-name substring filter. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.",
            false,
        ),
    ] {
        let input = &tool(&catalog, name)["inputSchema"];
        let property = &input["properties"][field];
        let string = resolved(input, property);
        let string = string["anyOf"]
            .as_array()
            .map(|branches| {
                branches
                    .iter()
                    .map(|branch| resolved(input, branch))
                    .find(|branch| allows_type(input, branch, "string"))
                    .expect("string branch")
            })
            .unwrap_or(string);
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
            allows_type(input, property, "null"),
            !required,
            "{name}.{field} nullability"
        );
    }
    for name in ["exceptions_list", "exceptions_get"] {
        let schema = &tool(&catalog, name)["outputSchema"];
        let success = root_success(schema);
        assert_eq!(success["type"], "object");
        let page = resolved(schema, &success["properties"]["page"]);
        let page = page["anyOf"]
            .as_array()
            .expect("nullable page alternatives")
            .iter()
            .map(|branch| resolved(schema, branch))
            .find(|branch| branch.get("properties").is_some())
            .expect("page object branch");
        for (field, kind) in [
            ("limit", "integer"),
            ("returned", "integer"),
            ("truncated", "boolean"),
        ] {
            assert!(allows_type(schema, &page["properties"][field], kind));
        }
        assert!(allows_type(schema, &page["properties"]["total"], "integer"));
        assert!(allows_type(schema, &page["properties"]["total"], "null"));
        assert!(allows_type(
            schema,
            &page["properties"]["has_more"],
            "boolean"
        ));
        assert!(allows_type(schema, &page["properties"]["has_more"], "null"));
        assert_schema_object(
            schema,
            root_failure(schema),
            &["error", "target"],
            &["error", "target"],
        );
        let error = resolved(schema, &root_failure(schema)["properties"]["error"]);
        assert_schema_object(
            schema,
            error,
            &["code", "http_status", "kind", "message"],
            &["kind", "code", "message"],
        );
        for field in ["kind", "code", "message"] {
            assert!(allows_type(schema, &error["properties"][field], "string"));
        }
        assert!(allows_type(
            schema,
            &error["properties"]["http_status"],
            "integer"
        ));
        assert!(allows_type(
            schema,
            &error["properties"]["http_status"],
            "null"
        ));
    }
    let list_schema = &tool(&catalog, "exceptions_list")["outputSchema"];
    let list_data = resolved(
        list_schema,
        &root_success(list_schema)["properties"]["data"],
    );
    assert_schema_object(list_schema, list_data, &["lists"], &["lists"]);
    let containers = resolved(list_schema, &list_data["properties"]["lists"]);
    assert!(allows_type(list_schema, containers, "array"));
    let container = resolved(list_schema, &containers["items"]);
    assert_schema_object(
        list_schema,
        container,
        &[
            "description",
            "list_id",
            "name",
            "namespace_type",
            "tags",
            "type",
        ],
        &["list_id", "namespace_type"],
    );
    for field in ["list_id", "namespace_type", "name", "description", "type"] {
        assert!(allows_type(
            list_schema,
            &container["properties"][field],
            "string"
        ));
    }
    let tags = resolved(list_schema, &container["properties"]["tags"]);
    assert!(allows_type(list_schema, tags, "array"));
    assert!(allows_type(list_schema, &tags["items"], "string"));
    let get_schema = &tool(&catalog, "exceptions_get")["outputSchema"];
    let get_data = resolved(get_schema, &root_success(get_schema)["properties"]["data"]);
    assert_schema_object(
        get_schema,
        get_data,
        &["container", "items"],
        &["container", "items"],
    );
    let item = resolved(
        get_schema,
        &resolved(get_schema, &get_data["properties"]["items"])["items"],
    );
    assert_schema_object(
        get_schema,
        item,
        &[
            "description",
            "entries",
            "item_id",
            "name",
            "os_types",
            "tags",
        ],
        &["item_id"],
    );
    for field in ["item_id", "name", "description"] {
        assert!(allows_type(
            get_schema,
            &item["properties"][field],
            "string"
        ));
    }
    for field in ["os_types", "tags"] {
        let field = resolved(get_schema, &item["properties"][field]);
        assert!(allows_type(get_schema, field, "array"));
        assert!(allows_type(get_schema, &field["items"], "string"));
    }
    let entries = resolved(get_schema, &item["properties"]["entries"]);
    assert!(allows_type(get_schema, entries, "array"));
    let entry = resolved(get_schema, &entries["items"]);
    assert!(entry == &Value::Bool(true) || entry.as_object().is_some_and(|value| value.is_empty()));
    assert_success_envelope(list_schema, &["lists"], &["lists"]);
    assert_success_envelope(get_schema, &["container", "items"], &["container", "items"]);
    assert!(allows_type(
        list_schema,
        &list_data["properties"]["lists"],
        "array"
    ));
    assert!(allows_type(
        get_schema,
        &get_data["properties"]["items"],
        "array"
    ));
    assert_schema_object(
        list_schema,
        container,
        &[
            "description",
            "list_id",
            "name",
            "namespace_type",
            "tags",
            "type",
        ],
        &["list_id", "namespace_type"],
    );
    let get_container = resolved(get_schema, &get_data["properties"]["container"]);
    assert_schema_object(
        get_schema,
        get_container,
        &[
            "description",
            "list_id",
            "name",
            "namespace_type",
            "tags",
            "type",
        ],
        &["list_id", "namespace_type"],
    );
    for field in ["list_id", "namespace_type"] {
        assert!(allows_type(
            list_schema,
            &container["properties"][field],
            "string"
        ));
        assert!(allows_type(
            get_schema,
            &get_container["properties"][field],
            "string"
        ));
    }
    for field in ["name", "description", "type"] {
        assert_optional_scalar(list_schema, container, field, "string");
        assert_optional_scalar(get_schema, get_container, field, "string");
    }
    assert_optional_string_array(list_schema, container, "tags");
    assert_optional_string_array(get_schema, get_container, "tags");
    for field in ["name", "description"] {
        assert_optional_scalar(get_schema, item, field, "string");
    }
    for field in ["os_types", "tags"] {
        assert_optional_string_array(get_schema, item, field);
    }
    assert!(allows_type(
        get_schema,
        &item["properties"]["entries"],
        "null"
    ));
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn recorded_exception_responses_project_through_current_and_legacy_protocols() {
    let find: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/serverless-9.6.0/exception_lists_find.json"
    ))
    .expect("recorded list fixture");
    let container: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/serverless-9.6.0/exception_list_get.json"
    ))
    .expect("recorded container fixture");
    let items: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/serverless-9.6.0/exception_list_items_find.json"
    ))
    .expect("recorded item fixture");
    let server = stack().await;
    mount_find(
        &server,
        "single",
        find["response"]["data"].as_array().unwrap().clone(),
    )
    .await;
    mount_find(&server, "agnostic", vec![]).await;
    mount_get_list(
        &server,
        "elasticctl-sample-exceptions",
        "single",
        container["response"].clone(),
    )
    .await;
    mount_items(
        &server,
        "elasticctl-sample-exceptions",
        "single",
        items["response"]["data"].as_array().unwrap().clone(),
    )
    .await;
    let mut current = Harness::start(target_for(&server), options());
    let list_reply = call(&mut current, 2, "exceptions_list", json!({})).await;
    assert_eq!(list_reply["result"]["isError"], false);
    let get_reply = call(
        &mut current,
        3,
        "exceptions_get",
        json!({"list_id": "elasticctl-sample-exceptions", "namespace": "single"}),
    )
    .await;
    let structured = get_reply["result"]["structuredContent"].clone();
    assert_eq!(
        structured["data"]["container"]["list_id"],
        "elasticctl-sample-exceptions"
    );
    assert_eq!(
        structured["data"]["items"][0]["item_id"],
        "elasticctl-sample-exception-item"
    );
    assert!(!get_reply.to_string().contains("created_by"));
    current.close_input();
    current.join().await.expect("clean EOF");
    let mut legacy = Harness::start(target_for(&server), options());
    legacy.send_json(support::legacy_initialize(4)).await;
    assert_eq!(legacy.receive_json().await["id"], 4);
    let legacy_reply = legacy_call(
        &mut legacy,
        5,
        "exceptions_get",
        json!({"list_id": "elasticctl-sample-exceptions", "namespace": "single"}),
    )
    .await;
    assert_eq!(legacy_reply["result"]["structuredContent"], structured);
    legacy.close_input();
    legacy.join().await.expect("clean EOF");
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(
        &requests,
        &[
            "/api/status",
            "/api/exception_lists/_find",
            "/api/exception_lists",
            "/api/exception_lists/items/_find",
        ],
    );
    assert_get_route(&requests, "/api/exception_lists/_find", 2, &[("page", "1")]);
    assert_get_route(
        &requests,
        "/api/exception_lists",
        4,
        &[
            ("list_id", "elasticctl-sample-exceptions"),
            ("namespace_type", "single"),
        ],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists/items/_find",
        2,
        &[
            ("list_id", "elasticctl-sample-exceptions"),
            ("namespace_type", "single"),
            ("page", "1"),
        ],
    );
}

#[tokio::test]
async fn exceptions_list_reads_both_namespaces_projects_only_allowed_fields_and_keeps_identity() {
    let server = stack().await;
    mount_find(&server, "single", vec![list("same", None)]).await;
    mount_find(&server, "agnostic", vec![list("same", Some("agnostic"))]).await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(&mut harness, 2, "exceptions_list", json!({})).await;
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(reply["result"]["isError"], false);
    assert_eq!(
        structured["page"],
        json!({"limit": 50, "returned": 2, "total": 2, "has_more": false, "truncated": false})
    );
    let lists = structured["data"]["lists"].as_array().expect("list rows");
    assert_eq!(lists.len(), 2);
    assert_eq!(lists[0]["namespace_type"], "agnostic");
    assert_eq!(lists[1]["namespace_type"], "single");
    for container in lists {
        assert_eq!(container["list_id"], "same");
        assert_eq!(
            object_keys(container),
            expected_keys(&[
                "description",
                "list_id",
                "name",
                "namespace_type",
                "tags",
                "type"
            ])
        );
        assert!(container.get("created_by").is_none());
        assert_eq!(container["tags"], json!(["elasticctl-sample"]));
    }
    assert!(!reply.to_string().contains("container-sentinel"));
    assert!(!reply.to_string().contains("test-api-key"));
    assert_result_text_matches_structured(&reply);
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(&requests, &["/api/status", "/api/exception_lists/_find"]);
    let find_routes = requests
        .iter()
        .filter(|request| request.url.path() == "/api/exception_lists/_find")
        .map(|request| {
            (
                query(request, "namespace_type").expect("namespace"),
                query(request, "page").expect("page"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        find_routes,
        vec![
            ("single".to_string(), "1".to_string()),
            ("agnostic".to_string(), "1".to_string()),
        ]
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn exceptions_get_preserves_container_identity_and_caps_complete_item_rows() {
    let server = stack().await;
    mount_get_list(
        &server,
        "sample",
        "agnostic",
        list("sample", Some("agnostic")),
    )
    .await;
    mount_items(
        &server,
        "sample",
        "agnostic",
        (0..201).map(|n| item(&format!("i{n}"))).collect(),
    )
    .await;
    let mut harness = Harness::start(target_for(&server), options());
    let catalog = tools(&mut harness).await;
    let schema = tool(&catalog, "exceptions_get")["outputSchema"].clone();
    let reply = call(
        &mut harness,
        2,
        "exceptions_get",
        json!({"list_id": "sample", "namespace": "agnostic"}),
    )
    .await;
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(
        structured["data"]["container"]["namespace_type"],
        "agnostic"
    );
    assert_eq!(structured["data"]["items"].as_array().unwrap().len(), 50);
    assert_eq!(structured["page"]["total"], 201);
    assert_eq!(structured["page"]["returned"], 50);
    assert_eq!(structured["page"]["truncated"], true);
    assert_eq!(structured["page"]["has_more"], true);
    let item = &structured["data"]["items"][0];
    assert_eq!(
        object_keys(&structured["data"]),
        expected_keys(&["container", "items"])
    );
    assert_eq!(
        object_keys(&structured["data"]["container"]),
        expected_keys(&[
            "description",
            "list_id",
            "name",
            "namespace_type",
            "tags",
            "type"
        ])
    );
    assert_eq!(
        object_keys(item),
        expected_keys(&[
            "description",
            "entries",
            "item_id",
            "name",
            "os_types",
            "tags"
        ])
    );
    assert_eq!(
        item["entries"],
        json!([{"field": "host.name", "operator": "included", "value": "sentinel"}, 17, null])
    );
    for excluded in ["list_id", "namespace_type", "type", "created_by"] {
        assert!(item.get(excluded).is_none(), "{excluded} is excluded");
    }
    assert!(!reply.to_string().contains("hidden-parent-sentinel"));
    assert!(!reply.to_string().contains("item-sentinel"));
    assert!(!reply.to_string().contains("test-api-key"));
    assert_result_text_matches_structured(&reply);
    let success = root_success(&schema);
    let data = resolved(&schema, &success["properties"]["data"]);
    let container = resolved(&schema, &data["properties"]["container"]);
    assert_eq!(container["required"], json!(["list_id", "namespace_type"]));
    assert_eq!(container["properties"]["namespace_type"]["type"], "string");
    let items = resolved(&schema, &data["properties"]["items"]);
    let row = resolved(&schema, &items["items"]);
    assert_eq!(row["required"], json!(["item_id"]));
    assert!(row["properties"].get("list_id").is_none());
    assert!(
        resolved(&schema, &row["properties"]["entries"])["type"]
            .as_array()
            .is_some_and(|types| types.iter().any(|value| value == "array"))
    );
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(
        &requests,
        &[
            "/api/status",
            "/api/exception_lists",
            "/api/exception_lists/items/_find",
        ],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists",
        2,
        &[("list_id", "sample"), ("namespace_type", "agnostic")],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists/items/_find",
        1,
        &[
            ("list_id", "sample"),
            ("namespace_type", "agnostic"),
            ("page", "1"),
        ],
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn exception_inputs_fail_before_transport_and_preserve_valid_multibyte_filter() {
    for (tool_name, fields) in [
        ("exceptions_list", vec!["list_type", "tag", "search"]),
        ("exceptions_get", vec!["list_id"]),
    ] {
        for value in ["", " \t\n", &"x".repeat(1_025)] {
            let server = stack().await;
            let mut harness = Harness::start(target_for(&server), options());
            for field in &fields {
                let reply = call(&mut harness, 2, tool_name, json!({(*field): value})).await;
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
    }
    for (tool_name, arguments) in [
        ("exceptions_list", json!({"namespace": "unknown"})),
        (
            "exceptions_get",
            json!({"list_id": "sample", "namespace": "unknown"}),
        ),
        ("exceptions_list", json!({"unexpected": true})),
        ("exceptions_get", json!({"list_id": "sample", "limit": 201})),
    ] {
        let server = stack().await;
        let mut harness = Harness::start(target_for(&server), options());
        let reply = call(&mut harness, 2, tool_name, arguments).await;
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"],
            "invalid_argument"
        );
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
    for (tool_name, field) in [
        ("exceptions_list", "list_type"),
        ("exceptions_list", "tag"),
        ("exceptions_list", "search"),
        ("exceptions_get", "list_id"),
    ] {
        for value in ["x".repeat(1_024), "é".repeat(512)] {
            let server = stack().await;
            let mut harness = Harness::start(target_for(&server), options());
            let reply = call(&mut harness, 2, tool_name, json!({field: value})).await;
            assert_ne!(
                reply["result"]["structuredContent"]["error"]["code"],
                "invalid_argument"
            );
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
    }
    let server = stack().await;
    let text = "é".repeat(512);
    mount_find(&server, "single", vec![]).await;
    mount_find(&server, "agnostic", vec![]).await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(&mut harness, 2, "exceptions_list", json!({"search": text})).await;
    assert_eq!(reply["result"]["isError"], false);
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(
        requests[1]
            .url
            .query_pairs()
            .find(|(key, _)| key == "filter")
            .map(|(_, value)| value.into_owned()),
        Some(format!(
            "exception-list.attributes.name: \"*{}*\"",
            "é".repeat(512)
        ))
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn exceptions_list_preserves_open_filter_text_and_explicit_namespace_mapping() {
    let server = stack().await;
    mount_find(&server, "agnostic", vec![]).await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(
        &mut harness,
        2,
        "exceptions_list",
        json!({
            "namespace": "agnostic",
            "list_type": "future-type",
            "tag": "tag value",
            "search": "猫",
            "limit": 200,
        }),
    )
    .await;
    assert_eq!(reply["result"]["isError"], false);
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 2);
    assert_read_paths(&requests, &["/api/status", "/api/exception_lists/_find"]);
    assert_get_route(
        &requests,
        "/api/exception_lists/_find",
        1,
        &[("namespace_type", "agnostic"), ("page", "1")],
    );
    assert_eq!(
        requests[1]
            .url
            .query_pairs()
            .find(|(key, _)| key == "namespace_type")
            .map(|(_, value)| value.into_owned()),
        Some("agnostic".to_string())
    );
    let filter = requests[1]
        .url
        .query_pairs()
        .find(|(key, _)| key == "filter")
        .map(|(_, value)| value.into_owned())
        .expect("filter query");
    assert!(filter.contains("future-type"));
    assert!(filter.contains("tag value"));
    assert!(filter.contains("猫"));
    assert!(requests.iter().all(|request| request.method == "GET"));
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn exceptions_list_keeps_exact_totals_at_row_and_byte_caps() {
    let server = stack().await;
    mount_find(
        &server,
        "single",
        (0..201)
            .map(|index| list(&format!("l{index}"), Some("single")))
            .collect(),
    )
    .await;
    mount_find(&server, "agnostic", vec![]).await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(&mut harness, 2, "exceptions_list", json!({})).await;
    assert_eq!(reply["result"]["structuredContent"]["page"]["total"], 201);
    assert_eq!(reply["result"]["structuredContent"]["page"]["returned"], 50);
    assert_eq!(
        reply["result"]["structuredContent"]["page"]["truncated"],
        true
    );
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(&requests, &["/api/status", "/api/exception_lists/_find"]);
    assert_get_route(&requests, "/api/exception_lists/_find", 2, &[("page", "1")]);
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = stack().await;
    let mut large = list("large", Some("single"));
    large["description"] = json!("x".repeat(262_145));
    mount_find(&server, "single", vec![large]).await;
    mount_find(&server, "agnostic", vec![]).await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(&mut harness, 2, "exceptions_list", json!({})).await;
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["code"],
        "result_too_large"
    );
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(&requests, &["/api/status", "/api/exception_lists/_find"]);
    assert_get_route(&requests, "/api/exception_lists/_find", 2, &[("page", "1")]);
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = stack().await;
    let mut first = list("first", Some("single"));
    first["description"] = json!("x".repeat(150_000));
    let mut second = list("second", Some("single"));
    second["description"] = json!("y".repeat(150_000));
    mount_find(&server, "single", vec![first, second]).await;
    mount_find(&server, "agnostic", vec![]).await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(&mut harness, 2, "exceptions_list", json!({"limit": 2})).await;
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(structured["data"]["lists"].as_array().unwrap().len(), 1);
    assert_eq!(
        structured["page"],
        json!({"limit": 2, "returned": 1, "total": 2, "has_more": true, "truncated": true})
    );
    assert_result_text_matches_structured(&reply);
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(&requests, &["/api/status", "/api/exception_lists/_find"]);
    assert_get_route(&requests, "/api/exception_lists/_find", 2, &[("page", "1")]);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn exception_get_keeps_namespace_ambiguity_and_rejects_malformed_selected_data() {
    let server = stack().await;
    mount_get_list(&server, "same", "single", list("same", Some("single"))).await;
    mount_get_list(&server, "same", "agnostic", list("same", Some("agnostic"))).await;
    let mut harness = Harness::start(target_for(&server), options());
    let conflict = call(
        &mut harness,
        2,
        "exceptions_get",
        json!({"list_id": "same"}),
    )
    .await;
    assert_eq!(
        conflict["result"]["structuredContent"]["error"]["kind"],
        "conflict"
    );
    assert_eq!(
        conflict["result"]["structuredContent"]["error"]["code"],
        "elastic_conflict"
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 3);
    assert_read_paths(&requests, &["/api/status", "/api/exception_lists"]);
    assert_get_route(&requests, "/api/exception_lists", 2, &[("list_id", "same")]);
    assert_result_text_matches_structured(&conflict);
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = stack().await;
    let mut malformed = list("broken", Some("single"));
    malformed["namespace_type"] = json!(17);
    mount_get_list(&server, "broken", "single", malformed).await;
    mount_items(&server, "broken", "single", vec![]).await;
    let mut harness = Harness::start(target_for(&server), options());
    let malformed = call(
        &mut harness,
        2,
        "exceptions_get",
        json!({"list_id": "broken", "namespace": "single"}),
    )
    .await;
    assert_eq!(
        malformed["result"]["structuredContent"]["error"]["code"],
        "elastic_http"
    );
    assert_result_text_matches_structured(&malformed);
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(
        &requests,
        &[
            "/api/status",
            "/api/exception_lists",
            "/api/exception_lists/items/_find",
        ],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists",
        2,
        &[("list_id", "broken"), ("namespace_type", "single")],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists/items/_find",
        1,
        &[
            ("list_id", "broken"),
            ("namespace_type", "single"),
            ("page", "1"),
        ],
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn exception_failures_are_classified_without_remote_sentinels_and_use_read_routes_only() {
    let server = stack().await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/_find"))
        .and(query_param("namespace_type", "single"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"message": "list-error-sentinel"})),
        )
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let list_reply = call(&mut harness, 2, "exceptions_list", json!({})).await;
    assert_eq!(
        list_reply["result"]["structuredContent"]["error"]["code"],
        "elastic_http"
    );
    assert!(!list_reply.to_string().contains("list-error-sentinel"));
    assert_result_text_matches_structured(&list_reply);
    let list_requests = server.received_requests().await.expect("requests");
    assert_read_paths(
        &list_requests,
        &["/api/status", "/api/exception_lists/_find"],
    );
    assert_get_route(
        &list_requests,
        "/api/exception_lists/_find",
        3,
        &[("namespace_type", "single"), ("page", "1")],
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = stack().await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists"))
        .and(query_param("list_id", "missing"))
        .and(query_param("namespace_type", "single"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"message": "get-error-sentinel"})),
        )
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let get_reply = call(
        &mut harness,
        2,
        "exceptions_get",
        json!({"list_id": "missing", "namespace": "single"}),
    )
    .await;
    assert_eq!(
        get_reply["result"]["structuredContent"]["error"]["code"],
        "elastic_http"
    );
    assert!(!get_reply.to_string().contains("get-error-sentinel"));
    assert_result_text_matches_structured(&get_reply);
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(&requests, &["/api/status", "/api/exception_lists"]);
    assert_get_route(
        &requests,
        "/api/exception_lists",
        3,
        &[("list_id", "missing"), ("namespace_type", "single")],
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn exception_empty_and_malformed_collector_responses_do_not_become_partial_successes() {
    let server = stack().await;
    mount_find(&server, "single", vec![]).await;
    mount_find(&server, "agnostic", vec![]).await;
    mount_get_list(&server, "empty", "single", list("empty", Some("single"))).await;
    mount_items(&server, "empty", "single", vec![]).await;
    let mut harness = Harness::start(target_for(&server), options());
    let list_reply = call(&mut harness, 2, "exceptions_list", json!({})).await;
    assert_eq!(
        list_reply["result"]["structuredContent"]["data"]["lists"],
        json!([])
    );
    assert_eq!(
        list_reply["result"]["structuredContent"]["page"]["total"],
        0
    );
    let get_reply = call(
        &mut harness,
        3,
        "exceptions_get",
        json!({"list_id": "empty", "namespace": "single"}),
    )
    .await;
    assert_eq!(
        get_reply["result"]["structuredContent"]["data"]["items"],
        json!([])
    );
    assert_eq!(get_reply["result"]["structuredContent"]["page"]["total"], 0);
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(
        &requests,
        &[
            "/api/status",
            "/api/exception_lists/_find",
            "/api/exception_lists",
            "/api/exception_lists/items/_find",
        ],
    );
    assert_get_route(&requests, "/api/exception_lists/_find", 2, &[("page", "1")]);
    assert_get_route(
        &requests,
        "/api/exception_lists",
        2,
        &[("list_id", "empty"), ("namespace_type", "single")],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists/items/_find",
        1,
        &[
            ("list_id", "empty"),
            ("namespace_type", "single"),
            ("page", "1"),
        ],
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = stack().await;
    mount_get_list(
        &server,
        "malformed",
        "single",
        list("malformed", Some("single")),
    )
    .await;
    mount_items(
        &server,
        "malformed",
        "single",
        vec![json!({"item_id": 17, "created_by": "malformed-item-sentinel"})],
    )
    .await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(
        &mut harness,
        2,
        "exceptions_get",
        json!({"list_id": "malformed", "namespace": "single"}),
    )
    .await;
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["code"],
        "elastic_error"
    );
    assert!(!reply.to_string().contains("malformed-item-sentinel"));
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(
        &requests,
        &[
            "/api/status",
            "/api/exception_lists",
            "/api/exception_lists/items/_find",
        ],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists",
        2,
        &[("list_id", "malformed"), ("namespace_type", "single")],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists/items/_find",
        1,
        &[
            ("list_id", "malformed"),
            ("namespace_type", "single"),
            ("page", "1"),
        ],
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn exception_get_refuses_absent_short_or_oversized_results_and_preserves_unicode_and_selector_text()
 {
    let server = stack().await;
    let mut harness = Harness::start(target_for(&server), options());
    let absent = call(
        &mut harness,
        2,
        "exceptions_get",
        json!({"list_id": "absent"}),
    )
    .await;
    assert_eq!(
        absent["result"]["structuredContent"]["error"]["code"],
        "elastic_not_found"
    );
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(&requests, &["/api/status", "/api/exception_lists"]);
    assert_get_route(
        &requests,
        "/api/exception_lists",
        2,
        &[("list_id", "absent")],
    );
    let namespaces = requests
        .iter()
        .filter(|request| request.url.path() == "/api/exception_lists")
        .map(|request| query(request, "namespace_type").expect("namespace"))
        .collect::<Vec<_>>();
    assert_eq!(namespaces, vec!["single", "agnostic"]);
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = stack().await;
    mount_get_list(&server, "short", "single", list("short", Some("single"))).await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/items/_find"))
        .and(query_param("list_id", "short"))
        .and(query_param("namespace_type", "single"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [], "page": 1, "per_page": 10000, "total": 1,
        })))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let short = call(
        &mut harness,
        2,
        "exceptions_get",
        json!({"list_id": "short", "namespace": "single"}),
    )
    .await;
    assert_eq!(
        short["result"]["structuredContent"]["error"]["code"],
        "elastic_http"
    );
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(
        &requests,
        &[
            "/api/status",
            "/api/exception_lists",
            "/api/exception_lists/items/_find",
        ],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists",
        2,
        &[("list_id", "short"), ("namespace_type", "single")],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists/items/_find",
        1,
        &[
            ("list_id", "short"),
            ("namespace_type", "single"),
            ("page", "1"),
        ],
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = stack().await;
    let selector = "  unicode list 猫\t";
    mount_get_list(&server, selector, "single", list(selector, Some("single"))).await;
    let mut unicode = item("unicode-item");
    unicode["description"] = json!("猫".repeat(1_000));
    mount_items(&server, selector, "single", vec![unicode]).await;
    let mut harness = Harness::start(target_for(&server), options());
    let unicode = call(
        &mut harness,
        2,
        "exceptions_get",
        json!({"list_id": selector, "namespace": "single"}),
    )
    .await;
    assert_eq!(unicode["result"]["isError"], false);
    assert_eq!(
        unicode["result"]["structuredContent"]["data"]["items"][0]["description"],
        "猫".repeat(1_000)
    );
    let requests = server.received_requests().await.expect("requests");
    assert!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/api/exception_lists")
            .all(|request| {
                request
                    .url
                    .query_pairs()
                    .find(|(key, _)| key == "list_id")
                    .is_some_and(|(_, value)| value == selector)
            })
    );
    assert_read_paths(
        &requests,
        &[
            "/api/status",
            "/api/exception_lists",
            "/api/exception_lists/items/_find",
        ],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists",
        2,
        &[("list_id", selector), ("namespace_type", "single")],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists/items/_find",
        1,
        &[
            ("list_id", selector),
            ("namespace_type", "single"),
            ("page", "1"),
        ],
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = stack().await;
    mount_get_list(
        &server,
        "large-item",
        "single",
        list("large-item", Some("single")),
    )
    .await;
    let mut large = item("large-item");
    large["description"] = json!("x".repeat(262_145));
    mount_items(&server, "large-item", "single", vec![large]).await;
    let mut harness = Harness::start(target_for(&server), options());
    let large = call(
        &mut harness,
        2,
        "exceptions_get",
        json!({"list_id": "large-item", "namespace": "single"}),
    )
    .await;
    assert_eq!(large["result"]["isError"], true);
    assert_eq!(
        large["result"]["structuredContent"]["error"]["code"],
        "result_too_large"
    );
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(
        &requests,
        &[
            "/api/status",
            "/api/exception_lists",
            "/api/exception_lists/items/_find",
        ],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists",
        2,
        &[("list_id", "large-item"), ("namespace_type", "single")],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists/items/_find",
        1,
        &[
            ("list_id", "large-item"),
            ("namespace_type", "single"),
            ("page", "1"),
        ],
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn exception_projections_default_null_namespace_omit_optional_fields_and_bound_bytes() {
    let server = stack().await;
    let mut container =
        json!({"list_id": "minimal", "namespace_type": null, "name": "", "tags": []});
    mount_get_list(&server, "minimal", "single", container.take()).await;
    let mut minimal_item = json!({"item_id": "", "name": "", "entries": null, "tags": []});
    mount_items(&server, "minimal", "single", vec![minimal_item.take()]).await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(
        &mut harness,
        2,
        "exceptions_get",
        json!({"list_id": "minimal", "namespace": "single"}),
    )
    .await;
    let data = &reply["result"]["structuredContent"]["data"];
    assert_eq!(data["container"]["namespace_type"], "single");
    assert_eq!(data["container"]["name"], "");
    assert_eq!(data["container"]["tags"], json!([]));
    assert!(data["container"].get("description").is_none());
    assert_eq!(data["items"][0]["item_id"], "");
    assert_eq!(data["items"][0]["name"], "");
    assert_eq!(data["items"][0]["tags"], json!([]));
    assert!(data["items"][0].get("entries").is_none());
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(
        &requests,
        &[
            "/api/status",
            "/api/exception_lists",
            "/api/exception_lists/items/_find",
        ],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists",
        2,
        &[("list_id", "minimal"), ("namespace_type", "single")],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists/items/_find",
        1,
        &[
            ("list_id", "minimal"),
            ("namespace_type", "single"),
            ("page", "1"),
        ],
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = stack().await;
    mount_get_list(&server, "large", "single", list("large", Some("single"))).await;
    let oversized_rows = (0..50)
        .map(|n| {
            let mut value = item(&format!("i{n}"));
            value["description"] = json!("x".repeat(7_000));
            value
        })
        .collect();
    mount_items(&server, "large", "single", oversized_rows).await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(
        &mut harness,
        2,
        "exceptions_get",
        json!({"list_id": "large", "namespace": "single", "limit": 50}),
    )
    .await;
    let page = &reply["result"]["structuredContent"]["page"];
    assert!(page["returned"].as_u64().unwrap() < 50);
    assert_eq!(page["total"], 50);
    assert_eq!(page["truncated"], true);
    assert_eq!(page["has_more"], true);
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(
        &requests,
        &[
            "/api/status",
            "/api/exception_lists",
            "/api/exception_lists/items/_find",
        ],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists",
        2,
        &[("list_id", "large"), ("namespace_type", "single")],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists/items/_find",
        1,
        &[
            ("list_id", "large"),
            ("namespace_type", "single"),
            ("page", "1"),
        ],
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn exception_inputs_cover_null_limits_unicode_overflow_exact_filters_and_feature_floor() {
    let server = stack().await;
    mount_find(&server, "single", vec![]).await;
    mount_find(&server, "agnostic", vec![]).await;
    let mut harness = Harness::start(target_for(&server), options());
    let list_reply = call(
        &mut harness,
        2,
        "exceptions_list",
        json!({"list_type": null, "tag": null, "namespace": null, "search": null}),
    )
    .await;
    assert_eq!(list_reply["result"]["isError"], false);
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(&requests, &["/api/status", "/api/exception_lists/_find"]);
    assert_get_route(&requests, "/api/exception_lists/_find", 2, &[("page", "1")]);
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = stack().await;
    mount_get_list(
        &server,
        "null-namespace",
        "single",
        list("null-namespace", Some("single")),
    )
    .await;
    mount_items(&server, "null-namespace", "single", vec![]).await;
    let mut harness = Harness::start(target_for(&server), options());
    let get_reply = call(
        &mut harness,
        2,
        "exceptions_get",
        json!({"list_id": "null-namespace", "namespace": null}),
    )
    .await;
    assert_eq!(get_reply["result"]["isError"], false);
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(
        &requests,
        &[
            "/api/status",
            "/api/exception_lists",
            "/api/exception_lists/items/_find",
        ],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists",
        3,
        &[("list_id", "null-namespace")],
    );
    let namespaces = requests
        .iter()
        .filter(|request| request.url.path() == "/api/exception_lists")
        .map(|request| query(request, "namespace_type").expect("namespace"))
        .collect::<Vec<_>>();
    assert_eq!(namespaces, vec!["single", "agnostic", "single"]);
    assert_get_route(
        &requests,
        "/api/exception_lists/items/_find",
        1,
        &[
            ("list_id", "null-namespace"),
            ("namespace_type", "single"),
            ("page", "1"),
        ],
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");

    for (name, base) in [
        ("exceptions_list", json!({})),
        ("exceptions_get", json!({"list_id": "value"})),
    ] {
        for limit in [
            Value::Null,
            json!(0),
            json!(-1),
            json!(1.5),
            json!("1"),
            json!(201),
        ] {
            let server = stack().await;
            let mut arguments = base.clone();
            arguments["limit"] = limit;
            let mut harness = Harness::start(target_for(&server), options());
            let reply = call(&mut harness, 2, name, arguments).await;
            assert_eq!(
                reply["result"]["structuredContent"]["error"]["code"],
                "invalid_argument"
            );
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
    }
    for (name, field) in [
        ("exceptions_list", "list_type"),
        ("exceptions_list", "tag"),
        ("exceptions_list", "search"),
        ("exceptions_get", "list_id"),
    ] {
        let server = stack().await;
        let mut harness = Harness::start(target_for(&server), options());
        let reply = call(&mut harness, 2, name, json!({field: "é".repeat(513)})).await;
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"],
            "invalid_argument"
        );
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

    let server = stack().await;
    mount_find(&server, "agnostic", vec![]).await;
    let list_type = "  type\\\"  ";
    let tag = "  tag\\\"  ";
    let search = "  *?\\\"  ";
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(
        &mut harness,
        2,
        "exceptions_list",
        json!({"namespace": "agnostic", "list_type": list_type, "tag": tag, "search": search}),
    )
    .await;
    assert_eq!(reply["result"]["isError"], false);
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(&requests, &["/api/status", "/api/exception_lists/_find"]);
    assert_get_route(
        &requests,
        "/api/exception_lists/_find",
        1,
        &[("namespace_type", "agnostic"), ("page", "1")],
    );
    let request = requests.last().expect("find request");
    let filter = request
        .url
        .query_pairs()
        .find(|(key, _)| key == "filter")
        .map(|(_, value)| value.into_owned());
    assert_eq!(
        filter,
        Some(r#"exception-list-agnostic.attributes.type: "  type\\\"  " AND exception-list-agnostic.attributes.tags: "  tag\\\"  " AND exception-list-agnostic.attributes.name: "*  \*\?\\\"  *""#.to_string())
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = stack_with_version("9.5.0").await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(&mut harness, 2, "exceptions_list", json!({})).await;
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["code"],
        "elastic_unsupported"
    );
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(&requests, &["/api/status"]);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn exception_collectors_page_before_capping_and_reject_later_malformed_items() {
    let server = stack().await;
    mount_get_list(&server, "paged", "single", list("paged", Some("single"))).await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/items/_find"))
        .and(query_param("list_id", "paged"))
        .and(query_param("namespace_type", "single"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": (0..50).map(|index| item(&format!("i{index}"))).collect::<Vec<_>>(),
            "page": 1, "per_page": 10000, "total": 51,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/items/_find"))
        .and(query_param("list_id", "paged"))
        .and(query_param("namespace_type", "single"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"item_id": 17, "created_by": "later-item-sentinel"}],
            "page": 2, "per_page": 10000, "total": 51,
        })))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(
        &mut harness,
        2,
        "exceptions_get",
        json!({"list_id": "paged", "namespace": "single", "limit": 50}),
    )
    .await;
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["code"],
        "elastic_error"
    );
    assert!(!reply.to_string().contains("later-item-sentinel"));
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(
        &requests,
        &[
            "/api/status",
            "/api/exception_lists",
            "/api/exception_lists/items/_find",
        ],
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/api/exception_lists/items/_find")
            .count(),
        2
    );
    let item_pages = requests
        .iter()
        .filter(|request| request.url.path() == "/api/exception_lists/items/_find")
        .map(|request| query(request, "page").expect("item page"))
        .collect::<Vec<_>>();
    assert_eq!(item_pages, vec!["1", "2"]);
    assert_get_route(
        &requests,
        "/api/exception_lists",
        2,
        &[("list_id", "paged"), ("namespace_type", "single")],
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = stack().await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/_find"))
        .and(query_param("namespace_type", "single"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": (0..200).map(|index| list(&format!("l{index}"), Some("single"))).collect::<Vec<_>>(),
            "page": 1, "per_page": 10000, "total": 201,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/_find"))
        .and(query_param("namespace_type", "single"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [list("l200", Some("single"))], "page": 2, "per_page": 10000, "total": 201,
        })))
        .mount(&server)
        .await;
    mount_find(&server, "agnostic", vec![]).await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(&mut harness, 2, "exceptions_list", json!({})).await;
    assert_eq!(
        reply["result"]["structuredContent"]["page"],
        json!({"limit":50,"returned":50,"total":201,"has_more":true,"truncated":true})
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/api/exception_lists/_find")
            .count(),
        3
    );
    assert_read_paths(&requests, &["/api/status", "/api/exception_lists/_find"]);
    let find_pages = requests
        .iter()
        .filter(|request| request.url.path() == "/api/exception_lists/_find")
        .map(|request| {
            (
                query(request, "namespace_type").expect("namespace"),
                query(request, "page").expect("page"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        find_pages,
        vec![
            ("single".to_string(), "1".to_string()),
            ("single".to_string(), "2".to_string()),
            ("agnostic".to_string(), "1".to_string())
        ]
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn exception_projection_rejects_wrong_optional_outer_types_and_keeps_container_during_item_byte_truncation()
 {
    for (field, value) in [
        ("name", json!(17)),
        ("description", json!([])),
        ("type", json!(false)),
        ("tags", json!("not-an-array")),
    ] {
        let server = stack().await;
        let mut container = list("wrong-container", Some("single"));
        container[field] = value;
        mount_get_list(&server, "wrong-container", "single", container).await;
        mount_items(&server, "wrong-container", "single", vec![]).await;
        let mut harness = Harness::start(target_for(&server), options());
        let reply = call(
            &mut harness,
            2,
            "exceptions_get",
            json!({"list_id": "wrong-container", "namespace": "single"}),
        )
        .await;
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"],
            "elastic_http"
        );
        assert!(!reply.to_string().contains("test-api-key"));
        let requests = server.received_requests().await.expect("requests");
        assert_read_paths(
            &requests,
            &[
                "/api/status",
                "/api/exception_lists",
                "/api/exception_lists/items/_find",
            ],
        );
        assert_get_route(
            &requests,
            "/api/exception_lists",
            2,
            &[("list_id", "wrong-container"), ("namespace_type", "single")],
        );
        assert_get_route(
            &requests,
            "/api/exception_lists/items/_find",
            1,
            &[
                ("list_id", "wrong-container"),
                ("namespace_type", "single"),
                ("page", "1"),
            ],
        );
        harness.close_input();
        harness.join().await.expect("clean EOF");
    }
    for (field, value) in [
        ("name", json!(17)),
        ("description", json!([])),
        ("os_types", json!("not-an-array")),
        ("tags", json!({})),
        ("entries", json!({"not": "an array"})),
    ] {
        let server = stack().await;
        mount_get_list(
            &server,
            "wrong-item",
            "single",
            list("wrong-item", Some("single")),
        )
        .await;
        let mut bad = item("bad");
        bad[field] = value;
        mount_items(&server, "wrong-item", "single", vec![bad]).await;
        let mut harness = Harness::start(target_for(&server), options());
        let reply = call(
            &mut harness,
            2,
            "exceptions_get",
            json!({"list_id": "wrong-item", "namespace": "single"}),
        )
        .await;
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"],
            "elastic_http"
        );
        assert!(!reply.to_string().contains("test-api-key"));
        let requests = server.received_requests().await.expect("requests");
        assert_read_paths(
            &requests,
            &[
                "/api/status",
                "/api/exception_lists",
                "/api/exception_lists/items/_find",
            ],
        );
        assert_get_route(
            &requests,
            "/api/exception_lists",
            2,
            &[("list_id", "wrong-item"), ("namespace_type", "single")],
        );
        assert_get_route(
            &requests,
            "/api/exception_lists/items/_find",
            1,
            &[
                ("list_id", "wrong-item"),
                ("namespace_type", "single"),
                ("page", "1"),
            ],
        );
        harness.close_input();
        harness.join().await.expect("clean EOF");
    }

    let server = stack().await;
    let container = list("byte-container", Some("single"));
    mount_get_list(&server, "byte-container", "single", container.clone()).await;
    let rows = (0..50)
        .map(|index| {
            let mut row = item(&format!("i{index}"));
            row["description"] = json!("x".repeat(7_000));
            row
        })
        .collect();
    mount_items(&server, "byte-container", "single", rows).await;
    let mut harness = Harness::start(target_for(&server), options());
    let reply = call(
        &mut harness,
        2,
        "exceptions_get",
        json!({"list_id": "byte-container", "namespace": "single", "limit": 50}),
    )
    .await;
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(
        structured["data"]["container"],
        json!({"list_id":"byte-container","namespace_type":"single","name":"sample name","description":"sample description","type":"detection","tags":["elasticctl-sample"]})
    );
    assert!(structured["page"]["returned"].as_u64().unwrap() < 50);
    assert_eq!(structured["page"]["total"], 50);
    assert_eq!(structured["page"]["has_more"], true);
    assert_eq!(structured["page"]["truncated"], true);
    assert_result_text_matches_structured(&reply);
    assert!(!reply.to_string().contains("test-api-key"));
    let requests = server.received_requests().await.expect("requests");
    assert_read_paths(
        &requests,
        &[
            "/api/status",
            "/api/exception_lists",
            "/api/exception_lists/items/_find",
        ],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists",
        2,
        &[("list_id", "byte-container"), ("namespace_type", "single")],
    );
    assert_get_route(
        &requests,
        "/api/exception_lists/items/_find",
        1,
        &[
            ("list_id", "byte-container"),
            ("namespace_type", "single"),
            ("page", "1"),
        ],
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}
