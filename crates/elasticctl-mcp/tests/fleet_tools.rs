mod support;

use std::{env, process::Command};

use elasticctl_core::{Profile, Resolved, Source};
use serde_json::{Value, json};
use support::{EXPECTED_TOOL_NAMES, Harness, current_metadata, legacy_initialize, options};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

fn target_for(server: &MockServer) -> Resolved {
    Resolved {
        name: "test".into(),
        source: Source::Profile,
        profile: Profile {
            kibana_url: server.uri(),
            es_url: Some(server.uri()),
            api_key: Some("test-api-key".into()),
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 30,
        },
    }
}

async fn call(harness: &mut Harness, id: u64, name: &str, arguments: Value) -> Value {
    harness.send_json(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"_meta":current_metadata(),"name":name,"arguments":arguments}})).await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], id);
    reply
}

fn content(reply: &Value) -> &Value {
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(
        serde_json::from_str::<Value>(
            reply["result"]["content"][0]["text"]
                .as_str()
                .expect("text")
        )
        .expect("json copy"),
        *structured
    );
    structured
}

fn failure(reply: &Value) -> &Value {
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    &reply["result"]["structuredContent"]
}

async fn mount_status(server: &MockServer, version: &str) {
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"version":{"number":version,"build_flavor":"traditional"}})),
        )
        .mount(server)
        .await;
}

fn fixture(name: &str) -> Value {
    let source = match name {
        "agent_list" => {
            include_str!("../../../tests/fixtures/traditional-9.5.1/agent_policies_list.json")
        }
        "agent_get" => {
            include_str!("../../../tests/fixtures/traditional-9.5.1/agent_policy_get.json")
        }
        "integration_list" => {
            include_str!("../../../tests/fixtures/traditional-9.5.1/integration_policies_list.json")
        }
        "integration_get" => {
            include_str!("../../../tests/fixtures/traditional-9.5.1/integration_policy_get.json")
        }
        _ => panic!("unknown fixture"),
    };
    serde_json::from_str::<Value>(source).expect("recorded Fleet fixture decodes")["response"]
        .clone()
}

fn agent(id: &str, name: &str) -> Value {
    json!({"id":id,"name":name,"namespace":"default","description":"safe description","agents":1,"status":"active","package_policies":["integration-1"],"updated_by":"private-sentinel","integrations":[{"vars":{"token":"private-sentinel"}}]})
}
fn integration(id: &str, name: &str) -> Value {
    json!({"id":id,"name":name,"namespace":"default","description":"safe description","policy_ids":["parent-1"],"package":{"name":"system","version":"2.0.0"},"inputs":{},"enabled":true})
}
fn parent(id: &str, integration_id: &str) -> Value {
    let mut value = agent(id, "parent");
    value["package_policies"] = json!([integration_id]);
    value
}
fn page(items: Vec<Value>, total: usize) -> Value {
    json!({"items":items,"total":total,"page":1,"perPage":1000})
}

async fn mount_agent_list(server: &MockServer, body: Value) {
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}
async fn mount_integration_list(server: &MockServer, body: Value) {
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn assert_read_routes(server: &MockServer, expected: &[&str]) {
    let mut actual = server
        .received_requests()
        .await
        .expect("requests")
        .iter()
        .map(|request| format!("{} {}", request.method, request.url.path()))
        .collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = expected
        .iter()
        .map(|path| format!("GET {path}"))
        .collect::<Vec<_>>();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

async fn assert_requested_pages(server: &MockServer, path: &str, expected: &[&str]) {
    let actual = server
        .received_requests()
        .await
        .expect("requests")
        .iter()
        .filter(|request| request.url.path() == path)
        .filter_map(|request| {
            request
                .url
                .query_pairs()
                .find(|(name, _)| name == "page")
                .map(|(_, value)| value.into_owned())
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

fn tool<'a>(tools: &'a [Value], name: &str) -> &'a Value {
    tools
        .iter()
        .find(|tool| tool["name"] == name)
        .expect("Fleet tool")
}
fn resolve<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    let mut schema = schema;
    while let Some(reference) = schema["$ref"].as_str() {
        schema = root
            .pointer(reference.strip_prefix('#').expect("local reference"))
            .expect("reference");
    }
    schema
}
fn has_type(root: &Value, schema: &Value, kind: &str) -> bool {
    let schema = resolve(root, schema);
    schema["type"] == kind
        || schema["type"]
            .as_array()
            .is_some_and(|types| types.iter().any(|value| value == kind))
        || schema["anyOf"]
            .as_array()
            .is_some_and(|branches| branches.iter().any(|branch| has_type(root, branch, kind)))
}
fn nullable(root: &Value, schema: &Value, kind: &str, expected: bool) {
    assert!(has_type(root, schema, kind));
    assert_eq!(has_type(root, schema, "null"), expected);
}
fn property_names(schema: &Value) -> Vec<&str> {
    let mut names = schema["properties"]
        .as_object()
        .expect("properties")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}
fn array_branch<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    let schema = resolve(root, schema);
    if schema.get("items").is_some() && has_type(root, schema, "array") {
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
fn object_schema<'a>(
    root: &'a Value,
    schema: &'a Value,
    fields: &[&str],
    required: &[&str],
) -> &'a Value {
    let schema = resolve(root, schema);
    let schema = if schema.get("properties").is_some() {
        schema
    } else {
        schema["anyOf"]
            .as_array()
            .expect("object alternatives")
            .iter()
            .map(|branch| resolve(root, branch))
            .find(|branch| branch.get("properties").is_some())
            .expect("object branch")
    };
    assert!(has_type(root, schema, "object"));
    assert!(schema.get("additionalProperties").is_none());
    let mut actual = schema["properties"]
        .as_object()
        .expect("properties")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = fields.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected, "{schema}");
    let mut actual = schema["required"]
        .as_array()
        .map(|fields| {
            fields
                .iter()
                .map(|field| field.as_str().expect("required"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    actual.sort_unstable();
    let mut expected = required.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected);
    schema
}

#[tokio::test]
async fn fleet_catalog_declares_closed_inputs_safe_outputs_and_common_envelopes() {
    let mut harness = Harness::start(support::target(), options());
    harness.send_json(json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":current_metadata()}})).await;
    let reply = harness.receive_json().await;
    let tools = reply["result"]["tools"].as_array().expect("tool list");
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool["name"].as_str().expect("tool name"))
            .collect::<Vec<_>>(),
        EXPECTED_TOOL_NAMES,
    );
    for (name, field, is_list, data_key, row_fields, required) in [
        (
            "fleet_agent_policies_list",
            "search",
            true,
            "agent_policies",
            vec!["id", "name", "namespace", "description", "agents"],
            vec!["id", "name", "namespace"],
        ),
        (
            "fleet_agent_policies_get",
            "selector",
            false,
            "",
            vec![
                "id",
                "name",
                "namespace",
                "description",
                "agents",
                "status",
                "attached_integrations",
                "blocked_by",
            ],
            vec![
                "id",
                "name",
                "namespace",
                "agents",
                "attached_integrations",
                "blocked_by",
            ],
        ),
        (
            "fleet_integration_policies_list",
            "search",
            true,
            "integration_policies",
            vec![
                "id",
                "name",
                "namespace",
                "description",
                "policy_ids",
                "package",
            ],
            vec!["id", "name", "namespace", "policy_ids", "package"],
        ),
        (
            "fleet_integration_policies_get",
            "selector",
            false,
            "",
            vec![
                "id",
                "name",
                "namespace",
                "description",
                "policy_ids",
                "package",
                "affected_agents",
                "blocked_by",
            ],
            vec![
                "id",
                "name",
                "namespace",
                "policy_ids",
                "package",
                "affected_agents",
                "blocked_by",
            ],
        ),
    ] {
        let tool = tool(tools, name);
        assert_eq!(
            tool["annotations"],
            json!({"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true})
        );
        let input = &tool["inputSchema"];
        assert_eq!(input["type"], "object");
        assert_eq!(input["additionalProperties"], false);
        if is_list {
            assert_eq!(property_names(input), ["limit", "search"]);
            assert!(input["required"].is_null());
            assert_eq!(input["properties"]["limit"]["default"], 50);
            assert_eq!(input["properties"]["limit"]["minimum"], 1);
            assert_eq!(input["properties"]["limit"]["maximum"], 200);
            nullable(input, &input["properties"]["limit"], "integer", false);
        } else {
            assert_eq!(property_names(input), ["selector"]);
            assert_eq!(input["required"], json!(["selector"]));
        }
        let string = &input["properties"][field];
        assert!(has_type(input, string, "string"), "{name}: {string}");
        assert!(has_type(input, string, "null") == is_list);
        let string = string["anyOf"]
            .as_array()
            .and_then(|branches| branches.iter().find(|branch| branch["type"] == "string"))
            .unwrap_or(string);
        assert_eq!(string["minLength"], 1);
        assert_eq!(string["maxLength"], 1024);
        let description = string["description"].as_str().expect("description");
        for clause in ["non-whitespace", "1,024 UTF-8 bytes", "used unchanged"] {
            assert!(
                description.contains(clause),
                "{name} {field}: {description}"
            );
        }
        let output = &tool["outputSchema"];
        assert_eq!(output["type"], "object");
        assert_eq!(output["anyOf"].as_array().map(Vec::len), Some(2));
        let success = output["anyOf"]
            .as_array()
            .expect("output union")
            .iter()
            .map(|branch| resolve(output, branch))
            .find(|branch| branch["properties"].get("data").is_some())
            .expect("success");
        object_schema(
            output,
            success,
            &["target", "data", "page"],
            &["target", "data"],
        );
        let target = object_schema(
            output,
            &success["properties"]["target"],
            &["host", "profile", "space"],
            &["host", "profile", "space"],
        );
        for field in ["host", "profile", "space"] {
            nullable(output, &target["properties"][field], "string", false);
        }
        let failure = output["anyOf"]
            .as_array()
            .expect("alternatives")
            .iter()
            .map(|branch| resolve(output, branch))
            .find(|branch| branch["properties"].get("error").is_some())
            .expect("failure");
        object_schema(output, failure, &["error", "target"], &["error", "target"]);
        let failure_target = object_schema(
            output,
            &failure["properties"]["target"],
            &["host", "profile", "space"],
            &["host", "profile", "space"],
        );
        for field in ["host", "profile", "space"] {
            nullable(
                output,
                &failure_target["properties"][field],
                "string",
                false,
            );
        }
        let error = object_schema(
            output,
            &failure["properties"]["error"],
            &["code", "http_status", "kind", "message"],
            &["code", "kind", "message"],
        );
        for field in ["code", "kind", "message"] {
            nullable(output, &error["properties"][field], "string", false);
        }
        nullable(output, &error["properties"]["http_status"], "integer", true);
        nullable(output, &success["properties"]["data"], "object", false);
        let data = if is_list {
            object_schema(
                output,
                &success["properties"]["data"],
                &[data_key],
                &[data_key],
            )
        } else {
            resolve(output, &success["properties"]["data"])
        };
        let row = if is_list {
            let array = resolve(output, &data["properties"][data_key]);
            nullable(output, array, "array", false);
            let item = resolve(output, &array["items"]);
            nullable(output, item, "object", false);
            item
        } else {
            data
        };
        nullable(output, row, "object", false);
        let row = object_schema(output, row, &row_fields, &required);
        for field in ["id", "name", "namespace"] {
            nullable(output, &row["properties"][field], "string", false);
        }
        nullable(output, &row["properties"]["description"], "string", true);
        if name.contains("agent") {
            nullable(output, &row["properties"]["agents"], "integer", is_list);
            if !is_list {
                nullable(output, &row["properties"]["status"], "string", true);
                for field in ["attached_integrations", "blocked_by"] {
                    let array = array_branch(output, &row["properties"][field]);
                    nullable(output, &row["properties"][field], "array", false);
                    nullable(output, &array["items"], "string", false);
                }
            }
        } else {
            let policy_ids = array_branch(output, &row["properties"]["policy_ids"]);
            nullable(output, &row["properties"]["policy_ids"], "array", false);
            nullable(output, &policy_ids["items"], "string", false);
            nullable(output, &row["properties"]["package"], "object", false);
            let package = object_schema(
                output,
                &row["properties"]["package"],
                &["name", "version"],
                &["name", "version"],
            );
            nullable(output, &package["properties"]["name"], "string", false);
            nullable(output, &package["properties"]["version"], "string", false);
            if !is_list {
                nullable(
                    output,
                    &row["properties"]["affected_agents"],
                    "integer",
                    false,
                );
                let blocked_by = array_branch(output, &row["properties"]["blocked_by"]);
                nullable(output, &row["properties"]["blocked_by"], "array", false);
                nullable(output, &blocked_by["items"], "string", false);
            }
        }
        nullable(output, &success["properties"]["page"], "object", true);
        let page = object_schema(
            output,
            &success["properties"]["page"],
            &["limit", "returned", "total", "has_more", "truncated"],
            &["limit", "returned", "truncated"],
        );
        nullable(output, &page["properties"]["limit"], "integer", false);
        nullable(output, &page["properties"]["returned"], "integer", false);
        nullable(output, &page["properties"]["total"], "integer", true);
        nullable(output, &page["properties"]["has_more"], "boolean", true);
        nullable(output, &page["properties"]["truncated"], "boolean", false);
    }
    harness.close_input();
    harness.join().await.expect("clean EOF");
    let mut legacy = Harness::start(support::target(), options());
    legacy.send_json(legacy_initialize(2)).await;
    assert_eq!(legacy.receive_json().await["id"], 2);
    legacy.close_input();
    legacy.join().await.expect("legacy clean EOF");
}

#[tokio::test]
async fn fleet_tools_use_recorded_decoders_and_safe_typed_projections() {
    let server = MockServer::start().await;
    mount_status(&server, "9.5.1").await;
    mount_agent_list(&server, fixture("agent_list")).await;
    mount_integration_list(&server, fixture("integration_list")).await;
    let mut agent_get = fixture("agent_get");
    agent_get["item"]["vars"] = json!({"secret":"private-sentinel"});
    agent_get["item"]["inputs"] = json!({"system":{"vars":{"secret":"private-sentinel"}}});
    agent_get["item"]["secret_references"] = json!([{"id":"private-sentinel"}]);
    agent_get["item"]["updated_by"] = json!("private-sentinel");
    agent_get["item"]["integrations"] = json!([{"vars":{"secret":"private-sentinel"}}]);
    Mock::given(method("GET"))
        .and(path(
            "/api/fleet/agent_policies/elasticctl-sample-agent-policy",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(agent_get))
        .mount(&server)
        .await;
    let mut integration_get = fixture("integration_get");
    integration_get["item"]["vars"] = json!({"secret":"private-sentinel"});
    integration_get["item"]["inputs"] = json!({"system":{"vars":{"secret":"private-sentinel"}}});
    integration_get["item"]["secret_references"] = json!([{"id":"private-sentinel"}]);
    integration_get["item"]["updated_by"] = json!("private-sentinel");
    Mock::given(method("GET"))
        .and(path(
            "/api/fleet/package_policies/elasticctl-sample-integration-policy",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(integration_get))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"item":parent("elasticctl-sample-integration-policy-parent", "elasticctl-sample-integration-policy")}),
        ))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    let agent_list_reply = call(&mut harness, 1, "fleet_agent_policies_list", json!({})).await;
    let agent_list = content(&agent_list_reply);
    assert_eq!(
        agent_list["data"]["agent_policies"][0]["id"],
        "elasticctl-sample-agent-policy"
    );
    let agent_detail_reply = call(
        &mut harness,
        2,
        "fleet_agent_policies_get",
        json!({"selector":"elasticctl-sample-agent-policy"}),
    )
    .await;
    let agent_detail = content(&agent_detail_reply);
    assert_eq!(agent_detail["data"]["id"], "elasticctl-sample-agent-policy");
    assert_eq!(agent_detail["data"]["agents"], 0);
    let integration_list_reply = call(
        &mut harness,
        3,
        "fleet_integration_policies_list",
        json!({}),
    )
    .await;
    let integration_list = content(&integration_list_reply);
    assert_eq!(
        integration_list["data"]["integration_policies"][0]["package"]["name"],
        "system"
    );
    let integration_detail_reply = call(
        &mut harness,
        4,
        "fleet_integration_policies_get",
        json!({"selector":"elasticctl-sample-integration-policy"}),
    )
    .await;
    let integration_detail = content(&integration_detail_reply);
    assert_eq!(
        integration_detail["data"]["id"],
        "elasticctl-sample-integration-policy"
    );
    assert_eq!(integration_detail["data"]["package"]["name"], "system");
    for (structured, reply) in [
        (&agent_list, &agent_list_reply),
        (&agent_detail, &agent_detail_reply),
        (&integration_list, &integration_list_reply),
        (&integration_detail, &integration_detail_reply),
    ] {
        assert!(!structured.to_string().contains("private-sentinel"));
        assert!(
            !reply["result"]["content"][0]["text"]
                .as_str()
                .expect("text")
                .contains("private-sentinel")
        );
    }
    assert_read_routes(
        &server,
        &[
            "/api/status",
            "/api/fleet/agent_policies",
            "/api/fleet/agent_policies/elasticctl-sample-agent-policy",
            "/api/fleet/package_policies",
            "/api/fleet/package_policies/elasticctl-sample-integration-policy",
            "/api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
        ],
    )
    .await;
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn fleet_list_filters_before_mcp_cap_and_orders_stably() {
    let server = MockServer::start().await;
    mount_status(&server, "9.5.1").await;
    let agents = (0..100)
        .rev()
        .map(|index| {
            agent(
                &format!("agent-{index:03}"),
                if index == 90 || index == 1 {
                    "MATCH"
                } else {
                    "other"
                },
            )
        })
        .collect();
    let integrations = (0..100)
        .rev()
        .map(|index| {
            integration(
                &format!("integration-{index:03}"),
                if index == 90 || index == 1 {
                    "MATCH"
                } else {
                    "other"
                },
            )
        })
        .collect();
    mount_agent_list(&server, page(agents, 100)).await;
    mount_integration_list(&server, page(integrations, 100)).await;
    let mut harness = Harness::start(target_for(&server), options());
    for (id, tool, key) in [
        (1, "fleet_agent_policies_list", "agent_policies"),
        (2, "fleet_integration_policies_list", "integration_policies"),
    ] {
        let reply = call(&mut harness, id, tool, json!({"search":"MATCH","limit":1})).await;
        let result = content(&reply);
        assert_eq!(
            result["page"],
            json!({"limit":1,"returned":1,"total":2,"has_more":true,"truncated":true})
        );
        let expected = if key == "agent_policies" {
            "agent-001"
        } else {
            "integration-001"
        };
        assert_eq!(
            result["data"][key]
                .as_array()
                .expect("rows")
                .iter()
                .map(|row| row["id"].as_str().expect("id"))
                .collect::<Vec<_>>(),
            [expected]
        );
    }
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn fleet_validates_every_string_before_any_io_and_preserves_boundaries() {
    let server = MockServer::start().await;
    let mut harness = Harness::start(target_for(&server), options());
    for (tool, field) in [
        ("fleet_agent_policies_list", "search"),
        ("fleet_agent_policies_get", "selector"),
        ("fleet_integration_policies_list", "search"),
        ("fleet_integration_policies_get", "selector"),
    ] {
        for value in [
            String::new(),
            " \t\n".into(),
            "x".repeat(1025),
            "é".repeat(513),
            format!("{}x", "é".repeat(512)),
        ] {
            assert_eq!(
                failure(&call(&mut harness, 1, tool, json!({field:value})).await)["error"]["code"],
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

    for value in ["x".repeat(1024), "é".repeat(512)] {
        let server = MockServer::start().await;
        mount_status(&server, "9.5.1").await;
        let encoded = value.replace('é', "%C3%A9");
        let prefix = if value.starts_with('é') {
            "é".repeat(511)
        } else {
            "x".repeat(1023)
        };
        mount_agent_list(
            &server,
            page(
                vec![
                    agent("accepted-agent", &value),
                    agent("truncated-agent", &prefix),
                ],
                2,
            ),
        )
        .await;
        mount_integration_list(
            &server,
            page(
                vec![
                    integration("accepted-integration", &value),
                    integration("truncated-integration", &prefix),
                ],
                2,
            ),
        )
        .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/agent_policies/{encoded}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"item":agent(&value,&value)})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/package_policies/{encoded}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"item":integration(&value,&value)})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"item":parent("parent-1", &value)})),
            )
            .mount(&server)
            .await;
        let mut harness = Harness::start(target_for(&server), options());
        let agent_list_reply = call(
            &mut harness,
            1,
            "fleet_agent_policies_list",
            json!({"search":value}),
        )
        .await;
        let agent_list = content(&agent_list_reply);
        assert_eq!(
            agent_list["data"]["agent_policies"]
                .as_array()
                .expect("agent rows")
                .iter()
                .map(|row| row["id"].as_str().expect("id"))
                .collect::<Vec<_>>(),
            ["accepted-agent"]
        );
        let agent_get_reply = call(
            &mut harness,
            2,
            "fleet_agent_policies_get",
            json!({"selector":value}),
        )
        .await;
        let agent_get = content(&agent_get_reply);
        assert_eq!(agent_get["data"]["id"], value);
        let integration_list_reply = call(
            &mut harness,
            3,
            "fleet_integration_policies_list",
            json!({"search":value}),
        )
        .await;
        let integration_list = content(&integration_list_reply);
        assert_eq!(
            integration_list["data"]["integration_policies"]
                .as_array()
                .expect("integration rows")
                .iter()
                .map(|row| row["id"].as_str().expect("id"))
                .collect::<Vec<_>>(),
            ["accepted-integration"]
        );
        let integration_get_reply = call(
            &mut harness,
            4,
            "fleet_integration_policies_get",
            json!({"selector":value}),
        )
        .await;
        let integration_get = content(&integration_get_reply);
        assert_eq!(integration_get["data"]["id"], value);
        let agent_path = format!("/api/fleet/agent_policies/{encoded}");
        let integration_path = format!("/api/fleet/package_policies/{encoded}");
        assert_read_routes(
            &server,
            &[
                "/api/status",
                "/api/fleet/agent_policies",
                agent_path.as_str(),
                "/api/fleet/package_policies",
                integration_path.as_str(),
                "/api/fleet/agent_policies/parent-1",
            ],
        )
        .await;
        harness.close_input();
        harness.join().await.expect("clean EOF");
    }

    for value in [" leading", "trailing "] {
        let server = MockServer::start().await;
        mount_status(&server, "9.5.1").await;
        mount_agent_list(
            &server,
            page(
                vec![
                    agent("space-agent", value),
                    agent("trimmed-agent", value.trim()),
                ],
                2,
            ),
        )
        .await;
        mount_integration_list(
            &server,
            page(
                vec![
                    integration("space-integration", value),
                    integration("trimmed-integration", value.trim()),
                ],
                2,
            ),
        )
        .await;
        let mut harness = Harness::start(target_for(&server), options());
        for (id, tool, key, expected) in [
            (
                1,
                "fleet_agent_policies_list",
                "agent_policies",
                "space-agent",
            ),
            (
                2,
                "fleet_integration_policies_list",
                "integration_policies",
                "space-integration",
            ),
        ] {
            let raw_reply = call(&mut harness, id, tool, json!({"search":value})).await;
            let reply = content(&raw_reply);
            assert_eq!(
                reply["data"][key]
                    .as_array()
                    .expect("rows")
                    .iter()
                    .map(|row| row["id"].as_str().expect("id"))
                    .collect::<Vec<_>>(),
                [expected]
            );
        }
        assert_read_routes(
            &server,
            &[
                "/api/status",
                "/api/fleet/agent_policies",
                "/api/fleet/package_policies",
            ],
        )
        .await;
        harness.close_input();
        harness.join().await.expect("clean EOF");
    }
}

#[tokio::test]
async fn fleet_preserves_floor_permission_empty_ambiguity_and_checked_read_failures() {
    let old = MockServer::start().await;
    mount_status(&old, "9.5.0").await;
    let mut harness = Harness::start(target_for(&old), options());
    assert_eq!(
        failure(&call(&mut harness, 1, "fleet_agent_policies_list", json!({})).await)["error"]["code"],
        "elastic_unsupported"
    );
    assert_read_routes(&old, &["/api/status"]).await;
    harness.close_input();
    harness.join().await.expect("clean EOF");
    let server = MockServer::start().await;
    mount_status(&server, "9.5.1").await;
    mount_agent_list(
        &server,
        page(vec![agent("one", "same"), agent("two", "same")], 2),
    )
    .await;
    mount_integration_list(&server, page(vec![], 0)).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/same"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode":404,"error":"Not Found","message":"private"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/forbidden"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"statusCode":403,"error":"Forbidden","message":"private"})),
        )
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    assert_eq!(
        content(
            &call(
                &mut harness,
                1,
                "fleet_integration_policies_list",
                json!({})
            )
            .await
        )["data"]["integration_policies"],
        json!([])
    );
    assert_eq!(
        failure(
            &call(
                &mut harness,
                2,
                "fleet_agent_policies_get",
                json!({"selector":"same"})
            )
            .await
        )["error"]["code"],
        "elastic_conflict"
    );
    assert_eq!(
        failure(
            &call(
                &mut harness,
                3,
                "fleet_integration_policies_get",
                json!({"selector":"forbidden"})
            )
            .await
        )["error"]["code"],
        "elastic_permission"
    );
    assert_read_routes(
        &server,
        &[
            "/api/status",
            "/api/fleet/package_policies",
            "/api/fleet/agent_policies/same",
            "/api/fleet/agent_policies",
            "/api/fleet/package_policies/forbidden",
        ],
    )
    .await;
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn fleet_gets_preserve_permission_absence_and_integration_ambiguity_without_repairs() {
    let permission = MockServer::start().await;
    mount_status(&permission, "9.5.1").await;
    let mut missing_agents = agent("missing-agents", "missing-agents");
    missing_agents
        .as_object_mut()
        .expect("object")
        .remove("agents");
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/missing-agents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item":missing_agents})))
        .mount(&permission)
        .await;
    let mut harness = Harness::start(target_for(&permission), options());
    assert_eq!(
        failure(
            &call(
                &mut harness,
                1,
                "fleet_agent_policies_get",
                json!({"selector":"missing-agents"}),
            )
            .await,
        )["error"]["code"],
        "elastic_permission"
    );
    assert_read_routes(
        &permission,
        &["/api/status", "/api/fleet/agent_policies/missing-agents"],
    )
    .await;
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let absence = MockServer::start().await;
    mount_status(&absence, "9.5.1").await;
    for route in [
        "/api/fleet/agent_policies/absent-agent",
        "/api/fleet/package_policies/absent-integration",
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(
                    json!({"statusCode":404,"error":"Not Found","message":"private"}),
                ),
            )
            .mount(&absence)
            .await;
    }
    mount_agent_list(&absence, page(vec![], 0)).await;
    mount_integration_list(&absence, page(vec![], 0)).await;
    let mut harness = Harness::start(target_for(&absence), options());
    for (id, tool, selector) in [
        (1, "fleet_agent_policies_get", "absent-agent"),
        (2, "fleet_integration_policies_get", "absent-integration"),
    ] {
        assert_eq!(
            failure(&call(&mut harness, id, tool, json!({"selector":selector})).await)["error"]["code"],
            "elastic_not_found"
        );
    }
    assert_read_routes(
        &absence,
        &[
            "/api/status",
            "/api/fleet/agent_policies/absent-agent",
            "/api/fleet/agent_policies",
            "/api/fleet/package_policies/absent-integration",
            "/api/fleet/package_policies",
        ],
    )
    .await;
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let ambiguity = MockServer::start().await;
    mount_status(&ambiguity, "9.5.1").await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/same"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode":404,"error":"Not Found","message":"private"})),
        )
        .mount(&ambiguity)
        .await;
    mount_integration_list(
        &ambiguity,
        page(
            vec![integration("one", "same"), integration("two", "same")],
            2,
        ),
    )
    .await;
    let mut harness = Harness::start(target_for(&ambiguity), options());
    assert_eq!(
        failure(
            &call(
                &mut harness,
                1,
                "fleet_integration_policies_get",
                json!({"selector":"same"}),
            )
            .await,
        )["error"]["code"],
        "elastic_conflict"
    );
    assert_read_routes(
        &ambiguity,
        &[
            "/api/status",
            "/api/fleet/package_policies/same",
            "/api/fleet/package_policies",
        ],
    )
    .await;
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let fleet_absence = MockServer::start().await;
    mount_status(&fleet_absence, "9.5.1").await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode":404,"error":"Not Found","message":"private"})),
        )
        .mount(&fleet_absence)
        .await;
    let mut harness = Harness::start(target_for(&fleet_absence), options());
    assert_eq!(
        failure(&call(&mut harness, 1, "fleet_agent_policies_list", json!({})).await)["error"]["code"],
        "elastic_not_found"
    );
    assert_read_routes(
        &fleet_absence,
        &["/api/status", "/api/fleet/agent_policies"],
    )
    .await;
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn fleet_propagates_collector_page_failures_and_integration_selection_races() {
    let server = MockServer::start().await;
    mount_status(&server, "9.5.1").await;
    mount_agent_list(&server, page(vec![agent("one", "one")], 2)).await;
    mount_integration_list(&server, page(vec![integration("one", "one")], 2)).await;
    let mut harness = Harness::start(target_for(&server), options());
    for (id, tool) in [
        (1, "fleet_agent_policies_list"),
        (2, "fleet_integration_policies_list"),
    ] {
        assert_eq!(
            failure(&call(&mut harness, id, tool, json!({})).await)["error"]["code"],
            "elastic_http"
        );
    }
    assert_read_routes(
        &server,
        &[
            "/api/status",
            "/api/fleet/agent_policies",
            "/api/fleet/package_policies",
        ],
    )
    .await;
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let server = MockServer::start().await;
    mount_status(&server, "9.5.1").await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/wanted"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode":404,"error":"Not Found","message":"private"})),
        )
        .mount(&server)
        .await;
    mount_integration_list(&server, page(vec![integration("one", "wanted")], 1)).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/one"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"item":integration("changed", "wanted")})),
        )
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    assert_eq!(
        failure(
            &call(
                &mut harness,
                3,
                "fleet_integration_policies_get",
                json!({"selector":"wanted"})
            )
            .await
        )["error"]["code"],
        "elastic_http"
    );
    assert_read_routes(
        &server,
        &[
            "/api/status",
            "/api/fleet/package_policies/wanted",
            "/api/fleet/package_policies",
            "/api/fleet/package_policies/one",
        ],
    )
    .await;
    harness.close_input();
    harness.join().await.expect("clean EOF");

    let same_id = MockServer::start().await;
    mount_status(&same_id, "9.5.1").await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/wanted"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode":404,"error":"Not Found","message":"private"})),
        )
        .mount(&same_id)
        .await;
    mount_integration_list(&same_id, page(vec![integration("one", "wanted")], 1)).await;
    let mut changed_summary = integration("one", "wanted");
    changed_summary["package"]["version"] = json!("changed-version");
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item":changed_summary})))
        .mount(&same_id)
        .await;
    let mut harness = Harness::start(target_for(&same_id), options());
    assert_eq!(
        failure(
            &call(
                &mut harness,
                4,
                "fleet_integration_policies_get",
                json!({"selector":"wanted"}),
            )
            .await,
        )["error"]["code"],
        "elastic_http"
    );
    assert_read_routes(
        &same_id,
        &[
            "/api/status",
            "/api/fleet/package_policies/wanted",
            "/api/fleet/package_policies",
            "/api/fleet/package_policies/one",
        ],
    )
    .await;
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn fleet_rejects_changed_page_totals_before_partial_result() {
    let server = MockServer::start().await;
    mount_status(&server, "9.5.1").await;
    let items = (0..1000)
        .map(|index| agent(&format!("agent-{index}"), "one"))
        .collect::<Vec<_>>();
    let integration_items = (0..1000)
        .map(|index| integration(&format!("integration-{index}"), "one"))
        .collect::<Vec<_>>();
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies"))
        .and(query_param("page", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"items":items,"total":1001,"page":1,"perPage":1000})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"items":[agent("agent-1000", "one")],"total":1002,"page":2,"perPage":1000}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies"))
        .and(query_param("page", "1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"items":integration_items,"total":1001,"page":1,"perPage":1000}),
            ),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"items":[integration("integration-1000", "one")],"total":1002,"page":2,"perPage":1000}),
        ))
        .mount(&server)
        .await;
    let mut harness = Harness::start(target_for(&server), options());
    assert_eq!(
        failure(&call(&mut harness, 1, "fleet_agent_policies_list", json!({})).await)["error"]["code"],
        "elastic_http"
    );
    assert_eq!(
        failure(
            &call(
                &mut harness,
                2,
                "fleet_integration_policies_list",
                json!({}),
            )
            .await,
        )["error"]["code"],
        "elastic_http"
    );
    assert_requested_pages(&server, "/api/fleet/agent_policies", &["1", "2"]).await;
    assert_requested_pages(&server, "/api/fleet/package_policies", &["1", "2"]).await;
    assert_read_routes(
        &server,
        &[
            "/api/status",
            "/api/fleet/agent_policies",
            "/api/fleet/agent_policies",
            "/api/fleet/package_policies",
            "/api/fleet/package_policies",
        ],
    )
    .await;
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn fleet_excluded_values_do_not_reach_real_child_stderr() {
    let Ok(uri) = env::var("ELASTICCTL_MCP_FLEET_STDERR_URI") else {
        return;
    };
    let mut harness = Harness::start(
        Resolved {
            name: "stderr".into(),
            source: Source::Profile,
            profile: Profile {
                kibana_url: uri.clone(),
                es_url: Some(uri),
                api_key: Some("test".into()),
                username: None,
                password: None,
                space: "default".into(),
                verify: true,
                timeout_secs: 30,
            },
        },
        options(),
    );
    let agent_reply = call(
        &mut harness,
        1,
        "fleet_agent_policies_get",
        json!({"selector":"agent-1"}),
    )
    .await;
    let agent = content(&agent_reply);
    assert_eq!(agent["data"]["id"], "agent-1");
    assert_eq!(agent["data"]["agents"], 1);
    assert!(!agent.to_string().contains("private-sentinel"));
    let integration_reply = call(
        &mut harness,
        2,
        "fleet_integration_policies_get",
        json!({"selector":"integration-1"}),
    )
    .await;
    let integration = content(&integration_reply);
    assert_eq!(integration["data"]["id"], "integration-1");
    assert_eq!(integration["data"]["package"]["name"], "system");
    assert!(!integration.to_string().contains("private-sentinel"));
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn fleet_excluded_values_do_not_reach_subprocess_stderr() {
    let server = MockServer::start().await;
    mount_status(&server, "9.5.1").await;
    let mut private_integration = integration("integration-1", "integration");
    private_integration["vars"] = json!({"token":"private-sentinel"});
    private_integration["inputs"] = json!({"system":{"vars":{"token":"private-sentinel"}}});
    private_integration["secret_references"] = json!([{"id":"private-sentinel"}]);
    private_integration["updated_by"] = json!("private-sentinel");
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/agent-1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item":agent("agent-1","agent")})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item":private_integration})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"item":parent("parent-1", "integration-1")})),
        )
        .mount(&server)
        .await;
    let executable = env::current_exe().expect("test exe");
    let uri = server.uri();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(executable)
            .arg("fleet_excluded_values_do_not_reach_real_child_stderr")
            .arg("--exact")
            .arg("--nocapture")
            .env("ELASTICCTL_MCP_FLEET_STDERR_URI", uri)
            .output()
            .expect("child")
    })
    .await
    .expect("join");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-sentinel"));
}
