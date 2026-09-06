#![allow(dead_code)]
mod support;

use elasticctl_core::{Profile, Resolved, Source};
use rmcp::{
    ClientLifecycleMode, ClientServiceExt, RoleClient,
    model::{CallToolRequest, CallToolRequestParams, ClientRequest, ProtocolVersion},
    service::PeerRequestOptions,
    transport::async_rw::AsyncRwTransport,
};
use serde_json::{Map, Value, json};
use std::{
    env,
    pin::Pin,
    process::Command,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use support::{Harness, current_metadata, options};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

struct TapWriter {
    inner: tokio::io::DuplexStream,
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl tokio::io::AsyncWrite for TapWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buffer) {
            Poll::Ready(Ok(written)) => {
                this.bytes
                    .lock()
                    .expect("tap lock")
                    .extend_from_slice(&buffer[..written]);
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn target_for(server: &MockServer) -> Resolved {
    target_for_uri(server.uri())
}

fn target_for_uri(uri: String) -> Resolved {
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

async fn mount_stack_info(server: &MockServer, delay: Option<Duration>) {
    let status = ResponseTemplate::new(200)
        .insert_header("x-found-handling-cluster", "test")
        .set_body_json(json!({"version": {"number": "9.5.2", "build_flavor": "traditional"}}));
    let status = match delay {
        Some(delay) => status.set_delay(delay),
        None => status,
    };
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(status)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/spaces/space"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"id": "default"}])))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/_license"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"license": {"type": "enterprise"}})),
        )
        .mount(server)
        .await;
}

async fn wait_for_requests(server: &MockServer, route: &str, expected: usize) {
    for _ in 0..100 {
        let requests = server.received_requests().await.expect("request log");
        if requests
            .iter()
            .filter(|request| request.url.path() == route)
            .count()
            >= expected
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("did not observe {expected} requests for {route}");
}

async fn raw_call(harness: &mut Harness, id: u64, name: &str, arguments: Value) -> Value {
    harness
        .send_json(json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"_meta": current_metadata(), "name": name, "arguments": arguments},
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], id);
    reply
}

async fn raw_catalog(harness: &mut Harness, id: u64) -> Value {
    harness
        .send_json(json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/list",
            "params": {"_meta": current_metadata()},
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], id);
    reply["result"]["tools"].clone()
}

fn structured(result: &Value) -> &Value {
    &result["result"]["structuredContent"]
}

fn assert_text_copy(result: &Value) {
    let text = result["result"]["content"][0]["text"]
        .as_str()
        .expect("one text item");
    assert_eq!(
        serde_json::from_str::<Value>(text).expect("text is JSON"),
        *structured(result)
    );
}

fn assert_schema(schema: &Value, instance: &Value) {
    let validator = jsonschema::validator_for(schema).expect("output schema compiles");
    let errors = validator.iter_errors(instance).collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema rejected {instance}: {errors:?}");
}

fn assert_static_unknown_tool(error: rmcp::service::ServiceError) {
    let rmcp::service::ServiceError::McpError(error) = error else {
        panic!("SDK returned a non-protocol error for an unknown tool");
    };
    assert_eq!(error.code.0, -32601);
    assert_eq!(error.message, "Unknown MCP tool");
}

fn fixture(name: &str) -> Value {
    let source = match name {
        "status" => include_str!("../../../tests/fixtures/serverless-9.6.0/status.json"),
        "spaces" => include_str!("../../../tests/fixtures/serverless-9.6.0/spaces.json"),
        "license" => include_str!("../../../tests/fixtures/serverless-9.6.0/license.json"),
        "authenticate" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/authenticate.json")
        }
        "signals_search" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/signals_search.json")
        }
        "cases_find" => include_str!("../../../tests/fixtures/serverless-9.6.0/cases_find.json"),
        "case_get" => include_str!("../../../tests/fixtures/serverless-9.6.0/case_get.json"),
        "data_views_list" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/data_views_list.json")
        }
        "data_view_get" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/data_view_get.json")
        }
        "data_view_default_get" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/data_view_default_get.json")
        }
        "dashboard_search" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/dashboard_search.json")
        }
        "dashboard_get" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/dashboard_get.json")
        }
        "agent_policies_list" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/agent_policies_list.json")
        }
        "agent_policy_get" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/agent_policy_get.json")
        }
        "integration_policies_list" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/integration_policies_list.json")
        }
        "integration_policy_get" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/integration_policy_get.json")
        }
        "integration_policy_parent_get" => include_str!(
            "../../../tests/fixtures/serverless-9.6.0/integration_policy_parent_get.json"
        ),
        "rules_find" => include_str!("../../../tests/fixtures/serverless-9.6.0/rules_find.json"),
        "rules_get" => include_str!("../../../tests/fixtures/serverless-9.6.0/rules_get.json"),
        "prebuilt_status" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/prebuilt_status.json")
        }
        "exception_lists_find" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/exception_lists_find.json")
        }
        "exception_list_get" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/exception_list_get.json")
        }
        "exception_list_items_find" => {
            include_str!("../../../tests/fixtures/serverless-9.6.0/exception_list_items_find.json")
        }
        "esql_query" => include_str!("../../../tests/fixtures/serverless-9.6.0/esql_query.json"),
        _ => panic!("unknown fixture {name}"),
    };
    serde_json::from_str::<Value>(source).expect("fixture parses")["response"].clone()
}

async fn mount_fixture(server: &MockServer, verb: &str, route: &str, name: &str) {
    let mock = Mock::given(method(verb))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture(name)));
    mock.mount(server).await;
}

async fn mount_catalog_success_routes(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture("status")))
        .mount(server)
        .await;
    for (verb, route, body) in [
        ("GET", "/api/spaces/space", "spaces"),
        ("GET", "/_license", "license"),
        ("GET", "/_security/_authenticate", "authenticate"),
        (
            "POST",
            "/api/detection_engine/signals/search",
            "signals_search",
        ),
        ("GET", "/api/cases/_find", "cases_find"),
        ("GET", "/api/cases/elasticctl-fixture-case", "case_get"),
        ("GET", "/api/data_views", "data_views_list"),
        (
            "GET",
            "/api/data_views/data_view/elasticctl-sample-data-view-source",
            "data_view_get",
        ),
        ("GET", "/api/data_views/default", "data_view_default_get"),
        ("GET", "/api/dashboards", "dashboard_search"),
        (
            "GET",
            "/api/dashboards/elasticctl-sample-dashboard",
            "dashboard_get",
        ),
        ("GET", "/api/fleet/agent_policies", "agent_policies_list"),
        (
            "GET",
            "/api/fleet/agent_policies/elasticctl-sample-agent-policy",
            "agent_policy_get",
        ),
        (
            "GET",
            "/api/fleet/package_policies",
            "integration_policies_list",
        ),
        (
            "GET",
            "/api/fleet/package_policies/elasticctl-sample-integration-policy",
            "integration_policy_get",
        ),
        (
            "GET",
            "/api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            "integration_policy_parent_get",
        ),
        ("GET", "/api/detection_engine/rules/_find", "rules_find"),
        (
            "GET",
            "/api/detection_engine/rules/prepackaged/_status",
            "prebuilt_status",
        ),
        ("GET", "/api/exception_lists/_find", "exception_lists_find"),
        ("GET", "/api/exception_lists", "exception_list_get"),
        (
            "GET",
            "/api/exception_lists/items/_find",
            "exception_list_items_find",
        ),
        ("POST", "/_query", "esql_query"),
    ] {
        mount_fixture(server, verb, route, body).await;
    }
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "elasticctl-fixture-probe"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture("rules_get")))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/lists/index"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode":404,"error":"Not Found","message":"absent"})),
        )
        .mount(server)
        .await;
    Mock::given(method("POST")).and(path("/logs-*/_search")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"hits":{"hits":[{"_id":"sample","_index":"logs-sample","_score":1.0,"_source":{"message":"sample"}}]}}))).mount(server).await;
}

fn success_arguments(name: &str) -> Value {
    match name {
        "alerts_get" => json!({"alert_id":"elasticctl-fixture-alert-1"}),
        "cases_get" => json!({"id":"elasticctl-fixture-case"}),
        "data_views_get" => json!({"selector":"elasticctl-sample-data-view-source"}),
        "dashboards_get" => json!({"selector":"elasticctl-sample-dashboard"}),
        "fleet_agent_policies_get" => json!({"selector":"elasticctl-sample-agent-policy"}),
        "fleet_integration_policies_get" => {
            json!({"selector":"elasticctl-sample-integration-policy"})
        }
        "rules_get" => json!({"selector":"elasticctl-fixture-probe"}),
        "exceptions_get" => json!({"list_id":"elasticctl-sample-exceptions","namespace":"single"}),
        "search_esql" => json!({"query":"FROM logs-*"}),
        "search_dsl" => json!({"index":"logs-*","query":{"match_all":{}}}),
        _ => json!({}),
    }
}

#[tokio::test]
async fn sdk_current_and_legacy_paths_agree_on_catalog_and_stack_info() {
    let mock = MockServer::start().await;
    mount_stack_info(&mock, None).await;

    let (current_write, current_read_server) = tokio::io::duplex(16_384);
    let (current_write_server, current_read) = tokio::io::duplex(16_384);
    let current_server = tokio::spawn(elasticctl_mcp::serve_io(
        target_for(&mock),
        options(),
        current_read_server,
        current_write_server,
    ));
    let current = ()
        .serve_with_lifecycle(
            AsyncRwTransport::<RoleClient, _, _>::new_client(current_read, current_write),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .expect("current SDK client starts");
    let current_tools = current
        .list_tools(None)
        .await
        .expect("current list succeeds");
    let current_tool_data = serde_json::to_value(&current_tools.tools).expect("catalog serializes");
    for name in ["search_esql", "search_dsl"] {
        let unknown = current
            .call_tool(CallToolRequestParams::new(name).with_arguments(Map::new()))
            .await
            .expect_err("default SDK session rejects query tool");
        assert_static_unknown_tool(unknown);
    }
    let current_info = current
        .call_tool(CallToolRequestParams::new("stack_info").with_arguments(Map::new()))
        .await
        .expect("current stack info succeeds");
    let current_info_data = current_info
        .structured_content
        .expect("current structured content");
    current.cancel().await.expect("current client closes");
    current_server
        .await
        .expect("current server task")
        .expect("current server cleanly exits");

    let mut query_options = options();
    query_options.allow_query_tools = true;
    let (query_write, query_read_server) = tokio::io::duplex(16_384);
    let (query_write_server, query_read) = tokio::io::duplex(16_384);
    let query_server = tokio::spawn(elasticctl_mcp::serve_io(
        target_for(&mock),
        query_options,
        query_read_server,
        query_write_server,
    ));
    let query_client = ()
        .serve_with_lifecycle(
            AsyncRwTransport::<RoleClient, _, _>::new_client(query_read, query_write),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .expect("opt-in SDK client starts");
    let query_tool_data = serde_json::to_value(
        &query_client
            .list_tools(None)
            .await
            .expect("opt-in list succeeds")
            .tools,
    )
    .expect("opt-in catalog serializes");
    let query_tools = query_tool_data.as_array().expect("opt-in catalog array");
    let additions = query_tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .filter(|name| name.starts_with("search_"))
        .collect::<Vec<_>>();
    assert_eq!(query_tools.len(), 22);
    assert_eq!(additions, ["search_dsl", "search_esql"]);
    assert_eq!(
        Value::Array(
            query_tools
                .iter()
                .filter(|tool| !tool["name"]
                    .as_str()
                    .is_some_and(|name| name.starts_with("search_")))
                .cloned()
                .collect(),
        ),
        current_tool_data
    );
    query_client.cancel().await.expect("opt-in client closes");
    query_server
        .await
        .expect("opt-in server task")
        .expect("opt-in server cleanly exits");

    let (legacy_write, legacy_read_server) = tokio::io::duplex(16_384);
    let (legacy_write_server, legacy_read) = tokio::io::duplex(16_384);
    let legacy_server = tokio::spawn(elasticctl_mcp::serve_io(
        target_for(&mock),
        options(),
        legacy_read_server,
        legacy_write_server,
    ));
    let legacy_info =
        rmcp::model::ClientInfo::default().with_protocol_version(ProtocolVersion::V_2025_11_25);
    let legacy = legacy_info
        .serve_with_lifecycle(
            AsyncRwTransport::<RoleClient, _, _>::new_client(legacy_read, legacy_write),
            ClientLifecycleMode::Initialize,
        )
        .await
        .expect("legacy SDK client initializes");
    assert_eq!(
        legacy
            .peer_info()
            .expect("legacy peer info")
            .protocol_version,
        ProtocolVersion::V_2025_11_25
    );
    let legacy_tools = legacy.list_tools(None).await.expect("legacy list succeeds");
    let legacy_tool_data =
        serde_json::to_value(&legacy_tools.tools).expect("legacy catalog serializes");
    let legacy_info = legacy
        .call_tool(CallToolRequestParams::new("stack_info").with_arguments(Map::new()))
        .await
        .expect("legacy stack info succeeds");
    assert_eq!(current_tool_data, legacy_tool_data);
    assert_eq!(
        current_info_data,
        legacy_info
            .structured_content
            .expect("legacy structured content")
    );
    legacy.cancel().await.expect("legacy client closes");
    legacy_server
        .await
        .expect("legacy server task")
        .expect("legacy server cleanly exits");
}

#[tokio::test]
async fn catalog_schema_accepts_each_declared_success_and_router_error() {
    let mock = MockServer::start().await;
    mount_catalog_success_routes(&mock).await;
    let mut harness = Harness::start(target_for(&mock), options());
    let default_catalog = raw_catalog(&mut harness, 1).await;
    assert_eq!(default_catalog.as_array().expect("catalog array").len(), 20);
    for (offset, tool) in default_catalog
        .as_array()
        .expect("catalog array")
        .iter()
        .enumerate()
    {
        let name = tool["name"].as_str().expect("tool name");
        let schema = &tool["outputSchema"];
        let success = raw_call(
            &mut harness,
            10 + offset as u64,
            name,
            success_arguments(name),
        )
        .await;
        assert_eq!(success["result"]["isError"], false, "{name}");
        assert_text_copy(&success);
        assert_schema(schema, structured(&success));
        let reply = raw_call(
            &mut harness,
            100 + offset as u64,
            name,
            json!({"unexpected": true}),
        )
        .await;
        assert_eq!(reply["result"]["isError"], true, "{name}");
        assert_text_copy(&reply);
        assert_schema(schema, structured(&reply));
    }
    for name in ["search_esql", "search_dsl"] {
        let reply = raw_call(&mut harness, 200, name, json!({})).await;
        assert_eq!(reply["error"]["code"], -32601);
        assert_eq!(reply["error"]["message"], "Unknown MCP tool");
    }
    harness.close_input();
    harness.join().await.expect("default server exits");

    let mut enabled = options();
    enabled.allow_query_tools = true;
    let mut harness = Harness::start(target_for(&mock), enabled);
    let query_catalog = raw_catalog(&mut harness, 2).await;
    assert_eq!(query_catalog.as_array().expect("catalog array").len(), 22);
    let query_names = query_catalog
        .as_array()
        .expect("catalog array")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .filter(|name| name.starts_with("search_"))
        .collect::<Vec<_>>();
    assert_eq!(query_names, ["search_dsl", "search_esql"]);
    for (offset, tool) in query_catalog
        .as_array()
        .expect("catalog array")
        .iter()
        .filter(|tool| {
            tool["name"]
                .as_str()
                .is_some_and(|name| name.starts_with("search_"))
        })
        .enumerate()
    {
        let schema = &tool["outputSchema"];
        let name = tool["name"].as_str().expect("query name");
        let success = raw_call(
            &mut harness,
            250 + offset as u64,
            name,
            success_arguments(name),
        )
        .await;
        assert_eq!(success["result"]["isError"], false, "{name}");
        assert_text_copy(&success);
        assert_schema(schema, structured(&success));
        let reply = raw_call(
            &mut harness,
            300 + offset as u64,
            name,
            json!({"unexpected": true}),
        )
        .await;
        assert_eq!(reply["result"]["isError"], true);
        assert_text_copy(&reply);
        assert_schema(schema, structured(&reply));
    }
    harness.close_input();
    harness.join().await.expect("enabled server exits");
}

#[tokio::test]
async fn fifth_call_is_busy_and_one_second_call_times_out() {
    let mock = MockServer::start().await;
    mount_stack_info(&mock, Some(Duration::from_secs(2))).await;
    let (client_write, server_read) = tokio::io::duplex(16_384);
    let (server_write, client_read) = tokio::io::duplex(16_384);
    let server = tokio::spawn(elasticctl_mcp::serve_io(
        target_for(&mock),
        options(),
        server_read,
        server_write,
    ));
    let client = ()
        .serve_with_lifecycle(
            AsyncRwTransport::<RoleClient, _, _>::new_client(client_read, client_write),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .expect("SDK client starts");
    let peer = client.peer().clone();
    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let peer = peer.clone();
        calls.spawn(async move {
            peer.call_tool_once(CallToolRequestParams::new("stack_info").with_arguments(Map::new()))
                .await
        });
    }
    wait_for_requests(&mock, "/api/status", 4).await;
    let busy = tokio::time::timeout(
        Duration::from_millis(100),
        client.call_tool(CallToolRequestParams::new("stack_info").with_arguments(Map::new())),
    )
    .await
    .expect("fifth call returns immediately")
    .expect("fifth call returns a tool result");
    assert_eq!(
        busy.structured_content.expect("busy structured content")["error"]["code"],
        "busy"
    );
    assert_eq!(
        mock.received_requests()
            .await
            .expect("request log")
            .iter()
            .filter(|request| request.url.path() == "/api/status")
            .count(),
        4,
        "busy call makes no Elastic request"
    );
    while let Some(result) = calls.join_next().await {
        let result = result
            .expect("call task joins")
            .expect("admitted call completes");
        let rmcp::model::CallToolResponse::Complete(result) = result else {
            panic!("admitted call completed normally");
        };
        assert_eq!(result.is_error, Some(false), "admitted call is successful");
    }
    client.cancel().await.expect("busy client closes");
    server
        .await
        .expect("busy server task")
        .expect("busy server exits");

    let mut one_second = options();
    one_second.call_timeout = Duration::from_secs(1);
    let (client_write, server_read) = tokio::io::duplex(16_384);
    let (server_write, client_read) = tokio::io::duplex(16_384);
    let server = tokio::spawn(elasticctl_mcp::serve_io(
        target_for(&mock),
        one_second,
        server_read,
        server_write,
    ));
    let client = ()
        .serve_with_lifecycle(
            AsyncRwTransport::<RoleClient, _, _>::new_client(client_read, client_write),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .expect("timeout SDK client starts");
    let timed_out = client
        .call_tool(CallToolRequestParams::new("stack_info").with_arguments(Map::new()))
        .await
        .expect("timeout returns a tool result");
    assert_eq!(
        timed_out
            .structured_content
            .expect("timeout structured content")["error"]["code"],
        "deadline_exceeded"
    );
    client.cancel().await.expect("timeout client closes");
    server
        .await
        .expect("timeout server task")
        .expect("timeout server exits");
}

#[tokio::test]
async fn sdk_cancellation_keeps_the_session_usable() {
    let mock = MockServer::start().await;
    mount_stack_info(&mock, Some(Duration::from_secs(2))).await;
    let (client_write, server_read) = tokio::io::duplex(16_384);
    let (server_write, client_read) = tokio::io::duplex(16_384);
    let frames = Arc::new(Mutex::new(Vec::new()));
    let server = tokio::spawn(elasticctl_mcp::serve_io(
        target_for(&mock),
        options(),
        server_read,
        TapWriter {
            inner: server_write,
            bytes: Arc::clone(&frames),
        },
    ));
    let client = ()
        .serve_with_lifecycle(
            AsyncRwTransport::<RoleClient, _, _>::new_client(client_read, client_write),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .expect("SDK client starts");
    let request = ClientRequest::CallToolRequest(CallToolRequest::new(
        CallToolRequestParams::new("stack_info").with_arguments(Map::new()),
    ));
    let handle = client
        .peer()
        .send_cancellable_request(request, PeerRequestOptions::no_options())
        .await
        .expect("SDK sends delayed request");
    let cancelled_id = serde_json::to_value(&handle.id).expect("request id serializes");
    wait_for_requests(&mock, "/api/status", 1).await;
    handle
        .cancel(Some("test cancellation".to_string()))
        .await
        .expect("SDK cancellation succeeds");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let listed = client
        .list_tools(None)
        .await
        .expect("cancelled session remains usable");
    assert_eq!(listed.tools.len(), 20);
    client.cancel().await.expect("client closes");
    server.await.expect("server task").expect("server exits");
    let frames = frames.lock().expect("tap lock").clone();
    for frame in frames.split_inclusive(|byte| *byte == b'\n') {
        assert_eq!(
            frame.last(),
            Some(&b'\n'),
            "server emitted an incomplete frame"
        );
        let response: Value =
            serde_json::from_slice(&frame[..frame.len() - 1]).expect("server emitted JSON frame");
        assert_ne!(
            response.get("id"),
            Some(&cancelled_id),
            "cancelled request emitted a later response: {response}"
        );
    }
}

#[tokio::test]
async fn oversized_input_child() {
    let Ok(uri) = env::var("ELASTICCTL_MCP_OVERSIZED_INPUT_CHILD_URI") else {
        return;
    };
    let (mut write, read) = tokio::io::duplex(1_048_576);
    let (server_write, output) = tokio::io::duplex(1_048_576);
    let mut output = BufReader::new(output);
    let server = tokio::spawn(elasticctl_mcp::serve_io(
        target_for_uri(uri),
        options(),
        read,
        server_write,
    ));
    write.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},\"name\":\"stack_info\",\"arguments\":{}}}\n").await.expect("write successful request");
    let mut reply = Vec::new();
    let count = output
        .read_until(b'\n', &mut reply)
        .await
        .expect("read successful reply");
    assert!(count > 0, "successful call replies first");
    let successful: Value = serde_json::from_slice(&reply).expect("successful response is JSON");
    assert_eq!(
        successful["result"]["isError"], false,
        "first response is a successful tools/call result"
    );
    write
        .write_all(&vec![b'x'; 262_145])
        .await
        .expect("write oversized line");
    write
        .write_all(b"\n")
        .await
        .expect("terminate oversized line");
    write.shutdown().await.expect("close input");
    server
        .await
        .expect("server task")
        .expect("oversized input ends cleanly");
    reply.clear();
    let no_reply = output
        .read_until(b'\n', &mut reply)
        .await
        .expect("EOF after oversized frame");
    assert_eq!(
        no_reply,
        0,
        "oversized frame has no reply: {}",
        String::from_utf8_lossy(&reply)
    );
}

#[tokio::test]
async fn oversized_input_has_only_static_stderr_diagnostic() {
    let executable = env::current_exe().expect("test executable");
    let mock = MockServer::start().await;
    mount_stack_info(&mock, None).await;
    let uri = mock.uri();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(executable)
            .arg("oversized_input_child")
            .arg("--exact")
            .arg("--nocapture")
            .env("ELASTICCTL_MCP_OVERSIZED_INPUT_CHILD_URI", uri)
            .output()
            .expect("child starts")
    })
    .await
    .expect("child joins");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "MCP input frame exceeds the configured limit\n"
    );
}
