mod support;

use serde_json::json;
use std::time::Duration;
use support::{EXPECTED_TOOL_NAMES, Harness, current_metadata, legacy_initialize, options, target};

#[tokio::test]
async fn current_list_is_the_first_request_and_matches_the_expected_catalog() {
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
    assert_eq!(reply["id"], 1);
    assert_eq!(reply["result"]["resultType"], "complete");
    let names = reply["result"]["tools"]
        .as_array()
        .expect("tools is an array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool has a name"))
        .collect::<Vec<_>>();
    assert_eq!(names, EXPECTED_TOOL_NAMES);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn current_server_discovery_is_the_first_request_and_advertises_exact_versions() {
    let mut harness = Harness::start(target(), options());
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "server/discover",
            "params": { "_meta": current_metadata() },
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], 10);
    assert_eq!(reply["result"]["resultType"], "complete");
    assert_eq!(
        reply["result"]["supportedVersions"],
        json!(["2026-07-28", "2025-11-25"])
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn current_unknown_tool_returns_a_static_protocol_error() {
    let mut harness = Harness::start(target(), options());
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "_meta": current_metadata(),
                "name": "credential-sentinel",
                "arguments": {},
            },
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], 2);
    assert_eq!(reply["error"]["code"], -32601);
    assert_eq!(reply["error"]["message"], "Unknown MCP tool");
    assert!(!reply.to_string().contains("credential-sentinel"));
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn legacy_initialization_negotiates_the_configured_revision() {
    let mut harness = Harness::start(target(), options());
    harness.send_json(legacy_initialize(3)).await;
    let initialized = harness.receive_json().await;
    assert_eq!(initialized["id"], 3);
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/list",
            "params": {},
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], 4);
    assert!(reply["result"].get("resultType").is_none());
    let names = reply["result"]["tools"]
        .as_array()
        .expect("tools is an array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool has a name"))
        .collect::<Vec<_>>();
    assert_eq!(names, EXPECTED_TOOL_NAMES);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn current_startup_rejects_a_late_initialize_request() {
    let mut harness = Harness::start(target(), options());
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/list",
            "params": { "_meta": current_metadata() },
        }))
        .await;
    let _ = harness.receive_json().await;
    harness.send_json(legacy_initialize(6)).await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], 6);
    assert_eq!(reply["error"]["code"], -32600);
    assert_eq!(reply["error"]["message"], "Invalid MCP request");
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn current_startup_rejects_later_requests_without_complete_metadata() {
    let mut harness = Harness::start(target(), options());
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/list",
            "params": { "_meta": current_metadata() },
        }))
        .await;
    let _ = harness.receive_json().await;
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/list",
            "params": {},
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], 12);
    assert_eq!(reply["error"]["code"], -32600);
    assert_eq!(reply["error"]["message"], "Invalid MCP request");
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn current_startup_rejects_each_missing_metadata_key() {
    for (id, missing) in [
        (120, "io.modelcontextprotocol/protocolVersion"),
        (121, "io.modelcontextprotocol/clientCapabilities"),
    ] {
        let mut harness = Harness::start(target(), options());
        harness
            .send_json(json!({
                "jsonrpc": "2.0",
                "id": 119,
                "method": "tools/list",
                "params": { "_meta": current_metadata() },
            }))
            .await;
        assert_eq!(harness.receive_json().await["id"], 119);
        let mut metadata = current_metadata();
        metadata
            .as_object_mut()
            .expect("metadata object")
            .remove(missing);
        harness
            .send_json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/list",
                "params": { "_meta": metadata },
            }))
            .await;
        let reply = harness.receive_json().await;
        assert_eq!(reply["id"], id);
        assert_eq!(reply["error"]["code"], -32600);
        assert_eq!(reply["error"]["message"], "Invalid MCP request");
        harness.close_input();
        harness.join().await.expect("clean EOF");
    }
}

#[tokio::test]
async fn current_ping_is_unavailable_with_a_static_method_not_found_error() {
    let mut harness = Harness::start(target(), options());
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 122,
            "method": "ping",
            "params": { "_meta": current_metadata() },
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], 122);
    assert_eq!(reply["error"]["code"], -32601);
    assert_eq!(reply["error"]["message"], "Unknown MCP tool");
    assert!(reply.get("result").is_none());
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn incomplete_first_current_request_is_rejected_before_a_handler_runs() {
    let mut harness = Harness::start(target(), options());
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 123,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                },
            },
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], 123);
    assert_eq!(reply["error"]["code"], -32602);
    assert_eq!(reply["error"]["message"], "Invalid MCP request");
    harness.close_input();
    let error = harness
        .join()
        .await
        .expect_err("SDK startup rejects incomplete current metadata");
    assert_eq!(error.message, "MCP protocol startup failed");
}

#[tokio::test]
async fn current_lifecycle_rejects_legacy_and_unsupported_metadata_versions() {
    for (id, version) in [(18, "2025-11-25"), (19, "2099-01-01")] {
        let mut harness = Harness::start(target(), options());
        let mut metadata = current_metadata();
        metadata["io.modelcontextprotocol/protocolVersion"] = json!(version);
        harness
            .send_json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/list",
                "params": { "_meta": metadata },
            }))
            .await;
        let reply = harness.receive_json().await;
        assert_eq!(reply["id"], id);
        assert_eq!(reply["error"]["code"], -32600);
        assert_eq!(reply["error"]["message"], "Invalid MCP request");
        harness.close_input();
        harness.join().await.expect("clean EOF");
    }
}

#[tokio::test]
async fn resources_and_prompts_are_not_advertised_or_served() {
    for (id, method) in [
        (20, "resources/list"),
        (21, "resources/templates/list"),
        (22, "prompts/list"),
    ] {
        let mut harness = Harness::start(target(), options());
        harness
            .send_json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": { "_meta": current_metadata() },
            }))
            .await;
        let reply = harness.receive_json().await;
        assert_eq!(reply["id"], id);
        assert_eq!(reply["error"]["code"], -32601);
        assert_eq!(reply["error"]["message"], "Unknown MCP tool");
        harness.close_input();
        harness.join().await.expect("clean EOF");
    }
}

#[tokio::test]
async fn unsupported_legacy_initialization_uses_the_configured_fallback() {
    let mut harness = Harness::start(target(), options());
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "0" },
            },
        }))
        .await;
    let initialized = harness.receive_json().await;
    assert_eq!(initialized["id"], 13);
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/list",
            "params": {},
        }))
        .await;
    let listed = harness.receive_json().await;
    assert_eq!(listed["id"], 14);
    let names = listed["result"]["tools"]
        .as_array()
        .expect("tools is an array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool has a name"))
        .collect::<Vec<_>>();
    assert_eq!(names, EXPECTED_TOOL_NAMES);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn bare_ping_then_initialize_stays_on_the_legacy_lifecycle() {
    let mut harness = Harness::start(target(), options());
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 15,
            "method": "ping",
            "params": {},
        }))
        .await;
    assert_eq!(harness.receive_json().await["id"], 15);
    harness.send_json(legacy_initialize(16)).await;
    assert_eq!(
        harness.receive_json().await["result"]["protocolVersion"],
        "2025-11-25"
    );
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 17,
            "method": "tools/list",
            "params": {},
        }))
        .await;
    assert_eq!(harness.receive_json().await["id"], 17);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn bare_ping_then_unsupported_initialize_uses_the_legacy_fallback() {
    let mut harness = Harness::start(target(), options());
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 24,
            "method": "ping",
            "params": {},
        }))
        .await;
    assert_eq!(harness.receive_json().await["id"], 24);
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 25,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "0" },
            },
        }))
        .await;
    assert_eq!(
        harness.receive_json().await["result"]["protocolVersion"],
        "2025-11-25"
    );
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 26,
            "method": "tools/list",
            "params": {},
        }))
        .await;
    assert_eq!(harness.receive_json().await["id"], 26);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn a_bare_legacy_ping_cannot_switch_the_connection_to_current_requests() {
    let mut harness = Harness::start(target(), options());
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "ping",
            "params": {},
        }))
        .await;
    let ping = harness.receive_json().await;
    assert_eq!(ping["id"], 7);
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/list",
            "params": { "_meta": current_metadata() },
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], 8);
    assert_eq!(reply["error"]["code"], -32600);
    assert_eq!(reply["error"]["message"], "Invalid MCP request");
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn startup_rejects_query_tools_without_opening_the_protocol() {
    let (input, _) = tokio::io::duplex(64);
    let (_, output) = tokio::io::duplex(64);
    let error = elasticctl_mcp::serve_io(
        target(),
        elasticctl_mcp::ServerOptions {
            call_timeout: Duration::from_secs(30),
            allow_query_tools: true,
        },
        input,
        output,
    )
    .await
    .expect_err("query tools are deferred to a later release");
    assert_eq!(error.kind, elasticctl_core::ErrorKind::Unsupported);
}

#[tokio::test]
async fn startup_rejects_a_target_query_before_protocol_io() {
    let mut invalid = target();
    invalid.profile.es_url = Some("https://es.example.test/base?token=sentinel".to_string());
    let (input, _) = tokio::io::duplex(64);
    let (_, output) = tokio::io::duplex(64);
    let error = elasticctl_mcp::serve_io(invalid, options(), input, output)
        .await
        .expect_err("configured URL queries are unsafe");
    assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
    assert!(!error.message.contains("sentinel"));
}

#[tokio::test]
async fn public_startup_rejects_a_mixed_case_doubled_kibana_scheme() {
    let mut invalid = target();
    invalid.profile.kibana_url = "HTTP://HTTPS://kibana.example.test".to_string();
    let (input, _) = tokio::io::duplex(64);
    let (_, output) = tokio::io::duplex(64);
    let error = elasticctl_mcp::serve_io(invalid, options(), input, output)
        .await
        .expect_err("mixed-case doubled Kibana scheme is rejected before protocol I/O");
    assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
}

#[tokio::test]
async fn public_startup_rejects_a_mixed_case_doubled_elasticsearch_scheme() {
    let mut invalid = target();
    invalid.profile.es_url = Some("https://HTTP://elasticsearch.example.test".to_string());
    let (input, _) = tokio::io::duplex(64);
    let (_, output) = tokio::io::duplex(64);
    let error = elasticctl_mcp::serve_io(invalid, options(), input, output)
        .await
        .expect_err("mixed-case doubled Elasticsearch scheme is rejected before protocol I/O");
    assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
}

#[tokio::test]
async fn public_startup_validation_checks_every_resolved_url_and_timeout_boundary() {
    for invalid_url in [
        "ftp://example.test",
        "https:///missing-authority",
        "https://example.test/?credential-sentinel",
        "https://example.test/#credential-sentinel",
        "https://https://example.test",
    ] {
        for kibana in [true, false] {
            let mut resolved = target();
            if kibana {
                resolved.profile.kibana_url = invalid_url.to_string();
            } else {
                resolved.profile.es_url = Some(invalid_url.to_string());
            }
            let (input, _) = tokio::io::duplex(64);
            let (_, output) = tokio::io::duplex(64);
            let error = elasticctl_mcp::serve_io(resolved, options(), input, output)
                .await
                .expect_err("unsafe resolved URL is rejected before protocol I/O");
            assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
            assert!(!error.message.contains("credential-sentinel"));
        }
    }

    for seconds in [0, 121] {
        let (input, _) = tokio::io::duplex(64);
        let (_, output) = tokio::io::duplex(64);
        let error = elasticctl_mcp::serve_io(
            target(),
            elasticctl_mcp::ServerOptions {
                call_timeout: Duration::from_secs(seconds),
                allow_query_tools: false,
            },
            input,
            output,
        )
        .await
        .expect_err("out-of-range timeout is rejected before protocol I/O");
        assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
    }

    for seconds in [1, 120] {
        let mut resolved = target();
        resolved.profile.kibana_url =
            "https://kibana.example.test/proxy/https://upstream".to_string();
        resolved.profile.es_url = Some("https://es.example.test/proxy/http://upstream".to_string());
        let (input, server_input) = tokio::io::duplex(64);
        let (server_output, output) = tokio::io::duplex(64);
        drop(input);
        drop(output);
        elasticctl_mcp::serve_io(
            resolved,
            elasticctl_mcp::ServerOptions {
                call_timeout: Duration::from_secs(seconds),
                allow_query_tools: false,
            },
            server_input,
            server_output,
        )
        .await
        .expect("valid base paths and timeout boundary start without network I/O");
    }
}
