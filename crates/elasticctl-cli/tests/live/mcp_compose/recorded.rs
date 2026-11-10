//! Recorded responses exercise the real MCP server with the live validators.
use super::shape;
use elasticctl_core::{Profile, Resolved, Source};
use elasticctl_mcp::{ServerOptions, serve_io};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use wiremock::{Mock, MockServer, Request, ResponseTemplate, matchers::any};

fn fixture(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/serverless-9.7.0")
        .join(name);
    serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap()).unwrap()["response"]
        .clone()
}

async fn result(tool: &str, arguments: Value) -> Value {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(|r: &Request| {
            let name = match r.url.path() {
                "/api/status" => "status.json",
                "/api/detection_engine/rules" => "rule_get_executed.json",
                "/api/detection_engine/rules/_find" => "rules_find_sorted_page.json",
                "/api/detection_engine/signals/search" => "signals_search_rule_activity.json",
                "/api/exception_lists" => "exception_list_get.json",
                "/api/exception_lists/items/_find" => "exception_items_count.json",
                "/api/data_views" => "data_views_list.json",
                "/api/fleet/package_policies" => "integration_policies_list.json",
                p if p.starts_with("/api/fleet/epm/packages/") => "package_system.json",
                p if p.starts_with("/_resolve/index/") => "resolve_index_match.json",
                p if p.starts_with("/api/cases/alerts/") => "cases_by_alert.json",
                p if p.starts_with("/api/cases/") => "case_get.json",
                p => panic!("unexpected mock route: {p}"),
            };
            ResponseTemplate::new(200).set_body_json(fixture(name))
        })
        .mount(&server)
        .await;
    let target = Resolved {
        name: "test".into(),
        source: Source::Profile,
        profile: Profile {
            kibana_url: server.uri(),
            es_url: Some(server.uri()),
            api_key: Some("test".into()),
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 30,
        },
    };
    let (mut input, server_input) = tokio::io::duplex(1_048_576);
    let (server_output, output) = tokio::io::duplex(1_048_576);
    let task = tokio::spawn(serve_io(
        target,
        ServerOptions::default(),
        server_input,
        server_output,
    ));
    let frame = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params": {
        "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28", "io.modelcontextprotocol/clientCapabilities":{}},
        "name":tool,"arguments":arguments
    }});
    input
        .write_all(format!("{frame}\n").as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        BufReader::new(output).read_line(&mut line),
    )
    .await
    .unwrap()
    .unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    drop(input);
    task.await.unwrap().unwrap();
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    let out = reply["result"]["structuredContent"].clone();
    assert_eq!(
        serde_json::from_str::<Value>(reply["result"]["content"][0]["text"].as_str().unwrap())
            .unwrap(),
        out
    );
    out
}

#[tokio::test]
async fn recorded_alert_context_passes_live_validator() {
    let out = result(
        "alert_context",
        json!({"alert_id":"elasticctl-fixture-alert-1"}),
    )
    .await;
    shape::alert_context(&out).unwrap();
    assert_eq!(out["data"]["cases"]["status"], "ok");
    assert_eq!(out["data"]["rule"]["status"], "ok");
}

#[tokio::test]
async fn recorded_rule_health_passes_live_validator() {
    let id = fixture("rule_get_executed.json")["rule_id"].clone();
    let out = result("rule_health", json!({"selector":id})).await;
    shape::rule_health(&out).unwrap();
    assert_eq!(out["data"]["alerts"]["status"], "ok");
    assert_eq!(out["data"]["exceptions"]["status"], "ok");
}

#[tokio::test]
async fn recorded_detection_coverage_passes_live_validator() {
    let out = result("detection_coverage", json!({})).await;
    shape::detection_coverage(&out).unwrap();
    assert!(out["data"]["summary"]["rules"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn recorded_rule_readiness_passes_live_validator() {
    let id = fixture("rule_get_executed.json")["rule_id"].clone();
    let out = result("rule_readiness", json!({"selector":id})).await;
    shape::rule_readiness(&out).unwrap();
    for part in ["data_views", "patterns", "integrations"] {
        assert_eq!(out["data"][part]["status"], "ok");
    }
}
