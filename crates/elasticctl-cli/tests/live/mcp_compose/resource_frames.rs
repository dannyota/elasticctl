use super::*;
use crate::mcp_smoke::{initialize_child, mcp_subprocess_config};
use wiremock::{Mock, MockServer, Request, ResponseTemplate, matchers::any};

fn recorded(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/serverless-9.7.0")
        .join(name);
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

async fn stack() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(|request: &Request| {
            let name = match request.url.path() {
                "/api/status" => "status.json",
                "/_license" => "license.json",
                "/api/spaces/space" => "spaces.json",
                "/api/detection_engine/rules/_find" => "rules_find_source_prebuilt.json",
                "/api/detection_engine/rules" => {
                    if request
                        .url
                        .query_pairs()
                        .any(|(k, v)| k == "rule_id" && v.contains("compose-missing-rule"))
                    {
                        let missing = recorded("resolve_index_not_found.json");
                        return ResponseTemplate::new(
                            missing["error"]["http_status"].as_u64().unwrap() as u16,
                        );
                    }
                    "rule_get_executed.json"
                }
                path => panic!("Unexpected fixture route: {path}"),
            };
            ResponseTemplate::new(200).set_body_json(&recorded(name)["response"])
        })
        .mount(&server)
        .await;
    server
}

#[tokio::test(flavor = "multi_thread")]
async fn real_current_resource_frames_match_live_validators() {
    let server = stack().await;
    let dir = tempfile::tempdir().unwrap();
    let config = mcp_subprocess_config(dir.path(), &server.uri());
    let mut child = McpChild::spawn(&config, false).unwrap();
    let mut failures = Vec::new();
    let frame = child.request("server/discover", json!({})).unwrap();
    if let Err(error) = validate_capabilities(&frame) {
        failures.push(format!("server/discover: {error}: {frame}"));
    }
    for (method, key, entries) in [
        (
            "resources/list",
            "resources",
            expected_resource_entries(false),
        ),
        (
            "resources/templates/list",
            "resourceTemplates",
            expected_resource_entries(true),
        ),
        ("prompts/list", "prompts", expected_prompts()),
    ] {
        let frame = child.request(method, json!({})).unwrap();
        if let Err(error) = validate_list(&frame, key, &entries) {
            failures.push(format!("{method}: {error}: {frame}"));
        }
    }
    let rule = recorded("rule_get_executed.json")["response"]["rule_id"]
        .as_str()
        .unwrap()
        .to_string();
    for (uri, tool, args) in [
        (
            "elasticctl://stack/info".to_string(),
            "stack_info",
            json!({}),
        ),
        (
            format!(
                "elasticctl://stack/rules/{}",
                elasticctl_core::urlencode(&rule)
            ),
            "rules_get",
            json!({"selector":rule}),
        ),
    ] {
        if let Err(error) = read_pair(&mut child, &uri, &uri, tool, args) {
            let frame = child.request("resources/read", json!({"uri":uri})).unwrap();
            failures.push(format!("{uri}: {error}: {frame}"));
        }
    }
    for (index, args, replacement) in [
        (
            0,
            json!({"rule":rule}),
            format!(r#"{{"selector":"{rule}"}}"#),
        ),
        (
            1,
            json!({}),
            r#"{"group_by":"technique","limit":200}"#.to_string(),
        ),
        (
            2,
            json!({"rule":rule}),
            format!(r#"{{"selector":"{rule}","since":"24h"}}"#),
        ),
        (
            3,
            json!({"alert_id":"recorded-alert"}),
            r#"{"alert_id":"recorded-alert","since":"24h"}"#.to_string(),
        ),
    ] {
        let definition = &expected_prompts()[index];
        let expected = json!({"description":definition["description"],"messages":[{"role":"user","content":{"type":"text","text":PROMPT_TEXTS[index].replace("<args>",&replacement)}}]});
        let frame = child
            .request(
                "prompts/get",
                json!({"name":definition["name"],"arguments":args}),
            )
            .unwrap();
        if let Err(error) = validate_prompt(&frame, &expected) {
            failures.push(format!(
                "prompts/get {}: {error}: {frame}",
                definition["name"]
            ));
        }
    }
    not_found_checks(&mut child).unwrap();
    child.shutdown().unwrap();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test(flavor = "multi_thread")]
async fn real_legacy_resource_errors_match_live_validators() {
    let server = stack().await;
    let dir = tempfile::tempdir().unwrap();
    let config = mcp_subprocess_config(dir.path(), &server.uri());
    let mut child = McpChild::spawn(&config, true).unwrap();
    initialize_child(&mut child, true).unwrap();
    not_found_checks(&mut child).unwrap();
    child.shutdown().unwrap();
}
