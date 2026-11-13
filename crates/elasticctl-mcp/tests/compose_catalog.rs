#[allow(dead_code)]
mod support;
use serde_json::json;
use support::*;
#[tokio::test]
async fn catalogs_and_path_validation() {
    for query in [false, true] {
        let mut opts = options();
        opts.allow_query_tools = query;
        let mut h = Harness::start(target(), opts);
        h.send_json(json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":current_metadata()}})).await;
        let r = h.receive_json().await;
        let tools = r["result"]["tools"].as_array().unwrap();
        let mut expected = vec![
            "alert_context",
            "alerts_get",
            "alerts_list",
            "cases_get",
            "cases_list",
            "dashboards_get",
            "dashboards_list",
            "data_views_default_get",
            "data_views_get",
            "data_views_list",
            "detection_coverage",
            "exceptions_get",
            "exceptions_list",
            "fleet_agent_policies_get",
            "fleet_agent_policies_list",
            "fleet_integration_policies_get",
            "fleet_integration_policies_list",
            "rule_health",
            "rule_readiness",
            "rules_get",
            "rules_list",
            "rules_prebuilt_status",
        ];
        if query {
            expected.extend(["search_dsl", "search_esql"]);
        }
        expected.extend(["stack_doctor", "stack_info"]);
        assert_eq!(
            tools
                .iter()
                .map(|t| t["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            expected
        );
        for name in [
            "alert_context",
            "detection_coverage",
            "rule_health",
            "rule_readiness",
        ] {
            let tool = tools.iter().find(|t| t["name"] == name).unwrap();
            assert_eq!(
                tool["annotations"],
                json!({"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true})
            );
        }
        for id in [".", ".."] {
            h.send_json(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cases_get","arguments":{"id":id},"_meta":current_metadata()}})).await;
            let r = h.receive_json().await;
            assert_eq!(
                r["result"]["structuredContent"]["error"]["code"],
                "invalid_argument"
            );
        }
        h.close_input();
        h.join().await.unwrap();
    }
}
#[tokio::test]
async fn cases_path_and_query_rejection() {
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};
    let s = MockServer::start().await;
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/traditional-9.5.1/case_get.json"
    )))
    .unwrap();
    Mock::given(path("/api/cases/ordinary"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&fixture["response"]))
        .mount(&s)
        .await;
    let mut target = target();
    target.profile.kibana_url = s.uri();
    target.profile.api_key = Some("fake-auth-marker".to_string());
    let mut h = Harness::start(target, options());
    for (name, args, code) in [
        ("cases_get", json!({"id":"."}), "invalid_argument"),
        ("cases_get", json!({"id":".."}), "invalid_argument"),
        (
            "data_views_get",
            json!({"selector":"."}),
            "invalid_argument",
        ),
        (
            "data_views_get",
            json!({"selector":".."}),
            "invalid_argument",
        ),
        (
            "dashboards_get",
            json!({"selector":"."}),
            "invalid_argument",
        ),
        (
            "dashboards_get",
            json!({"selector":".."}),
            "invalid_argument",
        ),
        (
            "fleet_agent_policies_get",
            json!({"selector":"."}),
            "invalid_argument",
        ),
        (
            "fleet_agent_policies_get",
            json!({"selector":".."}),
            "invalid_argument",
        ),
        (
            "fleet_integration_policies_get",
            json!({"selector":"."}),
            "invalid_argument",
        ),
        (
            "fleet_integration_policies_get",
            json!({"selector":".."}),
            "invalid_argument",
        ),
    ] {
        h.send_json(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":current_metadata(),"name":name,"arguments":args}})).await;
        let reply = h.receive_json().await;
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"], code,
            "{name} {args}: {reply}"
        );
    }
    for name in ["search_dsl", "search_esql"] {
        h.send_json(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":current_metadata(),"name":name,"arguments":{}}})).await;
        let reply = h.receive_json().await;
        assert_eq!(reply["error"]["code"], -32601, "{name}: {reply}");
    }
    assert!(s.received_requests().await.unwrap().is_empty());
    h.send_json(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"_meta":current_metadata(),"name":"cases_get","arguments":{"id":"ordinary"}}})).await;
    let reply = h.receive_json().await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    let req = s.received_requests().await.unwrap();
    assert_eq!(req.len(), 1);
    assert_eq!(req[0].url.path(), "/api/cases/ordinary");
    h.close_input();
    h.join().await.unwrap();
}
