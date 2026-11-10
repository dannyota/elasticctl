#[allow(dead_code)]
mod support;
use serde_json::{Value, json};
use support::{Harness, initialize, options, request, target};
#[tokio::test]
async fn capabilities_lists_and_cursors_on_both_paths() {
    for current in [true, false] {
        let mut h = Harness::start(target(), options());
        initialize(&mut h, current).await;
        if current {
            let got = request(&mut h, current, 1, "server/discover", json!({})).await;
            assert_eq!(
                got["result"]["capabilities"],
                json!({"prompts":{},"resources":{},"tools":{}})
            );
        }
        let tools = request(&mut h, current, 2, "tools/list", json!({})).await;
        for (method, key, uris, entries) in [
            (
                "resources/list",
                "resources",
                support::EXPECTED_RESOURCE_URIS,
                expected_resources(),
            ),
            (
                "resources/templates/list",
                "resourceTemplates",
                support::EXPECTED_TEMPLATE_URIS,
                expected_templates(),
            ),
        ] {
            let got = request(&mut h, current, 3, method, json!({})).await;
            let rows = got["result"][key].as_array().unwrap();
            let uri_key = if key == "resources" {
                "uri"
            } else {
                "uriTemplate"
            };
            assert_eq!(
                rows.iter()
                    .map(|r| r[uri_key].as_str().unwrap())
                    .collect::<Vec<_>>(),
                uris
            );
            for (row, (name, title, tool)) in rows.iter().zip(entries) {
                let desc = tools["result"]["tools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|t| t["name"] == tool)
                    .unwrap()["description"]
                    .clone();
                assert_eq!(
                    *row,
                    json!({uri_key:row[uri_key],"name":name,"title":title,"description":desc,"mimeType":"application/json"})
                );
            }
            for (key, val) in [
                ("ttlMs", json!(0)),
                ("cacheScope", json!("private")),
                ("resultType", json!("complete")),
            ] {
                if current {
                    assert_eq!(got["result"][key], val);
                } else {
                    assert!(got["result"].get(key).is_none());
                }
            }
            assert!(got["result"].get("nextCursor").is_none());
            let got = request(&mut h, current, 4, method, json!({"cursor":"sentinel"})).await;
            assert_eq!(
                got["error"],
                json!({"code":-32602,"message":"Invalid cursor"})
            );
        }
        h.close_input();
        h.join().await.unwrap();
    }
}
fn expected_resources() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "coverage-tactic",
            "Detection coverage by ATT&CK tactic",
            "detection_coverage",
        ),
        (
            "coverage-technique",
            "Detection coverage by ATT&CK technique",
            "detection_coverage",
        ),
        ("doctor", "Stack diagnostics", "stack_doctor"),
        ("info", "Stack version and flavor", "stack_info"),
        (
            "prebuilt-rules-status",
            "Prebuilt rule status",
            "rules_prebuilt_status",
        ),
    ]
}
fn expected_templates() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("alert", "Alert by id", "alerts_get"),
        ("case", "Case by id", "cases_get"),
        (
            "exception-list",
            "Exception list by namespace and id",
            "exceptions_get",
        ),
        ("rule", "Rule by rule_id", "rules_get"),
    ]
}
#[tokio::test]
async fn invalid_uris_and_unimplemented_methods_are_refused() {
    for current in [true, false] {
        let mut h = Harness::start(target(), options());
        initialize(&mut h, current).await;
        for uri in [
            "elasticctl://plans/info",
            "elasticctl://stack/nope",
            "elasticctl://stack/rules/%zz",
            "elasticctl://stack/info?sentinel",
        ] {
            let got = request(&mut h, current, 1, "resources/read", json!({"uri":uri})).await;
            assert_eq!(
                got["error"],
                json!({"code":if current {-32602} else {-32002},"message":"Resource not found"})
            );
        }
        for (method, params) in [
            (
                "completion/complete",
                json!({"ref":{"type":"ref/prompt","name":"triage_alert"},"argument":{"name":"alert_id","value":"a"}}),
            ),
            ("subscriptions/listen", json!({})),
            (
                "resources/subscribe",
                json!({"uri":"elasticctl://stack/info"}),
            ),
            ("tasks/get", json!({"taskId":"id"})),
            ("skills/list", json!({})),
        ] {
            let got = request(&mut h, current, 2, method, params).await;
            assert_eq!(got["error"]["code"], -32601, "{got}");
        }
        h.close_input();
        h.join().await.unwrap();
    }
}

use std::time::Duration;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
fn recorded(name: &str) -> Value {
    let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/ech-9.5.2")
        .join(format!("{name}.json"));
    serde_json::from_str::<Value>(&std::fs::read_to_string(file).unwrap()).unwrap()["response"]
        .clone()
}
fn target_for(server: &MockServer) -> elasticctl_core::Resolved {
    let mut t = target();
    t.profile.kibana_url = server.uri();
    t.profile.es_url = Some(server.uri());
    t.profile.api_key = Some("fake-key".into());
    t
}
async fn mount(server: &MockServer, verb: &str, route: &str, body: Value) {
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}
async fn routes(server: &MockServer) {
    for (verb, route, fixture) in [
        ("GET", "/api/status", "status"),
        ("GET", "/_license", "license"),
        ("GET", "/api/spaces/space", "spaces"),
        ("GET", "/_security/_authenticate", "authenticate"),
        ("GET", "/api/detection_engine/rules/_find", "rules_find"),
        ("GET", "/api/detection_engine/rules", "rules_get"),
        (
            "GET",
            "/api/detection_engine/rules/prepackaged/_status",
            "prebuilt_status",
        ),
        (
            "POST",
            "/api/detection_engine/signals/search",
            "signals_search",
        ),
        ("GET", "/api/cases/id", "case_get"),
        ("GET", "/api/exception_lists", "exception_list_get"),
        (
            "GET",
            "/api/exception_lists/items/_find",
            "exception_list_items_find",
        ),
    ] {
        mount(server, verb, route, recorded(fixture)).await;
    }
}
#[tokio::test]
async fn all_nine_reads_equal_tool_text_on_both_paths() {
    for current in [true, false] {
        let server = MockServer::start().await;
        routes(&server).await;
        let mut h = Harness::start(target_for(&server), options());
        initialize(&mut h, current).await;
        for (suffix, tool, args) in [
            (
                "coverage/tactic",
                "detection_coverage",
                json!({"group_by":"tactic","limit":200}),
            ),
            (
                "coverage/technique",
                "detection_coverage",
                json!({"group_by":"technique","limit":200}),
            ),
            ("doctor", "stack_doctor", json!({})),
            ("info", "stack_info", json!({})),
            ("prebuilt-rules/status", "rules_prebuilt_status", json!({})),
            ("alerts/id", "alerts_get", json!({"alert_id":"id"})),
            ("cases/id", "cases_get", json!({"id":"id"})),
            (
                "exception-lists/single/elasticctl-sample-exceptions",
                "exceptions_get",
                json!({"namespace":"single","list_id":"elasticctl-sample-exceptions","limit":50}),
            ),
            (
                "rules/elasticctl-fixture-probe",
                "rules_get",
                json!({"selector":"elasticctl-fixture-probe"}),
            ),
        ] {
            let uri = format!("elasticctl://stack/{suffix}");
            let tool_result = request(
                &mut h,
                current,
                1,
                "tools/call",
                json!({"name":tool,"arguments":args}),
            )
            .await;
            assert_eq!(
                tool_result["result"]["isError"], false,
                "{tool}: {tool_result}"
            );
            let read = request(&mut h, current, 2, "resources/read", json!({"uri":uri})).await;
            assert_eq!(
                read["result"]["contents"],
                json!([{"uri":uri,"mimeType":"application/json","text":tool_result["result"]["content"][0]["text"]}]),
                "{read}"
            );
        }
        h.close_input();
        h.join().await.unwrap();
    }
}
#[tokio::test]
async fn errors_are_sanitized_and_rule_names_are_not_identity() {
    for current in [true, false] {
        for status in [403, 404, 200] {
            let server = MockServer::start().await;
            mount(&server, "GET", "/api/status", recorded("status")).await;
            let error_fixture: Value = serde_json::from_str(include_str!(
                "../../../tests/fixtures/ech-9.5.2/data_view_not_found.json"
            ))
            .unwrap();
            let body = if status == 200 {
                recorded("rules_get")
            } else {
                json!({"statusCode":status,"error":"Not Found","message":format!("{} upstream-sentinel",error_fixture["error"]["message"].as_str().unwrap())})
            };
            Mock::given(method("GET"))
                .and(path("/api/detection_engine/rules"))
                .respond_with(ResponseTemplate::new(status).set_body_json(body))
                .mount(&server)
                .await;
            mount(
                &server,
                "GET",
                "/api/detection_engine/rules/_find",
                recorded("rules_find"),
            )
            .await;
            let mut h = Harness::start(target_for(&server), options());
            initialize(&mut h, current).await;
            let got = request(
                &mut h,
                current,
                1,
                "resources/read",
                json!({"uri":"elasticctl://stack/rules/remote-sentinel"}),
            )
            .await;
            if status == 403 {
                assert_eq!(
                    got["error"],
                    json!({"code":-32603,"message":"Resource read failed","data":{"kind":"permission","http_status":403,"code":"elastic_permission"}})
                );
            } else {
                assert_eq!(
                    got["error"],
                    json!({"code":if current {-32602}else{-32002},"message":"Resource not found"})
                );
            }
            assert!(!got.to_string().contains("remote-sentinel"));
            assert!(!got.to_string().contains("upstream-sentinel"));
            h.close_input();
            h.join().await.unwrap();
        }
    }
}
#[tokio::test]
async fn encoded_identifier_is_decoded_once() {
    let server = MockServer::start().await;
    routes(&server).await;
    mount(&server, "GET", "/api/cases/a%2Fb", recorded("case_get")).await;
    let mut h = Harness::start(target_for(&server), options());
    let got = request(
        &mut h,
        true,
        1,
        "resources/read",
        json!({"uri":"elasticctl://stack/cases/a%2Fb"}),
    )
    .await;
    assert!(got.get("result").is_some(), "{got}");
    let requests = server.received_requests().await.unwrap();
    assert!(requests.iter().any(|r| r.url.path() == "/api/cases/a%2Fb"));
    h.close_input();
    h.join().await.unwrap();
}
#[tokio::test]
async fn deadline_and_structured_cap_are_protocol_errors() {
    for current in [true, false] {
        for oversized in [false, true] {
            let server = MockServer::start().await;
            mount(&server, "GET", "/api/status", recorded("status")).await;
            let mut body = recorded("rules_get");
            if oversized {
                body["description"] = json!("x".repeat(262_145));
            }
            Mock::given(method("GET"))
                .and(path("/api/detection_engine/rules"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body).set_delay(
                    if oversized {
                        Duration::ZERO
                    } else {
                        Duration::from_secs(2)
                    },
                ))
                .mount(&server)
                .await;
            let mut opts = options();
            opts.call_timeout = Duration::from_secs(1);
            let mut h = Harness::start(target_for(&server), opts);
            initialize(&mut h, current).await;
            let got = request(
                &mut h,
                current,
                1,
                "resources/read",
                json!({"uri":"elasticctl://stack/rules/elasticctl-fixture-probe"}),
            )
            .await;
            assert_eq!(
                got["error"],
                json!({"code":-32603,"message":"Resource read failed","data":{"kind":if oversized {"unsupported"}else{"timeout"},"http_status":null,"code":if oversized {"result_too_large"}else{"deadline_exceeded"}}})
            );
            h.close_input();
            h.join().await.unwrap();
        }
    }
}

async fn wait_for_requests(server: &MockServer, count: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path() == "/api/detection_engine/rules")
                .count()
                >= count
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reads reached Elastic");
}
async fn send_read(h: &mut Harness, current: bool, id: u64) {
    let mut params = json!({"uri":"elasticctl://stack/rules/elasticctl-fixture-probe"});
    if current {
        params["_meta"] = support::current_metadata();
    }
    h.send_json(json!({"jsonrpc":"2.0","id":id,"method":"resources/read","params":params}))
        .await;
}
#[tokio::test]
async fn reads_share_permits_with_tools_and_cancellation_releases_one() {
    for current in [true, false] {
        let server = MockServer::start().await;
        mount(&server, "GET", "/api/status", recorded("status")).await;
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(recorded("rules_get"))
                    .set_delay(Duration::from_secs(2)),
            )
            .mount(&server)
            .await;
        let mut h = Harness::start(target_for(&server), options());
        initialize(&mut h, current).await;
        for id in 1..=4 {
            send_read(&mut h, current, id).await;
        }
        wait_for_requests(&server, 4).await;
        let got = request(
            &mut h,
            current,
            5,
            "resources/read",
            json!({"uri":"elasticctl://stack/rules/elasticctl-fixture-probe"}),
        )
        .await;
        assert_eq!(
            got["error"],
            json!({"code":-32603,"message":"Resource read failed","data":{"kind":"error","http_status":null,"code":"busy"}})
        );
        let got = request(
            &mut h,
            current,
            6,
            "tools/call",
            json!({"name":"rules_get","arguments":{"selector":"elasticctl-fixture-probe"}}),
        )
        .await;
        assert_eq!(got["result"]["structuredContent"]["error"]["code"], "busy");
        for (method, params) in [
            ("resources/list", json!({})),
            ("resources/templates/list", json!({})),
            ("prompts/list", json!({})),
            (
                "prompts/get",
                json!({"name":"triage_alert","arguments":{"alert_id":"id"}}),
            ),
        ] {
            let got = request(&mut h, current, 7, method, params).await;
            assert!(got.get("result").is_some(), "{got}");
        }
        h.send_json(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":"remote-sentinel"}})).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        send_read(&mut h, current, 8).await;
        wait_for_requests(&server, 5).await;
        let mut ids = Vec::new();
        for _ in 0..4 {
            let got = tokio::time::timeout(Duration::from_secs(4), h.receive_json())
                .await
                .unwrap();
            assert!(got.get("result").is_some(), "{got}");
            ids.push(got["id"].as_u64().unwrap());
        }
        ids.sort();
        assert_eq!(ids, vec![2, 3, 4, 8]);
        let got = request(
            &mut h,
            current,
            9,
            "prompts/get",
            json!({"name":"review_detection_coverage"}),
        )
        .await;
        assert!(got.get("result").is_some());
        h.close_input();
        h.join().await.unwrap();
    }
}
#[tokio::test]
async fn lists_and_prompt_get_send_no_requests_without_credentials() {
    for current in [true, false] {
        let server = MockServer::start().await;
        let mut t = target_for(&server);
        t.profile.api_key = None;
        let mut h = Harness::start(t, options());
        initialize(&mut h, current).await;
        for (method, params) in [
            ("resources/list", json!({})),
            ("resources/templates/list", json!({})),
            ("prompts/list", json!({})),
            ("prompts/get", json!({"name":"review_detection_coverage"})),
        ] {
            let got = request(&mut h, current, 1, method, params).await;
            assert!(got.get("result").is_some(), "{got}");
        }
        assert!(server.received_requests().await.unwrap().is_empty());
        h.close_input();
        h.join().await.unwrap();
    }
}

#[tokio::test]
async fn prompt_get_and_lists_succeed_while_four_tools_are_held() {
    for current in [true, false] {
        let server = MockServer::start().await;
        mount(&server, "GET", "/api/status", recorded("status")).await;
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(recorded("rules_get"))
                    .set_delay(Duration::from_secs(2)),
            )
            .mount(&server)
            .await;
        let mut h = Harness::start(target_for(&server), options());
        initialize(&mut h, current).await;
        for id in 1..=4 {
            let mut params =
                json!({"name":"rules_get","arguments":{"selector":"elasticctl-fixture-probe"}});
            if current {
                params["_meta"] = support::current_metadata();
            }
            h.send_json(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params}))
                .await;
        }
        wait_for_requests(&server, 4).await;
        for (method, params) in [
            ("resources/list", json!({})),
            ("resources/templates/list", json!({})),
            ("prompts/list", json!({})),
            (
                "prompts/get",
                json!({"name":"triage_alert","arguments":{"alert_id":"id"}}),
            ),
        ] {
            let got = request(&mut h, current, 7, method, params).await;
            assert!(got.get("result").is_some(), "{got}");
        }
        for _ in 0..4 {
            let got = h.receive_json().await;
            assert_eq!(got["result"]["isError"], false);
        }
        h.close_input();
        h.join().await.unwrap();
    }
}

#[tokio::test]
async fn rule_found_by_display_name_is_not_a_resource_match() {
    for current in [true, false] {
        let server = MockServer::start().await;
        routes(&server).await;
        let name = recorded("rules_get")["name"].as_str().unwrap().to_owned();
        let error_fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ech-9.5.2/data_view_not_found.json"
        ))
        .unwrap();
        Mock::given(method("GET")).and(path("/api/detection_engine/rules"))
 .and(wiremock::matchers::query_param("rule_id",name.clone()))
 .respond_with(ResponseTemplate::new(404).set_body_json(json!({"statusCode":404,"error":"Not Found","message":error_fixture["error"]["message"]})))
 .with_priority(1).mount(&server).await;
        let mut h = Harness::start(target_for(&server), options());
        initialize(&mut h, current).await;
        let tool = request(
            &mut h,
            current,
            1,
            "tools/call",
            json!({"name":"rules_get","arguments":{"selector":name}}),
        )
        .await;
        assert_eq!(tool["result"]["isError"], false);
        assert_eq!(
            tool["result"]["structuredContent"]["data"]["rule_id"],
            "elasticctl-fixture-probe"
        );
        let got = request(
            &mut h,
            current,
            2,
            "resources/read",
            json!({"uri":format!("elasticctl://stack/rules/{}",name.replace(' ',"%20"))}),
        )
        .await;
        assert_eq!(
            got["error"],
            json!({"code":if current {-32602}else{-32002},"message":"Resource not found"})
        );
        h.close_input();
        h.join().await.unwrap();
    }
}
