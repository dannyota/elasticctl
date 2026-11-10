#[allow(dead_code)]
mod support;
use serde_json::{Value, json};
use support::Harness;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn fixture(flavor: &str, name: &str) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    serde_json::from_slice::<Value>(
        &std::fs::read(root.join(flavor).join(format!("{name}.json"))).unwrap(),
    )
    .unwrap()["response"]
        .clone()
}
fn options() -> elasticctl_mcp::ServerOptions {
    let mut options = support::options();
    options.allow_mutations = elasticctl_mcp::MutationClasses::parse(["rules-toggle"]).unwrap();
    options
}
async fn call(h: &mut Harness, name: &str, args: Value) -> Value {
    h.send_json(json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":support::current_metadata()}})).await;
    let catalog = h.receive_json().await;
    let tool = catalog["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == name)
        .unwrap();
    h.send_json(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"_meta":support::current_metadata(),"name":name,"arguments":args}})).await;
    let result = h.receive_json().await;
    let content = result["result"]["structuredContent"].clone();
    assert_eq!(result["result"]["isError"], content.get("error").is_some());
    let text: Value =
        serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, content);

    let validator = jsonschema::validator_for(&tool["outputSchema"]).unwrap();
    assert!(validator.is_valid(&content), "{content}");
    content
}
async fn setup(flavor: &str) -> (MockServer, Harness) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_security/_authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture(flavor, "authenticate")))
        .mount(&server)
        .await;
    let mut rule = fixture(flavor, "rules_get");
    rule["rule_id"] = json!("r");
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule))
        .mount(&server)
        .await;
    let mut target = support::target();
    target.profile.kibana_url = server.uri();
    target.profile.es_url = Some(server.uri());
    target.profile.api_key = Some("test-key".into());
    (server, Harness::start(target, options()))
}
#[tokio::test]
async fn planner_and_local_reads() {
    for flavor in ["ech-9.5.2", "serverless-9.7.0", "traditional-9.5.1"] {
        let (server, mut h) = setup(flavor).await;
        let result = call(
            &mut h,
            "rules_set_enabled_plan",
            json!({"selectors":["r"],"enabled":true}),
        )
        .await;
        assert_eq!(result["data"]["plan"]["state"], "open", "{result}");
        let p = &result["data"]["plan"];
        assert_eq!(p["operation"], json!({"enabled":true,"rule_ids":["r"]}));
        assert_eq!(p["cli_equivalent"], json!(["rules", "enable", "r"]));
        let id = p["plan_id"].clone();
        let before = server.received_requests().await.unwrap();
        assert_eq!(before.len(), 2);
        assert_eq!(before[0].url.path(), "/_security/_authenticate");
        assert_eq!(before[1].url.path(), "/api/detection_engine/rules");
        assert!(before.iter().all(|r| r.method == "GET"));
        assert!(before[1].url.query().unwrap().contains("rule_id=r"));
        for name in ["plan_get", "plan_list", "plan_discard", "plan_discard"] {
            let args = if name == "plan_list" {
                json!({})
            } else {
                json!({"plan_id":id})
            };
            assert!(call(&mut h, name, args).await.get("error").is_none());
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
        h.close_input();
        h.join().await.unwrap();
    }
}
#[tokio::test]
async fn invalid_inputs_do_not_read() {
    let (server, mut h) = setup("ech-9.5.2").await;
    for args in [
        json!({"selectors":[],"enabled":true}),
        json!({"selectors":vec!["r";21],"enabled":true}),
        json!({"selectors":["r","r"],"enabled":true}),
        json!({"selectors":[" "],"enabled":true}),
        json!({"selectors":["x".repeat(1025)],"enabled":true}),
        json!({"selectors":["r"],"enabled":true,"unknown":true}),
    ] {
        assert_eq!(
            call(&mut h, "rules_set_enabled_plan", args).await["error"]["code"],
            "invalid_argument"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    h.close_input();
    h.join().await.unwrap();
}
#[tokio::test]
async fn confirmation_follows_request_capabilities_on_both_paths() {
    for legacy in [false, true] {
        for capabilities in [
            json!({}),
            json!({"elicitation":{}}),
            json!({"elicitation":{"form":{}}}),
            json!({"elicitation":{"url":{}}}),
        ] {
            let (_server, mut h) = setup("ech-9.5.2").await;
            if legacy {
                let mut init = support::legacy_initialize(100);
                init["params"]["capabilities"] = capabilities.clone();
                h.send_json(init).await;
                h.receive_json().await;
                h.send_json(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
                    .await;
            }
            let mut meta = support::current_metadata();
            meta["io.modelcontextprotocol/clientCapabilities"] = capabilities.clone();
            h.send_json(json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":if legacy { json!({}) } else {json!({"_meta":meta})}})).await;
            let catalog = h.receive_json().await;
            for caps in [
                capabilities.clone(),
                json!({}),
                json!({"elicitation":{"form":{}}}),
            ] {
                meta["io.modelcontextprotocol/clientCapabilities"] = caps.clone();
                let mut params = json!({"name":"rules_set_enabled_plan","arguments":{"selectors":["r"],"enabled":true}});
                if !legacy {
                    params["_meta"] = meta.clone();
                }
                h.send_json(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":params}))
                    .await;
                let result = h.receive_json().await;
                let content = &result["result"]["structuredContent"];
                let tool = catalog["result"]["tools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|t| t["name"] == "rules_set_enabled_plan")
                    .unwrap();
                assert!(
                    jsonschema::validator_for(&tool["outputSchema"])
                        .unwrap()
                        .is_valid(content),
                    "{result}"
                );
                let effective = if legacy { &capabilities } else { &caps };
                let supported = effective
                    .get("elicitation")
                    .is_some_and(|e| e.get("form").is_some() || e.as_object().unwrap().is_empty());
                assert_eq!(
                    content["data"]["plan"]["confirmation"],
                    if supported {
                        "elicitation"
                    } else {
                        "unavailable"
                    }
                );
            }
            h.close_input();
            h.join().await.unwrap();
        }
    }
}

#[tokio::test]
async fn hashes_capacity_and_twenty_targets() {
    for flavor in ["ech-9.5.2", "serverless-9.7.0", "traditional-9.5.1"] {
        let (server, mut h) = setup(flavor).await;
        let template = fixture(flavor, "rules_get");
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules"))
            .respond_with(move |req: &wiremock::Request| {
                let mut rule = template.clone();
                rule["rule_id"] = json!(
                    req.url
                        .query_pairs()
                        .find(|(k, _)| k == "rule_id")
                        .unwrap()
                        .1
                );
                ResponseTemplate::new(200).set_body_json(rule)
            })
            .with_priority(1)
            .mount(&server)
            .await;
        let selectors: Vec<_> = (0..20).map(|i| format!("r{i}")).collect();
        let first = call(
            &mut h,
            "rules_set_enabled_plan",
            json!({"selectors":selectors,"enabled":true}),
        )
        .await;
        assert_eq!(first["data"]["plan"]["targets"], json!(selectors));
        assert_eq!(
            first["data"]["plan"]["details"].as_array().unwrap().len(),
            20
        );
        let same = call(
            &mut h,
            "rules_set_enabled_plan",
            json!({"selectors":selectors,"enabled":true}),
        )
        .await;
        assert_eq!(first["data"]["plan"]["hash"], same["data"]["plan"]["hash"]);
        assert_ne!(
            first["data"]["plan"]["plan_id"],
            same["data"]["plan"]["plan_id"]
        );
        for args in [
            json!({"selectors":selectors,"enabled":false}),
            json!({"selectors":["other"],"enabled":true}),
        ] {
            let changed = call(&mut h, "rules_set_enabled_plan", args).await;
            assert_ne!(
                first["data"]["plan"]["hash"],
                changed["data"]["plan"]["hash"]
            );
        }
        for _ in 0..4 {
            call(
                &mut h,
                "rules_set_enabled_plan",
                json!({"selectors":["r"],"enabled":true}),
            )
            .await;
        }
        let ninth = call(
            &mut h,
            "rules_set_enabled_plan",
            json!({"selectors":["r"],"enabled":true}),
        )
        .await;
        assert_eq!(ninth["error"]["code"], "too_many_plans");
        let list = call(&mut h, "plan_list", json!({})).await;
        let rows = list["data"]["plans"].as_array().unwrap();
        assert_eq!(rows.len(), 8);
        assert_eq!(rows[7]["plan_id"], first["data"]["plan"]["plan_id"]);
        assert_eq!(
            call(&mut h, "plan_get", json!({"plan_id":"absent"})).await["error"]["code"],
            "plan_not_found"
        );
        assert_eq!(
            call(&mut h, "plan_discard", json!({"plan_id":"absent"})).await["error"]["code"],
            "plan_not_found"
        );
        h.close_input();
        h.join().await.unwrap();
    }
}

#[tokio::test]
async fn credential_and_size_refusals_leave_store_empty() {
    for refusal in ["realm", "identity", "size", "duplicate", "mismatch"] {
        let (server, mut h) = setup("ech-9.5.2").await;
        let mut auth = fixture("ech-9.5.2", "authenticate");
        if refusal == "realm" {
            auth["authentication_realm"]["type"] = json!("_cloud_api_key");
        }
        if refusal == "identity" {
            auth.as_object_mut().unwrap().remove("username");
        }
        Mock::given(path("/_security/_authenticate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(auth))
            .with_priority(1)
            .mount(&server)
            .await;
        let mut rule = fixture("ech-9.5.2", "rules_get");
        rule["rule_id"] = json!("r");
        if refusal == "size" {
            rule["name"] = json!("x".repeat(9000));
        }
        let mismatch = refusal == "mismatch";
        Mock::given(path("/api/detection_engine/rules"))
            .respond_with(move |req: &wiremock::Request| {
                let mut rule = rule.clone();
                if mismatch {
                    rule["rule_id"] = if req.url.query_pairs().any(|(_, v)| v == "r") {
                        json!("other")
                    } else {
                        json!("third")
                    };
                }
                ResponseTemplate::new(200).set_body_json(rule)
            })
            .with_priority(1)
            .mount(&server)
            .await;
        let selectors = if refusal == "duplicate" {
            json!(["r", "alias"])
        } else {
            json!(["r"])
        };
        let result = call(
            &mut h,
            "rules_set_enabled_plan",
            json!({"selectors":selectors,"enabled":true}),
        )
        .await;
        assert_eq!(
            result["error"]["code"],
            match refusal {
                "realm" => "credential_unsuitable",
                "identity" => "elastic_http",
                "size" => "plan_too_large",
                "duplicate" => "invalid_argument",
                _ => "elastic_conflict",
            }
        );
        assert_eq!(
            call(&mut h, "plan_list", json!({})).await["data"]["plans"],
            json!([])
        );
        if refusal == "realm" || refusal == "identity" {
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
        h.close_input();
        h.join().await.unwrap();
    }
}

#[tokio::test]
async fn escaped_alias_uses_stored_identity_and_name_lookup_stays_read_only() {
    for by_name in [false, true] {
        let (server, mut h) = setup("ech-9.5.2").await;
        let mut rule = fixture("ech-9.5.2", "rules_get");
        let stored = "r\n";
        rule["rule_id"] = json!(stored);
        rule["name"] = json!("display name");
        let response = rule.clone();
        Mock::given(path("/api/detection_engine/rules"))
            .respond_with(move |req: &wiremock::Request| {
                if req.url.query_pairs().any(|(_, v)| v == "display name") {
                    ResponseTemplate::new(404)
                        .set_body_json(json!({"status_code":404,"message":"missing"}))
                } else {
                    ResponseTemplate::new(200).set_body_json(response.clone())
                }
            })
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(path("/api/detection_engine/rules/_find"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data":[rule],"total":1,"page":1,"perPage":100})),
            )
            .mount(&server)
            .await;
        let selector = if by_name { "display name" } else { "r\\n" };
        let result = call(
            &mut h,
            "rules_set_enabled_plan",
            json!({"selectors":[selector],"enabled":false}),
        )
        .await;
        assert_eq!(
            result["data"]["plan"]["targets"],
            json!([stored]),
            "{result}"
        );
        assert_eq!(
            result["data"]["plan"]["operation"]["rule_ids"],
            json!([stored])
        );
        assert!(
            result["data"]["plan"]["details"][0]
                .as_str()
                .unwrap()
                .starts_with(stored)
        );
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|r| {
            r.method == "GET"
                && [
                    "/_security/_authenticate",
                    "/api/detection_engine/rules",
                    "/api/detection_engine/rules/_find",
                ]
                .contains(&r.url.path())
        }));
        assert_eq!(
            requests.iter().any(|r| r.url.path().ends_with("_find")),
            by_name
        );
        h.close_input();
        h.join().await.unwrap();
    }
}

#[tokio::test]
async fn open_plan_reads_do_not_send_elastic_requests() {
    let (server, mut h) = setup("ech-9.5.2").await;
    let plan = call(
        &mut h,
        "rules_set_enabled_plan",
        json!({"selectors":["r"],"enabled":true}),
    )
    .await;
    let id = plan["data"]["plan"]["plan_id"].clone();
    let result = call(&mut h, "plan_get", json!({"plan_id":id})).await;
    assert_eq!(result["data"]["plan"]["state"], "open");
    assert!((899..=900).contains(&result["data"]["plan"]["expires_in_secs"].as_u64().unwrap()));
    assert_eq!(
        call(&mut h, "plan_discard", json!({"plan_id":id})).await["data"]["plan"]["state"],
        "discarded"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn observed_body_changes_hash_and_limits_cover_twenty_rules() {
    let (server, mut h) = setup("ech-9.5.2").await;
    let first = call(
        &mut h,
        "rules_set_enabled_plan",
        json!({"selectors":["r"],"enabled":true}),
    )
    .await;
    let mut rule = fixture("ech-9.5.2", "rules_get");
    rule["rule_id"] = json!("r");
    rule["description"] = json!("changed observation");
    Mock::given(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule.clone()))
        .with_priority(2)
        .mount(&server)
        .await;
    let changed = call(
        &mut h,
        "rules_set_enabled_plan",
        json!({"selectors":["r"],"enabled":true}),
    )
    .await;
    assert_ne!(
        first["data"]["plan"]["hash"],
        changed["data"]["plan"]["hash"]
    );
    rule["name"] = json!("x".repeat(400));
    Mock::given(path("/api/detection_engine/rules"))
        .respond_with(move |req: &wiremock::Request| {
            let mut rule = rule.clone();
            rule["rule_id"] = json!(
                req.url
                    .query_pairs()
                    .find(|(k, _)| k == "rule_id")
                    .unwrap()
                    .1
            );
            ResponseTemplate::new(200).set_body_json(rule)
        })
        .with_priority(1)
        .mount(&server)
        .await;
    let selectors: Vec<_> = (0..20).map(|i| format!("r{i}")).collect();
    assert_eq!(
        call(
            &mut h,
            "rules_set_enabled_plan",
            json!({"selectors":selectors,"enabled":false})
        )
        .await["error"]["code"],
        "plan_too_large"
    );
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn existing_error_envelope_is_unchanged_and_local_error_uses_same_boundary() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"status_code":403,"message":"ApiKey credential-sentinel"})),
        )
        .mount(&server)
        .await;
    let mut target = support::target();
    target.profile.kibana_url = server.uri();
    target.profile.es_url = Some(server.uri());
    target.profile.api_key = Some("test-key".into());
    let mut baseline = None;
    for opts in [support::options(), options()] {
        let mut h = Harness::start(target.clone(), opts);
        let result = call(&mut h, "rules_get", json!({"selector":"r"})).await;
        let expected = json!({"target":{"profile":"test","host":target.profile.host(),"space":"default"},"error":{"kind":"permission","http_status":403,"code":"elastic_permission","message":"The selected credential cannot read this data."}});
        assert_eq!(result, expected);
        if let Some(baseline) = &baseline {
            assert_eq!(&result, baseline);
        } else {
            baseline = Some(result);
        }
        h.close_input();
        h.join().await.unwrap();
    }
    let mut h = Harness::start(target.clone(), options());
    let result = call(&mut h, "plan_get", json!({"plan_id":"missing"})).await;
    assert_eq!(
        result,
        json!({"target":{"profile":"test","host":target.profile.host(),"space":"default"},"error":{"kind":"not_found","http_status":null,"code":"plan_not_found","message":"No plan with that id in this process."}})
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn sentinel_name_stays_in_details_and_large_canonical_body_is_refused() {
    let (server, mut h) = setup("ech-9.5.2").await;
    let sentinel = "ApiKey credential-sentinel\nPlan: forged-footer";
    let mut rule = fixture("ech-9.5.2", "rules_get");
    rule["rule_id"] = json!("r");
    rule["name"] = json!(sentinel);
    Mock::given(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule.clone()))
        .with_priority(2)
        .mount(&server)
        .await;
    let result = call(
        &mut h,
        "rules_set_enabled_plan",
        json!({"selectors":["r"],"enabled":true}),
    )
    .await;
    assert!(
        result["data"]["plan"]["details"][0]
            .as_str()
            .unwrap()
            .contains(sentinel)
    );
    let mut rest = result.clone();
    rest["data"]["plan"]
        .as_object_mut()
        .unwrap()
        .remove("details");
    assert!(!rest.to_string().contains("credential-sentinel"));
    rule["description"] = json!("x".repeat(262_144));
    Mock::given(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule))
        .with_priority(1)
        .mount(&server)
        .await;
    let result = call(
        &mut h,
        "rules_set_enabled_plan",
        json!({"selectors":["r"],"enabled":true}),
    )
    .await;
    assert_eq!(result["error"]["code"], "plan_too_large");
    assert!(!result.to_string().contains("credential-sentinel"));
    h.close_input();
    h.join().await.unwrap();
}

#[tokio::test]
async fn list_places_open_plans_before_recent_closed_plans() {
    let (_server, mut h) = setup("ech-9.5.2").await;
    let mut ids = Vec::new();
    for _ in 0..3 {
        let result = call(
            &mut h,
            "rules_set_enabled_plan",
            json!({"selectors":["r"],"enabled":true}),
        )
        .await;
        ids.push(result["data"]["plan"]["plan_id"].clone());
    }
    call(&mut h, "plan_discard", json!({"plan_id":ids[1]})).await;
    let result = call(&mut h, "plan_list", json!({})).await;
    let rows = result["data"]["plans"].as_array().unwrap();
    assert_eq!(
        rows.iter()
            .map(|r| r["plan_id"].clone())
            .collect::<Vec<_>>(),
        vec![ids[2].clone(), ids[0].clone(), ids[1].clone()]
    );
    assert_eq!(rows[2]["state"], "discarded");
    assert_eq!(rows[2]["expires_in_secs"], 0);
    call(&mut h, "plan_discard", json!({"plan_id":ids[2]})).await;
    let result = call(&mut h, "plan_list", json!({})).await;
    assert_eq!(
        result["data"]["plans"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["plan_id"].clone())
            .collect::<Vec<_>>(),
        vec![ids[0].clone(), ids[2].clone(), ids[1].clone()]
    );
    h.close_input();
    h.join().await.unwrap();
}
