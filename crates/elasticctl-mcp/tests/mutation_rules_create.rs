#[allow(dead_code)]
mod support;
use serde_json::{Value, json};
use support::Harness;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const NOTE: &str = "Note: Kibana creates the rule disabled and without an API key. The credential that first enables it gives it a key, and the rule then runs with that credential's privileges.";
const FLAVORS: [&str; 3] = ["traditional-9.5.1", "ech-9.5.2", "serverless-9.7.0"];
fn fixture(flavor: &str, name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(flavor)
        .join(format!("{name}.json"));
    serde_json::from_slice::<Value>(&std::fs::read(p).unwrap()).unwrap()["response"].clone()
}
fn rule() -> Value {
    json!({"rule_id":"new-rule","name":"New rule","type":"query","query":"event.kind: event"})
}
async fn setup(flavor: &str, current: bool) -> (MockServer, Harness) {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_security/_authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture(flavor, "authenticate")))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"status_code":404,"message":"not found"})),
        )
        .mount(&s)
        .await;
    let mut t = support::target();
    t.profile.kibana_url = s.uri();
    t.profile.es_url = Some(s.uri());
    t.profile.api_key = Some("test-key".into());
    let mut o = support::options();
    o.allow_mutations = elasticctl_mcp::MutationClasses::parse(["rules-create"]).unwrap();
    let mut h = Harness::start(t, o);
    if !current {
        let mut init = support::legacy_initialize(90);
        init["params"]["capabilities"] = json!({"elicitation":{"form":{}}});
        h.send_json(init).await;
        assert!(h.receive_json().await.get("result").is_some());
        h.send_json(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
    }
    (s, h)
}
fn params(current: bool, name: &str, args: Value) -> Value {
    let mut p = json!({"name":name,"arguments":args});
    if current {
        p["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}});
    }
    p
}
async fn call(h: &mut Harness, current: bool, name: &str, args: Value) -> Value {
    h.send_json(
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":params(current,name,args)}),
    )
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(10), h.receive_json())
        .await
        .unwrap()
}
fn content(r: &Value) -> &Value {
    &r["result"]["structuredContent"]
}
async fn plan(h: &mut Harness, current: bool, rule: Value) -> Value {
    let r = call(h, current, "rules_create_plan", json!({"rule":rule})).await;
    assert_eq!(content(&r)["data"]["plan"]["state"], "open", "{r}");
    content(&r)["data"]["plan"].clone()
}
async fn question(h: &mut Harness, current: bool, id: &Value) -> (Value, String) {
    let r = call(h, current, "plan_apply", json!({"plan_id":id})).await;
    let text = if current {
        &r["result"]["inputRequests"]["confirm"]["params"]["message"]
    } else {
        assert_eq!(r["method"], "elicitation/create", "{r}");
        &r["params"]["message"]
    };
    (
        r.clone(),
        text.as_str().unwrap_or_else(|| panic!("{r}")).into(),
    )
}
async fn accept(h: &mut Harness, current: bool, id: &Value, q: &Value) -> Value {
    let answer = json!({"action":"accept","content":{"apply":true}});
    if current {
        let mut p = params(true, "plan_apply", json!({"plan_id":id}));
        p["requestState"] = q["result"]["requestState"].clone();
        p["inputResponses"] = json!({"confirm":answer});
        h.send_json(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":p}))
            .await;
    } else {
        h.send_json(json!({"jsonrpc":"2.0","id":q["id"],"result":answer}))
            .await;
    }
    h.receive_json().await
}
async fn finish(mut h: Harness) {
    h.close_input();
    h.join().await.unwrap();
}
async fn no_plan(h: &mut Harness, current: bool) {
    let r = call(h, current, "plan_list", json!({})).await;
    assert_eq!(content(&r)["data"]["plans"], json!([]), "{r}");
    assert!(h.audit.lock().unwrap().is_empty());
}

#[tokio::test]
async fn invalid_inputs_before_io() {
    for current in [true, false] {
        let (s, mut h) = setup(FLAVORS[0], current).await;
        let mut inputs = vec![
            json!({}),
            json!({"rule":[]}),
            json!({"rule":rule(),"extra":true}),
        ];
        for key in ["rule_id", "name", "type"] {
            for value in [None, Some(json!(1)), Some(json!(" "))] {
                let mut r = rule();
                if let Some(v) = value {
                    r[key] = v;
                } else {
                    r.as_object_mut().unwrap().remove(key);
                }
                inputs.push(json!({"rule":r}));
            }
        }
        for key in elasticctl_api::model::VOLATILE_FIELDS {
            let mut r = rule();
            r[key] = json!(null);
            inputs.push(json!({"rule":r}));
        }
        for key in ["exceptions_list", "actions", "response_actions"] {
            for v in [json!([{}]), json!(null), json!({})] {
                let mut r = rule();
                r[key] = v;
                inputs.push(json!({"rule":r}));
            }
        }
        for v in [json!(true), json!(null), json!("false")] {
            let mut r = rule();
            r["enabled"] = v;
            inputs.push(json!({"rule":r}));
        }
        let mut large = rule();
        large["query"] = json!("");
        let base = serde_json::to_vec(&large).unwrap().len();
        large["query"] = json!("x".repeat(65537 - base));
        assert_eq!(serde_json::to_vec(&large).unwrap().len(), 65537);
        inputs.push(json!({"rule":large}));
        for c in ('\u{7f}'..='\u{9f}')
            .chain(['\u{2028}', '\u{2029}'])
            .chain('\u{202a}'..='\u{202e}')
            .chain('\u{2066}'..='\u{2069}')
        {
            for key in ["name", "nested"] {
                let mut r = rule();
                r[key] = if key == "nested" {
                    json!({"array":[format!("x{c}")]})
                } else {
                    json!(format!("x{c}"))
                };
                inputs.push(json!({"rule":r}));
            }
            let mut r = rule();
            r[format!("key{c}")] = json!("value");
            inputs.push(json!({"rule":r}));
        }
        for args in inputs {
            let r = call(&mut h, current, "rules_create_plan", args.clone()).await;
            assert_eq!(
                content(&r)["error"]["code"],
                "invalid_argument",
                "input {args}: {r}"
            );
        }
        assert!(s.received_requests().await.unwrap().is_empty());
        no_plan(&mut h, current).await;
        finish(h).await;
    }
}

#[tokio::test]
async fn organization_key_refused_before_rule_read() {
    for flavor in FLAVORS {
        for current in [true, false] {
            let (s, mut h) = setup(flavor, current).await;
            let mut auth = fixture(flavor, "authenticate");
            auth["authentication_realm"]["type"] = json!("_cloud_api_key");
            Mock::given(method("GET"))
                .and(path("/_security/_authenticate"))
                .respond_with(ResponseTemplate::new(200).set_body_json(auth))
                .with_priority(1)
                .mount(&s)
                .await;
            let out = call(&mut h, current, "rules_create_plan", json!({"rule":rule()})).await;
            assert_eq!(
                content(&out)["error"]["code"],
                "credential_unsuitable",
                "{out}"
            );
            no_plan(&mut h, current).await;
            let requests = s.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].method, "GET");
            assert_eq!(requests[0].url.path(), "/_security/_authenticate");
            finish(h).await;
        }
    }
}

#[tokio::test]
async fn flow_exact_consent_and_routes_all_flavors_and_protocols() {
    for flavor in FLAVORS {
        for current in [true, false] {
            let (s, mut h) = setup(flavor, current).await;
            let mut r = rule();
            r["query"] = json!("first\n\tsecond");
            r["threat_query"] = json!("threat\nquery");
            r["threat_mapping"] = json!([{"entries":[{"value":"x","field":"a"}]}]);
            r["filters"] = json!([{"term":{"x":"y"}}]);
            r["threshold"] = json!({"value":2,"field":["host.name"]});
            r["unknown_field"] = json!({"z":1,"a":2});
            let mut response = fixture(flavor, "rules_create");
            response["rule_id"] = r["rule_id"].clone();
            Mock::given(method("POST"))
                .and(path("/api/detection_engine/rules"))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&s)
                .await;
            let p = plan(&mut h, current, r.clone()).await;
            r["enabled"] = json!(false);
            assert_eq!(p["operation"]["rule"], r);
            assert!(p["cli_equivalent"].is_null());
            let before = s.received_requests().await.unwrap();
            assert_eq!(before.len(), 2);
            assert_eq!(before[0].url.path(), "/_security/_authenticate");
            assert_eq!(
                before[1].url.query_pairs().collect::<Vec<_>>(),
                vec![("rule_id".into(), "new-rule".into())]
            );
            let (q, text) = question(&mut h, current, &p["plan_id"]).await;
            assert_eq!(
                text.lines().take(3).collect::<Vec<_>>(),
                [
                    "elasticctl asks to apply: Create 1 rule (disabled)",
                    &format!("Target: profile test @ {}, space default", s.address()),
                    "  rule_id: \"new-rule\""
                ]
            );
            assert!(text.lines().any(|l| l == NOTE));
            assert!(!text.contains("this server's credential"));
            let expected = [
                r#"rule_id: "new-rule""#,
                "enabled: false",
                r#"filters: [{"term":{"x":"y"}}]"#,
                r#"name: "New rule""#,
                r#"query: "first\n\tsecond""#,
                r#"threat_mapping: [{"entries":[{"field":"a","value":"x"}]}]"#,
                r#"threat_query: "threat\nquery""#,
                r#"threshold: {"field":["host.name"],"value":2}"#,
                r#"type: "query""#,
                r#"unknown_field: {"a":2,"z":1}"#,
            ];
            assert_eq!(p["details"], json!(expected));
            for line in expected {
                assert!(text.lines().any(|l| l == format!("  {line}")));
            }
            assert!(text.contains("query: \"first\\n\\tsecond\""));
            let applied = accept(&mut h, current, &p["plan_id"], &q).await;
            assert_eq!(
                content(&applied)["data"]["plan"]["state"],
                "applied",
                "{applied}"
            );
            assert_eq!(
                content(&applied)["data"]["outcome"],
                json!({"requested":1,"updated":1,"unchanged":0,"failed":0,"complete":true,"created":{"rule_id":"new-rule"}})
            );
            let requests = s.received_requests().await.unwrap();
            let writes = requests
                .iter()
                .filter(|r| r.method != "GET")
                .collect::<Vec<_>>();
            assert_eq!(writes.len(), 1);
            assert_eq!(writes[0].method, "POST");
            assert_eq!(writes[0].url.path(), "/api/detection_engine/rules");
            assert_eq!(writes[0].body_json::<Value>().unwrap(), r);
            assert!(requests.iter().all(|r| {
                ["/_security/_authenticate", "/api/detection_engine/rules"].contains(&r.url.path())
            }));
            finish(h).await;
        }
    }
}

#[tokio::test]
async fn line_feeds_in_identity_and_name_stay_json_escaped() {
    for key in ["rule_id", "name"] {
        let (_s, mut h) = setup(FLAVORS[0], true).await;
        let mut r = rule();
        r[key] = json!("first\nFORGED");
        let p = plan(&mut h, true, r).await;
        let (_, text) = question(&mut h, true, &p["plan_id"]).await;
        assert!(text.contains(&format!("  {key}: \"first\\nFORGED\"")));
        assert!(!text.lines().any(|l| l.starts_with("FORGED")));
        assert!(text.lines().nth(2).unwrap().starts_with("  rule_id: "));
        finish(h).await;
    }
}

#[tokio::test]
async fn finished_consent_boundary_in_query_and_other_field() {
    for key in ["query", "description"] {
        let (_s, mut h) = setup(FLAVORS[0], true).await;
        let mut r = rule();
        r[key] = json!("");
        let p = plan(&mut h, true, r.clone()).await;
        let (_, text) = question(&mut h, true, &p["plan_id"]).await;
        let padding = 8192 - text.len();
        finish(h).await;
        for extra in [0, 1] {
            let (s, mut h) = setup(FLAVORS[0], true).await;
            r[key] = json!("x".repeat(padding + extra));
            if extra == 0 {
                let p = plan(&mut h, true, r.clone()).await;
                let (_, text) = question(&mut h, true, &p["plan_id"]).await;
                assert_eq!(text.len(), 8192);
            } else {
                let out = call(&mut h, true, "rules_create_plan", json!({"rule":r})).await;
                assert_eq!(content(&out)["error"]["code"], "plan_too_large", "{out}");
                no_plan(&mut h, true).await;
            }
            assert!(
                s.received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .all(|r| r.method == "GET")
            );
            finish(h).await;
        }
    }
}

#[tokio::test]
async fn existing_and_appearing_rule_refused() {
    for at_plan in [true, false] {
        let (s, mut h) = setup(FLAVORS[0], true).await;
        let p = if at_plan {
            Value::Null
        } else {
            plan(&mut h, true, rule()).await
        };
        let mut existing = fixture(FLAVORS[0], "rules_create");
        existing["rule_id"] = json!("new-rule");
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(existing))
            .with_priority(1)
            .mount(&s)
            .await;
        let out = if at_plan {
            call(&mut h, true, "rules_create_plan", json!({"rule":rule()})).await
        } else {
            call(&mut h, true, "plan_apply", json!({"plan_id":p["plan_id"]})).await
        };
        assert_eq!(
            content(&out)["error"]["code"],
            if at_plan {
                "elastic_conflict"
            } else {
                "plan_stale"
            },
            "{out}"
        );
        if at_plan {
            no_plan(&mut h, true).await;
        } else {
            let out = call(&mut h, true, "plan_get", json!({"plan_id":p["plan_id"]})).await;
            assert_eq!(content(&out)["data"]["plan"]["state"], "stale");
        }
        assert!(
            s.received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method == "GET")
        );
        finish(h).await;
    }
}

#[tokio::test]
async fn post_conflict_bad_request_and_enabled_response_classification() {
    for (status, enabled, code, state) in [
        (409, false, "plan_stale", "stale"),
        (400, false, "elastic_http", "failed"),
        (200, true, "apply_outcome_unknown", "unknown"),
    ] {
        let (s, mut h) = setup(FLAVORS[0], true).await;
        let mut response = fixture(FLAVORS[0], "rules_create");
        response["rule_id"] = json!("new-rule");
        response["enabled"] = json!(enabled);
        let body = if status == 200 {
            response
        } else {
            json!({"status_code":status,"message":"refused"})
        };
        Mock::given(method("POST"))
            .and(path("/api/detection_engine/rules"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .expect(1)
            .mount(&s)
            .await;
        let p = plan(&mut h, true, rule()).await;
        assert_eq!(p["operation"]["rule"]["enabled"], false);
        let (q, _) = question(&mut h, true, &p["plan_id"]).await;
        let out = accept(&mut h, true, &p["plan_id"], &q).await;
        assert_eq!(content(&out)["error"]["code"], code, "{out}");
        if status == 400 {
            assert_eq!(content(&out)["error"]["http_status"], status);
        }
        let out = call(&mut h, true, "plan_get", json!({"plan_id":p["plan_id"]})).await;
        assert_eq!(content(&out)["data"]["plan"]["state"], state);
        assert!(content(&out)["data"]["outcome"].is_null());
        let audit = h
            .audit
            .lock()
            .unwrap()
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).unwrap()["audit"].clone())
            .collect::<Vec<_>>();
        assert!(audit.iter().any(|a| a["event"] == "apply_started"));
        let last = audit
            .iter()
            .find(|a| a["event"] == "apply_finished")
            .unwrap();
        assert_eq!(last["state"], state);
        assert_eq!(
            last["http_status"],
            if status == 200 {
                Value::Null
            } else {
                json!(status)
            }
        );
        let finished = audit
            .iter()
            .position(|a| a["event"] == "apply_finished")
            .unwrap();
        let closed: Vec<usize> = (0..audit.len())
            .filter(|&i| audit[i]["event"] == "plan_closed")
            .collect();
        if state == "stale" {
            assert_eq!(closed.len(), 1, "{audit:?}");
            assert!(closed[0] > finished, "{audit:?}");
            assert_eq!(audit[closed[0]]["state"], "stale");
        } else {
            assert!(closed.is_empty(), "{audit:?}");
        }
        let requests = s.received_requests().await.unwrap();
        let post = requests
            .iter()
            .filter(|r| r.method == "POST")
            .collect::<Vec<_>>();
        assert_eq!(post.len(), 1);
        assert_eq!(post[0].body_json::<Value>().unwrap()["enabled"], false);
        finish(h).await;
    }
}

#[tokio::test]
async fn mixed_session_invalid_request_before_io() {
    let (s, mut h) = setup(FLAVORS[0], false).await;
    let out = call(&mut h, true, "rules_create_plan", json!({"rule":rule()})).await;
    assert_eq!(out["error"]["code"], -32600, "{out}");
    assert!(s.received_requests().await.unwrap().is_empty());
    assert!(h.audit.lock().unwrap().is_empty());
    finish(h).await;
}
