use elasticctl_api::{
    alerts::AlertStatus, alerts_ops, cases::CaseStatus, cases_ops, model::Rule, normalize,
    rules_ops,
};
use elasticctl_api_test_support::MockStack;
use elasticctl_core::{Profile, Transport};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};

fn fixture(set: &str, name: &str) -> Value {
    let path = format!(
        "{}/../../tests/fixtures/{set}/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap()).unwrap()["response"]
        .clone()
}

fn transport(uri: &str) -> Transport {
    Transport::new(&Profile {
        kibana_url: uri.into(),
        es_url: Some(uri.into()),
        api_key: Some("test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .unwrap()
}

#[tokio::test]
async fn plan_set_enabled_observed_matches_plan_set_enabled_and_sends_the_same_requests() {
    for set in ["ech-9.5.2", "serverless-9.7.0", "traditional-9.5.1"] {
        let rule = fixture(set, "rules_get");
        let id = rule["rule_id"].as_str().unwrap().to_string();
        let mut second = rule.clone();
        second["rule_id"] = json!("second-rule");
        let ids = vec![id, "second-rule".into()];
        let stack = MockStack::with_rules(vec![rule.clone(), second.clone()]).await;
        let (plan, seen) = rules_ops::plan_set_enabled_observed(stack.transport(), &ids, false)
            .await
            .unwrap();
        let observed: Vec<_> = stack
            .requests()
            .await
            .into_iter()
            .map(|r| (r.method, r.path, r.query, r.body))
            .collect();
        let old_stack = MockStack::with_rules(vec![rule.clone(), second]).await;
        let old = rules_ops::plan_set_enabled(old_stack.transport(), &ids, false)
            .await
            .unwrap();
        let old_requests: Vec<_> = old_stack
            .requests()
            .await
            .into_iter()
            .map(|r| (r.method, r.path, r.query, r.body))
            .collect();
        assert_eq!(plan, old);
        let canonical =
            normalize::canonical(&serde_json::from_value::<Rule>(rule).unwrap()).into_value();
        assert_eq!(seen.0.len(), 2);
        assert_eq!(seen.0[0].state, Some(canonical));
        assert_eq!(observed.len(), 2);
        assert_eq!(observed, old_requests);
    }
}

async fn requests(server: &MockServer) -> Vec<(String, String, Option<String>, Vec<u8>)> {
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .map(|r| {
            (
                r.method.to_string(),
                r.url.path().to_string(),
                r.url.query().map(str::to_string),
                r.body,
            )
        })
        .collect()
}

async fn case_server(body: &Value, second: &Value) -> MockServer {
    let server = MockServer::start().await;
    for case in [body, second] {
        let id = case["id"].as_str().unwrap();
        Mock::given(method("GET"))
            .and(path(format!("/api/cases/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(case))
            .mount(&server)
            .await;
    }
    server
}

async fn check_case_planner(comment: bool) {
    for set in ["ech-9.5.2", "serverless-9.7.0", "traditional-9.5.1"] {
        let original = fixture(set, "case_get");
        for variant in 0..5 {
            let mut body = original.clone();
            match variant {
                1 => body["settings"]["syncAlerts"] = json!(true),
                2 => {
                    body.as_object_mut().unwrap().remove("settings");
                }
                3 => {
                    body["settings"]
                        .as_object_mut()
                        .unwrap()
                        .remove("syncAlerts");
                }
                4 => body["settings"]["syncAlerts"] = json!("false"),
                _ => {}
            }
            let id = body["id"].as_str().unwrap();
            let mut second = body.clone();
            second["id"] = json!("second-case");
            let ids = vec![id.to_string(), "second-case".into()];
            let server = case_server(&body, &second).await;
            let old_server = case_server(&body, &second).await;
            let t = transport(&server.uri());
            let old_t = transport(&old_server.uri());
            if !comment {
                let (plan, seen) = cases_ops::plan_status_observed(&t, &ids, CaseStatus::Closed)
                    .await
                    .unwrap();
                assert_eq!(
                    plan,
                    cases_ops::plan_status(&old_t, &ids, CaseStatus::Closed)
                        .await
                        .unwrap()
                );
                let sync_alerts = match variant {
                    0 => json!(false),
                    1 => json!(true),
                    _ => Value::Null,
                };
                assert_eq!(
                    seen.0[0].state,
                    Some(json!({
                        "status": body["status"],
                        "title": body["title"],
                        "version": body["version"],
                        "sync_alerts": sync_alerts
                    }))
                );
            } else {
                let (plan, seen) = cases_ops::plan_comment_observed(&t, id, "hello")
                    .await
                    .unwrap();
                assert_eq!(
                    plan,
                    cases_ops::plan_comment(&old_t, id, "hello").await.unwrap()
                );
                assert_eq!(
                    seen.0[0].state,
                    Some(json!({ "status": body["status"], "title": body["title"] }))
                );
            }
            let observed = requests(&server).await;
            assert_eq!(observed.len(), if comment { 1 } else { 2 });
            assert_eq!(observed, requests(&old_server).await);
        }
    }
}

#[tokio::test]
async fn case_status_state_reads_sync_alerts_strictly() {
    check_case_planner(false).await;
}

#[tokio::test]
async fn plan_comment_observed_matches_plan_comment_and_sends_the_same_requests() {
    check_case_planner(true).await;
}

async fn check_alert_planner(tags: bool) {
    for set in ["ech-9.5.2", "serverless-9.7.0", "traditional-9.5.1"] {
        for nested in [false, true] {
            let mut body = fixture(set, "signals_search");
            let source = body["hits"]["hits"][0]["_source"].clone();
            let status = source["kibana.alert.workflow_status"]
                .as_str()
                .unwrap()
                .to_string();
            let name = source["kibana.alert.rule.name"]
                .as_str()
                .unwrap()
                .to_string();
            if nested {
                body["hits"]["hits"][0]["_source"] = json!({
                    "kibana": {
                        "alert": {
                            "workflow_status": status,
                            "rule": { "name": name }
                        }
                    }
                });
            }
            let id = body["hits"]["hits"][0]["_id"].as_str().unwrap().to_string();
            let mut second_hit = body["hits"]["hits"][0].clone();
            second_hit["_id"] = json!("second-alert");
            body["hits"]["hits"]
                .as_array_mut()
                .unwrap()
                .push(second_hit);
            let ids = vec![id.clone(), "second-alert".into()];
            let server = MockServer::start().await;
            let expected = json!({
                "query": { "ids": { "values": [id, "second-alert"] } },
                "size": 2,
                "_source": ["kibana.alert.rule.name", "kibana.alert.workflow_status"]
            });
            let old_server = MockServer::start().await;
            for target in [&server, &old_server] {
                Mock::given(method("POST"))
                    .and(path("/api/detection_engine/signals/search"))
                    .and(body_json(expected.clone()))
                    .respond_with(ResponseTemplate::new(200).set_body_json(&body))
                    .mount(target)
                    .await;
            }
            let t = transport(&server.uri());
            let old_t = transport(&old_server.uri());
            if !tags {
                let (plan, seen) =
                    alerts_ops::plan_status_by_ids_observed(&t, &ids, AlertStatus::Closed, None)
                        .await
                        .unwrap();
                assert_eq!(
                    plan,
                    alerts_ops::plan_status_by_ids(&old_t, &ids, AlertStatus::Closed, None)
                        .await
                        .unwrap()
                );
                assert_eq!(seen.0[0].state, Some(json!({ "workflow_status": status })));
            } else {
                let (plan, seen) =
                    alerts_ops::plan_tags_observed(&t, &ids, vec!["tag".into()], vec![])
                        .await
                        .unwrap();
                assert_eq!(
                    plan,
                    alerts_ops::plan_tags(&old_t, &ids, vec!["tag".into()], vec![])
                        .await
                        .unwrap()
                );
                assert_eq!(seen.0[0].state, Some(json!({})));
            }
            let observed = requests(&server).await;
            assert_eq!(observed.len(), 1);
            assert_eq!(observed, requests(&old_server).await);
        }
    }
}

#[tokio::test]
async fn plan_status_by_ids_observed_matches_plan_and_sends_the_same_requests() {
    check_alert_planner(false).await;
}

#[tokio::test]
async fn plan_tags_observed_matches_plan_and_sends_the_same_requests() {
    check_alert_planner(true).await;
}
