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
        let stack = MockStack::with_rules(vec![rule.clone()]).await;
        let (plan, seen) = rules_ops::plan_set_enabled_observed(
            stack.transport(),
            &[id.clone(), id.clone()],
            false,
        )
        .await
        .unwrap();
        let old = rules_ops::plan_set_enabled(stack.transport(), &[id.clone(), id], false)
            .await
            .unwrap();
        assert_eq!(plan, old);
        let canonical =
            normalize::canonical(&serde_json::from_value::<Rule>(rule).unwrap()).into_value();
        assert_eq!(seen.0.len(), 2);
        assert_eq!(seen.0[0].state, Some(canonical));
        let req = stack.requests().await;
        let split = req.len() / 2;
        for (a, b) in req[..split].iter().zip(&req[split..]) {
            assert_eq!(
                (&a.method, &a.path, &a.query, &a.body),
                (&b.method, &b.path, &b.query, &b.body)
            );
        }
    }
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
            let server = MockServer::start().await;
            let id = body["id"].as_str().unwrap();
            Mock::given(method("GET"))
                .and(path(format!("/api/cases/{id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(&body))
                .mount(&server)
                .await;
            let t = transport(&server.uri());
            if !comment {
                let (plan, seen) =
                    cases_ops::plan_status_observed(&t, &[id.into()], CaseStatus::Closed)
                        .await
                        .unwrap();
                assert_eq!(
                    plan,
                    cases_ops::plan_status(&t, &[id.into()], CaseStatus::Closed)
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
                    cases_ops::plan_comment(&t, id, "hello").await.unwrap()
                );
                assert_eq!(
                    seen.0[0].state,
                    Some(json!({ "status": body["status"], "title": body["title"] }))
                );
            }
            let req = server.received_requests().await.unwrap();
            assert!(req.iter().all(|r| r.method.as_str() == "GET"
                && r.url.path() == format!("/api/cases/{id}")
                && r.body.is_empty()));
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
            let ids = vec![id.clone(), id.clone()];
            let server = MockServer::start().await;
            let expected = json!({
                "query": { "ids": { "values": [id] } },
                "size": 1,
                "_source": ["kibana.alert.rule.name", "kibana.alert.workflow_status"]
            });
            Mock::given(method("POST"))
                .and(path("/api/detection_engine/signals/search"))
                .and(body_json(expected.clone()))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
            let t = transport(&server.uri());
            if !tags {
                let (plan, seen) =
                    alerts_ops::plan_status_by_ids_observed(&t, &ids, AlertStatus::Closed, None)
                        .await
                        .unwrap();
                assert_eq!(
                    plan,
                    alerts_ops::plan_status_by_ids(&t, &ids, AlertStatus::Closed, None)
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
                    alerts_ops::plan_tags(&t, &ids, vec!["tag".into()], vec![])
                        .await
                        .unwrap()
                );
                assert_eq!(seen.0[0].state, Some(json!({})));
            }
            let req = server.received_requests().await.unwrap();
            assert_eq!(req.len(), 2);
            assert!(req.iter().all(|r| r.method.as_str() == "POST"
                && r.url.path() == "/api/detection_engine/signals/search"
                && r.body_json::<Value>().unwrap() == expected));
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
