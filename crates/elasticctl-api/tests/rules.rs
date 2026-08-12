use elasticctl_api::rules::{self, BulkAction, RuleFilter};
use elasticctl_core::{Profile, Transport};
use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn transport(server: &MockServer) -> Transport {
    Transport::new(&Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .unwrap()
}

fn rule_json(id: &str) -> serde_json::Value {
    json!({"rule_id": id, "name": format!("rule {id}"), "type": "query", "risk_score": 21})
}

#[test]
fn an_empty_filter_produces_no_kql() {
    assert_eq!(RuleFilter::default().to_kql(), None);
}

#[test]
fn filters_combine_with_and() {
    let f = RuleFilter {
        enabled: Some(true),
        severity: Some("high".into()),
        ..Default::default()
    };
    let kql = f.to_kql().unwrap();
    assert!(kql.contains("alert.attributes.enabled: true"), "{kql}");
    assert!(
        kql.contains("alert.attributes.params.severity: \"high\""),
        "{kql}"
    );
    assert!(kql.contains(" AND "), "{kql}");
}

#[tokio::test]
async fn find_page_returns_rules_and_the_total() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 20, "total": 2, "data": [rule_json("a"), rule_json("b")]
        })))
        .mount(&server)
        .await;

    let (rules, total) = rules::find_page(&transport(&server), &RuleFilter::default(), 1, 20)
        .await
        .unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(total, 2);
}

#[tokio::test]
async fn find_all_pages_until_the_total_is_reached() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 2, "total": 3, "data": [rule_json("a"), rule_json("b")]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 2, "perPage": 2, "total": 3, "data": [rule_json("c")]
        })))
        .mount(&server)
        .await;

    let all = rules::find_all(&transport(&server), &RuleFilter::default())
        .await
        .unwrap();
    assert_eq!(all.len(), 3, "every page must be collected");
}

#[tokio::test]
async fn find_all_stops_on_an_empty_page_rather_than_looping() {
    // Guards against an infinite loop if `total` is larger than what is served.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 20, "total": 999, "data": []
        })))
        .mount(&server)
        .await;

    assert!(
        rules::find_all(&transport(&server), &RuleFilter::default())
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn get_queries_by_rule_id_not_by_server_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_json("abc")))
        .mount(&server)
        .await;

    let r = rules::get(&transport(&server), "abc").await.unwrap();
    assert_eq!(r.rule_id().unwrap(), "abc");
}

#[tokio::test]
async fn patch_targets_the_stable_rule_id() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/detection_engine/rules"))
        .and(body_partial_json(
            json!({"rule_id": "abc", "enabled": true}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rule_id": "abc", "name": "r", "enabled": true
        })))
        .mount(&server)
        .await;

    let r = rules::patch(&transport(&server), "abc", &json!({"enabled": true}))
        .await
        .unwrap();
    assert!(r.enabled());
}

#[tokio::test]
async fn bulk_targets_rule_ids_through_the_query_form() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_bulk_action"))
        .and(body_partial_json(json!({"action": "disable"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true, "rules_count": 2,
            "attributes": {"summary": {"succeeded": 2, "failed": 0, "skipped": 0, "total": 2}}
        })))
        .mount(&server)
        .await;

    let ids = vec!["a".to_string(), "b".to_string()];
    let out = rules::bulk_by_rule_ids(&transport(&server), BulkAction::Disable, &ids, false)
        .await
        .unwrap();
    assert_eq!(out.succeeded, 2);
    assert_eq!(out.total, 2);
}

#[tokio::test]
async fn bulk_dry_run_sets_the_query_parameter() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_bulk_action"))
        .and(query_param("dry_run", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "attributes": {"summary": {"succeeded": 1, "failed": 0, "skipped": 0, "total": 1}}
        })))
        .mount(&server)
        .await;

    let ids = vec!["a".to_string()];
    let out = rules::bulk_by_rule_ids(&transport(&server), BulkAction::Enable, &ids, true)
        .await
        .unwrap();
    assert_eq!(out.succeeded, 1);
}

#[tokio::test]
async fn bulk_with_no_targets_makes_no_request() {
    // An empty selection must not become an unscoped query that hits every rule.
    let server = MockServer::start().await;
    let out = rules::bulk_by_rule_ids(&transport(&server), BulkAction::Delete, &[], false)
        .await
        .unwrap();
    assert_eq!(out.total, 0);
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "no request may be sent"
    );
}

#[tokio::test]
async fn export_separates_rules_from_the_trailer() {
    let server = MockServer::start().await;
    let body = format!(
        "{}\n{}\n",
        serde_json::to_string(&rule_json("a")).unwrap(),
        r#"{"exported_count":1,"exported_rules_count":1,"missing_rules_count":0}"#
    );
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_export"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let (rules, summary) = rules::export(&transport(&server)).await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(summary.unwrap().exported_rules_count, 1);
}

#[tokio::test]
async fn a_404_from_get_is_a_not_found_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "not found"})))
        .mount(&server)
        .await;

    let err = rules::get(&transport(&server), "missing")
        .await
        .unwrap_err();
    assert_eq!(err.kind, elasticctl_core::ErrorKind::NotFound);
}
