use elasticctl_api::alerts::{self, AlertStatus, Conflicts};
use elasticctl_core::{Profile, Transport};
use serde_json::json;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_transport(uri: &str) -> Transport {
    Transport::new(&Profile {
        kibana_url: uri.to_string(),
        es_url: Some(uri.to_string()),
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .expect("transport")
}

#[test]
fn decodes_an_alert_page_with_ids() {
    let body = json!({
        "took": 3,
        "hits": {
            "total": {"value": 2, "relation": "eq"},
            "hits": [
                {"_id": "a1", "_index": ".alerts-security.alerts-default",
                 "_source": {"kibana.alert.rule.name": "Alpha", "kibana.alert.workflow_status": "open"},
                 "sort": [1725000000000i64, "a1"]},
                {"_id": "a2", "_source": {"kibana.alert.rule.name": "Beta"}}
            ]
        }
    });
    let page = alerts::decode_page(&body).expect("decode");
    assert_eq!(page.total, Some(2));
    assert_eq!(page.hits.len(), 2);
    assert_eq!(page.hits[0].id, "a1");
    assert_eq!(
        page.hits[0].source["kibana.alert.rule.name"],
        json!("Alpha")
    );
    assert_eq!(page.hits[0].sort.as_ref().unwrap().len(), 2);
    assert!(page.hits[1].sort.is_none());
}

#[test]
fn rejects_a_hit_without_an_id() {
    let body = json!({"hits": {"hits": [{"_source": {"x": 1}}]}});
    let err = alerts::decode_page(&body).expect_err("must fail");
    assert!(err.message.contains("_id"), "{}", err.message);
}

#[test]
fn decodes_an_update_by_query_outcome() {
    let body = json!({
        "took": 5, "timed_out": false, "total": 3, "updated": 2, "deleted": 0,
        "batches": 1, "version_conflicts": 1, "noops": 0, "retries": {"bulk": 0, "search": 0},
        "throttled_millis": 0, "requests_per_second": -1.0, "throttled_until_millis": 0,
        "failures": []
    });
    let o = alerts::decode_outcome(&body).expect("decode");
    assert_eq!(
        (o.total, o.updated, o.version_conflicts, o.noops),
        (3, 2, 1, 0)
    );
    assert!(o.failures.is_empty());
}

#[test]
fn rejects_an_outcome_missing_a_counter() {
    let body = json!({"took": 5, "updated": 2, "version_conflicts": 0, "noops": 0, "failures": []});
    assert!(
        alerts::decode_outcome(&body).is_err(),
        "missing `total` must fail closed"
    );
}

#[test]
fn parses_the_status_vocabulary() {
    assert_eq!(
        AlertStatus::parse("acknowledged").unwrap().as_str(),
        "acknowledged"
    );
    assert!(
        AlertStatus::parse("in-progress").is_err(),
        "the pre-8.0 name is never accepted"
    );
    assert_eq!(AlertStatus::Closed.verb(), "Close");
    assert_eq!(Conflicts::parse("proceed").unwrap().as_str(), "proceed");
}

#[tokio::test]
async fn status_by_ids_posts_signal_ids() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/status"))
        .and(body_json(
            json!({"signal_ids": ["a1"], "status": "closed", "reason": "false_positive"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1, "updated": 1, "version_conflicts": 0, "noops": 0, "failures": []
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let o = alerts::status_by_ids(
        &t,
        &["a1".into()],
        AlertStatus::Closed,
        Some("false_positive"),
    )
    .await
    .expect("status");
    assert_eq!(o.updated, 1);
}

#[tokio::test]
async fn status_by_query_posts_query_and_conflicts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/status"))
        .and(body_json(json!({
            "query": {"term": {"kibana.alert.rule.rule_id": "r1"}},
            "status": "open",
            "conflicts": "proceed"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 4, "updated": 4, "version_conflicts": 0, "noops": 0, "failures": []
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let o = alerts::status_by_query(
        &t,
        &json!({"term": {"kibana.alert.rule.rule_id": "r1"}}),
        AlertStatus::Open,
        Conflicts::Proceed,
        None,
    )
    .await
    .expect("status");
    assert_eq!(o.total, 4);
}

#[tokio::test]
async fn search_all_pages_with_search_after() {
    let server = MockServer::start().await;
    let sort = json!([{"@timestamp": {"order": "desc"}}, {"kibana.alert.uuid": {"order": "asc"}}]);
    let page1 = json!({"hits": {"total": {"value": 3, "relation": "eq"}, "hits": [
        {"_id": "a1", "_source": {"seq": 1}, "sort": [3, "a1"]},
        {"_id": "a2", "_source": {"seq": 2}, "sort": [2, "a2"]}
    ]}});
    let page2 = json!({"hits": {"total": {"value": 3, "relation": "eq"}, "hits": [
        {"_id": "a3", "_source": {"seq": 3}, "sort": [1, "a3"]}
    ]}});
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .and(body_json(json!({
            "query": {"match_all": {}}, "sort": sort, "size": 2, "search_after": [2, "a2"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(page2))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page1))
        .mount(&server)
        .await;

    let t = test_transport(&server.uri());
    let hits = alerts::search_all_with_page_size(&t, &json!({"match_all": {}}), &sort, None, 2)
        .await
        .expect("stream");
    assert_eq!(hits.len(), 3);
    assert_eq!(hits[2].id, "a3");
}

#[tokio::test]
async fn set_tags_and_assignees_post_their_bodies() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/tags"))
        .and(body_json(
            json!({"ids": ["a1"], "tags": {"tags_to_add": ["t1"], "tags_to_remove": []}}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1, "updated": 1, "version_conflicts": 0, "noops": 0, "failures": []
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/assignees"))
        .and(body_json(
            json!({"ids": ["a1"], "assignees": {"add": ["u_1"], "remove": []}}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1, "updated": 1, "version_conflicts": 0, "noops": 0, "failures": []
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    assert_eq!(
        alerts::set_tags(&t, &["a1".into()], &["t1".into()], &[])
            .await
            .unwrap()
            .updated,
        1
    );
    assert_eq!(
        alerts::set_assignees(&t, &["a1".into()], &["u_1".into()], &[])
            .await
            .unwrap()
            .updated,
        1
    );
}
