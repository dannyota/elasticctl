use elasticctl_api::alerts::{self, AlertStatus, Conflicts};
use elasticctl_api::profiles::{self, UserProfile};
use elasticctl_core::{Flavor, Profile, Transport};
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

fn profile(uid: &str, username: &str, realm: Option<&str>) -> UserProfile {
    UserProfile {
        uid: uid.into(),
        username: username.into(),
        realm: realm.map(str::to_owned),
    }
}

#[test]
fn decodes_the_public_suggest_shape() {
    let body = json!({
        "total": 1, "took": 3,
        "profiles": [
            {"uid": "u_abc_0", "enabled": true,
             "user": {"username": "danny", "realm_name": "cloud-saml", "roles": ["superuser"]},
             "data": {}, "labels": {}}
        ]
    });
    let profiles = profiles::decode_public(&body).expect("decode");
    assert_eq!(
        profiles,
        vec![profile("u_abc_0", "danny", Some("cloud-saml"))]
    );
}

#[test]
fn decodes_the_internal_find_shape() {
    let body = json!([
        {"uid": "u_abc_0", "enabled": true, "data": {},
         "user": {"username": "danny", "full_name": "REDACTED"}}
    ]);
    let profiles = profiles::decode_internal(&body).expect("decode");
    assert_eq!(profiles, vec![profile("u_abc_0", "danny", None)]);
}

#[test]
fn pick_exact_matches_usernames_exactly() {
    let list = [profile("u_1", "danny", Some("native"))];
    assert_eq!(profiles::pick_exact(&list, "danny").unwrap(), "u_1");

    let err = profiles::pick_exact(&list, "dan").expect_err("no prefix matching");
    assert_eq!(err.kind, elasticctl_core::ErrorKind::NotFound);
    assert!(
        err.message.contains("logged into Kibana"),
        "{}",
        err.message
    );

    let dup = [
        profile("u_1", "danny", Some("native")),
        profile("u_2", "danny", Some("saml")),
    ];
    let err = profiles::pick_exact(&dup, "danny").expect_err("ambiguous");
    assert_eq!(err.kind, elasticctl_core::ErrorKind::Conflict);
    assert!(
        err.message.contains("native") && err.message.contains("saml"),
        "{}",
        err.message
    );
}

#[tokio::test]
async fn suggest_routes_by_flavor() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/_security/profile/_suggest"))
        .and(body_json(json!({"name": "danny", "size": 10})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1, "took": 1,
            "profiles": [{"uid": "u_pub", "user": {"username": "danny", "realm_name": "native"}}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/internal/detection_engine/users/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"uid": "u_int", "user": {"username": "danny"}}
        ])))
        .mount(&server)
        .await;

    let t = test_transport(&server.uri());
    let public = profiles::suggest(&t, Flavor::ElasticCloudHosted, "danny")
        .await
        .unwrap();
    assert_eq!(public[0].uid, "u_pub");
    let internal = profiles::suggest(&t, Flavor::Serverless, "danny")
        .await
        .unwrap();
    assert_eq!(internal[0].uid, "u_int");
}

#[tokio::test]
async fn an_unavailable_suggest_route_downgrades_to_unsupported() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/_security/profile/_suggest"))
        .respond_with(ResponseTemplate::new(410).set_body_json(json!({
            "error": {"type": "api_not_available_exception",
                      "reason": "Request for uri [...] is not available when running in serverless mode"},
            "status": 410
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let err = profiles::suggest(&t, Flavor::SelfManaged, "danny")
        .await
        .expect_err("410");
    assert_eq!(err.kind, elasticctl_core::ErrorKind::Unsupported);
    assert!(
        err.message.contains("uid:"),
        "the remedy names the bypass: {}",
        err.message
    );
}

#[tokio::test]
async fn resolve_assignee_bypasses_with_a_uid_prefix() {
    // No mocks: the uid: path must not touch the network or the flavor probe.
    let t = test_transport("http://127.0.0.1:1");
    assert_eq!(
        profiles::resolve_assignee(&t, "uid:u_raw").await.unwrap(),
        "u_raw"
    );
    assert!(
        profiles::resolve_assignee(&t, "uid:").await.is_err(),
        "an empty uid is refused"
    );
}
