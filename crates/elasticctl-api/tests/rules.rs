use elasticctl_api::model::Rule;
use elasticctl_api::rules::{self, BulkAction, RuleFilter};
use elasticctl_core::{Profile, Transport};
use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn profile_for(server: &MockServer) -> Profile {
    Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    }
}

fn transport(server: &MockServer) -> Transport {
    Transport::new(&profile_for(server)).unwrap()
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

#[test]
fn a_name_filter_produces_the_recorded_kql_path() {
    let f = RuleFilter {
        name: Some("Suspicious PowerShell".into()),
        ..Default::default()
    };
    assert_eq!(
        f.to_kql().unwrap(),
        "alert.attributes.name: \"Suspicious PowerShell\""
    );
}

#[test]
fn a_name_filter_escapes_a_quote() {
    let f = RuleFilter {
        name: Some("a\"b".into()),
        ..Default::default()
    };
    let kql = f.to_kql().unwrap();
    let mut expected = String::from("alert.attributes.name: \"a");
    expected.push('\\');
    expected.push('"');
    expected.push_str("b\"");
    assert_eq!(kql, expected);
}

#[test]
fn a_name_filter_combines_with_the_others() {
    let f = RuleFilter {
        name: Some("X".into()),
        enabled: Some(true),
        ..Default::default()
    };
    let kql = f.to_kql().unwrap();
    assert!(kql.contains("alert.attributes.name: \"X\""), "{kql}");
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
        .expect(1)
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

/// A rule as it comes back from the API: carries the volatile fields a
/// create/update body must never forward.
fn rule_with_volatile_fields(id: &str) -> Rule {
    Rule::from_value(json!({
        "rule_id": id, "name": format!("rule {id}"), "type": "query", "risk_score": 21,
        "id": "server-side-id", "created_at": "2026-01-01T00:00:00.000Z",
        "created_by": "someone", "updated_at": "2026-01-01T00:00:00.000Z",
        "updated_by": "someone", "revision": 3, "version": 4
    }))
    .unwrap()
}

#[tokio::test]
async fn create_posts_to_the_rules_endpoint_and_returns_the_parsed_rule() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_json("a")))
        .mount(&server)
        .await;

    let rule = Rule::from_value(rule_json("a")).unwrap();
    let r = rules::create(&transport(&server), &rule).await.unwrap();
    assert_eq!(r.rule_id().unwrap(), "a");
}

#[tokio::test]
async fn create_strips_volatile_fields_from_the_request_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_json("a")))
        .mount(&server)
        .await;

    rules::create(&transport(&server), &rule_with_volatile_fields("a"))
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = requests[0].body_json().unwrap();
    assert!(body.get("id").is_none(), "volatile id must not be sent");
    assert!(body.get("created_at").is_none());
    assert!(body.get("updated_by").is_none());
    assert_eq!(body["rule_id"], "a", "the stable identity must survive");
}

#[tokio::test]
async fn update_puts_to_the_rules_endpoint_and_returns_the_parsed_rule() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_json("a")))
        .mount(&server)
        .await;

    let rule = Rule::from_value(rule_json("a")).unwrap();
    let r = rules::update(&transport(&server), &rule).await.unwrap();
    assert_eq!(r.rule_id().unwrap(), "a");
}

#[tokio::test]
async fn update_strips_volatile_fields_from_the_request_body() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_json("a")))
        .mount(&server)
        .await;

    rules::update(&transport(&server), &rule_with_volatile_fields("a"))
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = requests[0].body_json().unwrap();
    assert!(body.get("id").is_none(), "volatile id must not be sent");
    assert!(body.get("created_at").is_none());
    assert!(body.get("updated_by").is_none());
    assert_eq!(body["rule_id"], "a", "the stable identity must survive");
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

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = requests[0].body_json().unwrap();
    let query = body["query"].as_str().unwrap();
    assert!(
        query.contains("alert.attributes.params.ruleId"),
        "must target the stable rule_id through the query form: {query}"
    );
    assert!(
        query.contains("\"a\"") && query.contains("\"b\""),
        "both ids must appear in the query: {query}"
    );
    assert!(
        body.get("ids").is_none(),
        "must not target the volatile server-side ids"
    );
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

    let (rules, summary) = rules::export(&transport(&server), None).await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(summary.unwrap().exported_rules_count, 1);
}

#[tokio::test]
async fn a_scoped_export_sends_the_objects_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_export"))
        .and(body_partial_json(
            json!({"objects": [{"rule_id": "a"}, {"rule_id": "b"}]}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(concat!(
            r#"{"rule_id":"a","name":"A"}"#,
            "\n",
            r#"{"exported_count":1,"exported_rules_count":1,"missing_rules":[{"rule_id":"b"}],"missing_rules_count":1}"#,
            "\n"
        )))
        .mount(&server)
        .await;

    let ids = vec!["a".to_string(), "b".to_string()];
    let (rules, summary) = rules::export(&transport(&server), Some(&ids))
        .await
        .unwrap();
    assert_eq!(rules.len(), 1);
    let summary = summary.unwrap();
    assert_eq!(summary.missing_rules_count, 1);
    assert_eq!(summary.missing_rules[0]["rule_id"], "b");
}

/// The unscoped call must stay byte-identical: no body at all, exactly as
/// before, or every existing export changes shape.
#[tokio::test]
async fn an_unscoped_export_sends_no_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_export"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "{\"exported_count\":0,\"exported_rules_count\":0,\"missing_rules_count\":0}\n",
        ))
        .mount(&server)
        .await;

    rules::export(&transport(&server), None).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].body.is_empty(),
        "an unscoped export must post no body: {:?}",
        String::from_utf8_lossy(&requests[0].body)
    );
}

#[tokio::test]
async fn existing_rule_ids_reports_only_the_ids_the_server_knows() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 3, "total": 1, "data": [rule_json("b")]
        })))
        .mount(&server)
        .await;

    let ids = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let found = rules::existing_rule_ids(&transport(&server), &ids)
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert!(found.contains("b"));
}

#[tokio::test]
async fn existing_rule_ids_sends_no_request_for_an_empty_list() {
    let server = MockServer::start().await;
    assert!(
        rules::existing_rule_ids(&transport(&server), &[])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "an empty list must never become an unscoped find"
    );
}

#[tokio::test]
async fn import_reflects_overwrite_true_in_the_query_string() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .and(query_param("overwrite", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true, "success_count": 1, "errors": []
        })))
        .mount(&server)
        .await;

    let ndjson = format!("{}\n", serde_json::to_string(&rule_json("a")).unwrap());
    let result = rules::import(&transport(&server), &ndjson, true)
        .await
        .unwrap();
    assert_eq!(result["success_count"], 1);
}

#[tokio::test]
async fn import_reflects_overwrite_false_in_the_query_string() {
    // Overwrite silently replaces existing detections; the two settings must
    // never be conflated.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .and(query_param("overwrite", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true, "success_count": 1, "errors": []
        })))
        .mount(&server)
        .await;

    let ndjson = format!("{}\n", serde_json::to_string(&rule_json("a")).unwrap());
    let result = rules::import(&transport(&server), &ndjson, false)
        .await
        .unwrap();
    assert_eq!(result["success_count"], 1);
}

#[tokio::test]
async fn import_sends_the_ndjson_as_a_multipart_upload() {
    // Kibana's import takes a multipart file upload, not a JSON body — easy
    // to get wrong in a way no other test would catch.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true, "success_count": 1, "errors": []
        })))
        .mount(&server)
        .await;

    let ndjson = format!("{}\n", serde_json::to_string(&rule_json("abc")).unwrap());
    rules::import(&transport(&server), &ndjson, true)
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let content_type = requests[0]
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        content_type.starts_with("multipart/form-data"),
        "{content_type}"
    );
    let body = String::from_utf8_lossy(&requests[0].body);
    assert!(body.contains("\"rule_id\":\"abc\""), "{body}");
}

#[tokio::test]
async fn a_failing_import_is_a_classified_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "message": "invalid ndjson"
        })))
        .mount(&server)
        .await;

    let err = rules::import(&transport(&server), "not ndjson", true)
        .await
        .unwrap_err();
    assert_eq!(err.kind, elasticctl_core::ErrorKind::Http);
    assert!(err.message.contains("invalid ndjson"), "{}", err.message);
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

/// The recorded exchange, replayed. A hand-written mock would encode what we
/// assumed the preview alerts index returns; this encodes what it sent.
#[tokio::test]
async fn preview_hits_parses_the_recorded_response() {
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/serverless-9.6.0/rules_preview_hits.json"
        ))
        .expect("rules_preview_hits fixture"),
    )
    .expect("fixture is JSON");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(
            r"^/\.preview\.alerts-security\.alerts-default/_search$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture["response"].clone()))
        .mount(&server)
        .await;

    let mut profile = profile_for(&server);
    profile.es_url = Some(server.uri());
    let t = Transport::new(&profile).unwrap();

    let hits = rules::preview_hits(&t, "default", "pv-1", 3).await.unwrap();
    assert!(hits.total >= 1, "the recorded response carries hits");
    assert!(!hits.sample.is_empty(), "a sample must carry the documents");
    assert!(
        hits.sample[0].get("_source").is_some(),
        "a sample entry is the alert document, not a summary of it: {:?}",
        hits.sample[0]
    );
}

#[tokio::test]
async fn preview_hits_queries_the_space_scoped_preview_index_by_preview_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/.preview.alerts-security.alerts-soc/_search"))
        .and(body_partial_json(json!({
            "size": 0,
            "track_total_hits": true,
            "query": {"term": {"kibana.alert.rule.uuid": "pv-9"}}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 302, "relation": "eq"}, "hits": []}
        })))
        .mount(&server)
        .await;

    let mut profile = profile_for(&server);
    profile.es_url = Some(server.uri());
    let t = Transport::new(&profile).unwrap();

    let hits = rules::preview_hits(&t, "soc", "pv-9", 0).await.unwrap();
    assert_eq!(hits.total, 302);
    assert!(hits.sample.is_empty(), "size 0 asks for no documents");
}

#[tokio::test]
async fn preview_hits_treats_an_empty_space_as_default() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/.preview.alerts-security.alerts-default/_search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 0}, "hits": []}
        })))
        .mount(&server)
        .await;
    let mut profile = profile_for(&server);
    profile.es_url = Some(server.uri());
    let t = Transport::new(&profile).unwrap();

    assert_eq!(
        rules::preview_hits(&t, "", "pv-1", 0).await.unwrap().total,
        0
    );
}
