use elasticctl_api::alerts::{self, AlertStatus, Conflicts};
use elasticctl_api::alerts_ops::{self, AlertFilter};
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
    assert_eq!(
        page.hits[0].index.as_deref(),
        Some(".alerts-security.alerts-default")
    );
    assert!(page.hits[1].index.is_none());
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

/// Finding 4: the internal route family's spec-measured unavailability shape
/// is a 400 whose message says "exists but is not available" (the
/// `x-elastic-internal-origin` refusal), not a 404/410/Permission.
/// `downgrade_unavailable` must classify it the same way.
/// Finding 6: with no `es_url` configured, `post_absolute_es` silently falls
/// back to the Kibana host, so a public-route 404 gets downgraded to
/// "profile suggestion is unavailable on <flavor>" — blaming the deployment
/// for what is actually a profile misconfiguration. The message must name
/// the missing `es_url` when that is the likely cause.
#[tokio::test]
async fn a_missing_es_url_is_named_in_the_suggest_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/_security/profile/_suggest"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "statusCode": 404, "error": "Not Found", "message": "Not Found"
        })))
        .mount(&server)
        .await;
    let t = Transport::new(&Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .expect("transport");
    let err = profiles::suggest(&t, Flavor::ElasticCloudHosted, "danny")
        .await
        .expect_err("404");
    assert_eq!(err.kind, elasticctl_core::ErrorKind::Unsupported);
    assert!(
        err.message.contains("es_url"),
        "the missing es_url must be named as the likely cause: {}",
        err.message
    );
    assert!(
        err.message.contains("uid:"),
        "the remedy still names the bypass: {}",
        err.message
    );
}

#[tokio::test]
async fn an_internal_route_400_is_not_available_downgrades_to_unsupported() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/internal/detection_engine/users/_find"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "statusCode": 400,
            "error": "Bad Request",
            "message": "uri [/internal/detection_engine/users/_find] exists but is not available with the current configuration"
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let err = profiles::suggest(&t, Flavor::Serverless, "danny")
        .await
        .expect_err("400");
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

#[test]
fn since_accepts_durations_and_passes_timestamps_through() {
    assert_eq!(
        alerts_ops::since_clause("24h"),
        json!({"range": {"@timestamp": {"gte": "now-24h"}}})
    );
    assert_eq!(
        alerts_ops::since_clause("2026-08-30T00:00:00Z"),
        json!({"range": {"@timestamp": {"gte": "2026-08-30T00:00:00Z"}}})
    );
}

#[tokio::test]
async fn build_query_composes_filters_and_resolves_the_rule() {
    let server = MockServer::start().await;
    // `selection::to_rule_id` tries the rule GET first; answer it directly so
    // no name-search fallback runs.
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(wiremock::matchers::query_param("rule_id", "r-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rule_id": "r-1", "name": "Alpha", "enabled": true
        })))
        .mount(&server)
        .await;

    let t = test_transport(&server.uri());
    let f = AlertFilter {
        status: Some(AlertStatus::Open),
        severity: Some("high".into()),
        rule: Some("r-1".into()),
        tag: Some("triaged".into()),
        // `uid:` bypasses resolution, so this needs no extra mock or flavor
        // probe.
        assignee: Some("uid:u_1".into()),
        since: Some("7d".into()),
        search: Some("powershell".into()),
    };
    let q = alerts_ops::build_query(&t, &f).await.expect("query");
    let filters = q["bool"]["filter"].as_array().expect("filter array");
    assert_eq!(filters.len(), 7);
    assert!(filters.contains(&json!({"term": {"kibana.alert.workflow_status": "open"}})));
    assert!(filters.contains(&json!({"term": {"kibana.alert.severity": "high"}})));
    assert!(filters.contains(&json!({"term": {"kibana.alert.rule.rule_id": "r-1"}})));
    assert!(filters.contains(&json!({"term": {"kibana.alert.workflow_tags": "triaged"}})));
    assert!(filters.contains(&json!({"term": {"kibana.alert.workflow_assignee_ids": "u_1"}})));
    assert!(filters.contains(&json!({"range": {"@timestamp": {"gte": "now-7d"}}})));
    let search_clause = filters
        .iter()
        .find(|f| f.get("bool").is_some())
        .expect("search clause");
    let shoulds = search_clause["bool"]["should"].as_array().unwrap();
    assert_eq!(shoulds.len(), 2);
    assert_eq!(
        shoulds[0]["wildcard"]["kibana.alert.rule.name"]["value"],
        json!("*powershell*")
    );
}

/// Finding 3: `--search` text is interpolated into a `wildcard` value
/// unescaped, so `--search '*'` matches every alert and text carrying `\`,
/// `*`, or `?` injects its own wildcards. Mirror the rules-side
/// `kql_escape_wildcard` behavior: escape `\` first, then `*` and `?`.
#[tokio::test]
async fn build_query_escapes_wildcard_metacharacters_in_search_text() {
    let t = test_transport("http://127.0.0.1:1");
    let f = AlertFilter {
        search: Some("a*b".into()),
        ..Default::default()
    };
    let q = alerts_ops::build_query(&t, &f).await.expect("query");
    let filters = q["bool"]["filter"].as_array().expect("filter array");
    let search_clause = filters
        .iter()
        .find(|f| f.get("bool").is_some())
        .expect("search clause");
    let shoulds = search_clause["bool"]["should"].as_array().unwrap();
    assert_eq!(
        shoulds[0]["wildcard"]["kibana.alert.rule.name"]["value"],
        json!("*a\\*b*")
    );
    assert_eq!(
        shoulds[1]["wildcard"]["kibana.alert.reason"]["value"],
        json!("*a\\*b*")
    );
}

#[tokio::test]
async fn an_empty_filter_is_match_all() {
    let t = test_transport("http://127.0.0.1:1");
    let q = alerts_ops::build_query(&t, &AlertFilter::default())
        .await
        .expect("query");
    assert_eq!(q, json!({"match_all": {}}));
}

#[tokio::test]
async fn list_peeks_and_reports_truncation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 5, "relation": "eq"}, "hits": [
                {"_id": "a1", "_source": {"n": 1}},
                {"_id": "a2", "_source": {"n": 2}}
            ]}
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let out = alerts_ops::list(&t, &AlertFilter::default(), 1)
        .await
        .expect("list");
    assert!(out.truncated, "two hits against limit 1 is a truncation");
    assert_eq!(out.hits.len(), 1);
    assert_eq!(out.total, Some(5));
}

/// Finding 9: `list`'s peek sizes the request `limit + 1` so truncation is
/// observable without a second request; a plain `+` panics in debug builds
/// (and wraps to 0 in release) at `usize::MAX`. `cmd/search.rs` already
/// saturates at the same seam — `list` must too.
#[tokio::test]
async fn list_saturates_a_huge_limit_instead_of_overflowing() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let out = alerts_ops::list(&t, &AlertFilter::default(), usize::MAX)
        .await
        .expect("a huge limit must not panic");
    assert_eq!(out.hits.len(), 0);
}

#[tokio::test]
async fn get_one_returns_not_found_for_a_missing_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let err = alerts_ops::get_one(&t, "missing")
        .await
        .expect_err("absent");
    assert_eq!(err.kind, elasticctl_core::ErrorKind::NotFound);
    assert!(err.message.contains("missing"), "{}", err.message);
}

fn resolution_page() -> serde_json::Value {
    json!({"hits": {"total": {"value": 2, "relation": "eq"}, "hits": [
        {"_id": "a1", "_source": {
            "kibana.alert.rule.name": "Suspicious PowerShell",
            "kibana.alert.workflow_status": "open"}},
        {"_id": "a2", "_source": {
            "kibana.alert.rule.name": "Rare DNS Tunnel",
            "kibana.alert.workflow_status": "closed"}}
    ]}})
}

#[tokio::test]
async fn plan_status_by_ids_previews_transitions_and_noops() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(resolution_page()))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let plan =
        alerts_ops::plan_status_by_ids(&t, &["a1".into(), "a2".into()], AlertStatus::Closed, None)
            .await
            .expect("plan");
    assert_eq!(plan.preview_action, "Close 2 alerts");
    assert_eq!(plan.targets, vec!["a1".to_string(), "a2".to_string()]);
    assert!(
        plan.preview_details[0].contains("open -> closed"),
        "{:?}",
        plan.preview_details
    );
    assert!(
        plan.preview_details[1].contains("already closed"),
        "{:?}",
        plan.preview_details
    );
}

#[tokio::test]
async fn a_partially_resolving_id_list_is_refused() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(resolution_page()))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let err = alerts_ops::plan_status_by_ids(
        &t,
        &["a1".into(), "a2".into(), "ghost".into()],
        AlertStatus::Closed,
        None,
    )
    .await
    .expect_err("must refuse the partial set");
    assert_eq!(err.kind, elasticctl_core::ErrorKind::NotFound);
    assert!(err.message.contains("ghost"), "{}", err.message);
}

#[tokio::test]
async fn plan_status_by_query_counts_and_samples() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 1214, "relation": "eq"}, "hits": [
                {"_id": "a1", "_source": {
                    "kibana.alert.rule.name": "Suspicious PowerShell",
                    "kibana.alert.severity": "high",
                    "@timestamp": "2026-08-30T21:14:02Z"}}
            ]}
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let plan = alerts_ops::plan_status_by_query(
        &t,
        json!({"term": {"kibana.alert.rule.rule_id": "r-1"}}),
        AlertStatus::Closed,
        Conflicts::Abort,
        Some("false_positive".into()),
    )
    .await
    .expect("plan");
    assert_eq!(plan.matched, 1214);
    assert_eq!(plan.preview_action, "Close alerts matching query");
    assert!(
        plan.preview_details[0].contains("matched now: 1,214"),
        "{:?}",
        plan.preview_details
    );
    assert!(
        plan.preview_details[0].contains("showing 1 of 1,214"),
        "{:?}",
        plan.preview_details
    );
    assert!(
        plan.preview_details.last().unwrap().contains("advisory"),
        "{:?}",
        plan.preview_details
    );
}

#[tokio::test]
async fn an_empty_query_object_is_rejected() {
    let t = test_transport("http://127.0.0.1:1");
    let err = alerts_ops::plan_status_by_query(
        &t,
        json!({}),
        AlertStatus::Closed,
        Conflicts::Abort,
        None,
    )
    .await
    .expect_err("empty query");
    assert!(
        err.message.contains("match_all"),
        "the remedy names the explicit form: {}",
        err.message
    );
}

/// Finding 7: the empty-`{}` rejection lives only in `plan_status_by_query`.
/// `QueryStatusPlan`'s public fields plus the public `apply_status_by_query`
/// let a caller that skips `plan_status_by_query` (the planned MCP server,
/// or any other `-api` consumer) apply an unscoped query. `apply` must
/// enforce the same rule, and refuse before any request reaches the mock.
#[tokio::test]
async fn apply_status_by_query_refuses_an_unscoped_query_before_any_request() {
    // No mocks: a request that reaches the server fails the test.
    let t = test_transport("http://127.0.0.1:1");
    let plan = alerts_ops::QueryStatusPlan {
        status: AlertStatus::Closed,
        reason: None,
        conflicts: Conflicts::Abort,
        query: json!({}),
        matched: 0,
        preview_action: "Close alerts matching query".into(),
        preview_details: vec![],
    };
    let err = alerts_ops::apply_status_by_query(&t, &plan)
        .await
        .expect_err("an empty query must be refused at apply time too");
    assert!(
        err.message.contains("match_all"),
        "the remedy names the explicit form: {}",
        err.message
    );
}

#[tokio::test]
async fn apply_status_by_query_reports_conflicts_as_failures_under_abort() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 3, "updated": 2, "version_conflicts": 1, "noops": 0, "failures": []
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let plan = alerts_ops::QueryStatusPlan {
        status: AlertStatus::Closed,
        reason: None,
        conflicts: Conflicts::Abort,
        query: json!({"term": {"x": 1}}),
        matched: 3,
        preview_action: "Close alerts matching query".into(),
        preview_details: vec![],
    };
    let report = alerts_ops::apply_status_by_query(&t, &plan)
        .await
        .expect("apply");
    assert_eq!(report.failed, 1, "an aborted conflict is a failure");
    assert_eq!(
        report.version_conflicts, 1,
        "the verbatim count still renders"
    );

    let plan = alerts_ops::QueryStatusPlan {
        conflicts: Conflicts::Proceed,
        ..plan
    };
    let report = alerts_ops::apply_status_by_query(&t, &plan)
        .await
        .expect("apply");
    assert_eq!(report.failed, 0, "proceed opts into best-effort");
}

/// The CLI's `required = true` is not the only door: both plans are public
/// `-api` entry points, so an empty target list must be refused there too,
/// before any resolution or request.
#[tokio::test]
async fn tag_and_assign_plans_refuse_an_empty_target_list_before_any_request() {
    // No mocks: a request that reaches the server fails the test.
    let t = test_transport("http://127.0.0.1:1");

    let err = alerts_ops::plan_tags(&t, &[], vec!["triaged".into()], vec![])
        .await
        .expect_err("an empty target list must be refused");
    assert!(
        err.message.contains("at least one alert id"),
        "{}",
        err.message
    );

    let err = alerts_ops::plan_assign(&t, &[], &["uid:u_1".into()], &[])
        .await
        .expect_err("an empty target list must be refused");
    assert!(
        err.message.contains("at least one alert id"),
        "{}",
        err.message
    );
}

#[tokio::test]
async fn plan_tags_requires_an_edit_and_rejects_overlap() {
    let t = test_transport("http://127.0.0.1:1");
    let err = alerts_ops::plan_tags(&t, &["a1".into()], vec![], vec![])
        .await
        .expect_err("no edit");
    assert!(
        err.message.contains("--add") && err.message.contains("--remove"),
        "{}",
        err.message
    );

    let err = alerts_ops::plan_tags(&t, &["a1".into()], vec!["t".into()], vec!["t".into()])
        .await
        .expect_err("overlap");
    assert_eq!(err.kind, elasticctl_core::ErrorKind::Conflict);
}

#[tokio::test]
async fn plan_assign_resolves_users_and_shows_the_mapping() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [
                {"_id": "a1", "_source": {
                    "kibana.alert.rule.name": "Alpha",
                    "kibana.alert.workflow_status": "open"}}
            ]}
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let plan = alerts_ops::plan_assign(&t, &["a1".into()], &["uid:u_1".into()], &[])
        .await
        .expect("plan");
    assert_eq!(plan.add, vec!["u_1".to_string()]);
    assert_eq!(plan.preview_action, "Assign 1 alert");
    assert!(
        plan.preview_details
            .iter()
            .any(|d| d.contains("uid:u_1") && d.contains("u_1")),
        "the mapping is visible: {:?}",
        plan.preview_details
    );
}
