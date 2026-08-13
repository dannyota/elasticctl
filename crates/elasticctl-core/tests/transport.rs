use elasticctl_core::{Profile, Transport};
use serde_json::json;
use wiremock::matchers::{body_partial_json, header, method, path};
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

#[test]
fn space_path_prefixes_only_non_default_spaces() {
    // Kibana serves the default space at the bare path.
    assert_eq!(Transport::space_path("default", "/api/x"), "/api/x");
    assert_eq!(Transport::space_path("soc", "/api/x"), "/s/soc/api/x");
}

#[tokio::test]
async fn get_sends_the_authorization_and_version_headers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/thing"))
        .and(header("authorization", "ApiKey essu_test"))
        .and(header("elastic-api-version", "2023-10-31"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    assert_eq!(t.get("/api/thing").await.unwrap()["ok"], true);
}

#[tokio::test]
async fn non_get_requests_carry_the_xsrf_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/thing"))
        .and(header("kbn-xsrf", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"created": true})))
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    assert_eq!(
        t.post("/api/thing", Some(&json!({}))).await.unwrap()["created"],
        true
    );
}

#[tokio::test]
async fn a_404_becomes_a_not_found_error_carrying_the_server_message() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(
            json!({"statusCode": 404, "error": "Not Found", "message": "rule not found"}),
        ))
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    let err = t.get("/api/missing").await.unwrap_err();
    assert_eq!(err.kind, elasticctl_core::ErrorKind::NotFound);
    assert_eq!(err.message, "rule not found");
}

#[tokio::test]
async fn the_cloud_edge_proxy_envelope_is_classified_too() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/gone"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"ok": false, "message": "Unknown resource."})),
        )
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    let err = t.get("/api/gone").await.unwrap_err();
    assert_eq!(err.kind, elasticctl_core::ErrorKind::NotFound);
    assert_eq!(err.message, "Unknown resource.");
}

#[tokio::test]
async fn a_429_is_retried_and_then_succeeds() {
    let server = MockServer::start().await;
    // wiremock serves mounted mocks in order with `up_to_n_times`.
    Mock::given(method("GET"))
        .and(path("/api/flaky"))
        .respond_with(ResponseTemplate::new(429))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/flaky"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    assert_eq!(t.get("/api/flaky").await.unwrap()["ok"], true);
}

#[tokio::test]
async fn a_400_is_never_retried() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/bad"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"message": "bad input"})))
        .expect(1) // exactly one call proves no retry happened
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    assert!(t.get("/api/bad").await.is_err());
    // MockServer verifies `expect(1)` on drop.
}

#[test]
fn urlencode_escapes_what_breaks_a_url_and_leaves_the_rest() {
    // Escape only query-breaking characters to keep recorded fixtures readable.
    assert_eq!(elasticctl_core::urlencode("a-b_c.d~e"), "a-b_c.d~e");
    assert_eq!(elasticctl_core::urlencode("a b"), "a%20b");
    assert_eq!(elasticctl_core::urlencode("x\"y"), "x%22y");
    assert_eq!(
        elasticctl_core::urlencode("alert.attributes.params.ruleId: \"a/b\""),
        "alert.attributes.params.ruleId%3A%20%22a%2Fb%22"
    );
}

#[tokio::test]
async fn post_absolute_es_sends_the_body_to_the_es_host() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/index/_search"))
        .and(header("authorization", "ApiKey essu_test"))
        .and(body_partial_json(json!({"size": 1})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"hits": {"total": {"value": 3}}})),
        )
        .mount(&server)
        .await;

    let mut profile = profile_for(&server);
    // Cloud deployments use a different Elasticsearch host from Kibana.
    profile.es_url = Some(server.uri());
    profile.kibana_url = "https://kibana.invalid".into();
    let t = Transport::new(&profile).unwrap();

    let body = t
        .post_absolute_es("/index/_search", &json!({"size": 1}))
        .await
        .unwrap();
    assert_eq!(body["hits"]["total"]["value"], 3);
}

#[tokio::test]
async fn post_absolute_es_classifies_an_error_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/index/_search"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "no access"})))
        .mount(&server)
        .await;
    let mut profile = profile_for(&server);
    profile.es_url = Some(server.uri());
    let t = Transport::new(&profile).unwrap();

    let err = t
        .post_absolute_es("/index/_search", &json!({}))
        .await
        .unwrap_err();
    assert_eq!(err.kind, elasticctl_core::ErrorKind::Permission);
    assert_eq!(err.message, "no access");
}

#[tokio::test]
async fn delete_absolute_es_targets_the_es_host() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/scratch-index"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .mount(&server)
        .await;
    let mut profile = profile_for(&server);
    profile.es_url = Some(server.uri());
    let t = Transport::new(&profile).unwrap();

    assert_eq!(
        t.delete_absolute_es("/scratch-index").await.unwrap()["acknowledged"],
        true
    );
}

#[tokio::test]
async fn post_text_returns_the_raw_body_for_ndjson_export() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/export"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("{\"rule_id\":\"a\"}\n{\"exported_count\":1}\n"),
        )
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    let body = t.post_text("/api/export", None).await.unwrap();
    assert_eq!(body.lines().count(), 2);
}
