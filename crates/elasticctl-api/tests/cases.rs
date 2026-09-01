use elasticctl_api::cases::{self, CaseStatus, NewCase};
use elasticctl_core::{Profile, Transport};
use serde_json::json;
use wiremock::matchers::{body_json, method, path, query_param};
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

fn case_body(id: &str, status: &str) -> serde_json::Value {
    json!({
        "id": id, "version": "WzEsMV0=", "title": "Suspicious activity",
        "status": status, "severity": "high", "tags": ["elasticctl-sample"],
        "description": "d", "assignees": [{"uid": "u_1"}],
        "created_at": "2026-01-01T00:00:00.000Z", "updated_at": "2026-01-01T00:00:00.000Z",
        "totalComment": 2, "owner": "securitySolution"
    })
}

#[test]
fn decodes_a_case_and_keeps_unknown_fields() {
    let case = cases::decode_case(&case_body("c1", "open")).expect("decode");
    assert_eq!(
        (case.id.as_str(), case.version.as_str()),
        ("c1", "WzEsMV0=")
    );
    assert_eq!(case.status, "open");
    assert_eq!(case.total_comment, Some(2));
    assert_eq!(case.extra["owner"], json!("securitySolution"));
}

#[test]
fn rejects_a_case_missing_its_version() {
    let mut body = case_body("c1", "open");
    body.as_object_mut().unwrap().remove("version");
    let err = cases::decode_case(&body).expect_err("must fail");
    assert!(err.message.contains("version"), "{}", err.message);
}

#[test]
fn decodes_a_find_page_with_total() {
    let body = json!({
        "cases": [case_body("c1", "open"), case_body("c2", "closed")],
        "page": 1, "per_page": 100, "total": 7,
        "count_open_cases": 3, "count_in_progress_cases": 1, "count_closed_cases": 3
    });
    let (cases, total) = cases::decode_find(&body).expect("decode");
    assert_eq!(cases.len(), 2);
    assert_eq!(total, 7);
}

#[test]
fn parses_the_case_status_vocabulary() {
    assert_eq!(
        CaseStatus::parse("in-progress").unwrap().as_str(),
        "in-progress"
    );
    assert!(
        CaseStatus::parse("acknowledged").is_err(),
        "alert vocabulary is not case vocabulary"
    );
}

#[tokio::test]
async fn create_posts_the_documented_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/cases"))
        .and(body_json(json!({
            "title": "T", "description": "T", "tags": ["a"],
            "assignees": [{"uid": "u_1"}],
            "connector": {"id": "none", "name": "none", "type": ".none", "fields": null},
            "settings": {"syncAlerts": false},
            "owner": "securitySolution"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c9", "open")))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let case = cases::create(
        &t,
        &NewCase {
            title: "T".into(),
            description: None,
            tags: vec!["a".into()],
            severity: None,
            assignee_uids: vec!["u_1".into()],
        },
    )
    .await
    .expect("create");
    assert_eq!(case.id, "c9");
}

#[tokio::test]
async fn patch_status_sends_versions_and_delete_encodes_ids() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/cases"))
        .and(body_json(
            json!({"cases": [{"id": "c1", "version": "WzEsMV0=", "status": "closed"}]}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([case_body("c1", "closed")])))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/cases"))
        .and(query_param("ids", r#"["c1","c2"]"#))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let updated = cases::patch_status(&t, &[("c1".into(), "WzEsMV0=".into(), CaseStatus::Closed)])
        .await
        .expect("patch");
    assert_eq!(updated[0].status, "closed");
    cases::delete(&t, &["c1".into(), "c2".into()])
        .await
        .expect("delete");
}

#[tokio::test]
async fn comments_and_alert_attachments_post_their_shapes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/cases/c1/comments"))
        .and(body_json(
            json!({"type": "user", "comment": "hello", "owner": "securitySolution"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c1", "open")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/cases/c2/comments"))
        .and(body_json(json!({
            "type": "alert",
            "alertId": ["a1", "a2"],
            "index": [".alerts-security.alerts-default", ".alerts-security.alerts-default"],
            "rule": {"id": "r-uuid", "name": "Alpha"},
            "owner": "securitySolution"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c2", "open")))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    cases::add_comment(&t, "c1", "hello")
        .await
        .expect("comment");
    cases::attach_alerts(
        &t,
        "c2",
        &["a1".into(), "a2".into()],
        &[
            ".alerts-security.alerts-default".into(),
            ".alerts-security.alerts-default".into(),
        ],
        "r-uuid",
        "Alpha",
    )
    .await
    .expect("attach");
}
