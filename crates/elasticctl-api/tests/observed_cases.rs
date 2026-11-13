use elasticctl_api::cases::CaseStatus;
use elasticctl_api::cases_ops::{observe_cases, plan_comment_observed, plan_status_observed};
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn transport(uri: &str) -> Transport {
    Transport::new(&Profile {
        kibana_url: uri.into(),
        es_url: Some(uri.into()),
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .unwrap()
}

async fn mount(server: &MockServer, id: &str, status: u16, body: Value) {
    Mock::given(method("GET"))
        .and(path(format!("/api/cases/{id}")))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(server)
        .await;
}

fn body() -> Value {
    let recorded: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/traditional-9.5.1/case_get.json"
    ))
    .unwrap();
    let mut case = recorded["response"].clone();
    case["id"] = json!("c1");
    case["version"] = json!("v1");
    case["settings"]["syncAlerts"] = json!(true);
    case
}

fn error_body() -> Value {
    let recorded: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/traditional-9.5.1/case_conflict.json"
    ))
    .unwrap();
    recorded["error"].clone()
}

#[tokio::test]
async fn states_match_planners_and_version_changes() {
    let server = MockServer::start().await;
    let mut changed = body();
    changed["version"] = json!("v2");
    mount(&server, "c1", 200, body()).await;
    mount(&server, "c2", 200, changed).await;
    let t = transport(&server.uri());
    let ids = vec!["c1".into(), "c2".into(), "c1".into()];
    let full = observe_cases(&t, &ids, true).await.unwrap();
    let simple = observe_cases(&t, &ids, false).await.unwrap();
    assert_eq!(
        full.0.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(),
        vec!["c1", "c2", "c1"]
    );
    assert!(full.0.iter().all(|x| x.object == "case"));
    let case = body();
    assert_eq!(
        full.0[0].state,
        Some(json!({
            "status": case["status"],
            "title": case["title"],
            "version": "v1",
            "sync_alerts": true
        }))
    );
    assert_eq!(
        simple.0[0].state,
        Some(json!({ "status": case["status"], "title": case["title"] }))
    );
    assert_ne!(full.0[0].state, full.0[1].state);
    assert_eq!(simple.0[0].state, simple.0[1].state);
    let (_, status) = plan_status_observed(&t, &["c1".into()], CaseStatus::Closed)
        .await
        .unwrap();
    let (_, comment) = plan_comment_observed(&t, "c1", "hello").await.unwrap();
    assert_eq!(full.0[0], status.0[0]);
    assert_eq!(simple.0[0], comment.0[0]);
    let requests = server.received_requests().await.unwrap();
    let paths: Vec<_> = requests.iter().map(|r| r.url.path()).collect();
    assert_eq!(
        paths,
        vec![
            "/api/cases/c1",
            "/api/cases/c2",
            "/api/cases/c1",
            "/api/cases/c1",
            "/api/cases/c2",
            "/api/cases/c1",
            "/api/cases/c1",
            "/api/cases/c1"
        ]
    );
}

#[tokio::test]
async fn empty_missing_and_errors() {
    let server = MockServer::start().await;
    let t = transport(&server.uri());
    assert!(observe_cases(&t, &[], true).await.unwrap().0.is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
    for (id, status) in [("missing", 404), ("denied", 403), ("broken", 500)] {
        mount(&server, id, status, error_body()).await;
    }
    assert_eq!(
        observe_cases(&t, &["missing".into()], false)
            .await
            .unwrap()
            .0[0]
            .state,
        None
    );
    for (id, status, kind) in [
        ("denied", 403, ErrorKind::Permission),
        ("broken", 500, ErrorKind::Http),
    ] {
        let err = observe_cases(&t, &[id.into()], true).await.unwrap_err();
        assert_eq!(err.kind, kind);
        assert_eq!(err.http_status, Some(status));
    }
}

#[tokio::test]
async fn fixtures_and_strict_sync_alerts() {
    for fixture in [
        include_str!("../../../tests/fixtures/ech-9.5.2/case_get.json"),
        include_str!("../../../tests/fixtures/serverless-9.7.0/case_get.json"),
        include_str!("../../../tests/fixtures/traditional-9.5.1/case_get.json"),
    ] {
        let original = serde_json::from_str::<Value>(fixture).unwrap()["response"].clone();
        for settings in [
            json!({"syncAlerts":true}),
            json!({"syncAlerts":false}),
            json!({"syncAlerts":"true"}),
            json!({}),
            Value::Null,
        ] {
            let server = MockServer::start().await;
            let mut case = original.clone();
            if settings.is_null() {
                case.as_object_mut().unwrap().remove("settings");
            } else {
                case["settings"] = settings.clone();
            }
            let id = case["id"].as_str().unwrap();
            mount(&server, id, 200, case.clone()).await;
            let seen = observe_cases(&transport(&server.uri()), &[id.into()], true)
                .await
                .unwrap();
            let expected = settings
                .get("syncAlerts")
                .filter(|v| v.is_boolean())
                .cloned()
                .unwrap_or(Value::Null);
            assert_eq!(seen.0[0].state.as_ref().unwrap()["sync_alerts"], expected);
            assert_eq!(
                seen.0[0].state.as_ref().unwrap()["version"],
                case["version"]
            );
        }
    }
}
