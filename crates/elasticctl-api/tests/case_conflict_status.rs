use elasticctl_api::{cases::CaseStatus, cases_ops};
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::Value;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn fixture(set: &str, name: &str) -> Value {
    let file = format!(
        "{}/../../tests/fixtures/{set}/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap()
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

async fn check_status(status: u16) {
    for set in ["ech-9.5.2", "serverless-9.7.0", "traditional-9.5.1"] {
        let server = MockServer::start().await;
        let body = fixture(set, "case_get")["response"].clone();
        let id = body["id"].as_str().unwrap();
        Mock::given(method("GET"))
            .and(path(format!("/api/cases/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;
        let error = fixture(set, "case_conflict")["error"].clone();
        Mock::given(method("PATCH"))
            .and(path("/api/cases"))
            .respond_with(ResponseTemplate::new(status).set_body_json(&error))
            .mount(&server)
            .await;
        let t = transport(&server.uri());
        let plan = cases_ops::plan_status(&t, &[id.into()], CaseStatus::Closed)
            .await
            .unwrap();
        let got = cases_ops::apply_status(&t, &plan).await.unwrap_err();
        assert_eq!(got.http_status, Some(status));
        assert_eq!(
            got.kind,
            match status {
                409 => ErrorKind::Conflict,
                403 => ErrorKind::Permission,
                _ => ErrorKind::Http,
            }
        );
        if status == 409 {
            assert_eq!(
                got.message,
                format!(
                    "a case changed since the preview ({}); re-run the command",
                    error["message"].as_str().unwrap()
                )
            );
        }
    }
}

#[tokio::test]
async fn apply_status_conflict_keeps_http_status_and_message() {
    check_status(409).await;
}

#[tokio::test]
async fn apply_status_preserves_permission_and_server_errors() {
    check_status(403).await;
    check_status(500).await;
}
