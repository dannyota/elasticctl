use elasticctl_api::{
    alerts::AlertStatus,
    alerts_ops::{self, AlertFacet},
};
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

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

fn fixture(set: &str) -> Value {
    let path = format!(
        "{}/../../tests/fixtures/{set}/signals_search.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap()).unwrap()["response"]
        .clone()
}

async fn server(body: &Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn recheck_matches_planners_and_replays_fixtures() {
    for set in ["ech-9.5.2", "serverless-9.7.0", "traditional-9.5.1"] {
        for nested in [false, true] {
            let mut body = fixture(set);
            let hit = &mut body["hits"]["hits"][0];
            let id = hit["_id"].as_str().unwrap().to_string();
            let status = hit["_source"]["kibana.alert.workflow_status"]
                .as_str()
                .unwrap()
                .to_string();
            if nested {
                hit["_source"] =
                    json!({"kibana":{"alert":{"workflow_status":status,"rule":{"name":"rule"}}}});
            }
            let ids = vec![id.clone(), id.clone()];
            let s = server(&body).await;
            let t = transport(&s.uri());
            let (_, planned_status) =
                alerts_ops::plan_status_by_ids_observed(&t, &ids, AlertStatus::Closed, None)
                    .await
                    .unwrap();
            let (_, planned_presence) =
                alerts_ops::plan_tags_observed(&t, &ids, vec!["tag".into()], vec![])
                    .await
                    .unwrap();
            let status_seen = alerts_ops::observe_alerts(&t, &ids, AlertFacet::Status)
                .await
                .unwrap();
            let presence_seen = alerts_ops::observe_alerts(&t, &ids, AlertFacet::Presence)
                .await
                .unwrap();
            assert_eq!(status_seen, planned_status);
            assert_eq!(presence_seen, planned_presence);
            assert_eq!(status_seen.0[0].id, id);
            let requests = s.received_requests().await.unwrap();
            assert_eq!(requests.len(), 4);
            for request in &requests[1..] {
                assert_eq!(request.body, requests[0].body);
            }
            let mut changed = body.clone();
            if nested {
                changed["hits"]["hits"][0]["_source"]["kibana"]["alert"]["workflow_status"] =
                    json!("changed");
            } else {
                changed["hits"]["hits"][0]["_source"]["kibana.alert.workflow_status"] =
                    json!("changed");
            }
            let changed_server = server(&changed).await;
            let changed_t = transport(&changed_server.uri());
            assert_ne!(
                status_seen,
                alerts_ops::observe_alerts(&changed_t, &ids, AlertFacet::Status)
                    .await
                    .unwrap()
            );
            assert_eq!(
                presence_seen,
                alerts_ops::observe_alerts(&changed_t, &ids, AlertFacet::Presence)
                    .await
                    .unwrap()
            );
            let missing = vec!["missing".into(), id];
            let seen = alerts_ops::observe_alerts(&t, &missing, AlertFacet::Status)
                .await
                .unwrap();
            assert_eq!(seen.0.len(), 2);
            assert_eq!(seen.0[0].id, "missing");
            assert_eq!(seen.0[0].state, None);
            assert!(seen.0[1].state.is_some());
        }
    }
}

#[tokio::test]
async fn empty_ids_are_refused_before_request() {
    let s = server(&fixture("ech-9.5.2")).await;
    let err = alerts_ops::observe_alerts(&transport(&s.uri()), &[], AlertFacet::Status)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Error);
    assert!(err.to_string().contains("pass at least one alert id"));
    assert!(s.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn search_error_is_returned() {
    let s = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&s)
        .await;
    assert!(
        alerts_ops::observe_alerts(&transport(&s.uri()), &["id".into()], AlertFacet::Status)
            .await
            .is_err()
    );
    assert!(!s.received_requests().await.unwrap().is_empty());
}
