use elasticctl_api::dashboards::{self, DashboardSpec};
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, method, path};
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
    .expect("transport")
}

async fn dashboard_capability(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.5.1", "build_flavor": "traditional"}
        })))
        .mount(server)
        .await;
}

fn dashboard_response() -> Value {
    json!({
        "id": "dash-1",
        "data": {"title": "Security overview", "panels": []},
        "meta": {},
        "warnings": [{"message": "unsupported panel omitted"}]
    })
}

#[test]
fn dashboard_requires_id_object_data_and_non_empty_title() {
    assert!(
        DashboardSpec::try_from(json!({"id":"d1","data":{"title":"Overview","panels":[]}})).is_ok()
    );
    assert!(DashboardSpec::try_from(json!({"id":"","data":{"title":"Overview"}})).is_err());
    assert!(DashboardSpec::try_from(json!({"id":"d1","data":{"title":""}})).is_err());
    assert!(DashboardSpec::try_from(json!({"id":"d1","data":[]})).is_err());
}

#[test]
fn dashboard_spec_rejects_unknown_wrapper_keys() {
    let error = DashboardSpec::try_from(json!({
        "id": "dash-1",
        "data": {"title": "Overview"},
        "meta": {}
    }))
    .expect_err("portable specs must keep server metadata out of the wrapper");

    assert_eq!(error.kind, ErrorKind::Error);
    assert!(error.message.contains("meta"), "{}", error.message);
}

#[test]
fn dashboard_validation_names_a_nested_time_range_mode() {
    let spec = DashboardSpec::try_from(json!({
        "id": "dash-1",
        "data": {
            "title": "Overview",
            "panels": [{"config": {"time_range": {"mode": "relative"}}}]
        }
    }))
    .expect("structurally valid dashboard");

    let error = dashboards::validate_spec(&spec).expect_err("mode is lossy");
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert!(
        error.message.contains("$.panels[0].config.time_range.mode"),
        "{}",
        error.message
    );
}

#[test]
fn recursive_subset_reports_dropped_paths_and_allows_derived_keys() {
    let sent = json!({"title":"Overview","panels":[{"type":"vis","config":{"title":"Count"}}]});
    let accepted =
        json!({"title":"Overview","description":"derived","panels":[{"type":"vis","config":{}}]});
    let loss = dashboards::subset_losses(&sent, &accepted);
    assert_eq!(
        loss.iter().map(|v| v.path.as_str()).collect::<Vec<_>>(),
        vec!["$.panels[0].config.title"]
    );
}

#[test]
fn subset_reports_changed_values_and_missing_array_entries() {
    let sent = json!({"panels":[{"title":"first"},{"title":"second"}]});
    let accepted = json!({"panels":[{"title":"renamed"}]});

    assert_eq!(
        dashboards::subset_losses(&sent, &accepted),
        vec![
            dashboards::DashboardLoss {
                path: "$.panels[0].title".into(),
                expected: json!("first"),
                actual: Some(json!("renamed")),
            },
            dashboards::DashboardLoss {
                path: "$.panels[1]".into(),
                expected: json!({"title":"second"}),
                actual: None,
            },
        ]
    );
}

#[test]
fn collects_unique_data_view_reference_ids() {
    let body = json!({"panels":[
        {"config":{"data_source":{"type":"data_view_reference","ref_id":"dv-2"}}},
        {"config":{"nested":{"type":"data_view_reference","ref_id":"dv-1"}}},
        {"config":{"data_source":{"type":"data_view_reference","ref_id":"dv-2"}}}
    ]});
    assert_eq!(
        dashboards::collect_data_view_refs(&body),
        vec!["dv-1", "dv-2"]
    );
}

#[tokio::test]
async fn search_uses_the_dashboard_page_query_contract() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{
                "id": "dash-1",
                "title": "Security overview",
                "description": "Detection activity",
                "tags": ["blue"]
            }],
            "meta": {"page": 1, "per_page": 1000, "total": 1}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let page = dashboards::search(&transport(&server), 1, Some("security"), &["blue".into()])
        .await
        .expect("search");

    assert_eq!(page.total, 1);
    assert_eq!(page.data[0].id, "dash-1");
    let requests = server.received_requests().await.expect("requests");
    let search = requests
        .iter()
        .find(|request| request.url.path() == "/api/dashboards")
        .expect("dashboard request");
    assert_eq!(
        search.url.query(),
        Some("page=1&per_page=1000&query=security&tags=blue")
    );
}

#[tokio::test]
async fn get_decodes_the_strict_dashboard_envelope() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(dashboard_response()))
        .expect(1)
        .mount(&server)
        .await;

    let dashboard = dashboards::get(&transport(&server), "dash-1")
        .await
        .expect("get");
    assert_eq!(dashboard.id, "dash-1");
    assert_eq!(dashboard.data["title"], "Security overview");
    assert_eq!(dashboard.warnings[0].message, "unsupported panel omitted");
}

#[tokio::test]
async fn get_rejects_missing_meta_and_non_string_warning_messages() {
    for body in [
        json!({"id":"dash-1","data":{"title":"Overview"}}),
        json!({
            "id":"dash-1",
            "data":{"title":"Overview"},
            "meta":{},
            "warnings":[{"message":false}]
        }),
    ] {
        let server = MockServer::start().await;
        dashboard_capability(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/dashboards/dash-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let error = dashboards::get(&transport(&server), "dash-1")
            .await
            .expect_err("malformed success response");
        assert_eq!(error.kind, ErrorKind::Http);
    }
}

#[tokio::test]
async fn put_sends_only_dashboard_data_and_decodes_the_response() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("PUT"))
        .and(path("/api/dashboards/dash-1"))
        .and(body_json(json!({"title":"Security overview","panels":[]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(dashboard_response()))
        .expect(1)
        .mount(&server)
        .await;
    let spec = DashboardSpec::try_from(json!({
        "id": "dash-1",
        "data": {"title": "Security overview", "panels": []}
    }))
    .expect("spec");

    let dashboard = dashboards::put(&transport(&server), &spec)
        .await
        .expect("put");
    assert_eq!(dashboard.id, "dash-1");
}

#[tokio::test]
async fn delete_accepts_the_measured_null_success_body() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("DELETE"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    dashboards::delete(&transport(&server), "dash-1")
        .await
        .expect("empty delete response");
}
