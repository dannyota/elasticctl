//! An id read from a response or a local file becomes one URL path segment
//! only when URL parsing cannot remove it. `.` and `..` would move the
//! request to a parent route, so they are refused before any request.
use elasticctl_api::compose::require_path_segment;
use elasticctl_api::dashboards::{self, DashboardSpec};
use elasticctl_api::fleet::{
    agent_policies, agent_policy_ops, integration_policies, integration_policy_ops,
};
use elasticctl_api::search::esql;
use elasticctl_api::{dashboards_ops, data_views, data_views_ops};
use elasticctl_core::{Error, ErrorKind, Profile, Transport, urlencode};
use serde_json::{Map, Value, json};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const HOSTILE: [&str; 2] = [".", ".."];
const REFUSED: &str = "id is not a single URL path segment";

fn fixture(set: &str, name: &str) -> Value {
    let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(set)
        .join(name);
    let body: Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
    body["response"].clone()
}

fn recorded(name: &str) -> Value {
    fixture("traditional-9.5.1", name)
}

async fn stack() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(recorded("status.json")))
        .mount(&server)
        .await;
    server
}

fn transport(server: &MockServer) -> Transport {
    Transport::new(&Profile {
        kibana_url: server.uri(),
        es_url: Some(server.uri()),
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .unwrap()
}

/// Every request after the capability probe, as `METHOD path`.
async fn requests(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path() != "/api/status")
        .map(|request| format!("{} {}", request.method, request.url.path()))
        .collect()
}

fn assert_refused(error: Error) {
    assert_eq!(error.kind, ErrorKind::Http, "{}", error.message);
    assert_eq!(error.message, REFUSED);
}

async fn mount_get(server: &MockServer, route: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

#[test]
fn the_shared_check_refuses_empty_and_dot_segments_as_http() {
    for id in ["", ".", ".."] {
        assert_refused(require_path_segment(id).unwrap_err());
    }
    for id in ["...", ".a", "a..b", "a/b", "logs"] {
        assert_eq!(require_path_segment(id).unwrap(), id);
    }
}

#[tokio::test]
async fn a_data_view_name_resolving_to_a_dot_id_sends_no_get() {
    for hostile in HOSTILE {
        let server = stack().await;
        let mut list = recorded("data_views_list.json");
        let name = list["data_view"][0]["name"].as_str().unwrap().to_owned();
        list["data_view"][0]["id"] = json!(hostile);
        mount_get(&server, "/api/data_views", list).await;

        let error = data_views_ops::get_op(&transport(&server), &name)
            .await
            .unwrap_err();

        assert_refused(error);
        assert_eq!(requests(&server).await, ["GET /api/data_views"]);
    }
}

#[tokio::test]
async fn a_dashboard_title_resolving_to_a_dot_id_sends_no_get() {
    for hostile in HOSTILE {
        let server = stack().await;
        let mut page = recorded("dashboard_search.json");
        let title = page["data"][0]["data"]["title"]
            .as_str()
            .unwrap()
            .to_owned();
        page["data"][0]["id"] = json!(hostile);
        mount_get(&server, "/api/dashboards", page).await;

        let error = dashboards_ops::get_op(&transport(&server), &title)
            .await
            .unwrap_err();

        assert_refused(error);
        assert_eq!(
            requests(&server).await,
            [
                format!("GET /api/dashboards/{}", urlencode(&title)),
                "GET /api/dashboards".to_owned(),
            ]
        );
    }
}

#[tokio::test]
async fn an_agent_policy_name_resolving_to_a_dot_id_sends_no_get() {
    for hostile in HOSTILE {
        let server = stack().await;
        let mut page = recorded("agent_policies_list.json");
        let name = page["items"][0]["name"].as_str().unwrap().to_owned();
        page["items"][0]["id"] = json!(hostile);
        mount_get(&server, "/api/fleet/agent_policies", page).await;

        let error = agent_policy_ops::get_op(&transport(&server), &name)
            .await
            .unwrap_err();

        assert_refused(error);
        assert_eq!(
            requests(&server).await,
            [
                format!("GET /api/fleet/agent_policies/{name}"),
                "GET /api/fleet/agent_policies".to_owned(),
            ]
        );
    }
}

#[tokio::test]
async fn an_integration_policy_name_resolving_to_a_dot_id_sends_no_get() {
    for hostile in HOSTILE {
        let server = stack().await;
        let mut page = recorded("integration_policies_list.json");
        let name = page["items"][0]["name"].as_str().unwrap().to_owned();
        page["items"][0]["id"] = json!(hostile);
        mount_get(&server, "/api/fleet/package_policies", page).await;

        let error = integration_policy_ops::get_op(&transport(&server), &name)
            .await
            .unwrap_err();

        assert_refused(error);
        assert_eq!(
            requests(&server).await,
            [
                format!("GET /api/fleet/package_policies/{name}"),
                "GET /api/fleet/package_policies".to_owned(),
            ]
        );
    }
}

#[tokio::test]
async fn an_integration_policy_with_a_dot_parent_id_sends_no_parent_get() {
    for hostile in HOSTILE {
        let server = stack().await;
        let mut body = recorded("integration_policy_get.json");
        let id = body["item"]["id"].as_str().unwrap().to_owned();
        body["item"]["policy_ids"] = json!([hostile]);
        let route = format!("/api/fleet/package_policies/{id}");
        mount_get(&server, &route, body).await;

        let error = integration_policy_ops::get_op(&transport(&server), &id)
            .await
            .unwrap_err();

        assert_refused(error);
        assert_eq!(requests(&server).await, [format!("GET {route}")]);
    }
}

#[tokio::test]
async fn an_esql_async_dot_id_sends_no_poll_or_cleanup() {
    for hostile in HOSTILE {
        let server = stack().await;
        let mut start = fixture("serverless-9.7.0", "esql_async_start.json");
        start["id"] = json!(hostile);
        Mock::given(method("POST"))
            .and(path("/_query/async"))
            .respond_with(ResponseTemplate::new(200).set_body_json(start))
            .mount(&server)
            .await;

        let error = esql::run_async(&transport(&server), "FROM logs | LIMIT 1")
            .await
            .unwrap_err();

        assert_refused(error);
        assert_eq!(requests(&server).await, ["POST /_query/async"]);
    }
}

#[tokio::test]
async fn an_esql_async_id_with_a_slash_stays_one_segment() {
    let server = stack().await;
    let mut start = fixture("serverless-9.7.0", "esql_async_start.json");
    start["id"] = json!("x/../../logs");
    Mock::given(method("POST"))
        .and(path("/_query/async"))
        .respond_with(ResponseTemplate::new(200).set_body_json(start))
        .mount(&server)
        .await;

    let error = esql::run_async(&transport(&server), "FROM logs | LIMIT 1")
        .await
        .unwrap_err();

    assert_eq!(error.kind, ErrorKind::NotFound);
    assert_eq!(
        requests(&server).await,
        [
            "POST /_query/async",
            "GET /_query/async/x%2F..%2F..%2Flogs",
            "DELETE /_query/async/x%2F..%2F..%2Flogs",
        ]
    );
}

#[tokio::test]
async fn every_request_wrapper_refuses_a_dot_id_before_any_request() {
    let get = recorded("integration_policy_get.json");
    let item: Map<String, Value> = get["item"].as_object().unwrap().clone();
    let integration = integration_policy_ops::normalize(&item, "default").unwrap();
    let package = integration.package.clone();
    let dashboard = recorded("dashboard_get.json");
    for hostile in HOSTILE {
        let server = stack().await;
        let t = transport(&server);
        let dashboard =
            DashboardSpec::try_from(json!({"id": hostile, "data": dashboard["data"]})).unwrap();
        let errors = [
            data_views::get(&t, hostile).await.map(drop),
            data_views::update(&t, hostile, &Default::default())
                .await
                .map(drop),
            data_views::update_fields_metadata(&t, hostile, &Map::new()).await,
            data_views::delete(&t, hostile).await,
            dashboards::get(&t, hostile).await.map(drop),
            dashboards::put(&t, &dashboard).await.map(drop),
            dashboards::delete(&t, hostile).await,
            agent_policies::get(&t, hostile).await.map(drop),
            agent_policies::update(&t, hostile, &json!({}))
                .await
                .map(drop),
            agent_policies::package_status(&t, hostile).await.map(drop),
            integration_policies::get(&t, hostile).await.map(drop),
            integration_policies::update(&t, hostile, &integration)
                .await
                .map(drop),
            integration_policies::delete(&t, hostile).await,
            integration_policies::package_metadata(&t, hostile, &package.version)
                .await
                .map(drop),
            integration_policies::package_metadata(&t, &package.name, hostile)
                .await
                .map(drop),
            esql::poll_until_complete(&t, hostile, 1, Duration::ZERO)
                .await
                .map(drop),
        ];
        for error in errors {
            assert_refused(error.unwrap_err());
        }
        assert!(requests(&server).await.is_empty());
    }
}

#[tokio::test]
async fn a_case_comment_or_attachment_to_a_dot_id_sends_no_post() {
    let server = stack().await;
    let t = transport(&server);
    for id in ["", ".", ".."] {
        assert_refused(
            elasticctl_api::cases::add_comment(&t, id, "marker comment")
                .await
                .unwrap_err(),
        );
        assert_refused(
            elasticctl_api::cases::attach_alerts(
                &t,
                id,
                &["alert-1".to_string()],
                &["index-1".to_string()],
                "rule-1",
                "rule name",
            )
            .await
            .unwrap_err(),
        );
    }
    assert!(requests(&server).await.is_empty());
}

/// An ordinary case selector whose read answers a dot id. The comment and
/// attachment plans keep the id the server returned, so applying them must
/// refuse it before any post.
#[tokio::test]
async fn case_plans_from_a_dot_id_response_send_no_post() {
    use elasticctl_api::cases_ops;
    for id in ["", ".", ".."] {
        let server = stack().await;
        let mut case = recorded("case_get.json");
        case["id"] = json!(id);
        mount_get(&server, "/api/cases/ordinary", case).await;
        let mut alerts = recorded("signals_search.json");
        let first = alerts["hits"]["hits"][0].clone();
        let alert_id = first["_id"].as_str().unwrap().to_string();
        let mut hit = first;
        hit["_source"]["kibana.alert.rule.uuid"] = json!("rule-uuid");
        alerts["hits"]["hits"] = json!([hit]);
        alerts["hits"]["total"] = json!({"value": 1, "relation": "eq"});
        Mock::given(method("POST"))
            .and(path("/api/detection_engine/signals/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(alerts))
            .mount(&server)
            .await;
        let t = transport(&server);

        let comment = cases_ops::plan_comment(&t, "ordinary", "marker comment")
            .await
            .unwrap();
        assert_eq!(comment.case_id, id);
        assert_refused(cases_ops::apply_comment(&t, &comment).await.unwrap_err());

        let attach = cases_ops::plan_attach(&t, "ordinary", &[alert_id])
            .await
            .unwrap();
        let refused = cases_ops::apply_attach(&t, &attach).await;
        let posted = requests(&server)
            .await
            .into_iter()
            .filter(|line| line.starts_with("POST /api/cases"))
            .collect::<Vec<_>>();
        assert!(posted.is_empty(), "{id:?}: {posted:?}");
        match refused {
            Err(error) => assert_refused(error),
            Ok(report) => assert_eq!(report.failed, report.total, "{id:?}"),
        }
    }
}
