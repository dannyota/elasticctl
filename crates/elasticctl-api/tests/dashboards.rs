use elasticctl_api::content_codec::ContentFormat;
use elasticctl_api::dashboards::{self, DashboardSpec};
use elasticctl_api::dashboards_ops::{self, DashboardFilter};
use elasticctl_api::{
    BundleImportOutcome, BundleImportPlan, DashboardImportPlan, DashboardImportReport, MutationPlan,
};
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BUNDLE: &str = concat!(
    r#"{"id":"dv-1","type":"index-pattern","attributes":{"title":"logs-*"},"references":[]}"#,
    "\n",
    r#"{"id":"dash-1","type":"dashboard","attributes":{"title":"Overview"},"references":[]}"#,
    "\n",
    r#"{"exportedCount":2,"missingRefCount":0,"missingReferences":[]}"#,
    "\n",
);

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

fn dashboard(id: &str, title: &str) -> Value {
    json!({
        "id": id,
        "data": {"title": title, "panels": []},
        "meta": {"created_at": "volatile"},
        "warnings": []
    })
}

fn dashboard_spec(id: &str, title: &str) -> DashboardSpec {
    DashboardSpec::try_from(json!({"id": id, "data": {"title": title, "panels": []}}))
        .expect("dashboard spec")
}

fn dashboard_artifact(specs: &[DashboardSpec]) -> tempfile::TempPath {
    let file = tempfile::NamedTempFile::new().expect("artifact");
    serde_json::to_writer(&file, specs).expect("write artifact");
    file.into_temp_path()
}

fn dashboard_import_plan(
    specs: Vec<DashboardSpec>,
    before: BTreeMap<String, Option<DashboardSpec>>,
) -> DashboardImportPlan {
    let preview_details = specs
        .iter()
        .map(|spec| match before.get(&spec.id).and_then(Option::as_ref) {
            None => format!(
                "{}  create  {}",
                spec.id,
                spec.data["title"].as_str().expect("title")
            ),
            Some(current) if current == spec => {
                format!(
                    "{}  no-op  {}",
                    spec.id,
                    spec.data["title"].as_str().expect("title")
                )
            }
            Some(current) => format!(
                "{}  replace  {} -> {}",
                spec.id,
                current.data["title"].as_str().expect("title"),
                spec.data["title"].as_str().expect("title")
            ),
        })
        .collect();
    DashboardImportPlan {
        preview: MutationPlan {
            preview_action: format!("Import {} dashboard(s)", specs.len()),
            preview_details,
            targets: specs.iter().map(|spec| spec.id.clone()).collect(),
        },
        total: specs.len(),
        specs,
        before,
        skipped: Vec::new(),
        overwrite: true,
    }
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

#[test]
fn dashboard_resolution_prefers_exact_id_and_names_every_duplicate_title_id() {
    let summaries = vec![
        dashboards::DashboardSummary {
            id: "same".into(),
            title: "id winner".into(),
            description: None,
            tags: None,
        },
        dashboards::DashboardSummary {
            id: "dash-a".into(),
            title: "same".into(),
            description: None,
            tags: None,
        },
        dashboards::DashboardSummary {
            id: "dash-b".into(),
            title: "same".into(),
            description: None,
            tags: None,
        },
    ];

    assert_eq!(
        dashboards_ops::resolve_from_summaries(&summaries, "same")
            .expect("stable id wins")
            .title,
        "id winner"
    );
    let error = dashboards_ops::resolve_from_summaries(&summaries, "same title")
        .expect_err("the unrelated selector must miss");
    assert_eq!(error.kind, ErrorKind::NotFound);

    let duplicates = &summaries[1..];
    let error = dashboards_ops::resolve_from_summaries(duplicates, "same")
        .expect_err("duplicate exact titles refuse");
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(
        error.message,
        "dashboard title 'same' is ambiguous: dash-a, dash-b"
    );
}

#[tokio::test]
async fn dashboard_list_pages_at_one_thousand_and_sorts_by_stable_id() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    let first_page = (0..1000)
        .map(|index| {
            json!({
                "id": if index == 0 { "z".to_string() } else { format!("dash-{index:04}") },
                "title": format!("Security {index}")
            })
        })
        .collect::<Vec<_>>();
    Mock::given(method("GET"))
        .and(path("/api/dashboards"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "1000"))
        .and(query_param("query", "Security"))
        .and(query_param("tags", "blue"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": first_page,
            "meta": {"page": 1, "per_page": 1000, "total": 1001}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards"))
        .and(query_param("page", "2"))
        .and(query_param("per_page", "1000"))
        .and(query_param("query", "Security"))
        .and(query_param("tags", "blue"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "a", "title": "Security final"}],
            "meta": {"page": 2, "per_page": 1000, "total": 1001}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let listed = dashboards_ops::list_op(
        &transport(&server),
        &DashboardFilter {
            search: Some("Security".into()),
            tag: Some("blue".into()),
            limit: None,
        },
    )
    .await
    .expect("list all pages");

    assert_eq!(listed.total, 1001);
    assert!(!listed.truncated);
    assert_eq!(listed.dashboards.len(), 1001);
    assert_eq!(listed.dashboards.first().expect("first").id, "a");
    assert_eq!(listed.dashboards.last().expect("last").id, "z");
}

#[tokio::test]
async fn dashboard_list_marks_a_user_limit_as_truncated() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "c", "title": "C"},
                {"id": "a", "title": "A"},
                {"id": "b", "title": "B"}
            ],
            "meta": {"page": 1, "per_page": 1000, "total": 3}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let listed = dashboards_ops::list_op(
        &transport(&server),
        &DashboardFilter {
            limit: Some(2),
            ..Default::default()
        },
    )
    .await
    .expect("limited list");

    assert_eq!(listed.total, 3);
    assert!(listed.truncated);
    assert_eq!(
        listed
            .dashboards
            .iter()
            .map(|dashboard| dashboard.id.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );
}

#[tokio::test]
async fn dashboard_export_refuses_every_warning_with_the_bundle_remedy() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    let warning_bearing = json!({
        "id": "dash-1",
        "data": {"title": "Security overview", "panels": []},
        "meta": {},
        "warnings": [
            {"message": "Maps panel was removed"},
            {"message": "A second transformation warning"}
        ]
    });
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(warning_bearing))
        .expect(2)
        .mount(&server)
        .await;

    let error =
        dashboards_ops::export(&transport(&server), &["dash-1".into()], ContentFormat::Json)
            .await
            .expect_err("warning-bearing dashboards are not portable");

    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(
        error.message,
        "dashboard 'dash-1' cannot be exported through the typed API without loss: Maps panel was removed; A second transformation warning; use `dashboards bundle export dash-1`"
    );
}

async fn export_dashboard_details(format: ContentFormat) -> String {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    for (id, title) in [("dash-b", "Second"), ("dash-a", "First")] {
        Mock::given(method("GET"))
            .and(path(format!("/api/dashboards/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dashboard(id, title)))
            .expect(2)
            .mount(&server)
            .await;
    }

    dashboards_ops::export(
        &transport(&server),
        &["dash-b".into(), "dash-a".into()],
        format,
    )
    .await
    .expect("portable export")
    .body
}

#[tokio::test]
async fn dashboard_export_omits_meta_sorts_ids_and_preserves_json_yaml_values() {
    let json_body = export_dashboard_details(ContentFormat::Json).await;
    let yaml_body = export_dashboard_details(ContentFormat::Yaml).await;
    let json_specs: Vec<DashboardSpec> = serde_json::from_str(&json_body).expect("JSON specs");
    let yaml_specs: Vec<DashboardSpec> = serde_yaml_ng::from_str(&yaml_body).expect("YAML specs");

    assert_eq!(json_specs, yaml_specs);
    assert_eq!(
        json_specs
            .iter()
            .map(|spec| spec.id.as_str())
            .collect::<Vec<_>>(),
        vec!["dash-a", "dash-b"]
    );
    assert!(!json_body.contains("meta"));
    assert!(!yaml_body.contains("meta"));
}

#[test]
fn dashboard_artifact_validation_sorts_ids_and_names_every_duplicate() {
    let duplicate = dashboard_artifact(&[
        dashboard_spec("dash-b", "B"),
        dashboard_spec("dash-a", "A"),
        dashboard_spec("dash-b", "B again"),
        dashboard_spec("dash-a", "A again"),
    ]);
    let error = dashboards_ops::validate(&duplicate).expect_err("duplicate ids refuse locally");
    assert_eq!(error.kind, ErrorKind::Error);
    assert_eq!(error.message, "duplicate dashboard ids: dash-a, dash-b");

    let ordered =
        dashboard_artifact(&[dashboard_spec("dash-b", "B"), dashboard_spec("dash-a", "A")]);
    assert_eq!(
        dashboards_ops::validate(&ordered)
            .expect("valid artifact")
            .iter()
            .map(|spec| spec.id.as_str())
            .collect::<Vec<_>>(),
        vec!["dash-a", "dash-b"]
    );
}

#[tokio::test]
async fn dashboard_import_preflight_classifies_create_replace_no_op_and_skip() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    for (id, detail) in [
        ("dash-new", None),
        ("dash-old", Some(dashboard("dash-old", "Old title"))),
        ("dash-same", Some(dashboard("dash-same", "Same title"))),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/api/dashboards/{id}")))
            .respond_with(match detail {
                Some(detail) => ResponseTemplate::new(200).set_body_json(detail),
                None => ResponseTemplate::new(404).set_body_json(json!({"message": "missing"})),
            })
            .expect(1)
            .mount(&server)
            .await;
    }
    let desired_old = dashboard_spec("dash-old", "New title");
    let desired_new = dashboard_spec("dash-new", "New dashboard");
    let desired_same = dashboard_spec("dash-same", "Same title");
    let artifact = dashboard_artifact(&[
        desired_old.clone(),
        desired_same.clone(),
        desired_new.clone(),
    ]);

    let plan = dashboards_ops::plan_import(Some(&transport(&server)), &artifact, true, false)
        .await
        .expect("overwrite plan");

    assert_eq!(plan.total, 3);
    assert_eq!(plan.specs, vec![desired_new, desired_old, desired_same]);
    assert_eq!(
        plan.preview.preview_details,
        vec![
            "dash-new  create  New dashboard",
            "dash-old  replace  Old title -> New title",
            "dash-same  no-op  Same title",
        ]
    );
    assert_eq!(plan.before["dash-new"], None);
    assert_eq!(
        plan.before["dash-old"].as_ref().expect("snapshot").id,
        "dash-old"
    );
    assert!(plan.skipped.is_empty());

    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-old"))
        .respond_with(ResponseTemplate::new(200).set_body_json(dashboard("dash-old", "Old title")))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-new"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "missing"})))
        .expect(1)
        .mount(&server)
        .await;
    let artifact = dashboard_artifact(&[
        dashboard_spec("dash-old", "New title"),
        dashboard_spec("dash-new", "New dashboard"),
    ]);
    let plan = dashboards_ops::plan_import(Some(&transport(&server)), &artifact, false, true)
        .await
        .expect("skip plan");
    assert_eq!(
        plan.specs,
        vec![dashboard_spec("dash-new", "New dashboard")]
    );
    assert_eq!(
        plan.skipped,
        vec![json!({"id": "dash-old", "reason": "exists"})]
    );
}

#[tokio::test]
async fn dashboard_import_refuses_default_conflicts_and_every_missing_data_view_before_guard() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    for id in ["dash-a", "dash-b"] {
        Mock::given(method("GET"))
            .and(path(format!("/api/dashboards/{id}")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "missing"})))
            .expect(1)
            .mount(&server)
            .await;
    }
    for id in ["dv-a", "dv-b"] {
        Mock::given(method("GET"))
            .and(path(format!("/api/data_views/data_view/{id}")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "missing"})))
            .expect(1)
            .mount(&server)
            .await;
    }
    let artifact = dashboard_artifact(&[
        DashboardSpec::try_from(json!({
            "id": "dash-b",
            "data": {"title": "B", "panels": [{"type": "data_view_reference", "ref_id": "dv-b"}]}
        }))
        .expect("spec"),
        DashboardSpec::try_from(json!({
            "id": "dash-a",
            "data": {"title": "A", "nested": {"ref": {"type": "data_view_reference", "ref_id": "dv-a"}, "again": {"type": "data_view_reference", "ref_id": "dv-b"}}}
        }))
        .expect("spec"),
    ]);

    let error = dashboards_ops::plan_import(Some(&transport(&server)), &artifact, false, false)
        .await
        .expect_err("missing dependencies refuse before a guard can apply");

    assert_eq!(error.kind, ErrorKind::NotFound);
    assert_eq!(
        error.message,
        "referenced data views do not exist: dv-a, dv-b"
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 5);

    let existing = MockServer::start().await;
    dashboard_capability(&existing).await;
    for id in ["dash-a", "dash-b"] {
        Mock::given(method("GET"))
            .and(path(format!("/api/dashboards/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dashboard(id, id)))
            .expect(1)
            .mount(&existing)
            .await;
    }
    let artifact =
        dashboard_artifact(&[dashboard_spec("dash-b", "B"), dashboard_spec("dash-a", "A")]);
    let error = dashboards_ops::plan_import(Some(&transport(&existing)), &artifact, false, false)
        .await
        .expect_err("default conflict mode refuses every existing id");
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(error.message, "dashboards already exist: dash-a, dash-b");
}

#[tokio::test]
async fn dashboard_import_apply_refuses_create_and_replace_races_without_puts() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-create"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(dashboard("dash-create", "Appeared")),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-replace"))
        .respond_with(ResponseTemplate::new(200).set_body_json(dashboard("dash-replace", "Raced")))
        .expect(1)
        .mount(&server)
        .await;
    let before = dashboard_spec("dash-replace", "Before");
    let plan = dashboard_import_plan(
        vec![
            dashboard_spec("dash-create", "Created"),
            dashboard_spec("dash-replace", "After"),
        ],
        BTreeMap::from([
            ("dash-create".into(), None),
            ("dash-replace".into(), Some(before)),
        ]),
    );

    let report = dashboards_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("per-object race report");

    assert_eq!(
        report.failed,
        vec![
            json!({"id":"dash-create","applied":false,"error":"dashboard appeared since preview"}),
            json!({"id":"dash-replace","applied":false,"error":"dashboard changed since preview"}),
        ]
    );
    assert!(report.succeeded.is_empty());
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .all(|request| request.method != "PUT")
    );
}

#[tokio::test]
async fn dashboard_import_apply_skips_no_op_and_continues_after_a_write_error() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    let no_op = dashboard_spec("dash-no-op", "Same");
    for (id, response) in [
        ("dash-fail", dashboard("dash-fail", "Before")),
        ("dash-no-op", dashboard("dash-no-op", "Same")),
        ("dash-pass", dashboard("dash-pass", "Before")),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/api/dashboards/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("PUT"))
        .and(path("/api/dashboards/dash-fail"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({"message": "request timed out"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/dashboards/dash-pass"))
        .respond_with(ResponseTemplate::new(200).set_body_json(dashboard("dash-pass", "After")))
        .expect(1)
        .mount(&server)
        .await;
    let before_fail = dashboard_spec("dash-fail", "Before");
    let before_pass = dashboard_spec("dash-pass", "Before");
    let plan = dashboard_import_plan(
        vec![
            dashboard_spec("dash-fail", "After"),
            no_op.clone(),
            dashboard_spec("dash-pass", "After"),
        ],
        BTreeMap::from([
            ("dash-fail".into(), Some(before_fail)),
            ("dash-no-op".into(), Some(no_op)),
            ("dash-pass".into(), Some(before_pass)),
        ]),
    );

    let report = dashboards_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("independent targets continue");

    assert_eq!(
        report.succeeded,
        vec![
            json!({"id":"dash-no-op","action":"unchanged"}),
            json!({"id":"dash-pass","action":"replaced"}),
        ]
    );
    assert_eq!(
        report.failed,
        vec![json!({"id":"dash-fail","applied":false,"error":"request timed out"})]
    );
}

#[tokio::test]
async fn dashboard_import_apply_reports_accepted_loss_once_with_get_warnings() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "missing"})))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "dash-1",
            "data": {"title": "Overview", "panels": [{"config": {}}]},
            "meta": {},
            "warnings": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "dash-1",
            "data": {"title": "Overview", "panels": [{"config": {}}]},
            "meta": {},
            "warnings": [{"message": "Unsupported panel property was removed"}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let desired = DashboardSpec::try_from(json!({
        "id": "dash-1",
        "data": {"title": "Overview", "panels": [{"config": {"title": "Count"}}]}
    }))
    .expect("spec");
    let plan = dashboard_import_plan(vec![desired], BTreeMap::from([("dash-1".into(), None)]));

    let report = dashboards_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("loss is a report row");

    assert_eq!(report.succeeded, Vec::<Value>::new());
    assert_eq!(
        report.lossy,
        vec![json!({
            "id":"dash-1",
            "applied":true,
            "paths":["$.panels[0].config.title"],
            "warnings":["Unsupported panel property was removed"]
        })]
    );
    assert!(report.failed.is_empty());
}

#[test]
fn dashboard_import_report_preserves_lossy_field_order() {
    let report = DashboardImportReport {
        applied: true,
        succeeded: Vec::new(),
        skipped: Vec::new(),
        failed: Vec::new(),
        lossy: Vec::new(),
        total: 0,
    };
    assert_eq!(
        serde_json::to_string(&report).expect("serialize"),
        "{\"applied\":true,\"succeeded\":[],\"skipped\":[],\"failed\":[],\"lossy\":[],\"total\":0}"
    );
}

#[tokio::test]
async fn dashboard_delete_plan_resolves_every_selector_deduplicates_ids_and_previews_titles() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(dashboard("dash-1", "Overview")))
        .expect(2)
        .mount(&server)
        .await;

    let plan =
        dashboards_ops::plan_delete(&transport(&server), &["dash-1".into(), "dash-1".into()])
            .await
            .expect("deduplicated delete plan");

    assert_eq!(plan.preview.preview_action, "Delete 1 dashboard(s)");
    assert_eq!(plan.preview.preview_details, vec!["dash-1  Overview"]);
    assert_eq!(plan.preview.targets, vec!["dash-1"]);
    assert_eq!(plan.targets.len(), 1);
}

#[tokio::test]
async fn dashboard_delete_apply_continues_after_an_independent_failure() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    for (id, title) in [("dash-a", "A"), ("dash-b", "B")] {
        Mock::given(method("GET"))
            .and(path(format!("/api/dashboards/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dashboard(id, title)))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("DELETE"))
        .and(path("/api/dashboards/dash-a"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"message": "delete failed"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/dashboards/dash-b"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let plan =
        dashboards_ops::plan_delete(&transport(&server), &["dash-a".into(), "dash-b".into()])
            .await
            .expect("delete plan");

    let report = dashboards_ops::apply_delete(&transport(&server), &plan)
        .await
        .expect("per-object delete report");

    assert_eq!(report.deleted, vec![json!({"id": "dash-b"})]);
    assert_eq!(
        report.failed,
        vec![json!({"id": "dash-a", "error": "delete failed"})]
    );
    assert_eq!(report.total, 2);
}

#[tokio::test]
async fn dashboard_list_refuses_an_empty_nonfinal_page() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [],
            "meta": {"page": 1, "per_page": 1000, "total": 1}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let error = dashboards_ops::list_op(&transport(&server), &DashboardFilter::default())
        .await
        .expect_err("an empty page before total must be malformed");

    assert_eq!(error.kind, ErrorKind::Http);
    assert_eq!(
        error.message,
        "decoding dashboard search: page was short before total"
    );
}

#[tokio::test]
async fn dashboard_resolution_refuses_a_get_with_the_wrong_embedded_id() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-a"))
        .respond_with(ResponseTemplate::new(200).set_body_json(dashboard("dash-b", "Wrong")))
        .expect(1)
        .mount(&server)
        .await;

    let error = dashboards_ops::resolve(&transport(&server), "dash-a")
        .await
        .expect_err("a direct-id GET must identity-check its response");

    assert_eq!(error.kind, ErrorKind::Http);
    assert_eq!(
        error.message,
        "decoding dashboard get: expected id 'dash-a', got 'dash-b'"
    );
}

#[tokio::test]
async fn dashboard_import_preflight_refuses_a_data_view_with_the_wrong_embedded_id() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "missing"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv-a"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data_view": {"id": "dv-b", "title": "logs-*"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let artifact = dashboard_artifact(&[DashboardSpec::try_from(json!({
        "id": "dash-1",
        "data": {"title": "Overview", "source": {"type": "data_view_reference", "ref_id": "dv-a"}}
    }))
    .expect("spec")]);

    let error = dashboards_ops::plan_import(Some(&transport(&server)), &artifact, false, false)
        .await
        .expect_err("reference identity must match its requested id");

    assert_eq!(error.kind, ErrorKind::Http);
    assert_eq!(
        error.message,
        "decoding data view: expected id 'dv-a', got 'dv-b'"
    );
}

#[tokio::test]
async fn dashboard_import_apply_refuses_a_tampered_preview_action_before_http() {
    let server = MockServer::start().await;
    let mut plan = dashboard_import_plan(
        vec![dashboard_spec("dash-1", "Overview")],
        BTreeMap::from([("dash-1".into(), None)]),
    );
    plan.preview.preview_action = "Import 1 dashboard(s) with altered action".into();

    let error = dashboards_ops::apply_import(&transport(&server), &plan)
        .await
        .expect_err("an altered guard preview must refuse before a GET or PUT");

    assert_eq!(error.kind, ErrorKind::Error);
    assert_eq!(
        error.message,
        "preview action does not match pending dashboards"
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn dashboard_bundle_export_resolves_selectors_before_sending_selected_ids() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/Overview"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "missing"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "dash-1", "title": "Overview"}],
            "meta": {"page": 1, "per_page": 1000, "total": 1}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/saved_objects/_export"))
        .and(body_json(json!({
            "objects": [{"type": "dashboard", "id": "dash-1"}],
            "includeReferencesDeep": true,
            "excludeExportDetails": false,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_string(BUNDLE))
        .expect(1)
        .mount(&server)
        .await;

    let outcome = dashboards_ops::export_bundle(&transport(&server), &["Overview".into()])
        .await
        .expect("bundle export");

    assert_eq!(outcome.body, BUNDLE);
    assert_eq!(outcome.exported, 1);
    assert!(outcome.missing.is_empty());
}

#[tokio::test]
async fn dashboard_bundle_export_without_selectors_exports_every_dashboard_not_dependencies() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "dash-1", "title": "Overview"}],
            "meta": {"page": 1, "per_page": 1000, "total": 1}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/saved_objects/_export"))
        .and(body_json(json!({
            "objects": [{"type": "dashboard", "id": "dash-1"}],
            "includeReferencesDeep": true,
            "excludeExportDetails": false,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_string(BUNDLE))
        .expect(1)
        .mount(&server)
        .await;

    let outcome = dashboards_ops::export_bundle(&transport(&server), &[])
        .await
        .expect("export every dashboard");

    assert_eq!(outcome.body, BUNDLE);
    assert_eq!(outcome.exported, 1);
}

#[tokio::test]
async fn dashboard_bundle_export_does_not_send_an_export_after_a_missing_selector() {
    let server = MockServer::start().await;
    dashboard_capability(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "missing"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [],
            "meta": {"page": 1, "per_page": 1000, "total": 0}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let error = dashboards_ops::export_bundle(&transport(&server), &["missing".into()])
        .await
        .expect_err("every selector must resolve before export");

    assert_eq!(error.kind, ErrorKind::NotFound);
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .all(|request| request.url.path() != "/api/saved_objects/_export")
    );
}

#[test]
fn dashboard_bundle_import_plan_preserves_ndjson_and_sorts_only_preview_dashboards() {
    let bundle = concat!(
        r#"{"id":"dash-z","type":"dashboard","attributes":{"title":"Z"}}"#,
        "\r\n",
        "\n",
        r#"{"id":"lens-1","type":"lens","attributes":{}}"#,
        "\r\n",
        r#"{"id":"dash-a","type":"dashboard","attributes":{"title":"A"}}"#,
        "\r\n",
        r#"{"id":"dv-1","type":"index-pattern","attributes":{}}"#,
        "\r\n",
        r#"{"id":"dv-2","type":"index-pattern","attributes":{}}"#,
        "\r\n",
        r#"{"exportedCount":5,"missingRefCount":0,"missingReferences":[]}"#,
        "\r\n",
    );
    let file = tempfile::NamedTempFile::new().expect("bundle file");
    std::fs::write(file.path(), bundle).expect("write bundle");

    let plan: BundleImportPlan =
        dashboards_ops::plan_bundle_import(file.path(), false).expect("bundle plan");

    assert_eq!(plan.ndjson, bundle);
    assert_eq!(plan.scan.dashboards, vec!["dash-z", "dash-a"]);
    assert_eq!(plan.scan.total, 5);
    assert_eq!(
        plan.preview.preview_action,
        "Import 2 dashboard(s) and 3 related saved object(s)"
    );
    assert_eq!(
        plan.preview.preview_details,
        vec![
            "dashboard/dash-a",
            "dashboard/dash-z",
            "index-pattern  2",
            "lens  1",
        ]
    );
    assert_eq!(plan.preview.targets, vec!["dash-z", "dash-a"]);
    assert!(!plan.overwrite);
}

#[test]
fn dashboard_bundle_import_plan_names_overwrite_as_replace() {
    let file = tempfile::NamedTempFile::new().expect("bundle file");
    std::fs::write(file.path(), BUNDLE).expect("write bundle");

    let plan = dashboards_ops::plan_bundle_import(file.path(), true).expect("bundle plan");

    assert_eq!(
        plan.preview.preview_action,
        "Import or replace 1 dashboard(s) and 1 related saved object(s)"
    );
    assert!(plan.overwrite);
}

#[tokio::test]
async fn dashboard_bundle_import_apply_preserves_server_rows_and_uploads_planned_ndjson() {
    let file = tempfile::NamedTempFile::new().expect("bundle file");
    std::fs::write(file.path(), BUNDLE).expect("write bundle");
    let plan = dashboards_ops::plan_bundle_import(file.path(), true).expect("bundle plan");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/saved_objects/_import"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": false,
            "successCount": 1,
            "successResults": [{
                "type": "dashboard",
                "id": "dash-1",
                "created": true,
            }],
            "errors": [{
                "type": "index-pattern",
                "id": "dv-1",
                "error": {"message": "conflict"},
            }],
        })))
        .expect(1)
        .mount(&server)
        .await;

    let outcome = dashboards_ops::apply_bundle_import(&transport(&server), &plan)
        .await
        .expect("bundle import report");

    assert!(outcome.applied);
    assert_eq!(
        outcome.succeeded,
        vec![json!({"type":"dashboard","id":"dash-1","created":true})]
    );
    assert_eq!(
        outcome.failed,
        vec![json!({
            "type":"index-pattern",
            "id":"dv-1",
            "error":{"message":"conflict"},
        })]
    );
    assert_eq!(outcome.total, 2);
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.query(), Some("overwrite=true"));
    assert!(
        String::from_utf8_lossy(&requests[0].body).contains(&plan.ndjson),
        "multipart body must contain the planned opaque input exactly"
    );
}

#[tokio::test]
async fn dashboard_bundle_import_refuses_a_tampered_guard_preview_before_http() {
    let file = tempfile::NamedTempFile::new().expect("bundle file");
    std::fs::write(file.path(), BUNDLE).expect("write bundle");
    let mut plan = dashboards_ops::plan_bundle_import(file.path(), false).expect("bundle plan");
    plan.preview.preview_action = "Import every saved object".into();
    let server = MockServer::start().await;

    let error = dashboards_ops::apply_bundle_import(&transport(&server), &plan)
        .await
        .expect_err("a guard preview must describe the immutable bundle");

    assert_eq!(error.kind, ErrorKind::Error);
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[test]
fn dashboard_bundle_import_outcome_preserves_published_field_order() {
    let outcome = BundleImportOutcome {
        applied: true,
        succeeded: vec![json!({"id": "dash-1"})],
        failed: vec![json!({"id": "dv-1"})],
        total: 2,
    };

    assert_eq!(
        serde_json::to_string(&outcome).expect("serialize outcome"),
        "{\"applied\":true,\"succeeded\":[{\"id\":\"dash-1\"}],\"failed\":[{\"id\":\"dv-1\"}],\"total\":2}"
    );
}
