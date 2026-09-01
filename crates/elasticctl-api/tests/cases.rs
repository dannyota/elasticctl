use elasticctl_api::cases::{self, CaseStatus, NewCase};
use elasticctl_api::cases_ops::{self, CaseFilter};
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

/// `case_row`'s key order is the rendered table-column contract
/// (`preserve_order`, spec — see `cases_ops::case_row`'s own doc comment):
/// reordering the struct's `insert` calls would silently reorder every
/// `cases list` column.
#[test]
fn case_row_emits_its_columns_in_the_documented_order() {
    let case = cases::decode_case(&case_body("c1", "open")).expect("decode");
    let row = cases_ops::case_row(&case);
    let keys: Vec<&str> = row
        .as_object()
        .expect("case_row returns an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        vec![
            "id",
            "title",
            "status",
            "severity",
            "tags",
            "comments",
            "created_at",
            "updated_at",
        ],
        "case_row key order is the rendered `cases list` column order"
    );
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

/// Finding 8: `Some("")` (an explicit but empty `--description`) defeats the
/// documented title fallback — `Option::unwrap_or_else` only fires on
/// `None`, so an empty string is sent as-is and the server 400s on minimum
/// length. Whitespace-only text must fall back too, not just the empty
/// string.
#[tokio::test]
async fn create_falls_back_to_the_title_when_description_is_empty_or_blank() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/cases"))
        .and(body_json(json!({
            "title": "T", "description": "T", "tags": [],
            "assignees": [],
            "connector": {"id": "none", "name": "none", "type": ".none", "fields": null},
            "settings": {"syncAlerts": false},
            "owner": "securitySolution"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c9", "open")))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    for description in [Some(String::new()), Some("   ".into())] {
        cases::create(
            &t,
            &NewCase {
                title: "T".into(),
                description,
                tags: vec![],
                severity: None,
                assignee_uids: vec![],
            },
        )
        .await
        .expect("create");
    }
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

#[test]
fn find_query_composes_all_filters_deterministically() {
    let f = CaseFilter {
        status: Some(CaseStatus::InProgress),
        severity: Some("high".into()),
        tag: Some("triage".into()),
        search: Some("power shell".into()),
    };
    assert_eq!(
        cases_ops::find_query(&f, 2, 100),
        "page=2&perPage=100&sortField=createdAt&sortOrder=desc\
         &status=in-progress&severity=high&tags=triage\
         &search=power%20shell&searchFields=title&searchFields=description"
    );
    assert_eq!(
        cases_ops::find_query(&CaseFilter::default(), 1, 100),
        "page=1&perPage=100&sortField=createdAt&sortOrder=desc"
    );
}

#[tokio::test]
async fn list_pages_until_the_limit_and_reports_truncation() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cases": [case_body("c1", "open"), case_body("c2", "open")],
            "page": 1, "per_page": 100, "total": 5
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let out = cases_ops::list(&t, &CaseFilter::default(), 1)
        .await
        .expect("list");
    assert!(out.truncated);
    assert_eq!(out.cases.len(), 1);
    assert_eq!(out.total, 5);
}

#[tokio::test]
async fn export_follows_pages_to_the_end() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cases": [case_body("c3", "open")], "page": 2, "per_page": 100, "total": 3
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cases": [case_body("c1", "open"), case_body("c2", "open")],
            "page": 1, "per_page": 100, "total": 3
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let all = cases_ops::export_with_page_size(&t, &CaseFilter::default(), 2, None)
        .await
        .expect("export");
    assert_eq!(all.len(), 3);
    assert_eq!(all[2].id, "c3");
}

/// A `--limit` that is satisfied within the first page must stop paging: no
/// page-2 mock is mounted, so a second request fails the test.
#[tokio::test]
async fn export_stops_paging_once_the_limit_is_in_hand() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cases": [case_body("c1", "open"), case_body("c2", "open")],
            "page": 1, "per_page": 100, "total": 5
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let all = cases_ops::export(&t, &CaseFilter::default(), Some(1))
        .await
        .expect("export");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, "c1");
}

#[tokio::test]
async fn plan_status_fetches_versions_and_marks_noops() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/cases/c1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c1", "open")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/cases/c2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c2", "closed")))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let plan = cases_ops::plan_status(&t, &["c1".into(), "c2".into()], CaseStatus::Closed)
        .await
        .expect("plan");
    assert_eq!(plan.preview_action, "Close 2 cases");
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
    // Only the case actually transitioning is PATCHed.
    assert_eq!(plan.updates.len(), 1);
    assert_eq!(plan.updates[0].0, "c1");
}

#[tokio::test]
async fn a_missing_case_id_refuses_the_whole_set() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/cases/c1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c1", "open")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/cases/ghost"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "statusCode": 404, "error": "Not Found", "message": "case not found"
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let err = cases_ops::plan_status(&t, &["c1".into(), "ghost".into()], CaseStatus::Closed)
        .await
        .expect_err("partial resolution must refuse");
    assert_eq!(err.kind, elasticctl_core::ErrorKind::NotFound);
    assert!(err.message.contains("ghost"), "{}", err.message);
}

#[tokio::test]
async fn a_stale_version_conflict_names_the_remedy() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/cases"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "statusCode": 409, "error": "Conflict", "message": "version mismatch"
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let plan = cases_ops::StatusPlan {
        target: CaseStatus::Closed,
        updates: vec![("c1".into(), "stale".into(), CaseStatus::Closed)],
        resolved: 1,
        preview_action: "Close 1 case".into(),
        preview_details: vec![],
    };
    let err = cases_ops::apply_status(&t, &plan).await.expect_err("409");
    assert_eq!(err.kind, elasticctl_core::ErrorKind::Conflict);
    assert!(
        err.message.contains("re-run"),
        "the remediation names the fix: {}",
        err.message
    );
}

/// `CaseEditReport::failed` is the exit-code seam: `render::exit_code_for_value`
/// keys on a positive `failed` count to exit 1, so a PATCH response short of
/// what was sent must be visible in the report, not just in `updated`.
#[tokio::test]
async fn apply_status_reports_zero_failed_on_a_full_patch_and_the_shortfall_otherwise() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/cases"))
        .and(body_json(json!({"cases": [
            {"id": "c1", "version": "WzEsMV0=", "status": "closed"},
            {"id": "c2", "version": "WzEsMV0=", "status": "closed"},
        ]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            case_body("c1", "closed"),
            case_body("c2", "closed"),
        ])))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let full_plan = cases_ops::StatusPlan {
        target: CaseStatus::Closed,
        updates: vec![
            ("c1".into(), "WzEsMV0=".into(), CaseStatus::Closed),
            ("c2".into(), "WzEsMV0=".into(), CaseStatus::Closed),
        ],
        resolved: 2,
        preview_action: "Close 2 cases".into(),
        preview_details: vec![],
    };
    let report = cases_ops::apply_status(&t, &full_plan)
        .await
        .expect("apply");
    assert_eq!(report.total, 2);
    assert_eq!(report.updated, 2);
    assert_eq!(report.failed, 0, "a full response leaves nothing failed");

    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/cases"))
        .and(body_json(json!({"cases": [
            {"id": "c1", "version": "WzEsMV0=", "status": "closed"},
            {"id": "c2", "version": "WzEsMV0=", "status": "closed"},
        ]})))
        // Server-side reality: only one of the two requested cases came
        // back updated, with no error surfaced elsewhere in the exchange.
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([case_body("c1", "closed")])))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let report = cases_ops::apply_status(&t, &full_plan)
        .await
        .expect("apply");
    assert_eq!(report.total, 2);
    assert_eq!(report.updated, 1);
    assert_eq!(
        report.failed, 1,
        "a short response must surface the shortfall as failed, since \
         render::exit_code_for_value keys on `failed` to choose the exit code"
    );

    // Finding 10: `saturating_sub` reads a surplus response (three cases
    // returned for a two-case PATCH) as zero failures, since `total -
    // updated` saturates at 0 when `updated > total`. The mismatch itself is
    // the anomaly to surface, in either direction.
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/cases"))
        .and(body_json(json!({"cases": [
            {"id": "c1", "version": "WzEsMV0=", "status": "closed"},
            {"id": "c2", "version": "WzEsMV0=", "status": "closed"},
        ]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            case_body("c1", "closed"),
            case_body("c2", "closed"),
            case_body("c3", "closed"),
        ])))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let report = cases_ops::apply_status(&t, &full_plan)
        .await
        .expect("apply");
    assert_eq!(report.total, 2);
    assert_eq!(report.updated, 3);
    assert_eq!(
        report.failed, 1,
        "a surplus response is a mismatch too, not zero failures"
    );
}

#[tokio::test]
async fn plan_delete_names_every_title() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/cases/c1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c1", "open")))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let plan = cases_ops::plan_delete(&t, &["c1".into()])
        .await
        .expect("plan");
    assert_eq!(plan.preview_action, "Delete 1 case permanently");
    assert!(
        plan.preview_details[0].contains("Suspicious activity"),
        "{:?}",
        plan.preview_details
    );
}

#[tokio::test]
async fn plan_attach_groups_alerts_by_rule() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/cases/c1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c1", "open")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 2, "relation": "eq"}, "hits": [
                {"_id": "a1", "_index": "idx-a",
                 "_source": {"kibana.alert.rule.name": "Alpha", "kibana.alert.rule.uuid": "ru-1",
                             "kibana.alert.workflow_status": "open"}},
                {"_id": "a2", "_index": "idx-a",
                 "_source": {"kibana.alert.rule.name": "Beta", "kibana.alert.rule.uuid": "ru-2",
                             "kibana.alert.workflow_status": "open"}}
            ]}
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let plan = cases_ops::plan_attach(&t, "c1", &["a1".into(), "a2".into()])
        .await
        .expect("plan");
    assert_eq!(
        plan.preview_action,
        "Attach 2 alerts to case 'Suspicious activity'"
    );
    assert_eq!(plan.groups.len(), 2, "two rules, two comment groups");
    assert_eq!(plan.groups[0].rule_name, "Alpha");
    assert_eq!(plan.groups[0].indices, vec!["idx-a".to_string()]);
}

/// Finding 5: `apply_attach` POSTs one comment per rule group with `?`
/// propagation, so when the second of two groups fails, the first group's
/// alerts are already attached but the command exits with only the raw
/// error — a retry would double-attach the first group. `apply_attach` must
/// accumulate per-group outcomes instead: the count of already-attached
/// groups still renders, and the failure is visible through `failed`, not
/// swallowed by an early `?`.
#[tokio::test]
async fn apply_attach_reports_a_partial_failure_instead_of_discarding_it() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/cases/c1/comments"))
        .and(body_json(json!({
            "type": "alert",
            "alertId": ["a1"],
            "index": ["idx-a"],
            "rule": {"id": "ru-1", "name": "Alpha"},
            "owner": "securitySolution"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(case_body("c1", "open")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/cases/c1/comments"))
        .and(body_json(json!({
            "type": "alert",
            "alertId": ["a2"],
            "index": ["idx-a"],
            "rule": {"id": "ru-2", "name": "Beta"},
            "owner": "securitySolution"
        })))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "message": "attach failed"
        })))
        .mount(&server)
        .await;
    let t = test_transport(&server.uri());
    let plan = cases_ops::AttachPlan {
        case_id: "c1".into(),
        groups: vec![
            cases_ops::AttachGroup {
                rule_id: "ru-1".into(),
                rule_name: "Alpha".into(),
                alert_ids: vec!["a1".into()],
                indices: vec!["idx-a".into()],
            },
            cases_ops::AttachGroup {
                rule_id: "ru-2".into(),
                rule_name: "Beta".into(),
                alert_ids: vec!["a2".into()],
                indices: vec!["idx-a".into()],
            },
        ],
        resolved: 2,
        preview_action: "Attach 2 alerts to case 'Suspicious activity'".into(),
        preview_details: vec![],
    };
    let report = cases_ops::apply_attach(&t, &plan)
        .await
        .expect("a partial failure is a report, not an error");
    assert_eq!(report.total, 2);
    assert_eq!(report.updated, 1, "the first group did attach");
    assert_eq!(
        report.failed, 1,
        "the second group's failure must be visible"
    );
}

#[tokio::test]
async fn plan_create_resolves_assignees_and_previews_them() {
    let t = test_transport("http://127.0.0.1:1");
    let plan = cases_ops::plan_create(
        &t,
        "Incident 7",
        None,
        vec!["triage".into()],
        Some("high".into()),
        &["uid:u_9".into()],
    )
    .await
    .expect("plan");
    assert_eq!(plan.preview_action, "Create case 'Incident 7'");
    assert!(
        plan.preview_details
            .iter()
            .any(|d| d.contains("assign uid:u_9 -> u_9")),
        "{:?}",
        plan.preview_details
    );
    assert_eq!(plan.new.assignee_uids, vec!["u_9".to_string()]);
}
