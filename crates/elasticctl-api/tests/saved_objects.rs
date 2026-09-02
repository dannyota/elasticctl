use elasticctl_api::saved_objects::{self, SavedObjectsImportReport};
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::json;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BUNDLE: &str = concat!(
    r#"{"id":"dv-1","type":"index-pattern","attributes":{"title":"logs-*"},"references":[]}"#,
    "\n",
    r#"{"id":"dash-1","type":"dashboard","attributes":{"title":"Overview"},"references":[{"id":"dv-1","type":"index-pattern","name":"indexpattern"}]}"#,
    "\n",
    r#"{"exportedCount":2,"missingRefCount":0,"missingReferences":[]}"#,
    "\n",
);

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

fn transport(server: &MockServer) -> Transport {
    Transport::new(&profile_for(server)).expect("transport")
}

#[test]
fn scan_counts_objects_without_rewriting_the_bundle() {
    let scan = saved_objects::scan_bundle(BUNDLE).expect("scan");
    assert_eq!(scan.dashboards, vec!["dash-1"]);
    assert_eq!(scan.counts["dashboard"], 1);
    assert_eq!(scan.counts["index-pattern"], 1);
    assert_eq!(scan.total, 2);
    assert!(scan.has_export_details);
}

#[test]
fn scan_rejects_an_invalid_json_line() {
    let error = saved_objects::scan_bundle("not json\n").expect_err("invalid JSON");
    assert_eq!(error.kind, ErrorKind::Error);
    assert!(error.message.contains("line 1"), "{error}");
}

#[test]
fn scan_rejects_a_saved_object_without_type_or_id() {
    for bundle in [r#"{"id":"dash-1"}"#, r#"{"type":"dashboard"}"#] {
        let error = saved_objects::scan_bundle(bundle).expect_err("identity is required");
        assert_eq!(error.kind, ErrorKind::Error);
    }
}

#[test]
fn scan_rejects_export_details_that_are_not_last_or_unique() {
    let trailer = r#"{"exportedCount":1,"missingRefCount":0,"missingReferences":[]}"#;
    for bundle in [
        format!("{trailer}\n{{\"id\":\"dash-1\",\"type\":\"dashboard\"}}\n"),
        format!("{{\"id\":\"dash-1\",\"type\":\"dashboard\"}}\n{trailer}\n{trailer}\n"),
    ] {
        let error = saved_objects::scan_bundle(&bundle).expect_err("invalid trailer placement");
        assert_eq!(error.kind, ErrorKind::Error);
    }
}

#[test]
fn scan_rejects_a_bundle_without_a_dashboard_or_valid_trailer_counters() {
    for bundle in [
        r#"{"id":"dv-1","type":"index-pattern"}"#,
        r#"{"id":"dash-1","type":"dashboard"}
{"exportedCount":"1","missingRefCount":0,"missingReferences":[]}"#,
    ] {
        let error = saved_objects::scan_bundle(bundle).expect_err("invalid bundle");
        assert_eq!(error.kind, ErrorKind::Error);
    }
}

#[tokio::test]
async fn export_sorts_and_deduplicates_dashboard_ids_without_changing_response_bytes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/saved_objects/_export"))
        .and(body_json(json!({
            "objects": [
                {"type": "dashboard", "id": "dash-1"},
                {"type": "dashboard", "id": "dash-2"}
            ],
            "includeReferencesDeep": true,
            "excludeExportDetails": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_string(BUNDLE))
        .expect(1)
        .mount(&server)
        .await;

    let exported = saved_objects::export(
        &transport(&server),
        &["dash-2".into(), "dash-1".into(), "dash-1".into()],
    )
    .await
    .expect("export");

    assert_eq!(exported, BUNDLE);
}

#[tokio::test]
async fn import_uploads_the_opaque_bundle_with_the_dashboard_filename_and_overwrite_choice() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/saved_objects/_import"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "successCount": 1,
            "successResults": [{"type": "dashboard", "id": "dash-1"}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let report = saved_objects::import(&transport(&server), BUNDLE, false)
        .await
        .expect("import");
    assert_eq!(
        report,
        SavedObjectsImportReport {
            success: true,
            success_count: 1,
            success_results: vec![json!({"type": "dashboard", "id": "dash-1"})],
            errors: vec![],
        }
    );
    let requests = server.received_requests().await.expect("requests");
    let request = &requests[0];
    assert_eq!(request.url.query(), Some("overwrite=false"));
    let body = String::from_utf8_lossy(&request.body);
    assert!(body.contains("filename=\"dashboards.ndjson\""));
    assert!(body.contains(BUNDLE));
}

#[tokio::test]
async fn import_rejects_a_malformed_success_envelope() {
    for body in [
        json!({"successCount": 0, "successResults": [], "errors": []}),
        json!({"success": true, "successCount": "0", "successResults": [], "errors": []}),
        json!({"success": true, "successCount": 1, "successResults": [], "errors": []}),
        json!({"success": true, "successCount": 0, "successResults": [], "errors": [{}]}),
        json!({"success": false, "successCount": 0, "successResults": [], "errors": []}),
        json!({"success": true, "successCount": 0, "successResults": {}, "errors": []}),
        json!({"success": true, "successCount": 0, "successResults": [], "errors": {}}),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/saved_objects/_import"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let error = saved_objects::import(&transport(&server), BUNDLE, true)
            .await
            .expect_err("malformed response");
        assert_eq!(error.kind, ErrorKind::Http, "{error}");
    }
}
