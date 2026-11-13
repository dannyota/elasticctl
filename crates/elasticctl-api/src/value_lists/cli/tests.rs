use super::*;
use elasticctl_core::{Profile, TransportOptions};
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn fixture(operation: &str) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/traditional-9.5.1/value_lists");
    std::fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            serde_json::from_slice::<Value>(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap()
        })
        .find(|value| value["operation"] == operation)
        .unwrap_or_else(|| panic!("missing {operation}"))
}

fn transport(server: &MockServer) -> Transport {
    Transport::with_options(
        &Profile {
            kibana_url: server.uri(),
            es_url: None,
            api_key: Some("synthetic".into()),
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 2,
        },
        TransportOptions {
            disable_retries: true,
            ..Default::default()
        },
    )
    .unwrap()
}

async fn mount_pair(server: &MockServer, id: &str, container: &str, values: &str) {
    Mock::given(method("GET"))
        .and(path("/api/lists"))
        .and(query_param("id", id))
        .respond_with(ResponseTemplate::new(200).set_body_json(&fixture(container)["response"]))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_export"))
        .and(query_param("list_id", id))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(fixture(values)["response"].as_str().unwrap()),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn get_projects_distinct_values_and_keeps_stored_duplicate_warnings() {
    let server = MockServer::start().await;
    let id = "elasticctl-fixture-value-list-id-3";
    mount_pair(&server, id, "container_read", "items_export").await;
    let report =
        serde_json::to_value(get_op(&transport(&server), id, true).await.unwrap()).unwrap();
    assert_eq!(report["distinct_values"], 3);
    assert_eq!(report["stored_values"], 4);
    assert_eq!(report["warnings"][0]["kind"], "duplicates");
    assert_eq!(
        report["values"],
        json!(["10.0.0.5-10.0.0.5", "10.0.0.6/32", "10.0.0.7/32"])
    );
    assert!(report.get("_version").is_none());
    assert!(report.get("created_by").is_none());
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].url.query().unwrap(), format!("id={id}"));
    assert_eq!(requests[1].url.query().unwrap(), format!("list_id={id}"));
    assert!(requests.iter().all(|request| request.body.is_empty()));
}

#[tokio::test]
async fn export_refuses_all_existing_destinations_without_fetching_or_writing() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    for extension in ["yaml", "txt"] {
        std::fs::write(dir.path().join(format!("taken.{extension}")), "unchanged").unwrap();
    }
    let error = export_op(
        &transport(&server),
        &["first".into(), "taken".into()],
        Some(dir.path()),
        false,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert!(error.message.contains("taken.yaml") && error.message.contains("taken.txt"));
    assert!(!dir.path().join("first.yaml").exists());
    assert!(!dir.path().join("first.txt").exists());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn export_writes_canonical_pairs_for_multiple_ids_in_id_order() {
    let server = MockServer::start().await;
    let first = "elasticctl-fixture-value-list-id-14";
    let second = "elasticctl-fixture-value-list-id-3";
    mount_pair(&server, first, "contain_create", "contain_export").await;
    mount_pair(&server, second, "container_read", "items_export").await;
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("new");
    let ExportReport::Files(files) = export_op(
        &transport(&server),
        &[second.into(), first.into()],
        Some(&destination),
        true,
        None,
    )
    .await
    .unwrap() else {
        panic!("expected files");
    };
    assert_eq!(
        files
            .iter()
            .map(|file| file.id.as_str())
            .collect::<Vec<_>>(),
        [first, second]
    );
    assert_eq!(
        std::fs::read_to_string(destination.join(format!("{first}.txt"))).unwrap(),
        "10.0.0.0/8\n10.0.0.5/32\n"
    );
    assert_eq!(
        std::fs::read_to_string(destination.join(format!("{second}.txt"))).unwrap(),
        "10.0.0.5-10.0.0.5\n10.0.0.6/32\n10.0.0.7/32\n"
    );
    let pair = read_pair(&files[1].container).unwrap();
    assert_eq!(pair.container.id, second);
    assert_eq!(pair.values.len(), 3);
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
}

#[tokio::test]
async fn export_injected_http_fault_on_a_later_read_writes_nothing() {
    let server = MockServer::start().await;
    let first = "elasticctl-fixture-value-list-id-14";
    let second = "elasticctl-fixture-value-list-id-3";
    mount_pair(&server, first, "contain_create", "contain_export").await;
    Mock::given(method("GET"))
        .and(path("/api/lists"))
        .and(query_param("id", second))
        .respond_with(
            ResponseTemplate::new(503).set_body_json(&fixture("container_read")["response"]),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    assert!(
        export_op(
            &transport(&server),
            &[first.into(), second.into()],
            Some(dir.path()),
            false,
            None,
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn validate_path_rejects_a_missing_sibling() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("example.yaml");
    std::fs::write(
        &path,
        "id: example\ntype: keyword\nname: Example\ndescription: Example list\n",
    )
    .unwrap();
    assert!(validate_path(&path).is_err());
}

#[test]
fn import_preview_marks_no_value_phases_and_lists_every_change_in_byte_order() {
    let container =
        crate::value_lists::decode_remote_container(&fixture("container_read")["response"])
            .unwrap();
    let local = crate::value_lists::LocalPair {
        stem: container.container.id.clone(),
        container: container.container.clone(),
        values: ["10.0.0.9/32".into(), "10.0.0.8/32".into()].into(),
    };
    let plan = crate::value_lists::plan_list(local.clone(), None, &[], &[]).unwrap();
    let report = serde_json::to_value(ImportPreview::from(&plan)).unwrap();
    assert_eq!(report["container_action"], "create");
    assert_eq!(report["adds"], json!(["10.0.0.8/32", "10.0.0.9/32"]));
    assert_eq!(report["removes"], json!([]));
    let before = crate::value_lists::RemoteList {
        container,
        stored: StoredValues::new(local.values.iter().cloned().collect()),
    };
    let plan = crate::value_lists::plan_list(local, Some(before), &[], &[]).unwrap();
    assert_eq!(
        serde_json::to_value(ImportPreview::from(&plan)).unwrap()["phase_order"],
        "none"
    );
}
