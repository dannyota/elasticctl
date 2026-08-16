//! End-to-end tests for the `exceptions` command group against a mock stack.
//! The endpoint wrappers are covered in `elasticctl-api`; these tests cover the
//! CLI's guard, refusal, namespace, and raw-stdout contracts.

use assert_cmd::Command;
use elasticctl_api_test_support::MockStack;
use serde_json::{Value, json};
use std::process::Output;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

mod common;

async fn mock_exception_lists(n: usize) -> MockStack {
    MockStack::with_exception_lists(n).await
}

async fn verified_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.5.1", "build_flavor": "traditional"}
        })))
        .mount(&server)
        .await;
    server
}

/// Run the binary against a mock server with a profile pointing at its URI.
async fn run(uri: &str, args: &[&str]) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config_for(dir.path(), uri);
    Command::cargo_bin("elasticctl")
        .unwrap()
        .arg("--config")
        .arg(&cfg)
        .args(args)
        .output()
        .unwrap()
}

fn uploaded_ndjson(request: &Request) -> String {
    let body = String::from_utf8(request.body.clone()).unwrap();
    let start = body.find("\r\n\r\n").expect("multipart headers") + 4;
    let end = body.rfind("\r\n--").expect("multipart closing boundary");
    body[start..end].to_string()
}

#[tokio::test]
async fn list_forwards_type_tag_and_namespace_filters() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{
                "id": "id-prod",
                "list_id": "prod-list",
                "type": "detection",
                "name": "Production",
                "namespace_type": "agnostic",
                "tags": ["prod"]
            }],
            "page": 1,
            "per_page": 1,
            "total": 1
        })))
        .mount(&server)
        .await;

    let out = run(
        &server.uri(),
        &[
            "exceptions",
            "list",
            "--type",
            "detection",
            "--tag",
            "prod",
            "--namespace",
            "agnostic",
            "--json",
        ],
    )
    .await;

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report.as_array().unwrap().len(), 1);
    assert_eq!(report[0]["list_id"], "prod-list");
    assert_eq!(report[0]["namespace_type"], "agnostic");
    let requests = server.received_requests().await.unwrap();
    let find = requests
        .iter()
        .find(|request| request.url.path() == "/api/exception_lists/_find")
        .unwrap();
    let query: std::collections::BTreeMap<_, _> = find.url.query_pairs().into_owned().collect();
    assert_eq!(query["namespace_type"], "agnostic");
    assert_eq!(
        query["filter"],
        "exception-list-agnostic.attributes.type: \"detection\" AND exception-list-agnostic.attributes.tags: \"prod\""
    );
}

#[tokio::test]
async fn list_forwards_search_as_a_name_substring_filter() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{
                "id": "id-sub",
                "list_id": "sub-list",
                "type": "detection",
                "name": "Subdomain List",
                "namespace_type": "single",
                "tags": []
            }],
            "page": 1,
            "per_page": 1,
            "total": 1
        })))
        .mount(&server)
        .await;

    let out = run(
        &server.uri(),
        &[
            "exceptions",
            "list",
            "--search",
            "Subdomain",
            "--namespace",
            "single",
            "--json",
        ],
    )
    .await;

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report.as_array().unwrap().len(), 1);
    assert_eq!(report[0]["list_id"], "sub-list");
    let requests = server.received_requests().await.unwrap();
    let find = requests
        .iter()
        .find(|request| request.url.path() == "/api/exception_lists/_find")
        .unwrap();
    let query: std::collections::BTreeMap<_, _> = find.url.query_pairs().into_owned().collect();
    assert_eq!(
        query["filter"],
        "exception-list.attributes.name: \"*Subdomain*\""
    );
}

#[test]
fn validate_is_offline_and_counts_lists_and_items() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("exceptions.ndjson");
    std::fs::write(
        &path,
        concat!(
            "{\"list_id\":\"l0\",\"type\":\"detection\",\"name\":\"L0\",\"namespace_type\":\"single\"}\n",
            "{\"item_id\":\"i0\",\"list_id\":\"l0\",\"type\":\"simple\",\"name\":\"I0\",\"namespace_type\":\"single\",\"entries\":[]}\n",
        ),
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["exceptions", "validate", "--path"])
        .arg(&path)
        .arg("--json")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report, json!({"valid": true, "lists": 1, "items": 1}));
}

/// Spec 4.3, applied to lists: an empty selection is never widened.
#[tokio::test]
async fn delete_with_a_selector_that_matches_nothing_is_refused() {
    let stack = mock_exception_lists(0).await;
    let out = run(&stack.uri(), &["exceptions", "delete", "absent", "--yes"]).await;
    assert_eq!(out.status.code(), Some(1));
    let err: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(err["error"]["kind"], "not_found");
    assert!(
        err["error"]["message"].as_str().unwrap().contains("absent"),
        "the refusal must name the selector"
    );
}

/// Every exception mutation previews first. Spec 6.1.
#[tokio::test]
async fn delete_without_yes_previews_and_changes_nothing() {
    let stack = mock_exception_lists(1).await;
    let out = run(&stack.uri(), &["exceptions", "delete", "l0"]).await;
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(text.contains("[DRY RUN]"), "{text}");
    assert!(stack.write_requests().await.is_empty());
}

/// Repeated selectors describe one list identity, so an apply must issue one
/// deletion and report one target rather than failing a duplicate second call.
#[tokio::test]
async fn delete_deduplicates_repeated_qualified_selectors() {
    let stack = mock_exception_lists(1).await;
    let out = run(
        &stack.uri(),
        &[
            "exceptions",
            "delete",
            "l0",
            "l0",
            "--namespace",
            "single",
            "--yes",
            "--json",
        ],
    )
    .await;

    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["total"], 1);
    assert_eq!(stack.deleted_list_ids().await, vec!["l0"]);
}

/// Spec 6.2: a file-producing command's stdout is the file.
#[tokio::test]
async fn export_without_out_writes_importable_ndjson_to_stdout() {
    let stack = mock_exception_lists(1).await;
    let out = run(&stack.uri(), &["exceptions", "export", "l0", "--json"]).await;
    let body = String::from_utf8(out.stdout).unwrap();
    assert!(
        !body.trim_start().starts_with("{\"ndjson\""),
        "--json must not wrap a file body"
    );
    let bundle = elasticctl_api::codec::decode_bundle(&body).expect("stdout must be importable");
    assert_eq!(
        bundle.lists.len(),
        1,
        "stdout must carry the exported container, not an empty body: {body}"
    );
}

/// A list can disappear after its live ID is resolved. The partial response is
/// still a file, but its trailer must make both export modes fail visibly.
#[tokio::test]
async fn a_deleted_exception_list_writes_the_partial_file_and_exits_one() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists"))
        .and(query_param("list_id", "l0"))
        .and(query_param("namespace_type", "single"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "id-l0",
            "list_id": "l0",
            "type": "detection",
            "name": "L0",
            "namespace_type": "single",
            "tags": ["sample"],
        })))
        .mount(&server)
        .await;
    let trailer = concat!(
        r#"{"exported_exception_list_count":0,"exported_exception_list_item_count":0,"missing_exception_lists":[{"reason":"deleted"}],"missing_exception_list_items":[]}"#,
        "\n"
    );
    Mock::given(method("POST"))
        .and(path("/api/exception_lists/_export"))
        .respond_with(ResponseTemplate::new(200).set_body_string(trailer))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config_for(dir.path(), &server.uri());
    let file = dir.path().join("partial.ndjson");
    let with_out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["exceptions", "export", "l0", "--json", "--config"])
        .arg(&cfg)
        .arg("--out")
        .arg(&file)
        .output()
        .unwrap();

    assert_eq!(with_out.status.code(), Some(1));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), trailer);
    let report: Value = serde_json::from_slice(&with_out.stdout).unwrap();
    assert_eq!(report["exported"], 0);
    assert_eq!(report["failed"][0]["list_id"], "l0");
    assert_eq!(report["failed"][0]["namespace_type"], "single");

    let to_stdout = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["exceptions", "export", "l0", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();

    assert_eq!(to_stdout.status.code(), Some(1));
    assert_eq!(String::from_utf8(to_stdout.stdout).unwrap(), trailer);
}

/// Spec 4.5: the same `list_id` in both namespaces is a supported configuration.
/// A bare `list_id` must be refused with a conflict naming `--namespace`, and
/// resolved when the flag qualifies it.
#[tokio::test]
async fn a_list_id_in_both_namespaces_needs_the_namespace_flag() {
    let server = verified_server().await;
    for ns in ["single", "agnostic"] {
        Mock::given(method("GET"))
            .and(path("/api/exception_lists"))
            .and(query_param("list_id", "l0"))
            .and(query_param("namespace_type", ns))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": format!("id-{ns}"),
                "list_id": "l0",
                "type": "detection",
                "name": "L0",
                "namespace_type": ns,
            })))
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/items/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [], "page": 1, "per_page": 10000, "total": 0
        })))
        .mount(&server)
        .await;

    // Without --namespace: refused, naming the remedy.
    let out = run(&server.uri(), &["exceptions", "get", "l0"]).await;
    assert_eq!(out.status.code(), Some(1));
    let err: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(err["error"]["kind"], "conflict");
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--namespace"),
        "the refusal must name the remedy: {}",
        err["error"]["message"]
    );

    // With --namespace: resolved to the named namespace.
    let out = run(
        &server.uri(),
        &[
            "exceptions",
            "get",
            "l0",
            "--namespace",
            "agnostic",
            "--json",
        ],
    )
    .await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["list"]["namespace_type"], "agnostic");
}

#[tokio::test]
async fn a_partial_import_failure_exits_one_and_keeps_valid_ndjson() {
    let server = verified_server().await;
    Mock::given(method("POST"))
        .and(path("/api/exception_lists/_import"))
        .and(query_param("overwrite", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": false,
            "success_count": 1,
            "errors": [{
                "list_id": "rejected",
                "namespace_type": "single",
                "error": {"status_code": 409, "message": "already exists"}
            }]
        })))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("import.ndjson");
    std::fs::write(
        &path,
        concat!(
            "{\"list_id\":\"accepted\",\"type\":\"detection\",\"name\":\"Accepted\",\"namespace_type\":\"single\"}\n",
            "{\"list_id\":\"rejected\",\"type\":\"detection\",\"name\":\"Rejected\",\"namespace_type\":\"single\"}\n",
        ),
    )
    .unwrap();
    let cfg = common::config_for(dir.path(), &server.uri());

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["exceptions", "import", "--path"])
        .arg(&path)
        .args(["--yes", "--json", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["succeeded"], 1);
    assert_eq!(report["failed"][0]["list_id"], "rejected");
    assert_eq!(report["failed"][0]["namespace_type"], "single");
    let requests = server.received_requests().await.unwrap();
    let upload = requests
        .iter()
        .find(|request| request.url.path() == "/api/exception_lists/_import")
        .unwrap();
    let ndjson = uploaded_ndjson(upload);
    let bundle = elasticctl_api::codec::decode_bundle(&ndjson).unwrap();
    assert_eq!(bundle.lists.len(), 2);
    assert!(bundle.items.is_empty());
}

#[tokio::test]
async fn skip_existing_uploads_only_the_absent_list_and_its_items() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists"))
        .and(query_param("list_id", "existing"))
        .and(query_param("namespace_type", "single"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "id-existing",
            "list_id": "existing",
            "type": "detection",
            "name": "Existing",
            "namespace_type": "single"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/exception_lists/_import"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "success_count": 2,
            "errors": []
        })))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("import.ndjson");
    std::fs::write(
        &path,
        concat!(
            "{\"list_id\":\"existing\",\"type\":\"detection\",\"name\":\"Existing\",\"namespace_type\":\"single\"}\n",
            "{\"item_id\":\"old-item\",\"list_id\":\"existing\",\"type\":\"simple\",\"name\":\"Old\",\"namespace_type\":\"single\",\"entries\":[]}\n",
            "{\"list_id\":\"absent\",\"type\":\"detection\",\"name\":\"Absent\",\"namespace_type\":\"single\"}\n",
            "{\"item_id\":\"new-item\",\"list_id\":\"absent\",\"type\":\"simple\",\"name\":\"New\",\"namespace_type\":\"single\",\"entries\":[]}\n",
        ),
    )
    .unwrap();
    let cfg = common::config_for(dir.path(), &server.uri());

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["exceptions", "import", "--path"])
        .arg(&path)
        .args(["--skip-existing", "--yes", "--json", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["succeeded"], 2);
    assert_eq!(report["skipped"].as_array().unwrap().len(), 1);
    assert_eq!(report["skipped"][0]["list_id"], "existing");
    assert_eq!(report["total"], 4);
    let requests = server.received_requests().await.unwrap();
    let upload = requests
        .iter()
        .find(|request| request.url.path() == "/api/exception_lists/_import")
        .unwrap();
    let ndjson = uploaded_ndjson(upload);
    let bundle = elasticctl_api::codec::decode_bundle(&ndjson).unwrap();
    assert_eq!(bundle.lists.len(), 1);
    assert_eq!(bundle.lists[0].list_id().unwrap(), "absent");
    assert_eq!(bundle.items.len(), 1);
    assert_eq!(bundle.items[0].item_id().unwrap(), "new-item");
}

#[tokio::test]
async fn a_qualified_delete_failure_keeps_the_full_identity() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists"))
        .and(query_param("list_id", "l0"))
        .and(query_param("namespace_type", "agnostic"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "id-l0",
            "list_id": "l0",
            "type": "detection",
            "name": "L0",
            "namespace_type": "agnostic"
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/exception_lists"))
        .and(query_param("list_id", "l0"))
        .and(query_param("namespace_type", "agnostic"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "message": "delete failed"
        })))
        .mount(&server)
        .await;

    let out = run(
        &server.uri(),
        &[
            "exceptions",
            "delete",
            "l0",
            "--namespace",
            "agnostic",
            "--yes",
            "--json",
        ],
    )
    .await;

    assert_eq!(out.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["failed"][0]["list_id"], "l0");
    assert_eq!(report["failed"][0]["namespace_type"], "agnostic");
}
