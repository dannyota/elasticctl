//! End-to-end tests for the `exceptions` command group against a mock stack.
//! The endpoint wrappers are covered in `elasticctl-api`; these tests cover the
//! CLI's guard, refusal, namespace, and raw-stdout contracts.

use assert_cmd::Command;
use elasticctl_api_test_support::MockStack;
use serde_json::{Value, json};
use std::process::Output;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;

async fn mock_exception_lists(n: usize) -> MockStack {
    MockStack::with_exception_lists(n).await
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

/// Every mutation previews first. Spec 6.1.
#[tokio::test]
async fn delete_without_yes_previews_and_changes_nothing() {
    let stack = mock_exception_lists(1).await;
    let out = run(&stack.uri(), &["exceptions", "delete", "l0"]).await;
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(text.contains("[DRY RUN]"), "{text}");
    assert!(stack.write_requests().await.is_empty());
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

/// Spec 4.5: the same `list_id` in both namespaces is a supported configuration.
/// A bare `list_id` must be refused with a conflict naming `--namespace`, and
/// resolved when the flag qualifies it.
#[tokio::test]
async fn a_list_id_in_both_namespaces_needs_the_namespace_flag() {
    let server = MockServer::start().await;
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
