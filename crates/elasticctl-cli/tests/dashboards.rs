use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

mod common;

const BUNDLE: &str = concat!(
    r#"{"id":"dv-1","type":"index-pattern","attributes":{"title":"logs-*"},"references":[]}"#,
    "\n",
    r#"{"id":"dash-1","type":"dashboard","attributes":{"title":"Overview"},"references":[]}"#,
    "\n",
    r#"{"exportedCount":2,"missingRefCount":0,"missingReferences":[]}"#,
    "\n",
);

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

async fn verified_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "version": {"number": "9.5.1", "build_flavor": "traditional"}
        })))
        .mount(&server)
        .await;
    server
}

fn dashboard(id: &str, title: &str) -> Value {
    serde_json::json!({
        "id": id,
        "data": {
            "title": title,
            "description": "Detection activity",
            "panels": [],
        },
        "meta": {"created_at": "server-owned"},
        "warnings": [],
    })
}

#[derive(Clone)]
struct SequenceResponder {
    responses: Arc<Vec<ResponseTemplate>>,
    next: Arc<AtomicUsize>,
}

impl SequenceResponder {
    fn new(responses: Vec<ResponseTemplate>) -> Self {
        Self {
            responses: Arc::new(responses),
            next: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Respond for SequenceResponder {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let index = self.next.fetch_add(1, Ordering::SeqCst);
        self.responses[index.min(self.responses.len() - 1)].clone()
    }
}

#[test]
fn clap_has_the_dashboard_tree_and_rejects_unsafe_arguments() {
    bin()
        .args(["dashboards", "list", "--help"])
        .assert()
        .success();
    bin()
        .args(["dashboards", "bundle", "export", "--help"])
        .assert()
        .success();

    let empty_delete = bin()
        .args(["dashboards", "delete", "--config", "missing.toml"])
        .output()
        .unwrap();
    assert_eq!(empty_delete.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&empty_delete.stderr)
            .contains("Name at least one dashboard to delete")
    );

    bin()
        .args([
            "dashboards",
            "import",
            "--path",
            "dashboards.json",
            "--overwrite",
            "--skip-existing",
        ])
        .assert()
        .code(2);
    bin()
        .args([
            "dashboards",
            "bundle",
            "import",
            "--path",
            "dashboards.ndjson",
            "--skip-existing",
        ])
        .assert()
        .code(2);
    bin()
        .args(["dashboards", "bundle", "export", "--format-file", "json"])
        .assert()
        .code(2);
}

#[test]
fn dashboard_command_tree_records_the_documented_guarded_paths() {
    let out = bin().args(["commands", "--json"]).output().unwrap();
    let tree: Value = serde_json::from_slice(&out.stdout).unwrap();
    let dashboards = tree["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|command| command["name"] == "dashboards")
        .expect("dashboards command");
    let children = dashboards["subcommands"].as_array().unwrap();
    let find = |name: &str| children.iter().find(|child| child["name"] == name).unwrap();
    assert_eq!(find("list")["mutates"], false);
    assert_eq!(find("get")["mutates"], false);
    assert_eq!(find("validate")["mutates"], false);
    assert_eq!(find("export")["mutates"], false);
    assert_eq!(find("import")["mutates"], true);
    assert_eq!(find("delete")["mutates"], true);
    let bundle = find("bundle")["subcommands"].as_array().unwrap();
    let bundle_find = |name: &str| bundle.iter().find(|child| child["name"] == name).unwrap();
    assert_eq!(bundle_find("export")["mutates"], false);
    assert_eq!(bundle_find("import")["mutates"], true);
}

#[test]
fn dashboard_validate_is_local_and_import_artifact_errors_precede_configuration_errors() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = dir.path().join("dashboards.json");
    fs::write(
        &artifact,
        r#"[{"id":"dash-1","data":{"title":"Overview","panels":[]}}]"#,
    )
    .unwrap();
    let out = bin()
        .args([
            "dashboards",
            "validate",
            "--json",
            "--config",
            "absent.toml",
            "--path",
        ])
        .arg(&artifact)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["total"],
        1
    );

    let malformed = dir.path().join("malformed.json");
    let empty = dir.path().join("empty.json");
    fs::write(&malformed, r#"[{"id":"dash-1","data":{"title":""}}]"#).unwrap();
    fs::write(&empty, "[]").unwrap();
    for (path, expected) in [
        (malformed.as_path(), "dashboard data.title"),
        (
            empty.as_path(),
            "dashboard import needs at least one dashboard",
        ),
    ] {
        let output = bin()
            .args(["dashboards", "import", "--path"])
            .arg(path)
            .args(["--json", "--config", "absent.toml"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        let message = error["error"]["message"].as_str().unwrap();
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains("config"), "{message}");
    }
}

#[tokio::test]
async fn dashboard_list_get_and_typed_export_preserve_typed_shapes_and_artifacts() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "1000"))
        .and(query_param("query", "security"))
        .and(query_param("tags", "blue"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"id": "dash-2", "title": "Second", "description": "Two", "tags": ["blue"]},
                {"id": "dash-1", "title": "Overview", "description": "One", "tags": ["blue"]}
            ],
            "meta": {"page": 1, "per_page": 1000, "total": 2}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(dashboard("dash-1", "Overview")))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = common::config_for(dir.path(), &server.uri());

    let list = bin()
        .args([
            "dashboards",
            "list",
            "--search",
            "security",
            "--tag",
            "blue",
            "--limit",
            "1",
            "--json",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let listed: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(
        listed,
        serde_json::json!([{
            "id": "dash-1", "title": "Overview", "description": "One", "tags": ["blue"]
        }])
    );

    let get = bin()
        .args(["dashboards", "get", "dash-1", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        get.status.success(),
        "{}",
        String::from_utf8_lossy(&get.stderr)
    );
    let gotten: Value = serde_json::from_slice(&get.stdout).unwrap();
    assert_eq!(gotten["id"], "dash-1");
    assert_eq!(gotten["data"]["title"], "Overview");
    assert_eq!(gotten["meta"]["created_at"], "server-owned");

    let export = bin()
        .args([
            "dashboards",
            "export",
            "dash-1",
            "--format",
            "table",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    let artifact = String::from_utf8(export.stdout).unwrap();
    assert!(artifact.starts_with("[\n"), "{artifact}");
    assert_eq!(
        serde_json::from_str::<Value>(&artifact).unwrap(),
        serde_json::json!([{
            "id": "dash-1",
            "data": {"title": "Overview", "description": "Detection activity", "panels": []}
        }])
    );

    let yaml = bin()
        .args([
            "dashboards",
            "export",
            "dash-1",
            "--format-file",
            "yaml",
            "--json",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        yaml.status.success(),
        "{}",
        String::from_utf8_lossy(&yaml.stderr)
    );
    assert!(String::from_utf8_lossy(&yaml.stdout).starts_with("- id: dash-1"));

    let out_path = dir.path().join("dashboards.json");
    let out = bin()
        .args(["dashboards", "export", "dash-1", "--out"])
        .arg(&out_path)
        .args(["--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["exported"],
        1
    );
    assert!(fs::read_to_string(&out_path).unwrap().starts_with("[\n"));
}

#[tokio::test]
async fn dashboard_get_refuses_ambiguous_exact_titles() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/Overview"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "statusCode": 404, "message": "missing"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"id": "dash-b", "title": "Overview"},
                {"id": "dash-a", "title": "Overview"}
            ],
            "meta": {"page": 1, "per_page": 1000, "total": 2}
        })))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = common::config_for(dir.path(), &server.uri());
    let output = bin()
        .args(["dashboards", "get", "Overview", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    let message = error["error"]["message"].as_str().unwrap();
    assert!(message.contains("dash-a, dash-b"), "{message}");
}

#[tokio::test]
async fn dashboard_bundle_export_writes_exact_opaque_bytes_to_stdout_and_out() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(dashboard("dash-1", "Overview")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/saved_objects/_export"))
        .and(body_partial_json(serde_json::json!({
            "objects": [{"type": "dashboard", "id": "dash-1"}],
            "includeReferencesDeep": true,
            "excludeExportDetails": false,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_string(BUNDLE))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = common::config_for(dir.path(), &server.uri());

    let stdout = bin()
        .args([
            "dashboards",
            "bundle",
            "export",
            "dash-1",
            "--format",
            "yaml",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        stdout.status.success(),
        "{}",
        String::from_utf8_lossy(&stdout.stderr)
    );
    assert_eq!(stdout.stdout, BUNDLE.as_bytes());

    let out_path = dir.path().join("dashboards.ndjson");
    let out = bin()
        .args(["dashboards", "bundle", "export", "dash-1", "--out"])
        .arg(&out_path)
        .args(["--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read(&out_path).unwrap(), BUNDLE.as_bytes());
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["exported"],
        1
    );
}

#[tokio::test]
async fn dashboard_import_dry_run_previews_without_writing_then_applies_put() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({"statusCode": 404, "message": "missing"})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/dashboards/dash-1"))
        .and(body_partial_json(serde_json::json!({
            "title": "Overview", "description": "Detection activity", "panels": []
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(dashboard("dash-1", "Overview")))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = common::config_for(dir.path(), &server.uri());
    let artifact = dir.path().join("dashboards.json");
    fs::write(
        &artifact,
        r#"[{"id":"dash-1","data":{"title":"Overview","description":"Detection activity","panels":[]}}]"#,
    )
    .unwrap();

    let dry = bin()
        .args(["dashboards", "import", "--path"])
        .arg(&artifact)
        .args(["--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        dry.status.success(),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    let stderr = String::from_utf8_lossy(&dry.stderr);
    assert!(
        stderr.contains("[DRY RUN]")
            && stderr.contains("Import 1 dashboard(s)")
            && stderr.contains("profile: default")
            && stderr.contains(server.uri().trim_start_matches("http://"))
            && stderr.contains("space: default")
            && stderr.contains("Pass --yes to apply."),
        "{stderr}"
    );
    assert!(server.received_requests().await.unwrap().is_empty());

    let apply = bin()
        .args(["dashboards", "import", "--path"])
        .arg(&artifact)
        .args(["--yes", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        apply.status.success(),
        "{}",
        String::from_utf8_lossy(&apply.stderr)
    );
    let report: Value = serde_json::from_slice(&apply.stdout).unwrap();
    assert_eq!(
        report["succeeded"][0],
        serde_json::json!({"id": "dash-1", "action": "created"})
    );
}

#[tokio::test]
async fn dashboard_delete_dry_run_previews_without_deleting_then_accepts_204() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(dashboard("dash-1", "Overview")))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = common::config_for(dir.path(), &server.uri());

    let dry = bin()
        .args(["dashboards", "delete", "dash-1", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        dry.status.success(),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    let stderr = String::from_utf8_lossy(&dry.stderr);
    assert!(
        stderr.contains("Delete 1 dashboard(s)")
            && stderr.contains("profile: default")
            && stderr.contains(server.uri().trim_start_matches("http://"))
            && stderr.contains("space: default")
            && stderr.contains("Pass --yes to apply."),
        "{stderr}"
    );
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.method == "DELETE")
    );

    let apply = bin()
        .args([
            "dashboards",
            "delete",
            "dash-1",
            "--yes",
            "--json",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        apply.status.success(),
        "{}",
        String::from_utf8_lossy(&apply.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&apply.stdout).unwrap()["deleted"][0]["id"],
        "dash-1"
    );
}

#[tokio::test]
async fn dashboard_bundle_import_dry_run_keeps_bytes_then_uploads_multipart() {
    let server = verified_server().await;
    Mock::given(method("POST"))
        .and(path("/api/saved_objects/_import"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "successCount": 1,
            "successResults": [{"type": "dashboard", "id": "dash-1", "created": true}],
            "errors": []
        })))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = common::config_for(dir.path(), &server.uri());
    let artifact = dir.path().join("dashboards.ndjson");
    fs::write(&artifact, BUNDLE).unwrap();

    let dry = bin()
        .args(["dashboards", "bundle", "import", "--path"])
        .arg(&artifact)
        .args(["--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        dry.status.success(),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    let stderr = String::from_utf8_lossy(&dry.stderr);
    assert!(
        stderr.contains("Import 1 dashboard(s) and 1 related saved object(s)")
            && stderr.contains("profile: default")
            && stderr.contains(server.uri().trim_start_matches("http://"))
            && stderr.contains("space: default")
            && stderr.contains("Pass --yes to apply."),
        "{stderr}"
    );
    assert!(server.received_requests().await.unwrap().is_empty());

    let apply = bin()
        .args(["dashboards", "bundle", "import", "--path"])
        .arg(&artifact)
        .args(["--overwrite", "--yes", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        apply.status.success(),
        "{}",
        String::from_utf8_lossy(&apply.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&apply.stdout).unwrap()["succeeded"][0]["id"],
        "dash-1"
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.query(), Some("overwrite=true"));
    assert!(String::from_utf8_lossy(&requests[0].body).contains(BUNDLE));
}

#[tokio::test]
async fn lossy_dashboard_import_prints_the_full_lossy_row_and_exits_one() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "dash-1",
                "data": {"title": "Overview", "panels": []},
                "meta": {},
                "warnings": [{"message": "Description was removed"}]
            })),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/dashboards/dash-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "dash-1",
            "data": {"title": "Overview", "panels": []},
            "meta": {},
            "warnings": []
        })))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = common::config_for(dir.path(), &server.uri());
    let artifact = dir.path().join("dashboards.json");
    fs::write(
        &artifact,
        r#"[{"id":"dash-1","data":{"title":"Overview","description":"Dropped","panels":[]}}]"#,
    )
    .unwrap();

    let output = bin()
        .args(["dashboards", "import", "--path"])
        .arg(&artifact)
        .args(["--yes", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["lossy"],
        serde_json::json!([{
            "id": "dash-1",
            "applied": true,
            "paths": ["$.description"],
            "warnings": ["Description was removed"]
        }])
    );
}
