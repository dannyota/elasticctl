use assert_cmd::Command;
use serde_json::{Value, json};
use std::fs;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn config_for(dir: &std::path::Path, uri: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    fs::write(
        &path,
        format!(
            "current = \"default\"\n\n[profiles.default]\nkibana_url = \"{uri}\"\napi_key = \"essu_t\"\nspace = \"default\"\nverify = true\ntimeout_secs = 5\n"
        ),
    )
    .unwrap();
    path
}

fn summary(id: &str, name: &str) -> Value {
    json!({"id": id, "name": name, "title": format!("logs-{id}-*"), "timeFieldName": "@timestamp"})
}

fn detail(id: &str, name: &str) -> Value {
    json!({"data_view": {
        "id": id, "name": name, "title": format!("logs-{id}-*"),
        "timeFieldName": "@timestamp", "allowNoIndex": false, "allowHidden": false
    }})
}

async fn server_with_view() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data_view": [summary("dv", "Security events"), summary("replacement", "Replacement")]})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail("dv", "Security events")))
        .mount(&server)
        .await;
    server
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
fn clap_has_the_data_view_tree_and_rejects_unsafe_arguments() {
    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["data-views", "default", "get", "--help"])
        .assert()
        .success();
    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["data-views", "delete"])
        .assert()
        .code(2);
    let bad_format = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["data-views", "export", "--format-file", "toml"])
        .output()
        .unwrap();
    assert_eq!(bad_format.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&bad_format.stderr)
            .contains("unknown format-file 'toml'; expected json or yaml")
    );
    Command::cargo_bin("elasticctl")
        .unwrap()
        .args([
            "data-views",
            "import",
            "--path",
            "views.json",
            "--overwrite",
            "--skip-existing",
        ])
        .assert()
        .code(2);
}

#[test]
fn validate_is_local_and_uses_json_or_yaml_extensions() {
    let dir = tempfile::tempdir().unwrap();
    let json_path = dir.path().join("views.json");
    fs::write(&json_path, "[{\"id\":\"dv\",\"title\":\"logs-*\"}]").unwrap();
    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["data-views", "validate", "--json", "--path"])
        .arg(&json_path)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["total"],
        1
    );

    let yaml_path = dir.path().join("views.yaml");
    fs::write(&yaml_path, "- id: dv\n  title: logs-*\n").unwrap();
    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["data-views", "validate", "--json", "--path"])
        .arg(&yaml_path)
        .assert()
        .success();
}

#[tokio::test]
async fn list_get_and_export_preserve_portable_artifacts() {
    let server = server_with_view().await;
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path(), &server.uri());

    let list = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["data-views", "list", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(list.status.success());
    let listed: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(listed["data_views"][0]["id"], "dv");
    assert_eq!(listed["data_views"][0]["time_field_name"], "@timestamp");

    let get = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["data-views", "get", "Security events", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(get.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&get.stdout).unwrap()["id"],
        "dv"
    );

    let export = Command::cargo_bin("elasticctl")
        .unwrap()
        .args([
            "data-views",
            "export",
            "dv",
            "--format-file",
            "yaml",
            "--format",
            "table",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert!(export.status.success());
    let artifact = String::from_utf8_lossy(&export.stdout);
    assert!(artifact.starts_with("- id: dv"), "{artifact}");
    assert!(!artifact.contains("exported"), "{artifact}");

    let out_path = dir.path().join("views.json");
    let confirmation = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["data-views", "export", "dv", "--out"])
        .arg(&out_path)
        .args(["--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(confirmation.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&confirmation.stdout).unwrap()["exported"],
        1
    );
    assert!(fs::read_to_string(&out_path).unwrap().starts_with("[\n"));
}

#[tokio::test]
async fn guarded_default_set_dry_runs_then_posts_the_checked_snapshot() {
    let server = server_with_view().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view_id": null})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/default"))
        .and(body_partial_json(
            json!({"data_view_id": "dv", "force": true}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path(), &server.uri());

    let dry = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["data-views", "default", "set", "dv", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(dry.status.success());
    let stderr = String::from_utf8_lossy(&dry.stderr);
    assert!(
        stderr.contains("[DRY RUN]")
            && stderr.contains("profile: default")
            && stderr.contains("space: default"),
        "{stderr}"
    );
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.method == "POST")
    );

    let apply = Command::cargo_bin("elasticctl")
        .unwrap()
        .args([
            "data-views",
            "default",
            "set",
            "dv",
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
        serde_json::from_slice::<Value>(&apply.stdout).unwrap()["data_view_id"],
        "dv"
    );
}

#[tokio::test]
async fn import_and_default_unset_dry_runs_never_write() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view_id": "dv"})))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path(), &server.uri());
    let artifact = dir.path().join("views.json");
    fs::write(&artifact, "[{\"id\":\"dv\",\"title\":\"logs-*\"}]").unwrap();

    let import = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["data-views", "import", "--path"])
        .arg(&artifact)
        .args(["--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        import.status.success(),
        "{}",
        String::from_utf8_lossy(&import.stderr)
    );
    assert!(String::from_utf8_lossy(&import.stderr).contains("[DRY RUN]"));

    let unset = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["data-views", "default", "unset", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        unset.status.success(),
        "{}",
        String::from_utf8_lossy(&unset.stderr)
    );
    assert!(String::from_utf8_lossy(&unset.stderr).contains("[DRY RUN]"));
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.method == "POST")
    );
}

#[tokio::test]
async fn import_apply_uses_the_planned_create_and_never_rereads_the_artifact() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(200).set_body_json(json!({"data_view": {
                "id": "dv", "title": "logs-*", "allowNoIndex": false, "allowHidden": false
            }})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view"))
        .and(body_partial_json(json!({
            "data_view": {"id": "dv", "title": "logs-*", "allowNoIndex": false, "allowHidden": false},
            "override": false,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view": {
            "id": "dv", "title": "logs-*", "allowNoIndex": false, "allowHidden": false
        }})))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path(), &server.uri());
    let artifact = dir.path().join("views.json");
    fs::write(&artifact, "[{\"id\":\"dv\",\"title\":\"logs-*\"}]").unwrap();

    let output = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["data-views", "import", "--path"])
        .arg(&artifact)
        .args(["--yes", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["succeeded"][0]["action"],
        "created"
    );
}

#[tokio::test]
async fn delete_apply_rechecks_then_uses_the_direct_delete_route() {
    let server = server_with_view().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view_id": null})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/swap_references/_preview"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": []})))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path(), &server.uri());
    let output = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["data-views", "delete", "dv", "--yes", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["deleted"][0]["id"],
        "dv"
    );
}

#[tokio::test]
async fn referenced_delete_refuses_before_guard_and_replacement_previews_dependents() {
    let server = server_with_view().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view_id": null})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/swap_references/_preview"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"result": [{"id": "dash-1", "type": "dashboard"}]})),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path(), &server.uri());
    let refuse = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["data-views", "delete", "dv", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(refuse.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&refuse.stderr).contains("[DRY RUN]"));

    // Replacement mode is allowed and names the dependent saved object before
    // any mutation.
    let preview = Command::cargo_bin("elasticctl")
        .unwrap()
        .args([
            "data-views",
            "delete",
            "dv",
            "--replace-with",
            "replacement",
            "--json",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert!(preview.status.success());
    let stderr = String::from_utf8_lossy(&preview.stderr);
    assert!(stderr.contains("dashboard/dash-1"), "{stderr}");
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.url.path() == "/api/data_views/swap_references")
    );
}
