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

fn policy_item(id: &str) -> Value {
    serde_json::json!({
        "id": id,
        "name": format!("Policy {id}"),
        "namespace": "default",
        "inactivity_timeout": 1209600,
        "monitoring_enabled": [],
        "agent_features": [],
        "global_data_tags": [],
        "is_managed": false,
        "is_protected": false,
        "has_fleet_server": null,
        "status": "active",
        "revision": 3,
        "schema_version": "1.1.1",
        "version": "WzEsMV0=",
        "updated_at": "2026-09-03T00:00:00.000Z",
        "updated_by": "system",
        "agents": 0,
        "unprivileged_agents": 0,
        "package_policies": [],
        "space_ids": ["default"]
    })
}

#[test]
fn clap_has_the_fleet_tree_and_rejects_unsafe_arguments() {
    bin()
        .args(["fleet", "agent-policies", "list", "--help"])
        .assert()
        .success();
    bin()
        .args(["fleet", "agent-policies", "delete"])
        .assert()
        .code(2);
    bin()
        .args(["fleet", "agent-policies", "export", "ap-1", "--all-custom"])
        .assert()
        .code(2);
    bin()
        .args([
            "fleet",
            "agent-policies",
            "import",
            "--path",
            "p.json",
            "--overwrite",
            "--skip-existing",
        ])
        .assert()
        .code(2);
    let bad = bin()
        .args([
            "fleet",
            "agent-policies",
            "export",
            "ap-1",
            "--format-file",
            "toml",
        ])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("expected json or yaml"));
}

#[test]
fn fleet_command_tree_records_the_documented_guarded_paths() {
    let out = bin().args(["commands", "--json"]).output().unwrap();
    let tree: Value = serde_json::from_slice(&out.stdout).unwrap();
    let fleet = tree["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "fleet")
        .expect("fleet");
    let agent_policies = fleet["subcommands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "agent-policies")
        .expect("agent-policies");
    let children = agent_policies["subcommands"].as_array().unwrap();
    let find = |name: &str| children.iter().find(|child| child["name"] == name).unwrap();
    for read_only in ["list", "get", "validate", "export"] {
        assert_eq!(find(read_only)["mutates"], false, "{read_only}");
    }
    assert_eq!(find("import")["mutates"], true);
    assert_eq!(find("delete")["mutates"], true);
}

#[tokio::test]
async fn list_renders_sorted_rows_and_export_streams_the_raw_artifact() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies"))
        .and(query_param("perPage", "1000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [policy_item("zeta"), policy_item("alpha")], "total": 2, "page": 1, "perPage": 1000
        })))
        .mount(&server)
        .await;
    for id in ["alpha", "zeta"] {
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/agent_policies/{id}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"item": policy_item(id)})),
            )
            .mount(&server)
            .await;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = common::config_for(dir.path(), &server.uri());

    let list = bin()
        .args(["fleet", "agent-policies", "list", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let rows: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(rows[0]["id"], "alpha");
    assert_eq!(rows[1]["id"], "zeta");

    let capped = bin()
        .args([
            "fleet",
            "agent-policies",
            "list",
            "--limit",
            "1",
            "--json",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        capped.status.success(),
        "{}",
        String::from_utf8_lossy(&capped.stderr)
    );
    assert!(String::from_utf8_lossy(&capped.stderr).contains("capped at 1 rows"));

    let export = bin()
        .args([
            "fleet",
            "agent-policies",
            "export",
            "--all-custom",
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
    let specs: Value = serde_json::from_slice(&export.stdout).expect("raw JSON artifact on stdout");
    assert_eq!(specs[0]["id"], "alpha");
    assert_eq!(specs[0]["inactivity_timeout"], 1209600);
}

#[tokio::test]
async fn import_dry_run_previews_without_writing_then_applies_create() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/ap-1"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"item": policy_item("ap-1")})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [], "total": 0, "page": 1, "perPage": 1000
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/agent_policies"))
        .and(query_param("sys_monitoring", "false"))
        .and(body_partial_json(
            serde_json::json!({"id": "ap-1", "name": "Policy ap-1", "namespace": "default"}),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"item": policy_item("ap-1")})),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = common::config_for(dir.path(), &server.uri());
    let artifact = dir.path().join("policies.json");
    fs::write(
        &artifact,
        r#"[{"id":"ap-1","name":"Policy ap-1","namespace":"default"}]"#,
    )
    .unwrap();

    let dry = bin()
        .args(["fleet", "agent-policies", "import", "--path"])
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
            && stderr.contains("Import 1 agent policy(ies)")
            && stderr.contains("profile: default")
            && stderr.contains(server.uri().trim_start_matches("http://"))
            && stderr.contains("space: default")
            && stderr.contains("Pass --yes to apply."),
        "{stderr}"
    );
    let dry_requests = server.received_requests().await.unwrap();
    assert!(dry_requests.iter().any(|request| request.method == "GET"));
    assert!(!dry_requests.iter().any(|request| request.method == "POST"));

    let apply = bin()
        .args(["fleet", "agent-policies", "import", "--path"])
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
        serde_json::json!({"id": "ap-1", "action": "created"})
    );
    assert_eq!(report["affected_agents"], 0);
}

#[tokio::test]
async fn delete_dry_run_previews_then_posts_the_delete_route() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/ap-1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"item": policy_item("ap-1")})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/agent_policies/delete"))
        .and(body_partial_json(
            serde_json::json!({"agentPolicyId": "ap-1"}),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"id": "ap-1", "name": "Policy ap-1"})),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = common::config_for(dir.path(), &server.uri());

    let dry = bin()
        .args([
            "fleet",
            "agent-policies",
            "delete",
            "ap-1",
            "--json",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert!(dry.status.success());
    assert!(String::from_utf8_lossy(&dry.stderr).contains("Delete 1 agent policy(ies)"));
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.method == "POST")
    );

    let apply = bin()
        .args([
            "fleet",
            "agent-policies",
            "delete",
            "ap-1",
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
    let report: Value = serde_json::from_slice(&apply.stdout).unwrap();
    assert_eq!(report["deleted"], serde_json::json!([{"id": "ap-1"}]));
    let body: Value = serde_json::from_slice(
        &server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .find(|r| r.method == "POST")
            .unwrap()
            .body,
    )
    .unwrap();
    assert!(body.get("force").is_none(), "{body}");
}
