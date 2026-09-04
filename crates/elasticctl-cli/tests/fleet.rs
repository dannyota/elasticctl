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

fn integration_item(id: &str) -> Value {
    serde_json::json!({
        "id": id,
        "name": format!("Integration {id}"),
        "namespace": "default",
        "policy_ids": ["parent-1"],
        "package": {"name": "system", "version": "2.0.0"},
        "inputs": {}
    })
}

fn live_integration_item(id: &str) -> Value {
    let mut item = integration_item(id);
    item["enabled"] = serde_json::json!(true);
    item
}

fn integration_parent_item(id: &str, agents: u64, attached: Value) -> Value {
    serde_json::json!({
        "id": id,
        "name": format!("Parent {id}"),
        "namespace": "default",
        "agents": agents,
        "package_policies": attached,
    })
}

fn installed_integration_package() -> Value {
    serde_json::json!({
        "name": "system",
        "status": "installed",
        "installationInfo": {"version": "2.0.0"},
    })
}

fn integration_package_metadata() -> Value {
    serde_json::json!({
        "name": "system",
        "version": "2.0.0",
        "vars": [],
        "policy_templates": [],
    })
}

async fn assert_no_integration_mutations(server: &MockServer) {
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests.iter().all(|request| {
            !matches!(request.method.as_str(), "POST" | "PUT" | "DELETE" | "PATCH")
        }),
        "dry run sent a mutation: {requests:?}"
    );
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

    for verb in ["list", "get", "validate", "export", "import", "delete"] {
        bin()
            .args(["fleet", "integration-policies", verb, "--help"])
            .assert()
            .success();
    }
    bin()
        .args(["fleet", "integration-policies", "delete"])
        .assert()
        .code(2);
    bin()
        .args([
            "fleet",
            "integration-policies",
            "export",
            "ip-1",
            "--all-custom",
        ])
        .assert()
        .code(2);
    bin()
        .args([
            "fleet",
            "integration-policies",
            "import",
            "--path",
            "p.json",
            "--overwrite",
            "--skip-existing",
        ])
        .assert()
        .code(2);
    let bare_export = bin()
        .args(["fleet", "integration-policies", "export"])
        .output()
        .unwrap();
    assert_eq!(bare_export.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&bare_export.stderr)
            .contains("integration-policy export needs selectors or --all-custom")
    );
    for args in [
        vec!["fleet", "integration-policies", "list", "--search", "   "],
        vec!["fleet", "integration-policies", "get", "  "],
        vec!["fleet", "integration-policies", "export", "  "],
        vec!["fleet", "integration-policies", "delete", "  "],
    ] {
        bin().args(args).assert().code(2);
    }
    let bad = bin()
        .args([
            "fleet",
            "integration-policies",
            "export",
            "ip-1",
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

    let integration_policies = fleet["subcommands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "integration-policies")
        .expect("integration-policies");
    let children = integration_policies["subcommands"].as_array().unwrap();
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

#[tokio::test]
async fn integration_list_get_validate_and_export_use_typed_safe_artifacts() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [integration_item("zeta"), integration_item("alpha")],
            "total": 2,
            "page": 1,
            "perPage": 1000,
        })))
        .mount(&server)
        .await;
    for id in ["alpha", "zeta"] {
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/package_policies/{id}")))
            .and(query_param("format", "simplified"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"item": live_integration_item(id)})),
            )
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "item": integration_parent_item("parent-1", 4, serde_json::json!(["alpha", "zeta"])),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "item": installed_integration_package(),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "item": integration_package_metadata(),
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let config = common::config_for(dir.path(), &server.uri());
    let artifact = dir.path().join("integration-policies.json");
    fs::write(
        &artifact,
        serde_json::json!([integration_item("local")]).to_string(),
    )
    .unwrap();

    let list = bin()
        .args([
            "fleet",
            "integration-policies",
            "list",
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
    let rows: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(rows[0]["id"], "alpha");
    assert_eq!(rows[1]["id"], "zeta");

    let get = bin()
        .args([
            "fleet",
            "integration-policies",
            "get",
            "alpha",
            "--json",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        get.status.success(),
        "{}",
        String::from_utf8_lossy(&get.stderr)
    );
    let detail: Value = serde_json::from_slice(&get.stdout).unwrap();
    assert_eq!(detail["id"], "alpha");
    assert_eq!(detail["affected_agents"], 4);
    assert!(detail.get("inputs").is_none());

    let validate = bin()
        .args(["fleet", "integration-policies", "validate", "--path"])
        .arg(&artifact)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&validate.stdout).unwrap(),
        serde_json::json!({"valid": true, "total": 1})
    );

    let json_export = bin()
        .args([
            "fleet",
            "integration-policies",
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
        json_export.status.success(),
        "{}",
        String::from_utf8_lossy(&json_export.stderr)
    );
    let exported: Value = serde_json::from_slice(&json_export.stdout).unwrap();
    assert_eq!(exported[0]["id"], "alpha");
    assert_eq!(exported[1]["id"], "zeta");

    let yaml_export = bin()
        .args([
            "fleet",
            "integration-policies",
            "export",
            "--all-custom",
            "--format-file",
            "yaml",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        yaml_export.status.success(),
        "{}",
        String::from_utf8_lossy(&yaml_export.stderr)
    );
    let yaml = String::from_utf8(yaml_export.stdout).unwrap();
    assert!(yaml.starts_with("- id: alpha\n"), "{yaml}");

    let out = dir.path().join("integration-policies-out.json");
    let file_export = bin()
        .args([
            "fleet",
            "integration-policies",
            "export",
            "--all-custom",
            "--out",
        ])
        .arg(&out)
        .args(["--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        file_export.status.success(),
        "{}",
        String::from_utf8_lossy(&file_export.stderr)
    );
    let report: Value = serde_json::from_slice(&file_export.stdout).unwrap();
    assert_eq!(report["exported"], 2);
    let from_file: Value = serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(from_file[0]["id"], "alpha");
}

#[test]
fn integration_import_rejects_an_empty_artifact_before_config_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = dir.path().join("empty.json");
    fs::write(&artifact, "[]").unwrap();

    let output = bin()
        .args(["fleet", "integration-policies", "import", "--path"])
        .arg(&artifact)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("integration-policy import needs at least one integration policy"),
        "{stderr}"
    );
    assert!(!stderr.contains("no active profile"), "{stderr}");
}

#[tokio::test]
async fn integration_import_previews_safely_then_applies_and_reports_row_failures() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/ip-1"))
        .and(query_param("format", "simplified"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing",
            })),
            ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing",
            })),
            ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing",
            })),
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"item": live_integration_item("ip-1")})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [], "total": 0, "page": 1, "perPage": 1000,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "item": integration_parent_item("parent-1", 3, serde_json::json!([])),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "item": {"name": "system", "status": "not_installed"},
            })),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "item": {"name": "system", "status": "not_installed"},
            })),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "item": {"name": "system", "status": "not_installed"},
            })),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "item": installed_integration_package(),
            })),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "item": integration_package_metadata(),
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/package_policies"))
        .and(body_partial_json(serde_json::json!({
            "id": "ip-1",
            "name": "Integration ip-1",
            "namespace": "default",
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"item": live_integration_item("ip-1")})),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let config = common::config_for(dir.path(), &server.uri());
    let artifact = dir.path().join("integration-policies.json");
    fs::write(
        &artifact,
        serde_json::json!([integration_item("ip-1")]).to_string(),
    )
    .unwrap();

    let dry = bin()
        .args(["fleet", "integration-policies", "import", "--path"])
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
    assert_eq!(
        serde_json::from_slice::<Value>(&dry.stdout).unwrap(),
        serde_json::json!({
            "applied": false,
            "total": 1,
            "skipped": [],
            "pending": 1,
            "package_installs": ["system@2.0.0"],
        })
    );
    assert!(!String::from_utf8_lossy(&dry.stdout).contains("inputs"));
    let dry_stderr = String::from_utf8_lossy(&dry.stderr);
    assert!(
        dry_stderr.contains("[DRY RUN]")
            && dry_stderr.contains("package install  system@2.0.0")
            && dry_stderr.contains("profile: default")
            && dry_stderr.contains(server.uri().trim_start_matches("http://"))
            && dry_stderr.contains("space: default")
            && dry_stderr.contains("Pass --yes to apply."),
        "{dry_stderr}"
    );
    assert_no_integration_mutations(&server).await;

    let apply = bin()
        .args(["fleet", "integration-policies", "import", "--path"])
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
        report["succeeded"],
        serde_json::json!([{"id": "ip-1", "action": "created"}])
    );
    assert_eq!(
        report["package_installs"],
        serde_json::json!(["system@2.0.0"])
    );
    assert!(report["failed"].as_array().unwrap().is_empty());
    let apply_stderr = String::from_utf8_lossy(&apply.stderr);
    assert!(
        apply_stderr.contains("Applying:")
            && apply_stderr.contains("profile: default")
            && apply_stderr.contains(server.uri().trim_start_matches("http://"))
            && apply_stderr.contains("space: default")
            && !apply_stderr.contains("Pass --yes to apply."),
        "{apply_stderr}"
    );
    let requests = server.received_requests().await.unwrap();
    let post = requests
        .iter()
        .find(|request| request.method == "POST")
        .unwrap();
    let post_body: Value = serde_json::from_slice(&post.body).unwrap();
    assert!(post_body.get("force").is_none(), "{post_body}");

    let failed_server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/ip-fails"))
        .and(query_param("format", "simplified"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing",
            })),
            ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing",
            })),
        ]))
        .mount(&failed_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [], "total": 0, "page": 1, "perPage": 1000,
        })))
        .mount(&failed_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "item": integration_parent_item("parent-1", 0, serde_json::json!([])),
        })))
        .mount(&failed_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "item": installed_integration_package(),
        })))
        .mount(&failed_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "item": integration_package_metadata(),
        })))
        .mount(&failed_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/package_policies"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "message": "server-body-must-not-leak",
        })))
        .mount(&failed_server)
        .await;
    let failed_config = common::config_for(dir.path(), &failed_server.uri());
    let failed_artifact = dir.path().join("failed-integration-policy.json");
    fs::write(
        &failed_artifact,
        serde_json::json!([integration_item("ip-fails")]).to_string(),
    )
    .unwrap();
    let failed = bin()
        .args(["fleet", "integration-policies", "import", "--path"])
        .arg(&failed_artifact)
        .args(["--yes", "--json", "--config"])
        .arg(&failed_config)
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(1));
    let failed_report: Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(failed_report["failed"][0]["id"], "ip-fails");
    assert_eq!(failed_report["failed"][0]["applied"], false);
    assert!(
        !String::from_utf8_lossy(&failed.stdout).contains("server-body-must-not-leak"),
        "{}",
        String::from_utf8_lossy(&failed.stdout)
    );
}

#[tokio::test]
async fn integration_delete_previews_without_writing_then_uses_the_exact_delete_route() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/ip-delete"))
        .and(query_param("format", "simplified"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"item": live_integration_item("ip-delete")})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "item": integration_parent_item("parent-1", 5, serde_json::json!(["ip-delete"])),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "item": installed_integration_package(),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "item": integration_package_metadata(),
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/fleet/package_policies/ip-delete"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "ip-delete"})),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let config = common::config_for(dir.path(), &server.uri());
    let dry = bin()
        .args([
            "fleet",
            "integration-policies",
            "delete",
            "ip-delete",
            "--json",
            "--config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        dry.status.success(),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&dry.stdout).unwrap(),
        serde_json::json!({"applied": false, "total": 1})
    );
    let dry_stderr = String::from_utf8_lossy(&dry.stderr);
    assert!(
        dry_stderr.contains("[DRY RUN]")
            && dry_stderr.contains("Delete 1 integration policy(ies)")
            && dry_stderr.contains("profile: default")
            && dry_stderr.contains(server.uri().trim_start_matches("http://"))
            && dry_stderr.contains("space: default")
            && dry_stderr.contains("Pass --yes to apply."),
        "{dry_stderr}"
    );
    assert_no_integration_mutations(&server).await;

    let apply = bin()
        .args([
            "fleet",
            "integration-policies",
            "delete",
            "ip-delete",
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
    assert_eq!(report["deleted"], serde_json::json!([{"id": "ip-delete"}]));
    assert_eq!(report["affected_agents"], 5);
    let apply_stderr = String::from_utf8_lossy(&apply.stderr);
    assert!(
        apply_stderr.contains("Applying:")
            && apply_stderr.contains("profile: default")
            && apply_stderr.contains(server.uri().trim_start_matches("http://"))
            && apply_stderr.contains("space: default")
            && !apply_stderr.contains("Pass --yes to apply."),
        "{apply_stderr}"
    );
    let delete_requests = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.method == "DELETE")
        .collect::<Vec<_>>();
    assert_eq!(delete_requests.len(), 1);
    assert_eq!(
        delete_requests[0].url.path(),
        "/api/fleet/package_policies/ip-delete"
    );
    assert!(delete_requests[0].url.query().is_none());
    assert!(delete_requests[0].body.is_empty());
}
