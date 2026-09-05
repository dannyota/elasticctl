//! Fleet conformance lifecycle and its cleanup lease.

#[path = "fleet/cleanup.rs"]
mod cleanup;

use super::*;
use cleanup::FleetCleanup;
use elasticctl_api::content_codec::ContentFormat;
use elasticctl_api::fleet::{
    agent_policies, agent_policy_ops, integration_policies, integration_policy_ops,
};
use elasticctl_api_test_support::fleet::{FleetState, PackageInventory, installed_packages};
use elasticctl_core::{Feature, Transport, urlencode};
use serde_json::{Value, json};

const SYSTEM_PACKAGE: &str = "system";

pub(super) enum FleetFailure {
    Contract(String),
    Cleanup(String),
}

/// The root ignored test delegates here so the controller's exact test filter
/// stays stable while this module owns the lifecycle implementation.
pub(super) fn run_contract(
    config: &std::path::Path,
    profile: Profile,
    nonce: String,
) -> Result<(), FleetFailure> {
    let runtime = tokio::runtime::Runtime::new().map_err(|error| {
        FleetFailure::Contract(format!("building Fleet contract runtime: {error}"))
    })?;
    runtime.block_on(fleet_lifecycle(config, profile, nonce))
}

async fn fleet_lifecycle(
    config: &std::path::Path,
    profile: Profile,
    nonce: String,
) -> Result<(), FleetFailure> {
    let transport = Transport::new(&profile).map_err(|error| {
        FleetFailure::Contract(format!("building Fleet transport: {}", error.kind.as_str()))
    })?;
    prepare_fleet(
        &transport,
        std::env::var("ELASTICCTL_CONFORMANCE_FLEET_SETUP").as_deref() == Ok("1"),
    )
    .await
    .map_err(FleetFailure::Contract)?;
    let fleet_baseline = FleetState::capture(&transport).await.map_err(|error| {
        FleetFailure::Contract(format!("capturing Fleet baseline: {}", error.kind.as_str()))
    })?;
    if !fleet_baseline.markers_empty() {
        return Err(FleetFailure::Contract(
            "Fleet baseline contains marker policies".to_string(),
        ));
    }
    let mut cleanup = FleetCleanup::new(profile.clone(), nonce.clone(), fleet_baseline.clone());
    let contract =
        fleet_lifecycle_inner(config, &transport, &nonce, &fleet_baseline, &mut cleanup).await;
    let cleanup_result = cleanup.finish_async().await;
    if let Err(error) = cleanup_result {
        return Err(FleetFailure::Cleanup(error));
    }
    let final_state = FleetState::capture(&transport).await.map_err(|error| {
        FleetFailure::Cleanup(format!("auditing Fleet cleanup: {}", error.kind.as_str()))
    })?;
    if final_state != fleet_baseline {
        return Err(FleetFailure::Cleanup(
            "Fleet cleanup did not restore the exact baseline".to_string(),
        ));
    }
    contract.map_err(FleetFailure::Contract)
}

async fn fleet_lifecycle_inner(
    config: &std::path::Path,
    transport: &Transport,
    nonce: &str,
    baseline: &FleetState,
    cleanup: &mut FleetCleanup,
) -> TestResult {
    let version = ensure_system(transport, baseline, cleanup).await?;
    assert_system_unchanged(transport, baseline, &version).await?;

    let parent_id = unique_name("fleet-parent");
    let parent_name = unique_name("fleet-parent-name");
    let description = format!("Fleet conformance marker {nonce}");
    let parent_artifact = json!([{
        "id": parent_id,
        "name": parent_name,
        "namespace": transport.space(),
        "description": description,
        "inactivity_timeout": 1209600,
        "monitoring_enabled": [],
        "agent_features": [],
        "global_data_tags": []
    }]);
    let mut parent = one_agent_spec(&parent_artifact)?;
    cleanup.register_parent(parent.id.clone(), parent.clone())?;
    let parent_path = write_artifact(config, "fleet-parent.json", &parent_artifact)?;
    assert_preview(
        transport,
        config,
        "agent-policies",
        &parent_path,
        &parent.id,
    )
    .await?;
    assert_system_unchanged(transport, baseline, &version).await?;
    assert_applied_import(config, "agent-policies", &parent_path, &parent.id)?;
    assert_cli_transfer_reads(
        config,
        "agent-policies",
        &parent.id,
        &serde_json::to_value(vec![parent.clone()]).unwrap(),
    )?;
    assert_agent_round_trip(transport, &parent).await?;
    parent.description = Some(format!("Fleet conformance marker changed {nonce}"));
    cleanup.allow_parent_state(&parent.id, parent.clone())?;
    let changed_parent_artifact = serde_json::to_value(vec![parent.clone()]).unwrap();
    let parent_path = write_artifact(config, "fleet-parent.json", &changed_parent_artifact)?;
    assert_overwrite(config, "agent-policies", &parent_path, &parent.id)?;
    assert_agent_round_trip(transport, &parent).await?;
    assert_conflict_skip_and_overwrite(config, "agent-policies", &parent_path, &parent.id)?;

    assert_system_unchanged(transport, baseline, &version).await?;
    let bootstrap_id = unique_name("fleet-bootstrap");
    let bootstrap_name = unique_name("fleet-bootstrap-name");
    let bootstrap = json!({
        "id": bootstrap_id,
        "name": bootstrap_name,
        "description": format!("Fleet bootstrap marker {nonce}"),
        "namespace": transport.space(),
        "policy_ids": [parent.id],
        "package": {"name": SYSTEM_PACKAGE, "version": version},
        "inputs": {}
    });
    let mut bootstrap_spec: elasticctl_api::fleet::integration_policies::IntegrationPolicySpec =
        serde_json::from_value(bootstrap)
            .map_err(|error| format!("decoding bootstrap: {error}"))?;
    bootstrap_spec = cleanup
        .materialize_system_inputs(transport, bootstrap_spec)
        .await?;

    assert_system_unchanged(transport, baseline, &version).await?;
    let integration_id = unique_name("fleet-integration");
    let integration_name = unique_name("fleet-integration-name");
    bootstrap_spec.id = integration_id.clone();
    bootstrap_spec.name = integration_name;
    bootstrap_spec.description = Some(format!("Fleet integration marker {nonce}"));
    bootstrap_spec.policy_ids = vec![parent.id.clone()];
    cleanup.register_integration(integration_id.clone(), bootstrap_spec.clone())?;
    let integration_artifact = serde_json::to_value(vec![bootstrap_spec.clone()]).unwrap();
    let integration_path = write_artifact(config, "fleet-integration.json", &integration_artifact)?;
    assert_preview(
        transport,
        config,
        "integration-policies",
        &integration_path,
        &integration_id,
    )
    .await?;
    assert_system_unchanged(transport, baseline, &version).await?;
    assert_applied_import(
        config,
        "integration-policies",
        &integration_path,
        &integration_id,
    )?;
    assert_cli_transfer_reads(
        config,
        "integration-policies",
        &integration_id,
        &serde_json::to_value(vec![bootstrap_spec.clone()]).unwrap(),
    )?;
    assert_integration_round_trip(transport, &bootstrap_spec).await?;
    bootstrap_spec.description = Some(format!("Fleet integration marker changed {nonce}"));
    cleanup.allow_integration_state(&integration_id, bootstrap_spec.clone())?;
    let integration_artifact = serde_json::to_value(vec![bootstrap_spec.clone()]).unwrap();
    let integration_path = write_artifact(config, "fleet-integration.json", &integration_artifact)?;
    assert_overwrite(
        config,
        "integration-policies",
        &integration_path,
        &integration_id,
    )?;
    assert_integration_round_trip(transport, &bootstrap_spec).await?;
    assert_conflict_skip_and_overwrite(
        config,
        "integration-policies",
        &integration_path,
        &integration_id,
    )?;

    // The command must refuse locally while attached. The dedicated wiremock
    // regression covers the no-parent-delete-route property offline.
    assert_attached_parent_conflict(config, &parent.id)?;
    delete_via_cli(config, "integration-policies", &integration_id)?;
    delete_via_cli(config, "agent-policies", &parent.id)?;
    assert_system_unchanged(transport, baseline, &version).await?;
    assert_applied_import(config, "agent-policies", &parent_path, &parent.id)?;
    assert_cli_transfer_reads(
        config,
        "agent-policies",
        &parent.id,
        &serde_json::to_value(vec![parent.clone()]).unwrap(),
    )?;
    assert_system_unchanged(transport, baseline, &version).await?;
    assert_applied_import(
        config,
        "integration-policies",
        &integration_path,
        &integration_id,
    )?;
    assert_cli_transfer_reads(
        config,
        "integration-policies",
        &integration_id,
        &serde_json::to_value(vec![bootstrap_spec.clone()]).unwrap(),
    )?;
    delete_via_cli(config, "integration-policies", &integration_id)?;
    delete_via_cli(config, "agent-policies", &parent.id)?;
    Ok(())
}

async fn setup_fleet(transport: &Transport) -> TestResult {
    let body = transport
        .post_once("/api/fleet/setup", Some(&json!({})))
        .await
        .map_err(|error| format!("setting up Fleet: {}", error.kind.as_str()))?;
    if body.get("isInitialized").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err("Fleet setup response was invalid".to_string())
    }
}

async fn prepare_fleet(transport: &Transport, controller_setup_complete: bool) -> TestResult {
    transport
        .require_feature(Feature::FleetPolicies)
        .await
        .map_err(|error| format!("Fleet feature gate: {}", error.kind.as_str()))?;
    if controller_setup_complete {
        Ok(())
    } else {
        setup_fleet(transport).await
    }
}

async fn ensure_system(
    transport: &Transport,
    baseline: &FleetState,
    cleanup: &mut FleetCleanup,
) -> TestResult<String> {
    let status = agent_policies::package_status(transport, SYSTEM_PACKAGE)
        .await
        .map_err(|error| format!("reading system package: {}", error.kind.as_str()))?;
    if status.status == "installed" {
        let version = status
            .installed_version
            .ok_or_else(|| "installed system has no version".to_string())?;
        if baseline.packages.get(SYSTEM_PACKAGE) != Some(&version) {
            return Err("system package status disagrees with baseline inventory".to_string());
        }
        return Ok(version);
    }
    if baseline.packages.contains_key(SYSTEM_PACKAGE) {
        return Err("system package baseline drifted before installation".to_string());
    }
    let raw = transport
        .get("/api/fleet/epm/packages/system")
        .await
        .map_err(|error| {
            format!(
                "reading system package latest version: {}",
                error.kind.as_str()
            )
        })?;
    let version = raw
        .pointer("/item/latestVersion")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "system package has no latest version".to_string())?
        .to_string();
    cleanup.claim_package(version.clone());
    let response = transport
        .post_once(
            &format!("/api/fleet/epm/packages/system/{}", urlencode(&version)),
            None,
        )
        .await;
    let response = match response {
        Ok(response) if decoded_system_install_success(&response) => response,
        Ok(_) => {
            return Err("system package install returned an invalid success response".to_string());
        }
        Err(_) => {
            // An unconfirmed claim is deliberately never uninstalled.
            let observed = installed_packages(transport).await.map_err(|error| {
                format!(
                    "observing ambiguous system install: {}",
                    error.kind.as_str()
                )
            })?;
            if observed == baseline.packages {
                return Err("system package install did not return a decoded success".to_string());
            }
            return Err("system package install is ambiguous".to_string());
        }
    };
    let _ = response;
    let exact = agent_policies::package_status(transport, SYSTEM_PACKAGE)
        .await
        .map_err(|error| format!("checking installed system: {}", error.kind.as_str()))?;
    let inventory = installed_packages(transport)
        .await
        .map_err(|error| format!("checking system package inventory: {}", error.kind.as_str()))?;
    if exact.status != "installed" || exact.installed_version.as_deref() != Some(&version) {
        return Err("system package install did not prove the exact version".to_string());
    }
    cleanup.confirm_package_owned(&version, &inventory)?;
    Ok(version)
}

/// Package installation returns a decoded asset-list response. Its response
/// does not carry the requested version coordinate, so the exact coordinate
/// remains proved by the status and inventory reads below.
fn decoded_system_install_success(body: &Value) -> bool {
    body.get("items")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().all(|item| {
                item.get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| !id.is_empty())
                    && item
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| !kind.is_empty())
            })
        })
        && body.pointer("/_meta/name").and_then(Value::as_str) == Some(SYSTEM_PACKAGE)
        && body
            .pointer("/_meta/install_source")
            .and_then(Value::as_str)
            == Some("registry")
}

async fn assert_system_unchanged(
    transport: &Transport,
    baseline: &FleetState,
    version: &str,
) -> TestResult {
    let inventory = installed_packages(transport).await.map_err(|error| {
        format!(
            "checking package inventory before policy create: {}",
            error.kind.as_str()
        )
    })?;
    let mut expected: PackageInventory = baseline.packages.clone();
    expected.insert(SYSTEM_PACKAGE.to_string(), version.to_string());
    if inventory != expected {
        return Err("package inventory drift blocks policy creation".to_string());
    }
    let status = agent_policies::package_status(transport, SYSTEM_PACKAGE)
        .await
        .map_err(|error| {
            format!(
                "checking system package before policy create: {}",
                error.kind.as_str()
            )
        })?;
    if status.status == "installed" && status.installed_version.as_deref() == Some(version) {
        Ok(())
    } else {
        Err("system package version drift blocks policy creation".to_string())
    }
}

fn write_artifact(
    config: &std::path::Path,
    name: &str,
    body: &Value,
) -> TestResult<std::path::PathBuf> {
    let path = config
        .parent()
        .ok_or_else(|| "live config has no parent".to_string())?
        .join(name);
    std::fs::write(&path, serde_json::to_vec(body).unwrap())
        .map_err(|error| format!("writing Fleet artifact: {error}"))?;
    Ok(path)
}

fn assert_cli_transfer_reads(
    config: &std::path::Path,
    policy_kind: &str,
    id: &str,
    expected_artifact: &Value,
) -> TestResult {
    let get = checked(
        cli(config).args(["fleet", policy_kind, "get", id, "--json"]),
        "Fleet get",
    )?;
    if json_output(&get, "Fleet get")?["id"] != id {
        return Err("Fleet get did not return the exact policy id".to_string());
    }
    let list = checked(
        cli(config).args([
            "fleet",
            policy_kind,
            "list",
            "--search",
            LIVE_PREFIX,
            "--json",
        ]),
        "Fleet marker list",
    )?;
    let rows = json_output(&list, "Fleet marker list")?;
    if rows
        .as_array()
        .is_none_or(|rows| rows.len() != 1 || rows[0]["id"] != id)
    {
        return Err("Fleet marker list was not an exact one-policy result".to_string());
    }
    for format in ["json", "yaml"] {
        let export = checked(
            cli(config).args(["fleet", policy_kind, "export", id, "--format-file", format]),
            "Fleet export",
        )?;
        let actual = if format == "json" {
            serde_json::from_slice::<Value>(&export.stdout)
                .map_err(|error| format!("decoding Fleet JSON export: {error}"))?
        } else {
            serde_yaml_ng::from_slice::<Value>(&export.stdout)
                .map_err(|error| format!("decoding Fleet YAML export: {error}"))?
        };
        if actual != *expected_artifact {
            return Err("Fleet export did not preserve the exact portable artifact".to_string());
        }
    }
    Ok(())
}

async fn assert_preview(
    transport: &Transport,
    config: &std::path::Path,
    policy_kind: &str,
    artifact: &std::path::Path,
    id: &str,
) -> TestResult {
    let out = checked(
        cli(config)
            .args(["fleet", policy_kind, "import", "--path"])
            .arg(artifact)
            .arg("--json"),
        "Fleet import preview",
    )?;
    let report = json_output(&out, "Fleet import preview")?;
    if report.get("applied").and_then(Value::as_bool) == Some(false) {
        let absence = match policy_kind {
            "agent-policies" => agent_policies::get(transport, id).await.map(|_| ()),
            "integration-policies" => integration_policies::get(transport, id).await.map(|_| ()),
            _ => return Err("unknown Fleet policy kind".to_string()),
        };
        match absence {
            Err(error) if error.kind == ErrorKind::NotFound => Ok(()),
            _ => Err("Fleet import preview changed remote policy state".to_string()),
        }
    } else {
        Err("Fleet import preview created a policy".to_string())
    }
}

fn assert_applied_import(
    config: &std::path::Path,
    policy_kind: &str,
    artifact: &std::path::Path,
    id: &str,
) -> TestResult {
    let out = checked(
        cli(config)
            .args(["fleet", policy_kind, "import", "--path"])
            .arg(artifact)
            .args(["--yes", "--json"]),
        "Fleet import apply",
    )?;
    let report = json_output(&out, "Fleet import apply")?;
    if report["applied"] == Value::Bool(true)
        && report["total"] == 1
        && report["succeeded"] == json!([{"id": id, "action": "created"}])
        && report["unchanged"] == json!([])
        && report["skipped"] == json!([])
        && report["failed"] == json!([])
        && report["affected_agents"] == 0
        && report["package_installs"] == json!([])
    {
        Ok(())
    } else {
        Err("Fleet import did not report the selected policy".to_string())
    }
}

fn assert_conflict_skip_and_overwrite(
    config: &std::path::Path,
    policy_kind: &str,
    artifact: &std::path::Path,
    id: &str,
) -> TestResult {
    let conflict = cli(config)
        .args(["fleet", policy_kind, "import", "--path"])
        .arg(artifact)
        .args(["--yes", "--json"])
        .output()
        .map_err(|error| format!("running Fleet conflict import: {error}"))?;
    if conflict.status.success() {
        return Err("Fleet conflict import unexpectedly succeeded".to_string());
    }
    require_conflict_error(&conflict.stderr, "Fleet conflict import")?;
    let skip = checked(
        cli(config)
            .args(["fleet", policy_kind, "import", "--path"])
            .arg(artifact)
            .args(["--yes", "--skip-existing", "--json"]),
        "Fleet skip import",
    )?;
    let report = json_output(&skip, "Fleet skip import")?;
    if report["applied"] != Value::Bool(true)
        || report["total"] != 1
        || report["succeeded"] != json!([])
        || report["unchanged"] != json!([])
        || report["skipped"] != json!([{"id": id, "reason": "exists"}])
        || report["failed"] != json!([])
        || report["affected_agents"] != 0
        || report["package_installs"] != json!([])
    {
        return Err("Fleet skip import did not report the policy".to_string());
    }
    let overwrite = checked(
        cli(config)
            .args(["fleet", policy_kind, "import", "--path"])
            .arg(artifact)
            .args(["--yes", "--overwrite", "--json"]),
        "Fleet overwrite import",
    )?;
    let report = json_output(&overwrite, "Fleet overwrite import")?;
    if !is_unchanged_overwrite_report(&report, id) {
        return Err("Fleet unchanged overwrite report was not exact".to_string());
    }
    Ok(())
}

fn assert_overwrite(
    config: &std::path::Path,
    policy_kind: &str,
    artifact: &std::path::Path,
    id: &str,
) -> TestResult {
    let out = checked(
        cli(config)
            .args(["fleet", policy_kind, "import", "--path"])
            .arg(artifact)
            .args(["--yes", "--overwrite", "--json"]),
        "Fleet changed overwrite",
    )?;
    let report = json_output(&out, "Fleet changed overwrite")?;
    if is_changed_overwrite_report(&report, id) {
        Ok(())
    } else {
        Err("Fleet overwrite did not report the changed policy".to_string())
    }
}

fn require_conflict_error(stderr: &[u8], operation: &str) -> TestResult {
    let error = serde_json::from_slice::<Value>(stderr)
        .map_err(|error| format!("decoding {operation} error: {error}"))?;
    if error["error"]["kind"] == "conflict" {
        Ok(())
    } else {
        Err(format!("{operation} did not report a conflict error"))
    }
}

fn is_unchanged_overwrite_report(report: &Value, id: &str) -> bool {
    report["applied"] == Value::Bool(true)
        && report["total"] == 1
        && report["succeeded"] == json!([])
        && report["unchanged"] == json!([{"id": id}])
        && report["skipped"] == json!([])
        && report["failed"] == json!([])
        && report["affected_agents"] == 0
        && report["package_installs"] == json!([])
}

fn is_changed_overwrite_report(report: &Value, id: &str) -> bool {
    report["applied"] == Value::Bool(true)
        && report["total"] == 1
        && report["succeeded"] == json!([{"id": id, "action": "replaced"}])
        && report["unchanged"] == json!([])
        && report["skipped"] == json!([])
        && report["failed"] == json!([])
        && report["affected_agents"] == 0
        && report["package_installs"] == json!([])
}

fn delete_via_cli(config: &std::path::Path, policy_kind: &str, id: &str) -> TestResult {
    checked(
        cli(config).args(["fleet", policy_kind, "delete", id, "--yes", "--json"]),
        "Fleet delete",
    )?;
    Ok(())
}

fn assert_attached_parent_conflict(config: &std::path::Path, parent_id: &str) -> TestResult {
    let output = cli(config)
        .args([
            "fleet",
            "agent-policies",
            "delete",
            parent_id,
            "--yes",
            "--json",
        ])
        .output()
        .map_err(|error| format!("running attached parent delete: {error}"))?;
    if !output.status.success()
        && require_conflict_error(&output.stderr, "attached parent delete").is_ok()
    {
        Ok(())
    } else {
        Err("attached Fleet parent delete was not refused".to_string())
    }
}

async fn assert_agent_round_trip(
    transport: &Transport,
    expected: &elasticctl_api::fleet::agent_policies::AgentPolicySpec,
) -> TestResult {
    let actual = agent_policy_ops::normalize(
        &agent_policies::get(transport, &expected.id)
            .await
            .map_err(|error| error.kind.as_str().to_string())?
            .item,
        transport.space(),
    )
    .map_err(|error| error.kind.as_str().to_string())?;
    if &actual == expected {
        Ok(())
    } else {
        Err("Fleet agent policy did not round trip exactly".to_string())
    }
}

async fn assert_integration_round_trip(
    transport: &Transport,
    expected: &elasticctl_api::fleet::integration_policies::IntegrationPolicySpec,
) -> TestResult {
    let exported = integration_policy_ops::export(
        transport,
        std::slice::from_ref(&expected.id),
        false,
        ContentFormat::Json,
    )
    .await
    .map_err(|error| error.kind.as_str().to_string())?;
    if one_integration_spec(
        &serde_json::from_str::<Value>(&exported.body).map_err(|error| error.to_string())?,
    )? == *expected
    {
        Ok(())
    } else {
        Err("Fleet integration did not round trip exactly".to_string())
    }
}

fn one_agent_spec(
    value: &Value,
) -> TestResult<elasticctl_api::fleet::agent_policies::AgentPolicySpec> {
    let mut specs = serde_json::from_value::<Vec<_>>(value.clone())
        .map_err(|error| error.to_string())?
        .into_iter();
    let spec = specs
        .next()
        .ok_or_else(|| "Fleet agent artifact was empty".to_string())?;
    if specs.next().is_some() {
        return Err("Fleet agent artifact must contain exactly one policy".to_string());
    }
    Ok(spec)
}

fn one_integration_spec(
    value: &Value,
) -> TestResult<elasticctl_api::fleet::integration_policies::IntegrationPolicySpec> {
    let mut specs = serde_json::from_value::<Vec<_>>(value.clone())
        .map_err(|error| error.to_string())?
        .into_iter();
    let spec = specs
        .next()
        .ok_or_else(|| "Fleet integration artifact was empty".to_string())?;
    if specs.next().is_some() {
        return Err("Fleet integration artifact must contain exactly one policy".to_string());
    }
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::cleanup::PackageLease;
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A delete attempt made ambiguous by transport failure must retain the
    /// cleanup obligation, rather than permitting a second delete request.
    #[test]
    fn ambiguous_package_delete_retains_cleanup_pending_lease() {
        let lease = PackageLease::owned("2.0.0");
        assert_eq!(
            lease.begin_cleanup(),
            PackageLease::cleanup_pending("2.0.0")
        );
    }

    /// A package discovered before this run is outside this lease even when
    /// the package name matches the conformance dependency.
    #[test]
    fn preexisting_package_cannot_become_cleanup_owned() {
        assert!(PackageLease::none().can_uninstall().is_none());
    }

    #[tokio::test]
    async fn attached_parent_delete_stops_before_the_mutation_route() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": {"number": "9.5.1", "build_flavor": "traditional"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
                "id": "parent-1", "name": "Parent", "namespace": "default",
                "description": "test", "inactivity_timeout": 1209600,
                "monitoring_enabled": [], "agent_features": [], "global_data_tags": [],
                "agents": 0, "package_policies": ["integration-1"],
                "is_default": false, "is_default_fleet_server": false,
                "has_fleet_server": null, "is_managed": false,
                "is_preconfigured": false, "is_verifier": null,
                "supports_agentless": null, "is_protected": false,
                "agentless": null, "space_ids": ["default"]
            }})))
            .mount(&server)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "current = \"default\"\n\n[profiles.default]\nkibana_url = \"{}\"\napi_key = \"test\"\nspace = \"default\"\nverify = true\ntimeout_secs = 5\n",
                server.uri()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let output = bin()
            .args(["--config"])
            .arg(&config)
            .args([
                "fleet",
                "agent-policies",
                "delete",
                "parent-1",
                "--yes",
                "--json",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"]["kind"], "conflict");
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            request.url.path() != "/api/fleet/agent_policies/delete"
                && !matches!(request.method.as_str(), "POST" | "PUT" | "DELETE" | "PATCH")
        }));
    }

    #[tokio::test]
    async fn standalone_setup_runs_once_and_controller_child_skips_it() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": {"number": "9.5.1", "build_flavor": "traditional"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/setup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"isInitialized": true})))
            .mount(&server)
            .await;
        let profile = Profile {
            kibana_url: server.uri(),
            es_url: None,
            api_key: Some("test".to_string()),
            username: None,
            password: None,
            space: "default".to_string(),
            verify: true,
            timeout_secs: 1,
        };
        let transport = Transport::new(&profile).unwrap();
        prepare_fleet(&transport, false).await.unwrap();
        prepare_fleet(&transport, true).await.unwrap();
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.url.path() == "/api/fleet/setup")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn unsupported_fleet_floor_stops_before_setup() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": {"number": "9.5.0", "build_flavor": "traditional"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/setup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"isInitialized": true})))
            .mount(&server)
            .await;
        let profile = Profile {
            kibana_url: server.uri(),
            es_url: None,
            api_key: Some("test".to_string()),
            username: None,
            password: None,
            space: "default".to_string(),
            verify: true,
            timeout_secs: 1,
        };
        assert!(
            prepare_fleet(&Transport::new(&profile).unwrap(), false)
                .await
                .is_err()
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.url.path() != "/api/fleet/setup")
        );
    }

    async fn install_transport(server: &MockServer) -> (Profile, FleetState) {
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": {"number": "9.5.1", "build_flavor": "traditional"}
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
                "name": "system", "status": "not_installed", "latestVersion": "2.0.0"
            }})))
            .mount(server)
            .await;
        (
            Profile {
                kibana_url: server.uri(),
                es_url: None,
                api_key: Some("test".to_string()),
                username: None,
                password: None,
                space: "default".to_string(),
                verify: true,
                timeout_secs: 1,
            },
            FleetState {
                agent_policies: BTreeSet::new(),
                integration_policies: BTreeSet::new(),
                packages: PackageInventory::new(),
            },
        )
    }

    #[tokio::test]
    async fn malformed_install_success_stays_claimed_and_never_uninstalls() {
        let server = MockServer::start().await;
        let (profile, baseline) = install_transport(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;
        let transport = Transport::new(&profile).unwrap();
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline.clone());
        assert!(
            ensure_system(&transport, &baseline, &mut cleanup)
                .await
                .is_err()
        );
        assert!(cleanup.finish_async().await.is_err());
        drop(cleanup);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "POST")
                .count(),
            1
        );
        assert!(requests.iter().all(|request| request.method != "DELETE"));
    }

    #[tokio::test]
    async fn failed_install_then_other_owner_install_never_uninstalls() {
        let server = MockServer::start().await;
        let (profile, baseline) = install_transport(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "lost"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"name": "system", "version": "2.0.0", "status": "installed"}], "total": 1
            })))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;
        let transport = Transport::new(&profile).unwrap();
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline.clone());
        assert!(
            ensure_system(&transport, &baseline, &mut cleanup)
                .await
                .is_err()
        );
        assert!(cleanup.finish_async().await.is_err());
        drop(cleanup);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "POST")
                .count(),
            1
        );
        assert!(requests.iter().all(|request| request.method != "DELETE"));
    }

    #[tokio::test]
    async fn claimed_before_install_send_then_foreign_install_never_uninstalls() {
        let server = MockServer::start().await;
        let (profile, baseline) = install_transport(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"name": "system", "version": "2.0.0", "status": "installed"}], "total": 1
            })))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline);
        cleanup.claim_package("2.0.0");
        assert!(cleanup.finish_async().await.is_err());
        drop(cleanup);
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| request.method != "POST"));
        assert!(requests.iter().all(|request| request.method != "DELETE"));
    }

    #[tokio::test]
    async fn failed_install_with_unreadable_observation_never_uninstalls() {
        let server = MockServer::start().await;
        let (profile, baseline) = install_transport(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "lost"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "lost"})))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;
        let transport = Transport::new(&profile).unwrap();
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline.clone());
        assert!(
            ensure_system(&transport, &baseline, &mut cleanup)
                .await
                .is_err()
        );
        assert!(cleanup.finish_async().await.is_err());
        drop(cleanup);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "POST")
                .count(),
            1
        );
        assert!(requests.iter().all(|request| request.method != "DELETE"));
    }

    #[test]
    fn single_policy_artifact_decoders_reject_extra_rows() {
        let parent = json!({
            "id": "parent-1", "name": "Parent", "namespace": "default",
            "inactivity_timeout": 1209600, "monitoring_enabled": [],
            "agent_features": [], "global_data_tags": []
        });
        assert!(one_agent_spec(&json!([parent.clone(), parent])).is_err());

        let integration = json!({
            "id": "integration-1", "name": "Integration", "namespace": "default",
            "policy_ids": ["parent-1"],
            "package": {"name": "system", "version": "2.0.0"}, "inputs": {}
        });
        assert!(one_integration_spec(&json!([integration.clone(), integration])).is_err());
    }

    #[test]
    fn default_conflict_requires_the_structured_conflict_kind() {
        assert!(
            require_conflict_error(
                br#"{"error":{"kind":"error","message":"conflict while parsing"}}"#,
                "Fleet conflict import",
            )
            .is_err()
        );
        assert!(
            require_conflict_error(
                br#"{"error":{"kind":"conflict","message":"other"}}"#,
                "Fleet conflict import",
            )
            .is_ok()
        );
    }

    #[test]
    fn overwrite_reports_require_applied_true() {
        let mut changed = json!({
            "applied": true, "total": 1,
            "succeeded": [{"id": "policy-1", "action": "replaced"}],
            "unchanged": [], "skipped": [], "failed": [],
            "affected_agents": 0, "package_installs": []
        });
        assert!(is_changed_overwrite_report(&changed, "policy-1"));
        changed["applied"] = Value::Bool(false);
        assert!(!is_changed_overwrite_report(&changed, "policy-1"));

        let mut unchanged = json!({
            "applied": true, "total": 1, "succeeded": [],
            "unchanged": [{"id": "policy-1"}], "skipped": [], "failed": [],
            "affected_agents": 0, "package_installs": []
        });
        assert!(is_unchanged_overwrite_report(&unchanged, "policy-1"));
        unchanged["applied"] = Value::Bool(false);
        assert!(!is_unchanged_overwrite_report(&unchanged, "policy-1"));
    }
}
