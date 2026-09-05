use std::collections::BTreeSet;

use elasticctl_api::content_codec::ContentFormat;
use elasticctl_api::fleet::{
    agent_policies, agent_policy_ops, integration_policies, integration_policy_ops,
};
use elasticctl_api_test_support::fleet::{FleetState, PackageInventory, installed_packages};
use elasticctl_core::{ErrorKind, Profile, Transport, urlencode};
use serde_json::{Map, Value, json};

type CleanupResult<T = ()> = Result<T, String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PackageLease {
    None,
    Claimed { version: String },
    Owned { version: String },
    CleanupPending { version: String },
}

impl PackageLease {
    pub(super) fn none() -> Self {
        Self::None
    }

    pub(super) fn claimed(version: impl Into<String>) -> Self {
        Self::Claimed {
            version: version.into(),
        }
    }

    pub(super) fn owned(version: impl Into<String>) -> Self {
        Self::Owned {
            version: version.into(),
        }
    }

    pub(super) fn cleanup_pending(version: impl Into<String>) -> Self {
        Self::CleanupPending {
            version: version.into(),
        }
    }

    pub(super) fn begin_cleanup(&self) -> Self {
        match self {
            Self::Owned { version } => Self::cleanup_pending(version.clone()),
            other => other.clone(),
        }
    }

    pub(super) fn can_uninstall(&self) -> Option<&str> {
        match self {
            Self::Owned { version } | Self::CleanupPending { version } => Some(version),
            Self::None | Self::Claimed { .. } => None,
        }
    }
}

#[derive(Clone)]
struct ParentLease {
    id: String,
    nonce: String,
    allowed: Vec<elasticctl_api::fleet::agent_policies::AgentPolicySpec>,
    delete_attempted: bool,
}

#[derive(Clone)]
struct IntegrationLease {
    id: String,
    nonce: String,
    allowed: Vec<elasticctl_api::fleet::integration_policies::IntegrationPolicySpec>,
    bootstrap: Option<elasticctl_api::fleet::integration_policies::IntegrationPolicySpec>,
    delete_attempted: bool,
}

/// Test-only cleanup state for the Fleet contract. It never discovers marker
/// objects by name: every mutation starts with a fresh exact GET and an owned
/// id registered before the operation that may create it.
pub(super) struct FleetCleanup {
    profile: Profile,
    nonce: String,
    parents: Vec<ParentLease>,
    integrations: Vec<IntegrationLease>,
    baseline: FleetState,
    package: PackageLease,
    finished: bool,
}

impl FleetCleanup {
    pub(super) fn new(profile: Profile, nonce: String, baseline: FleetState) -> Self {
        Self {
            profile,
            nonce,
            parents: Vec::new(),
            integrations: Vec::new(),
            baseline,
            package: PackageLease::None,
            finished: false,
        }
    }

    pub(super) fn claim_package(&mut self, version: impl Into<String>) {
        self.package = PackageLease::claimed(version);
    }

    pub(super) fn confirm_package_owned(
        &mut self,
        version: &str,
        inventory: &PackageInventory,
    ) -> CleanupResult {
        if !matches!(&self.package, PackageLease::Claimed { version: claimed } if claimed == version)
        {
            return Err("Fleet package lease was not claimed for the observed version".to_string());
        }
        if self.baseline.packages.contains_key("system")
            || inventory != &inventory_with_system(&self.baseline.packages, version)
        {
            return Err(
                "Fleet package install did not preserve the baseline inventory".to_string(),
            );
        }
        self.package = PackageLease::owned(version);
        Ok(())
    }

    pub(super) fn register_parent(
        &mut self,
        id: String,
        expected: elasticctl_api::fleet::agent_policies::AgentPolicySpec,
    ) -> CleanupResult {
        check_marker(&id, &self.nonce, expected.description.as_deref())?;
        self.parents.push(ParentLease {
            id,
            nonce: self.nonce.clone(),
            allowed: vec![expected],
            delete_attempted: false,
        });
        Ok(())
    }

    pub(super) fn register_integration(
        &mut self,
        id: String,
        expected: elasticctl_api::fleet::integration_policies::IntegrationPolicySpec,
    ) -> CleanupResult {
        check_marker(&id, &self.nonce, expected.description.as_deref())?;
        self.integrations.push(IntegrationLease {
            id,
            nonce: self.nonce.clone(),
            allowed: vec![expected],
            bootstrap: None,
            delete_attempted: false,
        });
        Ok(())
    }

    pub(super) fn allow_parent_state(
        &mut self,
        id: &str,
        expected: elasticctl_api::fleet::agent_policies::AgentPolicySpec,
    ) -> CleanupResult {
        let lease = self
            .parents
            .iter_mut()
            .find(|lease| lease.id == id)
            .ok_or_else(|| "Fleet parent was not registered for cleanup".to_string())?;
        check_marker(&lease.id, &lease.nonce, expected.description.as_deref())?;
        lease.allowed.push(expected);
        Ok(())
    }

    pub(super) fn allow_integration_state(
        &mut self,
        id: &str,
        expected: elasticctl_api::fleet::integration_policies::IntegrationPolicySpec,
    ) -> CleanupResult {
        let lease = self
            .integrations
            .iter_mut()
            .find(|lease| lease.id == id)
            .ok_or_else(|| "Fleet integration was not registered for cleanup".to_string())?;
        check_marker(&lease.id, &lease.nonce, expected.description.as_deref())?;
        lease.allowed.push(expected);
        lease.bootstrap = None;
        Ok(())
    }

    pub(super) async fn materialize_system_inputs(
        &mut self,
        transport: &Transport,
        expected: elasticctl_api::fleet::integration_policies::IntegrationPolicySpec,
    ) -> Result<elasticctl_api::fleet::integration_policies::IntegrationPolicySpec, String> {
        if !expected.inputs.is_empty()
            || expected.policy_ids.len() != 1
            || expected.package.name != "system"
            || expected
                .namespace
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            || expected
                .description
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            || !self
                .parents
                .iter()
                .any(|parent| parent.id == expected.policy_ids[0] && !parent.delete_attempted)
        {
            return Err("Fleet bootstrap specification is outside the cleanup lease".to_string());
        }
        require_exact_system_package(transport, &self.baseline, &expected.package.version).await?;
        self.register_integration(expected.id.clone(), expected.clone())?;
        self.integrations
            .iter_mut()
            .find(|lease| lease.id == expected.id)
            .expect("bootstrap lease was registered above")
            .bootstrap = Some(expected.clone());

        let body = serde_json::to_value(&expected)
            .map_err(|_| "encoding Fleet bootstrap failed".to_string())?;
        let create = transport
            .post_once("/api/fleet/package_policies?format=simplified", Some(&body))
            .await;
        let create_result = match create {
            Ok(response) => response
                .get("item")
                .and_then(Value::as_object)
                .ok_or_else(|| "Fleet bootstrap create response was invalid".to_string())
                .and_then(|item| {
                    validate_bootstrap_live(&expected, item, transport.space()).map(|_| ())
                }),
            Err(_) => Err("Fleet bootstrap create was ambiguous".to_string()),
        };

        let current = integration_policies::get(transport, &expected.id)
            .await
            .map_err(|_| "reading Fleet bootstrap after create failed".to_string())?
            .item;
        let materialized = validate_bootstrap_live(&expected, &current, transport.space())?;
        let exported = export_exact_integration(transport, &expected.id).await?;
        if exported != materialized {
            return Err("Fleet bootstrap export did not match its exact read".to_string());
        }
        self.allow_integration_state(&expected.id, materialized.clone())?;

        let lease = self
            .integrations
            .iter_mut()
            .find(|lease| lease.id == expected.id)
            .expect("bootstrap lease was registered above");
        delete_owned_integration(transport, lease).await?;

        let parent = self
            .parents
            .iter()
            .find(|parent| parent.id == expected.policy_ids[0])
            .expect("bootstrap parent was checked above");
        let current_parent = agent_policies::get(transport, &parent.id)
            .await
            .map_err(|_| "reading Fleet bootstrap parent after delete failed".to_string())?
            .item;
        assert_owned_parent(parent, &current_parent, transport.space())?;
        create_result?;
        Ok(materialized)
    }

    pub(super) fn finish(&mut self) -> CleanupResult {
        let result = self.clean();
        if result.is_ok() {
            self.finished = true;
        }
        result
    }

    pub(super) async fn finish_async(&mut self) -> CleanupResult {
        let result = self.clean_async().await;
        if result.is_ok() {
            self.finished = true;
        }
        result
    }

    async fn clean_async(&mut self) -> CleanupResult {
        let profile = self.profile.clone();
        let transport = Transport::new(&profile).map_err(|error| {
            format!("building Fleet cleanup transport: {}", error.kind.as_str())
        })?;
        for integration in &mut self.integrations {
            delete_owned_integration(&transport, integration).await?;
        }
        for parent in &mut self.parents {
            delete_owned_parent(&transport, parent).await?;
        }
        cleanup_package(
            &transport,
            &self.baseline,
            &self.parents,
            &self.integrations,
            &mut self.package,
        )
        .await
    }

    fn clean(&mut self) -> CleanupResult {
        tokio::runtime::Runtime::new()
            .map_err(|error| format!("building Fleet cleanup runtime: {error}"))?
            .block_on(self.clean_async())
    }
}

impl Drop for FleetCleanup {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if tokio::runtime::Handle::try_current().is_ok() {
                std::thread::scope(|scope| {
                    let _ = scope.spawn(|| self.clean()).join();
                });
            } else {
                let _ = self.clean();
            }
        }));
    }
}

async fn delete_owned_integration(
    transport: &Transport,
    lease: &mut IntegrationLease,
) -> CleanupResult {
    let current = match integration_policies::get(transport, &lease.id).await {
        Ok(policy) => policy.item,
        Err(error) if error.kind == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "reading Fleet integration for cleanup: {}",
                error.kind.as_str()
            ));
        }
    };
    if let Some(expected) = lease.bootstrap.clone() {
        let materialized = validate_bootstrap_live(&expected, &current, transport.space())?;
        let exported = export_exact_integration(transport, &lease.id).await?;
        if exported != materialized {
            return Err("Fleet bootstrap export did not match its exact read".to_string());
        }
        lease.allowed.push(materialized);
        lease.bootstrap = None;
    }
    assert_owned_integration(transport, lease, &current).await?;
    if !lease.delete_attempted {
        lease.delete_attempted = true;
        let path = format!("/api/fleet/package_policies/{}", urlencode(&lease.id));
        let _ = transport.delete_once(&path).await;
    }
    observe_integration_absent(transport, &lease.id).await
}

async fn delete_owned_parent(transport: &Transport, lease: &mut ParentLease) -> CleanupResult {
    let current = match agent_policies::get(transport, &lease.id).await {
        Ok(policy) => policy.item,
        Err(error) if error.kind == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "reading Fleet agent policy for cleanup: {}",
                error.kind.as_str()
            ));
        }
    };
    assert_owned_parent(lease, &current, transport.space())?;
    if !lease.delete_attempted {
        lease.delete_attempted = true;
        let path = "/api/fleet/agent_policies/delete";
        let body = json!({"agentPolicyId": lease.id});
        let _ = transport.post_once(path, Some(&body)).await;
    }
    observe_parent_absent(transport, &lease.id).await
}

async fn cleanup_package(
    transport: &Transport,
    baseline: &FleetState,
    parents: &[ParentLease],
    integrations: &[IntegrationLease],
    lease: &mut PackageLease,
) -> CleanupResult {
    if matches!(lease, PackageLease::Claimed { .. }) {
        let observed = installed_packages(transport)
            .await
            .map_err(|error| format!("observing claimed Fleet package: {}", error.kind.as_str()))?;
        if observed == baseline.packages {
            *lease = PackageLease::None;
            return Ok(());
        }
        return Err("a claimed Fleet package install could not be proved absent".to_string());
    }
    let Some(version) = lease.can_uninstall().map(str::to_owned) else {
        return Ok(());
    };
    if matches!(lease, PackageLease::CleanupPending { .. }) {
        let observed = installed_packages(transport)
            .await
            .map_err(|error| format!("observing Fleet package cleanup: {}", error.kind.as_str()))?;
        return if observed == baseline.packages {
            *lease = PackageLease::None;
            Ok(())
        } else {
            Err("Fleet package removal could not be proved".to_string())
        };
    }
    let state = FleetState::capture(transport)
        .await
        .map_err(|error| format!("checking Fleet cleanup state: {}", error.kind.as_str()))?;
    let owned_parents: BTreeSet<_> = parents.iter().map(|parent| parent.id.as_str()).collect();
    let owned_integrations: BTreeSet<_> = integrations
        .iter()
        .map(|integration| integration.id.as_str())
        .collect();
    if !state.agent_policies.is_empty() || !state.integration_policies.is_empty() {
        if state
            .agent_policies
            .iter()
            .all(|id| owned_parents.contains(id.as_str()))
            && state
                .integration_policies
                .iter()
                .all(|id| owned_integrations.contains(id.as_str()))
        {
            return Err("Fleet cleanup left owned policy markers".to_string());
        }
        return Err("Fleet cleanup found an unowned marker policy".to_string());
    }
    if state.packages != inventory_with_system(&baseline.packages, &version) {
        return Err("Fleet package inventory drift blocks uninstall".to_string());
    }
    let status = agent_policies::package_status(transport, "system")
        .await
        .map_err(|error| format!("checking Fleet package status: {}", error.kind.as_str()))?;
    if status.status != "installed" || status.installed_version.as_deref() != Some(&version) {
        return Err("Fleet package version drift blocks uninstall".to_string());
    }
    require_no_system_consumers(transport).await?;
    *lease = PackageLease::cleanup_pending(version.clone());
    let path = format!("/api/fleet/epm/packages/system/{}", urlencode(&version));
    let _ = transport.delete_once(&path).await;
    let observed = installed_packages(transport)
        .await
        .map_err(|error| format!("observing Fleet package cleanup: {}", error.kind.as_str()))?;
    if observed == baseline.packages {
        *lease = PackageLease::None;
        Ok(())
    } else {
        Err("Fleet package removal could not be proved".to_string())
    }
}

/// FleetState intentionally retains marker ids only. Package removal needs the
/// complete package-policy list because an unrelated policy can consume the
/// same exact coordinate without appearing in that marker-only audit.
async fn require_no_system_consumers(transport: &Transport) -> CleanupResult {
    let policies = integration_policy_ops::collect(transport)
        .await
        .map_err(|_| "reading Fleet package consumers failed".to_string())?;
    for policy in policies {
        policy
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| "reading Fleet package consumers failed".to_string())?;
        let package = policy
            .get("package")
            .and_then(Value::as_object)
            .ok_or_else(|| "reading Fleet package consumers failed".to_string())?;
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "reading Fleet package consumers failed".to_string())?;
        package
            .get("version")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "reading Fleet package consumers failed".to_string())?;
        if name == "system" {
            return Err("a Fleet policy still consumes the claimed system package".to_string());
        }
    }
    Ok(())
}

fn assert_owned_parent(
    lease: &ParentLease,
    current: &Map<String, Value>,
    space: &str,
) -> CleanupResult {
    require_string(current, "id")?;
    require_string(current, "name")?;
    require_string(current, "namespace")?;
    require_string(current, "description")?;
    require_u64(current, "inactivity_timeout")?;
    require_array(current, "monitoring_enabled")?;
    require_u64(current, "agents")?;
    require_array(current, "package_policies")?;
    require_optional_safe_parent_fields(current, space)?;
    check_marker(
        &lease.id,
        &lease.nonce,
        current.get("description").and_then(Value::as_str),
    )?;
    let actual = agent_policy_ops::normalize(current, space)
        .map_err(|_| "Fleet parent is outside the cleanup lease".to_string())?;
    if !lease.allowed.contains(&actual)
        || current.get("agents").and_then(Value::as_u64) != Some(0)
        || current
            .get("package_policies")
            .and_then(Value::as_array)
            .is_none_or(|items| !items.is_empty())
    {
        return Err("Fleet parent is outside the cleanup lease".to_string());
    }
    Ok(())
}

async fn assert_owned_integration(
    transport: &Transport,
    lease: &IntegrationLease,
    current: &Map<String, Value>,
) -> CleanupResult {
    validate_integration_live_fields(current, transport.space())?;
    check_marker(
        &lease.id,
        &lease.nonce,
        current.get("description").and_then(Value::as_str),
    )?;
    let actual = integration_policy_ops::normalize(current, transport.space())
        .map_err(|_| "Fleet integration is outside the cleanup lease".to_string())?;
    if !lease.allowed.contains(&actual)
        || current.get("enabled").and_then(Value::as_bool) != Some(true)
    {
        return Err("Fleet integration is outside the cleanup lease".to_string());
    }
    let exported = export_exact_integration(transport, &lease.id).await?;
    if exported != actual {
        return Err("Fleet integration cannot be exported safely for cleanup".to_string());
    }
    Ok(())
}

fn validate_bootstrap_live(
    expected: &elasticctl_api::fleet::integration_policies::IntegrationPolicySpec,
    current: &Map<String, Value>,
    space: &str,
) -> CleanupResult<elasticctl_api::fleet::integration_policies::IntegrationPolicySpec> {
    validate_integration_live_fields(current, space)?;
    let actual = integration_policy_ops::normalize(current, space)
        .map_err(|_| "Fleet bootstrap is outside the cleanup lease".to_string())?;
    let mut identity = actual.clone();
    identity.inputs.clear();
    if identity != *expected || actual.inputs.is_empty() {
        return Err("Fleet bootstrap is outside the cleanup lease".to_string());
    }
    Ok(actual)
}

async fn export_exact_integration(
    transport: &Transport,
    id: &str,
) -> CleanupResult<elasticctl_api::fleet::integration_policies::IntegrationPolicySpec> {
    let exported =
        integration_policy_ops::export(transport, &[id.to_string()], false, ContentFormat::Json)
            .await
            .map_err(|_| "Fleet integration cannot be exported safely for cleanup".to_string())?;
    let mut specs = elasticctl_api::content_codec::decode_sequence::<
        elasticctl_api::fleet::integration_policies::IntegrationPolicySpec,
    >(&exported.body, ContentFormat::Json, "integration policy")
    .map_err(|_| "Fleet integration cannot be exported safely for cleanup".to_string())?;
    if exported.exported != 1 || !exported.missing.is_empty() || specs.len() != 1 {
        return Err("Fleet integration cannot be exported safely for cleanup".to_string());
    }
    Ok(specs.pop().expect("one exported integration was checked"))
}

async fn require_exact_system_package(
    transport: &Transport,
    baseline: &FleetState,
    version: &str,
) -> CleanupResult {
    if version.trim().is_empty() {
        return Err("Fleet system package version is empty".to_string());
    }
    let inventory = installed_packages(transport)
        .await
        .map_err(|error| format!("checking Fleet package inventory: {}", error.kind.as_str()))?;
    let expected = match baseline.packages.get("system") {
        Some(baseline_version) if baseline_version == version => baseline.packages.clone(),
        Some(_) => return Err("Fleet system package baseline version changed".to_string()),
        None => inventory_with_system(&baseline.packages, version),
    };
    if inventory != expected {
        return Err("Fleet package inventory drift blocks policy creation".to_string());
    }
    let status = agent_policies::package_status(transport, "system")
        .await
        .map_err(|error| format!("checking Fleet package status: {}", error.kind.as_str()))?;
    if status.status == "installed" && status.installed_version.as_deref() == Some(version) {
        Ok(())
    } else {
        Err("Fleet package version drift blocks policy creation".to_string())
    }
}

fn require_string<'a>(item: &'a Map<String, Value>, field: &str) -> CleanupResult<&'a str> {
    item.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Fleet policy is outside the cleanup lease".to_string())
}

fn require_u64(item: &Map<String, Value>, field: &str) -> CleanupResult<u64> {
    item.get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| "Fleet policy is outside the cleanup lease".to_string())
}

fn require_array<'a>(item: &'a Map<String, Value>, field: &str) -> CleanupResult<&'a Vec<Value>> {
    item.get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| "Fleet policy is outside the cleanup lease".to_string())
}

fn optional_false(item: &Map<String, Value>, fields: &[&str]) -> bool {
    fields.iter().all(|field| {
        matches!(
            item.get(*field),
            None | Some(Value::Null) | Some(Value::Bool(false))
        )
    })
}

fn optional_null(item: &Map<String, Value>, fields: &[&str]) -> bool {
    fields
        .iter()
        .all(|field| matches!(item.get(*field), None | Some(Value::Null)))
}

fn optional_empty_array(item: &Map<String, Value>, fields: &[&str]) -> bool {
    fields.iter().all(|field| match item.get(*field) {
        None | Some(Value::Null) => true,
        Some(Value::Array(values)) => values.is_empty(),
        Some(_) => false,
    })
}

fn only_active_spaces(item: &Map<String, Value>, fields: &[&str], space: &str) -> bool {
    let active = if space.is_empty() { "default" } else { space };
    fields.iter().all(|field| match item.get(*field) {
        None | Some(Value::Null) => true,
        Some(Value::Array(spaces)) => spaces.iter().all(|value| value.as_str() == Some(active)),
        Some(_) => false,
    })
}

fn require_optional_safe_parent_fields(item: &Map<String, Value>, space: &str) -> CleanupResult {
    if optional_false(
        item,
        &[
            "is_default",
            "is_default_fleet_server",
            "has_fleet_server",
            "is_managed",
            "is_preconfigured",
            "is_verifier",
            "supports_agentless",
            "is_protected",
        ],
    ) && optional_null(item, &["agentless"])
        && optional_null(
            item,
            &[
                "data_output_id",
                "monitoring_output_id",
                "download_source_id",
                "fleet_server_host_id",
                "required_versions",
            ],
        )
        && only_active_spaces(item, &["space_ids", "spaceIds"], space)
    {
        Ok(())
    } else {
        Err("Fleet parent is outside the cleanup lease".to_string())
    }
}

fn validate_integration_live_fields(item: &Map<String, Value>, space: &str) -> CleanupResult {
    for field in ["id", "name", "namespace", "description"] {
        require_string(item, field)?;
    }
    let policy_ids = require_array(item, "policy_ids")?;
    if policy_ids.len() != 1
        || policy_ids[0]
            .as_str()
            .is_none_or(|value| value.trim().is_empty())
        || item
            .get("package")
            .and_then(Value::as_object)
            .is_none_or(|package| {
                package
                    .get("name")
                    .and_then(Value::as_str)
                    .is_none_or(|value| value.trim().is_empty())
                    || package
                        .get("version")
                        .and_then(Value::as_str)
                        .is_none_or(|value| value.trim().is_empty())
            })
        || item.get("enabled").and_then(Value::as_bool) != Some(true)
        || item.get("inputs").and_then(Value::as_object).is_none()
        || !optional_false(
            item,
            &[
                "is_managed",
                "supports_agentless",
                "supports_cloud_connector",
                "output_id",
                "cloud_connector_id",
                "cloud_connector_name",
            ],
        )
        || !optional_empty_array(item, &["secret_references"])
        || !only_active_spaces(item, &["spaceIds", "space_ids"], space)
    {
        return Err("Fleet integration is outside the cleanup lease".to_string());
    }
    Ok(())
}

async fn observe_integration_absent(transport: &Transport, id: &str) -> CleanupResult {
    match integration_policies::get(transport, id).await {
        Err(error) if error.kind == ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("Fleet integration deletion could not be proved".to_string()),
        Err(error) => Err(format!(
            "observing Fleet integration cleanup: {}",
            error.kind.as_str()
        )),
    }
}

async fn observe_parent_absent(transport: &Transport, id: &str) -> CleanupResult {
    match agent_policies::get(transport, id).await {
        Err(error) if error.kind == ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("Fleet parent deletion could not be proved".to_string()),
        Err(error) => Err(format!(
            "observing Fleet parent cleanup: {}",
            error.kind.as_str()
        )),
    }
}

fn check_marker(id: &str, nonce: &str, description: Option<&str>) -> CleanupResult {
    if id.starts_with("elasticctl-live-")
        && description.is_some_and(|description| description.contains(nonce))
    {
        Ok(())
    } else {
        Err("Fleet cleanup marker ownership is incomplete".to_string())
    }
}

fn inventory_with_system(baseline: &PackageInventory, version: &str) -> PackageInventory {
    let mut expected = baseline.clone();
    expected.insert("system".to_string(), version.to_string());
    expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[derive(Clone)]
    struct SequenceResponder {
        next: Arc<AtomicUsize>,
        responses: Vec<ResponseTemplate>,
    }

    impl SequenceResponder {
        fn new(responses: Vec<ResponseTemplate>) -> Self {
            Self {
                next: Arc::new(AtomicUsize::new(0)),
                responses,
            }
        }
    }

    impl Respond for SequenceResponder {
        fn respond(&self, _: &Request) -> ResponseTemplate {
            let index = self.next.fetch_add(1, Ordering::SeqCst);
            self.responses[index.min(self.responses.len() - 1)].clone()
        }
    }

    async fn mount_capabilities(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": {"number": "9.5.1", "build_flavor": "traditional"}
            })))
            .mount(server)
            .await;
    }

    async fn mount_system_status(server: &MockServer, version: &str) {
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": {
                    "name": "system",
                    "status": "installed",
                    "installationInfo": {"version": version}
                }
            })))
            .mount(server)
            .await;
    }

    fn parent_spec() -> elasticctl_api::fleet::agent_policies::AgentPolicySpec {
        serde_json::from_value(json!({
            "id": "elasticctl-live-parent",
            "name": "elasticctl-live-parent",
            "namespace": "default",
            "description": "marker nonce-a",
            "inactivity_timeout": 1209600,
            "monitoring_enabled": [],
            "agent_features": [],
            "global_data_tags": []
        }))
        .expect("valid portable parent")
    }

    fn parent_item(agents: Value) -> Map<String, Value> {
        serde_json::from_value(json!({
            "id": "elasticctl-live-parent",
            "name": "elasticctl-live-parent",
            "namespace": "default",
            "description": "marker nonce-a",
            "inactivity_timeout": 1209600,
            "monitoring_enabled": [],
            "agent_features": [],
            "global_data_tags": [],
            "is_default": false,
            "is_default_fleet_server": false,
            "has_fleet_server": null,
            "is_managed": false,
            "is_preconfigured": false,
            "is_verifier": null,
            "supports_agentless": null,
            "is_protected": false,
            "agentless": null,
            "space_ids": ["default"],
            "agents": agents,
            "package_policies": []
        }))
        .expect("complete test parent")
    }

    fn integration_spec() -> elasticctl_api::fleet::integration_policies::IntegrationPolicySpec {
        serde_json::from_value(json!({
            "id": "elasticctl-live-integration",
            "name": "elasticctl-live-integration",
            "namespace": "default",
            "description": "marker nonce-a",
            "policy_ids": ["elasticctl-live-parent"],
            "package": {"name": "system", "version": "2.0.0"},
            "inputs": {}
        }))
        .expect("valid portable integration")
    }

    fn integration_item(inputs: Value) -> Map<String, Value> {
        serde_json::from_value(json!({
            "id": "elasticctl-live-integration",
            "name": "elasticctl-live-integration",
            "namespace": "default",
            "description": "marker nonce-a",
            "policy_id": "elasticctl-live-parent",
            "policy_ids": ["elasticctl-live-parent"],
            "package": {"name": "system", "version": "2.0.0"},
            "inputs": inputs,
            "enabled": true,
            "is_managed": false,
            "supports_agentless": false,
            "supports_cloud_connector": false,
            "output_id": null,
            "cloud_connector_id": null,
            "cloud_connector_name": null,
            "secret_references": [],
            "spaceIds": ["default"]
        }))
        .expect("complete test integration")
    }

    #[test]
    fn a_different_nonce_never_satisfies_cleanup_ownership() {
        assert!(check_marker("elasticctl-live-parent", "nonce-a", Some("marker nonce-b")).is_err());
    }

    #[test]
    fn missing_or_nonzero_agent_counts_block_parent_cleanup() {
        let lease = ParentLease {
            id: "elasticctl-live-parent".to_string(),
            nonce: "nonce-a".to_string(),
            allowed: vec![parent_spec()],
            delete_attempted: false,
        };
        assert!(assert_owned_parent(&lease, &parent_item(json!(0)), "default").is_ok());
        assert!(assert_owned_parent(&lease, &parent_item(Value::Null), "default").is_err());
        assert!(assert_owned_parent(&lease, &parent_item(json!(1)), "default").is_err());
    }

    #[test]
    fn required_parent_fields_cannot_inherit_portable_defaults() {
        let lease = ParentLease {
            id: "elasticctl-live-parent".to_string(),
            nonce: "nonce-a".to_string(),
            allowed: vec![parent_spec()],
            delete_attempted: false,
        };
        for field in [
            "id",
            "name",
            "namespace",
            "description",
            "inactivity_timeout",
            "monitoring_enabled",
            "agents",
            "package_policies",
        ] {
            let mut item = parent_item(json!(0));
            item.remove(field);
            assert!(
                assert_owned_parent(&lease, &item, "default").is_err(),
                "missing {field} must fail closed"
            );
        }
    }

    #[test]
    fn required_integration_fields_and_unsafe_optional_state_fail_closed() {
        for field in [
            "id",
            "name",
            "namespace",
            "description",
            "policy_ids",
            "package",
            "inputs",
            "enabled",
        ] {
            let mut item = integration_item(json!({"system-system": {}}));
            item.remove(field);
            assert!(
                validate_integration_live_fields(&item, "default").is_err(),
                "missing {field} must fail closed"
            );
        }
        for (field, value) in [
            ("is_managed", json!(true)),
            ("secret_references", json!([{"id": "secret"}])),
            ("spaceIds", json!(["other"])),
            ("output_id", json!("target-local")),
        ] {
            let mut item = integration_item(json!({"system-system": {}}));
            item.insert(field.to_string(), value);
            assert!(
                validate_integration_live_fields(&item, "default").is_err(),
                "unsafe {field} must fail closed"
            );
        }
    }

    #[test]
    fn different_nonce_blocks_parent_delete_route_after_an_exact_read() {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let server = runtime.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/status"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "version": {"number": "9.5.1", "build_flavor": "traditional"}
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/status"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "version": {"number": "9.5.1", "build_flavor": "traditional"}
                })))
                .mount(&server)
                .await;
            let mut item = parent_item(json!(0));
            item.insert("description".to_string(), json!("marker someone-else"));
            Mock::given(method("GET"))
                .and(path("/api/fleet/agent_policies/elasticctl-live-parent"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item})))
                .mount(&server)
                .await;
            server
        });
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
        let transport = Transport::new(&profile).expect("mock transport");
        let mut lease = ParentLease {
            id: "elasticctl-live-parent".to_string(),
            nonce: "nonce-a".to_string(),
            allowed: vec![parent_spec()],
            delete_attempted: false,
        };
        assert!(
            runtime
                .block_on(delete_owned_parent(&transport, &mut lease))
                .is_err()
        );
        let requests = runtime.block_on(server.received_requests()).unwrap();
        assert!(requests.iter().all(|request| {
            request.url.path() != "/api/fleet/agent_policies/delete" && request.method != "POST"
        }));
    }

    #[test]
    fn package_inventory_drift_cannot_promote_a_claim() {
        let baseline = FleetState {
            agent_policies: BTreeSet::new(),
            integration_policies: BTreeSet::new(),
            packages: PackageInventory::new(),
        };
        let profile = Profile {
            kibana_url: "https://example.invalid".to_string(),
            es_url: None,
            api_key: Some("test".to_string()),
            username: None,
            password: None,
            space: "default".to_string(),
            verify: true,
            timeout_secs: 1,
        };
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline);
        cleanup.claim_package("2.0.0");
        let drifted = PackageInventory::from([
            ("system".to_string(), "2.0.0".to_string()),
            ("other".to_string(), "1.0.0".to_string()),
        ]);
        assert!(cleanup.confirm_package_owned("2.0.0", &drifted).is_err());
        cleanup.finished = true;
    }

    #[test]
    fn unconfirmed_claim_never_allows_uninstall_after_an_ambiguous_install() {
        assert_eq!(PackageLease::claimed("2.0.0").can_uninstall(), None);
    }

    #[test]
    fn unchanged_baseline_clears_an_unconfirmed_claim_without_uninstall() {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let server = runtime.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/fleet/epm/packages/installed"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "items": [], "total": 0
                })))
                .mount(&server)
                .await;
            server
        });
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
        let baseline = FleetState {
            agent_policies: BTreeSet::new(),
            integration_policies: BTreeSet::new(),
            packages: PackageInventory::new(),
        };
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline);
        cleanup.claim_package("2.0.0");
        assert!(cleanup.finish().is_ok());
        assert_eq!(cleanup.package, PackageLease::None);
        let requests = runtime.block_on(server.received_requests()).unwrap();
        assert!(requests.iter().all(|request| request.method != "DELETE"));
    }

    #[test]
    fn pre_existing_package_never_authorizes_an_uninstall() {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let server = runtime.block_on(MockServer::start());
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
        let baseline = FleetState {
            agent_policies: BTreeSet::new(),
            integration_policies: BTreeSet::new(),
            packages: PackageInventory::from([("system".to_string(), "2.0.0".to_string())]),
        };
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline);
        assert!(cleanup.finish().is_ok());
        let requests = runtime.block_on(server.received_requests()).unwrap();
        assert!(requests.iter().all(|request| request.method != "DELETE"));
    }

    #[test]
    fn integration_failure_blocks_parent_and_package_mutations() {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let server = runtime.block_on(async {
            let server = MockServer::start().await;
            mount_capabilities(&server).await;
            let mut foreign = integration_item(json!({"system-system": {}}));
            foreign.insert("description".to_string(), json!("marker someone-else"));
            Mock::given(method("GET"))
                .and(path(
                    "/api/fleet/package_policies/elasticctl-live-integration",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": foreign})))
                .mount(&server)
                .await;
            server
        });
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
        let baseline = FleetState {
            agent_policies: BTreeSet::new(),
            integration_policies: BTreeSet::new(),
            packages: PackageInventory::new(),
        };
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline);
        cleanup
            .register_parent("elasticctl-live-parent".to_string(), parent_spec())
            .unwrap();
        cleanup
            .register_integration(
                "elasticctl-live-integration".to_string(),
                integration_spec(),
            )
            .unwrap();
        cleanup.package = PackageLease::owned("2.0.0");
        assert!(cleanup.finish().is_err());
        cleanup.finished = true;
        let requests = runtime.block_on(server.received_requests()).unwrap();
        assert!(requests.iter().all(|request| {
            request.url.path() != "/api/fleet/agent_policies/delete"
                && request.url.path() != "/api/fleet/epm/packages/system/2.0.0"
        }));
    }

    #[test]
    fn valid_owned_parent_is_deleted_once_and_proved_absent() {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let server = runtime.block_on(async {
            let server = MockServer::start().await;
            mount_capabilities(&server).await;
            Mock::given(method("GET"))
                .and(path("/api/fleet/agent_policies/elasticctl-live-parent"))
                .respond_with(SequenceResponder::new(vec![
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"item": parent_item(json!(0))})),
                    ResponseTemplate::new(404).set_body_json(json!({
                        "statusCode": 404, "error": "Not Found", "message": "missing"
                    })),
                ]))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/api/fleet/agent_policies/delete"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "id": "elasticctl-live-parent"
                })))
                .mount(&server)
                .await;
            server
        });
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
        let mut lease = ParentLease {
            id: "elasticctl-live-parent".to_string(),
            nonce: "nonce-a".to_string(),
            allowed: vec![parent_spec()],
            delete_attempted: false,
        };
        assert!(
            runtime
                .block_on(delete_owned_parent(&transport, &mut lease))
                .is_ok()
        );
        assert!(lease.delete_attempted);
        let requests = runtime.block_on(server.received_requests()).unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.method == "POST"
                        && request.url.path() == "/api/fleet/agent_policies/delete"
                })
                .count(),
            1
        );
    }

    #[test]
    fn ambiguous_parent_delete_is_not_replayed_by_finish_then_drop() {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let server = runtime.block_on(async {
            let server = MockServer::start().await;
            mount_capabilities(&server).await;
            Mock::given(method("GET"))
                .and(path("/api/fleet/agent_policies/elasticctl-live-parent"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"item": parent_item(json!(0))})),
                )
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/api/fleet/agent_policies/delete"))
                .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "lost"})))
                .mount(&server)
                .await;
            server
        });
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
        let baseline = FleetState {
            agent_policies: BTreeSet::new(),
            integration_policies: BTreeSet::new(),
            packages: PackageInventory::new(),
        };
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline);
        cleanup
            .register_parent("elasticctl-live-parent".to_string(), parent_spec())
            .unwrap();
        assert!(cleanup.finish().is_err());
        drop(cleanup);
        let requests = runtime.block_on(server.received_requests()).unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.method == "POST"
                        && request.url.path() == "/api/fleet/agent_policies/delete"
                })
                .count(),
            1
        );
    }

    #[test]
    fn an_observed_absent_integration_delete_is_never_replayed() {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let server = runtime.block_on(async {
            let server = MockServer::start().await;
            mount_capabilities(&server).await;
            Mock::given(method("GET"))
                .and(path(
                    "/api/fleet/package_policies/elasticctl-live-integration",
                ))
                .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404, "error": "Not Found", "message": "missing"
                })))
                .mount(&server)
                .await;
            server
        });
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
        let mut lease = IntegrationLease {
            id: "elasticctl-live-integration".to_string(),
            nonce: "nonce-a".to_string(),
            allowed: vec![integration_spec()],
            bootstrap: None,
            delete_attempted: true,
        };
        assert!(
            runtime
                .block_on(delete_owned_integration(&transport, &mut lease))
                .is_ok()
        );
        let requests = runtime.block_on(server.received_requests()).unwrap();
        assert!(requests.iter().all(|request| request.method != "DELETE"));
    }

    #[test]
    fn bootstrap_identity_mismatch_never_authorizes_delete() {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let server = runtime.block_on(async {
            let server = MockServer::start().await;
            mount_capabilities(&server).await;
            Mock::given(method("GET"))
                .and(path("/api/fleet/epm/packages/installed"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "items": [{"name": "system", "version": "2.0.0", "status": "installed"}],
                    "total": 1
                })))
                .mount(&server)
                .await;
            mount_system_status(&server, "2.0.0").await;
            let materialized = integration_item(json!({"system-system": {}}));
            Mock::given(method("POST"))
                .and(path("/api/fleet/package_policies"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "item": materialized
                })))
                .mount(&server)
                .await;
            let mut mismatched = integration_item(json!({"system-system": {}}));
            mismatched.insert("name".to_string(), json!("someone-else"));
            Mock::given(method("GET"))
                .and(path(
                    "/api/fleet/package_policies/elasticctl-live-integration",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "item": mismatched
                })))
                .mount(&server)
                .await;
            server
        });
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
        let baseline = FleetState {
            agent_policies: BTreeSet::new(),
            integration_policies: BTreeSet::new(),
            packages: PackageInventory::new(),
        };
        let transport = Transport::new(&profile).unwrap();
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline);
        cleanup
            .register_parent("elasticctl-live-parent".to_string(), parent_spec())
            .unwrap();
        assert!(
            runtime
                .block_on(cleanup.materialize_system_inputs(&transport, integration_spec()))
                .is_err()
        );
        cleanup.finished = true;
        let requests = runtime.block_on(server.received_requests()).unwrap();
        assert!(requests.iter().all(|request| request.method != "DELETE"));
    }

    #[test]
    fn failed_bootstrap_create_and_export_are_recovered_without_replay() {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let server = runtime.block_on(async {
            let server = MockServer::start().await;
            mount_capabilities(&server).await;
            Mock::given(method("GET"))
                .and(path("/api/fleet/epm/packages/installed"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "items": [{"name": "system", "version": "2.0.0", "status": "installed"}],
                    "total": 1
                })))
                .mount(&server)
                .await;
            mount_system_status(&server, "2.0.0").await;
            let inputs = json!({
                "system-system": {
                    "enabled": true,
                    "streams": {"system.cpu": {"enabled": true, "vars": {"period": "10s"}}}
                }
            });
            let live = integration_item(inputs);
            Mock::given(method("POST"))
                .and(path("/api/fleet/package_policies"))
                .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "lost"})))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/fleet/package_policies/elasticctl-live-integration"))
                .respond_with(SequenceResponder::new(vec![
                    ResponseTemplate::new(200).set_body_json(json!({"item": live})); 5
                ].into_iter().chain([ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404, "error": "Not Found", "message": "missing"
                }))]).collect()))
                .mount(&server)
                .await;
            let mut attached = parent_item(json!(0));
            attached.insert("package_policies".to_string(), json!(["elasticctl-live-integration"]));
            Mock::given(method("GET"))
                .and(path("/api/fleet/agent_policies/elasticctl-live-parent"))
                .respond_with(SequenceResponder::new(vec![
                    ResponseTemplate::new(200).set_body_json(json!({"item": attached})),
                    ResponseTemplate::new(200).set_body_json(json!({"item": attached})),
                    ResponseTemplate::new(200).set_body_json(json!({"item": attached})),
                    ResponseTemplate::new(200).set_body_json(json!({"item": parent_item(json!(0))})),
                    ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404, "error": "Not Found", "message": "missing"})),
                ]))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/fleet/epm/packages/system/2.0.0"))
                .respond_with(SequenceResponder::new(vec![
                    ResponseTemplate::new(400).set_body_json(json!({"message": "temporary"})),
                    ResponseTemplate::new(200).set_body_json(json!({"item": {
                        "name": "system", "version": "2.0.0",
                        "policy_templates": [{"name": "system", "inputs": [{"type": "system", "streams": []}]}],
                        "data_streams": [{"dataset": "system.cpu", "streams": [{"input": "system", "vars": [{"name": "period"}]}]}]
                    }})),
                ]))
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path("/api/fleet/package_policies/elasticctl-live-integration"))
                .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "lost"})))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/api/fleet/agent_policies/delete"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "elasticctl-live-parent"})))
                .mount(&server)
                .await;
            server
        });
        let profile = Profile {
            kibana_url: server.uri(),
            es_url: None,
            api_key: Some("test".into()),
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 1,
        };
        let baseline = FleetState {
            agent_policies: BTreeSet::new(),
            integration_policies: BTreeSet::new(),
            packages: PackageInventory::from([("system".into(), "2.0.0".into())]),
        };
        let transport = Transport::new(&profile).unwrap();
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".into(), baseline);
        cleanup
            .register_parent("elasticctl-live-parent".into(), parent_spec())
            .unwrap();
        assert!(
            runtime
                .block_on(cleanup.materialize_system_inputs(&transport, integration_spec()))
                .is_err()
        );
        cleanup.finish().expect("bootstrap recovery must finish");
        let requests = runtime.block_on(server.received_requests()).unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.method == "POST" && r.url.path() == "/api/fleet/package_policies")
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.method == "DELETE"
                    && r.url.path() == "/api/fleet/package_policies/elasticctl-live-integration")
                .count(),
            1
        );
    }

    #[test]
    fn failed_package_delete_is_not_replayed_by_drop() {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let server = runtime.block_on(async {
            let server = MockServer::start().await;
            mount_capabilities(&server).await;
            for endpoint in ["/api/fleet/agent_policies", "/api/fleet/package_policies"] {
                Mock::given(method("GET"))
                    .and(path(endpoint))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "items": [], "page": 1, "perPage": 1000, "total": 0
                    })))
                    .mount(&server)
                    .await;
            }
            mount_system_status(&server, "2.0.0").await;
            Mock::given(method("GET"))
                .and(path("/api/fleet/epm/packages/installed"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "items": [{"name": "system", "version": "2.0.0", "status": "installed"}],
                    "total": 1
                })))
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path("/api/fleet/epm/packages/system/2.0.0"))
                .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "lost"})))
                .mount(&server)
                .await;
            server
        });
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
        let baseline = FleetState {
            agent_policies: BTreeSet::new(),
            integration_policies: BTreeSet::new(),
            packages: PackageInventory::new(),
        };
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline);
        cleanup.package = PackageLease::owned("2.0.0");
        assert!(
            cleanup.finish().is_err(),
            "ambiguous delete must fail cleanup"
        );
        assert!(matches!(
            cleanup.package,
            PackageLease::CleanupPending { .. }
        ));
        drop(cleanup);
        let delete_requests = runtime.block_on(async {
            server
                .received_requests()
                .await
                .expect("request log")
                .into_iter()
                .filter(|request| {
                    request.method == "DELETE"
                        && request.url.path() == "/api/fleet/epm/packages/system/2.0.0"
                })
                .count()
        });
        assert_eq!(
            delete_requests, 1,
            "Drop must only observe an ambiguous delete"
        );
    }

    #[test]
    fn unowned_system_consumer_blocks_package_delete() {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let server = runtime.block_on(async {
            let server = MockServer::start().await;
            mount_capabilities(&server).await;
            Mock::given(method("GET"))
                .and(path("/api/fleet/agent_policies"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "items": [], "page": 1, "perPage": 1000, "total": 0
                })))
                .mount(&server)
                .await;
            mount_system_status(&server, "2.0.0").await;
            Mock::given(method("GET"))
                .and(path("/api/fleet/package_policies"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "items": [{"id": "someone-else", "name": "other", "package": {"name": "system", "version": "2.0.0"}}],
                    "page": 1, "perPage": 1000, "total": 1
                })))
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
            server
        });
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
        let baseline = FleetState {
            agent_policies: BTreeSet::new(),
            integration_policies: BTreeSet::new(),
            packages: PackageInventory::new(),
        };
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline);
        cleanup.package = PackageLease::owned("2.0.0");
        assert!(cleanup.finish().is_err());
        cleanup.finished = true;
        let requests = runtime.block_on(server.received_requests()).unwrap();
        assert!(
            requests
                .iter()
                .all(|request| request.url.path() != "/api/fleet/epm/packages/system/2.0.0")
        );
    }

    #[test]
    fn cleanup_time_inventory_drift_sends_no_package_delete() {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let server = runtime.block_on(async {
            let server = MockServer::start().await;
            mount_capabilities(&server).await;
            for endpoint in ["/api/fleet/agent_policies", "/api/fleet/package_policies"] {
                Mock::given(method("GET"))
                    .and(path(endpoint))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "items": [], "page": 1, "perPage": 1000, "total": 0
                    })))
                    .mount(&server)
                    .await;
            }
            Mock::given(method("GET"))
                .and(path("/api/fleet/epm/packages/installed"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "items": [
                        {"name": "system", "version": "2.0.0", "status": "installed"},
                        {"name": "other", "version": "1.0.0", "status": "installed"}
                    ],
                    "total": 2
                })))
                .mount(&server)
                .await;
            server
        });
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
        let baseline = FleetState {
            agent_policies: BTreeSet::new(),
            integration_policies: BTreeSet::new(),
            packages: PackageInventory::new(),
        };
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline);
        cleanup.package = PackageLease::owned("2.0.0");
        assert_eq!(
            cleanup.finish().unwrap_err(),
            "Fleet package inventory drift blocks uninstall"
        );
        cleanup.finished = true;
        let requests = runtime.block_on(server.received_requests()).unwrap();
        assert!(requests.iter().all(|request| {
            request.method != "DELETE"
                || request.url.path() != "/api/fleet/epm/packages/system/2.0.0"
        }));
    }

    #[test]
    fn changed_installed_version_sends_no_package_delete() {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let server = runtime.block_on(async {
            let server = MockServer::start().await;
            mount_capabilities(&server).await;
            for endpoint in ["/api/fleet/agent_policies", "/api/fleet/package_policies"] {
                Mock::given(method("GET"))
                    .and(path(endpoint))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "items": [], "page": 1, "perPage": 1000, "total": 0
                    })))
                    .mount(&server)
                    .await;
            }
            Mock::given(method("GET"))
                .and(path("/api/fleet/epm/packages/installed"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "items": [{"name": "system", "version": "2.0.0", "status": "installed"}],
                    "total": 1
                })))
                .mount(&server)
                .await;
            mount_system_status(&server, "2.1.0").await;
            server
        });
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
        let baseline = FleetState {
            agent_policies: BTreeSet::new(),
            integration_policies: BTreeSet::new(),
            packages: PackageInventory::new(),
        };
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline);
        cleanup.package = PackageLease::owned("2.0.0");
        assert_eq!(
            cleanup.finish().unwrap_err(),
            "Fleet package version drift blocks uninstall"
        );
        cleanup.finished = true;
        let requests = runtime.block_on(server.received_requests()).unwrap();
        assert!(requests.iter().all(|request| {
            request.method != "DELETE"
                || request.url.path() != "/api/fleet/epm/packages/system/2.0.0"
        }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_inside_the_contract_runtime_attempts_cleanup_without_panicking() {
        let server = MockServer::start().await;
        mount_capabilities(&server).await;
        for endpoint in ["/api/fleet/agent_policies", "/api/fleet/package_policies"] {
            Mock::given(method("GET"))
                .and(path(endpoint))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "items": [], "page": 1, "perPage": 1000, "total": 0
                })))
                .mount(&server)
                .await;
        }
        mount_system_status(&server, "2.0.0").await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"name": "system", "version": "2.0.0", "status": "installed"}],
                "total": 1
            })))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "lost"})))
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
        let baseline = FleetState {
            agent_policies: BTreeSet::new(),
            integration_policies: BTreeSet::new(),
            packages: PackageInventory::new(),
        };
        let mut cleanup = FleetCleanup::new(profile, "nonce-a".to_string(), baseline);
        cleanup.package = PackageLease::owned("2.0.0");
        drop(cleanup);
        let delete_requests = server
            .received_requests()
            .await
            .expect("request log")
            .into_iter()
            .filter(|request| {
                request.method == "DELETE"
                    && request.url.path() == "/api/fleet/epm/packages/system/2.0.0"
            })
            .count();
        assert_eq!(
            delete_requests, 1,
            "Drop must execute the pending cleanup attempt"
        );
    }
}
