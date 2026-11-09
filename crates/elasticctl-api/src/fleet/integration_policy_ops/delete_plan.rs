use super::common::*;
use super::metadata::{configured_secret_paths, validate_package_metadata_snapshot};
use super::normalization::normalize;
use super::read::{ResolvedIntegrationPolicy, collect};

const DELETE_RACE_WARNING: &str =
    "warning  Fleet can change after the final recheck and before the write";

/// A safe, fully preflighted integration-policy deletion. Only the guard
/// presentation and count are public: Fleet snapshots and package metadata can
/// include configuration values, so they remain private to the API layer.
#[derive(Clone, PartialEq)]
pub struct IntegrationPolicyDeletePlan {
    pub preview: MutationPlan,
    pub total: usize,
    pub(super) host: String,
    pub(super) host_snapshot: String,
    pub(super) space: String,
    pub(super) space_snapshot: String,
    pub(super) parent_snapshots: BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
    pub(super) parent_snapshots_snapshot:
        BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
    pub(super) targets: Vec<IntegrationPolicyDeleteTarget>,
}

impl fmt::Debug for IntegrationPolicyDeletePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntegrationPolicyDeletePlan")
            .field("target_count", &self.targets.len())
            .field("total", &self.total)
            .finish()
    }
}

/// Private execution facts for one stable-id delete. The raw item detects a
/// Fleet change before deletion; the normalized policy and metadata prove that
/// no secret or environment-bound configuration has crossed the guard.
#[derive(Clone, PartialEq)]
pub(super) struct IntegrationPolicyDeleteTarget {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) item: Map<String, Value>,
    pub(super) item_snapshot: Map<String, Value>,
    pub(super) spec: IntegrationPolicySpec,
    pub(super) spec_snapshot: IntegrationPolicySpec,
    pub(super) parents: BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
    pub(super) package: IntegrationPackageSpec,
    pub(super) dependency: PackageDependencySnapshot,
    pub(super) dependency_snapshot: PackageDependencySnapshot,
    pub(super) metadata: Map<String, Value>,
    pub(super) metadata_snapshot: Map<String, Value>,
}

/// Plan safe, stable-id integration-policy deletion without issuing a
/// mutation. Each selected object is retained exactly so `apply_delete` can
/// reject a Fleet change before it reaches the single-id delete route.
pub async fn plan_delete(
    transport: &Transport,
    selectors: &[String],
) -> Result<IntegrationPolicyDeletePlan> {
    if selectors.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "integration-policy delete needs at least one selector",
        ));
    }
    if selectors.iter().any(|selector| selector.trim().is_empty()) {
        return Err(Error::new(
            ErrorKind::Error,
            "integration-policy delete selectors must not be empty",
        ));
    }

    let mut resolved = BTreeMap::new();
    for selector in selectors {
        let resolved_policy = resolve_delete_item(transport, selector).await?;
        let id = required_string(
            &resolved_policy.item,
            "id",
            "integration policy delete planning read",
        )?;
        if id != resolved_policy.summary.id {
            return Err(http(
                "decoding integration policy delete planning read: response id did not match its summary",
            ));
        }
        resolved.entry(id).or_insert(resolved_policy);
    }

    let mut targets = Vec::with_capacity(resolved.len());
    let mut issues = Vec::new();
    for (id, resolved_policy) in resolved {
        match plan_delete_target(transport, &id, resolved_policy.item).await {
            Ok(target) => targets.push(target),
            Err(error) => issues.push(error),
        }
    }
    if !issues.is_empty() {
        return collapse_delete_planning_issues(issues);
    }

    let parent_snapshots = shared_delete_parents(&targets).map_err(|_| {
        Error::new(
            ErrorKind::Conflict,
            "agent policy changed while planning integration deletion",
        )
    })?;
    let plan = IntegrationPolicyDeletePlan {
        preview: delete_preview(&targets),
        total: targets.len(),
        host_snapshot: transport.kibana_url().to_owned(),
        host: transport.kibana_url().to_owned(),
        space_snapshot: transport.space().to_owned(),
        space: transport.space().to_owned(),
        parent_snapshots_snapshot: parent_snapshots.clone(),
        parent_snapshots,
        targets,
    };
    validate_delete_plan(&plan)?;
    Ok(plan)
}

/// Delete planning must bind an id selector to the id Fleet returned for that
/// id route. The general resolver keeps its historical public behavior for
/// list, get, and export; a mutation cannot accept a mismatched one-object
/// response as a different target.
async fn resolve_delete_item(
    transport: &Transport,
    selector: &str,
) -> Result<ResolvedIntegrationPolicy> {
    match integration_policies::get(transport, selector).await {
        Ok(policy) => {
            let summary = summary_from_item(&policy.item)?;
            if summary.id != selector {
                return Err(http(
                    "decoding integration policy delete planning read: response id did not match the selector",
                ));
            }
            return Ok(ResolvedIntegrationPolicy {
                summary,
                item: policy.item,
            });
        }
        Err(error) if error.kind == ErrorKind::NotFound => {}
        Err(error) => return Err(delete_remote_error(error, "planning integration read")),
    }
    let matches = collect(transport)
        .await
        .map_err(|error| delete_remote_error(error, "planning integration list read"))?
        .iter()
        .filter(|item| item.get("name").and_then(Value::as_str) == Some(selector))
        .map(summary_from_item)
        .collect::<Result<Vec<_>>>()?;
    match matches.as_slice() {
        [] => Err(Error::new(
            ErrorKind::NotFound,
            format!("no integration policy with id or name '{selector}'"),
        )),
        [summary] => {
            let policy = integration_policies::get(transport, &summary.id)
                .await
                .map_err(|error| delete_remote_error(error, "planning name read"))?;
            let returned_id = required_string(
                &policy.item,
                "id",
                "integration policy delete planning read",
            )?;
            if returned_id != summary.id {
                return Err(http(
                    "decoding integration policy delete planning read: name resolution returned an unexpected id",
                ));
            }
            Ok(ResolvedIntegrationPolicy {
                summary: summary.clone(),
                item: policy.item,
            })
        }
        many => Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "integration policy '{selector}' is ambiguous: {}",
                many.iter()
                    .map(|policy| policy.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

async fn plan_delete_target(
    transport: &Transport,
    id: &str,
    item: Map<String, Value>,
) -> Result<IntegrationPolicyDeleteTarget> {
    if required_string(&item, "id", "integration policy delete planning read")? != id {
        return Err(http(
            "decoding integration policy delete planning read: response id did not match the request",
        ));
    }
    let spec = normalize(&item, transport.space())?;
    if spec.id != id {
        return Err(http(
            "decoding integration policy delete planning read: normalized id did not match the request",
        ));
    }
    let parent_ids = read_parents(id, &item)?;
    let parents = read_parent_snapshots(transport, id, &parent_ids)
        .await
        .map_err(|error| delete_remote_error(error, "planning parent read"))?;
    validate_delete_parent_safety(id, &spec, &parents)?;

    let package = package_coordinate(&item, "integration policy delete planning read")?;
    if package != spec.package {
        return Err(http(
            "decoding integration policy delete planning read: package did not normalize canonically",
        ));
    }
    let dependency = read_dependencies(transport, &package)
        .await
        .map_err(|error| delete_remote_error(error, "planning package read"))?;
    ensure_delete_dependency(id, &dependency, &package)?;
    let metadata =
        integration_policies::package_metadata(transport, &package.name, &package.version)
            .await
            .map_err(|error| delete_remote_error(error, "planning package metadata read"))?
            .item;
    validate_package_metadata_snapshot(&metadata, &package)?;
    let secret_paths = configured_secret_paths(&spec, &metadata)?;
    if !secret_paths.is_empty() {
        return unsupported(format!(
            "integration policy '{id}' is not portable: {}",
            secret_paths
                .into_iter()
                .map(|path| format!("{id}:{path}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    Ok(IntegrationPolicyDeleteTarget {
        id: id.to_owned(),
        name: spec.name.clone(),
        item_snapshot: item.clone(),
        item,
        spec_snapshot: spec.clone(),
        spec,
        parents,
        package,
        dependency_snapshot: dependency.clone(),
        dependency,
        metadata_snapshot: metadata.clone(),
        metadata,
    })
}

fn collapse_delete_planning_issues(mut issues: Vec<Error>) -> Result<IntegrationPolicyDeletePlan> {
    if issues.len() == 1 {
        return Err(issues.remove(0));
    }
    if issues.iter().all(|error| error.kind == ErrorKind::Conflict) {
        return Err(Error::new(
            ErrorKind::Conflict,
            issues
                .into_iter()
                .map(|error| error.message)
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }
    Err(issues.remove(0))
}

fn validate_delete_parent_safety(
    id: &str,
    spec: &IntegrationPolicySpec,
    parents: &BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
) -> Result<()> {
    if parents.len() != spec.policy_ids.len()
        || parents
            .keys()
            .map(String::as_str)
            .ne(spec.policy_ids.iter().map(String::as_str))
    {
        return Err(http(format!(
            "decoding integration policy '{id}': parent snapshots do not match policy_ids"
        )));
    }
    for parent in parents.values() {
        if parent.platform_owned {
            return unsupported(format!(
                "integration policy '{id}' is not portable: parent {} is platform-owned",
                parent.id
            ));
        }
        if parent.protected {
            return unsupported(format!(
                "integration policy '{id}' is not portable: parent {} is_protected",
                parent.id
            ));
        }
        if parent
            .attached_integrations
            .binary_search_by(|attached| attached.as_str().cmp(id))
            .is_err()
        {
            return Err(http(format!(
                "decoding integration policy '{id}': parent '{}' is missing its attachment",
                parent.id
            )));
        }
    }
    let namespaces = parents
        .values()
        .map(|parent| parent.namespace.as_str())
        .collect::<BTreeSet<_>>();
    match &spec.namespace {
        Some(namespace)
            if parents
                .values()
                .all(|parent| &parent.namespace == namespace) => {}
        Some(_) => {
            return unsupported(format!(
                "integration policy '{id}' is not portable: namespace does not match every parent"
            ));
        }
        None if namespaces.len() == 1 => {}
        None => {
            return unsupported(format!(
                "integration policy '{id}' is not portable: parents have different namespaces"
            ));
        }
    }
    Ok(())
}

fn ensure_delete_dependency(
    id: &str,
    dependency: &PackageDependencySnapshot,
    package: &IntegrationPackageSpec,
) -> Result<()> {
    match &dependency.state {
        PackageDependencyState::Installed { version }
            if dependency.name == package.name && version == &package.version =>
        {
            Ok(())
        }
        PackageDependencyState::Installed { .. } => Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "integration policy '{id}' package {} has a different installed version",
                package.name
            ),
        )),
        PackageDependencyState::NotInstalled => Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "integration policy '{id}' package {} is not installed",
                package.name
            ),
        )),
    }
}

fn shared_delete_parents(
    targets: &[IntegrationPolicyDeleteTarget],
) -> Result<BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>> {
    let mut shared = BTreeMap::new();
    for target in targets {
        for (id, parent) in &target.parents {
            match shared.entry(id.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(parent.clone());
                }
                std::collections::btree_map::Entry::Occupied(entry) if entry.get() != parent => {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        format!("agent policy '{id}' changed while planning integration deletion"),
                    ));
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
    }
    Ok(shared)
}

fn delete_preview(targets: &[IntegrationPolicyDeleteTarget]) -> MutationPlan {
    let mut affected = BTreeMap::new();
    let mut preview_details = Vec::with_capacity(targets.len() + 2);
    for target in targets {
        let parents = target
            .parents
            .values()
            .map(|parent| {
                affected.entry(parent.id.clone()).or_insert(parent.agents);
                format!("{} ({}) agents {}", parent.id, parent.name, parent.agents)
            })
            .collect::<Vec<_>>();
        let agents = target
            .parents
            .values()
            .map(|parent| parent.agents)
            .sum::<u64>();
        preview_details.push(format!(
            "{}  {}  parents {}  agents {agents}",
            target.id,
            target.name,
            parents.join(", ")
        ));
    }
    preview_details.push(format!(
        "affected agents {}",
        affected.values().sum::<u64>()
    ));
    preview_details.push(DELETE_RACE_WARNING.to_owned());
    MutationPlan {
        preview_action: format!("Delete {} integration policy(ies)", targets.len()),
        preview_details,
        targets: targets.iter().map(|target| target.id.clone()).collect(),
    }
}

pub(super) fn delete_remote_error(error: Error, context: &str) -> Error {
    let message = format!("integration-policy delete {context} failed");
    match error.http_status {
        Some(status) => Error::with_status(error.kind, status, message),
        None => Error::new(error.kind, message),
    }
}

pub(super) fn validate_delete_plan(plan: &IntegrationPolicyDeletePlan) -> Result<()> {
    let invalid = || Error::new(ErrorKind::Error, "invalid integration-policy delete plan");
    if plan.targets.is_empty()
        || plan.total != plan.targets.len()
        || plan.host.trim().is_empty()
        || plan.host != plan.host_snapshot
        || plan.space != plan.space_snapshot
    {
        return Err(invalid());
    }

    let mut previous: Option<&str> = None;
    let mut shared = BTreeMap::new();
    for target in &plan.targets {
        if target.id.trim().is_empty()
            || target.name.trim().is_empty()
            || previous.is_some_and(|previous| previous >= target.id.as_str())
            || target.item != target.item_snapshot
            || target.spec.validate().is_err()
            || target.spec != target.spec_snapshot
            || target.id != target.spec.id
            || target.name != target.spec.name
            || required_string(&target.item, "id", "integration policy delete plan")
                .ok()
                .as_deref()
                != Some(target.id.as_str())
            || normalize(&target.item, &plan.space).ok().as_ref() != Some(&target.spec)
            || package_coordinate(&target.item, "integration policy delete plan")
                .ok()
                .as_ref()
                != Some(&target.package)
            || target.package != target.spec.package
            || target.dependency != target.dependency_snapshot
            || !valid_package_state(&target.dependency)
            || target.dependency.name != target.package.name
            || !is_exact_installed(&target.dependency, &target.package)
            || target.metadata != target.metadata_snapshot
            || validate_package_metadata_snapshot(&target.metadata, &target.package).is_err()
            || !matches!(configured_secret_paths(&target.spec, &target.metadata), Ok(paths) if paths.is_empty())
        {
            return Err(invalid());
        }

        let parent_ids = match read_parents(&target.id, &target.item) {
            Ok(ids) => ids,
            Err(_) => return Err(invalid()),
        };
        if parent_ids.iter().collect::<BTreeSet<_>>()
            != target.parents.keys().collect::<BTreeSet<_>>()
            || validate_delete_parent_safety(&target.id, &target.spec, &target.parents).is_err()
        {
            return Err(invalid());
        }
        for (parent_id, parent) in &target.parents {
            if !valid_parent_snapshot(parent_id, parent)
                || parent.platform_owned
                || parent.protected
                || parent
                    .attached_integrations
                    .binary_search_by(|attached| attached.as_str().cmp(&target.id))
                    .is_err()
            {
                return Err(invalid());
            }
            match shared.entry(parent_id.as_str()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(parent);
                }
                std::collections::btree_map::Entry::Occupied(entry) if *entry.get() != parent => {
                    return Err(invalid());
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
        previous = Some(&target.id);
    }
    if plan.parent_snapshots != plan.parent_snapshots_snapshot
        || shared_delete_parents(&plan.targets).ok().as_ref() != Some(&plan.parent_snapshots)
    {
        return Err(invalid());
    }
    if plan.preview != delete_preview(&plan.targets) {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod delete_plan_tests {
    use super::super::delete_apply::apply_delete;
    use super::*;
    use elasticctl_core::{Profile, Transport};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    fn transport_for(server: &MockServer) -> Transport {
        Transport::new(&Profile {
            kibana_url: server.uri(),
            es_url: None,
            api_key: Some("essu_test".into()),
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 5,
        })
        .expect("transport")
    }

    fn valid_plan() -> IntegrationPolicyDeletePlan {
        let spec = IntegrationPolicySpec::try_from(json!({
            "id": "delete-1",
            "name": "Delete integration",
            "namespace": "default",
            "policy_ids": ["parent-1"],
            "package": {"name": "system", "version": "2.0.0"},
            "inputs": {}
        }))
        .expect("valid integration policy");
        let mut item = serde_json::to_value(&spec)
            .expect("serialize integration policy")
            .as_object()
            .expect("integration policy is an object")
            .clone();
        item.insert("enabled".into(), Value::Bool(true));
        let parent = agent_policy_ops::AgentPolicyParentSnapshot {
            id: "parent-1".into(),
            name: "Parent 1".into(),
            namespace: "default".into(),
            agents: 4,
            attached_integrations: vec!["delete-1".into()],
            platform_owned: false,
            protected: false,
        };
        let parents = BTreeMap::from([(parent.id.clone(), parent)]);
        let dependency = PackageDependencySnapshot {
            name: "system".into(),
            state: PackageDependencyState::Installed {
                version: "2.0.0".into(),
            },
        };
        let metadata = json!({
            "name": "system",
            "version": "2.0.0",
            "vars": [],
            "policy_templates": []
        })
        .as_object()
        .expect("metadata object")
        .clone();
        let target = IntegrationPolicyDeleteTarget {
            id: spec.id.clone(),
            name: spec.name.clone(),
            item_snapshot: item.clone(),
            item,
            spec_snapshot: spec.clone(),
            spec,
            parents: parents.clone(),
            package: IntegrationPackageSpec {
                name: "system".into(),
                version: "2.0.0".into(),
            },
            dependency_snapshot: dependency.clone(),
            dependency,
            metadata_snapshot: metadata.clone(),
            metadata,
        };
        let targets = vec![target];
        let parent_snapshots = parents;
        IntegrationPolicyDeletePlan {
            preview: delete_preview(&targets),
            total: targets.len(),
            host: "https://fleet.example.invalid".into(),
            host_snapshot: "https://fleet.example.invalid".into(),
            space: "default".into(),
            space_snapshot: "default".into(),
            parent_snapshots_snapshot: parent_snapshots.clone(),
            parent_snapshots,
            targets,
        }
    }

    #[test]
    fn delete_plan_accepts_a_coherent_private_snapshot() {
        assert!(validate_delete_plan(&valid_plan()).is_ok());
    }

    #[test]
    fn delete_plan_rejects_empty_total_order_and_preview_tampering() {
        let plan = valid_plan();

        let mut empty = plan.clone();
        empty.targets.clear();
        empty.total = 0;
        empty.parent_snapshots.clear();
        empty.parent_snapshots_snapshot.clear();
        empty.preview = delete_preview(&empty.targets);
        assert!(validate_delete_plan(&empty).is_err());

        let mut total = plan.clone();
        total.total = 2;
        assert!(validate_delete_plan(&total).is_err());

        let mut duplicate = plan.clone();
        duplicate.targets.push(duplicate.targets[0].clone());
        duplicate.total = 2;
        duplicate.preview = delete_preview(&duplicate.targets);
        assert!(validate_delete_plan(&duplicate).is_err());

        let mut preview = plan;
        preview.preview.preview_action = "tampered".into();
        assert!(validate_delete_plan(&preview).is_err());

        let mut host = valid_plan();
        host.host = "https://other.example.invalid".into();
        assert!(validate_delete_plan(&host).is_err());

        let mut space = valid_plan();
        space.space = "other".into();
        assert!(validate_delete_plan(&space).is_err());
    }

    #[test]
    fn delete_plan_rejects_raw_spec_parent_package_and_metadata_tampering() {
        let plan = valid_plan();

        let mut raw_and_spec = plan.clone();
        raw_and_spec.targets[0]
            .item
            .insert("description".into(), json!("tampered"));
        raw_and_spec.targets[0].spec.description = Some("tampered".into());
        raw_and_spec.preview = delete_preview(&raw_and_spec.targets);
        assert!(validate_delete_plan(&raw_and_spec).is_err());

        let mut parent = plan.clone();
        parent.targets[0]
            .parents
            .get_mut("parent-1")
            .expect("parent")
            .agents = 99;
        parent.preview = delete_preview(&parent.targets);
        assert!(validate_delete_plan(&parent).is_err());

        let mut parent_snapshot = plan.clone();
        parent_snapshot
            .parent_snapshots
            .get_mut("parent-1")
            .expect("parent")
            .agents = 99;
        assert!(validate_delete_plan(&parent_snapshot).is_err());

        let mut dependency = plan.clone();
        dependency.targets[0].dependency = PackageDependencySnapshot {
            name: "system".into(),
            state: PackageDependencyState::Installed {
                version: "1.0.0".into(),
            },
        };
        assert!(validate_delete_plan(&dependency).is_err());

        let mut metadata = plan;
        metadata.targets[0]
            .metadata
            .insert("version".into(), json!("9.9.9"));
        assert!(validate_delete_plan(&metadata).is_err());
    }

    #[tokio::test]
    async fn delete_apply_rereads_metadata_after_coherent_secret_tampering() {
        let server = verified_server().await;
        let transport = transport_for(&server);
        let spec = IntegrationPolicySpec::try_from(json!({
            "id": "delete-1",
            "name": "Delete integration",
            "namespace": "default",
            "policy_ids": ["parent-1"],
            "package": {"name": "system", "version": "2.0.0"},
            "vars": {"package_secret": "live-plaintext-value-must-not-leak"},
            "inputs": {}
        }))
        .expect("valid integration policy");
        let mut item = serde_json::to_value(&spec)
            .expect("serialize integration policy")
            .as_object()
            .expect("integration policy is an object")
            .clone();
        item.insert("enabled".into(), Value::Bool(true));
        let parent = agent_policy_ops::AgentPolicyParentSnapshot {
            id: "parent-1".into(),
            name: "Parent 1".into(),
            namespace: "default".into(),
            agents: 4,
            attached_integrations: vec![spec.id.clone()],
            platform_owned: false,
            protected: false,
        };
        let parents = BTreeMap::from([(parent.id.clone(), parent)]);
        let dependency = PackageDependencySnapshot {
            name: "system".into(),
            state: PackageDependencyState::Installed {
                version: "2.0.0".into(),
            },
        };
        let original_metadata = json!({
            "name": "system",
            "version": "2.0.0",
            "vars": [{"name": "package_secret", "secret": true}],
            "policy_templates": []
        })
        .as_object()
        .expect("metadata object")
        .clone();
        let mut target = IntegrationPolicyDeleteTarget {
            id: spec.id.clone(),
            name: spec.name.clone(),
            item_snapshot: item.clone(),
            item,
            spec_snapshot: spec.clone(),
            spec,
            parents: parents.clone(),
            package: IntegrationPackageSpec {
                name: "system".into(),
                version: "2.0.0".into(),
            },
            dependency_snapshot: dependency.clone(),
            dependency,
            metadata_snapshot: original_metadata.clone(),
            metadata: original_metadata.clone(),
        };
        let mut plan = IntegrationPolicyDeletePlan {
            preview: delete_preview(std::slice::from_ref(&target)),
            total: 1,
            host: server.uri(),
            host_snapshot: server.uri(),
            space: "default".into(),
            space_snapshot: "default".into(),
            parent_snapshots_snapshot: parents.clone(),
            parent_snapshots: parents,
            targets: vec![target.clone()],
        };
        assert!(validate_delete_plan(&plan).is_err());

        let forged_metadata = json!({
            "name": "system",
            "version": "2.0.0",
            "vars": [{"name": "package_secret", "secret": false}],
            "policy_templates": []
        })
        .as_object()
        .expect("metadata object")
        .clone();
        target.metadata = forged_metadata.clone();
        target.metadata_snapshot = forged_metadata;
        target.item_snapshot = target.item.clone();
        target.spec_snapshot = target.spec.clone();
        plan.targets = vec![target];
        plan.parent_snapshots = shared_delete_parents(&plan.targets).expect("shared parents");
        plan.parent_snapshots_snapshot = plan.parent_snapshots.clone();
        plan.preview = delete_preview(&plan.targets);
        assert!(validate_delete_plan(&plan).is_ok());

        let item = plan.targets[0].item.clone();
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/delete-1"))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": parent_item_for_delete_test("parent-1", "delete-1")
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": {
                    "name": "system",
                    "status": "installed",
                    "installationInfo": {"version": "2.0.0"}
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": original_metadata
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/fleet/package_policies/delete-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "delete-1"})))
            .expect(0)
            .mount(&server)
            .await;

        let report = apply_delete(&transport, &plan)
            .await
            .expect("metadata race is a row failure");
        assert!(report.deleted.is_empty());
        assert_eq!(
            report.failed,
            vec![json!({
                "id": "delete-1",
                "applied": false,
                "error": "integration policy package metadata changed since preview"
            })]
        );
        let requests = server.received_requests().await.expect("recorded requests");
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.url.path() == "/api/fleet/epm/packages/system/2.0.0")
                .count(),
            1
        );
        assert!(requests.iter().all(|request| request.method != "DELETE"));
        assert!(
            !report.failed[0]["error"]
                .as_str()
                .expect("error string")
                .contains("live-plaintext-value-must-not-leak")
        );
    }

    fn parent_item_for_delete_test(id: &str, attached: &str) -> Value {
        json!({
            "id": id,
            "name": "Parent 1",
            "namespace": "default",
            "agents": 4,
            "package_policies": [attached],
        })
    }
}
