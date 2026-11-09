use super::common::*;
use super::read::collect;

const IMPORT_RACE_WARNING: &str =
    "warning  Fleet can change after the final recheck and before the write";

/// A locally decoded import artifact. Its canonical specifications are kept
/// private so callers can retain a validated source across context setup
/// without being able to alter what remote planning will use.
pub struct IntegrationPolicyImportArtifact {
    pub(super) source: PathBuf,
    pub(super) canonical: Vec<IntegrationPolicySpec>,
}

impl fmt::Debug for IntegrationPolicyImportArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntegrationPolicyImportArtifact")
            .field("policy_count", &self.canonical.len())
            .finish()
    }
}

/// What `plan_import` preflights and `apply_import` rechecks. Only guard
/// presentation is public: the canonical artifact, effective specifications,
/// and Fleet snapshots never cross the API boundary.
#[derive(Clone, PartialEq)]
pub struct IntegrationPolicyImportPlan {
    pub preview: MutationPlan,
    pub skipped: Vec<Value>,
    pub package_installs: Vec<String>,
    pub total: usize,
    pub(super) source: PathBuf,
    pub(super) host: String,
    pub(super) space: String,
    pub(super) canonical: Vec<IntegrationPolicySpec>,
    pub(super) name_owners: BTreeMap<String, BTreeSet<String>>,
    pub(super) name_owners_snapshot: BTreeMap<String, BTreeSet<String>>,
    pub(super) parent_snapshots: BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
    pub(super) skipped_snapshot: Vec<Value>,
    // Exact get-by-id results from before import classification. This covers
    // every canonical id, so a mutable target or skipped row cannot turn an
    // absent policy into an existing one (or the reverse).
    pub(super) existing_snapshot: BTreeMap<String, Option<Map<String, Value>>>,
    pub(super) targets: Vec<IntegrationPolicyImportTarget>,
    pub(super) package_groups: BTreeMap<String, IntegrationPackageGroup>,
    pub(super) overwrite: bool,
    pub(super) skip_existing: bool,
}

impl fmt::Debug for IntegrationPolicyImportPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntegrationPolicyImportPlan")
            .field("target_count", &self.preview.targets.len())
            .field("skipped_count", &self.skipped.len())
            .field("package_install_count", &self.package_installs.len())
            .field("existing_snapshot_count", &self.existing_snapshot.len())
            .field("total", &self.total)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct IntegrationPolicyImportTarget {
    pub(super) effective: IntegrationPolicySpec,
    pub(super) current: Option<IntegrationPolicyCurrentSnapshot>,
    pub(super) parents: BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
    pub(super) replacement_body: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct IntegrationPolicyCurrentSnapshot {
    pub(super) item: Map<String, Value>,
    pub(super) spec: IntegrationPolicySpec,
    pub(super) parent_ids: Vec<String>,
}

/// One package coordinate is shared by every pending policy that uses it.
/// `*_snapshot` copies are deliberate: plan validation compares the retained
/// exact Fleet response with the mutable execution expectation before it ever
/// starts remote work.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct IntegrationPackageGroup {
    pub(super) package: IntegrationPackageSpec,
    pub(super) state: PackageDependencySnapshot,
    pub(super) state_snapshot: PackageDependencySnapshot,
    pub(super) metadata: Map<String, Value>,
    pub(super) metadata_snapshot: Map<String, Value>,
}

pub(super) fn validate_requested_package_versions(specs: &[IntegrationPolicySpec]) -> Result<()> {
    let mut versions = BTreeMap::new();
    for spec in specs {
        match versions.entry(spec.package.name.as_str()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(spec.package.version.as_str());
            }
            std::collections::btree_map::Entry::Occupied(entry)
                if entry.get() != &spec.package.version.as_str() =>
            {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    format!(
                        "integration package '{}' is requested at more than one version",
                        spec.package.name
                    ),
                ));
            }
            std::collections::btree_map::Entry::Occupied(_) => {}
        }
    }
    Ok(())
}

pub(super) async fn relevant_name_owners(
    transport: &Transport,
    names: &BTreeSet<String>,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut owners = names
        .iter()
        .map(|name| (name.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    if names.is_empty() {
        return Ok(owners);
    }
    for item in collect(transport).await? {
        let Some(name) = item.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(owners) = owners.get_mut(name) else {
            continue;
        };
        owners.insert(required_string(&item, "id", "integration policies list")?);
    }
    Ok(owners)
}

pub(super) fn target_name_owners_match(
    target: &IntegrationPolicyImportTarget,
    owners: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    let Some(actual) = owners.get(&target.effective.name) else {
        return false;
    };
    let expected = match &target.current {
        None => BTreeSet::new(),
        Some(current) if current.spec.name == target.effective.name => {
            BTreeSet::from([target.effective.id.clone()])
        }
        Some(_) => BTreeSet::new(),
    };
    actual == &expected
}

pub(super) async fn read_import_parent_snapshots(
    transport: &Transport,
    integration_id: &str,
    current_parent_ids: &[String],
    desired_parent_ids: &[String],
) -> Result<BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>> {
    let parent_ids = current_parent_ids
        .iter()
        .chain(desired_parent_ids)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut parents = BTreeMap::new();
    for parent_id in parent_ids {
        let parent = agent_policy_ops::read_parent_snapshot(transport, &parent_id).await?;
        if current_parent_ids.binary_search(&parent_id).is_ok()
            && parent
                .attached_integrations
                .binary_search_by(|attached| attached.as_str().cmp(integration_id))
                .is_err()
        {
            return Err(http(format!(
                "decoding integration policy '{integration_id}': parent '{parent_id}' is missing its attachment"
            )));
        }
        parents.insert(parent_id, parent);
    }
    Ok(parents)
}

pub(super) fn effective_import_spec(
    canonical: &IntegrationPolicySpec,
    parents: &BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
) -> Result<IntegrationPolicySpec> {
    canonical.validate()?;
    for parent in parents.values() {
        if parent.platform_owned {
            return unsupported(format!(
                "integration policy '{}' is not portable: parent {} is platform-owned",
                canonical.id, parent.id
            ));
        }
        if parent.protected {
            return unsupported(format!(
                "integration policy '{}' is not portable: parent {} is_protected",
                canonical.id, parent.id
            ));
        }
    }
    let selected = canonical
        .policy_ids
        .iter()
        .map(|id| {
            parents.get(id).ok_or_else(|| {
                Error::new(
                    ErrorKind::Error,
                    format!(
                        "integration policy '{}' has no parent snapshot for '{id}'",
                        canonical.id
                    ),
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut effective = canonical.clone();
    if let Some(namespace) = &effective.namespace {
        if selected.iter().any(|parent| &parent.namespace != namespace) {
            return unsupported(format!(
                "integration policy '{}' is not portable: namespace does not match every parent",
                canonical.id
            ));
        }
    } else {
        let namespaces = selected
            .iter()
            .map(|parent| parent.namespace.as_str())
            .collect::<BTreeSet<_>>();
        if namespaces.len() != 1 {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "integration policy '{}' is not portable: parents have different namespaces",
                    canonical.id
                ),
            ));
        }
        effective.namespace = namespaces.into_iter().next().map(str::to_owned);
    }
    Ok(effective)
}

pub(super) fn replace_wire_body(spec: &IntegrationPolicySpec) -> Result<Value> {
    spec.validate()?;
    let mut body = serde_json::to_value(spec)
        .map_err(|error| {
            Error::new(
                ErrorKind::Error,
                format!("encoding integration policy: {error}"),
            )
        })?
        .as_object()
        .cloned()
        .expect("integration policy specs serialize to objects");
    body.remove("id");
    Ok(Value::Object(body))
}

pub(super) fn planned_package_installs(
    groups: &BTreeMap<String, IntegrationPackageGroup>,
) -> Vec<String> {
    groups
        .values()
        .filter_map(|group| match group.state.state {
            PackageDependencyState::NotInstalled => {
                Some(format!("{}@{}", group.package.name, group.package.version))
            }
            PackageDependencyState::Installed { .. } => None,
        })
        .collect()
}

pub(super) fn import_preview(
    path: &Path,
    targets: &[IntegrationPolicyImportTarget],
    package_installs: &[String],
) -> MutationPlan {
    let mut details = targets
        .iter()
        .map(|target| {
            let parents = target
                .parents
                .values()
                .map(|parent| format!("{} ({})", parent.id, parent.name))
                .collect::<Vec<_>>()
                .join(", ");
            let agents = target
                .parents
                .values()
                .map(|parent| parent.agents)
                .sum::<u64>();
            let action = match &target.current {
                None => "create".to_owned(),
                Some(current) if current.spec == target.effective => "unchanged".to_owned(),
                Some(current) if current.spec.name == target.effective.name => "replace".to_owned(),
                Some(current) => format!(
                    "replace  {} -> {}",
                    current.spec.name, target.effective.name
                ),
            };
            format!(
                "{}  {action}  {}  parents {parents}  agents {agents}",
                target.effective.id, target.effective.name
            )
        })
        .collect::<Vec<_>>();
    details.extend(
        package_installs
            .iter()
            .map(|package| format!("package install  {package}")),
    );
    details.push(IMPORT_RACE_WARNING.to_owned());
    MutationPlan {
        preview_action: format!(
            "Import {} integration policy(ies) from {}",
            targets.len(),
            path.display()
        ),
        preview_details: details,
        targets: targets
            .iter()
            .map(|target| target.effective.id.clone())
            .collect(),
    }
}

pub(super) fn import_remote_error(error: Error, context: &str) -> Error {
    let message = format!("integration-policy import {context} failed");
    match error.http_status {
        Some(status) => Error::with_status(error.kind, status, message),
        None => Error::new(error.kind, message),
    }
}
