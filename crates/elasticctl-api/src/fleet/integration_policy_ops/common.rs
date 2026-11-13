pub(super) use crate::content_codec::{self, ContentFormat};
pub(super) use crate::fleet::integration_policies::{
    self, IntegrationPackageSpec, IntegrationPolicyDetail, IntegrationPolicySpec,
    IntegrationPolicySummary,
};
pub(super) use crate::fleet::{agent_policies, agent_policy_ops};
pub(super) use crate::ops::{ExportOutcome, MutationPlan};
pub(super) use elasticctl_core::{Error, ErrorKind, Result, Transport};
pub(super) use serde::Serialize;
pub(super) use serde_json::{Map, Value, json};
pub(super) use std::collections::{BTreeMap, BTreeSet};
pub(super) use std::fmt;
pub(super) use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PackageDependencyState {
    Installed { version: String },
    NotInstalled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PackageDependencySnapshot {
    pub(super) name: String,
    pub(super) state: PackageDependencyState,
}

pub(super) fn read_parents(id: &str, item: &Map<String, Value>) -> Result<Vec<String>> {
    let policy_ids = item
        .get("policy_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            http(format!(
                "decoding integration policy '{id}': policy_ids must be an array"
            ))
        })?;
    if policy_ids.is_empty() {
        return Err(http(format!(
            "decoding integration policy '{id}': policy_ids must not be empty"
        )));
    }
    let mut ids = Vec::with_capacity(policy_ids.len());
    for parent in policy_ids {
        let parent = parent
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                http(format!(
                    "decoding integration policy '{id}': policy_ids must contain non-empty strings"
                ))
            })?;
        ids.push(parent.to_owned());
    }
    ids.sort();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(http(format!(
            "decoding integration policy '{id}': duplicate policy_ids"
        )));
    }
    Ok(ids)
}

pub(super) async fn read_parent_snapshots(
    transport: &Transport,
    integration_id: &str,
    parent_ids: &[String],
) -> Result<BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>> {
    let mut parents = BTreeMap::new();
    for parent_id in parent_ids {
        let parent = agent_policy_ops::read_parent_snapshot(transport, parent_id).await?;
        if !parent
            .attached_integrations
            .binary_search_by(|attached| attached.as_str().cmp(integration_id))
            .is_ok()
        {
            return Err(http(format!(
                "decoding integration policy '{integration_id}': parent '{parent_id}' is missing its attachment"
            )));
        }
        parents.insert(parent_id.clone(), parent);
    }
    Ok(parents)
}

pub(super) async fn read_dependencies(
    transport: &Transport,
    package: &IntegrationPackageSpec,
) -> Result<PackageDependencySnapshot> {
    let status = agent_policies::package_status(transport, &package.name).await?;
    let state = match (status.status.as_str(), status.installed_version) {
        ("installed", Some(version)) if !version.trim().is_empty() => {
            PackageDependencyState::Installed { version }
        }
        ("not_installed", None) => PackageDependencyState::NotInstalled,
        _ => {
            return Err(http(format!(
                "decoding package dependency '{}': invalid status/version state",
                package.name
            )));
        }
    };
    Ok(PackageDependencySnapshot {
        name: status.name,
        state,
    })
}

pub(super) fn optional_bool(
    item: &Map<String, Value>,
    field: &str,
    id: &str,
) -> Result<Option<bool>> {
    match item.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(http(format!(
            "decoding integration policy '{id}': {field} must be a boolean or null"
        ))),
    }
}

pub(super) fn summary_from_item(item: &Map<String, Value>) -> Result<IntegrationPolicySummary> {
    let id = required_string(item, "id", "integration policy")?;
    let name = required_string(item, "name", "integration policy")?;
    let namespace = required_string(item, "namespace", "integration policy")?;
    let description = match item.get("description") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => {
            return Err(http(
                "decoding integration policy: description must be a string or null",
            ));
        }
    };
    let policy_ids = item
        .get("policy_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| http("decoding integration policy: policy_ids must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    http("decoding integration policy: policy_ids must contain non-empty strings")
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let package = package_coordinate(item, "integration policy")?;
    Ok(IntegrationPolicySummary {
        id,
        name,
        namespace,
        description,
        policy_ids,
        package,
    })
}

pub(super) fn package_coordinate(
    item: &Map<String, Value>,
    context: &str,
) -> Result<IntegrationPackageSpec> {
    let package = item
        .get("package")
        .and_then(Value::as_object)
        .ok_or_else(|| http(format!("decoding {context}: package must be an object")))?;
    Ok(IntegrationPackageSpec {
        name: package_required_string(package, "name", context)?,
        version: package_required_string(package, "version", context)?,
    })
}

fn package_required_string(
    package: &Map<String, Value>,
    field: &str,
    context: &str,
) -> Result<String> {
    package
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            http(format!(
                "decoding {context}: package.{field} must be a non-empty string"
            ))
        })
}

pub(super) fn required_string(
    item: &Map<String, Value>,
    field: &str,
    context: &str,
) -> Result<String> {
    item.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            http(format!(
                "decoding {context}: {field} must be a non-empty string"
            ))
        })
}

pub(super) fn is_exact_installed(
    snapshot: &PackageDependencySnapshot,
    package: &IntegrationPackageSpec,
) -> bool {
    snapshot.name == package.name
        && matches!(
            &snapshot.state,
            PackageDependencyState::Installed { version } if version == &package.version
        )
}

pub(super) fn verify_exact_installed(
    snapshot: &PackageDependencySnapshot,
    package: &IntegrationPackageSpec,
) -> std::result::Result<(), String> {
    if is_exact_installed(snapshot, package) {
        return Ok(());
    }
    match &snapshot.state {
        PackageDependencyState::Installed { .. } => Err(format!(
            "package {} installed a different version",
            package.name
        )),
        PackageDependencyState::NotInstalled => {
            Err(format!("package {} is not installed", package.name))
        }
    }
}

pub(super) fn valid_parent_snapshot(
    id: &str,
    parent: &agent_policy_ops::AgentPolicyParentSnapshot,
) -> bool {
    parent.id == id
        && !parent.id.trim().is_empty()
        && !parent.name.trim().is_empty()
        && !parent.namespace.trim().is_empty()
        && parent
            .attached_integrations
            .windows(2)
            .all(|ids| ids[0] < ids[1])
}

pub(super) fn valid_package_state(snapshot: &PackageDependencySnapshot) -> bool {
    if snapshot.name.trim().is_empty() {
        return false;
    }
    match &snapshot.state {
        PackageDependencyState::Installed { version } => !version.trim().is_empty(),
        PackageDependencyState::NotInstalled => true,
    }
}

pub(super) fn http(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Http, message)
}

pub(super) fn unsupported<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::new(ErrorKind::Unsupported, message))
}
