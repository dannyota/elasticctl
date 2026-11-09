//! Agent-policy selection, normalization, portability, planning, and apply.

use crate::content_codec::{self, ContentFormat};
use crate::fleet::agent_policies::{
    self, AGENTLESS_FIELD, AgentPolicyDetail, AgentPolicySpec, AgentPolicySummary, ENVIRONMENT_IDS,
    PLATFORM_FLAGS,
};
use crate::ops::{ExportOutcome, MutationPlan};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

mod artifact;
mod delete;
mod import;
pub use artifact::{export, validate};
pub use delete::{
    AgentPolicyDeletePlan, AgentPolicyDeleteReport, AgentPolicyDeleteTarget, apply_delete,
    plan_delete,
};
pub use import::{
    AgentPolicyImportPlan, AgentPolicyImportReport, apply_import, build_replace_body, plan_import,
};

const PAGE_SIZE: u64 = 1000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentPolicyFilter {
    pub search: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentPolicyList {
    pub total: u64,
    pub agent_policies: Vec<AgentPolicySummary>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct ResolvedAgentPolicy {
    summary: AgentPolicySummary,
    item: Map<String, Value>,
}

/// A single live read reduced to what planning needs.
#[derive(Debug, Clone, PartialEq)]
pub struct LiveAgentPolicy {
    pub spec: AgentPolicySpec,
    pub agents: u64,
    pub attached: Vec<String>,
}

/// The narrow parent facts an integration-policy operation needs to compare
/// attachment, namespace, ownership, and blast radius. This deliberately does
/// not apply agent-policy portability checks: environment references are not
/// integration-parent facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentPolicyParentSnapshot {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub agents: u64,
    pub attached_integrations: Vec<String>,
    pub platform_owned: bool,
    pub protected: bool,
}

/// Collect every page in the measured deterministic order, then sort by id.
pub async fn collect(transport: &Transport) -> Result<Vec<Map<String, Value>>> {
    let mut page_number = 1;
    let mut total = None;
    let mut items = Vec::new();
    let mut ids = BTreeSet::new();
    loop {
        let page = agent_policies::list_page(transport, page_number).await?;
        if page.page != page_number || page.per_page != PAGE_SIZE {
            return Err(http(
                "decoding agent policies list: unexpected page metadata",
            ));
        }
        match total {
            Some(total) if total != page.total => {
                return Err(http(
                    "decoding agent policies list: total changed while paging",
                ));
            }
            Some(_) => {}
            None => total = Some(page.total),
        }
        let page_len = page.items.len() as u64;
        for item in page.items {
            let id = item
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| http("decoding agent policies list: item without id"))?
                .to_owned();
            if !ids.insert(id.clone()) {
                return Err(http(format!(
                    "decoding agent policies list: duplicate agent policy id '{id}'"
                )));
            }
            items.push(item);
        }
        let expected = total.expect("set from the first page");
        if items.len() as u64 >= expected {
            break;
        }
        if page_len != PAGE_SIZE {
            return Err(http(
                "decoding agent policies list: page was short before total",
            ));
        }
        page_number += 1;
    }
    if items.len() as u64 > total.unwrap_or(0) {
        return Err(http(
            "decoding agent policies list: returned more items than total",
        ));
    }
    items.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    Ok(items)
}

pub async fn list_op(transport: &Transport, filter: &AgentPolicyFilter) -> Result<AgentPolicyList> {
    let items = collect(transport).await?;
    let total = items.len() as u64;
    let needle = filter.search.as_ref().map(|search| search.to_lowercase());
    let mut rows = Vec::new();
    for item in &items {
        let summary = AgentPolicySummary::from_item(item)?;
        let keep = needle.as_ref().is_none_or(|needle| {
            summary.id.to_lowercase().contains(needle)
                || summary.name.to_lowercase().contains(needle)
        });
        if keep {
            rows.push(summary);
        }
    }
    let limit = filter.limit.unwrap_or(usize::MAX);
    let truncated = rows.len() > limit;
    rows.truncate(limit);
    Ok(AgentPolicyList {
        total,
        agent_policies: rows,
        truncated,
    })
}

/// Stable id first through the single-object route; exact name second.
pub async fn resolve(transport: &Transport, selector: &str) -> Result<AgentPolicySummary> {
    Ok(resolve_item(transport, selector).await?.summary)
}

/// Resolve a selector and retain the single-object response needed by callers
/// that require populated agent and integration facts.
async fn resolve_item(transport: &Transport, selector: &str) -> Result<ResolvedAgentPolicy> {
    match agent_policies::get(transport, selector).await {
        Ok(policy) => {
            return Ok(ResolvedAgentPolicy {
                summary: AgentPolicySummary::from_item(&policy.item)?,
                item: policy.item,
            });
        }
        Err(error) if error.kind == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let items = collect(transport).await?;
    let matches: Vec<AgentPolicySummary> = items
        .iter()
        .filter(|item| item.get("name").and_then(Value::as_str) == Some(selector))
        .map(AgentPolicySummary::from_item)
        .collect::<Result<_>>()?;
    match matches.as_slice() {
        [] => Err(Error::new(
            ErrorKind::NotFound,
            format!("no agent policy with id or name '{selector}'"),
        )),
        [one] => {
            let policy = agent_policies::get(transport, &one.id).await?;
            Ok(ResolvedAgentPolicy {
                summary: one.clone(),
                item: policy.item,
            })
        }
        many => Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "agent policy '{selector}' is ambiguous: {}",
                many.iter()
                    .map(|row| row.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

pub async fn get_op(transport: &Transport, selector: &str) -> Result<AgentPolicyDetail> {
    let ResolvedAgentPolicy { summary, item } = resolve_item(transport, selector).await?;
    let agents = required_agents(&item, &summary.id)?;
    let attached_integrations = attached_integration_ids(&item, &summary.id)?;
    let status = match item.get("status") {
        None | Some(Value::Null) => None,
        Some(Value::String(status)) => Some(status.clone()),
        Some(_) => {
            return Err(http(format!(
                "decoding agent policy '{}': status must be a string or null",
                summary.id
            )));
        }
    };
    let blocked_by = portability_reasons(&item, transport.space())?
        .into_iter()
        .map(str::to_owned)
        .collect();
    Ok(AgentPolicyDetail {
        id: summary.id,
        name: summary.name,
        namespace: summary.namespace,
        description: summary.description,
        agents,
        status,
        attached_integrations,
        blocked_by,
    })
}

/// True when a boolean platform flag is true or `agentless` is non-null.
/// Used only by `--all-custom` filtering;
/// `normalize` still refuses these policies when selected explicitly.
pub fn is_platform_owned(item: &Map<String, Value>) -> Result<bool> {
    for flag in PLATFORM_FLAGS {
        if optional_server_bool(item, flag)? == Some(true) {
            return Ok(true);
        }
    }
    match item.get(AGENTLESS_FIELD) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Object(_)) => Ok(true),
        Some(_) => Err(http(
            "decoding agent policy: agentless must be an object or null",
        )),
    }
}

/// Read one agent-policy parent while retaining only integration-operation
/// facts. Missing `agents` is a Fleet privilege error; all other malformed
/// known parent fields are malformed HTTP responses.
pub(crate) async fn read_parent_snapshot(
    transport: &Transport,
    id: &str,
) -> Result<AgentPolicyParentSnapshot> {
    let policy = agent_policies::get(transport, id).await?;
    let item = &policy.item;
    let returned_id = item
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| http("decoding agent policy parent: id must be a non-empty string"))?;
    if returned_id != id {
        return Err(http(format!(
            "decoding agent policy parent: expected id '{id}', got '{returned_id}'"
        )));
    }
    let name = item
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            http(format!(
                "decoding agent policy '{id}': name must be a non-empty string"
            ))
        })?
        .to_owned();
    let namespace = item
        .get("namespace")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            http(format!(
                "decoding agent policy '{id}': namespace must be a non-empty string"
            ))
        })?
        .to_owned();
    Ok(AgentPolicyParentSnapshot {
        id: returned_id.to_owned(),
        name,
        namespace,
        agents: required_agents(item, id)?,
        attached_integrations: attached_integration_ids(item, id)?,
        platform_owned: is_platform_owned(item)?,
        protected: optional_server_bool(item, "is_protected")?.unwrap_or(false),
    })
}

const PORTABLE_OPTIONAL: [&str; 13] = [
    "description",
    "inactivity_timeout",
    "unenroll_timeout",
    "monitoring_enabled",
    "agent_features",
    "global_data_tags",
    "advanced_settings",
    "overrides",
    "keep_monitoring_alive",
    "monitoring_pprof_enabled",
    "monitoring_http",
    "monitoring_diagnostics",
    "namespace",
];

/// Live top-level fields normalization removes or refuses as server-owned or
/// derived, per spec 5.2: audit and saved-object identity, agent and
/// version-condition facts, populated `package_policies`, the platform and
/// portability-refusal fields, and the active space's `space_ids`. Sorted.
/// A live field outside this list and the portable set is `unsupported`.
const REMOVED_FIELDS: [&str; 31] = [
    "agentless",
    "agents",
    "agents_per_version",
    "created_at",
    "created_by",
    "data_output_id",
    "download_source_id",
    "fips_agents",
    "fleet_server_host_id",
    "has_agent_version_conditions",
    "has_fleet_server",
    "is_default",
    "is_default_fleet_server",
    "is_managed",
    "is_preconfigured",
    "is_protected",
    "is_verifier",
    "min_agent_version",
    "monitoring_output_id",
    "package_agent_version_conditions",
    "package_policies",
    "required_versions",
    "revision",
    "schema_version",
    "space_ids",
    "status",
    "supports_agentless",
    "unprivileged_agents",
    "updated_at",
    "updated_by",
    "version",
];

/// Convert a live policy into its filled portable form, or refuse it.
pub fn normalize(item: &Map<String, Value>, active_space: &str) -> Result<AgentPolicySpec> {
    let id = item
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| http("decoding agent policy: expected string id"))?;
    let reasons = portability_reasons(item, active_space)?;
    if !reasons.is_empty() {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!(
                "agent policy '{id}' is not portable: {}",
                reasons.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    }

    let mut portable = Map::new();
    for key in ["id", "name"] {
        if let Some(value) = item.get(key) {
            portable.insert(key.to_string(), value.clone());
        }
    }
    for key in PORTABLE_OPTIONAL {
        if let Some(value) = item.get(key)
            && !value.is_null()
        {
            portable.insert(key.to_string(), value.clone());
        }
    }
    let known: BTreeSet<&str> = ["id", "name"]
        .into_iter()
        .chain(PORTABLE_OPTIONAL)
        .chain(REMOVED_FIELDS)
        .collect();
    let unknown: BTreeSet<&str> = item
        .keys()
        .map(String::as_str)
        .filter(|key| !known.contains(key))
        .collect();
    if let Some(first) = unknown.into_iter().next() {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!("agent policy '{id}' carries unknown field '{first}'"),
        ));
    }
    AgentPolicySpec::try_from(Value::Object(portable))
        .map_err(|error| http(format!("decoding agent policy '{id}': {}", error.message)))
}

fn portability_reasons(
    item: &Map<String, Value>,
    active_space: &str,
) -> Result<BTreeSet<&'static str>> {
    let active = if active_space.is_empty() {
        "default"
    } else {
        active_space
    };
    let mut reasons = BTreeSet::new();
    for flag in PLATFORM_FLAGS.into_iter().chain(["is_protected"]) {
        if optional_server_bool(item, flag)? == Some(true) {
            reasons.insert(flag);
        }
    }
    match item.get(AGENTLESS_FIELD) {
        None | Some(Value::Null) => {}
        Some(Value::Object(_)) => {
            reasons.insert(AGENTLESS_FIELD);
        }
        Some(_) => {
            return Err(http(
                "decoding agent policy: agentless must be an object or null",
            ));
        }
    }
    for field in ENVIRONMENT_IDS {
        match item.get(field) {
            None | Some(Value::Null) => {}
            Some(Value::String(value)) if !value.trim().is_empty() => {
                reasons.insert(field);
            }
            Some(_) => {
                return Err(http(format!(
                    "decoding agent policy: {field} must be a non-empty string or null"
                )));
            }
        }
    }
    match item.get("required_versions") {
        None | Some(Value::Null) => {}
        Some(Value::Array(_)) => {
            reasons.insert("required_versions");
        }
        Some(_) => {
            return Err(http(
                "decoding agent policy: required_versions must be an array or null",
            ));
        }
    }
    match item.get("space_ids") {
        None | Some(Value::Null) => {}
        Some(Value::Array(spaces)) => {
            let decoded =
                spaces
                    .iter()
                    .map(|space| {
                        space.as_str().filter(|space| !space.is_empty()).ok_or_else(|| {
                        http("decoding agent policy: space_ids must contain non-empty strings")
                    })
                    })
                    .collect::<Result<Vec<_>>>()?;
            if decoded.iter().any(|space| *space != active) {
                reasons.insert("space_ids");
            }
        }
        Some(_) => {
            return Err(http(
                "decoding agent policy: space_ids must be an array or null",
            ));
        }
    }
    Ok(reasons)
}

fn optional_server_bool(item: &Map<String, Value>, field: &str) -> Result<Option<bool>> {
    match item.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(http(format!(
            "decoding agent policy: {field} must be a boolean or null"
        ))),
    }
}

/// Read one policy and reduce it to the facts planning compares and rechecks.
pub(crate) async fn read_live(transport: &Transport, id: &str) -> Result<LiveAgentPolicy> {
    let policy = agent_policies::get(transport, id).await?;
    live_from_policy(&policy, id, transport.space())
}

/// Reduce an already-read policy to the facts planning compares and rechecks,
/// without a further route call. Shared by `read_live` and `plan_import`'s
/// conversion of a raw existing snapshot, which must defer this call (and its
/// `normalize` refusal) until the row is known to need it: a skipped or
/// conflicting existing policy is never normalized.
fn live_from_policy(
    policy: &agent_policies::AgentPolicy,
    id: &str,
    active_space: &str,
) -> Result<LiveAgentPolicy> {
    live_from_item(&policy.item, id, active_space)
}

fn live_from_item(
    item: &Map<String, Value>,
    id: &str,
    active_space: &str,
) -> Result<LiveAgentPolicy> {
    let spec = normalize(item, active_space)?;
    if spec.id != id {
        return Err(http(format!(
            "decoding agent policy: expected id '{id}', got '{}'",
            spec.id
        )));
    }
    let agents = required_agents(item, id)?;
    let attached = attached_integration_ids(item, id)?;
    Ok(LiveAgentPolicy {
        spec,
        agents,
        attached,
    })
}

/// `package_policies` is a list of ids or of populated objects carrying `id`.
fn attached_integration_ids(item: &Map<String, Value>, id: &str) -> Result<Vec<String>> {
    let entries = item
        .get("package_policies")
        .ok_or_else(|| {
            http(format!(
                "decoding agent policy '{id}': missing package_policies"
            ))
        })?
        .as_array()
        .ok_or_else(|| {
            http(format!(
                "decoding agent policy '{id}': package_policies must be an array"
            ))
        })?;
    let mut ids = Vec::with_capacity(entries.len());
    for entry in entries {
        let attached_id = match entry {
            Value::String(attached_id) => Some(attached_id.as_str()),
            Value::Object(object) => object.get("id").and_then(Value::as_str),
            _ => None,
        }
        .filter(|attached_id| !attached_id.is_empty())
        .ok_or_else(|| {
            http(format!(
                "decoding agent policy '{id}': package_policies entry without id"
            ))
        })?;
        ids.push(attached_id.to_owned());
    }
    ids.sort();
    if ids.windows(2).any(|ids| ids[0] == ids[1]) {
        return Err(http(format!(
            "decoding agent policy '{id}': duplicate package_policies id"
        )));
    }
    Ok(ids)
}

/// Kibana populates `agents` only for a caller with Fleet agents read, so an
/// absent field is a privilege gap, not a malformed response.
fn required_agents(item: &Map<String, Value>, id: &str) -> Result<u64> {
    match item.get("agents") {
        None => Err(Error::new(
            ErrorKind::Permission,
            format!(
                "agent policy '{id}' has no agents count; the API key lacks the Fleet agents read privilege"
            ),
        )),
        Some(value) => value.as_u64().ok_or_else(|| {
            http(format!(
                "decoding agent policy '{id}': agents must be an unsigned integer"
            ))
        }),
    }
}

fn http(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Http, message)
}
