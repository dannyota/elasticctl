//! Agent-policy selection, normalization, portability, planning, and apply.

use crate::content_codec::{self, ContentFormat};
use crate::fleet::agent_policies::{
    self, AGENTLESS_FIELD, AgentPolicyDetail, AgentPolicySpec, AgentPolicySummary, ENVIRONMENT_IDS,
    PLATFORM_FLAGS,
};
use crate::ops::ExportOutcome;
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::path::Path;

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

/// A single live read reduced to what planning needs.
#[derive(Debug, Clone, PartialEq)]
pub struct LiveAgentPolicy {
    pub spec: AgentPolicySpec,
    pub agents: u64,
    pub attached: Vec<String>,
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
    match agent_policies::get(transport, selector).await {
        Ok(policy) => return AgentPolicySummary::from_item(&policy.item),
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
        [one] => Ok(one.clone()),
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
    let summary = resolve(transport, selector).await?;
    let policy = agent_policies::get(transport, &summary.id).await?;
    let agents = required_agents(&policy.item, &summary.id)?;
    let attached_integrations = attached_integration_ids(&policy.item, &summary.id)?;
    let status = match policy.item.get("status") {
        None | Some(Value::Null) => None,
        Some(Value::String(status)) => Some(status.clone()),
        Some(_) => {
            return Err(http(format!(
                "decoding agent policy '{}': status must be a string or null",
                summary.id
            )));
        }
    };
    let blocked_by = portability_reasons(&policy.item, transport.space())?
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
    let spec = normalize(&policy.item, transport.space())?;
    if spec.id != id {
        return Err(http(format!(
            "decoding agent policy: expected id '{id}', got '{}'",
            spec.id
        )));
    }
    let agents = required_agents(&policy.item, id)?;
    let attached = attached_integration_ids(&policy.item, id)?;
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

/// Read, decode, validate, and sort a portable artifact.
pub fn validate(path: &Path) -> Result<Vec<AgentPolicySpec>> {
    let body = std::fs::read_to_string(path).map_err(|error| {
        Error::new(
            ErrorKind::Error,
            format!("reading {}: {error}", path.display()),
        )
    })?;
    let mut specs = content_codec::decode_sequence::<AgentPolicySpec>(
        &body,
        ContentFormat::from_path(path),
        "agent policy",
    )?;
    let mut seen_ids = BTreeSet::new();
    let mut duplicate_ids = BTreeSet::new();
    let mut seen_names = BTreeSet::new();
    let mut duplicate_names = BTreeSet::new();
    for spec in &specs {
        if !seen_ids.insert(spec.id.as_str()) {
            duplicate_ids.insert(spec.id.as_str());
        }
        if !seen_names.insert(spec.name.as_str()) {
            duplicate_names.insert(spec.name.as_str());
        }
    }
    if !duplicate_ids.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            format!(
                "duplicate agent policy ids: {}",
                duplicate_ids.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    if !duplicate_names.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            format!(
                "duplicate agent policy names: {}",
                duplicate_names.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(specs)
}

/// Export selected policies, or every custom policy, as a portable artifact.
pub async fn export(
    transport: &Transport,
    selectors: &[String],
    all_custom: bool,
    format: ContentFormat,
) -> Result<ExportOutcome> {
    if selectors.is_empty() && !all_custom {
        return Err(Error::new(
            ErrorKind::Error,
            "agent-policy export needs selectors or --all-custom",
        ));
    }
    if !selectors.is_empty() && all_custom {
        return Err(Error::new(
            ErrorKind::Error,
            "--all-custom cannot be combined with selectors",
        ));
    }
    let ids: BTreeSet<String> = if all_custom {
        let mut ids = BTreeSet::new();
        for item in collect(transport).await? {
            if !is_platform_owned(&item)? {
                ids.insert(AgentPolicySummary::from_item(&item)?.id);
            }
        }
        ids
    } else {
        let mut ids = BTreeSet::new();
        for selector in selectors {
            ids.insert(resolve(transport, selector).await?.id);
        }
        ids
    };
    let mut specs = Vec::with_capacity(ids.len());
    for id in &ids {
        specs.push(read_live(transport, id).await?.spec);
    }
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    let body = content_codec::encode_sequence(&specs, format)?;
    Ok(ExportOutcome {
        body,
        exported: specs.len() as u64,
        missing: Vec::new(),
    })
}

fn http(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Http, message)
}
