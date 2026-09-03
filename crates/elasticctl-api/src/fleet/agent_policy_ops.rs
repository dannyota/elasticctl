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

/// What `plan_import` computed and `apply_import` uploads. Public fields are
/// the guard preview and the summary counts; the rest are the exact
/// snapshots and bodies `apply_import` rechecks against before every write.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentPolicyImportPlan {
    pub preview: MutationPlan,
    pub skipped: Vec<Value>,
    pub package_installs: Vec<String>,
    pub total: usize,
    source: std::path::PathBuf,
    specs: Vec<AgentPolicySpec>,
    before: BTreeMap<String, Option<LiveAgentPolicy>>,
    bodies: BTreeMap<String, Value>,
    monitoring_package: Option<agent_policies::PackageStatus>,
    overwrite: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentPolicyImportReport {
    pub applied: bool,
    pub succeeded: Vec<Value>,
    pub unchanged: Vec<Value>,
    pub skipped: Vec<Value>,
    pub failed: Vec<Value>,
    pub total: usize,
    pub affected_agents: u64,
    pub package_installs: Vec<String>,
}

const MONITORING_PACKAGE: &str = "elastic_agent";
const SERVER_SELECTED_INSTALL: &str = "elastic_agent@server-selected";

/// Build the full-spec PUT body for a merge-semantics update route.
pub fn build_replace_body(current: &AgentPolicySpec, desired: &AgentPolicySpec) -> Result<Value> {
    current.validate()?;
    desired.validate()?;
    if current.id != desired.id {
        return unsupported(
            "changing agent policy id is not supported by the agent-policy update API",
        );
    }
    let removed = [
        (
            "description",
            current.description.is_some() && desired.description.is_none(),
        ),
        (
            "unenroll_timeout",
            current.unenroll_timeout.is_some() && desired.unenroll_timeout.is_none(),
        ),
        (
            "monitoring_pprof_enabled",
            current.monitoring_pprof_enabled.is_some()
                && desired.monitoring_pprof_enabled.is_none(),
        ),
        (
            "advanced_settings",
            current.advanced_settings.is_some() && desired.advanced_settings.is_none(),
        ),
        (
            "monitoring_http",
            current.monitoring_http.is_some() && desired.monitoring_http.is_none(),
        ),
        (
            "monitoring_diagnostics",
            current.monitoring_diagnostics.is_some() && desired.monitoring_diagnostics.is_none(),
        ),
    ];
    if let Some((field, _)) = removed.iter().find(|(_, gone)| *gone) {
        return unsupported(format!(
            "removing {field} is not supported by the agent-policy update API"
        ));
    }
    // Nested objects need no removal check: Kibana maps them `flattened` and
    // replaces the stored object with the supplied one.
    let mut body = serde_json::to_value(desired)
        .map_err(|error| Error::new(ErrorKind::Error, format!("encoding agent policy: {error}")))?
        .as_object()
        .cloned()
        .expect("specs serialize to objects");
    body.remove("id");
    if current.overrides.is_some() && desired.overrides.is_none() {
        body.insert("overrides".into(), Value::Null);
    }
    if current.keep_monitoring_alive.is_some() && desired.keep_monitoring_alive.is_none() {
        body.insert("keep_monitoring_alive".into(), Value::Null);
    }
    Ok(Value::Object(body))
}

fn unsupported<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::new(ErrorKind::Unsupported, message))
}

pub async fn plan_import(
    transport: &Transport,
    path: &Path,
    overwrite: bool,
    skip_existing: bool,
) -> Result<AgentPolicyImportPlan> {
    let mut specs = validate(path)?;
    if specs.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "agent-policy import needs at least one agent policy",
        ));
    }
    if overwrite && skip_existing {
        return Err(Error::new(
            ErrorKind::Error,
            "--overwrite and --skip-existing cannot be used together",
        ));
    }
    let total = specs.len();

    let mut before = BTreeMap::new();
    let mut conflicts = Vec::new();
    for spec in &specs {
        match read_live(transport, &spec.id).await {
            Ok(live) => {
                if !overwrite && !skip_existing {
                    conflicts.push(spec.id.clone());
                }
                before.insert(spec.id.clone(), Some(live));
            }
            Err(error) if error.kind == ErrorKind::NotFound => {
                before.insert(spec.id.clone(), None);
            }
            Err(error) => return Err(error),
        }
    }
    // Fleet enforces unique names with a 409; catch it before the guard.
    let mut live_names = BTreeMap::new();
    for item in collect(transport).await? {
        let row = AgentPolicySummary::from_item(&item)?;
        if live_names
            .insert(row.name.clone(), row.id.clone())
            .is_some()
        {
            return Err(http(format!(
                "decoding agent policies list: duplicate name '{}'",
                row.name
            )));
        }
    }
    let taken: Vec<String> = specs
        .iter()
        .filter_map(|spec| {
            live_names
                .get(&spec.name)
                .filter(|owner| **owner != spec.id)
                .map(|owner| format!("{} ({owner})", spec.name))
        })
        .collect();
    if !taken.is_empty() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!("agent policy names already exist: {}", taken.join(", ")),
        ));
    }
    if !conflicts.is_empty() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!("agent policies already exist: {}", conflicts.join(", ")),
        ));
    }
    let mut skipped = Vec::new();
    if skip_existing {
        specs.retain(|spec| match before.get(&spec.id) {
            Some(Some(_)) => {
                skipped.push(json!({"id": spec.id, "reason": "exists"}));
                false
            }
            _ => true,
        });
        before.retain(|id, _| specs.iter().any(|spec| spec.id == *id));
    }

    let mut bodies = BTreeMap::new();
    for spec in &specs {
        if let Some(Some(current)) = before.get(&spec.id)
            && current.spec != *spec
        {
            bodies.insert(spec.id.clone(), build_replace_body(&current.spec, spec)?);
        }
    }

    let mut package_installs = Vec::new();
    let needs_monitoring = specs
        .iter()
        .any(|spec| monitoring_can_install(before.get(&spec.id).and_then(Option::as_ref), spec));
    let monitoring_package = if needs_monitoring {
        let status = agent_policies::package_status(transport, MONITORING_PACKAGE).await?;
        if status.status != "installed" {
            package_installs.push(SERVER_SELECTED_INSTALL.to_string());
        }
        Some(status)
    } else {
        None
    };

    let preview = MutationPlan {
        preview_action: format!(
            "Import {} agent policy(ies) from {}",
            specs.len(),
            path.display()
        ),
        preview_details: import_details(&specs, &before, &package_installs),
        targets: specs.iter().map(|spec| spec.id.clone()).collect(),
    };
    Ok(AgentPolicyImportPlan {
        preview,
        skipped,
        package_installs,
        total,
        source: path.to_path_buf(),
        specs,
        before,
        bodies,
        monitoring_package,
        overwrite,
    })
}

fn monitoring_can_install(current: Option<&LiveAgentPolicy>, desired: &AgentPolicySpec) -> bool {
    !desired.monitoring_enabled.is_empty()
        && current.is_none_or(|current| current.spec.monitoring_enabled.is_empty())
}

fn import_details(
    specs: &[AgentPolicySpec],
    before: &BTreeMap<String, Option<LiveAgentPolicy>>,
    package_installs: &[String],
) -> Vec<String> {
    let mut details: Vec<String> = specs
        .iter()
        .filter_map(|spec| match before.get(&spec.id) {
            Some(None) => Some(format!("{}  create  {}", spec.id, spec.name)),
            Some(Some(current)) if current.spec == *spec => {
                Some(format!("{}  unchanged  {}", spec.id, spec.name))
            }
            Some(Some(current)) => {
                let name = if current.spec.name == spec.name {
                    spec.name.clone()
                } else {
                    format!("{} -> {}", current.spec.name, spec.name)
                };
                Some(format!(
                    "{}  replace  {name}  agents {}",
                    spec.id, current.agents
                ))
            }
            None => None,
        })
        .collect();
    details.extend(
        package_installs
            .iter()
            .map(|install| format!("package install  {install}")),
    );
    details
}

pub async fn apply_import(
    transport: &Transport,
    plan: &AgentPolicyImportPlan,
) -> Result<AgentPolicyImportReport> {
    validate_import_plan(plan)?;
    let mut succeeded = Vec::new();
    let mut unchanged = Vec::new();
    let mut failed = Vec::new();
    let mut affected_agents = 0;
    let mut expected_package = plan.monitoring_package.clone();
    let mut package_installs = Vec::new();

    for desired in &plan.specs {
        let Some(before) = plan.before.get(&desired.id) else {
            failed.push(failed_row(&desired.id, false, "missing preflight snapshot"));
            continue;
        };
        let current = match read_live(transport, &desired.id).await {
            Ok(live) => Some(live),
            Err(error) if error.kind == ErrorKind::NotFound => None,
            Err(error) => {
                failed.push(failed_row(&desired.id, false, error.message));
                continue;
            }
        };
        match (before, current) {
            (None, Some(_)) => failed.push(failed_row(
                &desired.id,
                false,
                "agent policy appeared since preview",
            )),
            (Some(_), None) => failed.push(failed_row(
                &desired.id,
                false,
                "agent policy disappeared since preview",
            )),
            (Some(before), Some(live)) if before != &live => failed.push(failed_row(
                &desired.id,
                false,
                "agent policy changed since preview",
            )),
            (before, current) => {
                let package_can_change = monitoring_can_install(before.as_ref(), desired);
                if package_can_change {
                    let Some(expected) = expected_package.as_ref() else {
                        failed.push(failed_row(
                            &desired.id,
                            false,
                            "missing monitoring package snapshot",
                        ));
                        continue;
                    };
                    match agent_policies::package_status(transport, MONITORING_PACKAGE).await {
                        Ok(actual) if actual == *expected => {}
                        Ok(_) => {
                            failed.push(failed_row(
                                &desired.id,
                                false,
                                "elastic_agent package changed since preview",
                            ));
                            continue;
                        }
                        Err(error) => {
                            failed.push(failed_row(&desired.id, false, error.message));
                            continue;
                        }
                    }
                }

                let (action, applied, route_error) = match (before, current) {
                    (None, None) => {
                        match other_owner_of_name(transport, &desired.name).await {
                            Ok(Some(owner)) => {
                                failed.push(failed_row(
                                    &desired.id,
                                    false,
                                    format!(
                                        "agent policy name appeared since preview: {} ({owner})",
                                        desired.name
                                    ),
                                ));
                                continue;
                            }
                            Ok(None) => {}
                            Err(error) => {
                                failed.push(failed_row(&desired.id, false, error));
                                continue;
                            }
                        }
                        match agent_policies::create(transport, desired).await {
                            Ok(_) => ("created", true, None),
                            Err(error) => ("created", false, Some(error.message)),
                        }
                    }
                    (Some(before), Some(_)) if before.spec == *desired => {
                        unchanged.push(json!({"id": desired.id}));
                        continue;
                    }
                    (Some(before), Some(_)) => {
                        let body = plan
                            .bodies
                            .get(&desired.id)
                            .expect("validated replacement body");
                        match agent_policies::update(transport, &desired.id, body).await {
                            Ok(_) => {
                                affected_agents += before.agents;
                                ("replaced", true, None)
                            }
                            Err(error) => ("replaced", false, Some(error.message)),
                        }
                    }
                    _ => unreachable!("appearance and disappearance handled above"),
                };

                let stored_error = if applied {
                    verify_stored(transport, desired).await.err()
                } else {
                    None
                };
                let package_error = if package_can_change {
                    let expected = expected_package
                        .as_ref()
                        .expect("validated package snapshot");
                    match observe_package_after_write(transport, expected).await {
                        Ok((after, installed)) => {
                            expected_package = Some(after);
                            if let Some(installed) = installed
                                && !package_installs.contains(&installed)
                            {
                                package_installs.push(installed);
                            }
                            None
                        }
                        Err(error) => Some(error),
                    }
                } else {
                    None
                };

                let errors = [route_error, stored_error, package_error]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                if errors.is_empty() {
                    succeeded.push(json!({"id": desired.id, "action": action}));
                } else {
                    failed.push(failed_row(&desired.id, applied, errors.join("; ")));
                }
            }
        }
    }
    Ok(AgentPolicyImportReport {
        applied: true,
        succeeded,
        unchanged,
        skipped: plan.skipped.clone(),
        failed,
        total: plan.total,
        affected_agents,
        package_installs,
    })
}

async fn verify_stored(
    transport: &Transport,
    desired: &AgentPolicySpec,
) -> std::result::Result<(), String> {
    match read_live(transport, &desired.id).await {
        Ok(live) if live.spec == *desired => Ok(()),
        Ok(_) => Err("server stored a different agent-policy spec".into()),
        Err(error) => Err(error.message),
    }
}

/// Recheck the live list for a policy name claimed by a different id, right
/// before a planned create's POST. Fleet enforces unique names with a 409 on
/// create, so a name another client claimed since planning must fail the row
/// locally rather than reach the server.
async fn other_owner_of_name(
    transport: &Transport,
    name: &str,
) -> std::result::Result<Option<String>, String> {
    let items = collect(transport).await.map_err(|error| error.message)?;
    for item in &items {
        let row = AgentPolicySummary::from_item(item).map_err(|error| error.message)?;
        if row.name == name {
            return Ok(Some(row.id));
        }
    }
    Ok(None)
}

/// Re-read the monitoring package after a write that could install it. The
/// install is an observation: Fleet's create path tolerates an install error,
/// and a replace installs only from an absent stored value, so a package that
/// stays absent is not a failure. Only the read itself can fail the row.
async fn observe_package_after_write(
    transport: &Transport,
    before: &agent_policies::PackageStatus,
) -> std::result::Result<(agent_policies::PackageStatus, Option<String>), String> {
    let after = agent_policies::package_status(transport, MONITORING_PACKAGE)
        .await
        .map_err(|error| error.message)?;
    if before.status != "installed" && after.status == "installed" {
        let version = after
            .installed_version
            .clone()
            .expect("decoder requires installed version");
        return Ok((after, Some(format!("{MONITORING_PACKAGE}@{version}"))));
    }
    Ok((after, None))
}

fn failed_row(id: &str, applied: bool, error: impl Into<String>) -> Value {
    json!({"id": id, "applied": applied, "error": error.into()})
}

fn validate_import_plan(plan: &AgentPolicyImportPlan) -> Result<()> {
    let invalid = |message: &str| {
        Err(Error::new(
            ErrorKind::Error,
            format!("invalid agent-policy import plan: {message}"),
        ))
    };
    if plan.total == 0 || plan.total != plan.specs.len() + plan.skipped.len() {
        return invalid("total does not equal pending and skipped agent policies");
    }
    let mut previous_id: Option<&str> = None;
    let mut names = BTreeSet::new();
    let mut expected_body_ids = BTreeSet::new();
    for spec in &plan.specs {
        spec.validate()?;
        if previous_id.is_some_and(|previous| previous >= spec.id.as_str()) {
            return invalid("pending agent policies must be unique and sorted by id");
        }
        previous_id = Some(&spec.id);
        if !names.insert(spec.name.as_str()) {
            return invalid("pending agent-policy names must be unique");
        }
        let Some(before) = plan.before.get(&spec.id) else {
            return invalid("preflight snapshots do not match pending agent policies");
        };
        if let Some(current) = before {
            current.spec.validate()?;
            if current.spec.id != spec.id {
                return invalid("live snapshot id does not match its pending policy");
            }
            if current.attached.windows(2).any(|ids| ids[0] >= ids[1]) {
                return invalid("attached integration ids must be unique and sorted");
            }
        }
        match before {
            None if plan.bodies.contains_key(&spec.id) => {
                return invalid("planned creates must not carry a replacement body");
            }
            None => {}
            Some(current) if current.spec == *spec => {
                if plan.bodies.contains_key(&spec.id) {
                    return invalid("unchanged agent policies must not carry a replacement body");
                }
            }
            Some(current) => {
                expected_body_ids.insert(spec.id.as_str());
                if !plan.overwrite {
                    return invalid("replacement plan requires overwrite");
                }
                if plan.bodies.get(&spec.id) != Some(&build_replace_body(&current.spec, spec)?) {
                    return invalid("replacement body does not match its snapshots");
                }
            }
        }
    }
    if plan.before.len() != plan.specs.len() {
        return invalid("preflight snapshots do not match pending agent policies");
    }
    if plan
        .bodies
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_body_ids
    {
        return invalid("replacement bodies do not match changed agent policies");
    }
    let mut previous_skipped: Option<&str> = None;
    for skipped in &plan.skipped {
        let object = skipped.as_object().ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                "invalid agent-policy import plan: skipped row must be an object",
            )
        })?;
        if object.len() != 2 || object.get("reason").and_then(Value::as_str) != Some("exists") {
            return invalid("skipped rows must contain only id and reason exists");
        }
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Error,
                    "invalid agent-policy import plan: skipped id must be non-empty",
                )
            })?;
        if previous_skipped.is_some_and(|previous| previous >= id) {
            return invalid("skipped agent policies must be unique and sorted by id");
        }
        if plan.before.contains_key(id) {
            return invalid("an agent policy cannot be both pending and skipped");
        }
        previous_skipped = Some(id);
    }

    let needs_monitoring = plan.specs.iter().any(|spec| {
        monitoring_can_install(plan.before.get(&spec.id).and_then(Option::as_ref), spec)
    });
    match (&plan.monitoring_package, needs_monitoring) {
        (Some(status), true) if status.name == MONITORING_PACKAGE => {
            let expected = if status.status == "installed" {
                Vec::new()
            } else {
                vec![SERVER_SELECTED_INSTALL.to_string()]
            };
            if status.status == "installed" && status.installed_version.is_none() {
                return invalid("installed monitoring package needs an exact version");
            }
            if plan.package_installs != expected {
                return invalid("monitoring package preview does not match its snapshot");
            }
        }
        (None, false) if plan.package_installs.is_empty() => {}
        _ => return invalid("monitoring package snapshot does not match pending transitions"),
    }

    let expected_preview = MutationPlan {
        preview_action: format!(
            "Import {} agent policy(ies) from {}",
            plan.specs.len(),
            plan.source.display()
        ),
        preview_details: import_details(&plan.specs, &plan.before, &plan.package_installs),
        targets: plan.specs.iter().map(|spec| spec.id.clone()).collect(),
    };
    if plan.preview != expected_preview {
        return invalid("preview does not match the canonical plan");
    }
    Ok(())
}

fn http(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Http, message)
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentPolicyDeleteTarget {
    pub id: String,
    pub name: String,
    pub snapshot: LiveAgentPolicy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentPolicyDeletePlan {
    pub preview: MutationPlan,
    pub targets: Vec<AgentPolicyDeleteTarget>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentPolicyDeleteReport {
    pub applied: bool,
    pub deleted: Vec<Value>,
    pub failed: Vec<Value>,
    pub total: usize,
    pub affected_agents: u64,
}

pub async fn plan_delete(
    transport: &Transport,
    selectors: &[String],
) -> Result<AgentPolicyDeletePlan> {
    if selectors.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "agent-policy delete needs at least one selector",
        ));
    }
    let mut ids = BTreeSet::new();
    for selector in selectors {
        ids.insert(resolve(transport, selector).await?.id);
    }
    let mut targets = Vec::new();
    let mut conflicts = Vec::new();
    for id in ids {
        let live = read_live(transport, &id).await?;
        if live.agents > 0 {
            conflicts.push(format!(
                "agent policy '{id}' has {} assigned agents",
                live.agents
            ));
        }
        if !live.attached.is_empty() {
            conflicts.push(format!(
                "agent policy '{id}' has attached integrations: {}",
                live.attached.join(", ")
            ));
        }
        targets.push(AgentPolicyDeleteTarget {
            id: id.clone(),
            name: live.spec.name.clone(),
            snapshot: live,
        });
    }
    if !conflicts.is_empty() {
        return Err(Error::new(ErrorKind::Conflict, conflicts.join("; ")));
    }
    Ok(AgentPolicyDeletePlan {
        preview: delete_preview(&targets),
        targets,
    })
}

fn delete_preview(targets: &[AgentPolicyDeleteTarget]) -> MutationPlan {
    MutationPlan {
        preview_action: format!("Delete {} agent policy(ies)", targets.len()),
        preview_details: targets
            .iter()
            .map(|target| {
                format!(
                    "{}  {}  agents {}  integrations {}",
                    target.id,
                    target.name,
                    target.snapshot.agents,
                    target.snapshot.attached.len()
                )
            })
            .collect(),
        targets: targets.iter().map(|target| target.id.clone()).collect(),
    }
}

pub async fn apply_delete(
    transport: &Transport,
    plan: &AgentPolicyDeletePlan,
) -> Result<AgentPolicyDeleteReport> {
    validate_delete_plan(plan)?;
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    for target in &plan.targets {
        let live = match read_live(transport, &target.id).await {
            Ok(live) => live,
            Err(error) if error.kind == ErrorKind::NotFound => {
                failed.push(
                    json!({"id": target.id, "error": "agent policy disappeared since preview"}),
                );
                continue;
            }
            Err(error) => {
                failed.push(json!({"id": target.id, "error": error.message}));
                continue;
            }
        };
        if live != target.snapshot {
            failed.push(json!({"id": target.id, "error": "agent policy changed since preview"}));
            continue;
        }
        match agent_policies::delete(transport, &target.id).await {
            Ok(()) => deleted.push(json!({"id": target.id})),
            Err(error) => failed.push(json!({"id": target.id, "error": error.message})),
        }
    }
    Ok(AgentPolicyDeleteReport {
        applied: true,
        deleted,
        failed,
        total: plan.targets.len(),
        affected_agents: 0,
    })
}

fn validate_delete_plan(plan: &AgentPolicyDeletePlan) -> Result<()> {
    if plan.targets.is_empty() || plan.preview != delete_preview(&plan.targets) {
        return Err(Error::new(
            ErrorKind::Error,
            "invalid agent-policy delete plan",
        ));
    }
    let mut previous: Option<&str> = None;
    for target in &plan.targets {
        target.snapshot.spec.validate()?;
        if target.id != target.snapshot.spec.id
            || target.name != target.snapshot.spec.name
            || target.snapshot.agents != 0
            || !target.snapshot.attached.is_empty()
            || previous.is_some_and(|previous| previous >= target.id.as_str())
        {
            return Err(Error::new(
                ErrorKind::Error,
                "invalid agent-policy delete plan",
            ));
        }
        previous = Some(&target.id);
    }
    Ok(())
}
