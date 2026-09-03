//! Integration-policy selection, normalization, and local validation.

use crate::content_codec::{self, ContentFormat};
use crate::fleet::integration_policies::{
    self, IntegrationPackageSpec, IntegrationPolicyDetail, IntegrationPolicySpec,
    IntegrationPolicySummary,
};
use crate::fleet::{agent_policies, agent_policy_ops};
use crate::ops::ExportOutcome;
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const PAGE_SIZE: u64 = 1000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntegrationPolicyFilter {
    pub search: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IntegrationPolicyList {
    pub total: u64,
    pub integration_policies: Vec<IntegrationPolicySummary>,
    pub truncated: bool,
}

/// A resolved selector retains the one-object response for later operations.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ResolvedIntegrationPolicy {
    pub(crate) summary: IntegrationPolicySummary,
    pub(crate) item: Map<String, Value>,
}

/// Strictly reduced package installation state. Fleet's public status decoder
/// intentionally preserves registry text for agent-policy orchestration; an
/// integration dependency must not accept an ambiguous state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PackageDependencyState {
    Installed { version: String },
    NotInstalled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageDependencySnapshot {
    name: String,
    state: PackageDependencyState,
}

/// Exact package-defined secret variables. The companion `known_*` maps are
/// deliberately private implementation detail: a configured value is safe
/// only after Fleet metadata proves it has a definition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SecretSchema {
    package_vars: BTreeSet<String>,
    input_vars: BTreeMap<String, BTreeSet<String>>,
    stream_vars: BTreeMap<(String, String), BTreeSet<String>>,
}

#[derive(Debug, Clone, Default)]
struct KnownSchema {
    package_vars: BTreeSet<String>,
    input_vars: BTreeMap<String, BTreeSet<String>>,
    stream_vars: BTreeMap<(String, String), BTreeSet<String>>,
}

/// Collect all measured pages then sort by stable id locally.
pub async fn collect(transport: &Transport) -> Result<Vec<Map<String, Value>>> {
    let mut page_number = 1;
    let mut total = None;
    let mut items = Vec::new();
    let mut ids = BTreeSet::new();
    loop {
        let page = integration_policies::list_page(transport, page_number).await?;
        if page.page != page_number || page.per_page != PAGE_SIZE {
            return Err(http(
                "decoding integration policies list: unexpected page metadata",
            ));
        }
        if page.items.len() as u64 > PAGE_SIZE {
            return Err(http(
                "decoding integration policies list: page returned more items than requested",
            ));
        }
        match total {
            Some(expected) if expected != page.total => {
                return Err(http(
                    "decoding integration policies list: total changed while paging",
                ));
            }
            Some(_) => {}
            None => total = Some(page.total),
        }
        let page_len = page.items.len() as u64;
        for item in page.items {
            let id = required_string(&item, "id", "integration policies list")?;
            if !ids.insert(id.clone()) {
                return Err(http(format!(
                    "decoding integration policies list: duplicate integration policy id '{id}'"
                )));
            }
            items.push(item);
        }
        let expected = total.expect("first page sets total");
        if items.len() as u64 >= expected {
            break;
        }
        if page_len != PAGE_SIZE {
            return Err(http(
                "decoding integration policies list: page was short before total",
            ));
        }
        page_number += 1;
    }
    if items.len() as u64 > total.unwrap_or_default() {
        return Err(http(
            "decoding integration policies list: returned more items than total",
        ));
    }
    items.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    Ok(items)
}

/// List with local case-insensitive search and post-sort limiting.
pub async fn list_op(
    transport: &Transport,
    filter: &IntegrationPolicyFilter,
) -> Result<IntegrationPolicyList> {
    let items = collect(transport).await?;
    let total = items.len() as u64;
    let needle = filter.search.as_ref().map(|value| value.to_lowercase());
    let mut integration_policies = Vec::new();
    for item in &items {
        let summary = summary_from_item(item)?;
        if needle.as_ref().is_none_or(|needle| {
            summary.id.to_lowercase().contains(needle)
                || summary.name.to_lowercase().contains(needle)
        }) {
            integration_policies.push(summary);
        }
    }
    let limit = filter.limit.unwrap_or(usize::MAX);
    let truncated = integration_policies.len() > limit;
    integration_policies.truncate(limit);
    Ok(IntegrationPolicyList {
        total,
        integration_policies,
        truncated,
    })
}

/// Resolve a stable id first, then a unique exact name.
pub async fn resolve(transport: &Transport, selector: &str) -> Result<IntegrationPolicySummary> {
    Ok(resolve_item(transport, selector).await?.summary)
}

/// Resolve a selector and retain the exact one-object response for Task 4.
pub(crate) async fn resolve_item(
    transport: &Transport,
    selector: &str,
) -> Result<ResolvedIntegrationPolicy> {
    match integration_policies::get(transport, selector).await {
        Ok(policy) => {
            return Ok(ResolvedIntegrationPolicy {
                summary: summary_from_item(&policy.item)?,
                item: policy.item,
            });
        }
        Err(error) if error.kind == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let matches: Vec<IntegrationPolicySummary> = collect(transport)
        .await?
        .iter()
        .filter(|item| item.get("name").and_then(Value::as_str) == Some(selector))
        .map(summary_from_item)
        .collect::<Result<_>>()?;
    match matches.as_slice() {
        [] => Err(Error::new(
            ErrorKind::NotFound,
            format!("no integration policy with id or name '{selector}'"),
        )),
        [one] => {
            let policy = integration_policies::get(transport, &one.id).await?;
            Ok(ResolvedIntegrationPolicy {
                summary: one.clone(),
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

/// Return a safe integration-policy view. Parent reads are both the attachment
/// race check and the sole source of affected-agent counts.
pub async fn get_op(transport: &Transport, selector: &str) -> Result<IntegrationPolicyDetail> {
    let resolved = resolve_item(transport, selector).await?;
    let parents = read_parents(transport, &resolved.summary.id, &resolved.item)?;
    let parents = read_parent_snapshots(transport, &resolved.summary.id, &parents).await?;
    let mut blocked_by = live_blocked_by(&resolved.item, &resolved.summary.id, transport.space())?;
    for parent in parents.values() {
        if parent.platform_owned {
            blocked_by.insert(format!("parent:{}.platform_owned", parent.id));
        }
        if parent.protected {
            blocked_by.insert(format!("parent:{}.is_protected", parent.id));
        }
    }
    Ok(IntegrationPolicyDetail {
        id: resolved.summary.id,
        name: resolved.summary.name,
        namespace: resolved.summary.namespace,
        description: resolved.summary.description,
        policy_ids: parents.keys().cloned().collect(),
        package: resolved.summary.package,
        affected_agents: parents.values().map(|parent| parent.agents).sum(),
        blocked_by: blocked_by.into_iter().collect(),
    })
}

/// Export selected integrations or every custom integration. A selector is
/// resolved once and deduplicated by its stable id before any parent, package,
/// or metadata reads.
pub async fn export(
    transport: &Transport,
    selectors: &[String],
    all_custom: bool,
    format: ContentFormat,
) -> Result<ExportOutcome> {
    if selectors.is_empty() && !all_custom {
        return Err(Error::new(
            ErrorKind::Error,
            "integration-policy export needs selectors or --all-custom",
        ));
    }
    if !selectors.is_empty() && all_custom {
        return Err(Error::new(
            ErrorKind::Error,
            "--all-custom cannot be combined with selectors",
        ));
    }

    let mut rows = BTreeMap::new();
    if all_custom {
        for item in collect(transport).await? {
            let summary = summary_from_item(&item)?;
            if optional_bool(&item, "is_managed", &summary.id)? == Some(true) {
                continue;
            }
            let live = integration_policies::get(transport, &summary.id).await?;
            rows.insert(
                summary.id.clone(),
                ResolvedIntegrationPolicy {
                    summary,
                    item: live.item,
                },
            );
        }
    } else {
        for selector in selectors {
            let resolved = resolve_item(transport, selector).await?;
            rows.entry(resolved.summary.id.clone()).or_insert(resolved);
        }
    }

    let mut specs = Vec::new();
    for (id, resolved) in rows {
        let parent_ids = read_parents(transport, &id, &resolved.item)?;
        let parents = read_parent_snapshots(transport, &id, &parent_ids).await?;
        if all_custom
            && parents
                .values()
                .any(|parent| parent.platform_owned || parent.protected)
        {
            continue;
        }
        specs.push(effective_spec(transport, &id, &resolved.item, &parents).await?);
    }
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(ExportOutcome {
        body: content_codec::encode_sequence(&specs, format)?,
        exported: specs.len() as u64,
        missing: Vec::new(),
    })
}

fn read_parents(
    _transport: &Transport,
    id: &str,
    item: &Map<String, Value>,
) -> Result<Vec<String>> {
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

async fn read_parent_snapshots(
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

async fn effective_spec(
    transport: &Transport,
    id: &str,
    item: &Map<String, Value>,
    parents: &BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
) -> Result<IntegrationPolicySpec> {
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
    }
    let dependency =
        read_dependencies(transport, &package_coordinate(item, "integration policy")?).await?;
    let spec = normalize(item, transport.space())?;
    if let Some(namespace) = &spec.namespace {
        if parents
            .values()
            .any(|parent| &parent.namespace != namespace)
        {
            return unsupported(format!(
                "integration policy '{id}' is not portable: namespace does not match every parent"
            ));
        }
    } else {
        let namespaces: BTreeSet<&str> = parents
            .values()
            .map(|parent| parent.namespace.as_str())
            .collect();
        if namespaces.len() != 1 {
            return unsupported(format!(
                "integration policy '{id}' is not portable: parents have different namespaces"
            ));
        }
    }
    // A package policy can only have been compiled from the exact installed
    // coordinate. Treat a divergent or absent state as a loud conflict.
    match dependency.state {
        PackageDependencyState::Installed { ref version } if version == &spec.package.version => {}
        PackageDependencyState::Installed { .. } => {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "integration policy '{id}' package {} has a different installed version",
                    dependency.name
                ),
            ));
        }
        PackageDependencyState::NotInstalled => {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "integration policy '{id}' package {} is not installed",
                    dependency.name
                ),
            ));
        }
    }
    let metadata = integration_policies::package_metadata(
        transport,
        &spec.package.name,
        &spec.package.version,
    )
    .await?;
    let paths = configured_secret_paths(&spec, &metadata.item)?;
    if !paths.is_empty() {
        return unsupported(format!(
            "integration policy '{id}' is not portable: {}",
            paths
                .into_iter()
                .map(|path| format!("{id}:{path}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(spec)
}

async fn read_dependencies(
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

fn configured_secret_paths(
    spec: &IntegrationPolicySpec,
    metadata: &Map<String, Value>,
) -> Result<Vec<String>> {
    let (secrets, known) = secret_schema(metadata)?;
    let mut paths = BTreeSet::new();
    configured_vars(
        spec.vars.as_ref(),
        &known.package_vars,
        &secrets.package_vars,
        &spec.id,
        "vars",
        &mut paths,
    )?;
    for (input_key, input) in &spec.inputs {
        let input = input.as_object().ok_or_else(|| {
            http(format!(
                "decoding integration policy '{}': inputs.{input_key} must be an object",
                spec.id
            ))
        })?;
        let known_vars = known.input_vars.get(input_key).ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                format!(
                    "integration policy '{}': {}:inputs.{input_key} has no matching package definition",
                    spec.id, spec.id
                ),
            )
        })?;
        let secret_vars = secrets
            .input_vars
            .get(input_key)
            .cloned()
            .unwrap_or_default();
        configured_vars(
            input.get("vars").map(expect_object).transpose()?,
            known_vars,
            &secret_vars,
            &spec.id,
            &format!("inputs.{input_key}.vars"),
            &mut paths,
        )?;
        if let Some(streams) = input.get("streams") {
            let streams = streams.as_object().ok_or_else(|| {
                http(format!(
                    "decoding integration policy '{}': inputs.{input_key}.streams must be an object",
                    spec.id
                ))
            })?;
            for (dataset, stream) in streams {
                let stream = stream.as_object().ok_or_else(|| {
                    http(format!(
                        "decoding integration policy '{}': inputs.{input_key}.streams.{dataset} must be an object",
                        spec.id
                    ))
                })?;
                let key = (input_key.clone(), dataset.clone());
                let known_vars = known.stream_vars.get(&key).ok_or_else(|| {
                    Error::new(
                        ErrorKind::Unsupported,
                        format!(
                            "integration policy '{}': {}:inputs.{input_key}.streams.{dataset} has no matching package definition",
                            spec.id, spec.id
                        ),
                    )
                })?;
                let secret_vars = secrets.stream_vars.get(&key).cloned().unwrap_or_default();
                configured_vars(
                    stream.get("vars").map(expect_object).transpose()?,
                    known_vars,
                    &secret_vars,
                    &spec.id,
                    &format!("inputs.{input_key}.streams.{dataset}.vars"),
                    &mut paths,
                )?;
            }
        }
    }
    Ok(paths.into_iter().collect())
}

fn expect_object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| http("decoding integration policy: configured vars must be an object"))
}

fn configured_vars(
    configured: Option<&Map<String, Value>>,
    known: &BTreeSet<String>,
    secret: &BTreeSet<String>,
    policy_id: &str,
    prefix: &str,
    paths: &mut BTreeSet<String>,
) -> Result<()> {
    let Some(configured) = configured else {
        return Ok(());
    };
    for name in configured.keys() {
        if !known.contains(name) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "integration policy '{policy_id}' is not portable: {policy_id}:{prefix}.{name} has no matching package definition"
                ),
            ));
        }
        if secret.contains(name) {
            paths.insert(format!("{prefix}.{name}"));
        }
    }
    Ok(())
}

fn secret_schema(metadata: &Map<String, Value>) -> Result<(SecretSchema, KnownSchema)> {
    let mut secrets = SecretSchema::default();
    let mut known = KnownSchema::default();
    parse_var_definitions(
        metadata.get("vars"),
        &mut known.package_vars,
        &mut secrets.package_vars,
        "package metadata vars",
    )?;
    let templates = match metadata.get("policy_templates") {
        None | Some(Value::Null) => return Ok((secrets, known)),
        Some(Value::Array(value)) => value,
        Some(_) => {
            return Err(http(
                "decoding package metadata: policy_templates must be an array",
            ));
        }
    };
    for template in templates {
        let template = template.as_object().ok_or_else(|| {
            http("decoding package metadata: policy_templates entry must be an object")
        })?;
        let template_name = metadata_name(template, "name", "policy_templates entry")?;
        let inputs = match template.get("inputs") {
            None | Some(Value::Null) => continue,
            Some(Value::Array(value)) => value,
            Some(_) => {
                return Err(http(
                    "decoding package metadata: policy_templates inputs must be an array",
                ));
            }
        };
        for input in inputs {
            let input = input.as_object().ok_or_else(|| {
                http("decoding package metadata: policy_templates inputs entry must be an object")
            })?;
            let input_type = metadata_name(input, "type", "policy_templates input")?;
            let input_key = format!("{template_name}-{input_type}");
            let mut known_vars = BTreeSet::new();
            let mut secret_vars = BTreeSet::new();
            parse_var_definitions(
                input.get("vars"),
                &mut known_vars,
                &mut secret_vars,
                "package metadata input vars",
            )?;
            known.input_vars.insert(input_key.clone(), known_vars);
            if !secret_vars.is_empty() {
                secrets.input_vars.insert(input_key.clone(), secret_vars);
            }
            let streams = match input.get("streams") {
                None | Some(Value::Null) => continue,
                Some(Value::Array(value)) => value,
                Some(_) => {
                    return Err(http(
                        "decoding package metadata: input streams must be an array",
                    ));
                }
            };
            for stream in streams {
                let stream = stream.as_object().ok_or_else(|| {
                    http("decoding package metadata: input streams entry must be an object")
                })?;
                let data_stream = stream
                    .get("data_stream")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        http("decoding package metadata: stream data_stream must be an object")
                    })?;
                let dataset = metadata_name(data_stream, "dataset", "stream data_stream")?;
                let mut known_vars = BTreeSet::new();
                let mut secret_vars = BTreeSet::new();
                parse_var_definitions(
                    stream.get("vars"),
                    &mut known_vars,
                    &mut secret_vars,
                    "package metadata stream vars",
                )?;
                let key = (input_key.clone(), dataset);
                known.stream_vars.insert(key.clone(), known_vars);
                if !secret_vars.is_empty() {
                    secrets.stream_vars.insert(key, secret_vars);
                }
            }
        }
    }
    Ok((secrets, known))
}

fn parse_var_definitions(
    value: Option<&Value>,
    known: &mut BTreeSet<String>,
    secrets: &mut BTreeSet<String>,
    context: &str,
) -> Result<()> {
    let values = match value {
        None | Some(Value::Null) => return Ok(()),
        Some(Value::Array(values)) => values,
        Some(_) => return Err(http(format!("decoding {context}: vars must be an array"))),
    };
    for value in values {
        let definition = value
            .as_object()
            .ok_or_else(|| http(format!("decoding {context}: variable must be an object")))?;
        let name = metadata_name(definition, "name", context)?;
        if !known.insert(name.clone()) {
            return Err(http(format!(
                "decoding {context}: duplicate variable name '{name}'"
            )));
        }
        match definition.get("secret") {
            None => {}
            Some(Value::Bool(true)) => {
                secrets.insert(name);
            }
            Some(Value::Bool(false)) => {}
            Some(_) => {
                return Err(http(format!(
                    "decoding {context}: secret must be a boolean"
                )));
            }
        }
    }
    Ok(())
}

fn metadata_name(object: &Map<String, Value>, field: &str, context: &str) -> Result<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            http(format!(
                "decoding package metadata: {context} {field} must be a non-empty string"
            ))
        })
}

fn live_blocked_by(
    item: &Map<String, Value>,
    id: &str,
    active_space: &str,
) -> Result<BTreeSet<String>> {
    let mut reasons = BTreeSet::new();
    required_true(item, "enabled", id)?;
    for field in [
        "is_managed",
        "supports_agentless",
        "supports_cloud_connector",
    ] {
        if optional_bool(item, field, id)? == Some(true) {
            reasons.insert(field.to_owned());
        }
    }
    for field in ["output_id", "cloud_connector_id", "cloud_connector_name"] {
        match item.get(field) {
            None | Some(Value::Null) | Some(Value::Bool(false)) => {}
            Some(Value::String(_)) => {
                reasons.insert(field.to_owned());
            }
            Some(_) => {
                return Err(http(format!(
                    "decoding integration policy '{id}': {field} must be a string or null"
                )));
            }
        }
    }
    match item.get("secret_references") {
        None | Some(Value::Null) => {}
        Some(Value::Array(values)) if values.is_empty() => {}
        Some(Value::Array(_)) => {
            reasons.insert("secret_references".into());
        }
        Some(_) => {
            return Err(http(format!(
                "decoding integration policy '{id}': secret_references must be an array or null"
            )));
        }
    }
    let active = if active_space.is_empty() {
        "default"
    } else {
        active_space
    };
    match item.get("spaceIds") {
        None | Some(Value::Null) => {}
        Some(Value::Array(spaces)) => {
            for space in spaces {
                let space = space.as_str().filter(|value| !value.is_empty()).ok_or_else(|| {
                    http(format!("decoding integration policy '{id}': spaceIds must contain non-empty strings"))
                })?;
                if space != active {
                    reasons.insert("spaceIds".into());
                }
            }
        }
        Some(_) => {
            return Err(http(format!(
                "decoding integration policy '{id}': spaceIds must be an array or null"
            )));
        }
    }
    Ok(reasons)
}

const PORTABLE_OPTIONAL: [&str; 6] = [
    "description",
    "namespace",
    "vars",
    "var_group_selections",
    "condition",
    "additional_datastreams_permissions",
];

const REMOVED_FIELDS: [&str; 19] = [
    "agents",
    "cloud_connector_id",
    "cloud_connector_name",
    "created_at",
    "created_by",
    "elasticsearch",
    "enabled",
    "is_managed",
    "output_id",
    "package_agent_version_condition",
    "policy_id",
    "revision",
    "secret_references",
    "spaceIds",
    "supports_agentless",
    "supports_cloud_connector",
    "updated_at",
    "updated_by",
    "version",
];

/// Build a fresh portable policy from a simplified live Fleet response.
pub fn normalize(item: &Map<String, Value>, active_space: &str) -> Result<IntegrationPolicySpec> {
    let id = required_string(item, "id", "integration policy")?;
    portability_check(item, &id, active_space)?;
    reject_unknown_top_level(item, &id)?;

    let mut portable = Map::new();
    for field in ["id", "name", "policy_ids"] {
        if let Some(value) = item.get(field) {
            portable.insert(field.to_owned(), value.clone());
        }
    }
    portable.insert("package".to_owned(), normalize_package(item, &id)?);
    portable.insert("inputs".to_owned(), normalize_inputs(item, &id)?);
    for field in PORTABLE_OPTIONAL {
        if let Some(value) = item.get(field)
            && !value.is_null()
        {
            portable.insert(field.to_owned(), value.clone());
        }
    }
    IntegrationPolicySpec::try_from(Value::Object(portable)).map_err(|error| {
        http(format!(
            "decoding integration policy '{id}': {}",
            error.message
        ))
    })
}

fn normalize_package(item: &Map<String, Value>, id: &str) -> Result<Value> {
    let package = item
        .get("package")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            http(format!(
                "decoding integration policy '{id}': package must be an object"
            ))
        })?;
    for (field, expected) in [("title", "a string")] {
        if let Some(value) = package.get(field)
            && !value.is_null()
            && !value.is_string()
        {
            return Err(http(format!(
                "decoding integration policy '{id}': package.{field} must be {expected} or null"
            )));
        }
    }
    for field in ["requires_root", "fips_compatible"] {
        if let Some(value) = package.get(field)
            && !value.is_null()
            && !value.is_boolean()
        {
            return Err(http(format!(
                "decoding integration policy '{id}': package.{field} must be a boolean or null"
            )));
        }
    }
    let mut portable = Map::new();
    for field in ["name", "version"] {
        if let Some(value) = package.get(field) {
            portable.insert(field.to_owned(), value.clone());
        }
    }
    let known: BTreeSet<&str> = [
        "name",
        "version",
        "title",
        "requires_root",
        "fips_compatible",
    ]
    .into_iter()
    .collect();
    if let Some(field) = package
        .keys()
        .map(String::as_str)
        .filter(|field| !known.contains(field))
        .min()
    {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!("integration policy '{id}' carries unknown package field '{field}'"),
        ));
    }
    Ok(Value::Object(portable))
}

fn normalize_inputs(item: &Map<String, Value>, id: &str) -> Result<Value> {
    let inputs = item
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            http(format!(
                "decoding integration policy '{id}': inputs must be an object"
            ))
        })?;
    let mut normalized = Map::new();
    for (input_id, input) in inputs {
        normalized.insert(
            input_id.clone(),
            normalize_package_map(input, "compiled_input")?,
        );
    }
    Ok(Value::Object(normalized))
}

/// Keep package-defined input and stream maps open while rebuilding them
/// without Fleet-generated ids or compiled content.
fn normalize_package_map(value: &Value, compiled_field: &str) -> Result<Value> {
    let object = value
        .as_object()
        .ok_or_else(|| http("decoding integration policy: input must be an object"))?;
    let mut normalized = Map::new();
    for (field, value) in object {
        if field == "id" {
            if !value.is_string() {
                return Err(http(
                    "decoding integration policy: generated id must be a string",
                ));
            }
            continue;
        }
        if field == compiled_field {
            if !value.is_object() {
                return Err(http(format!(
                    "decoding integration policy: {compiled_field} must be an object"
                )));
            }
            continue;
        }
        if field == "streams" {
            let streams = value.as_object().ok_or_else(|| {
                http("decoding integration policy: input streams must be an object")
            })?;
            let mut normalized_streams = Map::new();
            for (stream_id, stream) in streams {
                normalized_streams.insert(
                    stream_id.clone(),
                    normalize_package_map(stream, "compiled_stream")?,
                );
            }
            normalized.insert(field.clone(), Value::Object(normalized_streams));
        } else {
            normalized.insert(field.clone(), value.clone());
        }
    }
    Ok(Value::Object(normalized))
}

fn portability_check(item: &Map<String, Value>, id: &str, active_space: &str) -> Result<()> {
    let mut reasons = BTreeSet::new();
    required_true(item, "enabled", id)?;
    if let Some(value) = item.get("elasticsearch")
        && !value.is_object()
    {
        return Err(http(format!(
            "decoding integration policy '{id}': elasticsearch must be an object"
        )));
    }
    if let Some(value) = item.get("package_agent_version_condition")
        && !value.is_null()
        && !value.is_string()
    {
        return Err(http(format!(
            "decoding integration policy '{id}': package_agent_version_condition must be a string or null"
        )));
    }
    for field in [
        "is_managed",
        "supports_agentless",
        "supports_cloud_connector",
    ] {
        if let Some(true) = optional_bool(item, field, id)? {
            reasons.insert(field);
        }
    }
    for field in ["output_id", "cloud_connector_id", "cloud_connector_name"] {
        match item.get(field) {
            None | Some(Value::Null) | Some(Value::Bool(false)) => {}
            Some(Value::String(_)) => {
                reasons.insert(field);
            }
            Some(_) => {
                return Err(http(format!(
                    "decoding integration policy '{id}': {field} must be a string or null"
                )));
            }
        }
    }
    match item.get("secret_references") {
        None | Some(Value::Null) => {}
        Some(Value::Array(references)) if references.is_empty() => {}
        Some(Value::Array(_)) => {
            reasons.insert("secret_references");
        }
        Some(_) => {
            return Err(http(format!(
                "decoding integration policy '{id}': secret_references must be an array or null"
            )));
        }
    }
    let active = if active_space.is_empty() {
        "default"
    } else {
        active_space
    };
    match item.get("spaceIds") {
        None | Some(Value::Null) => {}
        Some(Value::Array(spaces)) => {
            for space in spaces {
                let space = space.as_str().filter(|space| !space.is_empty()).ok_or_else(|| {
                    http(format!(
                        "decoding integration policy '{id}': spaceIds must contain non-empty strings"
                    ))
                })?;
                if space != active {
                    reasons.insert("spaceIds");
                }
            }
        }
        Some(_) => {
            return Err(http(format!(
                "decoding integration policy '{id}': spaceIds must be an array or null"
            )));
        }
    }
    if let Some(policy_id) = item.get("policy_id").filter(|value| !value.is_null()) {
        let policy_id = policy_id
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                http(format!(
                    "decoding integration policy '{id}': policy_id must be a non-empty string"
                ))
            })?;
        let policy_ids = item
            .get("policy_ids")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                http(format!(
                    "decoding integration policy '{id}': policy_ids must be an array"
                ))
            })?;
        if policy_ids.first().and_then(Value::as_str) != Some(policy_id) {
            return Err(http(format!(
                "decoding integration policy '{id}': policy_id must equal policy_ids[0]"
            )));
        }
    }
    if reasons.is_empty() {
        Ok(())
    } else {
        unsupported(format!(
            "integration policy '{id}' is not portable: {}",
            reasons.into_iter().collect::<Vec<_>>().join(", ")
        ))
    }
}

fn required_true(item: &Map<String, Value>, field: &str, id: &str) -> Result<()> {
    match item.get(field) {
        Some(Value::Bool(true)) => Ok(()),
        Some(Value::Bool(false)) => unsupported(format!(
            "integration policy '{id}' is not portable: {field}"
        )),
        _ => Err(http(format!(
            "decoding integration policy '{id}': {field} must be true"
        ))),
    }
}

fn optional_bool(item: &Map<String, Value>, field: &str, id: &str) -> Result<Option<bool>> {
    match item.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(http(format!(
            "decoding integration policy '{id}': {field} must be a boolean or null"
        ))),
    }
}

fn reject_unknown_top_level(item: &Map<String, Value>, id: &str) -> Result<()> {
    let known: BTreeSet<&str> = ["id", "name", "policy_ids", "package", "inputs"]
        .into_iter()
        .chain(PORTABLE_OPTIONAL)
        .chain(REMOVED_FIELDS)
        .collect();
    if let Some(field) = item
        .keys()
        .map(String::as_str)
        .filter(|field| !known.contains(field))
        .min()
    {
        return unsupported(format!(
            "integration policy '{id}' carries unknown field '{field}'"
        ));
    }
    Ok(())
}

fn summary_from_item(item: &Map<String, Value>) -> Result<IntegrationPolicySummary> {
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

fn package_coordinate(item: &Map<String, Value>, context: &str) -> Result<IntegrationPackageSpec> {
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

fn required_string(item: &Map<String, Value>, field: &str, context: &str) -> Result<String> {
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

/// Decode one JSON or YAML artifact without constructing transport or config.
pub fn validate(path: &Path) -> Result<Vec<IntegrationPolicySpec>> {
    let body = std::fs::read_to_string(path).map_err(|error| {
        Error::new(
            ErrorKind::Error,
            format!("reading {}: {error}", path.display()),
        )
    })?;
    let mut specs = content_codec::decode_sequence::<IntegrationPolicySpec>(
        &body,
        ContentFormat::from_path(path),
        "integration policy",
    )?;
    duplicate_error(&specs, |spec| &spec.id, "ids")?;
    duplicate_error(&specs, |spec| &spec.name, "names")?;
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(specs)
}

fn duplicate_error<'a, F>(specs: &'a [IntegrationPolicySpec], key: F, noun: &str) -> Result<()>
where
    F: Fn(&'a IntegrationPolicySpec) -> &'a String,
{
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for spec in specs {
        let value = key(spec);
        if !seen.insert(value.as_str()) {
            duplicates.insert(value.as_str());
        }
    }
    if duplicates.is_empty() {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Error,
            format!(
                "duplicate integration policy {noun}: {}",
                duplicates.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ))
    }
}

fn http(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Http, message)
}

fn unsupported<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::new(ErrorKind::Unsupported, message))
}
