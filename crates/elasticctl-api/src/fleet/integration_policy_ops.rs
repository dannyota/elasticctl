//! Integration-policy selection, normalization, and local validation.

use crate::content_codec::{self, ContentFormat};
use crate::fleet::integration_policies::{
    self, IntegrationPackageSpec, IntegrationPolicyDetail, IntegrationPolicySpec,
    IntegrationPolicySummary,
};
use crate::fleet::{agent_policies, agent_policy_ops};
use crate::ops::{ExportOutcome, MutationPlan};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

const PAGE_SIZE: u64 = 1000;
const IMPORT_RACE_WARNING: &str =
    "warning  Fleet can change after the final recheck and before the write";
const DELETE_RACE_WARNING: &str =
    "warning  Fleet can change after the final recheck and before the write";

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

/// What `plan_import` preflights and `apply_import` rechecks. Only guard
/// presentation is public: the canonical artifact, effective specifications,
/// and Fleet snapshots never cross the API boundary.
#[derive(Clone, PartialEq)]
pub struct IntegrationPolicyImportPlan {
    pub preview: MutationPlan,
    pub skipped: Vec<Value>,
    pub package_installs: Vec<String>,
    pub total: usize,
    source: PathBuf,
    host: String,
    space: String,
    canonical: Vec<IntegrationPolicySpec>,
    name_owners: BTreeMap<String, BTreeSet<String>>,
    name_owners_snapshot: BTreeMap<String, BTreeSet<String>>,
    parent_snapshots: BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
    skipped_snapshot: Vec<Value>,
    // Exact get-by-id results from before import classification. This covers
    // every canonical id, so a mutable target or skipped row cannot turn an
    // absent policy into an existing one (or the reverse).
    existing_snapshot: BTreeMap<String, Option<Map<String, Value>>>,
    targets: Vec<IntegrationPolicyImportTarget>,
    package_groups: BTreeMap<String, IntegrationPackageGroup>,
    overwrite: bool,
    skip_existing: bool,
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

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IntegrationPolicyImportReport {
    pub applied: bool,
    pub succeeded: Vec<Value>,
    pub unchanged: Vec<Value>,
    pub skipped: Vec<Value>,
    pub failed: Vec<Value>,
    pub total: usize,
    pub affected_agents: u64,
    pub package_installs: Vec<String>,
}

/// A safe, fully preflighted integration-policy deletion. Only the guard
/// presentation and count are public: Fleet snapshots and package metadata can
/// include configuration values, so they remain private to the API layer.
#[derive(Clone, PartialEq)]
pub struct IntegrationPolicyDeletePlan {
    pub preview: MutationPlan,
    pub total: usize,
    host: String,
    host_snapshot: String,
    space: String,
    space_snapshot: String,
    parent_snapshots: BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
    parent_snapshots_snapshot: BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
    targets: Vec<IntegrationPolicyDeleteTarget>,
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

/// The result of applying an integration-policy deletion plan.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IntegrationPolicyDeleteReport {
    pub applied: bool,
    pub deleted: Vec<Value>,
    pub failed: Vec<Value>,
    pub total: usize,
    pub affected_agents: u64,
}

#[derive(Debug, Clone, PartialEq)]
struct IntegrationPolicyImportTarget {
    effective: IntegrationPolicySpec,
    current: Option<IntegrationPolicyCurrentSnapshot>,
    parents: BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
    replacement_body: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
struct IntegrationPolicyCurrentSnapshot {
    item: Map<String, Value>,
    spec: IntegrationPolicySpec,
    parent_ids: Vec<String>,
}

/// Private execution facts for one stable-id delete. The raw item detects a
/// Fleet change before deletion; the normalized policy and metadata prove that
/// no secret or environment-bound configuration has crossed the guard.
#[derive(Clone, PartialEq)]
struct IntegrationPolicyDeleteTarget {
    id: String,
    name: String,
    item: Map<String, Value>,
    item_snapshot: Map<String, Value>,
    spec: IntegrationPolicySpec,
    spec_snapshot: IntegrationPolicySpec,
    parents: BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
    package: IntegrationPackageSpec,
    dependency: PackageDependencySnapshot,
    dependency_snapshot: PackageDependencySnapshot,
    metadata: Map<String, Value>,
    metadata_snapshot: Map<String, Value>,
}

/// One package coordinate is shared by every pending policy that uses it.
/// `*_snapshot` copies are deliberate: plan validation compares the retained
/// exact Fleet response with the mutable execution expectation before it ever
/// starts remote work.
#[derive(Debug, Clone, PartialEq)]
struct IntegrationPackageGroup {
    package: IntegrationPackageSpec,
    state: PackageDependencySnapshot,
    state_snapshot: PackageDependencySnapshot,
    metadata: Map<String, Value>,
    metadata_snapshot: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportAction {
    Create,
    Replace,
    Unchanged,
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
    let mut blocked_by = live_blocked_by(&resolved.item, &resolved.summary.id, transport.space())?;
    validate_safe_detail_shape(&resolved.item, transport.space())?;
    let parents = read_parents(&resolved.summary.id, &resolved.item)?;
    let parents = read_parent_snapshots(transport, &resolved.summary.id, &parents).await?;
    for parent in parents.values() {
        if parent.platform_owned {
            blocked_by.insert(format!("parent:{}.platform_owned", parent.id));
        }
        if parent.protected {
            blocked_by.insert(format!("parent:{}.is_protected", parent.id));
        }
    }
    if parents
        .values()
        .map(|parent| parent.namespace.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        != 1
    {
        blocked_by.insert("namespace".into());
    }
    if parents
        .values()
        .any(|parent| parent.namespace != resolved.summary.namespace)
    {
        blocked_by.insert("namespace".into());
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

/// Validate every live shape that a safe detail can reason about without
/// erasing its direct portability blockers. The projection keeps package-owned
/// configuration intact while replacing only values that a detail reports in
/// `blocked_by`, so `normalize` remains the single structural validator.
fn validate_safe_detail_shape(item: &Map<String, Value>, active_space: &str) -> Result<()> {
    let mut projected = item.clone();
    projected.insert("enabled".into(), Value::Bool(true));
    for field in [
        "is_managed",
        "supports_agentless",
        "supports_cloud_connector",
    ] {
        projected.insert(field.into(), Value::Bool(false));
    }
    for field in ["output_id", "cloud_connector_id", "cloud_connector_name"] {
        projected.insert(field.into(), Value::Null);
    }
    projected.insert("secret_references".into(), Value::Array(Vec::new()));
    projected.insert("spaceIds".into(), Value::Null);
    normalize(&projected, active_space).map(|_| ())
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
            if optional_bool(&live.item, "is_managed", &summary.id)? == Some(true) {
                continue;
            }
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
        let parent_ids = read_parents(&id, &resolved.item)?;
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

fn read_parents(id: &str, item: &Map<String, Value>) -> Result<Vec<String>> {
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
    let mut spec = normalize(item, transport.space())?;
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
        spec.namespace = namespaces.into_iter().next().map(str::to_owned);
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
        None => return Ok((secrets, known)),
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
            None => continue,
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
            match known.input_vars.entry(input_key.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(known_vars);
                }
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(http(format!(
                        "decoding package metadata: duplicate input key '{input_key}'"
                    )));
                }
            }
            if !secret_vars.is_empty() {
                secrets.input_vars.insert(input_key.clone(), secret_vars);
            }
            let streams = match input.get("streams") {
                None => continue,
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
                match known.stream_vars.entry(key.clone()) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(known_vars);
                    }
                    std::collections::btree_map::Entry::Occupied(_) => {
                        return Err(http(format!(
                            "decoding package metadata: duplicate stream key '{}:{}'",
                            key.0, key.1
                        )));
                    }
                }
                if !secret_vars.is_empty() {
                    secrets.stream_vars.insert(key.clone(), secret_vars);
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
        None => return Ok(()),
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
    match item.get("enabled") {
        Some(Value::Bool(true)) => {}
        Some(Value::Bool(false)) => {
            reasons.insert("enabled".into());
        }
        _ => {
            return Err(http(format!(
                "decoding integration policy '{id}': enabled must be true or false"
            )));
        }
    }
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
    for field in ["id", "name"] {
        if let Some(value) = item.get(field) {
            portable.insert(field.to_owned(), value.clone());
        }
    }
    portable.insert(
        "policy_ids".to_owned(),
        Value::Array(
            read_parents(&id, item)?
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
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

/// Plan a canonical integration-policy import without sending a write. The
/// artifact is decoded exactly once here; apply uses only the retained plan.
pub async fn plan_import(
    transport: &Transport,
    path: &Path,
    overwrite: bool,
    skip_existing: bool,
) -> Result<IntegrationPolicyImportPlan> {
    let canonical = validate(path)?;
    if canonical.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "integration-policy import needs at least one integration policy",
        ));
    }
    if overwrite && skip_existing {
        return Err(Error::new(
            ErrorKind::Error,
            "--overwrite and --skip-existing cannot be used together",
        ));
    }
    validate_requested_package_versions(&canonical)?;

    // Read only the requested ids. A conflicting or skipped existing policy is
    // deliberately kept raw: normalize can refuse an unsupported object, but
    // that object will not be written on those paths.
    let mut existing = BTreeMap::new();
    let mut conflicts = Vec::new();
    for spec in &canonical {
        match integration_policies::get(transport, &spec.id).await {
            Ok(policy) => {
                let returned_id = required_string(&policy.item, "id", "integration policy get")?;
                if returned_id != spec.id {
                    return Err(http(
                        "decoding integration policy get: response id did not match the request",
                    ));
                }
                if !overwrite && !skip_existing {
                    conflicts.push(spec.id.clone());
                }
                existing.insert(spec.id.clone(), Some(policy.item));
            }
            Err(error) if error.kind == ErrorKind::NotFound => {
                existing.insert(spec.id.clone(), None);
            }
            Err(error) => return Err(import_remote_error(error, "planning read")),
        }
    }
    if !conflicts.is_empty() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "integration policies already exist: {}",
                conflicts.join(", ")
            ),
        ));
    }

    // This phase comes before every parent, package-status, and metadata read.
    // A package-coordinate replacement is a different Fleet operation, never
    // a package-policy import update.
    for spec in &canonical {
        if skip_existing && matches!(existing.get(&spec.id), Some(Some(_))) {
            continue;
        }
        let Some(Some(item)) = existing.get(&spec.id) else {
            continue;
        };
        let current = package_coordinate(item, "integration policy")
            .map_err(|error| import_remote_error(error, "planning read"))?;
        if current != spec.package {
            return unsupported(format!(
                "integration policy '{}' cannot change package {}@{} to {}@{}",
                spec.id, current.name, current.version, spec.package.name, spec.package.version
            ));
        }
    }

    // Every artifact name stays relevant even if its id is skipped. A foreign
    // claimant is always a conflict, and this read deliberately happens before
    // any skipped object's raw response would be normalized.
    let names: BTreeSet<String> = canonical.iter().map(|spec| spec.name.clone()).collect();
    let name_owners = relevant_name_owners(transport, &names)
        .await
        .map_err(|error| import_remote_error(error, "planning names read"))?;
    let mut name_conflicts = Vec::new();
    for spec in &canonical {
        let owners = name_owners
            .get(&spec.name)
            .expect("requested name has an ownership entry");
        for owner in owners.iter().filter(|owner| owner.as_str() != spec.id) {
            name_conflicts.push(format!("{} ({owner})", spec.name));
        }
    }
    if !name_conflicts.is_empty() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "integration policy names already exist: {}",
                name_conflicts.join(", ")
            ),
        ));
    }

    let mut skipped = Vec::new();
    let pending: Vec<IntegrationPolicySpec> = canonical
        .iter()
        .filter_map(|spec| match existing.get(&spec.id) {
            Some(Some(item)) if skip_existing => {
                skipped.push(json!({"id": spec.id, "reason": "exists"}));
                None
            }
            _ => Some(spec.clone()),
        })
        .collect();

    let mut targets = Vec::with_capacity(pending.len());
    let mut shared_parents = BTreeMap::new();
    for spec in pending {
        let raw = existing
            .get(&spec.id)
            .expect("every canonical id was fetched")
            .clone();
        let current_parent_ids = raw
            .as_ref()
            .map(|item| {
                read_parents(&spec.id, item)
                    .map_err(|error| import_remote_error(error, "planning read"))
            })
            .transpose()?;
        let parents = read_import_parent_snapshots(
            transport,
            &spec.id,
            current_parent_ids.as_deref().unwrap_or_default(),
            &spec.policy_ids,
        )
        .await
        .map_err(|error| import_remote_error(error, "planning parent read"))?;
        for (parent_id, parent) in &parents {
            match shared_parents.entry(parent_id.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(parent.clone());
                }
                std::collections::btree_map::Entry::Occupied(entry) if entry.get() != parent => {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        format!(
                            "agent policy '{parent_id}' changed while planning integration import"
                        ),
                    ));
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
        let effective = effective_import_spec(&spec, &parents)?;
        let current = raw
            .map(|item| {
                let normalized = normalize(&item, transport.space())
                    .map_err(|error| import_remote_error(error, "planning read"))?;
                if normalized.id != spec.id {
                    return Err(http(
                        "decoding integration policy: response id did not match the request",
                    ));
                }
                Ok(IntegrationPolicyCurrentSnapshot {
                    item,
                    spec: normalized,
                    parent_ids: current_parent_ids.expect("raw policy has parents"),
                })
            })
            .transpose()?;
        targets.push(IntegrationPolicyImportTarget {
            effective,
            current,
            parents,
            replacement_body: None,
        });
    }
    if targets
        .iter()
        .any(|target| !target_name_owners_match(target, &name_owners))
    {
        return Err(Error::new(
            ErrorKind::Conflict,
            "integration policy name ownership changed while planning",
        ));
    }

    let mut package_coordinates = BTreeMap::new();
    for target in &targets {
        package_coordinates
            .entry(target.effective.package.name.clone())
            .or_insert_with(|| target.effective.package.clone());
    }
    let mut package_groups = BTreeMap::new();
    for (name, package) in package_coordinates {
        let state = read_dependencies(transport, &package)
            .await
            .map_err(|error| import_remote_error(error, "planning package read"))?;
        match &state.state {
            PackageDependencyState::Installed { version } if version == &package.version => {}
            PackageDependencyState::Installed { .. } => {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    format!("integration package {name} has a different installed version"),
                ));
            }
            PackageDependencyState::NotInstalled => {
                if targets
                    .iter()
                    .any(|target| target.effective.package.name == name && target.current.is_some())
                {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        format!("integration package {name} is not installed"),
                    ));
                }
            }
        }
        let metadata =
            integration_policies::package_metadata(transport, &package.name, &package.version)
                .await
                .map_err(|error| import_remote_error(error, "planning package metadata read"))?
                .item;
        validate_package_metadata_snapshot(&metadata, &package)
            .map_err(|error| import_remote_error(error, "planning package metadata read"))?;
        package_groups.insert(
            name,
            IntegrationPackageGroup {
                package,
                state: state.clone(),
                state_snapshot: state,
                metadata_snapshot: metadata.clone(),
                metadata,
            },
        );
    }

    let mut secret_paths = BTreeSet::new();
    for target in &targets {
        let package = package_groups
            .get(&target.effective.package.name)
            .expect("every effective package has a group");
        if let Some(current) = &target.current {
            for path in configured_secret_paths(&current.spec, &package.metadata)? {
                secret_paths.insert(format!("{}:{path}", current.spec.id));
            }
        }
        for path in configured_secret_paths(&target.effective, &package.metadata)? {
            secret_paths.insert(format!("{}:{path}", target.effective.id));
        }
    }
    if !secret_paths.is_empty() {
        return unsupported(format!(
            "integration policy import contains configured secrets: {}",
            secret_paths.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }

    for target in &mut targets {
        if let Some(current) = &target.current
            && current.spec != target.effective
        {
            target.replacement_body = Some(replace_wire_body(&target.effective)?);
        }
    }
    let package_installs = planned_package_installs(&package_groups);
    let preview = import_preview(path, &targets, &package_installs);
    let plan = IntegrationPolicyImportPlan {
        preview,
        skipped_snapshot: skipped.clone(),
        skipped,
        package_installs,
        total: canonical.len(),
        source: path.to_path_buf(),
        host: transport.kibana_url().to_owned(),
        space: transport.space().to_owned(),
        canonical,
        name_owners_snapshot: name_owners.clone(),
        name_owners,
        parent_snapshots: shared_parents,
        existing_snapshot: existing.clone(),
        targets,
        package_groups,
        overwrite,
        skip_existing,
    };
    validate_import_plan(&plan)?;
    Ok(plan)
}

fn validate_requested_package_versions(specs: &[IntegrationPolicySpec]) -> Result<()> {
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

async fn relevant_name_owners(
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

fn target_name_owners_match(
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

async fn read_import_parent_snapshots(
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

fn effective_import_spec(
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

fn validate_package_metadata_snapshot(
    metadata: &Map<String, Value>,
    package: &IntegrationPackageSpec,
) -> Result<()> {
    let name = metadata_name(metadata, "name", "package metadata")?;
    let version = metadata_name(metadata, "version", "package metadata")?;
    if name != package.name || version != package.version {
        return Err(http(format!(
            "decoding package metadata: expected {}@{}, got {name}@{version}",
            package.name, package.version
        )));
    }
    secret_schema(metadata).map(|_| ())
}

fn replace_wire_body(spec: &IntegrationPolicySpec) -> Result<Value> {
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
    body.insert("enabled".into(), Value::Bool(true));
    Ok(Value::Object(body))
}

fn planned_package_installs(groups: &BTreeMap<String, IntegrationPackageGroup>) -> Vec<String> {
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

fn import_preview(
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

/// Apply a previously validated import plan. Rows are independent except for
/// their exact package group and shared parent-attachment snapshots.
pub async fn apply_import(
    transport: &Transport,
    plan: &IntegrationPolicyImportPlan,
) -> Result<IntegrationPolicyImportReport> {
    validate_import_plan(plan)?;
    if plan.host != transport.kibana_url() || plan.space != transport.space() {
        return Err(Error::new(
            ErrorKind::Conflict,
            "integration import target changed since preview",
        ));
    }
    let mut succeeded = Vec::new();
    let mut unchanged = Vec::new();
    let mut failed = Vec::new();
    let mut expected_groups = plan.package_groups.clone();
    let mut expected_parents = plan.parent_snapshots.clone();
    let mut blocked_packages = BTreeMap::<String, String>::new();
    let mut affected_parents = BTreeMap::<String, u64>::new();
    let mut observed_installs = BTreeSet::new();

    for target in &plan.targets {
        let package_name = &target.effective.package.name;
        if let Some(error) = blocked_packages.get(package_name) {
            failed.push(import_failed_row(
                &target.effective.id,
                false,
                format!("package dependency is unavailable: {error}"),
            ));
            continue;
        }

        let action = match recheck_import_object(transport, target).await {
            Ok(action) => action,
            Err(error) => {
                failed.push(import_failed_row(
                    &target.effective.id,
                    false,
                    error.message,
                ));
                continue;
            }
        };
        if let Err(error) = recheck_import_name_owner(transport, target, &plan.name_owners).await {
            failed.push(import_failed_row(
                &target.effective.id,
                false,
                error.message,
            ));
            continue;
        }
        if let Err(error) = recheck_import_parents(transport, target, &expected_parents).await {
            failed.push(import_failed_row(
                &target.effective.id,
                false,
                error.message,
            ));
            continue;
        }

        let group = expected_groups
            .get_mut(package_name)
            .expect("validated target package group");
        let actual_state = match read_dependencies(transport, &target.effective.package).await {
            Ok(state) if state == group.state => state,
            Ok(_) => {
                let message = "package changed since preview".to_owned();
                blocked_packages.insert(package_name.clone(), message.clone());
                failed.push(import_failed_row(&target.effective.id, false, message));
                continue;
            }
            Err(error) => {
                let message = import_remote_error(error, "apply package read").message;
                blocked_packages.insert(package_name.clone(), message.clone());
                failed.push(import_failed_row(&target.effective.id, false, message));
                continue;
            }
        };
        debug_assert_eq!(actual_state, group.state);

        if action == ImportAction::Unchanged {
            unchanged.push(json!({"id": target.effective.id}));
            continue;
        }

        let (label, applied, route_error) = match action {
            ImportAction::Create => {
                match integration_policies::create(transport, &target.effective).await {
                    Ok(_) => ("created", true, None),
                    Err(error) => (
                        "created",
                        false,
                        Some(import_remote_error(error, "create request").message),
                    ),
                }
            }
            ImportAction::Replace => {
                let _body = target
                    .replacement_body
                    .as_ref()
                    .expect("validated replacement body");
                match integration_policies::update(
                    transport,
                    &target.effective.id,
                    &target.effective,
                )
                .await
                {
                    Ok(_) => ("replaced", true, None),
                    Err(error) => (
                        "replaced",
                        false,
                        Some(import_remote_error(error, "update request").message),
                    ),
                }
            }
            ImportAction::Unchanged => unreachable!("unchanged rows continue above"),
        };

        if applied {
            record_affected_parents(&mut affected_parents, target);
            advance_parent_snapshots(&mut expected_parents, target);
        }

        // A missing package is a shared dependency. Fleet's create path can
        // install it even when the policy write fails, so observation is
        // mandatory after every create attempt, not only decoded success.
        let mut observed_after_create = None;
        let mut package_observation_error = None;
        if action == ImportAction::Create
            && matches!(group.state.state, PackageDependencyState::NotInstalled)
        {
            match read_dependencies(transport, &target.effective.package).await {
                Ok(after) => {
                    if is_exact_installed(&after, &target.effective.package) {
                        group.state = after.clone();
                        observed_installs.insert(format!(
                            "{}@{}",
                            target.effective.package.name, target.effective.package.version
                        ));
                    } else if !matches!(after.state, PackageDependencyState::NotInstalled) {
                        let message =
                            "package installed a different version after create".to_owned();
                        blocked_packages.insert(package_name.clone(), message.clone());
                        package_observation_error = Some(message);
                    }
                    observed_after_create = Some(after);
                }
                Err(error) => {
                    let message = import_remote_error(error, "post-create package read").message;
                    blocked_packages.insert(package_name.clone(), message.clone());
                    package_observation_error = Some(message);
                }
            }
        }

        let mut errors = route_error.into_iter().collect::<Vec<_>>();
        if applied {
            if let Err(error) = verify_import_stored(transport, &target.effective).await {
                errors.push(error.message);
            }
            let package_result = match observed_after_create.as_ref() {
                Some(after) => verify_exact_installed(after, &target.effective.package),
                None => match read_dependencies(transport, &target.effective.package).await {
                    Ok(after) => verify_exact_installed(&after, &target.effective.package),
                    Err(error) => Err(import_remote_error(error, "package verification").message),
                },
            };
            if let Err(message) = package_result {
                blocked_packages
                    .entry(package_name.clone())
                    .or_insert_with(|| message.clone());
                errors.push(message);
            }
        }
        if let Some(error) = package_observation_error
            && !errors.contains(&error)
        {
            errors.push(error);
        }

        if errors.is_empty() {
            succeeded.push(json!({"id": target.effective.id, "action": label}));
        } else {
            failed.push(import_failed_row(
                &target.effective.id,
                applied,
                errors.join("; "),
            ));
        }
    }

    Ok(IntegrationPolicyImportReport {
        applied: true,
        succeeded,
        unchanged,
        skipped: plan.skipped.clone(),
        failed,
        total: plan.total,
        affected_agents: affected_parents.values().sum(),
        package_installs: observed_installs.into_iter().collect(),
    })
}

async fn recheck_import_object(
    transport: &Transport,
    target: &IntegrationPolicyImportTarget,
) -> Result<ImportAction> {
    match &target.current {
        None => match integration_policies::get(transport, &target.effective.id).await {
            Err(error) if error.kind == ErrorKind::NotFound => Ok(ImportAction::Create),
            Ok(_) => Err(Error::new(
                ErrorKind::Conflict,
                "integration policy appeared since preview",
            )),
            Err(error) => Err(import_remote_error(error, "apply integration-policy read")),
        },
        Some(expected) => match integration_policies::get(transport, &target.effective.id).await {
            Ok(actual) if actual.item == expected.item => {
                if expected.spec == target.effective {
                    Ok(ImportAction::Unchanged)
                } else {
                    Ok(ImportAction::Replace)
                }
            }
            Ok(_) => Err(Error::new(
                ErrorKind::Conflict,
                "integration policy changed since preview",
            )),
            Err(error) if error.kind == ErrorKind::NotFound => Err(Error::new(
                ErrorKind::Conflict,
                "integration policy disappeared since preview",
            )),
            Err(error) => Err(import_remote_error(error, "apply integration-policy read")),
        },
    }
}

async fn recheck_import_name_owner(
    transport: &Transport,
    target: &IntegrationPolicyImportTarget,
    expected_owners: &BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    let names = BTreeSet::from([target.effective.name.clone()]);
    let owners = relevant_name_owners(transport, &names)
        .await
        .map_err(|error| import_remote_error(error, "apply name read"))?;
    if owners.get(&target.effective.name) == expected_owners.get(&target.effective.name) {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Conflict,
            "integration policy name ownership changed since preview",
        ))
    }
}

async fn recheck_import_parents(
    transport: &Transport,
    target: &IntegrationPolicyImportTarget,
    expected_parents: &BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
) -> Result<()> {
    for parent_id in target.parents.keys() {
        let expected = expected_parents.get(parent_id).ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                "integration import lost a shared parent snapshot",
            )
        })?;
        let actual = agent_policy_ops::read_parent_snapshot(transport, parent_id)
            .await
            .map_err(|error| import_remote_error(error, "apply parent read"))?;
        if actual != *expected {
            return Err(Error::new(
                ErrorKind::Conflict,
                "integration policy parent changed since preview",
            ));
        }
    }
    Ok(())
}

fn record_affected_parents(
    affected: &mut BTreeMap<String, u64>,
    target: &IntegrationPolicyImportTarget,
) {
    for parent in target.parents.values() {
        affected.entry(parent.id.clone()).or_insert(parent.agents);
    }
}

fn advance_parent_snapshots(
    parents: &mut BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
    target: &IntegrationPolicyImportTarget,
) {
    let desired = target
        .effective
        .policy_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for parent_id in target.parents.keys() {
        let parent = parents
            .get_mut(parent_id)
            .expect("validated shared parent snapshot");
        if desired.contains(parent_id.as_str()) {
            if parent
                .attached_integrations
                .binary_search_by(|attached| attached.as_str().cmp(&target.effective.id))
                .is_err()
            {
                parent
                    .attached_integrations
                    .push(target.effective.id.clone());
                parent.attached_integrations.sort();
            }
        } else {
            parent
                .attached_integrations
                .retain(|attached| attached != &target.effective.id);
        }
    }
}

async fn verify_import_stored(
    transport: &Transport,
    desired: &IntegrationPolicySpec,
) -> Result<()> {
    let stored = integration_policies::get(transport, &desired.id)
        .await
        .map_err(|error| import_remote_error(error, "stored-policy read"))?;
    let stored = normalize(&stored.item, transport.space())
        .map_err(|error| import_remote_error(error, "stored-policy read"))?;
    if stored == *desired {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Http,
            "server stored a different integration-policy spec",
        ))
    }
}

fn is_exact_installed(
    snapshot: &PackageDependencySnapshot,
    package: &IntegrationPackageSpec,
) -> bool {
    snapshot.name == package.name
        && matches!(
            &snapshot.state,
            PackageDependencyState::Installed { version } if version == &package.version
        )
}

fn verify_exact_installed(
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

fn import_remote_error(error: Error, context: &str) -> Error {
    let message = format!("integration-policy import {context} failed");
    match error.http_status {
        Some(status) => Error::with_status(error.kind, status, message),
        None => Error::new(error.kind, message),
    }
}

fn import_failed_row(id: &str, applied: bool, error: impl Into<String>) -> Value {
    json!({"id": id, "applied": applied, "error": error.into()})
}

fn validate_import_plan(plan: &IntegrationPolicyImportPlan) -> Result<()> {
    let invalid = |message: &str| {
        Err(Error::new(
            ErrorKind::Error,
            format!("invalid integration-policy import plan: {message}"),
        ))
    };
    if plan.overwrite && plan.skip_existing {
        return invalid("overwrite and skip-existing cannot both be set");
    }
    if plan.host.trim().is_empty() {
        return invalid("planned Kibana host is empty");
    }
    if plan.canonical.is_empty() || plan.total != plan.canonical.len() {
        return invalid("total does not equal canonical integration policies");
    }
    let mut canonical_ids = BTreeMap::new();
    let mut canonical_names = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for spec in &plan.canonical {
        if spec.validate().is_err() {
            return invalid("canonical integration policy is invalid");
        }
        if previous.is_some_and(|previous| previous >= spec.id.as_str()) {
            return invalid("canonical integration policies must be unique and sorted by id");
        }
        if !canonical_names.insert(spec.name.as_str()) {
            return invalid("canonical integration-policy names must be unique");
        }
        previous = Some(&spec.id);
        canonical_ids.insert(spec.id.as_str(), spec);
    }
    if validate_requested_package_versions(&plan.canonical).is_err() {
        return invalid("canonical package requests are inconsistent");
    }
    let canonical_id_set = canonical_ids.keys().copied().collect::<BTreeSet<_>>();
    if plan
        .existing_snapshot
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != canonical_id_set
    {
        return invalid("existence snapshots do not match canonical integration policies");
    }
    for (id, existing) in &plan.existing_snapshot {
        if let Some(item) = existing
            && required_string(item, "id", "existing integration policy")
                .ok()
                .as_deref()
                != Some(id.as_str())
        {
            return invalid("existence snapshot has an unexpected id");
        }
    }
    if plan.name_owners != plan.name_owners_snapshot {
        return invalid("name ownership snapshots do not match");
    }
    if plan
        .name_owners
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != canonical_names
    {
        return invalid("name ownership snapshots do not match canonical names");
    }
    for spec in &plan.canonical {
        let Some(owners) = plan.name_owners.get(&spec.name) else {
            return invalid("canonical name has no ownership snapshot");
        };
        if owners
            .iter()
            .any(|owner| owner.trim().is_empty() || owner != &spec.id)
        {
            return invalid("name ownership snapshot has a foreign or malformed owner");
        }
    }

    let mut target_ids = BTreeSet::new();
    let mut expected_bodies = BTreeMap::new();
    let mut expected_group_names = BTreeSet::new();
    let mut shared_parents = BTreeMap::new();
    let mut previous_target: Option<&str> = None;
    for target in &plan.targets {
        if target.effective.validate().is_err() {
            return invalid("effective integration policy is invalid");
        }
        if previous_target.is_some_and(|previous| previous >= target.effective.id.as_str()) {
            return invalid("pending integration policies must be unique and sorted by id");
        }
        previous_target = Some(&target.effective.id);
        let Some(canonical) = canonical_ids.get(target.effective.id.as_str()) else {
            return invalid("pending policy is not in the canonical artifact");
        };
        if !target_ids.insert(target.effective.id.as_str()) {
            return invalid("pending integration policies must be unique and sorted by id");
        }
        let exact_current = match (
            &target.current,
            plan.existing_snapshot.get(&target.effective.id),
        ) {
            (None, Some(None)) => true,
            (Some(current), Some(Some(item))) => current.item == *item,
            _ => false,
        };
        if !exact_current {
            return invalid("target does not match its plan-time existence snapshot");
        }
        let current_parent_ids = match &target.current {
            None => Vec::new(),
            Some(current) => {
                if current.spec.validate().is_err()
                    || current.spec.id != target.effective.id
                    || normalize(&current.item, &plan.space).ok().as_ref() != Some(&current.spec)
                {
                    return invalid("current integration snapshot does not normalize canonically");
                }
                let parent_ids = match read_parents(&target.effective.id, &current.item) {
                    Ok(parent_ids) if parent_ids == current.parent_ids => parent_ids,
                    _ => {
                        return invalid(
                            "current integration parent snapshot does not match its item",
                        );
                    }
                };
                if package_coordinate(&current.item, "integration policy").ok()
                    != Some(target.effective.package.clone())
                {
                    return invalid("current and desired package coordinates differ");
                }
                parent_ids
            }
        };
        if target.current.is_some() && !plan.overwrite {
            return invalid("existing integration target requires overwrite");
        }
        if !target_name_owners_match(target, &plan.name_owners) {
            return invalid("name ownership snapshot does not match target state");
        }
        let expected_parent_ids = current_parent_ids
            .iter()
            .chain(&target.effective.policy_ids)
            .cloned()
            .collect::<BTreeSet<_>>();
        if target.parents.keys().cloned().collect::<BTreeSet<_>>() != expected_parent_ids {
            return invalid("parent snapshots do not match current and desired parents");
        }
        for (parent_id, parent) in &target.parents {
            if !valid_parent_snapshot(parent_id, parent)
                || parent.platform_owned
                || parent.protected
            {
                return invalid("parent snapshot is unsafe or malformed");
            }
            if current_parent_ids.binary_search(parent_id).is_ok()
                && parent
                    .attached_integrations
                    .binary_search_by(|attached| attached.as_str().cmp(&target.effective.id))
                    .is_err()
            {
                return invalid("current parent snapshot is missing its integration attachment");
            }
            match shared_parents.entry(parent_id.as_str()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(parent);
                }
                std::collections::btree_map::Entry::Occupied(entry) if *entry.get() != parent => {
                    return invalid("shared parent snapshots disagree");
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
        if effective_import_spec(canonical, &target.parents)
            .ok()
            .as_ref()
            != Some(&target.effective)
        {
            return invalid("effective integration policy does not match canonical parents");
        }
        if let Some(current) = &target.current {
            if current.spec != target.effective {
                if !plan.overwrite {
                    return invalid("replacement plan requires overwrite");
                }
                let body = match replace_wire_body(&target.effective) {
                    Ok(body) => body,
                    Err(_) => return invalid("replacement body cannot be encoded"),
                };
                if target.replacement_body.as_ref() != Some(&body) {
                    return invalid("replacement body does not match its effective policy");
                }
                expected_bodies.insert(target.effective.id.as_str(), body);
            } else if target.replacement_body.is_some() {
                return invalid("unchanged integration policy carries a replacement body");
            }
        } else if target.replacement_body.is_some() {
            return invalid("planned create carries a replacement body");
        }
        expected_group_names.insert(target.effective.package.name.as_str());
    }

    if plan
        .package_groups
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_group_names
    {
        return invalid("package groups do not match pending integration policies");
    }
    let expected_parent_snapshots: BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot> =
        shared_parents
            .iter()
            .map(|(id, parent)| ((*id).to_owned(), (*parent).clone()))
            .collect();
    if plan.parent_snapshots != expected_parent_snapshots {
        return invalid("shared parent snapshots do not match pending integrations");
    }
    for (name, group) in &plan.package_groups {
        if group.package.name != *name
            || group.package.name.trim().is_empty()
            || group.package.version.trim().is_empty()
            || group.state != group.state_snapshot
            || group.metadata != group.metadata_snapshot
            || group.state.name != group.package.name
            || !valid_package_state(&group.state)
            || validate_package_metadata_snapshot(&group.metadata, &group.package).is_err()
        {
            return invalid("package group snapshot is malformed or tampered");
        }
        if !is_exact_installed(&group.state, &group.package)
            && !matches!(group.state.state, PackageDependencyState::NotInstalled)
        {
            return invalid("package group does not hold an exact dependency state");
        }
        if matches!(group.state.state, PackageDependencyState::NotInstalled)
            && plan
                .targets
                .iter()
                .any(|target| target.effective.package.name == *name && target.current.is_some())
        {
            return invalid("existing integration cannot depend on an absent package");
        }
    }
    for target in &plan.targets {
        let Some(group) = plan.package_groups.get(&target.effective.package.name) else {
            return invalid("target has no package group");
        };
        if group.package != target.effective.package {
            return invalid("package group coordinate does not match its target");
        }
        match configured_secret_paths(&target.effective, &group.metadata) {
            Ok(paths) if paths.is_empty() => {}
            _ => return invalid("effective integration policy has unsafe configured variables"),
        }
        if let Some(current) = &target.current {
            match configured_secret_paths(&current.spec, &group.metadata) {
                Ok(paths) if paths.is_empty() => {}
                _ => {
                    return invalid("current integration policy has unsafe configured variables");
                }
            }
        }
    }
    if expected_bodies.len()
        != plan
            .targets
            .iter()
            .filter(|target| target.replacement_body.is_some())
            .count()
    {
        return invalid("replacement body set does not match changed integration policies");
    }

    let expected_skipped_ids = plan
        .canonical
        .iter()
        .filter(|spec| {
            plan.skip_existing && matches!(plan.existing_snapshot.get(&spec.id), Some(Some(_)))
        })
        .map(|spec| spec.id.as_str())
        .collect::<BTreeSet<_>>();
    let expected_target_ids = canonical_id_set
        .iter()
        .copied()
        .filter(|id| !expected_skipped_ids.contains(id))
        .collect::<BTreeSet<_>>();
    if target_ids != expected_target_ids {
        return invalid("pending integration policies do not match plan-time existence snapshots");
    }
    let expected_skipped = plan
        .canonical
        .iter()
        .filter(|spec| expected_skipped_ids.contains(spec.id.as_str()))
        .map(|spec| json!({"id": spec.id, "reason": "exists"}))
        .collect::<Vec<_>>();
    if plan.skipped != plan.skipped_snapshot {
        return invalid("skipped rows do not match their snapshot");
    }
    if (!plan.skip_existing && !plan.skipped.is_empty()) || plan.skipped != expected_skipped {
        return invalid("skipped rows do not match the canonical artifact");
    }
    let expected_installs = planned_package_installs(&plan.package_groups);
    if plan.package_installs != expected_installs {
        return invalid("package install preview does not match package groups");
    }
    let expected_preview = import_preview(&plan.source, &plan.targets, &plan.package_installs);
    if plan.preview != expected_preview {
        return invalid("preview does not match the canonical plan");
    }
    Ok(())
}

fn valid_parent_snapshot(id: &str, parent: &agent_policy_ops::AgentPolicyParentSnapshot) -> bool {
    parent.id == id
        && !parent.id.trim().is_empty()
        && !parent.name.trim().is_empty()
        && !parent.namespace.trim().is_empty()
        && parent
            .attached_integrations
            .windows(2)
            .all(|ids| ids[0] < ids[1])
}

fn valid_package_state(snapshot: &PackageDependencySnapshot) -> bool {
    if snapshot.name.trim().is_empty() {
        return false;
    }
    match &snapshot.state {
        PackageDependencyState::Installed { version } => !version.trim().is_empty(),
        PackageDependencyState::NotInstalled => true,
    }
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

/// Recheck the exact planning snapshots, then delete each independent target.
/// An acknowledged wrong-id response is deliberately not treated as a clean
/// deletion, and never advances shared parent expectations.
pub async fn apply_delete(
    transport: &Transport,
    plan: &IntegrationPolicyDeletePlan,
) -> Result<IntegrationPolicyDeleteReport> {
    validate_delete_plan(plan)?;
    if plan.host != transport.kibana_url() || plan.space != transport.space() {
        return Err(Error::new(
            ErrorKind::Conflict,
            "integration delete target changed since preview",
        ));
    }

    let mut expected_parents = plan.parent_snapshots.clone();
    let mut affected = BTreeMap::new();
    let mut deleted = Vec::new();
    let mut failed = Vec::new();

    for target in &plan.targets {
        match integration_policies::get(transport, &target.id).await {
            Ok(actual) if actual.item == target.item => {}
            Ok(_) => {
                failed.push(delete_failed_row(
                    &target.id,
                    false,
                    "integration policy changed since preview",
                ));
                continue;
            }
            Err(error) if error.kind == ErrorKind::NotFound => {
                failed.push(delete_failed_row(
                    &target.id,
                    false,
                    "integration policy disappeared since preview",
                ));
                continue;
            }
            Err(error) => {
                failed.push(delete_failed_row(
                    &target.id,
                    false,
                    delete_remote_error(error, "apply integration-policy read").message,
                ));
                continue;
            }
        }

        if let Err(error) = recheck_delete_parents(transport, target, &expected_parents).await {
            failed.push(delete_failed_row(&target.id, false, error.message));
            continue;
        }
        match read_dependencies(transport, &target.package).await {
            Ok(actual) if actual == target.dependency => {}
            Ok(_) => {
                failed.push(delete_failed_row(
                    &target.id,
                    false,
                    "integration policy package changed since preview",
                ));
                continue;
            }
            Err(error) => {
                failed.push(delete_failed_row(
                    &target.id,
                    false,
                    delete_remote_error(error, "apply package read").message,
                ));
                continue;
            }
        }

        match integration_policies::delete(transport, &target.id).await {
            Ok(()) => {
                record_delete_affected_parents(&mut affected, target, &expected_parents);
                advance_delete_parent_snapshots(&mut expected_parents, target);
                deleted.push(json!({"id": target.id}));
            }
            Err(error) => {
                let applied = error
                    .http_status
                    .is_some_and(|status| (200..300).contains(&status));
                let message = if applied {
                    "integration-policy delete response did not confirm the requested id"
                } else {
                    "integration-policy delete request failed"
                };
                failed.push(delete_failed_row(&target.id, applied, message));
            }
        }
    }

    Ok(IntegrationPolicyDeleteReport {
        applied: true,
        deleted,
        failed,
        total: plan.total,
        affected_agents: affected.values().sum(),
    })
}

async fn recheck_delete_parents(
    transport: &Transport,
    target: &IntegrationPolicyDeleteTarget,
    expected_parents: &BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
) -> Result<()> {
    for parent_id in target.parents.keys() {
        let expected = expected_parents.get(parent_id).ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                "integration delete lost a shared parent snapshot",
            )
        })?;
        match agent_policy_ops::read_parent_snapshot(transport, parent_id).await {
            Ok(actual) if actual == *expected => {}
            Ok(_) => {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "integration policy parent changed since preview",
                ));
            }
            Err(error) if error.kind == ErrorKind::NotFound => {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    "integration policy parent disappeared since preview",
                ));
            }
            Err(error) => return Err(delete_remote_error(error, "apply parent read")),
        }
    }
    Ok(())
}

fn record_delete_affected_parents(
    affected: &mut BTreeMap<String, u64>,
    target: &IntegrationPolicyDeleteTarget,
    expected_parents: &BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
) {
    for parent_id in target.parents.keys() {
        let parent = expected_parents
            .get(parent_id)
            .expect("validated delete target parent exists in shared snapshots");
        affected.entry(parent.id.clone()).or_insert(parent.agents);
    }
}

fn advance_delete_parent_snapshots(
    parents: &mut BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
    target: &IntegrationPolicyDeleteTarget,
) {
    for parent_id in target.parents.keys() {
        let parent = parents
            .get_mut(parent_id)
            .expect("validated delete target parent exists in shared snapshots");
        parent
            .attached_integrations
            .retain(|attached| attached != &target.id);
    }
}

fn delete_failed_row(id: &str, applied: bool, error: impl Into<String>) -> Value {
    json!({"id": id, "applied": applied, "error": error.into()})
}

fn delete_remote_error(error: Error, context: &str) -> Error {
    let message = format!("integration-policy delete {context} failed");
    match error.http_status {
        Some(status) => Error::with_status(error.kind, status, message),
        None => Error::new(error.kind, message),
    }
}

fn validate_delete_plan(plan: &IntegrationPolicyDeletePlan) -> Result<()> {
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

fn http(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Http, message)
}

fn unsupported<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::new(ErrorKind::Unsupported, message))
}

#[cfg(test)]
mod import_plan_tests {
    use super::*;

    fn valid_plan() -> IntegrationPolicyImportPlan {
        let effective = IntegrationPolicySpec::try_from(json!({
            "id": "fresh",
            "name": "Fresh integration",
            "namespace": "default",
            "policy_ids": ["parent-1"],
            "package": {"name": "system", "version": "2.0.0"},
            "inputs": {}
        }))
        .expect("valid test policy");
        let parent = agent_policy_ops::AgentPolicyParentSnapshot {
            id: "parent-1".into(),
            name: "Parent 1".into(),
            namespace: "default".into(),
            agents: 0,
            attached_integrations: Vec::new(),
            platform_owned: false,
            protected: false,
        };
        let targets = vec![IntegrationPolicyImportTarget {
            effective: effective.clone(),
            current: None,
            parents: BTreeMap::from([(parent.id.clone(), parent)]),
            replacement_body: None,
        }];
        let parent_snapshots = targets[0].parents.clone();
        let state = PackageDependencySnapshot {
            name: "system".into(),
            state: PackageDependencyState::NotInstalled,
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
        let package_groups = BTreeMap::from([(
            "system".into(),
            IntegrationPackageGroup {
                package: effective.package.clone(),
                state: state.clone(),
                state_snapshot: state,
                metadata_snapshot: metadata.clone(),
                metadata,
            },
        )]);
        let package_installs = vec!["system@2.0.0".into()];
        let source = PathBuf::from("fresh.json");
        let preview = import_preview(&source, &targets, &package_installs);
        IntegrationPolicyImportPlan {
            preview,
            skipped: Vec::new(),
            package_installs,
            total: 1,
            source,
            host: "https://fleet.example.invalid".into(),
            space: "default".into(),
            canonical: vec![effective.clone()],
            name_owners: BTreeMap::from([(effective.name.clone(), BTreeSet::new())]),
            name_owners_snapshot: BTreeMap::from([(effective.name.clone(), BTreeSet::new())]),
            parent_snapshots,
            skipped_snapshot: Vec::new(),
            existing_snapshot: BTreeMap::from([("fresh".into(), None)]),
            targets,
            package_groups,
            overwrite: false,
            skip_existing: false,
        }
    }

    fn existing_plan_without_overwrite() -> IntegrationPolicyImportPlan {
        let mut plan = valid_plan();
        let existing = {
            let target = plan.targets.first_mut().expect("fresh target");
            let mut item = serde_json::to_value(&target.effective)
                .expect("serialize current item")
                .as_object()
                .expect("current item object")
                .clone();
            item.insert("enabled".into(), Value::Bool(true));
            target.current = Some(IntegrationPolicyCurrentSnapshot {
                item: item.clone(),
                spec: target.effective.clone(),
                parent_ids: target.effective.policy_ids.clone(),
            });
            target
                .parents
                .get_mut("parent-1")
                .expect("parent")
                .attached_integrations
                .push(target.effective.id.clone());
            item
        };
        plan.existing_snapshot
            .insert("fresh".into(), Some(existing));

        let state = PackageDependencySnapshot {
            name: "system".into(),
            state: PackageDependencyState::Installed {
                version: "2.0.0".into(),
            },
        };
        let group = plan
            .package_groups
            .get_mut("system")
            .expect("package group");
        group.state = state.clone();
        group.state_snapshot = state;
        plan.package_installs.clear();
        plan.name_owners
            .get_mut("Fresh integration")
            .expect("name owner snapshot")
            .insert("fresh".into());
        plan.name_owners_snapshot = plan.name_owners.clone();
        plan.parent_snapshots = plan.targets[0].parents.clone();
        plan.preview = import_preview(&plan.source, &plan.targets, &plan.package_installs);
        plan
    }

    fn valid_skip_existing_plan() -> IntegrationPolicyImportPlan {
        let mut plan = existing_plan_without_overwrite();
        plan.skip_existing = true;
        plan.targets.clear();
        plan.parent_snapshots.clear();
        plan.package_groups.clear();
        plan.skipped = vec![json!({"id": "fresh", "reason": "exists"})];
        plan.skipped_snapshot = plan.skipped.clone();
        plan.package_installs.clear();
        plan.preview = import_preview(&plan.source, &plan.targets, &plan.package_installs);
        plan
    }

    fn valid_replace_plan() -> IntegrationPolicyImportPlan {
        let mut plan = existing_plan_without_overwrite();
        plan.overwrite = true;
        let desired = {
            let target = plan.targets.first_mut().expect("existing target");
            let mut desired = target.effective.clone();
            desired.description = Some("changed".into());
            target.effective = desired.clone();
            target.replacement_body = Some(replace_wire_body(&desired).expect("replace body"));
            desired
        };
        plan.canonical = vec![desired];
        plan.preview = import_preview(&plan.source, &plan.targets, &plan.package_installs);
        plan
    }

    #[test]
    fn import_plan_rejects_a_private_create_name_owner_tamper() {
        let mut plan = valid_plan();
        plan.name_owners
            .get_mut("Fresh integration")
            .expect("name owner snapshot")
            .insert("fresh".into());

        assert!(validate_import_plan(&plan).is_err());
    }

    #[test]
    fn import_plan_rejects_an_existing_target_without_overwrite() {
        let plan = existing_plan_without_overwrite();

        assert!(validate_import_plan(&plan).is_err());
    }

    #[test]
    fn import_plan_rejects_private_snapshot_body_group_and_order_tampering() {
        let replace = valid_replace_plan();
        assert!(validate_import_plan(&replace).is_ok());

        let mut tampered_body = replace.clone();
        tampered_body.targets[0].replacement_body = Some(json!({"tampered": true}));
        assert!(validate_import_plan(&tampered_body).is_err());

        let mut tampered_current = replace.clone();
        tampered_current.targets[0]
            .current
            .as_mut()
            .expect("current snapshot")
            .item
            .insert("enabled".into(), Value::Bool(false));
        assert!(validate_import_plan(&tampered_current).is_err());

        let mut tampered_group = valid_plan();
        tampered_group
            .package_groups
            .get_mut("system")
            .expect("package group")
            .metadata
            .insert("version".into(), Value::String("9.9.9".into()));
        assert!(validate_import_plan(&tampered_group).is_err());

        let mut tampered_order = valid_plan();
        tampered_order
            .targets
            .push(tampered_order.targets[0].clone());
        assert!(validate_import_plan(&tampered_order).is_err());

        let mut tampered_group_key = valid_plan();
        let group = tampered_group_key
            .package_groups
            .remove("system")
            .expect("package group");
        tampered_group_key
            .package_groups
            .insert("other".into(), group);
        assert!(validate_import_plan(&tampered_group_key).is_err());

        let mut tampered_state = valid_plan();
        tampered_state
            .package_groups
            .get_mut("system")
            .expect("package group")
            .state = PackageDependencySnapshot {
            name: "system".into(),
            state: PackageDependencyState::Installed {
                version: "2.0.0".into(),
            },
        };
        assert!(validate_import_plan(&tampered_state).is_err());

        let mut tampered_coordinate = valid_replace_plan();
        tampered_coordinate.canonical[0].package.version = "3.0.0".into();
        tampered_coordinate.targets[0].effective.package.version = "3.0.0".into();
        tampered_coordinate.targets[0].replacement_body = Some(
            replace_wire_body(&tampered_coordinate.targets[0].effective).expect("replace body"),
        );
        let group = tampered_coordinate
            .package_groups
            .get_mut("system")
            .expect("package group");
        group.package.version = "3.0.0".into();
        group.state = PackageDependencySnapshot {
            name: "system".into(),
            state: PackageDependencyState::Installed {
                version: "3.0.0".into(),
            },
        };
        group.state_snapshot = group.state.clone();
        group.metadata.insert("version".into(), json!("3.0.0"));
        group.metadata_snapshot = group.metadata.clone();
        tampered_coordinate.preview = import_preview(
            &tampered_coordinate.source,
            &tampered_coordinate.targets,
            &tampered_coordinate.package_installs,
        );
        assert!(validate_import_plan(&tampered_coordinate).is_err());
    }

    #[test]
    fn import_plan_rejects_a_private_parent_snapshot_tamper_even_with_preview_rebuilt() {
        let mut plan = valid_plan();
        plan.targets[0]
            .parents
            .get_mut("parent-1")
            .expect("parent snapshot")
            .agents = 42;
        plan.preview = import_preview(&plan.source, &plan.targets, &plan.package_installs);

        assert!(validate_import_plan(&plan).is_err());
    }

    #[test]
    fn import_plan_rejects_target_removal_rebuilt_as_a_skipped_row() {
        let mut plan = valid_plan();
        plan.skip_existing = true;
        plan.targets.clear();
        plan.parent_snapshots.clear();
        plan.package_groups.clear();
        plan.skipped = vec![json!({"id": "fresh", "reason": "exists"})];
        plan.skipped_snapshot = plan.skipped.clone();
        plan.package_installs.clear();
        plan.preview = import_preview(&plan.source, &plan.targets, &plan.package_installs);

        assert!(validate_import_plan(&plan).is_err());
    }

    #[test]
    fn import_plan_accepts_a_coherent_skip_existing_snapshot() {
        assert!(validate_import_plan(&valid_skip_existing_plan()).is_ok());
    }

    #[test]
    fn import_plan_rejects_existence_snapshot_key_and_target_mismatches() {
        let mut missing_current = valid_replace_plan();
        missing_current
            .existing_snapshot
            .insert("fresh".into(), None);
        assert!(validate_import_plan(&missing_current).is_err());

        let mut changed_current = valid_replace_plan();
        changed_current
            .existing_snapshot
            .get_mut("fresh")
            .expect("existing snapshot")
            .as_mut()
            .expect("existing item")
            .insert("description".into(), json!("tampered"));
        assert!(validate_import_plan(&changed_current).is_err());

        let mut extra_snapshot = valid_plan();
        extra_snapshot
            .existing_snapshot
            .insert("other".into(), None);
        assert!(validate_import_plan(&extra_snapshot).is_err());
    }

    #[test]
    fn import_plan_rejects_public_field_tampering_against_private_snapshots() {
        let plan = valid_plan();

        let mut total = plan.clone();
        total.total = 2;
        assert!(validate_import_plan(&total).is_err());

        let mut preview = plan.clone();
        preview.preview.preview_action = "tampered".into();
        assert!(validate_import_plan(&preview).is_err());

        let mut skipped = plan.clone();
        skipped.skipped = vec![json!({"id": "fresh", "reason": "exists"})];
        assert!(validate_import_plan(&skipped).is_err());

        let mut installs = plan;
        installs.package_installs.clear();
        assert!(validate_import_plan(&installs).is_err());
    }
}

#[cfg(test)]
mod delete_plan_tests {
    use super::*;

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
}
