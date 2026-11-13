use super::common::*;
use super::metadata::configured_secret_paths;
use super::normalization::normalize;

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

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ResolvedIntegrationPolicy {
    pub(crate) summary: IntegrationPolicySummary,
    pub(crate) item: Map<String, Value>,
}

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

pub async fn resolve(transport: &Transport, selector: &str) -> Result<IntegrationPolicySummary> {
    Ok(resolve_item(transport, selector).await?.summary)
}

pub(crate) async fn resolve_item(
    transport: &Transport,
    selector: &str,
) -> Result<ResolvedIntegrationPolicy> {
    match integration_policies::get_selector(transport, selector).await {
        Ok(policy) => return checked_read(selector, policy.item, None),
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
            checked_read(&one.id, policy.item, Some(one))
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

fn checked_read(
    requested_id: &str,
    item: Map<String, Value>,
    selected: Option<&IntegrationPolicySummary>,
) -> Result<ResolvedIntegrationPolicy> {
    let summary = summary_from_item(&item)?;
    if summary.id != requested_id {
        return Err(http(
            "decoding integration policy selector read: response id did not match the selector",
        ));
    }
    if selected.is_some_and(|selected| !same_summary(&summary, selected)) {
        return Err(http(
            "decoding integration policy selector read: fetched item did not match the selected list summary",
        ));
    }
    Ok(ResolvedIntegrationPolicy { summary, item })
}

fn same_summary(fetched: &IntegrationPolicySummary, selected: &IntegrationPolicySummary) -> bool {
    fetched.id == selected.id
        && fetched.name == selected.name
        && fetched.namespace == selected.namespace
        && fetched.description == selected.description
        && fetched.package == selected.package
        && sorted_parent_ids(&fetched.policy_ids) == sorted_parent_ids(&selected.policy_ids)
}

fn sorted_parent_ids(ids: &[String]) -> Vec<&str> {
    let mut sorted = ids.iter().map(String::as_str).collect::<Vec<_>>();
    sorted.sort_unstable();
    sorted
}

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
            let resolved = checked_read(&summary.id, live.item, Some(&summary))?;
            if optional_bool(&resolved.item, "is_managed", &summary.id)? == Some(true) {
                continue;
            }
            rows.insert(summary.id.clone(), resolved);
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
        if all_custom && parents.values().any(|parent| parent.platform_owned) {
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
