//! Integration-policy selection, normalization, and local validation.

use crate::content_codec::{self, ContentFormat};
use crate::fleet::integration_policies::{
    self, IntegrationPackageSpec, IntegrationPolicySpec, IntegrationPolicySummary,
};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
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

const PORTABLE_OPTIONAL: [&str; 6] = [
    "description",
    "namespace",
    "vars",
    "var_group_selections",
    "condition",
    "additional_datastreams_permissions",
];

const REMOVED_FIELDS: [&str; 17] = [
    "agents",
    "cloud_connector_id",
    "cloud_connector_name",
    "created_at",
    "created_by",
    "enabled",
    "is_managed",
    "output_id",
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
    for (field, expected) in [
        ("title", "a string"),
        ("package_agent_version_condition", "a string"),
    ] {
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
        "package_agent_version_condition",
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
/// without Fleet-generated ids, compiled content, or ES privilege facts.
fn normalize_package_map(value: &Value, compiled_field: &str) -> Result<Value> {
    let object = value
        .as_object()
        .ok_or_else(|| http("decoding integration policy: input must be an object"))?;
    let mut normalized = Map::new();
    for (field, value) in object {
        if matches!(field.as_str(), "id" | "elasticsearch") || field == compiled_field {
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
                    "decoding integration policy '{id}': {field} must be a string, false, or null"
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
    if let Some(policy_id) = item.get("policy_id") {
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

fn unsupported(message: impl Into<String>) -> Result<()> {
    Err(Error::new(ErrorKind::Unsupported, message))
}
