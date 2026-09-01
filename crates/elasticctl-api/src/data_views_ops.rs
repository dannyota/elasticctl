//! Data-view selection, portable normalization, and read orchestration.

use crate::content_codec::{self, ContentFormat};
use crate::data_views::{self, DataView, DataViewSpec, DataViewSummary, DataViewUpdate};
use crate::ops::{ExportOutcome, MutationPlan};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// A local, case-insensitive substring filter for data-view summaries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataViewFilter {
    pub search: Option<String>,
}

/// Data-view list output after local filtering and stable-id sorting.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DataViewList {
    pub total: usize,
    pub data_views: Vec<DataViewSummary>,
}

/// The two documented routes needed to replace a portable data view.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct DataViewPatch {
    pub base: Option<DataViewUpdate>,
    pub field_metadata: Map<String, Value>,
}

/// The immutable, guard-ready import work computed from one portable artifact.
#[derive(Debug, Clone, PartialEq)]
pub struct DataViewImportPlan {
    pub preview: MutationPlan,
    pub specs: Vec<DataViewSpec>,
    pub before: BTreeMap<String, Option<DataViewSpec>>,
    pub patches: BTreeMap<String, DataViewPatch>,
    pub skipped: Vec<Value>,
    pub total: usize,
    pub overwrite: bool,
}

/// The per-object result of applying a guarded data-view import.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DataViewImportReport {
    pub applied: bool,
    pub succeeded: Vec<Value>,
    pub skipped: Vec<Value>,
    pub failed: Vec<Value>,
    pub total: usize,
}

/// Select one entry by stable id or exact name without decoding unrelated
/// entries. Shared by data-view operations and the legacy search resolver.
pub(crate) fn select_by_id_or_name<'a, T>(
    entries: &'a [T],
    selector: &str,
    id: impl Fn(&T) -> Option<&str>,
    name: impl Fn(&T) -> Option<&str>,
) -> Result<&'a T> {
    if let Some(entry) = entries.iter().find(|entry| id(entry) == Some(selector)) {
        return Ok(entry);
    }

    let matches: Vec<&T> = entries
        .iter()
        .filter(|entry| name(entry) == Some(selector))
        .collect();
    match matches.as_slice() {
        [] => Err(Error::new(
            ErrorKind::NotFound,
            format!("no data view with id or name '{selector}'"),
        )),
        [entry] => Ok(entry),
        _ => Err(Error::new(
            ErrorKind::Conflict,
            format!("data view '{selector}' is ambiguous"),
        )),
    }
}

/// Resolve one selector from already-read data-view summaries.
///
/// Stable ids win over names. Names are a convenience selector and must be
/// unique when used.
pub fn resolve_from_summaries(
    views: &[DataViewSummary],
    selector: &str,
) -> Result<DataViewSummary> {
    Ok(select_by_id_or_name(
        views,
        selector,
        |view| Some(view.id.as_str()),
        |view| view.name.as_deref(),
    )?
    .clone())
}

/// Resolve one selector over the wire with one data-view list read.
pub async fn resolve(transport: &Transport, selector: &str) -> Result<DataViewSummary> {
    let views = data_views::list(transport).await?;
    resolve_from_summaries(&views, selector)
}

/// List data views using the portable command filter and stable-id ordering.
pub async fn list_op(transport: &Transport, filter: &DataViewFilter) -> Result<DataViewList> {
    let needle = filter.search.as_ref().map(|search| search.to_lowercase());
    let mut data_views: Vec<_> = data_views::list(transport)
        .await?
        .into_iter()
        .filter(|view| {
            needle.as_ref().is_none_or(|needle| {
                view.id.to_lowercase().contains(needle)
                    || view
                        .name
                        .as_ref()
                        .is_some_and(|name| name.to_lowercase().contains(needle))
                    || view.title.to_lowercase().contains(needle)
            })
        })
        .collect();
    data_views.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(DataViewList {
        total: data_views.len(),
        data_views,
    })
}

/// Resolve a selector, then read its full live data-view object.
pub async fn get_op(transport: &Transport, selector: &str) -> Result<DataView> {
    let view = resolve(transport, selector).await?;
    data_views::get(transport, &view.id).await
}

/// Convert a full live data-view object into its portable form.
pub fn normalize(data_view: &Value) -> Result<DataViewSpec> {
    let source = data_view
        .as_object()
        .ok_or_else(|| Error::new(ErrorKind::Http, "decoding data view: expected object"))?;
    let mut portable = Map::new();

    for key in ["id", "title"] {
        if let Some(value) = source.get(key) {
            portable.insert(key.to_string(), canonicalize(value));
        }
    }
    for key in [
        "name",
        "timeFieldName",
        "sourceFilters",
        "fieldFormats",
        "runtimeFieldMap",
        "fieldAttrs",
        "type",
    ] {
        if let Some(value) = source.get(key) {
            portable.insert(key.to_string(), canonicalize(value));
        }
    }
    for key in ["allowNoIndex", "allowHidden"] {
        portable.insert(
            key.to_string(),
            source
                .get(key)
                .map(canonicalize)
                .unwrap_or(Value::Bool(false)),
        );
    }
    if let Some(type_meta) = source.get("typeMeta")
        && !type_meta.is_null()
        && !matches!(type_meta, Value::Object(values) if values.is_empty())
    {
        portable.insert("typeMeta".to_string(), canonicalize(type_meta));
    }
    if let Some(fields) = source.get("fields") {
        let fields = match fields {
            Value::Object(fields) => Value::Object(
                fields
                    .iter()
                    .filter(|(_, field)| {
                        field.get("scripted").and_then(Value::as_bool) == Some(true)
                    })
                    .map(|(name, field)| (name.clone(), field.clone()))
                    .collect(),
            ),
            other => canonicalize(other),
        };
        portable.insert("fields".to_string(), canonicalize(&fields));
    }

    DataViewSpec::try_from(canonicalize(&Value::Object(portable))).map_err(|error| {
        Error::new(
            ErrorKind::Http,
            format!("decoding data view: {}", error.message),
        )
    })
}

/// Rebuild a JSON value with sorted object keys while preserving array order.
fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            Value::Object(
                keys.into_iter()
                    .map(|key| (key.clone(), canonicalize(&values[key])))
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

/// Fully read and validate a portable data-view artifact.
pub fn validate(path: &Path) -> Result<Vec<DataViewSpec>> {
    let body = std::fs::read_to_string(path).map_err(|error| {
        Error::new(
            ErrorKind::Error,
            format!("reading {}: {error}", path.display()),
        )
    })?;
    let mut specs = content_codec::decode_sequence::<DataViewSpec>(
        &body,
        ContentFormat::from_path(path),
        "data view",
    )?;

    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for spec in &specs {
        spec.validate()?;
        if !seen.insert(spec.id.as_str()) {
            duplicates.insert(spec.id.as_str());
        }
    }
    if !duplicates.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            format!(
                "duplicate data view ids: {}",
                duplicates.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    }

    specs.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(specs)
}

/// Build the exact documented replacement delta between canonical data views.
pub fn build_patch(current: &DataViewSpec, desired: &DataViewSpec) -> Result<DataViewPatch> {
    if current.id != desired.id {
        return unsupported("changing data view id is not supported by the data-view update API");
    }
    if current.allow_hidden != desired.allow_hidden {
        return unsupported("changing allowHidden is not supported by the data-view update API");
    }
    if current.name.is_some() && desired.name.is_none() {
        return unsupported("removing name is not supported by the data-view update API");
    }
    if current.time_field_name.is_some() && desired.time_field_name.is_none() {
        return unsupported("removing timeFieldName is not supported by the data-view update API");
    }
    if current.view_type.is_some() && desired.view_type.is_none() {
        return unsupported("removing type is not supported by the data-view update API");
    }
    if current.type_meta.is_some() && desired.type_meta.is_none() {
        return unsupported("removing typeMeta is not supported by the data-view update API");
    }

    let base = DataViewUpdate {
        allow_no_index: changed(&current.allow_no_index, &desired.allow_no_index)
            .then_some(desired.allow_no_index),
        field_formats: changed(&current.field_formats, &desired.field_formats)
            .then(|| desired.field_formats.clone()),
        fields: changed(&current.fields, &desired.fields).then(|| desired.fields.clone()),
        name: changed(&current.name, &desired.name)
            .then(|| desired.name.clone())
            .flatten(),
        runtime_field_map: changed(&current.runtime_field_map, &desired.runtime_field_map)
            .then(|| desired.runtime_field_map.clone()),
        source_filters: changed(&current.source_filters, &desired.source_filters)
            .then(|| desired.source_filters.clone()),
        time_field_name: changed(&current.time_field_name, &desired.time_field_name)
            .then(|| desired.time_field_name.clone())
            .flatten(),
        title: changed(&current.title, &desired.title).then(|| desired.title.clone()),
        view_type: changed(&current.view_type, &desired.view_type)
            .then(|| desired.view_type.clone())
            .flatten(),
        type_meta: changed(&current.type_meta, &desired.type_meta)
            .then(|| desired.type_meta.clone())
            .flatten(),
    };
    let base = (!is_empty_update(&base)).then_some(base);

    let mut field_metadata = Map::new();
    let names: BTreeSet<_> = current
        .field_attrs
        .keys()
        .chain(desired.field_attrs.keys())
        .collect();
    for name in names {
        let current_values = current.field_attrs.get(name).and_then(Value::as_object);
        let desired_values = desired.field_attrs.get(name).and_then(Value::as_object);
        let keys: BTreeSet<_> = current_values
            .into_iter()
            .flat_map(|values| values.keys())
            .chain(desired_values.into_iter().flat_map(|values| values.keys()))
            .collect();
        let mut delta = Map::new();
        for key in keys {
            let before = current_values.and_then(|values| values.get(key));
            let after = desired_values.and_then(|values| values.get(key));
            if before != after {
                delta.insert(key.clone(), after.cloned().unwrap_or(Value::Null));
            }
        }
        if !delta.is_empty() {
            field_metadata.insert(name.clone(), Value::Object(delta));
        }
    }
    Ok(DataViewPatch {
        base,
        field_metadata,
    })
}

/// Fully validate a portable artifact and prepare the exact guarded import.
pub async fn plan_import(
    transport: Option<&Transport>,
    path: &Path,
    overwrite: bool,
    skip_existing: bool,
) -> Result<DataViewImportPlan> {
    let mut specs = validate(path)?;
    if specs.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "data-view import needs at least one data view",
        ));
    }
    if overwrite && skip_existing {
        return Err(Error::new(
            ErrorKind::Error,
            "--overwrite and --skip-existing cannot be used together",
        ));
    }
    let total = specs.len();
    let requires_server = overwrite || skip_existing || transport.is_some();
    let transport = if requires_server { transport } else { None };
    if (overwrite || skip_existing) && transport.is_none() {
        return Err(Error::new(
            ErrorKind::Error,
            "data-view import conflict mode needs a transport",
        ));
    }

    let mut before = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut conflicts = Vec::new();
    if let Some(transport) = transport {
        for spec in &specs {
            match read_spec(transport, &spec.id).await {
                Ok(current) => {
                    if !overwrite && !skip_existing {
                        conflicts.push(spec.id.clone());
                    }
                    before.insert(spec.id.clone(), Some(current));
                }
                Err(error) if error.kind == ErrorKind::NotFound => {
                    before.insert(spec.id.clone(), None);
                }
                Err(error) => return Err(error),
            }
        }
    } else {
        before.extend(specs.iter().map(|spec| (spec.id.clone(), None)));
    }
    if !conflicts.is_empty() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!("data views already exist: {}", conflicts.join(", ")),
        ));
    }
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

    let mut patches = BTreeMap::new();
    for spec in &specs {
        match before.get(&spec.id).and_then(Option::as_ref) {
            Some(current) if current == spec => {
                patches.insert(spec.id.clone(), DataViewPatch::default());
            }
            Some(current) => {
                let patch = build_patch(current, spec)?;
                patches.insert(spec.id.clone(), patch);
            }
            None => {}
        }
    }
    let preview = MutationPlan {
        preview_action: format!(
            "Import {} data view(s) from {}",
            specs.len(),
            path.display()
        ),
        preview_details: preview_details(&specs, &before),
        targets: specs.iter().map(|spec| spec.id.clone()).collect(),
    };
    Ok(DataViewImportPlan {
        preview,
        specs,
        before,
        patches,
        skipped,
        total,
        overwrite,
    })
}

/// Apply a previously planned data-view import without rereading or replanning.
///
/// Each object gets one final pre-write read. The server exposes no conditional
/// write token, so the final verification read remains the smallest unavoidable
/// race window. Earlier successful writes are deliberately never rolled back.
pub async fn apply_import(
    transport: &Transport,
    plan: &DataViewImportPlan,
) -> Result<DataViewImportReport> {
    validate_import_plan(plan)?;
    let mut succeeded = Vec::new();
    let mut failed = Vec::new();

    for desired in &plan.specs {
        let before = match plan.before.get(&desired.id) {
            Some(before) => before,
            None => {
                failed.push(failed_row(&desired.id, false, "missing preflight snapshot"));
                continue;
            }
        };
        let current = match read_spec(transport, &desired.id).await {
            Ok(current) => Some(current),
            Err(error) if error.kind == ErrorKind::NotFound => None,
            Err(error) => {
                failed.push(failed_row(&desired.id, false, error.message));
                continue;
            }
        };

        match (before, current) {
            (None, Some(_)) => {
                failed.push(failed_row(
                    &desired.id,
                    false,
                    "data view appeared since preview",
                ));
                continue;
            }
            (Some(_), None) => {
                failed.push(failed_row(
                    &desired.id,
                    false,
                    "data view disappeared since preview",
                ));
                continue;
            }
            (Some(before), Some(current)) if before != &current => {
                failed.push(failed_row(
                    &desired.id,
                    false,
                    "data view changed since preview",
                ));
                continue;
            }
            (None, None) => {
                let mut applied = false;
                match data_views::create(transport, desired).await {
                    Ok(_) => applied = true,
                    Err(error) => {
                        failed.push(failed_row(&desired.id, applied, error.message));
                        continue;
                    }
                }
                match read_spec(transport, &desired.id).await {
                    Ok(stored) if stored == *desired => {
                        succeeded.push(json!({"id": desired.id, "action": "created"}));
                    }
                    Ok(_) => failed.push(failed_row(
                        &desired.id,
                        applied,
                        "server stored a different data-view spec",
                    )),
                    Err(error) => failed.push(failed_row(&desired.id, applied, error.message)),
                }
            }
            (Some(_), Some(_)) => {
                let patch = match plan.patches.get(&desired.id) {
                    Some(patch) => patch,
                    None => {
                        failed.push(failed_row(&desired.id, false, "missing replacement patch"));
                        continue;
                    }
                };
                if patch.base.is_none() && patch.field_metadata.is_empty() {
                    succeeded.push(json!({"id": desired.id, "action": "unchanged"}));
                    continue;
                }

                let mut applied = false;
                if let Some(base) = &patch.base {
                    if let Err(error) = data_views::update(transport, &desired.id, base).await {
                        failed.push(failed_row(
                            &desired.id,
                            applied,
                            format!("base update failed: {}", error.message),
                        ));
                        continue;
                    }
                    applied = true;
                }
                if !patch.field_metadata.is_empty()
                    && let Err(error) = data_views::update_fields_metadata(
                        transport,
                        &desired.id,
                        &patch.field_metadata,
                    )
                    .await
                {
                    let message = if applied {
                        format!("base updated; field metadata failed: {}", error.message)
                    } else {
                        format!("field metadata failed: {}", error.message)
                    };
                    failed.push(failed_row(&desired.id, applied, message));
                    continue;
                }
                if !patch.field_metadata.is_empty() {
                    applied = true;
                }
                match read_spec(transport, &desired.id).await {
                    Ok(stored) if stored == *desired => {
                        succeeded.push(json!({"id": desired.id, "action": "replaced"}));
                    }
                    Ok(_) => failed.push(failed_row(
                        &desired.id,
                        applied,
                        "server stored a different data-view spec",
                    )),
                    Err(error) => failed.push(failed_row(&desired.id, applied, error.message)),
                }
            }
        }
    }

    Ok(DataViewImportReport {
        applied: true,
        succeeded,
        skipped: plan.skipped.clone(),
        failed,
        total: plan.total,
    })
}

fn changed<T: PartialEq>(current: &T, desired: &T) -> bool {
    current != desired
}

fn is_empty_update(update: &DataViewUpdate) -> bool {
    update.allow_no_index.is_none()
        && update.field_formats.is_none()
        && update.fields.is_none()
        && update.name.is_none()
        && update.runtime_field_map.is_none()
        && update.source_filters.is_none()
        && update.time_field_name.is_none()
        && update.title.is_none()
        && update.view_type.is_none()
        && update.type_meta.is_none()
}

fn unsupported(message: impl Into<String>) -> Result<DataViewPatch> {
    Err(Error::new(ErrorKind::Unsupported, message))
}

fn failed_row(id: &str, applied: bool, error: impl Into<String>) -> Value {
    json!({"id": id, "applied": applied, "error": error.into()})
}

async fn read_spec(transport: &Transport, id: &str) -> Result<DataViewSpec> {
    let spec = normalize(&Value::Object(
        data_views::get(transport, id).await?.data_view,
    ))?;
    if spec.id != id {
        return Err(Error::new(
            ErrorKind::Http,
            format!("decoding data view: expected id '{id}', got '{}'", spec.id),
        ));
    }
    Ok(spec)
}

fn validate_import_plan(plan: &DataViewImportPlan) -> Result<()> {
    if plan.total == 0 {
        return invalid_plan("total must be greater than zero");
    }
    if plan.total != plan.specs.len() + plan.skipped.len() {
        return invalid_plan("total does not equal pending and skipped data views");
    }

    let mut pending_ids = Vec::with_capacity(plan.specs.len());
    for spec in &plan.specs {
        validate_canonical_spec(spec)?;
        if pending_ids
            .last()
            .is_some_and(|previous| previous >= &spec.id)
        {
            return invalid_plan("pending data views must be unique and sorted by id");
        }
        pending_ids.push(spec.id.clone());
    }
    let pending: BTreeSet<_> = pending_ids.iter().cloned().collect();
    let mut skipped_ids = BTreeSet::new();
    for row in &plan.skipped {
        let object = row
            .as_object()
            .filter(|object| object.len() == 2)
            .ok_or_else(|| Error::new(ErrorKind::Error, "invalid data-view import skipped row"))?;
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| Error::new(ErrorKind::Error, "invalid data-view import skipped row"))?;
        if object.get("reason").and_then(Value::as_str) != Some("exists")
            || !skipped_ids.insert(id.to_owned())
            || pending.contains(id)
        {
            return invalid_plan("invalid data-view import skipped rows");
        }
    }
    if plan.preview.targets != pending_ids {
        return invalid_plan("preview targets do not match pending data views");
    }
    let prefix = format!("Import {} data view(s) from ", plan.specs.len());
    if !plan.preview.preview_action.starts_with(&prefix)
        || plan.preview.preview_action[prefix.len()..].is_empty()
    {
        return invalid_plan("preview action does not match pending data views");
    }
    if plan.preview.preview_details != preview_details(&plan.specs, &plan.before) {
        return invalid_plan("preview details do not match pending data views");
    }

    let before_ids: BTreeSet<_> = plan.before.keys().cloned().collect();
    if before_ids != pending {
        return invalid_plan("preflight snapshots do not match pending data views");
    }
    let mut patch_ids = BTreeSet::new();
    for spec in &plan.specs {
        let before = plan.before.get(&spec.id).ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                "preflight snapshots do not match pending data views",
            )
        })?;
        match before {
            None => {
                if plan.patches.contains_key(&spec.id) {
                    return invalid_plan("planned creates must not carry a replacement patch");
                }
            }
            Some(snapshot) => {
                validate_canonical_spec(snapshot)?;
                if snapshot.id != spec.id {
                    return invalid_plan("preflight snapshot id does not match its target");
                }
                if !plan.overwrite {
                    return invalid_plan("replacement plan requires overwrite");
                }
                let expected = build_patch(snapshot, spec)?;
                let patch = plan.patches.get(&spec.id).ok_or_else(|| {
                    Error::new(ErrorKind::Error, "planned replacement is missing its patch")
                })?;
                if patch != &expected {
                    return invalid_plan("planned replacement patch does not match its snapshots");
                }
                patch_ids.insert(spec.id.clone());
            }
        }
    }
    if plan.patches.keys().cloned().collect::<BTreeSet<_>>() != patch_ids {
        return invalid_plan("replacement patches do not match preflight snapshots");
    }
    Ok(())
}

fn validate_canonical_spec(spec: &DataViewSpec) -> Result<()> {
    spec.validate()?;
    if matches!(spec.type_meta.as_ref(), Some(values) if values.is_empty()) {
        return Err(Error::new(
            ErrorKind::Error,
            "data view typeMeta must not be empty",
        ));
    }
    Ok(())
}

fn preview_details(
    specs: &[DataViewSpec],
    before: &BTreeMap<String, Option<DataViewSpec>>,
) -> Vec<String> {
    specs
        .iter()
        .filter_map(|spec| match before.get(&spec.id) {
            Some(None) => Some(format!("{}  create  {}", spec.id, spec.title)),
            Some(Some(current)) if current == spec => {
                Some(format!("{}  no-op  {}", spec.id, spec.title))
            }
            Some(Some(current)) => Some(format!(
                "{}  replace  {} -> {}",
                spec.id, current.title, spec.title
            )),
            None => None,
        })
        .collect()
}

fn invalid_plan(message: impl Into<String>) -> Result<()> {
    Err(Error::new(ErrorKind::Error, message))
}

/// Export selected data views as a portable JSON or YAML artifact.
pub async fn export(
    transport: &Transport,
    selectors: &[String],
    format: ContentFormat,
) -> Result<ExportOutcome> {
    let summaries = data_views::list(transport).await?;
    let selected = if selectors.is_empty() {
        summaries
    } else {
        selectors
            .iter()
            .map(|selector| resolve_from_summaries(&summaries, selector))
            .collect::<Result<Vec<_>>>()?
    };
    let selected: BTreeMap<_, _> = selected
        .into_iter()
        .map(|summary| (summary.id.clone(), summary))
        .collect();
    let expected = selected.len();
    let mut specs = Vec::with_capacity(expected);
    for (id, _) in selected {
        let detail = data_views::get(transport, &id).await?;
        let spec = normalize(&Value::Object(detail.data_view))?;
        if spec.id != id {
            return Err(Error::new(
                ErrorKind::Http,
                format!("data view export was short: expected id '{id}'"),
            ));
        }
        specs.push(spec);
    }
    if specs.len() != expected {
        return Err(Error::new(
            ErrorKind::Http,
            format!(
                "data view export was short: expected {expected}, got {}",
                specs.len()
            ),
        ));
    }
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    let body = content_codec::encode_sequence(&specs, format)?;
    Ok(ExportOutcome {
        body,
        exported: specs.len() as u64,
        missing: Vec::new(),
    })
}
