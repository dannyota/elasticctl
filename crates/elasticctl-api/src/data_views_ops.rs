use crate::content_codec::{self, ContentFormat};
use crate::data_views::{
    self, DataView, DataViewReference, DataViewSpec, DataViewSummary, DataViewUpdate,
};
use crate::ops::{DeleteOutcome, ExportOutcome, MutationPlan};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

mod defaults;
mod delete;
mod import;
pub use defaults::{DefaultPlan, apply_default, plan_default_set, plan_default_unset};
pub use delete::{DataViewDeletePlan, DataViewDeleteTarget, apply_delete, plan_delete};
pub use import::{
    DataViewImportPlan, DataViewImportReport, DataViewPatch, apply_import, build_patch, plan_import,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataViewFilter {
    pub search: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DataViewList {
    pub total: usize,
    pub data_views: Vec<DataViewSummary>,
}

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

pub async fn resolve(transport: &Transport, selector: &str) -> Result<DataViewSummary> {
    let views = data_views::list(transport).await?;
    resolve_from_summaries(&views, selector)
}

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

pub async fn get_op(transport: &Transport, selector: &str) -> Result<DataView> {
    let view = resolve(transport, selector).await?;
    data_views::get(transport, &view.id).await
}

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
            Value::Object(fields) => {
                let mut scripted: Vec<_> = fields
                    .iter()
                    .filter_map(|(name, field)| {
                        (field.get("scripted").and_then(Value::as_bool) == Some(true))
                            .then_some(name.as_str())
                    })
                    .collect();
                scripted.sort_unstable();
                if !scripted.is_empty() {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        format!(
                            "legacy scripted fields are unsupported: {}",
                            scripted.join(", ")
                        ),
                    ));
                }
                Value::Object(Map::new())
            }
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

fn invalid_plan(message: impl Into<String>) -> Result<()> {
    Err(Error::new(ErrorKind::Error, message))
}

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
