//! Opaque Saved Objects bundle transfer and validation.

use std::collections::{BTreeMap, BTreeSet};

use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;
use serde_json::{Map, Value, json};

const BASE: &str = "/api/saved_objects";

/// A Saved Object selected for export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SavedObjectRef {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
}

/// Read-only facts obtained by scanning an opaque Saved Objects bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleScan {
    pub dashboards: Vec<String>,
    pub counts: BTreeMap<String, usize>,
    pub total: usize,
    pub has_export_details: bool,
}

/// The server's Saved Objects import outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct SavedObjectsImportReport {
    pub success: bool,
    pub success_count: u64,
    pub success_results: Vec<Value>,
    pub errors: Vec<Value>,
}

/// Scan an opaque NDJSON bundle without changing any of its bytes.
pub fn scan_bundle(bundle: &str) -> Result<BundleScan> {
    let mut dashboards = Vec::new();
    let mut counts = BTreeMap::new();
    let mut total = 0;
    let mut export_details_lines = Vec::new();
    let mut last_nonempty_line = None;

    for (index, line) in bundle.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_number = index + 1;
        last_nonempty_line = Some(line_number);
        let value = serde_json::from_str::<Value>(line).map_err(|error| {
            local_error(format!(
                "invalid Saved Objects bundle JSON at line {line_number}: {error}"
            ))
        })?;
        let object = value.as_object().ok_or_else(|| {
            local_error(format!(
                "invalid Saved Objects bundle line {line_number}: expected a JSON object"
            ))
        })?;

        if is_export_details(object) {
            validate_export_details(object, line_number)?;
            export_details_lines.push(line_number);
            continue;
        }

        let object_type = required_string(object, "type", line_number)?;
        let id = required_string(object, "id", line_number)?;
        if object_type == "dashboard" {
            dashboards.push(id.to_owned());
        }
        *counts.entry(object_type.to_owned()).or_default() += 1;
        total += 1;
    }

    if export_details_lines.len() > 1 {
        return Err(local_error(
            "invalid Saved Objects bundle: more than one export-details trailer",
        ));
    }
    if let Some(line) = export_details_lines.first()
        && Some(*line) != last_nonempty_line
    {
        return Err(local_error(format!(
            "invalid Saved Objects bundle: export-details trailer at line {line} is not last"
        )));
    }
    if dashboards.is_empty() {
        return Err(local_error(
            "invalid Saved Objects bundle: expected at least one dashboard",
        ));
    }

    Ok(BundleScan {
        dashboards,
        counts,
        total,
        has_export_details: !export_details_lines.is_empty(),
    })
}

/// Export dashboards and their deep Saved Objects references as opaque NDJSON.
pub async fn export(t: &Transport, ids: &[String]) -> Result<String> {
    let ids: BTreeSet<String> = ids.iter().cloned().collect();
    let objects = ids
        .into_iter()
        .map(|id| SavedObjectRef {
            object_type: "dashboard".into(),
            id,
        })
        .collect::<Vec<_>>();
    let body = json!({
        "objects": objects,
        "includeReferencesDeep": true,
        "excludeExportDetails": false,
    });
    t.post_text(&format!("{BASE}/_export"), Some(&body)).await
}

/// Import an opaque Saved Objects NDJSON bundle.
pub async fn import(
    t: &Transport,
    bundle: &str,
    overwrite: bool,
) -> Result<SavedObjectsImportReport> {
    let response = t
        .post_multipart_ndjson_named(
            &format!("{BASE}/_import?overwrite={overwrite}"),
            "dashboards.ndjson",
            bundle,
        )
        .await?;
    decode_import_response(&response)
}

fn is_export_details(object: &Map<String, Value>) -> bool {
    object.contains_key("exportedCount")
        || object.contains_key("missingRefCount")
        || object.contains_key("missingReferences")
}

fn validate_export_details(object: &Map<String, Value>, line: usize) -> Result<()> {
    for field in ["exportedCount", "missingRefCount"] {
        if object.get(field).and_then(Value::as_u64).is_none() {
            return Err(local_error(format!(
                "invalid Saved Objects export-details trailer at line {line}: {field} must be an unsigned number"
            )));
        }
    }
    if object
        .get("missingReferences")
        .and_then(Value::as_array)
        .is_none()
    {
        return Err(local_error(format!(
            "invalid Saved Objects export-details trailer at line {line}: missingReferences must be an array"
        )));
    }
    Ok(())
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    line: usize,
) -> Result<&'a str> {
    object.get(field).and_then(Value::as_str).ok_or_else(|| {
        local_error(format!(
            "invalid Saved Objects bundle line {line}: {field} must be a string"
        ))
    })
}

fn decode_import_response(response: &Value) -> Result<SavedObjectsImportReport> {
    let object = response
        .as_object()
        .ok_or_else(|| import_error("response must be an object"))?;
    let success = object
        .get("success")
        .and_then(Value::as_bool)
        .ok_or_else(|| import_error("field `success` must be a boolean"))?;
    let success_count = object
        .get("successCount")
        .and_then(Value::as_u64)
        .ok_or_else(|| import_error("field `successCount` must be an unsigned number"))?;
    let success_results = optional_array(object, "successResults")?;
    let errors = optional_array(object, "errors")?;

    if success_count != success_results.len() as u64 {
        return Err(import_error(
            "field `successCount` must equal the number of `successResults`",
        ));
    }
    if success && !errors.is_empty() {
        return Err(import_error("successful imports must not contain `errors`"));
    }
    if !success && errors.is_empty() {
        return Err(import_error("failed imports must contain `errors`"));
    }

    Ok(SavedObjectsImportReport {
        success,
        success_count,
        success_results,
        errors,
    })
}

fn optional_array(object: &Map<String, Value>, field: &str) -> Result<Vec<Value>> {
    match object.get(field) {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) => Ok(values.clone()),
        Some(_) => Err(import_error(format!("field `{field}` must be an array"))),
    }
}

fn local_error(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Error, message)
}

fn import_error(message: impl Into<String>) -> Error {
    Error::new(
        ErrorKind::Http,
        format!("decoding Saved Objects import response: {}", message.into()),
    )
}
