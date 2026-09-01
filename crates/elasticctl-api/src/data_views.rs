//! Typed data-view models and public Kibana route wrappers.

use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

const BASE: &str = "/api/data_views";

/// The portable, author-controlled data-view representation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataViewSpec {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_field_name: Option<String>,
    #[serde(default)]
    pub allow_no_index: bool,
    #[serde(default)]
    pub allow_hidden: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_filters: Vec<Value>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub field_formats: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub runtime_field_map: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub field_attrs: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub fields: Map<String, Value>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub view_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_meta: Option<Map<String, Value>>,
}

impl DataViewSpec {
    /// Validate portable values that have extensible nested maps.
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(Error::new(
                ErrorKind::Error,
                "data view id must not be empty",
            ));
        }
        if self.title.trim().is_empty() {
            return Err(Error::new(
                ErrorKind::Error,
                "data view title must not be empty",
            ));
        }
        validate_object_values(&self.field_attrs, "fieldAttrs")?;
        for (name, field) in &self.fields {
            let path = format!("fields.{name}");
            let field = field
                .as_object()
                .ok_or_else(|| Error::new(ErrorKind::Error, format!("{path} must be an object")))?;
            if field.get("scripted").and_then(Value::as_bool) != Some(true) {
                return Err(Error::new(
                    ErrorKind::Error,
                    format!("{path}.scripted must be true"),
                ));
            }
        }
        Ok(())
    }
}

fn validate_object_values(values: &Map<String, Value>, path: &str) -> Result<()> {
    for (name, value) in values {
        if !value.is_object() {
            return Err(Error::new(
                ErrorKind::Error,
                format!("{path}.{name} must be an object"),
            ));
        }
    }
    Ok(())
}

impl TryFrom<Value> for DataViewSpec {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self> {
        validate_input_objects(&value)?;
        let spec: Self = serde_json::from_value(value).map_err(|error| {
            Error::new(ErrorKind::Error, format!("decoding data view: {error}"))
        })?;
        spec.validate()?;
        Ok(spec)
    }
}

fn validate_input_objects(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| Error::new(ErrorKind::Error, "data view must be a JSON object"))?;
    if let Some(type_meta) = object.get("typeMeta")
        && !type_meta.is_object()
    {
        return Err(Error::new(ErrorKind::Error, "typeMeta must be an object"));
    }
    for field in ["fieldAttrs", "fields"] {
        if let Some(entries) = object.get(field).and_then(Value::as_object) {
            for (name, entry) in entries {
                if !entry.is_object() {
                    return Err(Error::new(
                        ErrorKind::Error,
                        format!("{field}.{name} must be an object"),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// The documented partial-update fields. `None` omits a field from the body.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataViewUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_no_index: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_formats: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_field_map: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_filters: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_field_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub view_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_meta: Option<Map<String, Value>>,
}

/// A list row returned by Kibana.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataViewSummary {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub time_field_name: Option<String>,
}

/// A data view returned from its detail, create, or update route.
#[derive(Debug, Clone, PartialEq)]
pub struct DataView {
    pub spec: DataViewSpec,
}

/// A saved object that refers to a data view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataViewReference {
    pub id: String,
    #[serde(rename = "type")]
    pub object_type: String,
}

/// The delete result returned by a reference swap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteStatus {
    pub delete_performed: bool,
    pub remaining_refs: u64,
}

/// The affected references and deletion status from a reference swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceSwap {
    pub result: Vec<DataViewReference>,
    pub delete_status: DeleteStatus,
}

/// List all data views in the active space.
pub async fn list(transport: &Transport) -> Result<Vec<DataViewSummary>> {
    let body = transport.get(BASE).await?;
    let views = required_array(&body, "data_view", "data views list")?;
    views
        .iter()
        .cloned()
        .map(|view| {
            serde_json::from_value(view).map_err(|error| {
                Error::new(
                    ErrorKind::Http,
                    format!("decoding data views list entry: {error}"),
                )
            })
        })
        .collect()
}

/// Get one data view by its stable id.
pub async fn get(transport: &Transport, id: &str) -> Result<DataView> {
    decode_data_view(&transport.get(&data_view_path(id)).await?, "data view get")
}

/// Create a data view with its explicit, portable id.
pub async fn create(transport: &Transport, spec: &DataViewSpec) -> Result<DataView> {
    spec.validate()?;
    let body = json!({"data_view": spec, "override": false});
    decode_data_view(
        &transport
            .post(&format!("{BASE}/data_view"), Some(&body))
            .await?,
        "data view create",
    )
}

/// Apply the documented partial data-view update.
pub async fn update(transport: &Transport, id: &str, update: &DataViewUpdate) -> Result<DataView> {
    let body = json!({"data_view": update, "refresh_fields": true});
    decode_data_view(
        &transport.post(&data_view_path(id), Some(&body)).await?,
        "data view update",
    )
}

/// Update the field metadata delta for one data view.
pub async fn update_fields_metadata(
    transport: &Transport,
    id: &str,
    fields: &Map<String, Value>,
) -> Result<()> {
    let body = json!({"fields": fields});
    decode_acknowledged(
        &transport
            .post(&format!("{}/fields", data_view_path(id)), Some(&body))
            .await?,
        "data view field metadata update",
    )
}

/// Delete one unreferenced data view.
pub async fn delete(transport: &Transport, id: &str) -> Result<()> {
    decode_acknowledged(
        &transport.delete(&data_view_path(id)).await?,
        "data view delete",
    )
}

/// Get the active space's default data-view id, if one is set.
pub async fn get_default(transport: &Transport) -> Result<Option<String>> {
    let body = transport.get(&format!("{BASE}/default")).await?;
    match required_object(&body, "data view default")?.get("data_view_id") {
        Some(Value::String(id)) => Ok(Some(id.clone())),
        Some(Value::Null) => Ok(None),
        _ => Err(Error::new(
            ErrorKind::Http,
            "decoding data view default field `data_view_id`: expected string or null",
        )),
    }
}

/// Set a default data view, or clear it when `id` is `None`.
pub async fn set_default(transport: &Transport, id: Option<&str>) -> Result<()> {
    if matches!(id, Some(value) if value.trim().is_empty()) {
        return Err(Error::new(
            ErrorKind::Error,
            "data view default id must not be empty",
        ));
    }
    let body = json!({"data_view_id": id, "force": true});
    decode_acknowledged(
        &transport
            .post(&format!("{BASE}/default"), Some(&body))
            .await?,
        "data view default set",
    )
}

/// Preview the saved-object references a swap would change.
pub async fn preview_swap(
    transport: &Transport,
    from_id: &str,
    to_id: &str,
) -> Result<Vec<DataViewReference>> {
    let body = json!({"fromId": from_id, "toId": to_id});
    decode_references(
        &transport
            .post(&format!("{BASE}/swap_references/_preview"), Some(&body))
            .await?,
        "data view reference swap preview",
    )
}

/// Replace references and delete the source data view.
pub async fn swap(transport: &Transport, from_id: &str, to_id: &str) -> Result<ReferenceSwap> {
    let body = json!({"delete": true, "fromId": from_id, "toId": to_id});
    let response = transport
        .post(&format!("{BASE}/swap_references"), Some(&body))
        .await?;
    let result = decode_references(&response, "data view reference swap")?;
    let map = required_object(&response, "data view reference swap")?;
    let delete_status = map.get("deleteStatus").ok_or_else(|| {
        Error::new(
            ErrorKind::Http,
            "decoding data view reference swap field `deleteStatus`",
        )
    })?;
    let delete_status = serde_json::from_value(delete_status.clone()).map_err(|error| {
        Error::new(
            ErrorKind::Http,
            format!("decoding data view reference swap field `deleteStatus`: {error}"),
        )
    })?;
    Ok(ReferenceSwap {
        result,
        delete_status,
    })
}

fn data_view_path(id: &str) -> String {
    format!("{BASE}/data_view/{}", elasticctl_core::urlencode(id))
}

fn decode_data_view(body: &Value, context: &str) -> Result<DataView> {
    let value = required_object(body, context)?
        .get("data_view")
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                format!("decoding {context} field `data_view`"),
            )
        })?;
    let spec = DataViewSpec::try_from(value.clone()).map_err(|error| {
        Error::new(
            ErrorKind::Http,
            format!("decoding {context} field `data_view`: {}", error.message),
        )
    })?;
    Ok(DataView { spec })
}

fn decode_acknowledged(body: &Value, context: &str) -> Result<()> {
    if required_object(body, context)?.get("acknowledged") == Some(&Value::Bool(true)) {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Http,
            format!("decoding {context} field `acknowledged`: expected true"),
        ))
    }
}

fn decode_references(body: &Value, context: &str) -> Result<Vec<DataViewReference>> {
    let values = required_array(body, "result", context)?;
    values
        .iter()
        .cloned()
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                Error::new(
                    ErrorKind::Http,
                    format!("decoding {context} result entry: {error}"),
                )
            })
        })
        .collect()
}

fn required_object<'a>(body: &'a Value, context: &str) -> Result<&'a Map<String, Value>> {
    body.as_object().ok_or_else(|| {
        Error::new(
            ErrorKind::Http,
            format!("decoding {context}: expected a JSON object"),
        )
    })
}

fn required_array<'a>(body: &'a Value, field: &str, context: &str) -> Result<&'a Vec<Value>> {
    required_object(body, context)?
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                format!("decoding {context} field `{field}`: expected an array"),
            )
        })
}
