//! Typed dashboard models and public Kibana route wrappers.

use elasticctl_core::{Error, ErrorKind, Feature, Result, Transport, urlencode};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

const BASE: &str = "/api/dashboards";

/// The portable, author-controlled dashboard representation.
///
/// `data` is an ordered, open JSON map so new public API fields survive a
/// portable artifact round trip.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DashboardSpec {
    pub id: String,
    pub data: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDashboardSpec {
    id: String,
    data: Map<String, Value>,
}

impl DashboardSpec {
    fn validate_shape(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(Error::new(
                ErrorKind::Error,
                "dashboard id must not be empty",
            ));
        }
        match self.data.get("title") {
            Some(Value::String(title)) if !title.trim().is_empty() => Ok(()),
            _ => Err(Error::new(
                ErrorKind::Error,
                "dashboard data.title must be a non-empty string",
            )),
        }
    }
}

impl TryFrom<Value> for DashboardSpec {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self> {
        serde_json::from_value(value)
            .map_err(|error| Error::new(ErrorKind::Error, format!("decoding dashboard: {error}")))
    }
}

impl<'de> Deserialize<'de> for DashboardSpec {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawDashboardSpec::deserialize(deserializer)?;
        let spec = Self {
            id: raw.id,
            data: raw.data,
        };
        spec.validate_shape().map_err(serde::de::Error::custom)?;
        Ok(spec)
    }
}

/// A dashboard list row returned by Kibana.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardSummary {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

/// A warning Kibana returned while transforming a dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardWarning {
    pub message: String,
}

/// A full dashboard returned by Kibana.
#[derive(Debug, Clone, PartialEq)]
pub struct Dashboard {
    pub id: String,
    pub data: Map<String, Value>,
    pub meta: Map<String, Value>,
    pub warnings: Vec<DashboardWarning>,
}

/// One page returned by Kibana's dashboard list route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardPage {
    pub data: Vec<DashboardSummary>,
    pub page: u64,
    pub per_page: u64,
    pub total: u64,
}

/// One submitted value that Kibana did not persist.
#[derive(Debug, Clone, PartialEq)]
pub struct DashboardLoss {
    pub path: String,
    pub expected: Value,
    pub actual: Option<Value>,
}

/// List one page of dashboards through the public Dashboards API.
pub async fn search(
    transport: &Transport,
    page: u64,
    query: Option<&str>,
    tags: &[String],
) -> Result<DashboardPage> {
    transport.require_feature(Feature::Dashboards).await?;
    let mut route = format!("{BASE}?page={page}&per_page=1000");
    if let Some(query) = query {
        route.push_str("&query=");
        route.push_str(&urlencode(query));
    }
    for tag in tags {
        route.push_str("&tags=");
        route.push_str(&urlencode(tag));
    }
    decode_search(&transport.get(&route).await?)
}

/// Get one dashboard by its stable id.
pub async fn get(transport: &Transport, id: &str) -> Result<Dashboard> {
    transport.require_feature(Feature::Dashboards).await?;
    decode_dashboard(&transport.get(&dashboard_path(id)).await?, "dashboard get")
}

/// Upsert one dashboard using only its portable body.
pub async fn put(transport: &Transport, spec: &DashboardSpec) -> Result<Dashboard> {
    validate_spec(spec)?;
    transport.require_feature(Feature::Dashboards).await?;
    decode_dashboard(
        &transport
            .put(&dashboard_path(&spec.id), &Value::Object(spec.data.clone()))
            .await?,
        "dashboard put",
    )
}

/// Delete one dashboard by id.
pub async fn delete(transport: &Transport, id: &str) -> Result<()> {
    transport.require_feature(Feature::Dashboards).await?;
    match transport.delete(&dashboard_path(id)).await? {
        Value::Null => Ok(()),
        _ => Err(Error::new(
            ErrorKind::Http,
            "decoding dashboard delete: expected an empty response body",
        )),
    }
}

/// Reject locally known dashboard values that Kibana accepts but drops.
pub fn validate_spec(spec: &DashboardSpec) -> Result<()> {
    spec.validate_shape()?;
    if let Some(path) = time_range_mode_path(&Value::Object(spec.data.clone()), "$") {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!("dashboard {path} is unsupported because Kibana does not persist it"),
        ));
    }
    Ok(())
}

/// Return sorted, unique data-view reference ids found anywhere in `value`.
pub fn collect_data_view_refs(value: &Value) -> Vec<String> {
    fn collect(value: &Value, ids: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                if map.get("type").and_then(Value::as_str) == Some("data_view_reference")
                    && let Some(id) = map.get("ref_id").and_then(Value::as_str)
                {
                    ids.insert(id.to_string());
                }
                for value in map.values() {
                    collect(value, ids);
                }
            }
            Value::Array(values) => {
                for value in values {
                    collect(value, ids);
                }
            }
            _ => {}
        }
    }

    let mut ids = BTreeSet::new();
    collect(value, &mut ids);
    ids.into_iter().collect()
}

/// Find submitted values that are absent or changed in an accepted response.
pub fn subset_losses(expected: &Value, actual: &Value) -> Vec<DashboardLoss> {
    fn collect(
        expected: &Value,
        actual: Option<&Value>,
        path: &str,
        losses: &mut Vec<DashboardLoss>,
    ) {
        let Some(actual) = actual else {
            losses.push(DashboardLoss {
                path: path.to_string(),
                expected: expected.clone(),
                actual: None,
            });
            return;
        };

        match (expected, actual) {
            (Value::Object(expected), Value::Object(actual)) => {
                for (key, expected) in expected {
                    let path = format!("{path}.{}", json_path_key(key));
                    collect(expected, actual.get(key), &path, losses);
                }
            }
            (Value::Array(expected), Value::Array(actual)) => {
                for (index, expected) in expected.iter().enumerate() {
                    let path = format!("{path}[{index}]");
                    collect(expected, actual.get(index), &path, losses);
                }
            }
            _ if expected == actual => {}
            _ => losses.push(DashboardLoss {
                path: path.to_string(),
                expected: expected.clone(),
                actual: Some(actual.clone()),
            }),
        }
    }

    let mut losses = Vec::new();
    collect(expected, Some(actual), "$", &mut losses);
    losses
}

fn dashboard_path(id: &str) -> String {
    format!("{BASE}/{}", urlencode(id))
}

fn time_range_mode_path(value: &Value, path: &str) -> Option<String> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let child_path = format!("{path}.{}", json_path_key(key));
                if key == "time_range" && value.get("mode").is_some() {
                    return Some(format!("{child_path}.mode"));
                }
                if let Some(path) = time_range_mode_path(value, &child_path) {
                    return Some(path);
                }
            }
            None
        }
        Value::Array(values) => values
            .iter()
            .enumerate()
            .find_map(|(index, value)| time_range_mode_path(value, &format!("{path}[{index}]"))),
        _ => None,
    }
}

fn json_path_key(key: &str) -> String {
    if key.chars().enumerate().all(|(index, character)| {
        character == '_'
            || character.is_ascii_alphanumeric() && (index > 0 || !character.is_ascii_digit())
    }) {
        key.to_string()
    } else {
        format!("['{}']", key.replace('\\', "\\\\").replace('\'', "\\'"))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchEnvelope {
    data: Vec<DashboardSummary>,
    meta: SearchMeta,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchMeta {
    page: u64,
    per_page: u64,
    total: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DashboardEnvelope {
    id: String,
    data: Map<String, Value>,
    meta: Map<String, Value>,
    #[serde(default)]
    warnings: Vec<DashboardWarning>,
}

fn decode_search(body: &Value) -> Result<DashboardPage> {
    let response = decode_envelope::<SearchEnvelope>(body, "dashboard search")?;
    Ok(DashboardPage {
        data: response.data,
        page: response.meta.page,
        per_page: response.meta.per_page,
        total: response.meta.total,
    })
}

fn decode_dashboard(body: &Value, context: &str) -> Result<Dashboard> {
    let response = decode_envelope::<DashboardEnvelope>(body, context)?;
    if response.id.trim().is_empty() {
        return Err(Error::new(
            ErrorKind::Http,
            format!("decoding {context}: id must be a non-empty string"),
        ));
    }
    Ok(Dashboard {
        id: response.id,
        data: response.data,
        meta: response.meta,
        warnings: response.warnings,
    })
}

fn decode_envelope<T: DeserializeOwned>(body: &Value, context: &str) -> Result<T> {
    serde_json::from_value(body.clone())
        .map_err(|error| Error::new(ErrorKind::Http, format!("decoding {context}: {error}")))
}
