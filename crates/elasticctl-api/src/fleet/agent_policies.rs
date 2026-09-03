//! Typed agent-policy models and public Fleet route wrappers.

use elasticctl_core::{Error, ErrorKind, Feature, Result, Transport};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value, json};

const BASE: &str = "/api/fleet/agent_policies";
const PACKAGES: &str = "/api/fleet/epm/packages";

/// Fleet's create-time default for `inactivity_timeout`, in seconds.
pub const DEFAULT_INACTIVITY_TIMEOUT: u64 = 1_209_600;

/// Boolean flags that mark a policy Fleet or the deployment owns. Sorted.
pub const PLATFORM_FLAGS: [&str; 7] = [
    "has_fleet_server",
    "is_default",
    "is_default_fleet_server",
    "is_managed",
    "is_preconfigured",
    "is_verifier",
    "supports_agentless",
];

/// Nullable object that marks an agentless policy when present.
pub const AGENTLESS_FIELD: &str = "agentless";

/// Target-local infrastructure references. Sorted.
pub const ENVIRONMENT_IDS: [&str; 4] = [
    "data_output_id",
    "download_source_id",
    "fleet_server_host_id",
    "monitoring_output_id",
];

const MONITORING_VALUES: [&str; 3] = ["logs", "metrics", "traces"];

/// The portable, author-controlled agent-policy representation.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentPolicySpec {
    pub id: String,
    pub name: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub inactivity_timeout: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unenroll_timeout: Option<u64>,
    pub monitoring_enabled: Vec<String>,
    pub agent_features: Vec<Value>,
    pub global_data_tags: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advanced_settings: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_monitoring_alive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitoring_pprof_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitoring_http: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitoring_diagnostics: Option<Map<String, Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentPolicySpec {
    id: String,
    name: String,
    namespace: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    inactivity_timeout: Option<u64>,
    #[serde(default)]
    unenroll_timeout: Option<u64>,
    #[serde(default)]
    monitoring_enabled: Option<Vec<String>>,
    #[serde(default)]
    agent_features: Option<Vec<Value>>,
    #[serde(default)]
    global_data_tags: Option<Vec<Value>>,
    #[serde(default)]
    advanced_settings: Option<Map<String, Value>>,
    #[serde(default)]
    overrides: Option<Map<String, Value>>,
    #[serde(default)]
    keep_monitoring_alive: Option<bool>,
    #[serde(default)]
    monitoring_pprof_enabled: Option<bool>,
    #[serde(default)]
    monitoring_http: Option<Map<String, Value>>,
    #[serde(default)]
    monitoring_diagnostics: Option<Map<String, Value>>,
}

impl AgentPolicySpec {
    fn from_raw(raw: RawAgentPolicySpec) -> Result<Self> {
        let spec = Self {
            id: raw.id,
            name: raw.name,
            namespace: raw.namespace,
            description: raw.description,
            inactivity_timeout: raw.inactivity_timeout.unwrap_or(DEFAULT_INACTIVITY_TIMEOUT),
            unenroll_timeout: raw.unenroll_timeout,
            monitoring_enabled: raw.monitoring_enabled.unwrap_or_default(),
            agent_features: raw.agent_features.unwrap_or_default(),
            global_data_tags: raw.global_data_tags.unwrap_or_default(),
            advanced_settings: raw.advanced_settings,
            overrides: raw.overrides,
            keep_monitoring_alive: raw.keep_monitoring_alive,
            monitoring_pprof_enabled: raw.monitoring_pprof_enabled,
            monitoring_http: raw.monitoring_http,
            monitoring_diagnostics: raw.monitoring_diagnostics,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Validate a portable 0.6.0 agent-policy artifact.
    pub fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("id", &self.id),
            ("name", &self.name),
            ("namespace", &self.namespace),
        ] {
            if value.trim().is_empty() {
                return Err(Error::new(
                    ErrorKind::Error,
                    format!("agent policy {field} must not be empty"),
                ));
            }
        }
        for value in &self.monitoring_enabled {
            if !MONITORING_VALUES.contains(&value.as_str()) {
                return Err(Error::new(
                    ErrorKind::Error,
                    format!(
                        "monitoring_enabled value '{value}' must be one of logs, metrics, traces"
                    ),
                ));
            }
        }
        validate_agent_features(&self.agent_features)?;
        validate_global_data_tags(&self.global_data_tags)?;
        Ok(())
    }
}

fn object_name<'a>(value: &'a Value, field: &str, index: usize) -> Result<&'a str> {
    value
        .as_object()
        .and_then(|object| object.get("name"))
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                format!("{field}[{index}].name must be a non-empty string"),
            )
        })
}

fn validate_agent_features(values: &[Value]) -> Result<()> {
    for (index, value) in values.iter().enumerate() {
        object_name(value, "agent_features", index)?;
        if value
            .as_object()
            .and_then(|object| object.get("enabled"))
            .and_then(Value::as_bool)
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::Error,
                format!("agent_features[{index}].enabled must be a boolean"),
            ));
        }
    }
    Ok(())
}

fn validate_global_data_tags(values: &[Value]) -> Result<()> {
    let mut names = std::collections::BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let name = object_name(value, "global_data_tags", index)?;
        if name.chars().any(char::is_whitespace) {
            return Err(Error::new(
                ErrorKind::Error,
                format!("global_data_tags[{index}].name must not contain whitespace"),
            ));
        }
        if !names.insert(name) {
            return Err(Error::new(
                ErrorKind::Error,
                format!("duplicate global_data_tags name '{name}'"),
            ));
        }
        let valid_value = value
            .as_object()
            .and_then(|object| object.get("value"))
            .is_some_and(|value| value.is_string() || value.is_number());
        if !valid_value {
            return Err(Error::new(
                ErrorKind::Error,
                format!("global_data_tags[{index}].value must be a string or number"),
            ));
        }
    }
    Ok(())
}

impl TryFrom<Value> for AgentPolicySpec {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self> {
        serde_json::from_value(value).map_err(|error| {
            Error::new(ErrorKind::Error, format!("decoding agent policy: {error}"))
        })
    }
}

impl<'de> Deserialize<'de> for AgentPolicySpec {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawAgentPolicySpec::deserialize(deserializer)?;
        Self::from_raw(raw).map_err(serde::de::Error::custom)
    }
}

/// A list row. `agents` is present on list and single reads; ops requires it
/// for mutation planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentPolicySummary {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub description: Option<String>,
    pub agents: Option<u64>,
}

impl AgentPolicySummary {
    pub fn from_item(item: &Map<String, Value>) -> Result<Self> {
        Ok(Self {
            id: required_string(item, "id")?,
            name: required_string(item, "name")?,
            namespace: required_string(item, "namespace")?,
            description: optional_string(item, "description")?,
            agents: optional_u64(item, "agents")?,
        })
    }
}

/// Safe single-policy output. Raw Fleet items contain audit identities and
/// populated integration configurations, so they never cross the API boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentPolicyDetail {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub description: Option<String>,
    pub agents: u64,
    pub status: Option<String>,
    pub attached_integrations: Vec<String>,
    pub blocked_by: Vec<String>,
}

/// One page of the paginated list route.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentPolicyPage {
    pub items: Vec<Map<String, Value>>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
}

/// A single policy as returned by its read, create, or update route.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentPolicy {
    pub item: Map<String, Value>,
}

/// The installed state of one package, from `GET /api/fleet/epm/packages/{name}`.
/// The registry's `latestVersion` is deliberately not kept: it moves on a
/// registry refresh and would make two snapshots of one installation unequal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageStatus {
    pub name: String,
    pub status: String,
    pub installed_version: Option<String>,
}

fn required_string(item: &Map<String, Value>, field: &str) -> Result<String> {
    item.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                format!("decoding agent policy field `{field}`: expected a non-empty string"),
            )
        })
}

fn optional_string(item: &Map<String, Value>, field: &str) -> Result<Option<String>> {
    match item.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(Error::new(
            ErrorKind::Http,
            format!("decoding agent policy field `{field}`: expected a string or null"),
        )),
    }
}

fn optional_u64(item: &Map<String, Value>, field: &str) -> Result<Option<u64>> {
    match item.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                format!(
                    "decoding agent policy field `{field}`: expected an unsigned integer or null"
                ),
            )
        }),
    }
}

/// Read one page of the list route with the measured deterministic ordering.
pub async fn list_page(transport: &Transport, page: u64) -> Result<AgentPolicyPage> {
    transport.require_feature(Feature::FleetPolicies).await?;
    let body = transport
        .get(&format!(
            "{BASE}?page={page}&perPage=1000&sortField=created_at&sortOrder=asc"
        ))
        .await?;
    let envelope: PageEnvelope = decode(&body, "agent policies list")?;
    Ok(AgentPolicyPage {
        items: envelope.items,
        total: envelope.total,
        page: envelope.page,
        per_page: envelope.per_page,
    })
}

/// Read one policy by its stable id.
pub async fn get(transport: &Transport, id: &str) -> Result<AgentPolicy> {
    transport.require_feature(Feature::FleetPolicies).await?;
    decode_item(&transport.get(&policy_path(id)).await?, "agent policy get")
}

/// Create a policy with its explicit id and no implicit System integration.
pub async fn create(transport: &Transport, spec: &AgentPolicySpec) -> Result<AgentPolicy> {
    transport.require_feature(Feature::FleetPolicies).await?;
    spec.validate()?;
    let body = serde_json::to_value(spec)
        .map_err(|error| Error::new(ErrorKind::Error, format!("encoding agent policy: {error}")))?;
    decode_item(
        &transport
            .post(&format!("{BASE}?sys_monitoring=false"), Some(&body))
            .await?,
        "agent policy create",
    )
}

/// Replace a policy. `body` is the complete desired spec without `id`, plus
/// explicit nulls; `agent_policy_ops::build_replace_body` builds it.
pub async fn update(transport: &Transport, id: &str, body: &Value) -> Result<AgentPolicy> {
    transport.require_feature(Feature::FleetPolicies).await?;
    decode_item(
        &transport.put(&policy_path(id), body).await?,
        "agent policy update",
    )
}

/// Delete one policy by id. Never sends `force`.
pub async fn delete(transport: &Transport, id: &str) -> Result<()> {
    transport.require_feature(Feature::FleetPolicies).await?;
    let body = json!({"agentPolicyId": id});
    let response = transport
        .post(&format!("{BASE}/delete"), Some(&body))
        .await?;
    let deleted: DeleteEnvelope = decode(&response, "agent policy delete")?;
    if deleted.id != id {
        // The route call above only surfaces the decoded body, not its HTTP
        // status, and a body that decodes at all was a 2xx response.
        return Err(Error::with_status(
            ErrorKind::Http,
            200,
            format!(
                "decoding agent policy delete: expected id '{id}', got '{}'",
                deleted.id
            ),
        ));
    }
    Ok(())
}

/// Read a package's installation state. The full item is registry metadata;
/// only the installation facts are kept.
pub async fn package_status(transport: &Transport, name: &str) -> Result<PackageStatus> {
    transport.require_feature(Feature::FleetPolicies).await?;
    let body = transport
        .get(&format!("{PACKAGES}/{}", elasticctl_core::urlencode(name)))
        .await?;
    let item = body
        .get("item")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::new(ErrorKind::Http, "decoding package status: expected item"))?;
    let returned_name = required_string(item, "name")?;
    if returned_name != name {
        return Err(Error::new(
            ErrorKind::Http,
            format!("decoding package status: expected name '{name}', got '{returned_name}'"),
        ));
    }
    let status = required_string(item, "status")?;
    let installed_version = match item.get("installationInfo") {
        None | Some(Value::Null) => None,
        Some(Value::Object(info)) => optional_non_empty_string(info, "version")?,
        Some(_) => {
            return Err(Error::new(
                ErrorKind::Http,
                "decoding package status: installationInfo must be an object or null",
            ));
        }
    };
    if status == "installed" && installed_version.is_none() {
        return Err(Error::new(
            ErrorKind::Http,
            "decoding package status: installed package has no installed version",
        ));
    }
    Ok(PackageStatus {
        name: returned_name,
        status,
        installed_version,
    })
}

fn optional_non_empty_string(item: &Map<String, Value>, field: &str) -> Result<Option<String>> {
    match item.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
        Some(_) => Err(Error::new(
            ErrorKind::Http,
            format!("decoding package status field `{field}`: expected a non-empty string or null"),
        )),
    }
}

fn policy_path(id: &str) -> String {
    format!("{BASE}/{}", elasticctl_core::urlencode(id))
}

fn decode_item(body: &Value, context: &str) -> Result<AgentPolicy> {
    let envelope: ItemEnvelope = decode(body, context)?;
    Ok(AgentPolicy {
        item: envelope.item,
    })
}

fn decode<T: serde::de::DeserializeOwned>(body: &Value, context: &str) -> Result<T> {
    serde_json::from_value(body.clone())
        .map_err(|error| Error::new(ErrorKind::Http, format!("decoding {context}: {error}")))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageEnvelope {
    items: Vec<Map<String, Value>>,
    total: u64,
    page: u64,
    #[serde(rename = "perPage")]
    per_page: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemEnvelope {
    item: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteEnvelope {
    id: String,
    #[allow(dead_code)]
    name: String,
}
