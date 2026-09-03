//! Typed integration-policy models and public Fleet route wrappers.

use elasticctl_core::{Error, ErrorKind, Feature, Result, Transport, urlencode};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

const BASE: &str = "/api/fleet/package_policies";
const PACKAGES: &str = "/api/fleet/epm/packages";

/// The exact package coordinate required by a portable integration policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationPackageSpec {
    pub name: String,
    pub version: String,
}

/// The portable, author-controlled integration-policy representation.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IntegrationPolicySpec {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub policy_ids: Vec<String>,
    pub package: IntegrationPackageSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vars: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub var_group_selections: Option<Map<String, Value>>,
    pub inputs: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_datastreams_permissions: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIntegrationPolicySpec {
    id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    policy_ids: Vec<String>,
    package: IntegrationPackageSpec,
    #[serde(default)]
    vars: Option<Map<String, Value>>,
    #[serde(default)]
    var_group_selections: Option<Map<String, Value>>,
    inputs: Map<String, Value>,
    #[serde(default)]
    condition: Option<String>,
    #[serde(default)]
    additional_datastreams_permissions: Option<Vec<String>>,
}

impl IntegrationPolicySpec {
    fn from_raw(raw: RawIntegrationPolicySpec) -> Result<Self> {
        let spec = Self {
            id: raw.id,
            name: raw.name,
            description: raw.description,
            namespace: raw.namespace,
            policy_ids: raw.policy_ids,
            package: raw.package,
            vars: raw.vars,
            var_group_selections: raw.var_group_selections,
            inputs: raw.inputs,
            condition: raw.condition,
            additional_datastreams_permissions: raw.additional_datastreams_permissions,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Validate a portable 0.6.1 integration-policy artifact.
    pub fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("id", &self.id),
            ("name", &self.name),
            ("package.name", &self.package.name),
            ("package.version", &self.package.version),
        ] {
            if value.trim().is_empty() {
                return Err(Error::new(
                    ErrorKind::Error,
                    format!("integration policy {field} must not be empty"),
                ));
            }
        }
        if self.policy_ids.is_empty() {
            return Err(Error::new(
                ErrorKind::Error,
                "integration policy policy_ids must not be empty",
            ));
        }
        let mut previous = None;
        for policy_id in &self.policy_ids {
            if policy_id.trim().is_empty() {
                return Err(Error::new(
                    ErrorKind::Error,
                    "integration policy policy_ids must not contain an empty id",
                ));
            }
            if previous.is_some_and(|previous: &String| previous >= policy_id) {
                return Err(Error::new(
                    ErrorKind::Error,
                    "integration policy policy_ids must be sorted and duplicate-free",
                ));
            }
            previous = Some(policy_id);
        }
        if let Some(selections) = &self.var_group_selections {
            for (name, selection) in selections {
                if !selection.is_string() {
                    return Err(Error::new(
                        ErrorKind::Error,
                        format!("integration policy var_group_selections.{name} must be a string"),
                    ));
                }
            }
        }
        Ok(())
    }
}

impl TryFrom<Value> for IntegrationPolicySpec {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self> {
        serde_json::from_value(value).map_err(|error| {
            Error::new(
                ErrorKind::Error,
                format!("decoding integration policy: {error}"),
            )
        })
    }
}

impl<'de> Deserialize<'de> for IntegrationPolicySpec {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawIntegrationPolicySpec::deserialize(deserializer)?;
        Self::from_raw(raw).map_err(serde::de::Error::custom)
    }
}

/// A safe integration-policy list row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntegrationPolicySummary {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub description: Option<String>,
    pub policy_ids: Vec<String>,
    pub package: IntegrationPackageSpec,
}

/// Safe single-integration output. Raw Fleet items are never rendered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntegrationPolicyDetail {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub description: Option<String>,
    pub policy_ids: Vec<String>,
    pub package: IntegrationPackageSpec,
    pub affected_agents: u64,
    pub blocked_by: Vec<String>,
}

/// One page of the paginated simplified list route.
#[derive(Debug, Clone, PartialEq)]
pub struct IntegrationPolicyPage {
    pub items: Vec<Map<String, Value>>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
}

/// A single integration as returned by its read, create, or update route.
#[derive(Debug, Clone, PartialEq)]
pub struct IntegrationPolicy {
    pub item: Map<String, Value>,
}

/// Exact package metadata retained for internal secret classification only.
#[derive(Debug, Clone, PartialEq)]
pub struct PackageMetadata {
    pub(crate) item: Map<String, Value>,
}

/// Read one page of the simplified list route with deterministic ordering.
pub async fn list_page(transport: &Transport, page: u64) -> Result<IntegrationPolicyPage> {
    transport.require_feature(Feature::FleetPolicies).await?;
    let body = transport
        .get(&format!(
            "{BASE}?page={page}&perPage=1000&sortField=created_at&sortOrder=asc&format=simplified"
        ))
        .await?;
    let envelope: PageEnvelope = decode(&body, "integration policies list")?;
    Ok(IntegrationPolicyPage {
        items: envelope.items,
        total: envelope.total,
        page: envelope.page,
        per_page: envelope.per_page,
    })
}

/// Read one integration by its stable id in simplified form.
pub async fn get(transport: &Transport, id: &str) -> Result<IntegrationPolicy> {
    transport.require_feature(Feature::FleetPolicies).await?;
    decode_item(
        &transport
            .get(&format!("{}?format=simplified", policy_path(id)))
            .await?,
        "integration policy get",
    )
}

/// Create an integration from its complete portable specification.
pub async fn create(
    transport: &Transport,
    spec: &IntegrationPolicySpec,
) -> Result<IntegrationPolicy> {
    transport.require_feature(Feature::FleetPolicies).await?;
    spec.validate()?;
    let body = encode_spec(spec, "create")?;
    decode_item(
        &transport.post(BASE, Some(&body)).await?,
        "integration policy create",
    )
}

/// Replace an integration with its complete portable specification.
pub async fn update(
    transport: &Transport,
    id: &str,
    spec: &IntegrationPolicySpec,
) -> Result<IntegrationPolicy> {
    transport.require_feature(Feature::FleetPolicies).await?;
    spec.validate()?;
    let mut body = encode_spec(spec, "update")?;
    let object = body
        .as_object_mut()
        .expect("integration policy serialization is an object");
    object.remove("id");
    object.insert("enabled".into(), Value::Bool(true));
    decode_item(
        &transport.put(&policy_path(id), &body).await?,
        "integration policy update",
    )
}

/// Delete one integration by id. Never sends `force`.
pub async fn delete(transport: &Transport, id: &str) -> Result<()> {
    transport.require_feature(Feature::FleetPolicies).await?;
    let response = transport.delete(&policy_path(id)).await?;
    let deleted: DeleteEnvelope = decode(&response, "integration policy delete")?;
    if deleted.id != id {
        return Err(Error::with_status(
            ErrorKind::Http,
            200,
            format!(
                "decoding integration policy delete: expected id '{id}', got '{}'",
                deleted.id
            ),
        ));
    }
    Ok(())
}

/// Read exact package metadata for internal package-secret classification.
pub async fn package_metadata(
    transport: &Transport,
    name: &str,
    version: &str,
) -> Result<PackageMetadata> {
    transport.require_feature(Feature::FleetPolicies).await?;
    let body = transport
        .get(&format!(
            "{PACKAGES}/{}/{}",
            urlencode(name),
            urlencode(version)
        ))
        .await?;
    let envelope: ItemEnvelope = decode(&body, "integration package metadata")?;
    let returned_name = required_string(&envelope.item, "name", "integration package metadata")?;
    let returned_version =
        required_string(&envelope.item, "version", "integration package metadata")?;
    if returned_name != name || returned_version != version {
        return Err(Error::new(
            ErrorKind::Http,
            format!(
                "decoding integration package metadata: expected {name}@{version}, got {returned_name}@{returned_version}"
            ),
        ));
    }
    Ok(PackageMetadata {
        item: envelope.item,
    })
}

fn encode_spec(spec: &IntegrationPolicySpec, context: &str) -> Result<Value> {
    serde_json::to_value(spec).map_err(|error| {
        Error::new(
            ErrorKind::Error,
            format!("encoding integration policy {context}: {error}"),
        )
    })
}

fn policy_path(id: &str) -> String {
    format!("{BASE}/{}", urlencode(id))
}

fn decode_item(body: &Value, context: &str) -> Result<IntegrationPolicy> {
    let envelope: ItemEnvelope = decode(body, context)?;
    Ok(IntegrationPolicy {
        item: envelope.item,
    })
}

fn decode<T: serde::de::DeserializeOwned>(body: &Value, context: &str) -> Result<T> {
    serde_json::from_value(body.clone())
        .map_err(|error| Error::new(ErrorKind::Http, format!("decoding {context}: {error}")))
}

fn required_string(item: &Map<String, Value>, field: &str, context: &str) -> Result<String> {
    item.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                format!("decoding {context}: {field} must be a non-empty string"),
            )
        })
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
}
