//! Read-only projections for Fleet agent and integration policies.

use std::{future::Future, pin::Pin, sync::Arc};

use elasticctl_api::fleet::{
    agent_policies::{AgentPolicyDetail, AgentPolicySummary},
    agent_policy_ops::{self, AgentPolicyFilter},
    integration_policies::{
        IntegrationPackageSpec, IntegrationPolicyDetail, IntegrationPolicySummary,
    },
    integration_policy_ops::{self, IntegrationPolicyFilter},
};
use elasticctl_core::{Error, ErrorKind};
use rmcp::{
    model::{JsonObject, Tool, ToolAnnotations},
    schemars::{self, JsonSchema},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::{
    PageInfo, ServerState, ToolFailure, ToolSuccess,
    catalog::ToolId,
    server::{validate_limit, validate_text},
    tools::{AdapterError, AdapterResult, ToolAdapter},
};

const DEFAULT_LIMIT: usize = 50;
const MAX_TEXT_BYTES: usize = 1_024;

pub(crate) struct FleetAdapter;
static ADAPTER: FleetAdapter = FleetAdapter;

pub(crate) fn adapter() -> &'static dyn ToolAdapter {
    &ADAPTER
}

pub(crate) fn definitions() -> Vec<Tool> {
    vec![
        definition::<AgentPoliciesGetInput, AgentPoliciesGetOutput>(
            "fleet_agent_policies_get",
            "Inspect one Fleet agent policy by exact id or name.",
        ),
        definition::<AgentPoliciesListInput, AgentPoliciesListOutput>(
            "fleet_agent_policies_list",
            "List read-only Fleet agent policies from the selected stack.",
        ),
        definition::<IntegrationPoliciesGetInput, IntegrationPoliciesGetOutput>(
            "fleet_integration_policies_get",
            "Inspect one Fleet integration policy by exact id or name.",
        ),
        definition::<IntegrationPoliciesListInput, IntegrationPoliciesListOutput>(
            "fleet_integration_policies_list",
            "List read-only Fleet integration policies from the selected stack.",
        ),
    ]
}

fn definition<Input: JsonSchema + 'static, Output: JsonSchema + 'static>(
    name: &'static str,
    description: &'static str,
) -> Tool {
    let tool = Tool::new(name, description, JsonObject::new())
        .with_input_schema::<Input>()
        .with_output_schema::<Output>()
        .with_annotations(
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(true),
        );
    let mut schema = tool
        .output_schema
        .as_ref()
        .expect("typed schema")
        .as_ref()
        .clone();
    schema.insert("type".into(), Value::String("object".into()));
    tool.with_raw_output_schema(Arc::new(schema))
}
fn default_limit() -> usize {
    DEFAULT_LIMIT
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AgentPoliciesListInput {
    #[serde(default = "default_limit")]
    #[schemars(default = "default_limit")]
    #[schemars(range(min = 1, max = 200))]
    limit: usize,
    /// Agent-policy id or name substring. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    search: Option<String>,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct IntegrationPoliciesListInput {
    #[serde(default = "default_limit")]
    #[schemars(default = "default_limit")]
    #[schemars(range(min = 1, max = 200))]
    limit: usize,
    /// Integration-policy id or name substring. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    search: Option<String>,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AgentPoliciesGetInput {
    /// Exact Fleet agent-policy id or exact name. Must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    selector: String,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct IntegrationPoliciesGetInput {
    /// Exact Fleet integration-policy id or exact name. Must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    selector: String,
}

impl AgentPoliciesListInput {
    fn into_filter(self) -> Result<(usize, AgentPolicyFilter), AdapterError> {
        validate_limit(self.limit).map_err(|_| AdapterError::InvalidArgument)?;
        if let Some(search) = self.search.as_deref() {
            validate_text("search", search, MAX_TEXT_BYTES)
                .map_err(|_| AdapterError::InvalidArgument)?;
        }
        Ok((
            self.limit,
            AgentPolicyFilter {
                search: self.search,
                limit: None,
            },
        ))
    }
}
impl IntegrationPoliciesListInput {
    fn into_filter(self) -> Result<(usize, IntegrationPolicyFilter), AdapterError> {
        validate_limit(self.limit).map_err(|_| AdapterError::InvalidArgument)?;
        if let Some(search) = self.search.as_deref() {
            validate_text("search", search, MAX_TEXT_BYTES)
                .map_err(|_| AdapterError::InvalidArgument)?;
        }
        Ok((
            self.limit,
            IntegrationPolicyFilter {
                search: self.search,
                limit: None,
            },
        ))
    }
}
impl AgentPoliciesGetInput {
    fn selector(self) -> Result<String, AdapterError> {
        validate_text("selector", &self.selector, MAX_TEXT_BYTES)
            .map_err(|_| AdapterError::InvalidArgument)?;
        Ok(self.selector)
    }
}
impl IntegrationPoliciesGetInput {
    fn selector(self) -> Result<String, AdapterError> {
        validate_text("selector", &self.selector, MAX_TEXT_BYTES)
            .map_err(|_| AdapterError::InvalidArgument)?;
        Ok(self.selector)
    }
}

#[derive(Debug, Serialize, JsonSchema)]
struct AgentPolicyData {
    id: String,
    name: String,
    namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agents: Option<u64>,
}
#[derive(Debug, Serialize, JsonSchema)]
struct AgentPolicyDetailData {
    id: String,
    name: String,
    namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    agents: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    attached_integrations: Vec<String>,
    blocked_by: Vec<String>,
}
#[derive(Debug, Serialize, JsonSchema)]
struct PackageData {
    name: String,
    version: String,
}
#[derive(Debug, Serialize, JsonSchema)]
struct IntegrationPolicyData {
    id: String,
    name: String,
    namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    policy_ids: Vec<String>,
    package: PackageData,
}
#[derive(Debug, Serialize, JsonSchema)]
struct IntegrationPolicyDetailData {
    id: String,
    name: String,
    namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    policy_ids: Vec<String>,
    package: PackageData,
    affected_agents: u64,
    blocked_by: Vec<String>,
}
#[derive(Debug, Serialize, JsonSchema)]
struct AgentPoliciesListData {
    agent_policies: Vec<AgentPolicyData>,
}
#[derive(Debug, Serialize, JsonSchema)]
struct IntegrationPoliciesListData {
    integration_policies: Vec<IntegrationPolicyData>,
}

macro_rules! output {
    ($name:ident, $data:ty) => {
        #[allow(dead_code, clippy::large_enum_variant)]
        #[derive(JsonSchema)]
        #[serde(untagged)]
        enum $name {
            Success(ToolSuccess<$data>),
            Failure(ToolFailure),
        }
    };
}
output!(AgentPoliciesListOutput, AgentPoliciesListData);
output!(AgentPoliciesGetOutput, AgentPolicyDetailData);
output!(IntegrationPoliciesListOutput, IntegrationPoliciesListData);
output!(IntegrationPoliciesGetOutput, IntegrationPolicyDetailData);

impl ToolAdapter for FleetAdapter {
    fn definitions(&self) -> Vec<Tool> {
        definitions()
    }
    fn call<'a>(
        &'a self,
        tool: ToolId,
        arguments: Option<&'a JsonObject>,
        state: &'a ServerState,
        _cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<AdapterResult, AdapterError>> + Send + 'a>> {
        Box::pin(async move {
            match tool {
                ToolId::FleetAgentPoliciesList => {
                    let (limit, filter) =
                        parse_input::<AgentPoliciesListInput>(arguments)?.into_filter()?;
                    let report = agent_policy_ops::list_op(
                        state.transport().await.map_err(AdapterError::Core)?,
                        &filter,
                    )
                    .await
                    .map_err(AdapterError::Core)?;
                    let total = report.agent_policies.len();
                    let mut rows = report
                        .agent_policies
                        .iter()
                        .map(agent_summary)
                        .collect::<Vec<_>>();
                    rows.truncate(limit);
                    list(
                        AgentPoliciesListData {
                            agent_policies: rows,
                        },
                        limit,
                        total,
                        "agent_policies",
                    )
                }
                ToolId::FleetAgentPoliciesGet => {
                    let selector = parse_input::<AgentPoliciesGetInput>(arguments)?.selector()?;
                    let detail = agent_policy_ops::get_op(
                        state.transport().await.map_err(AdapterError::Core)?,
                        &selector,
                    )
                    .await
                    .map_err(AdapterError::Core)?;
                    project(agent_detail(&detail), None, None)
                }
                ToolId::FleetIntegrationPoliciesList => {
                    let (limit, filter) =
                        parse_input::<IntegrationPoliciesListInput>(arguments)?.into_filter()?;
                    let report = integration_policy_ops::list_op(
                        state.transport().await.map_err(AdapterError::Core)?,
                        &filter,
                    )
                    .await
                    .map_err(AdapterError::Core)?;
                    let total = report.integration_policies.len();
                    let mut rows = report
                        .integration_policies
                        .iter()
                        .map(integration_summary)
                        .collect::<Vec<_>>();
                    rows.truncate(limit);
                    list(
                        IntegrationPoliciesListData {
                            integration_policies: rows,
                        },
                        limit,
                        total,
                        "integration_policies",
                    )
                }
                ToolId::FleetIntegrationPoliciesGet => {
                    let selector =
                        parse_input::<IntegrationPoliciesGetInput>(arguments)?.selector()?;
                    let detail = integration_policy_ops::get_op(
                        state.transport().await.map_err(AdapterError::Core)?,
                        &selector,
                    )
                    .await
                    .map_err(AdapterError::Core)?;
                    project(integration_detail(&detail), None, None)
                }
                _ => Err(AdapterError::InvalidArgument),
            }
        })
    }
}

fn parse_input<T: DeserializeOwned>(arguments: Option<&JsonObject>) -> Result<T, AdapterError> {
    serde_json::from_value(Value::Object(arguments.cloned().unwrap_or_default()))
        .map_err(|_| AdapterError::InvalidArgument)
}
fn package(package: &IntegrationPackageSpec) -> PackageData {
    PackageData {
        name: package.name.clone(),
        version: package.version.clone(),
    }
}
fn agent_summary(row: &AgentPolicySummary) -> AgentPolicyData {
    AgentPolicyData {
        id: row.id.clone(),
        name: row.name.clone(),
        namespace: row.namespace.clone(),
        description: row.description.clone(),
        agents: row.agents,
    }
}
fn agent_detail(row: &AgentPolicyDetail) -> AgentPolicyDetailData {
    AgentPolicyDetailData {
        id: row.id.clone(),
        name: row.name.clone(),
        namespace: row.namespace.clone(),
        description: row.description.clone(),
        agents: row.agents,
        status: row.status.clone(),
        attached_integrations: row.attached_integrations.clone(),
        blocked_by: row.blocked_by.clone(),
    }
}
fn integration_summary(row: &IntegrationPolicySummary) -> IntegrationPolicyData {
    IntegrationPolicyData {
        id: row.id.clone(),
        name: row.name.clone(),
        namespace: row.namespace.clone(),
        description: row.description.clone(),
        policy_ids: row.policy_ids.clone(),
        package: package(&row.package),
    }
}
fn integration_detail(row: &IntegrationPolicyDetail) -> IntegrationPolicyDetailData {
    IntegrationPolicyDetailData {
        id: row.id.clone(),
        name: row.name.clone(),
        namespace: row.namespace.clone(),
        description: row.description.clone(),
        policy_ids: row.policy_ids.clone(),
        package: package(&row.package),
        affected_agents: row.affected_agents,
        blocked_by: row.blocked_by.clone(),
    }
}
fn list<T: Serialize>(
    data: T,
    limit: usize,
    total: usize,
    row_key: &'static str,
) -> Result<AdapterResult, AdapterError> {
    let returned = total.min(limit);
    project(
        data,
        Some(PageInfo {
            limit,
            returned,
            total: Some(u64::try_from(total).map_err(|_| AdapterError::Core(projection_error()))?),
            has_more: Some(returned < total),
            truncated: returned < total,
        }),
        Some(row_key),
    )
}
fn project<T: Serialize>(
    data: T,
    page: Option<PageInfo>,
    row_key: Option<&'static str>,
) -> Result<AdapterResult, AdapterError> {
    serde_json::to_value(data)
        .map(|data| AdapterResult {
            data,
            page,
            row_key,
        })
        .map_err(|_| AdapterError::Core(projection_error()))
}
fn projection_error() -> Error {
    Error::new(
        ErrorKind::Http,
        "the selected deployment returned an invalid Fleet projection",
    )
}
