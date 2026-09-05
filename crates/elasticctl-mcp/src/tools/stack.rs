//! Read-only projections for stack diagnostics.

use std::{future::Future, pin::Pin, sync::Arc};

use elasticctl_api::{DoctorReport, InfoReport, Status, health};
use elasticctl_core::{Error, ErrorKind};
use rmcp::{
    model::{JsonObject, Tool, ToolAnnotations},
    schemars::{self, JsonSchema},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::{
    ServerState, ToolFailure, ToolSuccess,
    catalog::ToolId,
    tools::{AdapterError, AdapterResult, ToolAdapter},
};

const DOCTOR_DESCRIPTION: &str = "Run read-only health checks against the selected Elastic stack.";
const INFO_DESCRIPTION: &str =
    "Inspect the selected Elastic stack version, flavor, license tier, and spaces.";

/// The explicit adapter for the two stack diagnostic tools.
pub(crate) struct StackAdapter;

static ADAPTER: StackAdapter = StackAdapter;

/// Return the stack diagnostics adapter.
pub(crate) fn adapter() -> &'static dyn ToolAdapter {
    &ADAPTER
}

/// Return the static stack diagnostic definitions in catalog order.
pub(crate) fn definitions() -> Vec<Tool> {
    vec![
        definition::<DoctorOutput>("stack_doctor", DOCTOR_DESCRIPTION),
        definition::<InfoOutput>("stack_info", INFO_DESCRIPTION),
    ]
}

fn definition<Output: JsonSchema + 'static>(name: &'static str, description: &'static str) -> Tool {
    let tool = Tool::new(name, description, JsonObject::new())
        .with_input_schema::<StackInput>()
        .with_output_schema::<Output>()
        .with_annotations(
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(true),
        );
    let mut output_schema = tool
        .output_schema
        .as_ref()
        .expect("typed output schema is present")
        .as_ref()
        .clone();
    output_schema.insert("type".to_string(), Value::String("object".to_string()));
    tool.with_raw_output_schema(Arc::new(output_schema))
}

/// Both stack operations require an empty object.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StackInput {}

/// Safe stack identity and optional capability data.
#[derive(Debug, Serialize, JsonSchema)]
struct InfoData {
    version: String,
    flavor: String,
    license: Option<String>,
    spaces: Option<Vec<String>>,
}

impl From<InfoReport> for InfoData {
    fn from(report: InfoReport) -> Self {
        Self {
            version: report.version,
            flavor: report.flavor,
            license: report.license,
            spaces: report.spaces,
        }
    }
}

/// One doctor check with all caller-safe fields.
#[derive(Debug, Serialize, JsonSchema)]
struct DoctorCheckData {
    #[serde(rename = "check")]
    name: String,
    status: String,
}

/// The detail-free doctor report.
#[derive(Debug, Serialize, JsonSchema)]
struct DoctorData {
    ok: bool,
    checks: Vec<DoctorCheckData>,
}

impl From<DoctorReport> for DoctorData {
    fn from(report: DoctorReport) -> Self {
        Self {
            ok: report.ok,
            checks: report
                .checks
                .into_iter()
                .map(|check| DoctorCheckData {
                    name: check.name,
                    status: match check.status {
                        Status::Ok => "ok",
                        Status::Warn => "warn",
                        Status::Fail => "fail",
                    }
                    .to_string(),
                })
                .collect(),
        }
    }
}

#[allow(dead_code)] // Used only to generate the public output schema.
#[derive(JsonSchema)]
#[serde(untagged)]
enum InfoOutput {
    Success(ToolSuccess<InfoData>),
    Failure(ToolFailure),
}

#[allow(dead_code)] // Used only to generate the public output schema.
#[derive(JsonSchema)]
#[serde(untagged)]
enum DoctorOutput {
    Success(ToolSuccess<DoctorData>),
    Failure(ToolFailure),
}

impl ToolAdapter for StackAdapter {
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
            parse_input(arguments)?;
            let transport = state.transport().await.map_err(AdapterError::Core)?;
            match tool {
                ToolId::StackInfo => {
                    let report = health::info(transport).await.map_err(AdapterError::Core)?;
                    project(InfoData::from(report))
                }
                ToolId::StackDoctor => {
                    let report = health::doctor(transport)
                        .await
                        .map_err(AdapterError::Core)?;
                    project(DoctorData::from(report))
                }
                _ => Err(AdapterError::InvalidArgument),
            }
        })
    }
}

fn parse_input(arguments: Option<&JsonObject>) -> Result<(), AdapterError> {
    let arguments = arguments.cloned().unwrap_or_default();
    serde_json::from_value::<StackInput>(serde_json::Value::Object(arguments))
        .map(|_| ())
        .map_err(|_| AdapterError::InvalidArgument)
}

fn project<T: Serialize>(data: T) -> Result<AdapterResult, AdapterError> {
    serde_json::to_value(data)
        .map(|data| AdapterResult {
            data,
            page: None,
            row_key: None,
        })
        .map_err(|_| {
            AdapterError::Core(Error::new(
                ErrorKind::Error,
                "serializing MCP stack result failed",
            ))
        })
}
