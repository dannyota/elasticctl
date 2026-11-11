//! Static mutation planner definitions.
use crate::{
    ServerState,
    catalog::ToolId,
    tools::{AdapterError, AdapterResult, ToolAdapter},
};
use rmcp::model::{JsonObject, Tool};
use serde_json::json;
use std::{future::Future, pin::Pin};
use tokio_util::sync::CancellationToken;
struct Adapter;
static ADAPTER: Adapter = Adapter;
pub(crate) fn adapter() -> &'static dyn ToolAdapter {
    &ADAPTER
}
impl ToolAdapter for Adapter {
    fn definitions(&self) -> Vec<Tool> {
        vec![super::definition(
            "rules_create_plan",
            "Plan one new rule, created disabled. This changes nothing. A plan lasts 15 minutes, lives in this server process only, and is applied with plan_apply after a person confirms in the client.",
            json!({"type": "object", "properties": {"rule": {"type": "object"}}, "required": ["rule"], "additionalProperties": false}),
        )]
    }
    fn call<'a>(
        &'a self,
        _tool: ToolId,
        _arguments: Option<&'a JsonObject>,
        _state: &'a ServerState,
        _cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<AdapterResult, AdapterError>> + Send + 'a>> {
        Box::pin(async {
            Err(AdapterError::Core(elasticctl_core::Error::new(
                elasticctl_core::ErrorKind::Unsupported,
                "This planner is unavailable.",
            )))
        })
    }
}
#[allow(dead_code)] // The planner consumes these arguments when implemented.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    rule: serde_json::Value,
}
