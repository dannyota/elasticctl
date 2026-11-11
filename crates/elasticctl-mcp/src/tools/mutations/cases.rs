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
        vec![
            super::definition(
                "cases_comment_plan",
                "Plan one comment on a case. This changes nothing. A plan lasts 15 minutes, lives in this server process only, and is applied with plan_apply after a person confirms in the client.",
                json!({"type": "object", "properties": {"id": {"type": "string", "minLength": 1, "maxLength": 1024}, "message": {"type": "string", "minLength": 1, "maxLength": 4096}}, "required": ["id", "message"], "additionalProperties": false}),
            ),
            super::definition(
                "cases_create_plan",
                "Plan one new case. This changes nothing. A plan lasts 15 minutes, lives in this server process only, and is applied with plan_apply after a person confirms in the client.",
                json!({"type": "object", "properties": {"title": {"type": "string", "minLength": 1, "maxLength": 160}, "description": {"type": "string", "minLength": 1, "maxLength": 4096}, "tags": {"type": "array", "minItems": 0, "maxItems": 10, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 256}}, "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]}}, "required": ["title"], "additionalProperties": false}),
            ),
            super::definition(
                "cases_set_status_plan",
                "Plan closing or reopening cases. This changes nothing. A plan lasts 15 minutes, lives in this server process only, and is applied with plan_apply after a person confirms in the client.",
                json!({"type": "object", "properties": {"ids": {"type": "array", "minItems": 1, "maxItems": 20, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 1024}}, "status": {"type": "string", "enum": ["open", "closed"]}}, "required": ["ids", "status"], "additionalProperties": false}),
            ),
        ]
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
struct CommentInput {
    id: String,
    message: String,
}
#[allow(dead_code)] // The planner consumes these arguments when implemented.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateInput {
    title: String,
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    severity: Option<String>,
}
#[allow(dead_code)] // The planner consumes these arguments when implemented.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusInput {
    ids: Vec<String>,
    status: String,
}
