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
                "alerts_set_status_plan",
                "Plan a status change for alerts by id. This changes nothing. A plan lasts 15 minutes, lives in this server process only, and is applied with plan_apply after a person confirms in the client.",
                json!({"type": "object", "properties": {"alert_ids": {"type": "array", "minItems": 1, "maxItems": 20, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 1024}}, "status": {"type": "string", "enum": ["open", "acknowledged", "closed"]}, "reason": {"type": "string", "enum": ["false_positive", "duplicate", "true_positive", "benign_positive", "automated_closure", "other"]}}, "required": ["alert_ids", "status"], "additionalProperties": false}),
            ),
            super::definition(
                "alerts_set_tags_plan",
                "Plan adding and removing alert tags by id. This changes nothing. A plan lasts 15 minutes, lives in this server process only, and is applied with plan_apply after a person confirms in the client.",
                json!({"type": "object", "properties": {"alert_ids": {"type": "array", "minItems": 1, "maxItems": 20, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 1024}}, "add": {"type": "array", "minItems": 0, "maxItems": 10, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 256}}, "remove": {"type": "array", "minItems": 0, "maxItems": 10, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 256}}}, "required": ["alert_ids"], "additionalProperties": false}),
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
struct StatusInput {
    alert_ids: Vec<String>,
    status: String,
    reason: Option<String>,
}
#[allow(dead_code)] // The planner consumes these arguments when implemented.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TagsInput {
    alert_ids: Vec<String>,
    #[serde(default)]
    add: Vec<String>,
    #[serde(default)]
    remove: Vec<String>,
}
