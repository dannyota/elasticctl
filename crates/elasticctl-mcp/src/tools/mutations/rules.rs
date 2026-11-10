//! Rule toggle planner definition and adapter.
use crate::{
    ServerState,
    catalog::ToolId,
    tools::{AdapterError, AdapterResult, ToolAdapter, plans},
};
use rmcp::model::{JsonObject, Tool};
use serde_json::json;
use std::{future::Future, pin::Pin};
use tokio_util::sync::CancellationToken;

struct RulesAdapter;
static ADAPTER: RulesAdapter = RulesAdapter;
pub(crate) fn adapter() -> &'static dyn ToolAdapter {
    &ADAPTER
}

impl ToolAdapter for RulesAdapter {
    fn definitions(&self) -> Vec<Tool> {
        vec![plans::definition(
            "rules_set_enabled_plan",
            "Plan enabling or disabling rules. This changes nothing. A plan lasts 15 minutes, lives in this server process only, and is applied with plan_apply after a person confirms in the client.",
            json!({
                "type":"object", "properties":{
                    "selectors":{"type":"array","minItems":1,"maxItems":20,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":1024}},
                    "enabled":{"type":"boolean"}
                },"required":["selectors","enabled"],"additionalProperties":false
            }),
            false,
        )]
    }
    fn call<'a>(
        &'a self,
        _tool: ToolId,
        _arguments: Option<&'a JsonObject>,
        _state: &'a ServerState,
        _cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<AdapterResult, AdapterError>> + Send + 'a>> {
        Box::pin(async { Err(plans::unsupported()) })
    }
}
