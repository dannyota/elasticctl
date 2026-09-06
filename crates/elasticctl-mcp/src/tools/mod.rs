//! Shared contracts and explicit registrations for the vertical MCP adapters.
//!
//! Adapter modules register here without moving admission, deadlines, result
//! shaping, or error mapping out of `server`.

use std::{future::Future, pin::Pin};

use elasticctl_core::Error;
use rmcp::model::Tool;
use tokio_util::sync::CancellationToken;

use crate::{PageInfo, ServerState, catalog::ToolId};

mod content;
mod exceptions;
mod fleet;
mod rules;
mod stack;
mod triage;

/// Typed adapter output before MCP result projection.
#[derive(Clone, Debug)]
pub struct AdapterResult {
    pub data: serde_json::Value,
    pub page: Option<PageInfo>,
    /// The array field to trim between complete rows for a list result.
    pub row_key: Option<&'static str>,
}

/// A failure an adapter may return to the central MCP boundary.
#[derive(Debug)]
pub enum AdapterError {
    /// Arguments failed typed decoding or adapter runtime validation.
    InvalidArgument,
    /// Existing API/core operation failure. Its message remains untrusted.
    Core(Error),
}

/// One vertical's explicit MCP allowlist and typed dispatch entry point.
pub trait ToolAdapter: Send + Sync {
    /// Static public definitions for this adapter's tools.
    fn definitions(&self) -> Vec<Tool>;

    /// Execute one already name-resolved tool.
    fn call<'a>(
        &'a self,
        tool: ToolId,
        arguments: Option<&'a rmcp::model::JsonObject>,
        state: &'a ServerState,
        cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<AdapterResult, AdapterError>> + Send + 'a>>;
}

/// Resolve an advertised adapter.
pub(crate) fn adapter_for(tool: ToolId) -> Option<&'static dyn ToolAdapter> {
    match tool {
        ToolId::DashboardsGet
        | ToolId::DashboardsList
        | ToolId::DataViewsDefaultGet
        | ToolId::DataViewsGet
        | ToolId::DataViewsList => Some(content::adapter()),
        ToolId::FleetAgentPoliciesGet
        | ToolId::FleetAgentPoliciesList
        | ToolId::FleetIntegrationPoliciesGet
        | ToolId::FleetIntegrationPoliciesList => Some(fleet::adapter()),
        ToolId::AlertsGet | ToolId::AlertsList | ToolId::CasesGet | ToolId::CasesList => {
            Some(triage::adapter())
        }
        ToolId::ExceptionsGet | ToolId::ExceptionsList => Some(exceptions::adapter()),
        ToolId::RulesGet | ToolId::RulesList | ToolId::RulesPrebuiltStatus => {
            Some(rules::adapter())
        }
        ToolId::StackDoctor | ToolId::StackInfo => Some(stack::adapter()),
    }
}

/// Return the production definitions in lexical catalog order.
pub(crate) fn definitions() -> Vec<Tool> {
    let mut definitions = triage::definitions();
    definitions.extend(content::definitions());
    definitions.extend(exceptions::definitions());
    definitions.extend(fleet::definitions());
    definitions.extend(rules::definitions());
    definitions.extend(stack::definitions());
    definitions
}
