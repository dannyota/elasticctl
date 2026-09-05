//! Shared contracts for the vertical MCP adapters.
//!
//! The Task 2 catalog is deliberately empty. Later adapter modules implement
//! these contracts and register through this module without moving admission,
//! deadlines, result shaping, or error mapping out of `server`.

use std::{future::Future, pin::Pin};

use elasticctl_core::Error;
use rmcp::model::Tool;
use tokio_util::sync::CancellationToken;

use crate::{PageInfo, ServerState, catalog::ToolId};

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

/// Resolve an advertised adapter. The foundation publishes no vertical tools.
pub(crate) fn adapter_for(_tool: ToolId) -> Option<&'static dyn ToolAdapter> {
    None
}

/// Return the production definitions. Adapter tasks extend this explicit list.
pub(crate) fn definitions() -> Vec<Tool> {
    Vec::new()
}
