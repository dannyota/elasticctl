//! Class-specific mutation planners.
pub(crate) mod rules;

use crate::{
    ToolError,
    plan::{audit, store::PlanStore},
    tools::AdapterResult,
};
use serde_json::Value;

pub(super) fn output(data: Value) -> AdapterResult {
    AdapterResult {
        data,
        page: None,
        row_key: None,
    }
}
pub(super) fn drain_closed<P: Clone>(
    sink: &audit::AuditSink,
    store: &mut PlanStore<P>,
    protocol: &str,
) {
    for snapshot in store.take_closed() {
        sink.emit(&audit::closed_line(
            audit::unix_seconds(),
            &snapshot,
            protocol,
        ));
    }
}
pub(super) fn local_error(error: ToolError) -> super::AdapterError {
    super::AdapterError::Tool(error)
}

pub(crate) mod alerts;
pub(crate) mod cases;
pub(crate) mod rules_create;

fn definition(name: &'static str, description: &'static str, input: Value) -> rmcp::model::Tool {
    let mut tool = crate::tools::plans::definition(name, description, input, false);
    tool.annotations = Some(
        rmcp::model::ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(true),
    );
    tool
}
