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
