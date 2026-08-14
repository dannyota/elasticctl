//! Report types shared across command verticals.
//!
//! A type lives here because more than one vertical consumes it; per-command
//! outcome shapes deliberately do not. `MutationPlan` and `ExportOutcome` are
//! the shared shapes today. Field order is the serialized JSON key order and
//! is contractual: the root `Cargo.toml` enables `serde_json`'s
//! `preserve_order`, so reordering these fields would silently change rendered
//! output.

use serde::Serialize;
use serde_json::Value;

/// What a guarded mutation will do, shown in the guard banner.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MutationPlan {
    pub preview_action: String,
    pub preview_details: Vec<String>,
    /// Object identities the plan will act on: `rule_id` values in the rules
    /// vertical, `list_id` values in the exceptions vertical.
    pub targets: Vec<String>,
}

/// A file-producing export: the encoded body and its counts.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportOutcome {
    pub body: String,
    pub exported: u64,
    pub missing: Vec<Value>,
}

/// The report a `delete` apply renders. Shared by the rules and exceptions
/// verticals: each reports the same applied/deleted/failed/total shape, only
/// the per-object entries differ (`rule_id` versus `list_id`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeleteOutcome {
    pub applied: bool,
    pub deleted: Vec<Value>,
    pub failed: Vec<Value>,
    pub total: usize,
}

/// The upload half of an import, before the caller adds the plan's totals.
/// Shared by the rules and exceptions verticals: both normalise Kibana's
/// import response to a succeeded count and an errors array.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportReport {
    pub succeeded: Value,
    pub failed: Value,
}
