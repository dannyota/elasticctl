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
