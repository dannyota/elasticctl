//! Report types shared across command verticals.
//!
//! A type lives here because more than one vertical consumes it; per-command
//! outcome shapes deliberately do not. Field order is the serialized JSON key
//! order and is contractual: the root `Cargo.toml` enables `serde_json`'s
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
    /// vertical; `list_id` and `item_id` values in the exceptions vertical.
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

/// What `plan_import` computed and `apply_import` uploads. Shared by the rules
/// and exceptions verticals: the plan, the re-encoded NDJSON, the in-file
/// object count, and the objects `--skip-existing` removed.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportPlan {
    pub preview: MutationPlan,
    /// The file re-encoded as NDJSON, resolved once at plan time so the apply
    /// never re-reads the file after the guard.
    pub ndjson: String,
    /// Every object in the file, before `--skip-existing`.
    pub total: usize,
    /// Objects the server already has, with `--skip-existing`.
    pub skipped: Vec<Value>,
}

/// The upload half of an import, before the caller adds the plan's totals.
/// Shared by the rules and exceptions verticals: both normalize Kibana's
/// import response to a succeeded count and an errors array.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportReport {
    pub succeeded: Value,
    pub failed: Value,
}
