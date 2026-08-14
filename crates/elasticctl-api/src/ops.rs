//! Report types shared across command verticals.
//!
//! The rules, exceptions, and prebuilt verticals all preview a mutation, apply
//! it behind a guard, and report the outcome. These four shapes are the shared
//! contract so `render` sees one shape per report kind rather than a near copy
//! per vertical. Field order is the serialized JSON key order and is
//! contractual: the root `Cargo.toml` enables `serde_json`'s `preserve_order`,
//! so reordering these fields would silently change rendered output.

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

/// The summary a bulk mutation reports after applying.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MutationOutcome {
    pub applied: bool,
    pub succeeded: u64,
    pub failed: u64,
    pub errors: Vec<Value>,
}

/// A file-producing export: the encoded body and its counts.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportOutcome {
    pub body: String,
    pub exported: u64,
    pub missing: Vec<Value>,
}

/// The summary an import reports after applying.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportOutcome {
    pub applied: bool,
    pub created: u64,
    pub skipped: u64,
    pub failed: u64,
    pub errors: Vec<Value>,
}
