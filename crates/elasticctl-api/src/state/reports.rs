//! Report and plan types for the state engine.
//!
//! Field order is the serialized JSON key order and is contractual: the root
//! `Cargo.toml` enables `serde_json`'s `preserve_order`, so reordering these
//! fields would silently change rendered output.

use crate::diff::{Change, FieldChange};
use crate::model::{ExceptionItem, ExceptionList, Rule};
use serde::Serialize;
use serde_json::Value;

/// The resolved deployment the change report records as its target.
///
/// Plain values, not `Context` or clap types, so `-api` may take them directly.
/// The caller builds this from its resolved profile.
#[derive(Debug, Clone, PartialEq)]
pub struct StackIdentity {
    pub profile: String,
    pub host: String,
    pub space: String,
}

/// The report `pull` renders.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PullReport {
    pub pulled: usize,
    pub exception_lists: usize,
    pub exception_items: usize,
    pub dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<usize>,
}

/// The report `diff` renders.
///
/// Field order is the serialized JSON key order and is contractual: the root
/// `Cargo.toml` enables `serde_json`'s `preserve_order`, so reordering these
/// fields would silently change rendered output.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiffReport {
    pub clean: bool,
    pub local: usize,
    pub remote: usize,
    pub changes: Vec<Change>,
    pub exceptions: ExceptionDrift,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_total: Option<usize>,
}

/// The summary `push` renders.
///
/// `created`, `updated`, `skipped_remote_only`, and `pending` count rules.
/// `failed` counts every failed write, rules and exceptions alike, so a failed
/// list or item write still exits nonzero. The `*_lists`/`items_*` fields name
/// the exception writes separately, so a run that creates only containers and
/// items never reads as "nothing happened".
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PushReport {
    pub applied: bool,
    pub created: usize,
    pub updated: usize,
    pub skipped_remote_only: usize,
    pub failed: usize,
    pub pending: usize,
    pub lists_created: usize,
    pub lists_updated: usize,
    pub items_created: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_total: Option<usize>,
}

/// The mirror `read_mirror` reads: every rule and exception-list file under
/// `dir`, with each list's `items` array split out.
///
/// It does not apply the reference closure itself; the state command consuming
/// the mirror narrows `lists`/`items` to what the in-scope rules reference.
#[derive(Debug)]
pub struct Mirror {
    pub rules: Vec<Rule>,
    pub lists: Vec<ExceptionList>,
    pub items: Vec<ExceptionItem>,
}

/// Exception-list drift, mirroring the rules block of `DiffReport`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExceptionDrift {
    pub local: usize,
    pub remote: usize,
    pub changes: Vec<ListChange>,
    pub dangling: Vec<DanglingPointer>,
}

impl ExceptionDrift {
    /// No container drift and no dangling pointer.
    pub fn is_clean(&self) -> bool {
        self.changes
            .iter()
            .all(|c| matches!(c, ListChange::Unchanged { .. }))
            && self.dangling.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum ListChange {
    Added {
        list_id: String,
        name: String,
    },
    Modified {
        list_id: String,
        name: String,
        fields: Vec<FieldChange>,
    },
    Unchanged {
        list_id: String,
    },
    RemoteOnly {
        list_id: String,
        name: String,
    },
    ItemAdded {
        list_id: String,
        item_id: String,
    },
    ItemModified {
        list_id: String,
        item_id: String,
        fields: Vec<FieldChange>,
    },
    ItemRemoved {
        list_id: String,
        item_id: String,
    },
}

/// A rule whose stored exception pointer does not match the live container.
///
/// `live_id` is `None` when no container with that `list_id` exists on this
/// stack.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DanglingPointer {
    pub rule_id: String,
    pub list_id: String,
    pub stored_id: Value,
    pub live_id: Option<String>,
}
