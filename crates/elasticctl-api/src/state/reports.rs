use crate::diff::{Change, FieldChange};
use crate::model::{ExceptionItem, ExceptionList, Rule};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct StackIdentity {
    pub profile: String,
    pub host: String,
    pub space: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PullReport {
    pub pulled: usize,
    pub exception_lists: usize,
    pub exception_items: usize,
    pub dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiffReport {
    pub clean: bool,
    pub local: usize,
    pub remote: usize,
    pub changes: Vec<Change>,
    pub exceptions: ExceptionDrift,
    #[serde(skip_serializing_if = "is_zero")]
    pub out_of_scope: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_total: Option<usize>,
}

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
    pub items_updated: usize,
    pub items_removed: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub out_of_scope: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_total: Option<usize>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Debug)]
pub struct Mirror {
    pub rules: Vec<Rule>,
    pub lists: Vec<ExceptionList>,
    pub items: Vec<ExceptionItem>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExceptionDrift {
    pub local: usize,
    pub remote: usize,
    pub changes: Vec<ListChange>,
    pub dangling: Vec<DanglingPointer>,
}

impl ExceptionDrift {
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

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DanglingPointer {
    pub rule_id: String,
    pub list_id: String,
    pub stored_id: Value,
    pub live_id: Option<String>,
}
