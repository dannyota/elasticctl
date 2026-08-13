//! The change-evidence report. Written so a push can be attached to a change
//! ticket: what was proposed, what was applied, and what the values were on
//! each side.

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
pub struct ReportEntry {
    pub rule_id: String,
    pub name: String,
    /// `create`, `update`, or `skipped_remote_only`.
    pub action: String,
    pub before: Option<Value>,
    pub after: Option<Value>,
    pub applied: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangeReport {
    pub profile: String,
    pub host: String,
    pub space: String,
    /// False for a dry run.
    pub applied: bool,
    pub entries: Vec<ReportEntry>,
}

impl ChangeReport {
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let created = self
            .entries
            .iter()
            .filter(|e| e.action == "create" && e.applied)
            .count();
        let updated = self
            .entries
            .iter()
            .filter(|e| e.action == "update" && e.applied)
            .count();
        let skipped = self
            .entries
            .iter()
            .filter(|e| e.action == "skipped_remote_only")
            .count();
        let failed = self.entries.iter().filter(|e| e.error.is_some()).count();
        (created, updated, skipped, failed)
    }
}
