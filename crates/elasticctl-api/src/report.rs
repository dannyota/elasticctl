//! Change evidence for a `push` attached to a change ticket.
//!
//! Records the proposed and applied changes, with values on both sides.

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
    /// `false` for a dry run.
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

    /// Proposed `create` and `update` entries with neither success nor error.
    /// A dry run leaves all actionable entries pending. After `push` runs,
    /// pending is zero: each actionable entry succeeds or fails. Pending means
    /// it awaits `--yes`, not that it failed.
    pub fn pending(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| {
                matches!(e.action.as_str(), "create" | "update") && !e.applied && e.error.is_none()
            })
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(action: &str, applied: bool, error: Option<&str>) -> ReportEntry {
        ReportEntry {
            rule_id: "x".into(),
            name: "X".into(),
            action: action.into(),
            before: None,
            after: None,
            applied,
            error: error.map(String::from),
        }
    }

    fn report(entries: Vec<ReportEntry>) -> ChangeReport {
        ChangeReport {
            profile: "default".into(),
            host: "kb.example.com".into(),
            space: "default".into(),
            applied: false,
            entries,
        }
    }

    #[test]
    fn pending_counts_unapplied_unfailed_create_and_update_entries() {
        let r = report(vec![
            entry("create", false, None),
            entry("update", false, None),
            entry("skipped_remote_only", false, None),
        ]);
        assert_eq!(r.pending(), 2);
    }

    #[test]
    fn pending_is_zero_once_every_actionable_entry_has_an_outcome() {
        let r = report(vec![
            entry("create", true, None),
            entry("update", false, Some("conflict")),
        ]);
        assert_eq!(r.pending(), 0, "applied or failed entries are not pending");
    }

    #[test]
    fn counts_are_unaffected_by_pending_entries() {
        let r = report(vec![
            entry("create", false, None),
            entry("update", true, None),
        ]);
        let (created, updated, skipped, failed) = r.counts();
        assert_eq!((created, updated, skipped, failed), (0, 1, 0, 0));
    }
}
