use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ReportEntry {
    pub rule_id: String,
    pub name: String,
    pub action: String,
    pub before: Option<Value>,
    pub after: Option<Value>,
    pub applied: bool,
    pub error: Option<String>,
    pub value_list: Option<crate::value_lists::Evidence>,
}

impl Serialize for ReportEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        if let Some(evidence) = &self.value_list {
            return evidence.serialize(serializer);
        }
        let mut value = serializer.serialize_struct("ReportEntry", 7)?;
        value.serialize_field("rule_id", &self.rule_id)?;
        value.serialize_field("name", &self.name)?;
        value.serialize_field("action", &self.action)?;
        value.serialize_field("before", &self.before)?;
        value.serialize_field("after", &self.after)?;
        value.serialize_field("applied", &self.applied)?;
        value.serialize_field("error", &self.error)?;
        value.end()
    }
}

impl From<crate::value_lists::Evidence> for ReportEntry {
    fn from(evidence: crate::value_lists::Evidence) -> Self {
        Self {
            rule_id: evidence.rule_id.clone(),
            name: evidence.name.clone(),
            action: serde_json::to_value(evidence.action)
                .expect("action serializes")
                .as_str()
                .unwrap()
                .into(),
            before: None,
            after: None,
            applied: evidence.outcome == crate::value_lists::Outcome::Applied,
            error: None,
            value_list: Some(evidence),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangeReport {
    pub profile: String,
    pub host: String,
    pub space: String,
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
            value_list: None,
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
