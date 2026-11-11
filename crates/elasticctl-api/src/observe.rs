//! States read from the stack for later comparison.

use elasticctl_core::{Error, ErrorKind, Result};

/// One object's state as read from the stack, in comparison form.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Observed {
    /// The object kind: "rule", "alert", or "case".
    pub object: &'static str,
    /// The object identifier.
    pub id: String,
    /// `None` when the object does not exist.
    pub state: Option<serde_json::Value>,
}

/// The object states read for a plan or re-check.
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize)]
pub struct Preconditions(pub Vec<Observed>);

impl Preconditions {
    /// Order by `object`, then `id`.
    pub fn sorted(mut self) -> Self {
        self.0
            .sort_by(|a, b| a.object.cmp(b.object).then_with(|| a.id.cmp(&b.id)));
        self
    }
}

/// Fail with kind `conflict` unless each present rule state has the expected `rule_id`.
pub fn require_rule_identity(seen: &Preconditions) -> Result<()> {
    for entry in &seen.0 {
        if entry.object == "rule"
            && let Some(state) = &entry.state
            && state.get("rule_id").and_then(serde_json::Value::as_str) != Some(&entry.id)
        {
            return Err(Error::new(
                ErrorKind::Conflict,
                "a rule read returned a different rule_id",
            ));
        }
    }
    Ok(())
}
