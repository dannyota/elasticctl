use elasticctl_core::{Error, ErrorKind, Result};

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Observed {
    pub object: &'static str,
    pub id: String,
    pub state: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Default, serde::Serialize)]
pub struct Preconditions(pub Vec<Observed>);

impl Preconditions {
    pub fn sorted(mut self) -> Self {
        self.0
            .sort_by(|a, b| a.object.cmp(b.object).then_with(|| a.id.cmp(&b.id)));
        self
    }
}

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
