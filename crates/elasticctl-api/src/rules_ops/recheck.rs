use super::*;
use crate::observe::{Observed, Preconditions};

pub async fn observe_rules(t: &Transport, rule_ids: &[String]) -> Result<Preconditions> {
    let mut entries = Vec::with_capacity(rule_ids.len());
    for id in rule_ids {
        let state = match rules::get(t, id).await {
            Ok(rule) => Some(normalize::canonical(&rule).into_value()),
            Err(err) if err.kind == ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };
        entries.push(Observed {
            object: "rule",
            id: id.clone(),
            state,
        });
    }
    Ok(Preconditions(entries))
}
