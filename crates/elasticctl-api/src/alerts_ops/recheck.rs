use super::*;
use crate::{Observed, Preconditions};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertFacet {
    Status,
    Presence,
}

pub async fn observe_alerts(
    t: &Transport,
    ids: &[String],
    facet: AlertFacet,
) -> Result<Preconditions> {
    super::require_targets(ids)?;
    let mut unique = Vec::with_capacity(ids.len());
    for id in ids {
        if !unique.contains(id) {
            unique.push(id.clone());
        }
    }
    let page = alerts::search(t, &super::resolve_body(&unique)).await?;
    Ok(Preconditions(
        unique
            .into_iter()
            .map(|id| {
                let state = page.hits.iter().find(|hit| hit.id == id).map(|hit| {
                    super::observed::alert_state(super::workflow_status(&hit.source), facet)
                });
                Observed {
                    object: "alert",
                    id,
                    state,
                }
            })
            .collect(),
    ))
}
