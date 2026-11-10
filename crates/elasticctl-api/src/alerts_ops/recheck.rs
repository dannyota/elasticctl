//! Alert state re-checks.

use super::*;
use crate::{Observed, Preconditions};

/// The alert state needed for a re-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertFacet {
    /// Compare workflow status.
    Status,
    /// Compare presence only.
    Presence,
}

/// Read alert states by ID, returning absent state for missing alerts.
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
