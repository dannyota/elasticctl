//! Alert mutation plans with observed state.

use super::*;
use crate::observe::{Observed, Preconditions};

pub(super) fn alert_state(status: &str, facet: AlertFacet) -> Value {
    match facet {
        AlertFacet::Status => json!({ "workflow_status": status }),
        AlertFacet::Presence => json!({}),
    }
}

/// Plan status changes and return the alert status read for each target.
pub async fn plan_status_by_ids_observed(
    t: &Transport,
    ids: &[String],
    status: AlertStatus,
    reason: Option<String>,
) -> Result<(StatusPlan, Preconditions)> {
    require_targets(ids)?;
    let resolved = resolve_ids(t, ids).await?;
    let seen = Preconditions(
        resolved
            .iter()
            .map(|r| Observed {
                object: "alert",
                id: r.id.clone(),
                state: Some(alert_state(&r.status, AlertFacet::Status)),
            })
            .collect(),
    );
    let preview_details = resolved
        .iter()
        .map(|r| {
            if r.status == status.as_str() {
                format!("{}  {}  already {}", r.id, r.rule_name, r.status)
            } else {
                format!(
                    "{}  {}  {} -> {}",
                    r.id,
                    r.rule_name,
                    r.status,
                    status.as_str()
                )
            }
        })
        .collect();
    Ok((
        StatusPlan {
            status,
            reason,
            preview_action: format!(
                "{} {} {}",
                status.verb(),
                resolved.len(),
                alert_noun(resolved.len())
            ),
            targets: resolved.into_iter().map(|r| r.id).collect(),
            preview_details,
        },
        seen,
    ))
}

/// Plan tag changes and return the presence read for each target.
pub async fn plan_tags_observed(
    t: &Transport,
    ids: &[String],
    add: Vec<String>,
    remove: Vec<String>,
) -> Result<(TagsPlan, Preconditions)> {
    require_targets(ids)?;
    require_edit(&add, &remove)?;
    require_disjoint(&add, &remove, "tags")?;
    let resolved = resolve_ids(t, ids).await?;
    let seen = Preconditions(
        resolved
            .iter()
            .map(|r| Observed {
                object: "alert",
                id: r.id.clone(),
                state: Some(alert_state(&r.status, AlertFacet::Presence)),
            })
            .collect(),
    );
    let summary = edit_summary(&add, &remove);
    let preview_details = resolved
        .iter()
        .map(|r| format!("{}  {}  {}", r.id, r.rule_name, summary))
        .collect();
    Ok((
        TagsPlan {
            preview_action: format!("Tag {} {}", resolved.len(), alert_noun(resolved.len())),
            targets: resolved.into_iter().map(|r| r.id).collect(),
            add,
            remove,
            preview_details,
        },
        seen,
    ))
}
