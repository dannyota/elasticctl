use super::*;
use crate::observe::{Observed, Preconditions};

pub async fn plan_set_enabled_observed(
    t: &Transport,
    selectors: &[String],
    enable: bool,
) -> Result<(MutationPlan, Preconditions)> {
    let resolved = resolve_targets(t, selectors).await?;
    let seen = Preconditions(
        resolved
            .iter()
            .map(|(id, rule)| Observed {
                object: "rule",
                id: id.clone(),
                state: Some(normalize::canonical(rule).into_value()),
            })
            .collect(),
    );
    let preview_details = resolved
        .iter()
        .map(|(id, r)| {
            let from = if r.enabled() { "enabled" } else { "disabled" };
            let to = if enable { "enabled" } else { "disabled" };
            format!("{id}  {}  {from} -> {to}", r.name())
        })
        .collect();
    let verb = if enable { "Enable" } else { "Disable" };
    Ok((
        MutationPlan {
            preview_action: format!("{verb} {} rule(s)", resolved.len()),
            preview_details,
            targets: resolved.into_iter().map(|(id, _)| id).collect(),
        },
        seen,
    ))
}
