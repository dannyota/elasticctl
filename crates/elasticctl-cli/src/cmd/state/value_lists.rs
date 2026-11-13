use crate::context::Context;
use crate::guard::{self, Preview, ValueListPreview};
use elasticctl_api::state::PushPlan;
use elasticctl_api::value_lists::{ContainerAction, ImportPreview};
use elasticctl_core::{Error, ErrorKind, Result};
use serde::Serialize;

pub(super) fn changed(plan: &PushPlan) -> bool {
    plan.value_lists.iter().any(|list| {
        list.container_action != ContainerAction::None
            || !list.adds.is_empty()
            || !list.removes.is_empty()
    })
}

#[derive(Serialize)]
struct PushPreview<'a> {
    #[serde(flatten)]
    target: ValueListPreview<'a, ImportPreview<'a>>,
    action: &'a str,
    details: &'a [String],
}

pub(super) fn check(ctx: &Context, plan: &PushPlan) -> Result<bool> {
    if ctx.global.json && changed(plan) {
        let lists: Vec<_> = plan.value_lists.iter().map(ImportPreview::from).collect();
        let preview = PushPreview {
            target: ValueListPreview::new(ctx, "state push", &lists),
            action: &plan.preview_action,
            details: &plan.preview_details,
        };
        eprintln!(
            "{}",
            serde_json::to_string(&preview).map_err(|error| {
                Error::new(ErrorKind::Error, format!("encoding preview: {error}"))
            })?
        );
        return Ok(ctx.global.yes);
    }
    let mut details = plan.preview_details.clone();
    for list in &plan.value_lists {
        if list.container_action == ContainerAction::None
            && list.adds.is_empty()
            && list.removes.is_empty()
        {
            continue;
        }
        let preview = ImportPreview::from(list);
        let action = match list.container_action {
            ContainerAction::Create => "create",
            ContainerAction::Update => "update",
            ContainerAction::None => "none",
        };
        details.push(format!(
            "value list {}: container: {}, {}, {} adds, {} removes; {}",
            preview.id,
            action,
            preview.phase_order,
            list.adds.len(),
            list.removes.len(),
            preview.phase_reason
        ));
        for value in &list.adds {
            details.push(format!("  + {value}"));
        }
        for value in &list.removes {
            details.push(format!("  - {value}"));
        }
    }
    Ok(guard::check(
        ctx,
        "state push",
        &Preview {
            action: plan.preview_action.clone(),
            details,
        },
    ))
}
