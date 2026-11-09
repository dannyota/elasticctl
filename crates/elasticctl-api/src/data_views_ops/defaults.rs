//! Default data view selection and updates.

use super::{
    DataViewSummary, Error, ErrorKind, MutationPlan, Result, Transport, data_views, invalid_plan,
    resolve_from_summaries,
};

/// An immutable, guard-ready default data-view change.
#[derive(Debug, Clone, PartialEq)]
pub struct DefaultPlan {
    pub preview: MutationPlan,
    pub before: Option<String>,
    pub after: Option<String>,
}
/// Resolve a data view and prepare a guarded default change.
pub async fn plan_default_set(transport: &Transport, selector: &str) -> Result<DefaultPlan> {
    let views = data_views::list(transport).await?;
    let target = resolve_from_summaries(&views, selector)?;
    let before = data_views::get_default(transport).await?;
    let label = default_label(&target);
    Ok(default_plan(before, Some(target.id), Some(label)))
}

/// Prepare a guarded request that explicitly clears the current default.
pub async fn plan_default_unset(transport: &Transport) -> Result<DefaultPlan> {
    Ok(default_plan(
        data_views::get_default(transport).await?,
        None,
        None,
    ))
}

/// Apply a guarded default change after checking the observed default remains
/// the exact snapshot shown to the operator.
pub async fn apply_default(transport: &Transport, plan: &DefaultPlan) -> Result<()> {
    validate_default_plan(plan)?;
    let current = data_views::get_default(transport).await?;
    if current != plan.before {
        return Err(Error::new(
            ErrorKind::Conflict,
            "default data view changed since preview",
        ));
    }
    if plan.before == plan.after {
        return Ok(());
    }
    data_views::set_default(transport, plan.after.as_deref()).await
}

fn default_plan(
    before: Option<String>,
    after: Option<String>,
    target_label: Option<String>,
) -> DefaultPlan {
    let (preview_action, preview_details, targets) = match (&before, &after) {
        (before, Some(after)) => {
            let label = target_label.expect("set default plans always have a resolved label");
            let detail = if before.as_deref() == Some(after) {
                format!("{after}  already default")
            } else {
                format!(
                    "{}  default -> {after}",
                    before.as_deref().unwrap_or("none")
                )
            };
            (
                format!("Set default data view to {after} ({label})"),
                vec![detail],
                vec![after.clone()],
            )
        }
        (Some(before), None) => (
            format!("Unset default data view {before}"),
            vec![format!("{before}  default -> unset")],
            vec![before.clone()],
        ),
        (None, None) => (
            "Unset default data view".into(),
            vec!["no default data view set".into()],
            Vec::new(),
        ),
    };
    DefaultPlan {
        preview: MutationPlan {
            preview_action,
            preview_details,
            targets,
        },
        before,
        after,
    }
}

fn default_label(view: &DataViewSummary) -> String {
    view.name.clone().unwrap_or_else(|| view.title.clone())
}

fn validate_default_plan(plan: &DefaultPlan) -> Result<()> {
    for id in [&plan.before, &plan.after].into_iter().flatten() {
        if id.trim().is_empty() {
            return invalid_plan("default data-view ids must not be empty");
        }
    }
    match (&plan.before, &plan.after) {
        (Some(before), Some(after)) if before == after => {
            if plan.preview.targets != [after.clone()]
                || plan.preview.preview_details != [format!("{after}  already default")]
                || !plan
                    .preview
                    .preview_action
                    .starts_with(&format!("Set default data view to {after} ("))
                || !plan.preview.preview_action.ends_with(')')
            {
                return invalid_plan("default preview does not match its snapshots");
            }
        }
        (before, Some(after)) => {
            if plan.preview.targets != [after.clone()]
                || plan.preview.preview_details
                    != [format!(
                        "{}  default -> {after}",
                        before.as_deref().unwrap_or("none")
                    )]
                || !plan
                    .preview
                    .preview_action
                    .starts_with(&format!("Set default data view to {after} ("))
                || !plan.preview.preview_action.ends_with(')')
            {
                return invalid_plan("default preview does not match its snapshots");
            }
        }
        (Some(before), None) => {
            if plan.preview.targets != [before.clone()]
                || plan.preview.preview_action != format!("Unset default data view {before}")
                || plan.preview.preview_details != [format!("{before}  default -> unset")]
            {
                return invalid_plan("default preview does not match its snapshots");
            }
        }
        (None, None) => {
            if !plan.preview.targets.is_empty()
                || plan.preview.preview_action != "Unset default data view"
                || plan.preview.preview_details != ["no default data view set"]
            {
                return invalid_plan("default preview does not match its snapshots");
            }
        }
    }
    Ok(())
}
