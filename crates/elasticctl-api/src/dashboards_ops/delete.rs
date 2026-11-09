//! Dashboard deletion planning and apply.

use super::{
    BTreeSet, DashboardSummary, DeleteOutcome, Error, ErrorKind, MutationPlan, Result, Transport,
    dashboards, invalid_plan, resolve,
};

/// The immutable, guard-ready targets for dashboard deletion.
#[derive(Debug, Clone, PartialEq)]
pub struct DashboardDeletePlan {
    pub preview: MutationPlan,
    pub targets: Vec<DashboardSummary>,
}
/// Resolve every dashboard selector and build the exact delete guard preview.
pub async fn plan_delete(
    transport: &Transport,
    selectors: &[String],
) -> Result<DashboardDeletePlan> {
    if selectors.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "dashboard delete needs at least one dashboard",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut targets = Vec::new();
    for selector in selectors {
        let dashboard = resolve(transport, selector).await?;
        if seen.insert(dashboard.id.clone()) {
            targets.push(dashboard);
        }
    }
    Ok(DashboardDeletePlan {
        preview: delete_preview(&targets),
        targets,
    })
}

/// Apply a guard-approved dashboard deletion without resolving selectors again.
pub async fn apply_delete(
    transport: &Transport,
    plan: &DashboardDeletePlan,
) -> Result<DeleteOutcome> {
    validate_delete_plan(plan)?;
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    for target in &plan.targets {
        match dashboards::delete(transport, &target.id).await {
            Ok(()) => deleted.push(serde_json::json!({"id": target.id})),
            Err(error) => failed.push(serde_json::json!({
                "id": target.id,
                "error": error.message,
            })),
        }
    }
    Ok(DeleteOutcome {
        applied: true,
        deleted,
        failed,
        total: plan.targets.len(),
    })
}

fn delete_preview(targets: &[DashboardSummary]) -> MutationPlan {
    MutationPlan {
        preview_action: format!("Delete {} dashboard(s)", targets.len()),
        preview_details: targets
            .iter()
            .map(|dashboard| format!("{}  {}", dashboard.id, dashboard.title))
            .collect(),
        targets: targets
            .iter()
            .map(|dashboard| dashboard.id.clone())
            .collect(),
    }
}

fn validate_delete_plan(plan: &DashboardDeletePlan) -> Result<()> {
    if plan.targets.is_empty() {
        return invalid_plan("dashboard delete plan needs at least one target");
    }
    let mut ids = BTreeSet::new();
    for target in &plan.targets {
        if target.id.trim().is_empty() || target.title.trim().is_empty() {
            return invalid_plan("dashboard delete target identity must not be empty");
        }
        if !ids.insert(target.id.clone()) {
            return invalid_plan("dashboard delete targets must be unique by id");
        }
    }
    if plan.preview != delete_preview(&plan.targets) {
        return invalid_plan("dashboard delete preview does not match guarded targets");
    }
    Ok(())
}
