use super::*;

#[derive(Default, Clone, Copy)]
pub(super) struct ExceptionCounts {
    pub(super) lists_created: usize,
    pub(super) lists_updated: usize,
    pub(super) items_created: usize,
    pub(super) items_updated: usize,
    pub(super) items_removed: usize,
}

pub(super) fn push_summary(
    report: &ChangeReport,
    selected: Option<usize>,
    local_total: Option<usize>,
    out_of_scope: usize,
    counts: ExceptionCounts,
) -> PushReport {
    let (created, updated, skipped, failed) = report.counts();
    PushReport {
        value_lists_created: 0,
        value_lists_updated: 0,
        values_added: 0,
        values_removed: 0,
        value_lists_unknown: 0,
        value_lists_not_reached: 0,
        applied: report.applied,
        created,
        updated,
        skipped_remote_only: skipped,
        failed,
        pending: report.pending(),
        lists_created: counts.lists_created,
        lists_updated: counts.lists_updated,
        items_created: counts.items_created,
        items_updated: counts.items_updated,
        items_removed: counts.items_removed,
        out_of_scope,
        selected,
        local_total,
    }
}

pub(super) fn update_value_summary(plan: &mut PushPlan) {
    use crate::value_lists::{Action, ContainerAction, Outcome};
    let summary = &mut plan.summary;
    summary.applied = plan.report.applied;
    for outcome in &plan.value_list_outcomes {
        let list = plan
            .values
            .plans
            .iter()
            .find(|p| p.local.container.id == outcome.id)
            .expect("outcome has a plan");
        match outcome.outcome {
            Outcome::Applied => {
                if list.container_action == ContainerAction::Create {
                    summary.value_lists_created += 1;
                } else if list.container_action == ContainerAction::Update
                    || !list.adds.is_empty()
                    || !list.removes.is_empty()
                {
                    summary.value_lists_updated += 1;
                }
            }
            Outcome::Unknown => {
                summary.value_lists_unknown += 1;
                summary.failed += 1;
            }
            Outcome::NotReached => summary.value_lists_not_reached += 1,
            Outcome::Failed => summary.failed += 1,
        }
        for entry in &outcome.evidence {
            if entry.phase_verified {
                let count = entry.values.as_ref().map_or(0, Vec::len);
                match entry.action {
                    Action::AddValues => summary.values_added += count,
                    Action::RemoveValues => summary.values_removed += count,
                    _ => {}
                }
            }
        }
    }
}
