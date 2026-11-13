use super::*;
use crate::state::diff::{ExceptionPlan, ItemOp};

pub(super) fn check(
    plans: &[ListPlan],
    installed: &[InstalledReference],
    desired: &[InstalledReference],
    local: &[Rule],
    remote: &[Rule],
    exceptions: &ExceptionPlan,
) -> Result<()> {
    let changed: BTreeSet<_> = plans
        .iter()
        .filter(|p| !p.adds.is_empty() || !p.removes.is_empty())
        .map(|p| p.local.container.id.as_str())
        .collect();
    for plan in plans
        .iter()
        .filter(|p| changed.contains(p.local.container.id.as_str()))
    {
        let id = &plan.local.container.id;
        let first_creation = plan.before.is_none() && plan.installed.is_empty();
        let old: Vec<_> = installed.iter().filter(|r| r.list_id == *id).collect();
        let new: Vec<_> = desired.iter().filter(|r| r.list_id == *id).collect();
        if !first_creation && (old.len() != new.len() || old.iter().any(|r| !new.contains(r))) {
            return conflict(id, "its reference entries change");
        }
        let using: Vec<_> = old.into_iter().chain(new).collect();
        let containers: BTreeSet<_> = using.iter().map(|r| r.container.clone()).collect();
        for reference in &using {
            if !first_creation
                && exceptions.item_ops.iter().any(|op| {
                    let item = match op {
                        ItemOp::Create(item) => item,
                        ItemOp::Update { after, .. } => after,
                        ItemOp::Remove { before, .. } => before,
                    };
                    item.item_id().ok() == Some(reference.item_id.as_str())
                        && item.list_id().ok() == Some(reference.container.list_id.as_str())
                        && item.namespace_type() == reference.container.namespace_type
                })
            {
                return conflict(
                    id,
                    &format!("referencing item {} changes", reference.name()),
                );
            }
            for other in installed.iter().chain(desired).filter(|r| {
                r.container == reference.container
                    && r.item_id == reference.item_id
                    && r.list_id != *id
            }) {
                if !first_creation && changed.contains(other.list_id.as_str()) {
                    return conflict(
                        id,
                        &format!(
                            "list {} in referencing item {} also changes values",
                            other.list_id, reference.item_id
                        ),
                    );
                }
            }
        }
        for rule in local {
            let before = remote
                .iter()
                .find(|r| r.rule_id().ok() == rule.rule_id().ok());
            let old = before
                .map(|r| super::super::referenced_keys(std::slice::from_ref(r)))
                .unwrap_or_default();
            let new = super::super::referenced_keys(std::slice::from_ref(rule));
            let removed = old.difference(&new).any(|k| containers.contains(k));
            let added = new.difference(&old).any(|k| containers.contains(k));
            if removed || (!first_creation && added) {
                return conflict(
                    id,
                    &format!(
                        "rule {} changes a binding to a referencing container",
                        rule.rule_id()?
                    ),
                );
            }
        }
    }
    Ok(())
}

fn conflict<T>(id: &str, change: &str) -> Result<T> {
    Err(Error::new(
        ErrorKind::Conflict,
        format!("value list {id} changes values while {change}; use separate runs"),
    ))
}
