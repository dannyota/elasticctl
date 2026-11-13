use super::diff::{ItemOp, ListOp};
use super::reports::{DanglingPointer, Mirror, PushReport, StackIdentity};
use crate::diff::{Change, Drift};
use crate::exceptions;
use crate::model::{ListKey, Rule};
use crate::normalize;
use crate::report::{ChangeReport, ReportEntry};
use crate::rules as api;
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

mod references;
mod summary;
use references::inject_list_ids;
use summary::{ExceptionCounts, push_summary, update_value_summary};

#[derive(Debug, Clone)]
pub struct PushPlan {
    pub preview_action: String,
    pub preview_details: Vec<String>,
    pub report: ChangeReport,
    pub summary: PushReport,
    desired: BTreeMap<String, Rule>,
    list_ops: Vec<ListOp>,
    item_ops: Vec<ItemOp>,
    pub value_lists: Vec<crate::value_lists::ListPlan>,
    pub value_list_outcomes: Vec<crate::value_lists::ListOutcome>,
    pub value_list_drift: Option<super::values::ValueListDrift>,
    values: super::values::ValuePlan,
}

pub async fn plan_push(
    t: &Transport,
    dir: &Path,
    selectors: &[String],
    tag: Option<&str>,
    search: Option<&str>,
    source: crate::rules::RuleSource,
    identity: &StackIdentity,
) -> Result<PushPlan> {
    let Mirror {
        rules: local_all,
        lists,
        items,
        value_lists,
        has_value_lists,
    } = super::mirror::read_mirror(dir)?;
    let scope = super::scope_of(t, selectors, tag, search, source, &local_all, "apply").await?;
    let (local, out_of_scope) = if scope.is_scoped() {
        (scope.narrow(local_all), 0)
    } else {
        scope.split_by_source(local_all)
    };

    let remote = scope.remote(t).await?;
    let drift = Drift::compute(&local, &remote)?;

    let plan =
        super::diff::exception_plan(t, lists.clone(), items.clone(), &local, &remote).await?;
    let values = super::values::plan(
        t,
        super::values::Inputs {
            pairs: &value_lists,
            has_root: has_value_lists,
            lists: &lists,
            items: &items,
            local: &local,
            remote: &remote,
            exception_plan: &plan,
        },
        true,
    )
    .await?;
    let exceptions = plan.drift;
    let list_ops = plan.list_ops;
    let item_ops = plan.item_ops;
    let resolvable = plan.resolvable;

    let by_id = |id: &str| local.iter().find(|r| r.rule_id().ok() == Some(id)).cloned();
    let remote_by_id = |id: &str| {
        remote
            .iter()
            .find(|r| r.rule_id().ok() == Some(id))
            .cloned()
    };

    let actionable = drift.actionable();
    let actionable_ids: BTreeSet<String> =
        actionable.iter().map(|c| c.rule_id().to_string()).collect();

    let mut repairs: Vec<DanglingPointer> = Vec::new();
    let mut repaired_ids: BTreeSet<String> = BTreeSet::new();
    for dangling in &exceptions.dangling {
        if actionable_ids.contains(&dangling.rule_id)
            || by_id(&dangling.rule_id).is_none()
            || !repaired_ids.insert(dangling.rule_id.clone())
        {
            continue;
        }
        repairs.push(dangling.clone());
    }

    let mut preview_details = Vec::new();

    for op in &list_ops {
        match op {
            ListOp::Create(list) => {
                preview_details.push(format!("{}  {}  create", list.list_id()?, list.name()))
            }
            ListOp::Update { after, .. } => {
                preview_details.push(format!("{}  {}  update", after.list_id()?, after.name()))
            }
        }
    }
    for op in &item_ops {
        match op {
            ItemOp::Create(item) => {
                preview_details.push(format!("{}  {}  create", item.item_id()?, item.list_id()?))
            }
            ItemOp::Update { after, .. } => preview_details.push(format!(
                "{}  {}  update",
                after.item_id()?,
                after.list_id()?
            )),
            ItemOp::Remove { before, .. } => preview_details.push(format!(
                "{}  {}  delete",
                before.item_id()?,
                before.list_id()?
            )),
        }
    }
    for change in &actionable {
        let line = match change {
            Change::Added { rule_id, name } => format!("{rule_id}  {name}  create"),
            Change::Modified {
                rule_id,
                name,
                fields,
            } => {
                let names: Vec<&str> = fields.iter().map(|f| f.field.as_str()).collect();
                format!("{rule_id}  {name}  update ({})", names.join(", "))
            }
            _ => String::new(),
        };
        if !line.is_empty() {
            preview_details.push(line);
        }
    }
    for dangling in &repairs {
        let name = by_id(&dangling.rule_id)
            .map(|r| r.name().to_string())
            .unwrap_or_default();
        preview_details.push(format!("{}  {}  update (pointer)", dangling.rule_id, name));
    }

    if let Some(drift) = &values.drift {
        for id in &drift.unreferenced {
            preview_details.push(format!("value list {id} is unreferenced; left unchanged"));
        }
        for warning in &drift.warnings {
            preview_details.push(format!("value list {}: {}", warning.id, warning.message));
        }
    }
    for list in &values.plans {
        if list.container_action != crate::value_lists::ContainerAction::None
            || !list.adds.is_empty()
            || !list.removes.is_empty()
        {
            preview_details.push(format!(
                "value list {}: {:?}, {} adds, {} removes; {}",
                list.local.container.id,
                list.order,
                list.adds.len(),
                list.removes.len(),
                list.order_reason
            ));
            for value in &list.adds {
                preview_details.push(format!("  + {value}"));
            }
            for value in &list.removes {
                preview_details.push(format!("  - {value}"));
            }
        }
    }

    let mut entries: Vec<ReportEntry> = Vec::new();
    let mut desired: BTreeMap<String, Rule> = BTreeMap::new();

    for change in &drift.changes {
        if let Change::RemoteOnly { rule_id, name } = change {
            entries.push(ReportEntry {
                rule_id: rule_id.clone(),
                name: name.clone(),
                action: "skipped_remote_only".into(),
                value_list: None,
                before: remote_by_id(rule_id).map(|r| normalize::canonical(&r).into_value()),
                after: None,
                applied: false,
                error: None,
            });
        }
    }

    for change in &actionable {
        let (rule_id, name, action) = match change {
            Change::Added { rule_id, name } => (rule_id.clone(), name.clone(), "create"),
            Change::Modified { rule_id, name, .. } => (rule_id.clone(), name.clone(), "update"),
            _ => continue,
        };

        let Some(desired_rule) = by_id(&rule_id) else {
            continue;
        };
        let before = remote_by_id(&rule_id).map(|r| normalize::canonical(&r).into_value());

        desired.insert(rule_id.clone(), desired_rule.clone());

        entries.push(ReportEntry {
            rule_id,
            name,
            action: action.into(),
            value_list: None,
            before,
            after: Some(normalize::canonical(&desired_rule).into_value()),
            applied: false,
            error: None,
        });
    }

    for dangling in &repairs {
        let desired_rule = by_id(&dangling.rule_id).expect("repair rule was found above");
        let before = remote_by_id(&dangling.rule_id).map(|r| normalize::canonical(&r).into_value());
        desired.insert(dangling.rule_id.clone(), desired_rule.clone());
        entries.push(ReportEntry {
            rule_id: dangling.rule_id.clone(),
            name: desired_rule.name().to_string(),
            action: "update".into(),
            value_list: None,
            before,
            after: Some(normalize::canonical(&desired_rule).into_value()),
            applied: false,
            error: None,
        });
    }

    let desired_rules: Vec<Rule> = desired.values().cloned().collect();
    let unresolved: Vec<String> = super::referenced_keys(&desired_rules)
        .into_iter()
        .filter(|key| !resolvable.contains(key))
        .map(|key| format!("\"{}\" ({})", key.list_id, key.namespace_type))
        .collect();
    if !unresolved.is_empty() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!(
                "rule(s) reference exception list(s) that do not exist on this stack and are \
                 not in the mirror: {}",
                unresolved.join(", ")
            ),
        ));
    }

    let item_removals = item_ops
        .iter()
        .filter(|op| matches!(op, ItemOp::Remove { .. }))
        .count();
    let item_writes = item_ops.len() - item_removals;
    let mut preview_action = format!(
        "Push {} rule change(s), {} exception list(s) and {} item(s)",
        actionable.len() + repairs.len(),
        list_ops.len(),
        item_writes,
    );
    if item_removals > 0 {
        preview_action.push_str(&format!(", {} item deletion(s)", item_removals));
    }
    preview_action.push_str(&format!(" from {}{}", dir.display(), scope.describe()));

    let report = ChangeReport {
        profile: identity.profile.clone(),
        host: identity.host.clone(),
        space: identity.space.clone(),
        applied: false,
        entries,
    };
    let summary = push_summary(
        &report,
        scope.is_scoped().then(|| scope.selected()),
        scope.is_scoped().then_some(scope.local_total),
        out_of_scope,
        ExceptionCounts::default(),
    );

    Ok(PushPlan {
        preview_action,
        preview_details,
        report,
        summary,
        desired,
        list_ops,
        item_ops,
        value_lists: values.plans.clone(),
        value_list_outcomes: Vec::new(),
        value_list_drift: values.drift.clone(),
        values,
    })
}

pub async fn apply_push(t: &Transport, plan: PushPlan) -> Result<PushPlan> {
    apply_push_with_clock(t, plan, &crate::value_lists::SystemClock::default()).await
}

async fn apply_push_with_clock<C: crate::value_lists::Clock>(
    t: &Transport,
    mut plan: PushPlan,
    clock: &C,
) -> Result<PushPlan> {
    let desired_rules: Vec<Rule> = plan.desired.values().cloned().collect();
    let wanted: Vec<ListKey> = super::referenced_keys(&desired_rules).into_iter().collect();
    let mut resolved = exceptions::resolve_ids(t, &wanted).await?;

    plan.value_list_outcomes = crate::value_lists::apply_plans(t, &plan.values.plans, clock).await;
    let value_entries: Vec<_> = plan
        .value_list_outcomes
        .iter()
        .flat_map(|outcome| outcome.evidence.iter().cloned())
        .map(ReportEntry::from)
        .collect();
    if plan
        .value_list_outcomes
        .iter()
        .any(|o| o.outcome != crate::value_lists::Outcome::Applied)
    {
        plan.report.entries.splice(0..0, value_entries);
        plan.report.applied = true;
        update_value_summary(&mut plan);
        return Ok(plan);
    }
    let mut counts = ExceptionCounts::default();
    let mut exception_entries = value_entries;

    for op in &plan.list_ops {
        let failure = match op {
            ListOp::Create(list) => match exceptions::create_list(t, list).await {
                Ok(created) => {
                    if let Some(id) = created.as_map().get("id").and_then(Value::as_str) {
                        resolved.insert(list.key()?, id.to_string());
                    }
                    counts.lists_created += 1;
                    exception_entries.push(ReportEntry {
                        rule_id: list.list_id().unwrap_or("<unreadable>").to_string(),
                        name: list.name().to_string(),
                        action: "create_list".into(),
                        value_list: None,
                        before: None,
                        after: Some(normalize::canonical_list(&created).into_value()),
                        applied: true,
                        error: None,
                    });
                    None
                }
                Err(e) => Some(ReportEntry {
                    rule_id: list.list_id().unwrap_or("<unreadable>").to_string(),
                    name: list.name().to_string(),
                    action: "create_list".into(),
                    value_list: None,
                    before: None,
                    after: None,
                    applied: false,
                    error: Some(e.message),
                }),
            },
            ListOp::Update { before, after } => match exceptions::update_list(t, after).await {
                Ok(applied) => {
                    counts.lists_updated += 1;
                    exception_entries.push(ReportEntry {
                        rule_id: after.list_id().unwrap_or("<unreadable>").to_string(),
                        name: after.name().to_string(),
                        action: "update_list".into(),
                        value_list: None,
                        before: Some(before.clone().into_value()),
                        after: Some(normalize::canonical_list(&applied).into_value()),
                        applied: true,
                        error: None,
                    });
                    None
                }
                Err(e) => Some(ReportEntry {
                    rule_id: after.list_id().unwrap_or("<unreadable>").to_string(),
                    name: after.name().to_string(),
                    action: "update_list".into(),
                    value_list: None,
                    before: Some(before.clone().into_value()),
                    after: None,
                    applied: false,
                    error: Some(e.message),
                }),
            },
        };
        if let Some(failed_entry) = failure {
            return Ok(finish_after_exception_failure(
                plan,
                exception_entries,
                failed_entry,
                counts,
            ));
        }
    }

    if let Err(error) = super::values::reread(t, &plan.values).await {
        let failed_entry = ReportEntry {
            rule_id: String::new(),
            name: String::new(),
            action: "check_value_lists".into(),
            before: None,
            after: None,
            applied: false,
            error: Some(error.message),
            value_list: None,
        };
        return Ok(finish_after_exception_failure(
            plan,
            exception_entries,
            failed_entry,
            counts,
        ));
    }

    for op in &plan.item_ops {
        let failure = match op {
            ItemOp::Create(item) => match exceptions::create_item(t, item).await {
                Ok(applied) => {
                    counts.items_created += 1;
                    exception_entries.push(ReportEntry {
                        rule_id: item.item_id().unwrap_or("<unreadable>").to_string(),
                        name: item.list_id().unwrap_or("<unreadable>").to_string(),
                        action: "create_item".into(),
                        value_list: None,
                        before: None,
                        after: Some(normalize::canonical_item(&applied).into_value()),
                        applied: true,
                        error: None,
                    });
                    None
                }
                Err(e) => Some(ReportEntry {
                    rule_id: item.item_id().unwrap_or("<unreadable>").to_string(),
                    name: item.list_id().unwrap_or("<unreadable>").to_string(),
                    action: "create_item".into(),
                    value_list: None,
                    before: None,
                    after: None,
                    applied: false,
                    error: Some(e.message),
                }),
            },
            ItemOp::Update { before, after } => match exceptions::update_item(t, after).await {
                Ok(applied) => {
                    counts.items_updated += 1;
                    exception_entries.push(ReportEntry {
                        rule_id: after.item_id().unwrap_or("<unreadable>").to_string(),
                        name: after.list_id().unwrap_or("<unreadable>").to_string(),
                        action: "update_item".into(),
                        value_list: None,
                        before: Some(before.clone().into_value()),
                        after: Some(normalize::canonical_item(&applied).into_value()),
                        applied: true,
                        error: None,
                    });
                    None
                }
                Err(e) => Some(ReportEntry {
                    rule_id: after.item_id().unwrap_or("<unreadable>").to_string(),
                    name: after.list_id().unwrap_or("<unreadable>").to_string(),
                    action: "update_item".into(),
                    value_list: None,
                    before: Some(before.clone().into_value()),
                    after: None,
                    applied: false,
                    error: Some(e.message),
                }),
            },
            ItemOp::Remove {
                before,
                namespace_type,
            } => match exceptions::delete_item(
                t,
                before.item_id().unwrap_or("<unreadable>"),
                namespace_type,
            )
            .await
            {
                Ok(_) => {
                    counts.items_removed += 1;
                    exception_entries.push(ReportEntry {
                        rule_id: before.item_id().unwrap_or("<unreadable>").to_string(),
                        name: before.list_id().unwrap_or("<unreadable>").to_string(),
                        action: "delete_item".into(),
                        value_list: None,
                        before: Some(before.clone().into_value()),
                        after: None,
                        applied: true,
                        error: None,
                    });
                    None
                }
                Err(e) => Some(ReportEntry {
                    rule_id: before.item_id().unwrap_or("<unreadable>").to_string(),
                    name: before.list_id().unwrap_or("<unreadable>").to_string(),
                    action: "delete_item".into(),
                    value_list: None,
                    before: Some(before.clone().into_value()),
                    after: None,
                    applied: false,
                    error: Some(e.message),
                }),
            },
        };
        if let Some(failed_entry) = failure {
            return Ok(finish_after_exception_failure(
                plan,
                exception_entries,
                failed_entry,
                counts,
            ));
        }
    }

    let mut entries = exception_entries;
    entries.reserve(plan.report.entries.len());
    for entry in plan.report.entries {
        if entry.action != "create" && entry.action != "update" {
            entries.push(entry);
            continue;
        }

        let Some(desired) = plan.desired.get(&entry.rule_id) else {
            let missing = entry.rule_id.clone();
            entries.push(ReportEntry {
                rule_id: entry.rule_id,
                name: entry.name,
                action: entry.action,
                value_list: None,
                before: entry.before,
                after: None,
                applied: false,
                error: Some(format!("the plan has no desired rule for \"{missing}\"")),
            });
            continue;
        };

        let mut to_write = desired.clone();
        if let Err(e) = inject_list_ids(&mut to_write, &resolved) {
            entries.push(ReportEntry {
                rule_id: entry.rule_id,
                name: entry.name,
                action: entry.action,
                value_list: None,
                before: entry.before,
                after: None,
                applied: false,
                error: Some(e.message),
            });
            continue;
        }
        let before = entry.before;
        let is_create = entry.action == "create";

        let outcome = if is_create {
            api::create(t, &to_write).await
        } else {
            api::update(t, &to_write).await
        };

        match outcome {
            Ok(applied) => entries.push(ReportEntry {
                rule_id: entry.rule_id,
                name: entry.name,
                action: entry.action,
                value_list: None,
                before,
                after: Some(normalize::canonical(&applied).into_value()),
                applied: true,
                error: None,
            }),
            Err(e) => entries.push(ReportEntry {
                rule_id: entry.rule_id,
                name: entry.name,
                action: entry.action,
                value_list: None,
                before,
                after: None,
                applied: false,
                error: Some(e.message),
            }),
        }
    }

    let (selected, local_total, out_of_scope) = (
        plan.summary.selected,
        plan.summary.local_total,
        plan.summary.out_of_scope,
    );
    plan.report.entries = entries;
    plan.report.applied = true;
    plan.summary = push_summary(&plan.report, selected, local_total, out_of_scope, counts);
    update_value_summary(&mut plan);
    Ok(plan)
}

fn finish_after_exception_failure(
    mut plan: PushPlan,
    mut exception_entries: Vec<ReportEntry>,
    failed_entry: ReportEntry,
    counts: ExceptionCounts,
) -> PushPlan {
    exception_entries.push(failed_entry);
    exception_entries.append(&mut plan.report.entries);
    plan.report.entries = exception_entries;
    plan.report.applied = true;
    let (selected, local_total, out_of_scope) = (
        plan.summary.selected,
        plan.summary.local_total,
        plan.summary.out_of_scope,
    );
    plan.summary = push_summary(&plan.report, selected, local_total, out_of_scope, counts);
    update_value_summary(&mut plan);
    plan
}

#[cfg(test)]
mod tests;
