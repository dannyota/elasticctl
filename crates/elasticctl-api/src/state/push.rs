//! `state push`: plan and apply, in container-then-item-then-rule order.

use super::reports::{Mirror, PushReport, StackIdentity};
use crate::diff::{Change, Drift};
use crate::exceptions;
use crate::model::{ExceptionItem, ListKey, Rule};
use crate::normalize;
use crate::report::{ChangeReport, ReportEntry};
use crate::rules as api;
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

/// What `plan_push` computed and `apply_push` performs.
///
/// The preview fields feed the caller's guard banner; `report` is the change
/// ticket; `summary` is the JSON report.
#[derive(Debug, Clone)]
pub struct PushPlan {
    pub preview_action: String,
    pub preview_details: Vec<String>,
    pub report: ChangeReport,
    pub summary: PushReport,
    /// The exact rules the preview described, resolved once at plan time so
    /// `apply_push` never re-reads the mirror after the guard.
    desired: BTreeMap<String, Rule>,
    /// Container writes, ordered before any item or rule write.
    list_ops: Vec<super::diff::ListOp>,
    /// Items for a newly created container, ordered before rule writes.
    item_creates: Vec<ExceptionItem>,
}

/// Compute the push preview and dry-run report without mutating the stack.
pub async fn plan_push(
    t: &Transport,
    dir: &Path,
    selectors: &[String],
    tag: Option<&str>,
    identity: &StackIdentity,
) -> Result<PushPlan> {
    let Mirror {
        rules: local_all,
        lists,
        items,
    } = super::mirror::read_mirror(dir)?;
    // Resolve locally first because disk-only rules have no remote ID and may
    // be created by a scoped push.
    let scope = super::scope_of(t, selectors, tag, &local_all, "apply").await?;
    let local = scope.narrow(local_all);
    let remote = scope.remote(t).await?;
    let drift = Drift::compute(&local, &remote)?;

    let (_, list_ops, item_creates) =
        super::diff::exception_plan(t, lists, items, &local, &remote).await?;

    let by_id = |id: &str| local.iter().find(|r| r.rule_id().ok() == Some(id)).cloned();
    let remote_by_id = |id: &str| {
        remote
            .iter()
            .find(|r| r.rule_id().ok() == Some(id))
            .cloned()
    };

    let actionable = drift.actionable();
    let mut preview_details = Vec::new();

    // Name containers and items first, matching apply order.
    for op in &list_ops {
        match op {
            super::diff::ListOp::Create(list) => {
                preview_details.push(format!("{}  {}  create", list.list_id()?, list.name()))
            }
            super::diff::ListOp::Update(list) => {
                preview_details.push(format!("{}  {}  update", list.list_id()?, list.name()))
            }
        }
    }
    for item in &item_creates {
        preview_details.push(format!("{}  {}  create", item.item_id()?, item.list_id()?));
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

    let mut entries: Vec<ReportEntry> = Vec::new();
    let mut desired: BTreeMap<String, Rule> = BTreeMap::new();

    // Record remote-only rules before applying changes, including in dry runs.
    // `actionable()` excludes them because push never deletes remote rules.
    for change in &drift.changes {
        if let Change::RemoteOnly { rule_id, name } = change {
            entries.push(ReportEntry {
                rule_id: rule_id.clone(),
                name: name.clone(),
                action: "skipped_remote_only".into(),
                before: remote_by_id(rule_id).map(|r| normalize::canonical(&r).into_value()),
                after: None,
                applied: false,
                error: None,
            });
        }
    }

    // Record every actionable change as a pending entry. The report and JSON
    // `pending` count describe proposed creates and updates.
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
            before,
            after: Some(normalize::canonical(&desired_rule).into_value()),
            applied: false,
            error: None,
        });
    }

    // Name the selection so a scoped preview differs from a full preview. The
    // banner names rule and exception counts (spec 6.1).
    let preview_action = format!(
        "Push {} rule change(s) and {} exception list(s) from {}{}",
        actionable.len(),
        list_ops.len(),
        dir.display(),
        scope.describe()
    );

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
    );

    Ok(PushPlan {
        preview_action,
        preview_details,
        report,
        summary,
        desired,
        list_ops,
        item_creates,
    })
}

/// Perform the mutations `plan_push` proposed.
///
/// The caller runs this only after its guard approves; a caller that never
/// calls it has performed a dry run by construction. It reads only from the
/// plan, never the mirror, so the preview and the apply cannot diverge.
pub async fn apply_push(t: &Transport, mut plan: PushPlan) -> Result<PushPlan> {
    // Resolve the live ids for every list a rule to write references, then
    // create or update containers, then items, then rules. The pointer is
    // injected only here, against the target stack, never at plan time.
    let desired_rules: Vec<Rule> = plan.desired.values().cloned().collect();
    let wanted: Vec<ListKey> = super::referenced_keys(&desired_rules).into_iter().collect();
    let mut resolved = exceptions::resolve_ids(t, &wanted).await?;

    // 1. Containers.
    for op in &plan.list_ops {
        match op {
            super::diff::ListOp::Create(list) => {
                let created = exceptions::create_list(t, list).await?;
                if let Some(id) = created.as_map().get("id").and_then(Value::as_str) {
                    resolved.insert(list.key()?, id.to_string());
                }
            }
            super::diff::ListOp::Update(list) => {
                exceptions::update_list(t, list).await?;
            }
        }
    }

    // 2. Items, only for a newly created container in Task 11.
    for item in &plan.item_creates {
        exceptions::create_item(t, item).await?;
    }

    // 3. Rules, injecting the resolved pointer into each.
    let mut entries = Vec::with_capacity(plan.report.entries.len());
    for entry in plan.report.entries {
        if entry.action != "create" && entry.action != "update" {
            // `skipped_remote_only` entries pass through untouched.
            entries.push(entry);
            continue;
        }

        let Some(desired) = plan.desired.get(&entry.rule_id) else {
            // `plan_push` records a desired rule for every actionable change,
            // so this is defensive. Record the inconsistency as a failure
            // rather than dropping the planned mutation from the report.
            let missing = entry.rule_id.clone();
            entries.push(ReportEntry {
                rule_id: entry.rule_id,
                name: entry.name,
                action: entry.action,
                before: entry.before,
                after: None,
                applied: false,
                error: Some(format!("the plan has no desired rule for \"{missing}\"")),
            });
            continue;
        };

        let mut to_write = desired.clone();
        // A rule referencing a list that is neither on the stack nor in the
        // mirror is refused here, before the rule is written.
        inject_list_ids(&mut to_write, &resolved)?;
        let before = entry.before;
        let is_create = entry.action == "create";

        // Continue after a per-rule failure so the report records every
        // outcome.
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
                before,
                after: Some(normalize::canonical(&applied).into_value()),
                applied: true,
                error: None,
            }),
            Err(e) => entries.push(ReportEntry {
                rule_id: entry.rule_id,
                name: entry.name,
                action: entry.action,
                before,
                after: None,
                applied: false,
                error: Some(e.message),
            }),
        }
    }

    let (selected, local_total) = (plan.summary.selected, plan.summary.local_total);
    plan.report.entries = entries;
    plan.report.applied = true;
    plan.summary = push_summary(&plan.report, selected, local_total);
    Ok(plan)
}

fn push_summary(
    report: &ChangeReport,
    selected: Option<usize>,
    local_total: Option<usize>,
) -> PushReport {
    let (created, updated, skipped, failed) = report.counts();
    PushReport {
        applied: report.applied,
        created,
        updated,
        skipped_remote_only: skipped,
        failed,
        pending: report.pending(),
        selected,
        local_total,
    }
}

/// Inject each referenced list's live `id` into the rule, refusing a list that
/// is neither on the stack nor in the mirror.
///
/// Measured fact 3: `id` is required on create and validated by nothing, so a
/// fabricated or carried pointer would be stored silently. Resolve against this
/// stack every time.
fn inject_list_ids(rule: &mut Rule, live: &BTreeMap<ListKey, String>) -> Result<()> {
    let Some(Value::Array(refs)) = rule.as_map_mut().get_mut("exceptions_list") else {
        return Ok(());
    };
    for reference in refs.iter_mut() {
        let Value::Object(map) = reference else {
            continue;
        };
        let Some(list_id) = map.get("list_id").and_then(Value::as_str) else {
            continue;
        };
        let namespace = map
            .get("namespace_type")
            .and_then(Value::as_str)
            .unwrap_or("single");
        let key = ListKey {
            list_id: list_id.to_string(),
            namespace_type: namespace.to_string(),
        };
        match live.get(&key) {
            Some(id) => {
                map.insert("id".into(), json!(id));
            }
            None => {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!(
                        "rule references exception list \"{list_id}\" ({namespace}), which does \
                         not exist on this stack and is not in the mirror"
                    ),
                ));
            }
        }
    }
    Ok(())
}
