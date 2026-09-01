//! Case orchestration: filters, list/get, and the guarded mutation plans.

use crate::alerts;
use crate::alerts_ops::source_str;
use crate::cases::{self, Case, CaseStatus, NewCase};
use crate::profiles;
use elasticctl_core::{Error, ErrorKind, Result, Transport, urlencode};
use serde_json::Value;

/// The `_find` route's per-page cap.
pub const PAGE_SIZE: u32 = 100;

#[derive(Debug, Clone, Default)]
pub struct CaseFilter {
    pub status: Option<CaseStatus>,
    pub severity: Option<String>,
    pub tag: Option<String>,
    /// Matches title and description server-side.
    pub search: Option<String>,
}

/// Deterministic query string for `GET /api/cases/_find`. Key order is
/// fixed so tests and fixtures are stable.
pub fn find_query(f: &CaseFilter, page: u32, per_page: u32) -> String {
    let mut q = format!("page={page}&perPage={per_page}&sortField=createdAt&sortOrder=desc");
    if let Some(status) = f.status {
        q.push_str(&format!("&status={}", status.as_str()));
    }
    if let Some(severity) = &f.severity {
        q.push_str(&format!("&severity={}", urlencode(severity)));
    }
    if let Some(tag) = &f.tag {
        q.push_str(&format!("&tags={}", urlencode(tag)));
    }
    if let Some(search) = &f.search {
        q.push_str(&format!(
            "&search={}&searchFields=title&searchFields=description",
            urlencode(search)
        ));
    }
    q
}

#[derive(Debug, Clone, PartialEq)]
pub struct CaseList {
    pub cases: Vec<Case>,
    pub total: u64,
    pub truncated: bool,
}

/// One bounded peek: page until `limit + 1` rows are in hand or the server
/// runs out, then truncate.
pub async fn list(t: &Transport, f: &CaseFilter, limit: usize) -> Result<CaseList> {
    let mut cases = Vec::new();
    let mut total = 0;
    let mut page = 1;
    while cases.len() <= limit {
        let (batch, batch_total) = cases::find_page(t, &find_query(f, page, PAGE_SIZE)).await?;
        total = batch_total;
        let got = batch.len();
        cases.extend(batch);
        if got < PAGE_SIZE as usize {
            break;
        }
        page += 1;
    }
    let truncated = cases.len() > limit;
    cases.truncate(limit);
    Ok(CaseList {
        cases,
        total,
        truncated,
    })
}

/// The `--out` path: every page, unless `limit` stops it early.
pub async fn export(t: &Transport, f: &CaseFilter, limit: Option<usize>) -> Result<Vec<Case>> {
    export_with_page_size(t, f, PAGE_SIZE, limit).await
}

/// The paging loop with an explicit page size, exposed for tests. Stops
/// paging as soon as `limit` rows are in hand, mirroring
/// `alerts_ops::export`'s shape.
pub async fn export_with_page_size(
    t: &Transport,
    f: &CaseFilter,
    per_page: u32,
    limit: Option<usize>,
) -> Result<Vec<Case>> {
    let mut all = Vec::new();
    let mut page = 1;
    loop {
        let (batch, _) = cases::find_page(t, &find_query(f, page, per_page)).await?;
        let got = batch.len();
        all.extend(batch);
        if let Some(limit) = limit
            && all.len() >= limit
        {
            all.truncate(limit);
            return Ok(all);
        }
        if got < per_page as usize {
            return Ok(all);
        }
        page += 1;
    }
}

pub async fn get_one(t: &Transport, id: &str) -> Result<Case> {
    cases::get(t, id).await
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCase {
    pub id: String,
    pub version: String,
    pub title: String,
    pub status: String,
}

fn case_noun(n: usize) -> &'static str {
    if n == 1 { "case" } else { "cases" }
}

/// Resolve explicit case ids. Fail-closed: every id must resolve or nothing
/// proceeds; duplicates collapse preserving first-seen order.
async fn resolve_cases(t: &Transport, ids: &[String]) -> Result<Vec<ResolvedCase>> {
    let mut unique: Vec<String> = Vec::with_capacity(ids.len());
    for id in ids {
        if !unique.contains(id) {
            unique.push(id.clone());
        }
    }
    let mut resolved = Vec::with_capacity(unique.len());
    let mut missing = Vec::new();
    for id in &unique {
        match cases::get(t, id).await {
            Ok(case) => resolved.push(ResolvedCase {
                id: case.id,
                version: case.version,
                title: case.title,
                status: case.status,
            }),
            Err(e) if e.kind == ErrorKind::NotFound => missing.push(id.clone()),
            Err(e) => return Err(e),
        }
    }
    if !missing.is_empty() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("No case with id: {}", missing.join(", ")),
        ));
    }
    Ok(resolved)
}

/// The compact case row for list output and mutation reports: stable columns
/// in a fixed order (`preserve_order` makes this the render contract).
pub fn case_row(case: &Case) -> Value {
    let mut row = serde_json::Map::new();
    row.insert("id".into(), Value::String(case.id.clone()));
    row.insert("title".into(), Value::String(case.title.clone()));
    row.insert("status".into(), Value::String(case.status.clone()));
    if let Some(severity) = &case.severity {
        row.insert("severity".into(), Value::String(severity.clone()));
    }
    row.insert("tags".into(), serde_json::json!(case.tags));
    if let Some(n) = case.total_comment {
        row.insert("comments".into(), serde_json::json!(n));
    }
    if let Some(at) = &case.created_at {
        row.insert("created_at".into(), Value::String(at.clone()));
    }
    if let Some(at) = &case.updated_at {
        row.insert("updated_at".into(), Value::String(at.clone()));
    }
    Value::Object(row)
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CaseEditReport {
    pub applied: bool,
    pub total: u64,
    pub updated: u64,
    /// `render::exit_code_for_value` keys on this field: a positive count
    /// exits 1. Field order is the rendered JSON key order (`preserve_order`).
    pub failed: u64,
    /// One entry per failed unit of work (currently only `apply_attach`'s
    /// per-rule-group comment POSTs), naming what failed and why. Empty for
    /// every other mutation's report. Appended after `failed` so existing
    /// consumers of the field order are unaffected.
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreatePlan {
    pub new: NewCase,
    pub preview_action: String,
    pub preview_details: Vec<String>,
}

pub async fn plan_create(
    t: &Transport,
    title: &str,
    description: Option<String>,
    tags: Vec<String>,
    severity: Option<String>,
    assignees: &[String],
) -> Result<CreatePlan> {
    if title.trim().is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "a case needs a non-empty --title",
        ));
    }
    let mut details = Vec::new();
    if let Some(severity) = &severity {
        details.push(format!("severity: {severity}"));
    }
    if !tags.is_empty() {
        details.push(format!("tags: {}", tags.join(", ")));
    }
    let mut assignee_uids = Vec::with_capacity(assignees.len());
    for user in assignees {
        let uid = profiles::resolve_assignee(t, user).await?;
        details.push(format!("assign {user} -> {uid}"));
        assignee_uids.push(uid);
    }
    Ok(CreatePlan {
        preview_action: format!("Create case '{title}'"),
        new: NewCase {
            title: title.to_string(),
            description,
            tags,
            severity,
            assignee_uids,
        },
        preview_details: details,
    })
}

pub async fn apply_create(t: &Transport, plan: &CreatePlan) -> Result<Value> {
    let case = cases::create(t, &plan.new).await?;
    let mut row = case_row(&case);
    if let Some(obj) = row.as_object_mut() {
        obj.insert("applied".into(), Value::Bool(true));
    }
    Ok(row)
}

#[derive(Debug, Clone, PartialEq)]
pub struct StatusPlan {
    pub target: CaseStatus,
    /// Only the cases actually transitioning: (id, version, target).
    pub updates: Vec<(String, String, CaseStatus)>,
    /// The resolved, deduplicated case count the preview names — what a
    /// dry-run stub must report, not the raw argv count.
    pub resolved: usize,
    pub preview_action: String,
    pub preview_details: Vec<String>,
}

/// Fetch each case for its version, mark already-in-state rows, and PATCH
/// only the rest. A no-op set still previews and reports zero updates.
pub async fn plan_status(t: &Transport, ids: &[String], target: CaseStatus) -> Result<StatusPlan> {
    let resolved = resolve_cases(t, ids).await?;
    let mut updates = Vec::new();
    let mut details = Vec::new();
    for case in &resolved {
        if case.status == target.as_str() {
            details.push(format!(
                "{}  {}  already {}",
                case.id, case.title, case.status
            ));
        } else {
            details.push(format!(
                "{}  {}  {} -> {}",
                case.id,
                case.title,
                case.status,
                target.as_str()
            ));
            updates.push((case.id.clone(), case.version.clone(), target));
        }
    }
    Ok(StatusPlan {
        preview_action: format!(
            "{} {} {}",
            target.verb(),
            resolved.len(),
            case_noun(resolved.len())
        ),
        target,
        updates,
        resolved: resolved.len(),
        preview_details: details,
    })
}

pub async fn apply_status(t: &Transport, plan: &StatusPlan) -> Result<CaseEditReport> {
    if plan.updates.is_empty() {
        return Ok(CaseEditReport {
            applied: true,
            total: 0,
            updated: 0,
            failed: 0,
            failures: Vec::new(),
        });
    }
    let updated = cases::patch_status(t, &plan.updates).await.map_err(|e| {
        if e.kind == ErrorKind::Conflict {
            Error::new(
                ErrorKind::Conflict,
                format!(
                    "a case changed since the preview ({}); re-run the command",
                    e.message
                ),
            )
        } else {
            e
        }
    })?;
    let total = plan.updates.len() as u64;
    let updated = updated.len() as u64;
    Ok(CaseEditReport {
        applied: true,
        total,
        updated,
        // `abs_diff`, not `saturating_sub`: a surplus response (more cases
        // came back than were sent) is a mismatch too, and `total -
        // updated` would saturate that at 0 and read it as zero failures.
        failed: total.abs_diff(updated),
        failures: Vec::new(),
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeletePlan {
    pub targets: Vec<String>,
    pub preview_action: String,
    pub preview_details: Vec<String>,
}

/// The 0.4 area's only destructive verb: the preview names each title.
pub async fn plan_delete(t: &Transport, ids: &[String]) -> Result<DeletePlan> {
    let resolved = resolve_cases(t, ids).await?;
    Ok(DeletePlan {
        preview_action: format!(
            "Delete {} {} permanently",
            resolved.len(),
            case_noun(resolved.len())
        ),
        preview_details: resolved
            .iter()
            .map(|c| format!("{}  {}  ({})", c.id, c.title, c.status))
            .collect(),
        targets: resolved.into_iter().map(|c| c.id).collect(),
    })
}

pub async fn apply_delete(t: &Transport, plan: &DeletePlan) -> Result<CaseEditReport> {
    cases::delete(t, &plan.targets).await?;
    Ok(CaseEditReport {
        applied: true,
        total: plan.targets.len() as u64,
        updated: plan.targets.len() as u64,
        failed: 0,
        failures: Vec::new(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachGroup {
    pub rule_id: String,
    pub rule_name: String,
    pub alert_ids: Vec<String>,
    pub indices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttachPlan {
    pub case_id: String,
    pub groups: Vec<AttachGroup>,
    /// The resolved, deduplicated alert count the preview names — what a
    /// dry-run stub must report, not the raw argv count.
    pub resolved: usize,
    pub preview_action: String,
    pub preview_details: Vec<String>,
}

/// Resolve the case (for its title) and every alert (id, index, rule),
/// fail-closed on any missing alert, then group by rule — the comments route
/// takes one `rule` object per comment.
pub async fn plan_attach(t: &Transport, case_id: &str, alert_ids: &[String]) -> Result<AttachPlan> {
    if alert_ids.is_empty() {
        return Err(Error::new(ErrorKind::Error, "pass at least one --alert id"));
    }
    let case = cases::get(t, case_id).await?;
    let mut unique: Vec<String> = Vec::with_capacity(alert_ids.len());
    for id in alert_ids {
        if !unique.contains(id) {
            unique.push(id.clone());
        }
    }
    let body = serde_json::json!({
        "query": {"ids": {"values": unique}},
        "size": unique.len(),
        "_source": ["kibana.alert.rule.name", "kibana.alert.rule.uuid", "kibana.alert.workflow_status"],
    });
    let page = alerts::search(t, &body).await?;
    let missing: Vec<&str> = unique
        .iter()
        .filter(|id| !page.hits.iter().any(|h| &h.id == *id))
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("No alert with id: {}", missing.join(", ")),
        ));
    }
    let mut groups: Vec<AttachGroup> = Vec::new();
    let mut details = Vec::new();
    for id in &unique {
        let hit = page
            .hits
            .iter()
            .find(|h| &h.id == id)
            .expect("checked above");
        let rule_id = source_str(&hit.source, "kibana.alert.rule.uuid")
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Http,
                    "decoding alert field `kibana.alert.rule.uuid`",
                )
            })?
            .to_string();
        let rule_name = source_str(&hit.source, "kibana.alert.rule.name")
            .unwrap_or("(unnamed rule)")
            .to_string();
        let index = hit.index.clone().ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                "decoding alert field `_index` (needed to attach)",
            )
        })?;
        details.push(format!("{}  {}", id, rule_name));
        match groups.iter_mut().find(|g| g.rule_id == rule_id) {
            Some(group) => {
                group.alert_ids.push(id.clone());
                group.indices.push(index);
            }
            None => groups.push(AttachGroup {
                rule_id,
                rule_name,
                alert_ids: vec![id.clone()],
                indices: vec![index],
            }),
        }
    }
    Ok(AttachPlan {
        preview_action: format!(
            "Attach {} {} to case '{}'",
            unique.len(),
            if unique.len() == 1 { "alert" } else { "alerts" },
            case.title
        ),
        case_id: case.id,
        groups,
        resolved: unique.len(),
        preview_details: details,
    })
}

/// One comments POST per rule group (the API takes one `rule` per comment).
/// A failed group must not discard the groups that already attached: a `?`
/// on the first error would report only the raw error while leaving earlier
/// groups attached, and a retry would then double-attach them. Accumulate
/// per-group outcomes instead, so a partial failure renders as counts plus
/// per-group detail rather than an opaque error.
pub async fn apply_attach(t: &Transport, plan: &AttachPlan) -> Result<CaseEditReport> {
    let total = plan.resolved as u64;
    let mut attached = 0u64;
    let mut failures = Vec::new();
    for group in &plan.groups {
        match cases::attach_alerts(
            t,
            &plan.case_id,
            &group.alert_ids,
            &group.indices,
            &group.rule_id,
            &group.rule_name,
        )
        .await
        {
            Ok(_) => attached += group.alert_ids.len() as u64,
            Err(e) => failures.push(format!("{}: {}", group.rule_name, e.message)),
        }
    }
    Ok(CaseEditReport {
        applied: true,
        total,
        updated: attached,
        // `abs_diff`, not `saturating_sub`: a surplus (more alerts attached
        // than the plan resolved) is a mismatch too, and `total - attached`
        // would saturate that at 0 and read it as zero failures.
        failed: total.abs_diff(attached),
        failures,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct CommentPlan {
    pub case_id: String,
    pub message: String,
    pub preview_action: String,
    pub preview_details: Vec<String>,
}

pub async fn plan_comment(t: &Transport, case_id: &str, message: &str) -> Result<CommentPlan> {
    if message.trim().is_empty() {
        return Err(Error::new(ErrorKind::Error, "pass a non-empty --message"));
    }
    let case = cases::get(t, case_id).await?;
    Ok(CommentPlan {
        preview_action: format!("Comment on case '{}'", case.title),
        preview_details: vec![message.to_string()],
        case_id: case.id,
        message: message.to_string(),
    })
}

pub async fn apply_comment(t: &Transport, plan: &CommentPlan) -> Result<CaseEditReport> {
    cases::add_comment(t, &plan.case_id, &plan.message).await?;
    Ok(CaseEditReport {
        applied: true,
        total: 1,
        updated: 1,
        failed: 0,
        failures: Vec::new(),
    })
}
