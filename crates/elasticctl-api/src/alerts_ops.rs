//! Alert orchestration: filter construction, list/get, and the triage
//! mutation plans behind the CLI guard.

use crate::alerts::{self, AlertHit, AlertStatus, Conflicts, SignalsOutcome};
use crate::{profiles, selection};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::{Value, json};

/// The `alerts list` filter set. Every field composes into one boolean query
/// over the measured `kibana.alert.*` fields (triage spec section 4).
#[derive(Debug, Clone, Default)]
pub struct AlertFilter {
    pub status: Option<AlertStatus>,
    pub severity: Option<String>,
    /// A rule name or `rule_id`, resolved through the standard name-or-id
    /// resolution before filtering on `kibana.alert.rule.rule_id`.
    pub rule: Option<String>,
    pub tag: Option<String>,
    /// A username or `uid:<profile_uid>`, resolved to a profile uid.
    pub assignee: Option<String>,
    /// A duration (`90m`, `24h`, `7d`) or an ISO timestamp.
    pub since: Option<String>,
    /// Substring match on the rule name and reason text.
    pub search: Option<String>,
}

/// `--since` as a range clause: `<digits><s|m|h|d|w>` becomes `now-<dur>`;
/// anything else passes through verbatim for the server to validate as a
/// timestamp or date-math expression.
pub fn since_clause(since: &str) -> Value {
    let bytes = since.as_bytes();
    let is_duration = bytes.len() >= 2
        && bytes[..bytes.len() - 1].iter().all(u8::is_ascii_digit)
        && matches!(bytes[bytes.len() - 1], b's' | b'm' | b'h' | b'd' | b'w');
    let gte = if is_duration {
        format!("now-{since}")
    } else {
        since.to_string()
    };
    json!({"range": {"@timestamp": {"gte": gte}}})
}

/// Newest first, with `kibana.alert.uuid` as the total-order tiebreaker
/// `search_after` needs.
pub fn default_sort() -> Value {
    json!([
        {"@timestamp": {"order": "desc"}},
        {"kibana.alert.uuid": {"order": "asc"}}
    ])
}

/// Compose the filter into one boolean query, resolving `rule` and
/// `assignee` first. An empty filter is an explicit `match_all`.
pub async fn build_query(t: &Transport, f: &AlertFilter) -> Result<Value> {
    let mut filter = Vec::new();
    if let Some(status) = f.status {
        filter.push(json!({"term": {"kibana.alert.workflow_status": status.as_str()}}));
    }
    if let Some(severity) = &f.severity {
        filter.push(json!({"term": {"kibana.alert.severity": severity}}));
    }
    if let Some(rule) = &f.rule {
        let rule_id = selection::to_rule_id(t, rule).await?;
        filter.push(json!({"term": {"kibana.alert.rule.rule_id": rule_id}}));
    }
    if let Some(tag) = &f.tag {
        filter.push(json!({"term": {"kibana.alert.workflow_tags": tag}}));
    }
    if let Some(assignee) = &f.assignee {
        let uid = profiles::resolve_assignee(t, assignee).await?;
        filter.push(json!({"term": {"kibana.alert.workflow_assignee_ids": uid}}));
    }
    if let Some(since) = &f.since {
        filter.push(since_clause(since));
    }
    if let Some(text) = &f.search {
        let pattern = format!("*{text}*");
        filter.push(json!({"bool": {"minimum_should_match": 1, "should": [
            {"wildcard": {"kibana.alert.rule.name": {"value": pattern, "case_insensitive": true}}},
            {"wildcard": {"kibana.alert.reason": {"value": pattern, "case_insensitive": true}}}
        ]}}));
    }
    if filter.is_empty() {
        Ok(json!({"match_all": {}}))
    } else {
        Ok(json!({"bool": {"filter": filter}}))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlertList {
    pub hits: Vec<AlertHit>,
    pub total: Option<u64>,
    pub truncated: bool,
}

/// One bounded peek: `limit + 1` rows so truncation is observable without a
/// second request.
pub async fn list(t: &Transport, f: &AlertFilter, limit: usize) -> Result<AlertList> {
    let query = build_query(t, f).await?;
    let body = json!({
        "query": query,
        "sort": default_sort(),
        "size": limit + 1,
        "track_total_hits": true,
    });
    let mut page = alerts::search(t, &body).await?;
    let truncated = page.hits.len() > limit;
    page.hits.truncate(limit);
    Ok(AlertList {
        hits: page.hits,
        total: page.total,
        truncated,
    })
}

/// The `--out` path: page the filtered set fully, or stop at `limit` rows
/// when the caller passes one (matching `search dsl --out --limit`).
pub async fn export(t: &Transport, f: &AlertFilter, limit: Option<usize>) -> Result<Vec<AlertHit>> {
    let query = build_query(t, f).await?;
    alerts::search_all(t, &query, &default_sort(), limit).await
}

/// `alerts get`: an `_id`-filtered search returning one document.
pub async fn get_one(t: &Transport, alert_id: &str) -> Result<AlertHit> {
    let body = json!({"query": {"ids": {"values": [alert_id]}}, "size": 1});
    let page = alerts::search(t, &body).await?;
    page.hits.into_iter().next().ok_or_else(|| {
        Error::new(
            ErrorKind::NotFound,
            format!("No alert with id '{alert_id}'"),
        )
    })
}

/// One explicitly named alert, resolved before a preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAlert {
    pub id: String,
    pub rule_name: String,
    pub status: String,
}

/// `_source` fields `resolve_ids` requests: only what a mutation preview
/// renders (rule name and current workflow status), not the whole document.
/// `pub` so the fixture recorder can send the identical production body
/// instead of a hand-rolled approximation (triage spec section 10).
pub const RESOLVE_SOURCE_FIELDS: &[&str] =
    &["kibana.alert.rule.name", "kibana.alert.workflow_status"];

/// Alert documents store dotted field names as flat `_source` keys; older
/// pipelines may nest them. Read both shapes.
fn source_str<'a>(source: &'a Value, key: &str) -> Option<&'a str> {
    if let Some(v) = source.get(key).and_then(Value::as_str) {
        return Some(v);
    }
    let pointer = format!("/{}", key.replace('.', "/"));
    source.pointer(&pointer).and_then(Value::as_str)
}

/// Resolve explicit ids to alerts. Fail-closed: every id must resolve or the
/// command refuses to proceed on the partial set (main spec section 6.3).
/// Duplicate ids are collapsed, preserving first-seen order.
async fn resolve_ids(t: &Transport, ids: &[String]) -> Result<Vec<ResolvedAlert>> {
    let mut unique: Vec<String> = Vec::with_capacity(ids.len());
    for id in ids {
        if !unique.contains(id) {
            unique.push(id.clone());
        }
    }
    let body = json!({
        "query": {"ids": {"values": unique}},
        "size": unique.len(),
        "_source": RESOLVE_SOURCE_FIELDS,
    });
    let page = alerts::search(t, &body).await?;
    let mut resolved = Vec::with_capacity(unique.len());
    for id in &unique {
        let hit = page.hits.iter().find(|h| &h.id == id).ok_or_else(|| {
            let missing: Vec<&str> = unique
                .iter()
                .filter(|i| !page.hits.iter().any(|h| &h.id == *i))
                .map(String::as_str)
                .collect();
            Error::new(
                ErrorKind::NotFound,
                format!("No alert with id: {}", missing.join(", ")),
            )
        })?;
        resolved.push(ResolvedAlert {
            id: id.clone(),
            rule_name: source_str(&hit.source, "kibana.alert.rule.name")
                .unwrap_or("(unnamed rule)")
                .to_string(),
            status: source_str(&hit.source, "kibana.alert.workflow_status")
                .unwrap_or("unknown")
                .to_string(),
        });
    }
    Ok(resolved)
}

fn alert_noun(n: usize) -> &'static str {
    if n == 1 { "alert" } else { "alerts" }
}

/// `1214` → `1,214`, matching the preview format in triage spec section 6.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct StatusPlan {
    pub status: AlertStatus,
    pub reason: Option<String>,
    pub targets: Vec<String>,
    pub preview_action: String,
    pub preview_details: Vec<String>,
}

pub async fn plan_status_by_ids(
    t: &Transport,
    ids: &[String],
    status: AlertStatus,
    reason: Option<String>,
) -> Result<StatusPlan> {
    let resolved = resolve_ids(t, ids).await?;
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
    Ok(StatusPlan {
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
    })
}

/// The mutation report the CLI renders. `failed` is elasticctl's judgment —
/// route failures plus, under `--conflicts abort`, version conflicts — and
/// drives the non-zero exit; the verbatim counters render beside it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct StatusReport {
    pub applied: bool,
    pub status: String,
    pub total: u64,
    pub updated: u64,
    pub version_conflicts: u64,
    pub noops: u64,
    pub failed: u64,
    pub failures: Vec<Value>,
}

fn failed_count(outcome: &SignalsOutcome, conflicts: Conflicts) -> u64 {
    outcome.failures.len() as u64
        + match conflicts {
            Conflicts::Abort => outcome.version_conflicts,
            Conflicts::Proceed => 0,
        }
}

fn status_report(
    status: AlertStatus,
    outcome: SignalsOutcome,
    conflicts: Conflicts,
) -> StatusReport {
    StatusReport {
        applied: true,
        status: status.as_str().to_string(),
        total: outcome.total,
        updated: outcome.updated,
        version_conflicts: outcome.version_conflicts,
        noops: outcome.noops,
        failed: failed_count(&outcome, conflicts),
        failures: outcome.failures,
    }
}

pub async fn apply_status_by_ids(t: &Transport, plan: &StatusPlan) -> Result<StatusReport> {
    let outcome =
        alerts::status_by_ids(t, &plan.targets, plan.status, plan.reason.as_deref()).await?;
    Ok(status_report(plan.status, outcome, Conflicts::Abort))
}

pub const QUERY_SAMPLE_SIZE: usize = 10;

#[derive(Debug, Clone, PartialEq)]
pub struct QueryStatusPlan {
    pub status: AlertStatus,
    pub reason: Option<String>,
    pub conflicts: Conflicts,
    pub query: Value,
    pub matched: u64,
    pub preview_action: String,
    pub preview_details: Vec<String>,
}

/// Resolve the operator's query to a count and a sample so the implicit set
/// is visible before it is mutated (triage spec section 6).
pub async fn plan_status_by_query(
    t: &Transport,
    query: Value,
    status: AlertStatus,
    conflicts: Conflicts,
    reason: Option<String>,
) -> Result<QueryStatusPlan> {
    let obj = query
        .as_object()
        .ok_or_else(|| Error::new(ErrorKind::Error, "--query must be a JSON object"))?;
    if obj.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "an empty --query would mutate every alert; say what it matches, \
             e.g. an explicit {\"match_all\":{}}",
        ));
    }
    let body = json!({
        "query": &query,
        "size": QUERY_SAMPLE_SIZE,
        "track_total_hits": true,
        "sort": default_sort(),
        "_source": ["kibana.alert.rule.name", "kibana.alert.severity", "@timestamp"],
    });
    let page = alerts::search(t, &body).await?;
    let matched = page.total.ok_or_else(|| {
        Error::new(
            ErrorKind::Http,
            "decoding alerts response field `hits.total.value`",
        )
    })?;
    let mut preview_details = vec![format!(
        "matched now: {}   showing {} of {}",
        thousands(matched),
        page.hits.len(),
        thousands(matched)
    )];
    for hit in &page.hits {
        preview_details.push(format!(
            "{}  {}  {}  {}",
            hit.id,
            source_str(&hit.source, "kibana.alert.rule.name").unwrap_or("(unnamed rule)"),
            source_str(&hit.source, "kibana.alert.severity").unwrap_or("-"),
            source_str(&hit.source, "@timestamp").unwrap_or("-"),
        ));
    }
    preview_details.push("The set is resolved again at apply time; this count is advisory.".into());
    Ok(QueryStatusPlan {
        preview_action: format!("{} alerts matching query", status.verb()),
        status,
        reason,
        conflicts,
        query,
        matched,
        preview_details,
    })
}

pub async fn apply_status_by_query(t: &Transport, plan: &QueryStatusPlan) -> Result<StatusReport> {
    let outcome = alerts::status_by_query(
        t,
        &plan.query,
        plan.status,
        plan.conflicts,
        plan.reason.as_deref(),
    )
    .await?;
    Ok(status_report(plan.status, outcome, plan.conflicts))
}

/// The tags/assignees report: the same counters without a target status.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct EditReport {
    pub applied: bool,
    pub total: u64,
    pub updated: u64,
    pub version_conflicts: u64,
    pub noops: u64,
    pub failed: u64,
    pub failures: Vec<Value>,
}

fn edit_report(outcome: SignalsOutcome) -> EditReport {
    EditReport {
        applied: true,
        total: outcome.total,
        updated: outcome.updated,
        version_conflicts: outcome.version_conflicts,
        noops: outcome.noops,
        failed: failed_count(&outcome, Conflicts::Abort),
        failures: outcome.failures,
    }
}

fn require_edit(add: &[String], remove: &[String]) -> Result<()> {
    if add.is_empty() && remove.is_empty() {
        return Err(Error::new(ErrorKind::Error, "pass --add and/or --remove"));
    }
    Ok(())
}

fn require_disjoint(add: &[String], remove: &[String], what: &str) -> Result<()> {
    let overlap: Vec<&str> = add
        .iter()
        .filter(|a| remove.contains(a))
        .map(String::as_str)
        .collect();
    if overlap.is_empty() {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Conflict,
            format!("{what} both added and removed: {}", overlap.join(", ")),
        ))
    }
}

fn edit_summary(add: &[String], remove: &[String]) -> String {
    let mut parts: Vec<String> = add.iter().map(|a| format!("+{a}")).collect();
    parts.extend(remove.iter().map(|r| format!("-{r}")));
    parts.join(" ")
}

#[derive(Debug, Clone, PartialEq)]
pub struct TagsPlan {
    pub targets: Vec<String>,
    pub add: Vec<String>,
    pub remove: Vec<String>,
    pub preview_action: String,
    pub preview_details: Vec<String>,
}

pub async fn plan_tags(
    t: &Transport,
    ids: &[String],
    add: Vec<String>,
    remove: Vec<String>,
) -> Result<TagsPlan> {
    require_edit(&add, &remove)?;
    require_disjoint(&add, &remove, "tags")?;
    let resolved = resolve_ids(t, ids).await?;
    let summary = edit_summary(&add, &remove);
    let preview_details = resolved
        .iter()
        .map(|r| format!("{}  {}  {}", r.id, r.rule_name, summary))
        .collect();
    Ok(TagsPlan {
        preview_action: format!("Tag {} {}", resolved.len(), alert_noun(resolved.len())),
        targets: resolved.into_iter().map(|r| r.id).collect(),
        add,
        remove,
        preview_details,
    })
}

pub async fn apply_tags(t: &Transport, plan: &TagsPlan) -> Result<EditReport> {
    Ok(edit_report(
        alerts::set_tags(t, &plan.targets, &plan.add, &plan.remove).await?,
    ))
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssignPlan {
    pub targets: Vec<String>,
    /// Resolved profile uids.
    pub add: Vec<String>,
    pub remove: Vec<String>,
    pub preview_action: String,
    pub preview_details: Vec<String>,
}

pub async fn plan_assign(
    t: &Transport,
    ids: &[String],
    add_users: &[String],
    remove_users: &[String],
) -> Result<AssignPlan> {
    require_edit(add_users, remove_users)?;
    let mut add = Vec::with_capacity(add_users.len());
    let mut remove = Vec::with_capacity(remove_users.len());
    let mut mapping = Vec::new();
    for user in add_users {
        let uid = profiles::resolve_assignee(t, user).await?;
        mapping.push(format!("add {user} -> {uid}"));
        add.push(uid);
    }
    for user in remove_users {
        let uid = profiles::resolve_assignee(t, user).await?;
        mapping.push(format!("remove {user} -> {uid}"));
        remove.push(uid);
    }
    require_disjoint(&add, &remove, "assignees")?;
    let resolved = resolve_ids(t, ids).await?;
    let summary = edit_summary(&add, &remove);
    let mut preview_details = mapping;
    preview_details.extend(
        resolved
            .iter()
            .map(|r| format!("{}  {}  {}", r.id, r.rule_name, summary)),
    );
    Ok(AssignPlan {
        preview_action: format!("Assign {} {}", resolved.len(), alert_noun(resolved.len())),
        targets: resolved.into_iter().map(|r| r.id).collect(),
        add,
        remove,
        preview_details,
    })
}

pub async fn apply_assign(t: &Transport, plan: &AssignPlan) -> Result<EditReport> {
    Ok(edit_report(
        alerts::set_assignees(t, &plan.targets, &plan.add, &plan.remove).await?,
    ))
}
