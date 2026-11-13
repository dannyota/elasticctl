mod recheck;
pub use recheck::{AlertFacet, observe_alerts};
mod observed;
pub use observed::{plan_status_by_ids_observed, plan_tags_observed};

use crate::alerts::{self, AlertHit, AlertStatus, Conflicts, SignalsOutcome};
use crate::{profiles, selection};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::{Value, json};

#[derive(Debug, Clone, Default)]
pub struct AlertFilter {
    pub status: Option<AlertStatus>,
    pub severity: Option<String>,
    pub rule: Option<String>,
    pub tag: Option<String>,
    pub assignee: Option<String>,
    pub since: Option<String>,
    pub search: Option<String>,
}

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

pub fn default_sort() -> Value {
    json!([
        {"@timestamp": {"order": "desc"}},
        {"kibana.alert.uuid": {"order": "asc"}}
    ])
}

fn escape_wildcard(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('*', "\\*")
        .replace('?', "\\?")
}

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
        let pattern = format!("*{}*", escape_wildcard(text));
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

pub async fn list(t: &Transport, f: &AlertFilter, limit: usize) -> Result<AlertList> {
    let query = build_query(t, f).await?;
    let body = json!({
        "query": query,
        "sort": default_sort(),
        "size": limit.saturating_add(1),
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

pub async fn export(t: &Transport, f: &AlertFilter, limit: Option<usize>) -> Result<Vec<AlertHit>> {
    let query = build_query(t, f).await?;
    alerts::search_all(t, &query, &default_sort(), limit).await
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAlert {
    pub id: String,
    pub rule_name: String,
    pub status: String,
}

pub const RESOLVE_SOURCE_FIELDS: &[&str] =
    &["kibana.alert.rule.name", "kibana.alert.workflow_status"];

pub(crate) fn source_str<'a>(source: &'a Value, key: &str) -> Option<&'a str> {
    if let Some(v) = source.get(key).and_then(Value::as_str) {
        return Some(v);
    }
    let pointer = format!("/{}", key.replace('.', "/"));
    source.pointer(&pointer).and_then(Value::as_str)
}

fn workflow_status(source: &Value) -> &str {
    source_str(source, "kibana.alert.workflow_status").unwrap_or("unknown")
}

fn resolve_body(unique: &[String]) -> Value {
    json!({
        "query": {"ids": {"values": unique}},
        "size": unique.len(),
        "_source": RESOLVE_SOURCE_FIELDS,
    })
}

async fn resolve_ids(t: &Transport, ids: &[String]) -> Result<Vec<ResolvedAlert>> {
    let mut unique: Vec<String> = Vec::with_capacity(ids.len());
    for id in ids {
        if !unique.contains(id) {
            unique.push(id.clone());
        }
    }
    let body = resolve_body(&unique);
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
            status: workflow_status(&hit.source).to_string(),
        });
    }
    Ok(resolved)
}

fn alert_noun(n: usize) -> &'static str {
    if n == 1 { "alert" } else { "alerts" }
}

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
    Ok(plan_status_by_ids_observed(t, ids, status, reason).await?.0)
}

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

fn failed_count(outcome: &SignalsOutcome, conflicts: Conflicts) -> Result<u64> {
    (outcome.failures.len() as u64)
        .checked_add(match conflicts {
            Conflicts::Abort => outcome.version_conflicts,
            Conflicts::Proceed => 0,
        })
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                "decoding alert response: counters are unreadable (failure count overflows u64)",
            )
        })
}

fn status_report(
    status: AlertStatus,
    outcome: SignalsOutcome,
    conflicts: Conflicts,
) -> Result<StatusReport> {
    Ok(StatusReport {
        applied: true,
        status: status.as_str().to_string(),
        total: outcome.total,
        updated: outcome.updated,
        version_conflicts: outcome.version_conflicts,
        noops: outcome.noops,
        failed: failed_count(&outcome, conflicts)?,
        failures: outcome.failures,
    })
}

pub async fn apply_status_by_ids(t: &Transport, plan: &StatusPlan) -> Result<StatusReport> {
    require_targets(&plan.targets)?;
    let outcome =
        alerts::status_by_ids(t, &plan.targets, plan.status, plan.reason.as_deref()).await?;
    status_report(plan.status, outcome, Conflicts::Abort)
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

fn require_scoped_query(query: &Value) -> Result<()> {
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
    Ok(())
}

pub async fn plan_status_by_query(
    t: &Transport,
    query: Value,
    status: AlertStatus,
    conflicts: Conflicts,
    reason: Option<String>,
) -> Result<QueryStatusPlan> {
    require_scoped_query(&query)?;
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
    require_scoped_query(&plan.query)?;
    let outcome = alerts::status_by_query(
        t,
        &plan.query,
        plan.status,
        plan.conflicts,
        plan.reason.as_deref(),
    )
    .await?;
    status_report(plan.status, outcome, plan.conflicts)
}

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

fn edit_report(outcome: SignalsOutcome) -> Result<EditReport> {
    Ok(EditReport {
        applied: true,
        total: outcome.total,
        updated: outcome.updated,
        version_conflicts: outcome.version_conflicts,
        noops: outcome.noops,
        failed: failed_count(&outcome, Conflicts::Abort)?,
        failures: outcome.failures,
    })
}

fn require_targets(ids: &[String]) -> Result<()> {
    if ids.is_empty() {
        return Err(Error::new(ErrorKind::Error, "pass at least one alert id"));
    }
    Ok(())
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
    Ok(plan_tags_observed(t, ids, add, remove).await?.0)
}

pub async fn apply_tags(t: &Transport, plan: &TagsPlan) -> Result<EditReport> {
    require_targets(&plan.targets)?;
    require_edit(&plan.add, &plan.remove)?;
    require_disjoint(&plan.add, &plan.remove, "tags")?;
    edit_report(alerts::set_tags(t, &plan.targets, &plan.add, &plan.remove).await?)
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssignPlan {
    pub targets: Vec<String>,
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
    require_targets(ids)?;
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
    require_targets(&plan.targets)?;
    require_edit(&plan.add, &plan.remove)?;
    require_disjoint(&plan.add, &plan.remove, "assignees")?;
    edit_report(alerts::set_assignees(t, &plan.targets, &plan.add, &plan.remove).await?)
}
