//! Alert orchestration: filter construction, list/get, and the triage
//! mutation plans behind the CLI guard.

use crate::alerts::{self, AlertHit, AlertStatus};
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

/// The `--out` path: page the filtered set fully.
pub async fn export(t: &Transport, f: &AlertFilter) -> Result<Vec<AlertHit>> {
    let query = build_query(t, f).await?;
    alerts::search_all(t, &query, &default_sort(), None).await
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
