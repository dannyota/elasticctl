//! Typed wrappers over the detection-engine API.
//!
//! Every function keys on the stable `rule_id`, never on the volatile
//! server-side `id`.

use crate::codec;
use crate::model::{ExportSummary, Rule};
use elasticctl_core::{Result, Transport};
use serde_json::{Value, json};

const BASE: &str = "/api/detection_engine/rules";
const DEFAULT_PAGE_SIZE: u32 = 100;
/// Backstop against a server that reports a total it never serves.
const MAX_PAGES: u32 = 1000;

#[derive(Debug, Clone, Default)]
pub struct RuleFilter {
    pub enabled: Option<bool>,
    pub rule_type: Option<String>,
    pub severity: Option<String>,
    pub tag: Option<String>,
    /// A raw KQL fragment, combined with the structured filters above.
    pub query: Option<String>,
}

impl RuleFilter {
    /// Kibana filters saved objects with KQL over `alert.attributes.*`.
    pub fn to_kql(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        if let Some(v) = self.enabled {
            parts.push(format!("alert.attributes.enabled: {v}"));
        }
        if let Some(v) = &self.rule_type {
            parts.push(format!("alert.attributes.params.type: \"{v}\""));
        }
        if let Some(v) = &self.severity {
            parts.push(format!("alert.attributes.params.severity: \"{v}\""));
        }
        if let Some(v) = &self.tag {
            parts.push(format!("alert.attributes.tags: \"{v}\""));
        }
        if let Some(v) = &self.query {
            parts.push(v.clone());
        }
        (!parts.is_empty()).then(|| parts.join(" AND "))
    }
}

/// KQL selecting exactly the given stable rule ids.
fn rule_id_query(rule_ids: &[String]) -> String {
    rule_ids
        .iter()
        .map(|id| format!("alert.attributes.params.ruleId: \"{id}\""))
        .collect::<Vec<_>>()
        .join(" OR ")
}

pub async fn find_page(
    t: &Transport,
    filter: &RuleFilter,
    page: u32,
    per_page: u32,
) -> Result<(Vec<Rule>, u64)> {
    let mut path = format!("{BASE}/_find?page={page}&per_page={per_page}");
    if let Some(kql) = filter.to_kql() {
        path.push_str(&format!("&filter={}", urlencode(&kql)));
    }

    let body = t.get(&path).await?;
    let total = body["total"].as_u64().unwrap_or(0);
    let data = body["data"].as_array().cloned().unwrap_or_default();
    let rules = data
        .into_iter()
        .map(Rule::from_value)
        .collect::<Result<Vec<_>>>()?;
    Ok((rules, total))
}

pub async fn find_all(t: &Transport, filter: &RuleFilter) -> Result<Vec<Rule>> {
    let mut all = Vec::new();
    let mut page = 1;

    loop {
        let (rules, total) = find_page(t, filter, page, DEFAULT_PAGE_SIZE).await?;
        // Stop on an empty page even if `total` claims more, so a server that
        // over-reports cannot spin this loop forever.
        if rules.is_empty() {
            break;
        }
        all.extend(rules);
        if all.len() as u64 >= total || page >= MAX_PAGES {
            break;
        }
        page += 1;
    }

    Ok(all)
}

pub async fn get(t: &Transport, rule_id: &str) -> Result<Rule> {
    let body = t
        .get(&format!("{BASE}?rule_id={}", urlencode(rule_id)))
        .await?;
    Rule::from_value(body)
}

pub async fn create(t: &Transport, rule: &Rule) -> Result<Rule> {
    let body = t
        .post(BASE, Some(&Value::Object(rule.as_map().clone())))
        .await?;
    Rule::from_value(body)
}

pub async fn update(t: &Transport, rule: &Rule) -> Result<Rule> {
    let body = t.put(BASE, &Value::Object(rule.as_map().clone())).await?;
    Rule::from_value(body)
}

pub async fn patch(t: &Transport, rule_id: &str, patch: &Value) -> Result<Rule> {
    let mut body = patch.as_object().cloned().unwrap_or_default();
    body.insert("rule_id".into(), json!(rule_id));
    // PATCH is the documented partial update and accepts rule_id directly,
    // which avoids resolving the volatile server id.
    let response = t.patch(BASE, &Value::Object(body)).await?;
    Rule::from_value(response)
}

pub async fn delete(t: &Transport, rule_id: &str) -> Result<Rule> {
    let body = t
        .delete(&format!("{BASE}?rule_id={}", urlencode(rule_id)))
        .await?;
    Rule::from_value(body)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkAction {
    Enable,
    Disable,
    Delete,
}

impl BulkAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BulkOutcome {
    pub succeeded: u64,
    pub failed: u64,
    pub skipped: u64,
    pub total: u64,
}

pub async fn bulk_by_rule_ids(
    t: &Transport,
    action: BulkAction,
    rule_ids: &[String],
    dry_run: bool,
) -> Result<BulkOutcome> {
    // An empty selection must never become an unscoped query — that would
    // target every rule in the space.
    if rule_ids.is_empty() {
        return Ok(BulkOutcome::default());
    }

    let path = if dry_run {
        format!("{BASE}/_bulk_action?dry_run=true")
    } else {
        format!("{BASE}/_bulk_action")
    };
    let body = json!({ "action": action.as_str(), "query": rule_id_query(rule_ids) });

    let response = t.post(&path, Some(&body)).await?;
    let s = &response["attributes"]["summary"];
    Ok(BulkOutcome {
        succeeded: s["succeeded"].as_u64().unwrap_or(0),
        failed: s["failed"].as_u64().unwrap_or(0),
        skipped: s["skipped"].as_u64().unwrap_or(0),
        total: s["total"].as_u64().unwrap_or(0),
    })
}

pub async fn export(t: &Transport) -> Result<(Vec<Rule>, Option<ExportSummary>)> {
    let body = t.post_text(&format!("{BASE}/_export"), None).await?;
    codec::decode_ndjson(&body)
}

pub async fn import(t: &Transport, ndjson: &str, overwrite: bool) -> Result<Value> {
    t.post_multipart_ndjson(&format!("{BASE}/_import?overwrite={overwrite}"), ndjson)
        .await
}

/// Percent-encode a query-string value. Only the characters that actually
/// break a URL are escaped, so recorded fixtures stay readable.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
