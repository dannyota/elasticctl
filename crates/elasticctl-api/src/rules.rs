//! Typed wrappers over the detection-engine API.
//!
//! Every function keys on the stable `rule_id`, never on the volatile
//! server-side `id`.

use crate::codec;
use crate::model::{ExportSummary, Rule};
use crate::normalize;
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
            parts.push(format!(
                "alert.attributes.params.type: \"{}\"",
                kql_escape(v)
            ));
        }
        if let Some(v) = &self.severity {
            parts.push(format!(
                "alert.attributes.params.severity: \"{}\"",
                kql_escape(v)
            ));
        }
        if let Some(v) = &self.tag {
            parts.push(format!("alert.attributes.tags: \"{}\"", kql_escape(v)));
        }
        if let Some(v) = &self.query {
            parts.push(v.clone());
        }
        (!parts.is_empty()).then(|| parts.join(" AND "))
    }
}

/// Escape a value for use inside a double-quoted KQL literal.
///
/// Without this, a value containing a quote closes the literal early and the
/// rest is parsed as KQL — turning a scoped bulk action into an unscoped one.
/// Backslash must be escaped first, or it would double-escape the quotes added
/// after it.
fn kql_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// KQL selecting exactly the given stable rule ids.
fn rule_id_query(rule_ids: &[String]) -> String {
    rule_ids
        .iter()
        .map(|id| format!("alert.attributes.params.ruleId: \"{}\"", kql_escape(id)))
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
    let mut payload = rule.clone();
    normalize::strip_volatile(&mut payload);
    let response = t
        .post(BASE, Some(&Value::Object(payload.as_map().clone())))
        .await?;
    Rule::from_value(response)
}

pub async fn update(t: &Transport, rule: &Rule) -> Result<Rule> {
    let mut payload = rule.clone();
    normalize::strip_volatile(&mut payload);
    let response = t
        .put(BASE, &Value::Object(payload.as_map().clone()))
        .await?;
    Rule::from_value(response)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kql_escape_doubles_a_lone_backslash() {
        assert_eq!(kql_escape("a\\b"), "a\\\\b");
    }

    #[test]
    fn kql_escape_escapes_a_lone_quote() {
        let mut expected = String::from("a");
        expected.push('\\');
        expected.push('"');
        expected.push('b');
        assert_eq!(kql_escape("a\"b"), expected);
    }

    /// A literal backslash immediately followed by a quote is the case that
    /// distinguishes escape order: escaping quotes before backslashes would
    /// double the backslash the quote-escape just inserted, corrupting the
    /// result.
    #[test]
    fn kql_escape_orders_backslash_before_quote() {
        let mut input = String::new();
        input.push('\\');
        input.push('"');

        let escaped = kql_escape(&input);

        // Correct order: the lone backslash is doubled first, then the quote
        // is escaped, giving three backslashes followed by a quote.
        let mut expected = "\\".repeat(3);
        expected.push('"');
        assert_eq!(escaped, expected);
    }

    #[test]
    fn rule_id_query_escapes_a_quote_in_the_id() {
        let mut id = String::from("x");
        id.push('"');
        id.push('y');

        let q = rule_id_query(&[id]);

        let mut expected = String::from("alert.attributes.params.ruleId: \"x");
        expected.push('\\');
        expected.push('"');
        expected.push_str("y\"");
        assert_eq!(q, expected);
        assert!(
            !q.contains(" OR "),
            "a single id must produce exactly one clause: {q}"
        );
    }

    #[test]
    fn rule_id_query_neutralizes_a_kql_injection_payload() {
        let payload = "x\" or alert.attributes.enabled: true or \"";
        let q = rule_id_query(&[payload.to_string()]);
        assert!(
            !q.contains("\" or alert.attributes.enabled: true or \""),
            "the injected quote must not close the literal: {q}"
        );
    }

    #[test]
    fn to_kql_escapes_a_quote_in_the_tag() {
        let f = RuleFilter {
            tag: Some("a\"b".into()),
            ..Default::default()
        };
        let kql = f.to_kql().unwrap();

        let mut expected = String::from("alert.attributes.tags: \"a");
        expected.push('\\');
        expected.push('"');
        expected.push_str("b\"");
        assert_eq!(kql, expected);
    }
}
