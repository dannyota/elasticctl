//! Typed wrappers over the detection-engine API.
//!
//! Every function keys on the stable `rule_id`, never on the volatile
//! server-side `id`.

use crate::codec;
use crate::model::{ExportSummary, Rule};
use crate::normalize;
use elasticctl_core::{Error, ErrorKind, Result, Transport, urlencode};
use serde_json::{Value, json};

const BASE: &str = "/api/detection_engine/rules";

/// Elasticsearch's result window. `_find` is a search underneath, so
/// `from + size` must not exceed this: 10001 comes back as a 400 naming the
/// window.
///
/// It bounds `per_page` and, through the sum, the largest corpus `_find` can
/// return at all — paging smaller does not evade a limit on `from + size`.
/// Reading at the window is therefore both the fastest way to read a corpus
/// and the only page size that reads as much of one as exists: measured
/// against 2,066 rules, one request costs 2.4 s where 21 pages of 100 cost
/// 8.4-11 s.
const RESULT_WINDOW: u32 = 10_000;

#[derive(Debug, Clone, Default)]
pub struct RuleFilter {
    pub enabled: Option<bool>,
    pub rule_type: Option<String>,
    pub severity: Option<String>,
    pub tag: Option<String>,
    /// Exact display name, filtered server-side. Resolving a name by walking
    /// every page cost 8.8 seconds against 2,066 rules; this is one request.
    pub name: Option<String>,
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
        if let Some(v) = &self.name {
            parts.push(format!("alert.attributes.name: \"{}\"", kql_escape(v)));
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
    decode_find(&body)
}

/// Decode a `_find` response envelope into its rules and total. Extracted so
/// the recorded `rules_find` fixture can be decoded offline by the same path
/// the live client uses.
pub fn decode_find(body: &Value) -> Result<(Vec<Rule>, u64)> {
    let total = body["total"].as_u64().unwrap_or(0);
    let data = body["data"].as_array().cloned().unwrap_or_default();
    let rules = data
        .into_iter()
        .map(Rule::from_value)
        .collect::<Result<Vec<_>>>()?;
    Ok((rules, total))
}

/// The seven detection-rule types. Every rule has exactly one `params.type`,
/// so partitioning the corpus on it yields slices that are disjoint and
/// together exhaustive — measured against 2,066 rules the seven sum to exactly
/// the corpus (spec 5.2). Tags cannot make that claim: a rule may carry many
/// or none, so tag slices both double-count and drop rules and no sum check
/// could detect it.
const RULE_TYPES: [&str; 7] = [
    "query",
    "eql",
    "esql",
    "threshold",
    "threat_match",
    "machine_learning",
    "new_terms",
];

/// Every rule matching the filter.
///
/// A corpus at or under the result window is read in one request, which is
/// the fast path and covers every real corpus today. Above the window `_find`
/// cannot serve the corpus by any page size — the limit is on `from + size` —
/// so the read is partitioned: one request per rule type, with any type still
/// over the window split again on `enabled`, which is likewise disjoint and
/// exhaustive. Exhaustiveness is enforced by summing the slice totals back to
/// the corpus total, not assumed.
///
/// A partial corpus is never returned as though it were whole. `state diff`
/// would report every unread rule as locally added, and `state pull` would
/// write a mirror missing them, both silently.
pub async fn find_all(t: &Transport, filter: &RuleFilter) -> Result<Vec<Rule>> {
    let (rules, total) = find_page(t, filter, 1, RESULT_WINDOW).await?;

    if total <= u64::from(RESULT_WINDOW) {
        if (rules.len() as u64) < total {
            return Err(short_read(total, rules.len()));
        }
        return Ok(rules);
    }

    // A caller already narrowed to one type cannot be partitioned further by
    // type; the single slice is what it asked for, and only the enabled split
    // below can subdivide it.
    let types: Vec<&str> = match &filter.rule_type {
        Some(t) => vec![t.as_str()],
        None => RULE_TYPES.to_vec(),
    };

    let mut collected: Vec<Rule> = Vec::new();
    let mut summed: u64 = 0;

    for rule_type in types {
        let mut type_filter = filter.clone();
        type_filter.rule_type = Some(rule_type.to_string());

        // A caller that already named this type made the opening request this
        // very slice, and it came back over the window. Re-issuing it would
        // fetch the same oversized count a second time only to arrive at the
        // same split below.
        let slice_total = if filter.rule_type.is_some() {
            total
        } else {
            let (slice_rules, slice_total) = find_page(t, &type_filter, 1, RESULT_WINDOW).await?;

            if slice_total <= u64::from(RESULT_WINDOW) {
                if (slice_rules.len() as u64) < slice_total {
                    return Err(short_read(slice_total, slice_rules.len()));
                }
                summed += slice_total;
                collected.extend(slice_rules);
                continue;
            }
            slice_total
        };

        // A caller that already fixed `enabled` leaves no room to split; the
        // slice is refused rather than truncated to the first 10,000.
        if filter.enabled.is_some() {
            return Err(oversized(slice_total));
        }

        for enabled in [true, false] {
            let mut enabled_filter = type_filter.clone();
            enabled_filter.enabled = Some(enabled);
            let (enabled_rules, enabled_total) =
                find_page(t, &enabled_filter, 1, RESULT_WINDOW).await?;
            if enabled_total > u64::from(RESULT_WINDOW) {
                return Err(oversized(enabled_total));
            }
            if (enabled_rules.len() as u64) < enabled_total {
                return Err(short_read(enabled_total, enabled_rules.len()));
            }
            summed += enabled_total;
            collected.extend(enabled_rules);
        }
    }

    // The sum is the exhaustiveness guarantee. A rule type added by a newer
    // stack version would read as zero and silently vanish from every pull
    // and read as remote-only in every diff unless the slices sum back to the
    // count the server gave for the whole corpus.
    if summed != total {
        return Err(Error::new(
            ErrorKind::Http,
            format!(
                "the server counted {total} rules across the corpus but the type slices \
                 sum to {summed}. Refusing a partial corpus: a rule type added by a newer \
                 stack version would otherwise read as zero in every pull and diff."
            ),
        ));
    }

    Ok(collected)
}

/// A server that counts more rules than it serves has contradicted itself.
/// Returning the short list would be indistinguishable from rules having been
/// deleted between the count and the read.
fn short_read(counted: u64, returned: usize) -> Error {
    Error::new(
        ErrorKind::Http,
        format!(
            "the server counted {counted} rules and returned {returned}. Refusing a partial \
             corpus: a short read is indistinguishable from rules having been deleted."
        ),
    )
}

/// A slice still over the window after both partitions cannot be served at
/// all; returning its first 10,000 as though they were the slice would make
/// every unread rule look remote-only in a diff.
fn oversized(count: u64) -> Error {
    Error::new(
        ErrorKind::Unsupported,
        format!(
            "{count} rules match, more than the {RESULT_WINDOW} a single search can return \
             even after partitioning by type and enabled. Narrow the selection with a \
             filter or a tag."
        ),
    )
}

/// How many `rule_id`s go into one filtered `_find`.
///
/// A KQL disjunction of every selected id would build a URL that grows with
/// the selection, and a `--tag` can select thousands. Chunking keeps each URL
/// well inside any practical limit; the chunks are cheap because each is a
/// server-side filter rather than a corpus read.
const ID_CHUNK: usize = 50;

/// The rules carrying exactly these `rule_id`s.
///
/// A selected id the stack does not have simply does not come back. That is
/// not an error here — for `state push` it is precisely the locally-added rule
/// the run exists to create.
pub async fn find_by_rule_ids(t: &Transport, rule_ids: &[String]) -> Result<Vec<Rule>> {
    let mut found = Vec::with_capacity(rule_ids.len());
    for chunk in rule_ids.chunks(ID_CHUNK) {
        let filter = RuleFilter {
            query: Some(rule_id_query(chunk)),
            ..Default::default()
        };
        let (rules, _) = find_page(t, &filter, 1, RESULT_WINDOW).await?;
        found.extend(rules);
    }
    Ok(found)
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

/// Export every rule, or exactly the named ones.
///
/// `None` posts no body at all, which is the whole-space export and is
/// byte-identical to what it has always sent. `Some(ids)` posts the scoped
/// `objects` form, so a subset export transfers the subset rather than
/// everything followed by a local filter.
pub async fn export(
    t: &Transport,
    rule_ids: Option<&[String]>,
) -> Result<(Vec<Rule>, Option<ExportSummary>)> {
    let body = rule_ids.map(|ids| {
        json!({
            "objects": ids
                .iter()
                .map(|id| json!({"rule_id": id}))
                .collect::<Vec<_>>()
        })
    });
    let text = t
        .post_text(&format!("{BASE}/_export"), body.as_ref())
        .await?;
    codec::decode_ndjson(&text)
}

/// How many ids to ask about in one `_find`. Large enough that a
/// forty-rule corpus is a single request; small enough that a thousand-rule
/// one cannot build a URL a proxy will reject.
const EXISTENCE_CHUNK: usize = 50;

/// Which of these rule ids already exist on the stack.
///
/// This is what makes an idempotent import possible: the file's ids are
/// checked before anything is uploaded, so an existing rule can be skipped
/// rather than becoming one of N conflict errors, and the dry run can say
/// which is which instead of listing every rule as if it would import.
pub async fn existing_rule_ids(
    t: &Transport,
    rule_ids: &[String],
) -> Result<std::collections::BTreeSet<String>> {
    // An empty list must never become an unscoped find — that would report
    // every rule in the space as "existing".
    let mut found = std::collections::BTreeSet::new();
    if rule_ids.is_empty() {
        return Ok(found);
    }

    for chunk in rule_ids.chunks(EXISTENCE_CHUNK) {
        let path = format!(
            "{BASE}/_find?page=1&per_page={}&filter={}",
            chunk.len(),
            urlencode(&rule_id_query(chunk))
        );
        let (rules, _) = decode_find(&t.get(&path).await?)?;
        for r in rules {
            if let Ok(id) = r.rule_id() {
                found.insert(id.to_string());
            }
        }
    }

    Ok(found)
}

pub async fn import(t: &Transport, ndjson: &str, overwrite: bool) -> Result<Value> {
    t.post_multipart_ndjson(&format!("{BASE}/_import?overwrite={overwrite}"), ndjson)
        .await
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PreviewResult {
    pub preview_id: Option<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Run a rule against historical data without writing alerts.
///
/// `invocationCount` and `timeframeEnd` are required by the API. The response
/// carries a `logs` array with one entry per simulated invocation, each with
/// its own errors and warnings.
pub async fn preview(
    t: &Transport,
    rule: &Rule,
    invocation_count: u32,
    timeframe_end: &str,
) -> Result<PreviewResult> {
    let mut body = rule.as_map().clone();
    // The preview API rejects identity fields that belong to a saved rule.
    for k in [
        "rule_id",
        "id",
        "immutable",
        "rule_source",
        "revision",
        "version",
    ] {
        body.remove(k);
    }
    body.insert("invocationCount".into(), json!(invocation_count));
    body.insert("timeframeEnd".into(), json!(timeframe_end));

    let response = t
        .post(&format!("{BASE}/preview"), Some(&Value::Object(body)))
        .await?;

    let collect = |key: &str| -> Vec<String> {
        response["logs"]
            .as_array()
            .map(|logs| {
                logs.iter()
                    .filter_map(|l| l.get(key)?.as_array())
                    .flatten()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };

    Ok(PreviewResult {
        preview_id: response["previewId"].as_str().map(str::to_owned),
        errors: collect("errors"),
        warnings: collect("warnings"),
    })
}

/// Where a preview's alerts land. Kibana names the alias per space.
///
/// Recorded in `tests/fixtures/*/rules_preview_hits.json`, which also records
/// the field the search filters on — a response alone cannot distinguish an
/// empty result from a wrong field name.
pub const PREVIEW_ALERTS_INDEX_PREFIX: &str = ".preview.alerts-security.alerts-";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PreviewHits {
    pub total: u64,
    /// One entry per returned document: `{"_id": ..., "_source": {...}}`.
    /// The alert document verbatim, because what the engineer wants to see is
    /// the event that matched, not a projection someone guessed at.
    pub sample: Vec<Value>,
}

/// Read back what a preview matched.
///
/// `rules/preview` returns a `previewId` and no hit count — four hits and zero
/// hits are byte-identical responses — so the alerts it wrote are searched
/// directly. `ignore_unavailable=true` turns "no preview has ever run in this
/// space" into an empty result rather than a 404, which is a correct answer to
/// "how many hits", not an error.
pub async fn preview_hits(
    t: &Transport,
    space: &str,
    preview_id: &str,
    sample: usize,
) -> Result<PreviewHits> {
    let space = if space.is_empty() { "default" } else { space };
    let index = urlencode(&format!("{PREVIEW_ALERTS_INDEX_PREFIX}{space}"));
    let body = json!({
        "size": sample,
        // Exact, not the 10,000 default cap: the count is the whole point.
        "track_total_hits": true,
        "query": {"term": {"kibana.alert.rule.uuid": preview_id}},
        "sort": [{"@timestamp": {"order": "desc"}}]
    });

    let response = t
        .post_absolute_es(&format!("/{index}/_search?ignore_unavailable=true"), &body)
        .await?;

    Ok(decode_preview_hits(&response))
}

/// Decode a preview-hits search response. Extracted so the recorded
/// `rules_preview_hits` fixture can be decoded offline by the same path the
/// live client uses.
pub fn decode_preview_hits(response: &Value) -> PreviewHits {
    let total = response["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let sample = response["hits"]["hits"]
        .as_array()
        .map(|hits| {
            hits.iter()
                .map(|h| {
                    json!({
                        "_id": h.get("_id").cloned().unwrap_or(Value::Null),
                        "_source": h.get("_source").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    PreviewHits { total, sample }
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
