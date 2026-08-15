//! Typed wrappers for the detection-engine API.
//!
//! Functions use stable `rule_id` values, not volatile server-side `id` values.

use crate::codec::{self, Bundle};
use crate::model::Rule;
use crate::normalize;
use elasticctl_core::{Error, ErrorKind, Result, Transport, urlencode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const BASE: &str = "/api/detection_engine/rules";

/// Elasticsearch's `_find` result window. `from + size` cannot exceed this;
/// 10,001 returns a 400 error.
///
/// It bounds `per_page` and the largest `_find` result. Smaller pages cannot
/// evade the `from + size` limit. A window-sized request read 2,066 rules in
/// 2.4 seconds; 21 pages of 100 took 8.4–11 seconds.
const RESULT_WINDOW: u32 = 10_000;

/// Which rules an operation acts on, grouped by source.
///
/// The server-side split filters on `alert.attributes.params.immutable`. On
/// Serverless 9.6.0, it agreed exactly with `params.ruleSource.type` (2,066
/// prebuilt / 0 custom). Its presence on older versions is unmeasured.
/// `customized` narrows the prebuilt set to rules edited on the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSource {
    Custom,
    Customized,
    Prebuilt,
    #[default]
    All,
}

impl RuleSource {
    /// The measured server-side filter clause. `None` means no clause: the
    /// whole corpus. Spec 5.5.
    pub fn clause(&self) -> Option<&'static str> {
        match self {
            RuleSource::Custom => Some("alert.attributes.params.immutable: false"),
            RuleSource::Prebuilt => Some("alert.attributes.params.immutable: true"),
            RuleSource::Customized => Some("alert.attributes.params.ruleSource.isCustomized: true"),
            RuleSource::All => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuleFilter {
    pub source: RuleSource,
    pub enabled: Option<bool>,
    pub rule_type: Option<String>,
    pub severity: Option<String>,
    pub tag: Option<String>,
    /// Exact display name, filtered server-side. This takes one request;
    /// walking 2,066 rules took 8.8 seconds.
    pub name: Option<String>,
    /// A raw KQL fragment, combined with the structured filters above.
    pub query: Option<String>,
}

impl RuleFilter {
    /// Kibana filters saved objects with KQL over `alert.attributes.*`.
    pub fn to_kql(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        if let Some(clause) = self.source.clause() {
            parts.push(clause.to_string());
        }
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
/// A quote could otherwise close the literal and make the remaining value KQL,
/// turning a scoped bulk action into an unscoped action. Escape backslashes
/// first to avoid double-escaping inserted quote escapes. Shared with the
/// exceptions vertical: the two filter builders must not diverge, because a
/// divergence silently matches the wrong objects.
pub(crate) fn kql_escape(value: &str) -> String {
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

/// Decode a `_find` response into rules and a total. Fixtures use this same
/// path offline.
pub fn decode_find(body: &Value) -> Result<(Vec<Rule>, u64)> {
    let map = body
        .as_object()
        .ok_or_else(|| find_error("response", "must be a JSON object"))?;
    let data = map
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| find_error("data", "must be an array"))?;
    let total = required_u64(map, "total")?;
    let page = required_u64(map, "page")?;
    if page == 0 {
        return Err(find_error("page", "must be greater than zero"));
    }
    let per_page = required_u64(map, "perPage")?;
    if per_page == 0 {
        return Err(find_error("perPage", "must be greater than zero"));
    }

    let data_len = data.len() as u64;
    if data_len > total {
        return Err(find_error(
            "data.len() > total",
            format!("{data_len} returned records exceed total {total}"),
        ));
    }
    if data_len > per_page {
        return Err(find_error(
            "data.len() > perPage",
            format!("{data_len} returned records exceed perPage {per_page}"),
        ));
    }

    let rules = data
        .iter()
        .cloned()
        .map(Rule::from_value)
        .collect::<Result<Vec<_>>>()?;
    Ok((rules, total))
}

fn find_error(field: &str, detail: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorKind::Http,
        format!("decoding rule _find response field {field}: {detail}"),
    )
}

fn required_u64(map: &serde_json::Map<String, Value>, field: &str) -> Result<u64> {
    map.get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| find_error(field, "must be an unsigned integer"))
}

/// The three totals that prove `immutable` divides the complete rule corpus.
pub(crate) struct SourceTotals {
    pub custom: u64,
    pub prebuilt: u64,
    pub all: u64,
}

impl SourceTotals {
    fn is_exhaustive(&self) -> bool {
        self.custom.checked_add(self.prebuilt) == Some(self.all)
    }
}

/// Verify that the custom and prebuilt `immutable` filters are disjoint and
/// exhaustive. `customized` is intentionally absent: it overlaps prebuilt.
///
/// This runs only after an otherwise unselected custom or prebuilt read found
/// no rules. A valid empty slice must still account for the entire corpus with
/// its opposite source slice.
pub(crate) async fn verify_source_partition(t: &Transport) -> Result<SourceTotals> {
    let (_, custom) = find_page(
        t,
        &RuleFilter {
            source: RuleSource::Custom,
            ..Default::default()
        },
        1,
        1,
    )
    .await?;
    let (_, prebuilt) = find_page(
        t,
        &RuleFilter {
            source: RuleSource::Prebuilt,
            ..Default::default()
        },
        1,
        1,
    )
    .await?;
    let (_, all) = find_page(t, &RuleFilter::default(), 1, 1).await?;

    let totals = SourceTotals {
        custom,
        prebuilt,
        all,
    };
    if !totals.is_exhaustive() {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!(
                "the immutable source partition is not exhaustive: custom={}, \
                 prebuilt={}, all={}. The field may be absent on this stack; \
                 re-run with --source all to read the corpus.",
                totals.custom, totals.prebuilt, totals.all
            ),
        ));
    }

    Ok(totals)
}

/// Detection-rule types used to partition a corpus. Each rule has one
/// `params.type`, so type slices are disjoint and exhaustive. Tags are not:
/// a rule can have many tags or none. Measured against 2,066 rules, these seven
/// type slices sum exactly to the corpus.
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
/// Read corpora within the result window in one request. For larger corpora,
/// partition by rule type, then by `enabled` when needed. Verify the partition
/// by summing slice totals to the corpus total.
///
/// Never return a partial corpus. `state diff` would report unread rules as
/// locally added, and `state pull` would silently omit them.
pub async fn find_all(t: &Transport, filter: &RuleFilter) -> Result<Vec<Rule>> {
    let (rules, total) = find_page(t, filter, 1, RESULT_WINDOW).await?;

    if total <= u64::from(RESULT_WINDOW) {
        if (rules.len() as u64) < total {
            return Err(short_read(total, rules.len()));
        }
        return Ok(rules);
    }

    // A caller that filtered by type has one requested slice. Only `enabled`
    // can subdivide it further.
    let types: Vec<&str> = match &filter.rule_type {
        Some(t) => vec![t.as_str()],
        None => RULE_TYPES.to_vec(),
    };

    let mut collected: Vec<Rule> = Vec::new();
    let mut summed: u64 = 0;

    for rule_type in types {
        let mut type_filter = filter.clone();
        type_filter.rule_type = Some(rule_type.to_string());

        // The opening request already fetched this selected type. Repeating it
        // would return the same oversized result before the `enabled` split.
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

        // A caller that filtered by `enabled` leaves no further partition.
        // Refuse the slice rather than truncating it to 10,000 rules.
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

    // The sum verifies exhaustiveness. A newer rule type would otherwise read
    // as zero, disappear from pulls, and appear remote-only in diffs.
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

/// A server that counts more rules than it serves contradicts itself. A short
/// list is indistinguishable from rules deleted between count and read.
fn short_read(counted: u64, returned: usize) -> Error {
    Error::new(
        ErrorKind::Http,
        format!(
            "the server counted {counted} rules and returned {returned}. Refusing a partial \
             corpus: a short read is indistinguishable from rules having been deleted."
        ),
    )
}

/// A slice that exceeds the window after both partitions cannot be served.
/// Returning its first 10,000 rules would make unread rules look remote-only.
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
/// A KQL disjunction grows with the selection, and `--tag` can select
/// thousands of rules. Chunking keeps each URL below practical limits.
const ID_CHUNK: usize = 50;

/// The rules carrying exactly these `rule_id`s.
///
/// IDs absent from the stack do not return. That is expected for locally added
/// rules that `state push` creates.
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
    // PATCH accepts `rule_id` directly, avoiding the volatile server `id`.
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
    // An empty selection must not become an unscoped query for every rule.
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
/// `None` posts no body for a whole-space export. `Some(ids)` posts `objects`
/// so a subset export transfers only the selected rules.
///
/// The response is a bundle: rules, exception-list containers, exception items,
/// and a trailer. `_export` appends the exception objects a rule references, so
/// decoding them to rules only would drop that content.
pub async fn export(t: &Transport, rule_ids: Option<&[String]>) -> Result<Bundle> {
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
    codec::decode_bundle(&text)
}

/// IDs to check in one `_find`. This keeps large requests below proxy URL
/// limits while a 40-rule corpus still uses one request.
const EXISTENCE_CHUNK: usize = 50;

/// Which of these rule ids already exist on the stack.
///
/// Check file IDs before upload so existing rules can be skipped. This makes
/// imports idempotent and lets dry runs distinguish skipped rules.
pub async fn existing_rule_ids(
    t: &Transport,
    rule_ids: &[String],
) -> Result<std::collections::BTreeSet<String>> {
    // An empty list must not become an unscoped find for every rule.
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
/// The API requires `invocationCount` and `timeframeEnd`. The `logs` array has
/// errors and warnings for each simulated invocation.
pub async fn preview(
    t: &Transport,
    rule: &Rule,
    invocation_count: u32,
    timeframe_end: &str,
) -> Result<PreviewResult> {
    let mut body = rule.as_map().clone();
    // The preview API rejects fields that identify a saved rule.
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
/// The `rules_preview_hits` fixtures record this alias and its filter field.
/// A response alone cannot distinguish an empty result from a wrong field.
pub const PREVIEW_ALERTS_INDEX_PREFIX: &str = ".preview.alerts-security.alerts-";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PreviewHits {
    pub total: u64,
    /// One entry for each returned document: `{"_id": ..., "_source": {...}}`.
    /// Contains the matching alert document, not a projected subset.
    pub sample: Vec<Value>,
}

/// Read back what a preview matched.
///
/// `rules/preview` returns a `previewId` but no hit count, so search the alerts
/// it wrote. `ignore_unavailable=true` reports no preview index as zero hits,
/// not a 404 error.
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
        // Count all matches, not only the default 10,000.
        "track_total_hits": true,
        "query": {"term": {"kibana.alert.rule.uuid": preview_id}},
        "sort": [{"@timestamp": {"order": "desc"}}]
    });

    let response = t
        .post_absolute_es(&format!("/{index}/_search?ignore_unavailable=true"), &body)
        .await?;

    Ok(decode_preview_hits(&response))
}

/// Decode a preview-hits response. Fixtures use this same path offline.
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

    /// Spec 5.5, measured 2026-08-14.
    #[test]
    fn each_source_maps_to_its_measured_filter() {
        assert_eq!(
            RuleSource::Custom.clause(),
            Some("alert.attributes.params.immutable: false")
        );
        assert_eq!(
            RuleSource::Customized.clause(),
            Some("alert.attributes.params.ruleSource.isCustomized: true")
        );
        assert_eq!(RuleSource::All.clause(), None, "all adds no clause");
    }

    #[test]
    fn a_source_clause_combines_with_other_filters() {
        let f = RuleFilter {
            source: RuleSource::Custom,
            tag: Some("prod".into()),
            ..Default::default()
        };
        let kql = f.to_kql().unwrap();
        assert!(kql.contains("immutable: false"), "{kql}");
        assert!(kql.contains("prod"), "{kql}");
        assert!(
            kql.contains(" AND "),
            "clauses combine, they do not replace: {kql}"
        );
    }

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

    /// A backslash before a quote tests escape order. Escaping quotes first
    /// would double the backslash inserted for the quote and corrupt the value.
    #[test]
    fn kql_escape_orders_backslash_before_quote() {
        let mut input = String::new();
        input.push('\\');
        input.push('"');

        let escaped = kql_escape(&input);

        // Double the backslash, then escape the quote: three backslashes and a
        // quote.
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
