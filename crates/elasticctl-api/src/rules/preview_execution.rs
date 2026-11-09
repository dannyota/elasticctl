//! Rule preview execution and matched alert retrieval.

use super::BASE;
use crate::model::Rule;
use elasticctl_core::{Error, ErrorKind, Result, Transport, urlencode};
use serde_json::{Value, json};

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

    decode_preview_hits_checked(&response)
}

/// Decode a preview-hits response, refusing a malformed success body.
pub fn decode_preview_hits_checked(response: &Value) -> Result<PreviewHits> {
    let map = response
        .as_object()
        .ok_or_else(|| preview_error("response", "must be a JSON object"))?;
    let hits = map
        .get("hits")
        .and_then(Value::as_object)
        .ok_or_else(|| preview_error("hits", "must be an object"))?;
    let total = hits
        .get("total")
        .and_then(|total| total.get("value"))
        .and_then(Value::as_u64)
        .ok_or_else(|| preview_error("hits.total.value", "must be an unsigned integer"))?;
    let sample = hits
        .get("hits")
        .and_then(Value::as_array)
        .ok_or_else(|| preview_error("hits.hits", "must be an array"))?
        .iter()
        .map(|h| {
            json!({
                "_id": h.get("_id").cloned().unwrap_or(Value::Null),
                "_source": h.get("_source").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();

    Ok(PreviewHits { total, sample })
}

fn preview_error(field: &str, detail: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorKind::Http,
        format!("decoding preview-hits response field {field}: {detail}"),
    )
}

/// Decode a preview-hits response, tolerating a malformed body as empty.
///
/// Fixtures and offline callers use this path; the live `preview_hits` uses the
/// checked decoder so a malformed success body fails instead of reading as zero.
pub fn decode_preview_hits(response: &Value) -> PreviewHits {
    decode_preview_hits_checked(response).unwrap_or_default()
}
