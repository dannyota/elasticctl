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

pub async fn preview(
    t: &Transport,
    rule: &Rule,
    invocation_count: u32,
    timeframe_end: &str,
) -> Result<PreviewResult> {
    let mut body = rule.as_map().clone();
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

pub const PREVIEW_ALERTS_INDEX_PREFIX: &str = ".preview.alerts-security.alerts-";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PreviewHits {
    pub total: u64,
    pub sample: Vec<Value>,
}

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
        "track_total_hits": true,
        "query": {"term": {"kibana.alert.rule.uuid": preview_id}},
        "sort": [{"@timestamp": {"order": "desc"}}]
    });

    let response = t
        .post_absolute_es(&format!("/{index}/_search?ignore_unavailable=true"), &body)
        .await?;

    decode_preview_hits_checked(&response)
}

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

pub fn decode_preview_hits(response: &Value) -> PreviewHits {
    decode_preview_hits_checked(response).unwrap_or_default()
}
