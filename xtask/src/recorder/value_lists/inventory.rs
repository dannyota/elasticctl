//! Marker inventory reads are private and fail closed on incomplete pages.

use super::PREFIX;
use crate::diagnostics::recording_error;
use elasticctl_core::{Result, Transport, urlencode};
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) fn total(body: &Value) -> Result<u64> {
    body["total"]
        .as_u64()
        .ok_or_else(|| recording_error("inventory total is missing or invalid"))
}

pub(super) fn data(body: &Value) -> Result<&Vec<Value>> {
    body["data"]
        .as_array()
        .ok_or_else(|| recording_error("inventory data is missing or invalid"))
}

pub(super) async fn require_clear(t: &Transport, absent: bool) -> Result<()> {
    let mut markers = BTreeSet::new();
    let mut cursor: Option<String> = None;
    let mut seen = 0;
    for page in 1..=1000 {
        let mut path = format!("/api/lists/_find?per_page=100&page={page}");
        if let Some(cursor) = &cursor {
            path.push_str(&format!("&cursor={}", urlencode(cursor)));
        }
        let body = match t.get(&path).await {
            Ok(body) => body,
            Err(error) if absent && error.http_status == Some(404) && page == 1 => break,
            Err(error) => return Err(error),
        };
        let rows = data(&body)?;
        for row in rows {
            marker_id(row, "id", &mut markers)?;
        }
        seen += rows.len() as u64;
        if seen == total(&body)? {
            break;
        }
        if rows.is_empty() || seen > total(&body)? || page == 1000 {
            return Err(recording_error("value-list marker scan is incomplete"));
        }
        let next = body["cursor"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| recording_error("value-list marker scan has no next cursor"))?;
        if cursor.as_deref() == Some(next) {
            return Err(recording_error("value-list marker scan repeated a cursor"));
        }
        cursor = Some(next.to_string());
    }
    for namespace in ["single", "agnostic"] {
        let mut seen = 0;
        for page in 1..=100 {
            let body = t
                .get(&format!(
                    "/api/exception_lists/_find?namespace_type={namespace}&per_page=100&page={page}"
                ))
                .await?;
            let rows = data(&body)?;
            for row in rows {
                marker_id(row, "id", &mut markers)?;
                marker_id(row, "list_id", &mut markers)?;
            }
            seen += rows.len() as u64;
            if seen == total(&body)? {
                break;
            }
            if rows.is_empty() || seen > total(&body)? || page == 100 {
                return Err(recording_error("exception marker scan is incomplete"));
            }
        }
    }
    marker_items(t, absent, &mut markers).await?;
    if !markers.is_empty() {
        return Err(recording_error(format!(
            "refusing to record: marker objects already exist: {}. Manual remediation: inspect and remove these exact ids before recording",
            markers.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    Ok(())
}

async fn marker_items(t: &Transport, absent: bool, markers: &mut BTreeSet<String>) -> Result<()> {
    if !t.has_es_url() {
        return Err(recording_error(
            "marker item audit requires an explicit Elasticsearch URL",
        ));
    }
    // Read the items stream directly. A late import can leave items after its container is gone.
    let path = format!(
        "/.items-{}/_search?size=100&track_total_hits=true&q={}",
        urlencode(t.space()),
        urlencode(&format!("list_id:{PREFIX}*"))
    );
    let body = match t.get_absolute_es(&path).await {
        Ok(body) => body,
        Err(error) if absent && error.http_status == Some(404) => return Ok(()),
        Err(error) => return Err(error),
    };
    let hits = body["hits"]["hits"]
        .as_array()
        .ok_or_else(|| recording_error("marker item audit has no hits"))?;
    if body["timed_out"] != false
        || body["_shards"]["failed"] != 0
        || body["hits"]["total"]["relation"] != "eq"
        || body["hits"]["total"]["value"].as_u64() != Some(hits.len() as u64)
    {
        return Err(recording_error(
            "marker item audit is incomplete; inspect the items data stream before recording",
        ));
    }
    for hit in hits {
        let id = hit["_id"]
            .as_str()
            .ok_or_else(|| recording_error("marker item audit has an invalid id"))?;
        let list = hit["_source"]["list_id"]
            .as_str()
            .filter(|id| id.starts_with(PREFIX))
            .ok_or_else(|| recording_error("marker item audit has an invalid list id"))?;
        markers.insert(format!("{id} (list_id={list})"));
    }
    Ok(())
}

fn marker_id(row: &Value, key: &str, markers: &mut BTreeSet<String>) -> Result<()> {
    let id = row[key]
        .as_str()
        .ok_or_else(|| recording_error("marker inventory has an invalid id"))?;
    if id.starts_with(PREFIX) {
        markers.insert(id.to_string());
    }
    Ok(())
}
