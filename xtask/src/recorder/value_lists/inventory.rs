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
    if !markers.is_empty() {
        return Err(recording_error(format!(
            "refusing to record: marker objects already exist: {}. Manual remediation: inspect and remove these exact ids before recording",
            markers.into_iter().collect::<Vec<_>>().join(", ")
        )));
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
