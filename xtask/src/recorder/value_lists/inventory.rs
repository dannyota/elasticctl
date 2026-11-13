use super::{PREFIX, Session};
use crate::diagnostics::recording_error;
use elasticctl_core::{Result, urlencode};
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

pub(super) async fn require_clear(session: &mut Session<'_>) -> Result<()> {
    scan_clear(session, &mut BTreeSet::new()).await
}

pub(super) async fn scan_clear(
    session: &mut Session<'_>,
    markers: &mut BTreeSet<String>,
) -> Result<()> {
    let absent = session.before_absent;
    let mut cursor: Option<String> = None;
    let mut seen = 0;
    for page in 1..=1000 {
        let mut path = format!("/api/lists/_find?per_page=100&page={page}");
        if let Some(cursor) = &cursor {
            path.push_str(&format!("&cursor={}", urlencode(cursor)));
        }
        let body = match session.t.get(&path).await {
            Ok(body) => body,
            Err(error) if absent && error.http_status == Some(404) && page == 1 => break,
            Err(error) => return Err(error),
        };
        let rows = data(&body)?;
        for row in rows {
            marker_id(row, "id", markers)?;
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
        let mut expected = None;
        for page in 1..=100 {
            let body = session
                .t
                .get(&format!(
                    "/api/exception_lists/_find?namespace_type={namespace}&per_page=100&page={page}"
                ))
                .await?;
            let count = total(&body)?;
            if expected
                .replace(count)
                .is_some_and(|previous| previous != count)
            {
                return Err(recording_error("exception marker scan totals disagree"));
            }
            let rows = data(&body)?;
            for row in rows {
                marker_id(row, "id", markers)?;
                marker_id(row, "list_id", markers)?;
                let list = row["list_id"].as_str().unwrap();
                exception_references(session, list, namespace, markers).await?;
            }
            seen += rows.len() as u64;
            if seen == count {
                break;
            }
            if rows.is_empty() || seen > total(&body)? || page == 100 {
                return Err(recording_error("exception marker scan is incomplete"));
            }
        }
    }
    let mut seen_rules = 0;
    let mut expected_rules = None;
    for page in 1..=1000 {
        let filter = urlencode("alert.attributes.params.ruleId: elasticctl-live-vl-*");
        let body = session
            .t
            .get(&format!(
                "/api/detection_engine/rules/_find?page={page}&per_page=100&filter={filter}"
            ))
            .await?;
        let count = total(&body)?;
        if expected_rules
            .replace(count)
            .is_some_and(|previous| previous != count)
        {
            return Err(recording_error("rule marker scan totals disagree"));
        }
        let rows = data(&body)?;
        for row in rows {
            marker_id(row, "rule_id", markers)?;
        }
        seen_rules += rows.len() as u64;
        if seen_rules == count {
            break;
        }
        if rows.is_empty() || seen_rules > count || page == 1000 {
            return Err(recording_error("rule marker scan is incomplete"));
        }
    }
    marker_items(session, absent, markers).await?;
    if !markers.is_empty() {
        return Err(recording_error(format!(
            "refusing to record: marker objects already exist: {}. Manual remediation: inspect and remove these exact ids before recording",
            markers.iter().cloned().collect::<Vec<_>>().join(", ")
        )));
    }
    Ok(())
}

async fn exception_references(
    session: &mut Session<'_>,
    list: &str,
    namespace: &str,
    markers: &mut BTreeSet<String>,
) -> Result<()> {
    let mut seen = 0;
    let mut expected = None;
    for page in 1..=100 {
        let body = session.t.get(&format!(
            "/api/exception_lists/items/_find?list_id={}&namespace_type={namespace}&per_page=100&page={page}",
            urlencode(list)
        )).await?;
        let count = total(&body)?;
        if expected
            .replace(count)
            .is_some_and(|previous| previous != count)
        {
            return Err(recording_error(format!(
                "exception item scan totals disagree for {list}"
            )));
        }
        let rows = data(&body)?;
        for row in rows {
            marker_id(row, "item_id", markers)?;
            let item = row["item_id"].as_str().ok_or_else(|| {
                recording_error(format!(
                    "exception item scan has an invalid item_id for {list}"
                ))
            })?;
            scan_entries(&row["entries"], list, item)?;
        }
        seen += rows.len() as u64;
        if seen == count {
            return Ok(());
        }
        if rows.is_empty() || seen > count || page == 100 {
            return Err(recording_error(format!(
                "exception item scan is incomplete for {list}"
            )));
        }
    }
    unreachable!()
}

fn scan_entries(entries: &Value, container: &str, item: &str) -> Result<()> {
    let invalid = || {
        recording_error(format!(
            "cannot decode exception entries in container {container}, item {item}"
        ))
    };
    for entry in entries.as_array().ok_or_else(invalid)? {
        match entry["type"].as_str() {
            Some("list") => {
                let id = entry["list"]["id"]
                    .as_str()
                    .filter(|id| !id.is_empty())
                    .ok_or_else(invalid)?;
                if id.starts_with(PREFIX) {
                    return Err(recording_error(format!(
                        "refusing to record: container {container}, item {item} references list {id}. Manual remediation: remove this reference before recording"
                    )));
                }
            }
            Some("nested") => scan_entries(&entry["entries"], container, item)?,
            Some("match" | "match_any" | "exists" | "wildcard") => {}
            _ => return Err(invalid()),
        }
    }
    Ok(())
}

pub(super) async fn marker_items(
    session: &mut Session<'_>,
    absent: bool,
    markers: &mut BTreeSet<String>,
) -> Result<()> {
    if !session.t.has_es_url() {
        return Err(recording_error(
            "marker item audit requires an explicit Elasticsearch URL",
        ));
    }
    let path = format!(
        "/.items-{}/_search?size=100&track_total_hits=true&q={}",
        urlencode(session.t.space()),
        urlencode(&format!("list_id:{PREFIX}*"))
    );
    let body = match session.t.get_absolute_es(&path).await {
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
