use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::{Value, json};

pub const SEARCH_PATH: &str = "/api/detection_engine/signals/search";
pub const STATUS_PATH: &str = "/api/detection_engine/signals/status";
pub const TAGS_PATH: &str = "/api/detection_engine/signals/tags";
pub const ASSIGNEES_PATH: &str = "/api/detection_engine/signals/assignees";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertStatus {
    Open,
    Acknowledged,
    Closed,
}

impl AlertStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AlertStatus::Open => "open",
            AlertStatus::Acknowledged => "acknowledged",
            AlertStatus::Closed => "closed",
        }
    }

    pub fn verb(self) -> &'static str {
        match self {
            AlertStatus::Open => "Open",
            AlertStatus::Acknowledged => "Acknowledge",
            AlertStatus::Closed => "Close",
        }
    }

    pub fn parse(s: &str) -> Result<AlertStatus> {
        match s {
            "open" => Ok(AlertStatus::Open),
            "acknowledged" => Ok(AlertStatus::Acknowledged),
            "closed" => Ok(AlertStatus::Closed),
            other => Err(Error::new(
                ErrorKind::Error,
                format!("unknown alert status '{other}': expected open, acknowledged, or closed"),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Conflicts {
    #[default]
    Abort,
    Proceed,
}

impl Conflicts {
    pub fn as_str(self) -> &'static str {
        match self {
            Conflicts::Abort => "abort",
            Conflicts::Proceed => "proceed",
        }
    }

    pub fn parse(s: &str) -> Result<Conflicts> {
        match s {
            "abort" => Ok(Conflicts::Abort),
            "proceed" => Ok(Conflicts::Proceed),
            other => Err(Error::new(
                ErrorKind::Error,
                format!("unknown conflicts mode '{other}': expected abort or proceed"),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlertHit {
    pub id: String,
    pub index: Option<String>,
    pub source: Value,
    pub sort: Option<Vec<Value>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlertPage {
    pub hits: Vec<AlertHit>,
    pub total: Option<u64>,
}

pub fn decode_page(value: &Value) -> Result<AlertPage> {
    let hits = value
        .pointer("/hits/hits")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                "decoding alerts response field `hits.hits`",
            )
        })?;
    let mut out = Vec::with_capacity(hits.len());
    for hit in hits {
        let id = hit
            .get("_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new(ErrorKind::Http, "decoding alert hit field `_id`"))?
            .to_string();
        let index = hit.get("_index").and_then(Value::as_str).map(str::to_owned);
        let source = hit
            .get("_source")
            .filter(|s| s.is_object())
            .cloned()
            .ok_or_else(|| Error::new(ErrorKind::Http, "decoding alert hit field `_source`"))?;
        let sort = hit.get("sort").and_then(Value::as_array).cloned();
        out.push(AlertHit {
            id,
            index,
            source,
            sort,
        });
    }
    let total = value.pointer("/hits/total/value").and_then(Value::as_u64);
    Ok(AlertPage { hits: out, total })
}

pub async fn search(t: &Transport, body: &Value) -> Result<AlertPage> {
    decode_page(&t.post(SEARCH_PATH, Some(body)).await?)
}

pub async fn search_all(
    t: &Transport,
    query: &Value,
    sort: &Value,
    limit: Option<usize>,
) -> Result<Vec<AlertHit>> {
    search_all_with_page_size(t, query, sort, limit, 1000).await
}

pub async fn search_all_with_page_size(
    t: &Transport,
    query: &Value,
    sort: &Value,
    limit: Option<usize>,
    page_size: usize,
) -> Result<Vec<AlertHit>> {
    let mut all = Vec::new();
    let mut search_after: Option<Vec<Value>> = None;
    loop {
        let mut body = json!({
            "query": query,
            "sort": sort,
            "size": page_size,
        });
        if let Some(sa) = &search_after {
            body["search_after"] = json!(sa);
        }
        let page = search(t, &body).await?;
        let short_page = page.hits.len() < page_size;
        let last_sort = page.hits.last().and_then(|h| h.sort.clone());
        all.extend(page.hits);
        if let Some(limit) = limit
            && all.len() >= limit
        {
            all.truncate(limit);
            return Ok(all);
        }
        if short_page {
            return Ok(all);
        }
        match last_sort {
            Some(sa) => search_after = Some(sa),
            None => return Ok(all),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SignalsOutcome {
    pub total: u64,
    pub updated: u64,
    pub version_conflicts: u64,
    pub noops: u64,
    pub failures: Vec<Value>,
}

pub fn decode_outcome(value: &Value) -> Result<SignalsOutcome> {
    let counter = |name: &str| {
        value.get(name).and_then(Value::as_u64).ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                format!("decoding signals outcome field `{name}`"),
            )
        })
    };
    Ok(SignalsOutcome {
        total: counter("total")?,
        updated: counter("updated")?,
        version_conflicts: counter("version_conflicts")?,
        noops: counter("noops")?,
        failures: value
            .get("failures")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| {
                Error::new(ErrorKind::Http, "decoding signals outcome field `failures`")
            })?,
    })
}

pub async fn status_by_ids(
    t: &Transport,
    ids: &[String],
    status: AlertStatus,
    reason: Option<&str>,
) -> Result<SignalsOutcome> {
    let mut body = json!({ "signal_ids": ids, "status": status.as_str() });
    if let Some(r) = reason {
        body["reason"] = json!(r);
    }
    decode_outcome(&t.post(STATUS_PATH, Some(&body)).await?)
}

pub async fn status_by_query(
    t: &Transport,
    query: &Value,
    status: AlertStatus,
    conflicts: Conflicts,
    reason: Option<&str>,
) -> Result<SignalsOutcome> {
    let mut body = json!({
        "query": query,
        "status": status.as_str(),
        "conflicts": conflicts.as_str(),
    });
    if let Some(r) = reason {
        body["reason"] = json!(r);
    }
    decode_outcome(&t.post(STATUS_PATH, Some(&body)).await?)
}

pub async fn set_tags(
    t: &Transport,
    ids: &[String],
    add: &[String],
    remove: &[String],
) -> Result<SignalsOutcome> {
    let body = json!({
        "ids": ids,
        "tags": { "tags_to_add": add, "tags_to_remove": remove },
    });
    decode_outcome(&t.post(TAGS_PATH, Some(&body)).await?)
}

pub async fn set_assignees(
    t: &Transport,
    ids: &[String],
    add: &[String],
    remove: &[String],
) -> Result<SignalsOutcome> {
    let body = json!({
        "ids": ids,
        "assignees": { "add": add, "remove": remove },
    });
    decode_outcome(&t.post(ASSIGNEES_PATH, Some(&body)).await?)
}

#[derive(Debug)]
pub struct ActivityPage {
    pub total: u64,
    pub buckets: Vec<(String, u64)>,
    pub other: u64,
    pub hits: Vec<AlertHit>,
}
pub async fn search_activity(t: &Transport, body: &Value) -> Result<ActivityPage> {
    let v = t.post(SEARCH_PATH, Some(body)).await?;
    let invalid = || Error::new(ErrorKind::Http, "invalid alert activity response");
    if v.pointer("/hits/total/relation").and_then(Value::as_str) != Some("eq") {
        return Err(invalid());
    }
    let total = v
        .pointer("/hits/total/value")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    let status = v.pointer("/aggregations/status").ok_or_else(invalid)?;
    let buckets = status
        .get("buckets")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?
        .iter()
        .map(|b| {
            Ok((
                b.get("key")
                    .and_then(Value::as_str)
                    .ok_or_else(invalid)?
                    .to_owned(),
                b.get("doc_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(invalid)?,
            ))
        })
        .collect::<Result<_>>()?;
    let other = status
        .get("sum_other_doc_count")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    Ok(ActivityPage {
        total,
        buckets,
        other,
        hits: decode_page(&v)?.hits,
    })
}
