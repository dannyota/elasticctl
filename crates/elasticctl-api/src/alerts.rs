//! Detection alerts: the signals search, status, tags, and assignees routes.
//!
//! Alert identity is the document `_id`. Every mutation here takes explicit
//! ids or an explicit query; there is no reconciliation path (triage spec
//! section 2).

use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::{Value, json};

pub const SEARCH_PATH: &str = "/api/detection_engine/signals/search";
pub const STATUS_PATH: &str = "/api/detection_engine/signals/status";
pub const TAGS_PATH: &str = "/api/detection_engine/signals/tags";
pub const ASSIGNEES_PATH: &str = "/api/detection_engine/signals/assignees";

/// The modern status vocabulary. The route also accepts `in-progress`, the
/// pre-8.0 name `acknowledged` replaced; elasticctl never sends it.
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

    /// The verb a preview banner uses: `Open 2 alerts`, `Close 1 alert`.
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

/// Version-conflict handling for query-scoped transitions. `Abort` is the
/// server default: a document whose version moved between resolution and
/// write stops the run rather than being silently skipped.
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
    /// The document `_id` — the identity every mutation route takes.
    pub id: String,
    /// The backing index, from `_index`. The cases attach body needs it.
    pub index: Option<String>,
    pub source: Value,
    pub sort: Option<Vec<Value>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlertPage {
    pub hits: Vec<AlertHit>,
    pub total: Option<u64>,
}

/// Decode a signals-search response. Fail-closed: `hits.hits` must be an
/// array and every hit must carry a string `_id` — an alert without identity
/// cannot be acted on — and an object `_source`.
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

/// Run one bounded signals search with the caller's body verbatim.
pub async fn search(t: &Transport, body: &Value) -> Result<AlertPage> {
    decode_page(&t.post(SEARCH_PATH, Some(body)).await?)
}

/// Page a query fully with `sort` + `search_after` through the same route.
/// `sort` must be a total order (the caller ends it with a tiebreaker field).
pub async fn search_all(
    t: &Transport,
    query: &Value,
    sort: &Value,
    limit: Option<usize>,
) -> Result<Vec<AlertHit>> {
    search_all_with_page_size(t, query, sort, limit, 1000).await
}

/// The paging loop with an explicit page size, exposed for tests.
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
            // A full page whose last hit has no sort values cannot advance;
            // stop rather than loop forever.
            None => return Ok(all),
        }
    }
}

/// The raw update-by-query envelope the status, tags, and assignees routes
/// answer with (measured, triage spec section 10).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SignalsOutcome {
    pub total: u64,
    pub updated: u64,
    pub version_conflicts: u64,
    pub noops: u64,
    pub failures: Vec<Value>,
}

/// Fail-closed decode: all four counters and the `failures` array are
/// required. A response missing one is an `http` error, never "nothing
/// happened" (main spec section 6.3).
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

/// Transition explicit alerts. The route is idempotent: a no-op transition
/// counts as processed.
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

/// Transition every alert a query matches. The server resolves the set and
/// mutates it in one update-by-query — no client-side id round-trip.
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

/// Add and remove workflow tags on explicit alerts in one request.
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

/// Add and remove assignee profile uids on explicit alerts in one request.
/// The route rejects a uid present in both lists; callers pre-check.
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
