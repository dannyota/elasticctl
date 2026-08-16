//! Query DSL responses and PIT + `search_after` pagination.

use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq)]
pub struct DslHit {
    pub source: Value,
    pub sort: Option<Vec<Value>>,
    pub id: Option<String>,
    pub index: Option<String>,
    pub score: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DslPage {
    pub hits: Vec<DslHit>,
    pub total: Option<u64>,
}

pub fn decode(value: &Value) -> Result<DslPage> {
    let hits = value
        .pointer("/hits/hits")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                "decoding search response field `hits.hits`",
            )
        })?;
    let out = hits
        .iter()
        .map(|h| {
            Ok(DslHit {
                source: h.get("_source").cloned().unwrap_or(Value::Null),
                sort: h.get("sort").and_then(Value::as_array).cloned(),
                id: h.get("_id").and_then(Value::as_str).map(str::to_owned),
                index: h.get("_index").and_then(Value::as_str).map(str::to_owned),
                score: h.get("_score").and_then(Value::as_f64),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let total = value.pointer("/hits/total/value").and_then(Value::as_u64);
    Ok(DslPage { hits: out, total })
}

/// Run one bounded `POST /<index>/_search` with the operator's body verbatim.
/// This is the peek path — one request, no PIT.
pub async fn run_sync(t: &Transport, index: &str, body: &Value) -> Result<DslPage> {
    let response = t
        .post_absolute_es(&format!("/{index}/_search"), body)
        .await?;
    decode(&response)
}

/// Normalize `sort` to a total order by appending `_shard_doc` (ascending)
/// when absent. A non-total sort makes `search_after` skip or repeat documents
/// across pages, so every export pages over a total order.
fn total_sort(sort: &Value) -> Value {
    let mut entries = match sort {
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    };
    let has_tiebreaker = entries.iter().any(|entry| {
        entry
            .as_object()
            .is_some_and(|obj| obj.contains_key("_shard_doc"))
    });
    if !has_tiebreaker {
        entries.push(json!({"_shard_doc": "asc"}));
    }
    Value::Array(entries)
}

/// Open a point-in-time on `index` and page it fully with `search_after`.
/// `query` is the operator's filter; `sort` is normalized to a total order by
/// appending `_shard_doc` when absent. The PIT is closed on every exit path,
/// success or error.
pub async fn run_stream(
    t: &Transport,
    index: &str,
    query: &Value,
    sort: &Value,
    limit: Option<usize>,
) -> Result<Vec<DslHit>> {
    let open: Value = t
        .post_absolute_es(&format!("/{index}/_pit?keep_alive=1m"), &json!({}))
        .await?;
    let pit_id = open
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(ErrorKind::Http, "decoding _pit open response field `id`"))?
        .to_string();

    let sort = total_sort(sort);
    let result = page_loop(t, &pit_id, query, &sort, limit).await;

    // Close the PIT on every path. The `_pit` delete takes the id in the
    // request body, so it uses the body-carrying DELETE. The `let _` swallow is
    // deliberate: the PIT self-expires after `keep_alive`, and any `page_loop`
    // error is the error to surface, not a best-effort close failure.
    let _ = t
        .delete_absolute_es_json("/_pit", &json!({ "id": pit_id }))
        .await;
    result
}

async fn page_loop(
    t: &Transport,
    pit_id: &str,
    query: &Value,
    sort: &Value,
    limit: Option<usize>,
) -> Result<Vec<DslHit>> {
    let mut all = Vec::new();
    let mut search_after: Option<Vec<Value>> = None;
    let size = limit.map_or(1000, |n| n.min(1000));
    loop {
        let mut body = json!({
            "size": size,
            "sort": sort,
            "pit": { "id": pit_id, "keep_alive": "1m" },
            "query": query
        });
        if let Some(sa) = &search_after {
            body["search_after"] = json!(sa);
        }
        let page = decode(&t.post_absolute_es("/_search", &body).await?)?;
        if page.hits.is_empty() {
            return Ok(all);
        }
        let last_sort = page.hits.last().and_then(|h| h.sort.clone());
        all.extend(page.hits);
        if let Some(limit) = limit
            && all.len() >= limit
        {
            all.truncate(limit);
            return Ok(all);
        }
        match last_sort {
            Some(sa) => search_after = Some(sa),
            None => return Ok(all),
        }
    }
}
