//! ES|QL responses and the sync/async `/_query` runners.

use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::{Map, Value};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct EsqlColumn {
    pub name: String,
    pub r#type: String,
}

/// Row-major `values`: one array of cells per row. `columnar` responses are
/// transposed into this shape by `decode_columnar` so callers always see rows.
#[derive(Debug, Clone, PartialEq)]
pub struct EsqlResponse {
    pub columns: Vec<EsqlColumn>,
    pub values: Vec<Vec<Value>>,
    pub is_partial: bool,
}

fn parse_columns(obj: &Map<String, Value>) -> Result<Vec<EsqlColumn>> {
    let columns = obj
        .get("columns")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new(ErrorKind::Http, "decoding esql response field `columns`"))?;
    let mut out = Vec::with_capacity(columns.len());
    for (i, col) in columns.iter().enumerate() {
        let name = col.get("name").and_then(Value::as_str).ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                format!("decoding esql response column {i} field `name`"),
            )
        })?;
        let ty = col.get("type").and_then(Value::as_str).ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                format!("decoding esql response column {i} field `type`"),
            )
        })?;
        out.push(EsqlColumn {
            name: name.to_string(),
            r#type: ty.to_string(),
        });
    }
    Ok(out)
}

fn is_partial(obj: &Map<String, Value>) -> bool {
    obj.get("is_partial")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Strict decode of a row-major `POST /_query` response. Unknown fields are
/// accepted; a missing or mistyped `columns`/`values` is an error, never an
/// empty result.
pub fn decode(value: &Value) -> Result<EsqlResponse> {
    let obj = value.as_object().ok_or_else(|| {
        Error::new(
            ErrorKind::Http,
            "decoding esql response: expected an object",
        )
    })?;
    let columns = parse_columns(obj)?;

    let values = obj
        .get("values")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new(ErrorKind::Http, "decoding esql response field `values`"))?
        .iter()
        .map(|row| {
            let cells = row.as_array().ok_or_else(|| {
                Error::new(
                    ErrorKind::Http,
                    "decoding esql response: `values` rows must be arrays",
                )
            })?;
            if cells.len() != columns.len() {
                return Err(Error::new(
                    ErrorKind::Http,
                    "decoding esql response: `values` row width does not match `columns`",
                ));
            }
            Ok(cells.clone())
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(EsqlResponse {
        columns,
        values,
        is_partial: is_partial(obj),
    })
}

/// Strict decode of a column-major (`columnar: true`) response. `values` holds
/// one array per column, each the length of the row count; the result is
/// transposed into the row-major `EsqlResponse` shape.
pub fn decode_columnar(value: &Value) -> Result<EsqlResponse> {
    let obj = value.as_object().ok_or_else(|| {
        Error::new(
            ErrorKind::Http,
            "decoding esql response: expected an object",
        )
    })?;
    let columns = parse_columns(obj)?;

    let cols = obj
        .get("values")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new(ErrorKind::Http, "decoding esql response field `values`"))?;
    if cols.len() != columns.len() {
        return Err(Error::new(
            ErrorKind::Http,
            "decoding esql response: `values` column count does not match `columns`",
        ));
    }
    let arrays = cols
        .iter()
        .enumerate()
        .map(|(i, col)| {
            col.as_array().ok_or_else(|| {
                Error::new(
                    ErrorKind::Http,
                    format!("decoding esql response: `values` column {i} must be an array"),
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let row_count = arrays.first().map(|col| col.len()).unwrap_or(0);
    if arrays.iter().any(|col| col.len() != row_count) {
        return Err(Error::new(
            ErrorKind::Http,
            "decoding esql response: `values` columns have unequal lengths",
        ));
    }

    let mut values = Vec::with_capacity(row_count);
    for r in 0..row_count {
        let mut row = Vec::with_capacity(columns.len());
        for col in &arrays {
            row.push(col[r].clone());
        }
        values.push(row);
    }

    Ok(EsqlResponse {
        columns,
        values,
        is_partial: is_partial(obj),
    })
}

/// Run a synchronous ES|QL query. `query` carries its own `FROM` and `LIMIT`.
pub async fn run_sync(t: &Transport, query: &str) -> Result<EsqlResponse> {
    let body = serde_json::json!({ "query": query });
    let response = t.post_absolute_es("/_query", &body).await?;
    decode(&response)
}

/// Run a query through the async API and poll until complete. ES|QL has no
/// page-by-page cursor; the full result returns in one response. `columnar:
/// true` keeps the payload and memory footprint low.
pub async fn run_async(t: &Transport, query: &str) -> Result<EsqlResponse> {
    let start = t
        .post_absolute_es(
            "/_query/async",
            &serde_json::json!({ "query": query, "wait_for_completion_timeout": "1ms", "columnar": true }),
        )
        .await?;
    // A query finishing within wait_for_completion_timeout returns the inline
    // result with is_running: false and no `id`; decode it directly.
    let id = match start.get("id").and_then(Value::as_str) {
        Some(id) => id.to_string(),
        None => return decode_columnar(&start),
    };
    // The start response can also carry both an `id` and an inline result.
    // Clean the id up before decoding either way.
    if start.get("is_running").and_then(Value::as_bool) == Some(false) {
        let _ = t.delete_absolute_es(&format!("/_query/async/{id}")).await;
        return decode_columnar(&start);
    }

    // Poll at most 30 times; an async query that never finishes is a timeout,
    // not an infinite loop. Clean up on the way out either way.
    for _ in 0..30 {
        let resp = match t.get_absolute_es(&format!("/_query/async/{id}")).await {
            Ok(resp) => resp,
            Err(err) => {
                let _ = t.delete_absolute_es(&format!("/_query/async/{id}")).await;
                return Err(err);
            }
        };
        if resp.get("is_running").and_then(Value::as_bool) == Some(false) {
            let _ = t.delete_absolute_es(&format!("/_query/async/{id}")).await;
            return decode_columnar(&resp);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let _ = t.delete_absolute_es(&format!("/_query/async/{id}")).await;
    Err(Error::new(
        ErrorKind::Timeout,
        format!("async query {id} still running after 30 polls"),
    ))
}

/// Run an async ES|QL query with `format: csv` and return the raw CSV body
/// (header row included). `format: csv` is an alternative to `columnar`; the
/// response is text, not `{columns, values}`.
pub async fn run_async_csv(t: &Transport, query: &str) -> Result<String> {
    let start = t
        .post_absolute_es_text(
            "/_query/async",
            &serde_json::json!({ "query": query, "wait_for_completion_timeout": "1ms", "format": "csv" }),
        )
        .await?;
    // The async start is JSON `{id, is_running}`; a query finishing within the
    // timeout returns the CSV body directly, with no `id`.
    let id = serde_json::from_str::<Value>(&start)
        .ok()
        .and_then(|v| v.get("id").and_then(Value::as_str).map(str::to_string));
    let Some(id) = id else {
        return Ok(start);
    };

    for _ in 0..30 {
        let resp = match t.get_absolute_es_text(&format!("/_query/async/{id}")).await {
            Ok(resp) => resp,
            Err(err) => {
                let _ = t.delete_absolute_es(&format!("/_query/async/{id}")).await;
                return Err(err);
            }
        };
        // A running query polls back JSON `{is_running: true}`; the terminal
        // response is the CSV text.
        let still_running = serde_json::from_str::<Value>(&resp)
            .ok()
            .and_then(|v| v.get("is_running").and_then(Value::as_bool))
            == Some(true);
        if !still_running {
            let _ = t.delete_absolute_es(&format!("/_query/async/{id}")).await;
            return Ok(resp);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let _ = t.delete_absolute_es(&format!("/_query/async/{id}")).await;
    Err(Error::new(
        ErrorKind::Timeout,
        format!("async query {id} still running after 30 polls"),
    ))
}
