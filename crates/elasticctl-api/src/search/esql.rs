use crate::compose::require_path_segment;
use elasticctl_core::{Error, ErrorKind, Result, Transport, urlencode};
use serde_json::{Map, Value};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct EsqlColumn {
    pub name: String,
    pub r#type: String,
}

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
    if cols.is_empty() {
        return Ok(EsqlResponse {
            columns,
            values: Vec::new(),
            is_partial: is_partial(obj),
        });
    }
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

pub async fn run_sync(t: &Transport, query: &str) -> Result<EsqlResponse> {
    let body = serde_json::json!({ "query": query });
    let response = t.post_absolute_es("/_query", &body).await?;
    decode(&response)
}

pub async fn run_async(t: &Transport, query: &str) -> Result<EsqlResponse> {
    let start = t
        .post_absolute_es(
            "/_query/async",
            &serde_json::json!({ "query": query, "wait_for_completion_timeout": "1ms", "columnar": true }),
        )
        .await?;
    let id = match start.get("id").and_then(Value::as_str) {
        Some(id) => id.to_string(),
        None => return decode_columnar(&start),
    };
    if start.get("is_running").and_then(Value::as_bool) == Some(false) {
        let _ = t.delete_absolute_es(&async_path(&id)?).await;
        return decode_columnar(&start);
    }

    poll_until_complete(t, &id, 300, Duration::from_secs(1)).await
}

fn async_path(id: &str) -> Result<String> {
    Ok(format!(
        "/_query/async/{}",
        urlencode(require_path_segment(id)?)
    ))
}

pub async fn poll_until_complete(
    t: &Transport,
    id: &str,
    max_polls: usize,
    interval: Duration,
) -> Result<EsqlResponse> {
    let path = async_path(id)?;
    for _ in 0..max_polls {
        let resp = match t.get_absolute_es(&path).await {
            Ok(resp) => resp,
            Err(err) => {
                let _ = t.delete_absolute_es(&path).await;
                return Err(err);
            }
        };
        if resp.get("is_running").and_then(Value::as_bool) == Some(false) {
            let _ = t.delete_absolute_es(&path).await;
            return decode_columnar(&resp);
        }
        tokio::time::sleep(interval).await;
    }
    let _ = t.delete_absolute_es(&path).await;
    Err(Error::new(
        ErrorKind::Timeout,
        format!("async query {id} still running after {max_polls} polls"),
    ))
}
