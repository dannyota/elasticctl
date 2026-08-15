//! ES|QL columnar responses and the sync `/_query` runner.

use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::Value;

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

/// Strict decode of a `POST /_query` response. Unknown fields are accepted; a
/// missing or mistyped `columns`/`values` is an error, never an empty result.
pub fn decode(value: &Value) -> Result<EsqlResponse> {
    let obj = value.as_object().ok_or_else(|| {
        Error::new(
            ErrorKind::Http,
            "decoding esql response: expected an object",
        )
    })?;

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

    let values = obj
        .get("values")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new(ErrorKind::Http, "decoding esql response field `values`"))?
        .iter()
        .map(|row| {
            row.as_array().cloned().ok_or_else(|| {
                Error::new(
                    ErrorKind::Http,
                    "decoding esql response: `values` rows must be arrays",
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let is_partial = obj
        .get("is_partial")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Ok(EsqlResponse {
        columns: out,
        values,
        is_partial,
    })
}

/// Run a synchronous ES|QL query. `query` carries its own `FROM` and `LIMIT`.
pub async fn run_sync(t: &Transport, query: &str) -> Result<EsqlResponse> {
    let body = serde_json::json!({ "query": query });
    let response = t.post_absolute_es("/_query", &body).await?;
    decode(&response)
}

/// Run a query through the async API and poll until complete. ES|QL has no
/// page-by-page cursor; the full result returns in one response.
pub async fn run_async(t: &Transport, query: &str) -> Result<EsqlResponse> {
    let start = t
        .post_absolute_es(
            "/_query/async",
            &serde_json::json!({ "query": query, "wait_for_completion_timeout": "1ms", "columnar": false }),
        )
        .await?;
    let id = start
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(ErrorKind::Http, "decoding async esql response field `id`"))?
        .to_string();
    loop {
        let resp = t
            .get_absolute_es(&format!(
                "/_query/async/{id}?wait_for_completion_timeout=10s"
            ))
            .await?;
        if resp.get("is_running").and_then(Value::as_bool) == Some(false) {
            let _ = t.delete_absolute_es(&format!("/_query/async/{id}")).await;
            return decode(&resp);
        }
    }
}
