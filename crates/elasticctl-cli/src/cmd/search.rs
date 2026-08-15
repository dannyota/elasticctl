//! Adapters for `search esql` and `search dsl`. Read-only: no mutation guard.

use crate::context::Context;
use elasticctl_api::search::{dataview, dsl, esql};
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::Value;
use std::collections::HashMap;

/// Convert ES|QL `columns`+`values` into an array of row objects for the
/// render layer. Column order comes from `columns`; a duplicate name (a `text`
/// field emits `message` and `message.keyword`) is disambiguated by suffix.
fn esql_rows(resp: &esql::EsqlResponse) -> Value {
    let mut seen = HashMap::<String, usize>::new();
    let names: Vec<String> = resp
        .columns
        .iter()
        .map(|c| {
            let count = seen.entry(c.name.clone()).or_insert(0);
            let n = *count;
            *count += 1;
            if n == 0 {
                c.name.clone()
            } else {
                format!("{}.{}", c.name, n)
            }
        })
        .collect();
    Value::Array(
        resp.values
            .iter()
            .map(|row| Value::Object(names.iter().cloned().zip(row.iter().cloned()).collect()))
            .collect(),
    )
}

/// Prepend `FROM <pattern>` unless the query already names a source command.
fn prepend_from(query: &str, pattern: &str) -> String {
    let first = query
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(first.as_str(), "from" | "row" | "show" | "metrics") {
        query.to_string()
    } else {
        format!("FROM {pattern} {query}")
    }
}

pub async fn esql(
    ctx: &Context,
    query: &str,
    data_view: Option<&str>,
    index: Option<&str>,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let resolved_query = match (index, data_view) {
        (Some(i), _) => prepend_from(query, i),
        (_, Some(dv)) => prepend_from(query, &dataview::resolve(t, dv).await?),
        _ => query.to_string(),
    };
    let resp = esql::run_sync(t, &resolved_query).await?;
    Ok(esql_rows(&resp))
}

pub async fn dsl(
    ctx: &Context,
    body: &str,
    data_view: Option<&str>,
    index: Option<&str>,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let body: Value = if let Some(path) = body.strip_prefix('@') {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::new(ErrorKind::Error, e.to_string()))?;
        serde_json::from_str(&text)
            .map_err(|e| Error::new(ErrorKind::Error, format!("parsing {path}: {e}")))?
    } else {
        serde_json::from_str(body)
            .map_err(|e| Error::new(ErrorKind::Error, format!("parsing body: {e}")))?
    };
    let index = match (index, data_view) {
        (Some(i), _) => i.to_string(),
        (_, Some(dv)) => dataview::resolve(t, dv).await?,
        _ => {
            return Err(Error::new(
                ErrorKind::Error,
                "dsl requires --index or --data-view; the body carries the query, not the index",
            ));
        }
    };
    let page = dsl::run_sync(t, &index, &body).await?;
    Ok(Value::Array(
        page.hits.into_iter().map(|h| h.source).collect(),
    ))
}
