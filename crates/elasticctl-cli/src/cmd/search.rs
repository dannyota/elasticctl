//! Adapters for `search esql` and `search dsl`. Read-only: no mutation guard.

use crate::context::Context;
use elasticctl_api::search::{dsl, esql};
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Value, json};
use std::collections::HashSet;

/// Convert ES|QL `columns`+`values` into an array of row objects for the
/// render layer (serialization, so it lives in `-cli`).
fn esql_rows(resp: &esql::EsqlResponse) -> Value {
    let mut used = HashSet::<String>::new();
    let names: Vec<String> = resp
        .columns
        .iter()
        .map(|c| {
            if used.insert(c.name.clone()) {
                return c.name.clone();
            }
            // Disambiguate a duplicate name with a `.N` suffix. Check the
            // candidate against every name already emitted, not just this
            // column's duplicates, so a generated `field.N` never collides
            // with a literal column already named `field.N`.
            let mut n = 1;
            loop {
                let candidate = format!("{}.{}", c.name, n);
                if used.insert(candidate.clone()) {
                    return candidate;
                }
                n += 1;
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

fn truncate(rows: &mut Value, limit: Option<usize>) {
    if let (Some(limit), Value::Array(items)) = (limit, rows) {
        items.truncate(limit);
    }
}

pub async fn esql(
    ctx: &Context,
    query: &str,
    data_view: Option<&str>,
    index: Option<&str>,
    limit: Option<usize>,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let req = elasticctl_api::search::SearchRequest {
        index: index.map(str::to_owned),
        data_view: data_view.map(str::to_owned),
        limit,
    };
    let resolved = elasticctl_api::search::resolve_esql_query(t, query, &req).await?;
    let resp = if ctx.global.out.is_some() {
        esql::run_async(t, &resolved).await?
    } else {
        esql::run_sync(t, &resolved).await?
    };
    let mut rows = esql_rows(&resp);
    if ctx.global.out.is_some() {
        // A bulk export is uncapped unless the operator set --limit.
        truncate(&mut rows, limit);
    } else {
        // A peek defaults to 100 rows and reports the client-side cap.
        let cap = limit.unwrap_or(100);
        if rows.as_array().is_some_and(|items| items.len() > cap) {
            truncate(&mut rows, Some(cap));
            eprintln!("capped at {cap} rows");
        }
    }
    Ok(rows)
}

pub async fn dsl(
    ctx: &Context,
    body: &str,
    data_view: Option<&str>,
    index: Option<&str>,
    limit: Option<usize>,
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
    let req = elasticctl_api::search::SearchRequest {
        index: index.map(str::to_owned),
        data_view: data_view.map(str::to_owned),
        limit,
    };
    let resolved_index = elasticctl_api::search::resolve_dsl_index(t, &req).await?;
    if ctx.global.out.is_some() {
        let sort = body
            .get("sort")
            .cloned()
            .unwrap_or_else(|| json!([{"_shard_doc": "asc"}]));
        let query = body
            .get("query")
            .cloned()
            .unwrap_or_else(|| json!({"match_all": {}}));
        let hits = dsl::run_stream(t, &resolved_index, &query, &sort, limit).await?;
        Ok(Value::Array(hits.into_iter().map(|h| h.source).collect()))
    } else {
        let page = dsl::run_sync(t, &resolved_index, &body).await?;
        let mut rows = Value::Array(page.hits.into_iter().map(|h| h.source).collect());
        // A peek defaults to 100 rows and reports the client-side cap.
        let cap = limit.unwrap_or(100);
        if rows.as_array().is_some_and(|items| items.len() > cap) {
            truncate(&mut rows, Some(cap));
            eprintln!("capped at {cap} rows");
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::esql_rows;
    use elasticctl_api::search::esql::{EsqlColumn, EsqlResponse};
    use serde_json::json;

    #[test]
    fn disambiguates_suffix_collisions_with_literal_names() {
        let resp = EsqlResponse {
            columns: vec![
                EsqlColumn {
                    name: "message".into(),
                    r#type: "text".into(),
                },
                EsqlColumn {
                    name: "message.keyword".into(),
                    r#type: "keyword".into(),
                },
                EsqlColumn {
                    name: "message.keyword".into(),
                    r#type: "keyword".into(),
                },
                EsqlColumn {
                    name: "message.keyword.1".into(),
                    r#type: "keyword".into(),
                },
            ],
            values: vec![vec![json!("a"), json!("b"), json!("c"), json!("d")]],
            is_partial: false,
        };
        let row = esql_rows(&resp);
        let obj = row.as_array().unwrap()[0].as_object().unwrap();
        assert_eq!(obj.len(), 4);
        assert!(obj.contains_key("message"));
        assert!(obj.contains_key("message.keyword"));
        assert!(obj.contains_key("message.keyword.1"));
        assert!(obj.contains_key("message.keyword.1.1"));
    }
}
