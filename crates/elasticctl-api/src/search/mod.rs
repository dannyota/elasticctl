//! Ad hoc data search: ES|QL and Query DSL.

pub mod dataview;
pub mod dsl;
pub mod esql;

use elasticctl_core::{Result, Transport};

pub struct SearchRequest {
    pub index: Option<String>,
    pub data_view: Option<String>,
    pub limit: Option<usize>,
}

pub fn has_source(query: &str) -> bool {
    matches!(
        query
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "from" | "row" | "show" | "metrics"
    )
}

pub fn prepend_from(query: &str, pattern: &str) -> String {
    if has_source(query) {
        query.to_string()
    } else {
        format!("FROM {pattern} {query}")
    }
}

/// Resolve an ES|QL query's source: `--index` wins, then `--data-view`, then
/// the query's own source, then the space's default alerts index.
pub async fn resolve_esql_query(t: &Transport, query: &str, req: &SearchRequest) -> Result<String> {
    match (&req.index, &req.data_view) {
        (Some(i), _) => Ok(prepend_from(query, i)),
        (_, Some(dv)) => Ok(prepend_from(query, &dataview::resolve(t, dv).await?)),
        _ => {
            if has_source(query) {
                Ok(query.to_string())
            } else {
                Ok(prepend_from(
                    query,
                    &dataview::default_alerts_index(t).await?,
                ))
            }
        }
    }
}

/// Resolve a DSL search's index: `--index` wins, then `--data-view`, then the
/// space's default alerts index.
pub async fn resolve_dsl_index(t: &Transport, req: &SearchRequest) -> Result<String> {
    match (&req.index, &req.data_view) {
        (Some(i), _) => Ok(i.clone()),
        (_, Some(dv)) => dataview::resolve(t, dv).await,
        _ => dataview::default_alerts_index(t).await,
    }
}
