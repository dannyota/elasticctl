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

/// Return `query` with leading whitespace and ES|QL comments (`// …` to end of
/// line, `/* … */` blocks) stripped, so classification reads the first real
/// token rather than a comment.
fn skip_leading_comments(query: &str) -> &str {
    let mut rest = query;
    loop {
        rest = rest.trim_start();
        if rest.starts_with("//") {
            rest = &rest[rest.find('\n').map_or(rest.len(), |end| end + 1)..];
        } else if rest.starts_with("/*") {
            let Some(end) = rest.find("*/") else {
                return "";
            };
            rest = &rest[end + 2..];
        } else {
            return rest;
        }
    }
}

pub fn has_source(query: &str) -> bool {
    let rest = skip_leading_comments(query);
    let word = &rest[..rest.find(char::is_whitespace).unwrap_or(rest.len())];
    matches!(
        word.to_ascii_lowercase().as_str(),
        "from" | "row" | "show" | "metrics"
    )
}

pub fn prepend_from(query: &str, pattern: &str) -> String {
    if has_source(query) {
        query.to_string()
    } else {
        let q = query.trim_start();
        let sep = if q.starts_with('|') { "" } else { "| " };
        format!("FROM {pattern} {sep}{q}")
    }
}

/// Rewrite an ES|QL query's source to `pattern`, used when `--index` or
/// `--data-view` is given. A leading `FROM <source>` becomes `FROM <pattern>`
/// with any `| …` pipeline kept; `ROW`/`SHOW`/`METRICS` pass through untouched;
/// a query with no source command gets `FROM <pattern>` prepended.
pub fn rewrite_from(query: &str, pattern: &str) -> String {
    let rest = skip_leading_comments(query);
    let leading = &query[..query.len() - rest.len()];
    let word_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let word = &rest[..word_end];
    if word.eq_ignore_ascii_case("from") {
        let after = &rest[word_end..];
        let source_end = after.find('|').unwrap_or(after.len());
        let pipeline = &after[source_end..];
        if pipeline.is_empty() {
            format!("{leading}FROM {pattern}")
        } else {
            format!("{leading}FROM {pattern} {pipeline}")
        }
    } else if word.eq_ignore_ascii_case("row")
        || word.eq_ignore_ascii_case("show")
        || word.eq_ignore_ascii_case("metrics")
    {
        query.to_string()
    } else {
        prepend_from(query, pattern)
    }
}

/// Resolve an ES|QL query's source: `--index` wins, then `--data-view`, then
/// the query's own source, then the space's default alerts index.
pub async fn resolve_esql_query(t: &Transport, query: &str, req: &SearchRequest) -> Result<String> {
    match (&req.index, &req.data_view) {
        (Some(i), _) => Ok(rewrite_from(query, i)),
        (_, Some(dv)) => Ok(rewrite_from(query, &dataview::resolve(t, dv).await?)),
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
