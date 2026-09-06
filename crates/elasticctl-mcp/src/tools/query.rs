//! Explicitly enabled synchronous Elasticsearch query adapters.

use std::{future::Future, pin::Pin, sync::Arc};

use elasticctl_api::search::{dsl, esql};
use elasticctl_core::{Error, ErrorKind, Result};
use rmcp::{
    model::{JsonObject, Tool, ToolAnnotations},
    schemars::{self, JsonSchema},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use crate::{
    PageInfo, ServerState, ToolFailure, ToolSuccess,
    catalog::ToolId,
    server::{validate_limit, validate_text},
    tools::{AdapterError, AdapterResult, ToolAdapter},
};

const DEFAULT_LIMIT: usize = 50;
const MAX_ESQL_BYTES: usize = 65_536;
const MAX_TEXT_BYTES: usize = 1_024;
const MAX_FIELDS: usize = 200;
const MAX_SORT: usize = 20;

pub(crate) struct QueryAdapter;
static ADAPTER: QueryAdapter = QueryAdapter;

pub(crate) fn adapter() -> &'static dyn ToolAdapter {
    &ADAPTER
}

pub(crate) fn definitions() -> Vec<Tool> {
    vec![
        definition::<DslInput, DslOutput>(
            "search_dsl",
            "Run a bounded synchronous Elasticsearch Query DSL search against the selected index.",
        ),
        definition::<EsqlInput, EsqlOutput>(
            "search_esql",
            "Run a bounded synchronous ES|QL query against the selected Elasticsearch target.",
        ),
    ]
}

fn definition<Input: JsonSchema + 'static, Output: JsonSchema + 'static>(
    name: &'static str,
    description: &'static str,
) -> Tool {
    let tool = Tool::new(name, description, JsonObject::new())
        .with_input_schema::<Input>()
        .with_output_schema::<Output>()
        .with_annotations(
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(true),
        );
    let mut schema = tool
        .output_schema
        .as_ref()
        .expect("typed output schema")
        .as_ref()
        .clone();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    tool.with_raw_output_schema(Arc::new(schema))
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EsqlInput {
    /// A complete ES|QL query that contains non-whitespace text, is at most 65,536 UTF-8 bytes, and is supplied unchanged before elasticctl appends its terminal limit.
    #[schemars(length(min = 1, max = 65_536))]
    query: String,
    #[serde(default = "default_limit")]
    #[schemars(default = "default_limit")]
    #[schemars(range(min = 1, max = 200))]
    limit: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DslInput {
    /// A comma-separated, nonempty list of ASCII letter, digit, `.`, `_`, `-`, or `*` patterns. Components cannot be `.` or `..`; URL syntax and remote cluster prefixes are rejected. The supplied value contains non-whitespace text, is used unchanged, and is at most 1,024 UTF-8 bytes.
    #[schemars(length(min = 1, max = 1024))]
    index: String,
    /// Elasticsearch Query DSL clause. This open object is embedded in the fixed request body.
    query: Map<String, Value>,
    /// Optional `_source` field names. Each supplied value contains non-whitespace text, is at most 1,024 UTF-8 bytes, and is used unchanged.
    #[schemars(length(max = 200), inner(length(min = 1, max = 1024)))]
    fields: Option<Vec<String>>,
    /// Optional sort entries. Each entry is a string or an open JSON object.
    #[schemars(length(max = 20))]
    sort: Option<Vec<SortEntry>>,
    #[serde(default = "default_limit")]
    #[schemars(default = "default_limit")]
    #[schemars(range(min = 1, max = 200))]
    limit: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
enum SortEntry {
    Name(String),
    Specification(Map<String, Value>),
}

#[derive(Serialize, JsonSchema)]
struct EsqlColumn {
    name: String,
    #[serde(rename = "type")]
    r#type: String,
}

#[derive(Serialize, JsonSchema)]
struct EsqlData {
    columns: Vec<EsqlColumn>,
    values: Vec<Vec<Value>>,
    is_partial: bool,
}

#[derive(Serialize, JsonSchema)]
struct DslHit {
    id: Option<String>,
    index: Option<String>,
    score: Option<f64>,
    source: Value,
}

#[derive(Serialize, JsonSchema)]
struct DslData {
    hits: Vec<DslHit>,
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum EsqlOutput {
    Success(ToolSuccess<EsqlData>),
    Failure(ToolFailure),
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum DslOutput {
    Success(ToolSuccess<DslData>),
    Failure(ToolFailure),
}

impl ToolAdapter for QueryAdapter {
    fn definitions(&self) -> Vec<Tool> {
        definitions()
    }

    fn call<'a>(
        &'a self,
        tool: ToolId,
        arguments: Option<&'a JsonObject>,
        state: &'a ServerState,
        _cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<AdapterResult, AdapterError>> + Send + 'a>>
    {
        Box::pin(async move {
            match tool {
                ToolId::SearchEsql => {
                    let input = parse::<EsqlInput>(arguments)?;
                    validate_text("query", &input.query, MAX_ESQL_BYTES)
                        .map_err(|_| AdapterError::InvalidArgument)?;
                    validate_limit(input.limit).map_err(|_| AdapterError::InvalidArgument)?;
                    run_esql(
                        input,
                        state.query_transport().await.map_err(AdapterError::Core)?,
                    )
                    .await
                }
                ToolId::SearchDsl => {
                    let input = parse::<DslInput>(arguments)?;
                    validate_dsl_input(&input)?;
                    run_dsl(
                        input,
                        state.query_transport().await.map_err(AdapterError::Core)?,
                    )
                    .await
                }
                _ => Err(AdapterError::InvalidArgument),
            }
        })
    }
}

async fn run_esql(
    input: EsqlInput,
    transport: &elasticctl_core::Transport,
) -> std::result::Result<AdapterResult, AdapterError> {
    let response = esql::run_sync(transport, &bounded_esql(&input.query, input.limit))
        .await
        .map_err(AdapterError::Core)?;
    let fetched = response.values.len();
    let mut values = response.values;
    let truncated = values.len() > input.limit;
    values.truncate(input.limit);
    project(
        EsqlData {
            columns: response
                .columns
                .into_iter()
                .map(|column| EsqlColumn {
                    name: column.name,
                    r#type: column.r#type,
                })
                .collect(),
            values,
            is_partial: response.is_partial,
        },
        "values",
        input.limit,
        fetched,
        truncated,
    )
}

async fn run_dsl(
    input: DslInput,
    transport: &elasticctl_core::Transport,
) -> std::result::Result<AdapterResult, AdapterError> {
    let mut body = serde_json::json!({ "query": input.query, "size": input.limit + 1, "track_total_hits": false });
    if let Some(fields) = input.fields {
        body["_source"] = Value::Array(fields.into_iter().map(Value::String).collect());
    }
    if let Some(sort) = input.sort {
        body["sort"] = Value::Array(
            sort.into_iter()
                .map(|entry| match entry {
                    SortEntry::Name(name) => Value::String(name),
                    SortEntry::Specification(specification) => Value::Object(specification),
                })
                .collect(),
        );
    }
    let response = dsl::run_sync(transport, &input.index, &body)
        .await
        .map_err(AdapterError::Core)?;
    let fetched = response.hits.len();
    let mut hits = response.hits;
    let truncated = hits.len() > input.limit;
    hits.truncate(input.limit);
    project(
        DslData {
            hits: hits
                .into_iter()
                .map(|hit| DslHit {
                    id: hit.id,
                    index: hit.index,
                    score: hit.score,
                    source: hit.source,
                })
                .collect(),
        },
        "hits",
        input.limit,
        fetched,
        truncated,
    )
}

fn validate_dsl_input(input: &DslInput) -> std::result::Result<(), AdapterError> {
    validate_index(&input.index).map_err(|_| AdapterError::InvalidArgument)?;
    validate_limit(input.limit).map_err(|_| AdapterError::InvalidArgument)?;
    if input
        .fields
        .as_ref()
        .is_some_and(|fields| fields.len() > MAX_FIELDS)
        || input
            .sort
            .as_ref()
            .is_some_and(|sort| sort.len() > MAX_SORT)
    {
        return Err(AdapterError::InvalidArgument);
    }
    if let Some(fields) = &input.fields {
        for field in fields {
            validate_text("fields", field, MAX_TEXT_BYTES)
                .map_err(|_| AdapterError::InvalidArgument)?;
        }
    }
    Ok(())
}

fn parse<T: for<'de> Deserialize<'de>>(
    arguments: Option<&JsonObject>,
) -> std::result::Result<T, AdapterError> {
    serde_json::from_value(Value::Object(arguments.cloned().unwrap_or_default()))
        .map_err(|_| AdapterError::InvalidArgument)
}

fn project<T: Serialize>(
    data: T,
    row_key: &'static str,
    limit: usize,
    fetched: usize,
    truncated: bool,
) -> std::result::Result<AdapterResult, AdapterError> {
    serde_json::to_value(data)
        .map(|data| AdapterResult {
            data,
            page: Some(PageInfo {
                limit,
                returned: fetched.min(limit),
                total: None,
                has_more: truncated.then_some(true),
                truncated,
            }),
            row_key: Some(row_key),
        })
        .map_err(|_| {
            AdapterError::Core(Error::new(
                ErrorKind::Error,
                "serializing MCP query result failed",
            ))
        })
}

fn validate_index(index: &str) -> Result<()> {
    if index.is_empty() || index.len() > MAX_TEXT_BYTES {
        return Err(Error::new(ErrorKind::Error, "index is invalid"));
    }
    for part in index.split(',') {
        if part.is_empty()
            || matches!(part, "." | "..")
            || !part.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'*')
            })
        {
            return Err(Error::new(ErrorKind::Error, "index is invalid"));
        }
    }
    Ok(())
}

fn bounded_esql(query: &str, limit: usize) -> String {
    format!("{query}\n| LIMIT {}", limit + 1)
}

#[cfg(test)]
mod tests {
    use super::{bounded_esql, validate_index};
    #[test]
    fn rejects_route_injection_indexes() {
        for index in [
            "../_bulk",
            "logs?scroll=1m",
            "logs%2f_bulk",
            "remote:logs",
            "logs,,other",
        ] {
            assert!(validate_index(index).is_err());
        }
    }
    #[test]
    fn appends_a_terminal_limit_after_trailing_comments() {
        assert_eq!(
            bounded_esql("FROM logs-* // note", 50),
            "FROM logs-* // note\n| LIMIT 51"
        );
    }
}
