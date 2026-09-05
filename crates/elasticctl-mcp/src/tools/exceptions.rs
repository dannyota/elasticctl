//! Read-only projections for Elastic Security exception lists and items.

use std::{future::Future, pin::Pin, sync::Arc};

use elasticctl_api::{ExceptionItem, ExceptionList, ListFilter, exceptions};
use elasticctl_core::{Error, ErrorKind};
use rmcp::{
    model::{JsonObject, Tool, ToolAnnotations},
    schemars::{self, JsonSchema},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use crate::{
    PageInfo, ServerState, ToolFailure, ToolSuccess,
    catalog::ToolId,
    server::{validate_limit, validate_text},
    tools::{AdapterError, AdapterResult, ToolAdapter},
};

const LIST_DESCRIPTION: &str = "List read-only Elastic Security exception-list containers.";
const GET_DESCRIPTION: &str = "Inspect one exception-list container and its bounded items.";
const DEFAULT_LIMIT: usize = 50;
const MAX_TEXT_BYTES: usize = 1_024;

/// The explicit adapter for exception inspection tools.
pub(crate) struct ExceptionsAdapter;

static ADAPTER: ExceptionsAdapter = ExceptionsAdapter;

/// Return the exception adapter.
pub(crate) fn adapter() -> &'static dyn ToolAdapter {
    &ADAPTER
}

/// Return static exception definitions in lexical catalog order.
pub(crate) fn definitions() -> Vec<Tool> {
    vec![
        definition::<ExceptionsGetInput, ExceptionsGetOutput>("exceptions_get", GET_DESCRIPTION),
        definition::<ExceptionsListInput, ExceptionsListOutput>(
            "exceptions_list",
            LIST_DESCRIPTION,
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
    let mut output_schema = tool
        .output_schema
        .as_ref()
        .expect("typed output schema is present")
        .as_ref()
        .clone();
    output_schema.insert("type".to_string(), Value::String("object".to_string()));
    tool.with_raw_output_schema(Arc::new(output_schema))
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

/// The API's closed exception namespace vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
enum NamespaceInput {
    Single,
    Agnostic,
}

impl NamespaceInput {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Agnostic => "agnostic",
        }
    }
}

/// Inputs for a bounded exception-container list.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExceptionsListInput {
    #[serde(default = "default_limit")]
    #[schemars(default = "default_limit")]
    #[schemars(range(min = 1, max = 200))]
    limit: usize,
    list_type: Option<String>,
    tag: Option<String>,
    namespace: Option<NamespaceInput>,
    search: Option<String>,
}

impl ExceptionsListInput {
    fn filter(self) -> Result<(usize, ListFilter), AdapterError> {
        validate_limit(self.limit).map_err(|_| AdapterError::InvalidArgument)?;
        for (field, value) in [
            ("list_type", self.list_type.as_deref()),
            ("tag", self.tag.as_deref()),
            ("search", self.search.as_deref()),
        ] {
            if let Some(value) = value {
                validate_text(field, value, MAX_TEXT_BYTES)
                    .map_err(|_| AdapterError::InvalidArgument)?;
            }
        }
        Ok((
            self.limit,
            ListFilter {
                list_type: self.list_type,
                tag: self.tag,
                namespace: self
                    .namespace
                    .map(|namespace| namespace.as_str().to_string()),
                search: self.search,
            },
        ))
    }
}

/// Inputs for an exact exception-list identity resolver and bounded items.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExceptionsGetInput {
    list_id: String,
    namespace: Option<NamespaceInput>,
    #[serde(default = "default_limit")]
    #[schemars(default = "default_limit")]
    #[schemars(range(min = 1, max = 200))]
    limit: usize,
}

impl ExceptionsGetInput {
    fn selection(self) -> Result<(String, Option<&'static str>, usize), AdapterError> {
        validate_limit(self.limit).map_err(|_| AdapterError::InvalidArgument)?;
        validate_text("list_id", &self.list_id, MAX_TEXT_BYTES)
            .map_err(|_| AdapterError::InvalidArgument)?;
        Ok((
            self.list_id,
            self.namespace.map(NamespaceInput::as_str),
            self.limit,
        ))
    }
}

/// The caller-safe exception-container projection.
#[derive(Debug, Serialize, JsonSchema)]
struct ContainerData {
    list_id: String,
    namespace_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    list_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
}

/// The caller-safe nested exception-item projection.
#[derive(Debug, Serialize, JsonSchema)]
struct ItemData {
    item_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entries: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
}

/// The bounded exception-list result data.
#[derive(Debug, Serialize, JsonSchema)]
struct ExceptionsListData {
    lists: Vec<ContainerData>,
}

/// The exception container plus its bounded item set.
#[derive(Debug, Serialize, JsonSchema)]
struct ExceptionsGetData {
    container: ContainerData,
    items: Vec<ItemData>,
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum ExceptionsListOutput {
    Success(ToolSuccess<ExceptionsListData>),
    Failure(ToolFailure),
}

#[allow(dead_code)]
#[allow(clippy::large_enum_variant)] // Schema-only alternatives are never instantiated.
#[derive(JsonSchema)]
#[serde(untagged)]
enum ExceptionsGetOutput {
    Success(ToolSuccess<ExceptionsGetData>),
    Failure(ToolFailure),
}

impl ToolAdapter for ExceptionsAdapter {
    fn definitions(&self) -> Vec<Tool> {
        definitions()
    }

    fn call<'a>(
        &'a self,
        tool: ToolId,
        arguments: Option<&'a JsonObject>,
        state: &'a ServerState,
        _cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<AdapterResult, AdapterError>> + Send + 'a>> {
        Box::pin(async move {
            match tool {
                ToolId::ExceptionsList => {
                    let (limit, filter) =
                        parse_input::<ExceptionsListInput>(arguments)?.filter()?;
                    let transport = state.transport().await.map_err(AdapterError::Core)?;
                    let report = exceptions::list_op(transport, &filter)
                        .await
                        .map_err(AdapterError::Core)?;
                    let total = u64::try_from(report.total)
                        .map_err(|_| AdapterError::Core(projection_error()))?;
                    let lists = report
                        .lists
                        .iter()
                        .map(project_container)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(AdapterError::Core)?;
                    let returned = lists.len().min(limit);
                    let truncated = returned < lists.len();
                    project(
                        ExceptionsListData {
                            lists: lists.into_iter().take(returned).collect(),
                        },
                        Some(PageInfo {
                            limit,
                            returned,
                            total: Some(total),
                            has_more: Some(truncated),
                            truncated,
                        }),
                        Some("lists"),
                    )
                }
                ToolId::ExceptionsGet => {
                    let (list_id, namespace, limit) =
                        parse_input::<ExceptionsGetInput>(arguments)?.selection()?;
                    let transport = state.transport().await.map_err(AdapterError::Core)?;
                    let detail = exceptions::get_op(transport, &list_id, namespace)
                        .await
                        .map_err(AdapterError::Core)?;
                    let container = project_container(&detail.list).map_err(AdapterError::Core)?;
                    let items = detail
                        .items
                        .iter()
                        .map(project_item)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(AdapterError::Core)?;
                    let total = u64::try_from(items.len())
                        .map_err(|_| AdapterError::Core(projection_error()))?;
                    let returned = items.len().min(limit);
                    let truncated = returned < items.len();
                    project(
                        ExceptionsGetData {
                            container,
                            items: items.into_iter().take(returned).collect(),
                        },
                        Some(PageInfo {
                            limit,
                            returned,
                            total: Some(total),
                            has_more: Some(truncated),
                            truncated,
                        }),
                        Some("items"),
                    )
                }
                _ => Err(AdapterError::InvalidArgument),
            }
        })
    }
}

fn parse_input<T: DeserializeOwned>(arguments: Option<&JsonObject>) -> Result<T, AdapterError> {
    serde_json::from_value(Value::Object(arguments.cloned().unwrap_or_default()))
        .map_err(|_| AdapterError::InvalidArgument)
}

fn project_container(list: &ExceptionList) -> Result<ContainerData, Error> {
    let map = list.as_map();
    let namespace_type = match map.get("namespace_type") {
        None | Some(Value::Null) => "single".to_string(),
        Some(Value::String(value)) => value.clone(),
        Some(_) => return Err(projection_error()),
    };
    Ok(ContainerData {
        list_id: required_field(map, "list_id")?,
        namespace_type,
        name: optional_field(map, "name")?,
        description: optional_field(map, "description")?,
        list_type: optional_field(map, "type")?,
        tags: optional_field(map, "tags")?,
    })
}

fn project_item(item: &ExceptionItem) -> Result<ItemData, Error> {
    let map = item.as_map();
    Ok(ItemData {
        item_id: required_field(map, "item_id")?,
        name: optional_field(map, "name")?,
        description: optional_field(map, "description")?,
        entries: optional_field(map, "entries")?,
        os_types: optional_field(map, "os_types")?,
        tags: optional_field(map, "tags")?,
    })
}

fn required_field<T: DeserializeOwned>(map: &Map<String, Value>, field: &str) -> Result<T, Error> {
    map.get(field)
        .cloned()
        .ok_or_else(projection_error)
        .and_then(|value| serde_json::from_value(value).map_err(|_| projection_error()))
}

fn optional_field<T: DeserializeOwned>(
    map: &Map<String, Value>,
    field: &str,
) -> Result<Option<T>, Error> {
    match map.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|_| projection_error()),
    }
}

fn projection_error() -> Error {
    Error::new(
        ErrorKind::Http,
        "the selected deployment returned an invalid exception projection",
    )
}

fn project<T: Serialize>(
    data: T,
    page: Option<PageInfo>,
    row_key: Option<&'static str>,
) -> Result<AdapterResult, AdapterError> {
    serde_json::to_value(data)
        .map(|data| AdapterResult {
            data,
            page,
            row_key,
        })
        .map_err(|_| AdapterError::Core(projection_error()))
}
