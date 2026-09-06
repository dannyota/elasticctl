//! Read-only projections for Kibana data views and dashboards.

use std::{future::Future, pin::Pin, sync::Arc};

use elasticctl_api::{
    dashboards::{Dashboard, DashboardSummary},
    dashboards_ops, data_views,
    data_views::{DataView, DataViewSummary},
    data_views_ops::{self, DataViewFilter},
};
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

const DEFAULT_LIMIT: usize = 50;
const MAX_TEXT_BYTES: usize = 1_024;

pub(crate) struct ContentAdapter;
static ADAPTER: ContentAdapter = ContentAdapter;

pub(crate) fn adapter() -> &'static dyn ToolAdapter {
    &ADAPTER
}

pub(crate) fn definitions() -> Vec<Tool> {
    vec![
        definition::<DashboardsGetInput, DashboardsGetOutput>(
            "dashboards_get",
            "Inspect one Kibana dashboard by exact id or title.",
        ),
        definition::<DashboardsListInput, DashboardsListOutput>(
            "dashboards_list",
            "List read-only Kibana dashboards from the selected stack.",
        ),
        definition::<DataViewsDefaultGetInput, DataViewsDefaultGetOutput>(
            "data_views_default_get",
            "Inspect the selected space's default Kibana data view.",
        ),
        definition::<DataViewsGetInput, DataViewsGetOutput>(
            "data_views_get",
            "Inspect one Kibana data view by exact id or name.",
        ),
        definition::<DataViewsListInput, DataViewsListOutput>(
            "data_views_list",
            "List read-only Kibana data views from the selected stack.",
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
        .expect("typed output schema is present")
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
struct DataViewsListInput {
    #[serde(default = "default_limit")]
    #[schemars(default = "default_limit")]
    #[schemars(range(min = 1, max = 200))]
    limit: usize,
    /// Data-view id, name, or title substring. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    search: Option<String>,
}

impl DataViewsListInput {
    fn filter(self) -> Result<(usize, DataViewFilter), AdapterError> {
        validate_limit(self.limit).map_err(|_| AdapterError::InvalidArgument)?;
        if let Some(value) = self.search.as_deref() {
            validate_text("search", value, MAX_TEXT_BYTES)
                .map_err(|_| AdapterError::InvalidArgument)?;
        }
        Ok((
            self.limit,
            DataViewFilter {
                search: self.search,
            },
        ))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DataViewsGetInput {
    /// Exact data-view id or exact data-view name. Must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    selector: String,
}
impl DataViewsGetInput {
    fn selector(self) -> Result<String, AdapterError> {
        validate_text("selector", &self.selector, MAX_TEXT_BYTES)
            .map_err(|_| AdapterError::InvalidArgument)?;
        Ok(self.selector)
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DataViewsDefaultGetInput {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DashboardsListInput {
    #[serde(default = "default_limit")]
    #[schemars(default = "default_limit")]
    #[schemars(range(min = 1, max = 200))]
    limit: usize,
    /// Dashboard title substring. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    search: Option<String>,
    /// Exact dashboard tag. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    tag: Option<String>,
}
impl DashboardsListInput {
    fn filter(self) -> Result<dashboards_ops::DashboardFilter, AdapterError> {
        validate_limit(self.limit).map_err(|_| AdapterError::InvalidArgument)?;
        for (field, value) in [
            ("search", self.search.as_deref()),
            ("tag", self.tag.as_deref()),
        ] {
            if let Some(value) = value {
                validate_text(field, value, MAX_TEXT_BYTES)
                    .map_err(|_| AdapterError::InvalidArgument)?;
            }
        }
        Ok(dashboards_ops::DashboardFilter {
            search: self.search,
            tag: self.tag,
            limit: Some(self.limit),
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DashboardsGetInput {
    /// Exact dashboard id or exact dashboard title. Must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    selector: String,
}
impl DashboardsGetInput {
    fn selector(self) -> Result<String, AdapterError> {
        validate_text("selector", &self.selector, MAX_TEXT_BYTES)
            .map_err(|_| AdapterError::InvalidArgument)?;
        Ok(self.selector)
    }
}

#[derive(Debug, Serialize, JsonSchema)]
struct DataViewData {
    id: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "timeFieldName", skip_serializing_if = "Option::is_none")]
    time_field_name: Option<String>,
}
#[derive(Debug, Serialize, JsonSchema)]
struct DataViewsListData {
    data_views: Vec<DataViewData>,
}
#[derive(Debug, Serialize, JsonSchema)]
struct DataViewGetData {
    data_view: DataViewDetailData,
}
#[derive(Debug, Serialize, JsonSchema)]
struct DataViewDetailData {
    id: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "timeFieldName", skip_serializing_if = "Option::is_none")]
    time_field_name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    view_type: Option<String>,
    #[serde(rename = "allowNoIndex", skip_serializing_if = "Option::is_none")]
    allow_no_index: Option<bool>,
    #[serde(rename = "allowHidden", skip_serializing_if = "Option::is_none")]
    allow_hidden: Option<bool>,
    #[serde(rename = "sourceFilters", skip_serializing_if = "Option::is_none")]
    source_filters: Option<Vec<Value>>,
    #[serde(rename = "fieldFormats", skip_serializing_if = "Option::is_none")]
    field_formats: Option<Map<String, Value>>,
    #[serde(rename = "runtimeFieldMap", skip_serializing_if = "Option::is_none")]
    runtime_field_map: Option<Map<String, Value>>,
    #[serde(rename = "fieldAttrs", skip_serializing_if = "Option::is_none")]
    field_attrs: Option<Map<String, Value>>,
    #[serde(rename = "typeMeta", skip_serializing_if = "Option::is_none")]
    type_meta: Option<Map<String, Value>>,
}
#[derive(Debug, Serialize, JsonSchema)]
#[schemars(extend("required" = ["id"]))]
struct DataViewsDefaultGetData {
    id: Option<String>,
}
#[derive(Debug, Serialize, JsonSchema)]
struct DashboardData {
    id: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
}
#[derive(Debug, Serialize, JsonSchema)]
struct DashboardsListData {
    dashboards: Vec<DashboardData>,
}
#[derive(Debug, Serialize, JsonSchema)]
struct DashboardGetData {
    id: String,
    data: Map<String, Value>,
}

macro_rules! output {
    ($name:ident, $data:ty) => {
        #[allow(dead_code)]
        #[allow(clippy::large_enum_variant)] // Schema-only alternatives are never instantiated.
        #[derive(JsonSchema)]
        #[serde(untagged)]
        enum $name {
            Success(ToolSuccess<$data>),
            Failure(ToolFailure),
        }
    };
}
output!(DataViewsListOutput, DataViewsListData);
output!(DataViewsGetOutput, DataViewGetData);
output!(DataViewsDefaultGetOutput, DataViewsDefaultGetData);
output!(DashboardsListOutput, DashboardsListData);
output!(DashboardsGetOutput, DashboardGetData);

impl ToolAdapter for ContentAdapter {
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
                ToolId::DataViewsList => {
                    let (limit, filter) = parse_input::<DataViewsListInput>(arguments)?.filter()?;
                    let report = data_views_ops::list_op(
                        state.transport().await.map_err(AdapterError::Core)?,
                        &filter,
                    )
                    .await
                    .map_err(AdapterError::Core)?;
                    let total = u64::try_from(report.total)
                        .map_err(|_| AdapterError::Core(projection_error()))?;
                    let views = report
                        .data_views
                        .iter()
                        .map(project_summary)
                        .collect::<Vec<_>>();
                    let returned = views.len().min(limit);
                    let truncated = returned < views.len();
                    project(
                        DataViewsListData {
                            data_views: views.into_iter().take(returned).collect(),
                        },
                        Some(PageInfo {
                            limit,
                            returned,
                            total: Some(total),
                            has_more: Some(truncated),
                            truncated,
                        }),
                        Some("data_views"),
                    )
                }
                ToolId::DataViewsGet => {
                    let selector = parse_input::<DataViewsGetInput>(arguments)?.selector()?;
                    let view = data_views_ops::get_op(
                        state.transport().await.map_err(AdapterError::Core)?,
                        &selector,
                    )
                    .await
                    .map_err(AdapterError::Core)?;
                    project(
                        DataViewGetData {
                            data_view: project_data_view(&view)?,
                        },
                        None,
                        None,
                    )
                }
                ToolId::DataViewsDefaultGet => {
                    parse_input::<DataViewsDefaultGetInput>(arguments)?;
                    let id = data_views::get_default(
                        state.transport().await.map_err(AdapterError::Core)?,
                    )
                    .await
                    .map_err(AdapterError::Core)?;
                    project(DataViewsDefaultGetData { id }, None, None)
                }
                ToolId::DashboardsList => {
                    let filter = parse_input::<DashboardsListInput>(arguments)?.filter()?;
                    let report = dashboards_ops::list_op(
                        state.transport().await.map_err(AdapterError::Core)?,
                        &filter,
                    )
                    .await
                    .map_err(AdapterError::Core)?;
                    project(
                        DashboardsListData {
                            dashboards: report
                                .dashboards
                                .iter()
                                .map(project_dashboard_summary)
                                .collect(),
                        },
                        Some(PageInfo {
                            limit: filter.limit.expect("MCP list limit is set"),
                            returned: report.dashboards.len(),
                            total: Some(report.total),
                            has_more: Some(report.truncated),
                            truncated: report.truncated,
                        }),
                        Some("dashboards"),
                    )
                }
                ToolId::DashboardsGet => {
                    let selector = parse_input::<DashboardsGetInput>(arguments)?.selector()?;
                    let dashboard = dashboards_ops::get_op(
                        state.transport().await.map_err(AdapterError::Core)?,
                        &selector,
                    )
                    .await
                    .map_err(AdapterError::Core)?;
                    project(project_dashboard(&dashboard), None, None)
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
fn project_summary(view: &DataViewSummary) -> DataViewData {
    DataViewData {
        id: view.id.clone(),
        title: view.title.clone(),
        name: view.name.clone(),
        time_field_name: view.time_field_name.clone(),
    }
}
fn project_dashboard_summary(dashboard: &DashboardSummary) -> DashboardData {
    DashboardData {
        id: dashboard.id.clone(),
        title: dashboard.title.clone(),
        description: dashboard.description.clone(),
        tags: dashboard.tags.clone(),
    }
}
fn project_dashboard(dashboard: &Dashboard) -> DashboardGetData {
    DashboardGetData {
        id: dashboard.id.clone(),
        data: dashboard.data.clone(),
    }
}
fn project_data_view(view: &DataView) -> Result<DataViewDetailData, AdapterError> {
    let map = &view.data_view;
    Ok(DataViewDetailData {
        id: required_field(map, "id")?,
        title: required_field(map, "title")?,
        name: optional_field(map, "name")?,
        time_field_name: optional_field(map, "timeFieldName")?,
        view_type: optional_field(map, "type")?,
        allow_no_index: optional_field(map, "allowNoIndex")?,
        allow_hidden: optional_field(map, "allowHidden")?,
        source_filters: optional_field(map, "sourceFilters")?,
        field_formats: optional_field(map, "fieldFormats")?,
        runtime_field_map: optional_field(map, "runtimeFieldMap")?,
        field_attrs: optional_field(map, "fieldAttrs")?,
        type_meta: optional_field(map, "typeMeta")?,
    })
}
fn required_field<T: DeserializeOwned>(
    map: &Map<String, Value>,
    field: &str,
) -> Result<T, AdapterError> {
    map.get(field)
        .cloned()
        .ok_or_else(|| AdapterError::Core(projection_error()))
        .and_then(|value| {
            serde_json::from_value(value).map_err(|_| AdapterError::Core(projection_error()))
        })
}
fn optional_field<T: DeserializeOwned>(
    map: &Map<String, Value>,
    field: &str,
) -> Result<Option<T>, AdapterError> {
    match map.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|_| AdapterError::Core(projection_error())),
    }
}
fn projection_error() -> Error {
    Error::new(
        ErrorKind::Http,
        "the selected deployment returned an invalid content projection",
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
