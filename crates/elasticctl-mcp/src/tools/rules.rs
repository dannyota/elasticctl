//! Read-only projections for Elastic Security rules.

use std::{future::Future, pin::Pin, sync::Arc};

use elasticctl_api::{PrebuiltStatus, Rule, RuleFilter, RuleSource, prebuilt, rules_ops};
use elasticctl_core::{Error, ErrorKind};
use rmcp::{
    model::{JsonObject, Tool, ToolAnnotations},
    schemars::{self, JsonSchema},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Number, Value};
use tokio_util::sync::CancellationToken;

use crate::{
    PageInfo, ServerState, ToolFailure, ToolSuccess,
    catalog::ToolId,
    server::{validate_limit, validate_text},
    tools::{AdapterError, AdapterResult, ToolAdapter},
};

const LIST_DESCRIPTION: &str = "List read-only Elastic Security rules from the selected stack.";
const GET_DESCRIPTION: &str = "Inspect one rule by its exact rule_id or display name.";
const PREBUILT_STATUS_DESCRIPTION: &str =
    "Inspect the installed, missing, outdated, and customized prebuilt-rule counts.";
const DEFAULT_LIMIT: usize = 50;
const MAX_TEXT_BYTES: usize = 1_024;

/// The explicit adapter for all read-only rule tools.
pub(crate) struct RulesAdapter;

static ADAPTER: RulesAdapter = RulesAdapter;

/// Return the read-only rule adapter.
pub(crate) fn adapter() -> &'static dyn ToolAdapter {
    &ADAPTER
}

/// Return static rule definitions in lexical catalog order.
pub(crate) fn definitions() -> Vec<Tool> {
    vec![
        definition::<RulesGetInput, RulesGetOutput>("rules_get", GET_DESCRIPTION),
        definition::<RulesListInput, RulesListOutput>("rules_list", LIST_DESCRIPTION),
        definition::<PrebuiltStatusInput, PrebuiltStatusOutput>(
            "rules_prebuilt_status",
            PREBUILT_STATUS_DESCRIPTION,
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

/// The closed source vocabulary accepted by the existing API.
#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
enum RuleSourceInput {
    Custom,
    Customized,
    Prebuilt,
    #[default]
    All,
}

impl From<RuleSourceInput> for RuleSource {
    fn from(source: RuleSourceInput) -> Self {
        match source {
            RuleSourceInput::Custom => Self::Custom,
            RuleSourceInput::Customized => Self::Customized,
            RuleSourceInput::Prebuilt => Self::Prebuilt,
            RuleSourceInput::All => Self::All,
        }
    }
}

fn default_source() -> RuleSourceInput {
    RuleSourceInput::All
}

/// Inputs for a bounded rule list.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RulesListInput {
    #[serde(default = "default_limit")]
    #[schemars(default = "default_limit")]
    #[schemars(range(min = 1, max = 200))]
    limit: usize,
    enabled: Option<bool>,
    rule_type: Option<String>,
    severity: Option<String>,
    tag: Option<String>,
    search: Option<String>,
    #[serde(default)]
    #[schemars(default = "default_source")]
    source: RuleSourceInput,
}

impl RulesListInput {
    fn filter(self) -> Result<(usize, RuleFilter), AdapterError> {
        validate_limit(self.limit).map_err(|_| AdapterError::InvalidArgument)?;
        for (field, value) in [
            ("rule_type", self.rule_type.as_deref()),
            ("severity", self.severity.as_deref()),
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
            RuleFilter {
                source: self.source.into(),
                enabled: self.enabled,
                rule_type: self.rule_type,
                severity: self.severity,
                tag: self.tag,
                search: self.search,
                ..Default::default()
            },
        ))
    }
}

/// Input for the existing exact-id-or-name resolver.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RulesGetInput {
    selector: String,
}

impl RulesGetInput {
    fn selector(self) -> Result<String, AdapterError> {
        validate_text("selector", &self.selector, MAX_TEXT_BYTES)
            .map_err(|_| AdapterError::InvalidArgument)?;
        Ok(self.selector)
    }
}

/// Prebuilt status accepts no arguments.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PrebuiltStatusInput {}

/// A projected list row. Fields absent in a rule remain absent in the result.
#[derive(Debug, Serialize, JsonSchema)]
struct RuleSummaryData {
    rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    rule_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk_score: Option<Number>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
}

/// A stable exception reference without its volatile saved-object id.
#[derive(Debug, Serialize, JsonSchema)]
struct ExceptionReferenceData {
    #[serde(skip_serializing_if = "Option::is_none")]
    list_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace_type: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    rule_type: Option<String>,
}

/// The explicit detailed rule projection.
#[derive(Debug, Serialize, JsonSchema)]
struct RuleGetData {
    rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    rule_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk_score: Option<Number>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<Vec<String>>,
    #[serde(rename = "from", skip_serializing_if = "Option::is_none")]
    from_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interval: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exceptions_list: Option<Vec<ExceptionReferenceData>>,
}

/// The bounded rule-list data object.
#[derive(Debug, Serialize, JsonSchema)]
struct RulesListData {
    rules: Vec<RuleSummaryData>,
}

/// Existing prebuilt status counters, with an MCP schema mirror.
#[derive(Debug, Serialize, JsonSchema)]
struct PrebuiltStatusData {
    installed: u64,
    not_installed: u64,
    not_updated: u64,
    custom_installed: u64,
    customized: u64,
    timelines_installed: u64,
    timelines_not_installed: u64,
    timelines_not_updated: u64,
}

impl From<PrebuiltStatus> for PrebuiltStatusData {
    fn from(status: PrebuiltStatus) -> Self {
        Self {
            installed: status.installed,
            not_installed: status.not_installed,
            not_updated: status.not_updated,
            custom_installed: status.custom_installed,
            customized: status.customized,
            timelines_installed: status.timelines_installed,
            timelines_not_installed: status.timelines_not_installed,
            timelines_not_updated: status.timelines_not_updated,
        }
    }
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum RulesListOutput {
    Success(ToolSuccess<RulesListData>),
    Failure(ToolFailure),
}

#[allow(dead_code)]
#[allow(clippy::large_enum_variant)] // Schema-only alternatives are never instantiated.
#[derive(JsonSchema)]
#[serde(untagged)]
enum RulesGetOutput {
    Success(ToolSuccess<RuleGetData>),
    Failure(ToolFailure),
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum PrebuiltStatusOutput {
    Success(ToolSuccess<PrebuiltStatusData>),
    Failure(ToolFailure),
}

impl ToolAdapter for RulesAdapter {
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
                ToolId::RulesList => {
                    let (limit, filter) = parse_input::<RulesListInput>(arguments)?.filter()?;
                    let transport = state.transport().await.map_err(AdapterError::Core)?;
                    let report = rules_ops::list(transport, &filter)
                        .await
                        .map_err(AdapterError::Core)?;
                    let total = u64::try_from(report.total)
                        .map_err(|_| AdapterError::Core(projection_error()))?;
                    let returned = report.rules.len().min(limit);
                    let truncated = returned < report.rules.len();
                    let rules = report
                        .rules
                        .iter()
                        .take(returned)
                        .map(project_summary)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(AdapterError::Core)?;
                    project(
                        RulesListData { rules },
                        Some(PageInfo {
                            limit,
                            returned,
                            total: Some(total),
                            has_more: Some(truncated),
                            truncated,
                        }),
                        Some("rules"),
                    )
                }
                ToolId::RulesGet => {
                    let selector = parse_input::<RulesGetInput>(arguments)?.selector()?;
                    let transport = state.transport().await.map_err(AdapterError::Core)?;
                    let rule = rules_ops::get_one(transport, &selector)
                        .await
                        .map_err(AdapterError::Core)?;
                    project(
                        project_detail(&rule).map_err(AdapterError::Core)?,
                        None,
                        None,
                    )
                }
                ToolId::RulesPrebuiltStatus => {
                    parse_input::<PrebuiltStatusInput>(arguments)?;
                    let transport = state.transport().await.map_err(AdapterError::Core)?;
                    let status = prebuilt::status(transport)
                        .await
                        .map_err(AdapterError::Core)?;
                    project(PrebuiltStatusData::from(status), None, None)
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

fn project_summary(rule: &Rule) -> Result<RuleSummaryData, Error> {
    let map = rule.as_map();
    Ok(RuleSummaryData {
        rule_id: required_field(map, "rule_id")?,
        name: optional_field(map, "name")?,
        rule_type: optional_field(map, "type")?,
        enabled: optional_field(map, "enabled")?,
        severity: optional_field(map, "severity")?,
        risk_score: optional_field(map, "risk_score")?,
        tags: optional_field(map, "tags")?,
    })
}

fn project_detail(rule: &Rule) -> Result<RuleGetData, Error> {
    let summary = project_summary(rule)?;
    let map = rule.as_map();
    Ok(RuleGetData {
        rule_id: summary.rule_id,
        name: summary.name,
        rule_type: summary.rule_type,
        enabled: summary.enabled,
        severity: summary.severity,
        risk_score: summary.risk_score,
        tags: summary.tags,
        description: optional_field(map, "description")?,
        language: optional_field(map, "language")?,
        query: optional_field(map, "query")?,
        index: optional_field(map, "index")?,
        from_: optional_field(map, "from")?,
        interval: optional_field(map, "interval")?,
        exceptions_list: project_exception_references(map)?,
    })
}

fn project_exception_references(
    map: &Map<String, Value>,
) -> Result<Option<Vec<ExceptionReferenceData>>, Error> {
    let Some(value) = map.get("exceptions_list") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let entries = value.as_array().ok_or_else(projection_error)?;
    entries
        .iter()
        .map(|entry| {
            let entry = entry.as_object().ok_or_else(projection_error)?;
            Ok(ExceptionReferenceData {
                list_id: optional_field(entry, "list_id")?,
                namespace_type: optional_field(entry, "namespace_type")?,
                rule_type: optional_field(entry, "type")?,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
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
        "the selected deployment returned an invalid rule projection",
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
