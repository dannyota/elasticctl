//! Read-only projections for Elastic Security alerts and cases.

use std::{future::Future, pin::Pin, sync::Arc};

use elasticctl_api::{
    AlertFilter, AlertHit, AlertStatus, Case, CaseFilter, CaseStatus, alerts_ops, cases_ops,
};
use elasticctl_core::{Error, ErrorKind};
use rmcp::{
    model::{JsonObject, Tool, ToolAnnotations},
    schemars::{self, JsonSchema},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Number, Value};
use tokio_util::sync::CancellationToken;

use crate::{
    PageInfo, ServerState, ToolFailure, ToolSuccess,
    catalog::ToolId,
    server::{validate_limit, validate_text},
    tools::{AdapterError, AdapterResult, ToolAdapter},
};

const ALERT_LIST_DESCRIPTION: &str =
    "List read-only Elastic Security alerts from the selected stack.";
const ALERT_GET_DESCRIPTION: &str = "Inspect one alert by its exact document id.";
const CASE_LIST_DESCRIPTION: &str =
    "List read-only Elastic Security cases from the selected stack.";
const CASE_GET_DESCRIPTION: &str = "Inspect one case by its exact id.";
const DEFAULT_LIMIT: usize = 50;
const MAX_TEXT_BYTES: usize = 1_024;

pub(crate) struct TriageAdapter;

static ADAPTER: TriageAdapter = TriageAdapter;

pub(crate) fn adapter() -> &'static dyn ToolAdapter {
    &ADAPTER
}

pub(crate) fn definitions() -> Vec<Tool> {
    vec![
        definition::<AlertsGetInput, AlertsGetOutput>("alerts_get", ALERT_GET_DESCRIPTION),
        definition::<AlertsListInput, AlertsListOutput>("alerts_list", ALERT_LIST_DESCRIPTION),
        definition::<CasesGetInput, CasesGetOutput>("cases_get", CASE_GET_DESCRIPTION),
        definition::<CasesListInput, CasesListOutput>("cases_list", CASE_LIST_DESCRIPTION),
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

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum AlertStatusInput {
    Open,
    Acknowledged,
    Closed,
}

impl From<AlertStatusInput> for AlertStatus {
    fn from(status: AlertStatusInput) -> Self {
        match status {
            AlertStatusInput::Open => Self::Open,
            AlertStatusInput::Acknowledged => Self::Acknowledged,
            AlertStatusInput::Closed => Self::Closed,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
enum CaseStatusInput {
    Open,
    InProgress,
    Closed,
}

impl From<CaseStatusInput> for CaseStatus {
    fn from(status: CaseStatusInput) -> Self {
        match status {
            CaseStatusInput::Open => Self::Open,
            CaseStatusInput::InProgress => Self::InProgress,
            CaseStatusInput::Closed => Self::Closed,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AlertsListInput {
    #[serde(default = "default_limit")]
    #[schemars(default = "default_limit")]
    #[schemars(range(min = 1, max = 200))]
    limit: usize,
    status: Option<AlertStatusInput>,
    /// Exact alert severity. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    severity: Option<String>,
    /// Exact alert rule id or display name. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    rule: Option<String>,
    /// Exact alert workflow tag. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    tag: Option<String>,
    /// Alert timestamp lower bound. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    since: Option<String>,
    /// Alert rule-name or reason substring. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    search: Option<String>,
}

impl AlertsListInput {
    fn filter(self) -> Result<(usize, AlertFilter), AdapterError> {
        validate_limit(self.limit).map_err(|_| AdapterError::InvalidArgument)?;
        for (field, value) in [
            ("severity", self.severity.as_deref()),
            ("rule", self.rule.as_deref()),
            ("tag", self.tag.as_deref()),
            ("since", self.since.as_deref()),
            ("search", self.search.as_deref()),
        ] {
            if let Some(value) = value {
                validate_text(field, value, MAX_TEXT_BYTES)
                    .map_err(|_| AdapterError::InvalidArgument)?;
            }
        }
        Ok((
            self.limit,
            AlertFilter {
                status: self.status.map(Into::into),
                severity: self.severity,
                rule: self.rule,
                tag: self.tag,
                since: self.since,
                search: self.search,
                ..Default::default()
            },
        ))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AlertsGetInput {
    /// Exact alert document id. Must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    alert_id: String,
}

impl AlertsGetInput {
    fn alert_id(self) -> Result<String, AdapterError> {
        validate_text("alert_id", &self.alert_id, MAX_TEXT_BYTES)
            .map_err(|_| AdapterError::InvalidArgument)?;
        Ok(self.alert_id)
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CasesListInput {
    #[serde(default = "default_limit")]
    #[schemars(default = "default_limit")]
    #[schemars(range(min = 1, max = 200))]
    limit: usize,
    status: Option<CaseStatusInput>,
    /// Exact case severity. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    severity: Option<String>,
    /// Exact case tag. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    tag: Option<String>,
    /// Case title or description substring. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    search: Option<String>,
}

impl CasesListInput {
    fn filter(self) -> Result<(usize, CaseFilter), AdapterError> {
        validate_limit(self.limit).map_err(|_| AdapterError::InvalidArgument)?;
        for (field, value) in [
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
            CaseFilter {
                status: self.status.map(Into::into),
                severity: self.severity,
                tag: self.tag,
                search: self.search,
            },
        ))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CasesGetInput {
    /// Exact case id. Must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    id: String,
}

impl CasesGetInput {
    fn id(self) -> Result<String, AdapterError> {
        validate_text("id", &self.id, MAX_TEXT_BYTES).map_err(|_| AdapterError::InvalidArgument)?;
        Ok(self.id)
    }
}

#[derive(Debug, Serialize, JsonSchema)]
struct AlertSourceData {
    #[serde(rename = "@timestamp", skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(
        rename = "kibana.alert.rule.rule_id",
        skip_serializing_if = "Option::is_none"
    )]
    rule_id: Option<String>,
    #[serde(
        rename = "kibana.alert.rule.name",
        skip_serializing_if = "Option::is_none"
    )]
    rule_name: Option<String>,
    #[serde(
        rename = "kibana.alert.severity",
        skip_serializing_if = "Option::is_none"
    )]
    severity: Option<String>,
    #[serde(
        rename = "kibana.alert.risk_score",
        skip_serializing_if = "Option::is_none"
    )]
    risk_score: Option<Number>,
    #[serde(
        rename = "kibana.alert.workflow_status",
        skip_serializing_if = "Option::is_none"
    )]
    workflow_status: Option<String>,
    #[serde(
        rename = "kibana.alert.reason",
        skip_serializing_if = "Option::is_none"
    )]
    reason: Option<String>,
    #[serde(
        rename = "kibana.alert.workflow_tags",
        skip_serializing_if = "Option::is_none"
    )]
    workflow_tags: Option<Vec<String>>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct AlertData {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<String>,
    source: AlertSourceData,
}

#[derive(Debug, Serialize, JsonSchema)]
struct AlertsListData {
    alerts: Vec<AlertData>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct CaseData {
    id: String,
    title: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
    #[serde(rename = "totalComment", skip_serializing_if = "Option::is_none")]
    total_comment: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct CasesListData {
    cases: Vec<CaseData>,
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum AlertsListOutput {
    Success(ToolSuccess<AlertsListData>),
    Failure(ToolFailure),
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum AlertsGetOutput {
    Success(ToolSuccess<AlertData>),
    Failure(ToolFailure),
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum CasesListOutput {
    Success(ToolSuccess<CasesListData>),
    Failure(ToolFailure),
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum CasesGetOutput {
    Success(ToolSuccess<CaseData>),
    Failure(ToolFailure),
}

impl ToolAdapter for TriageAdapter {
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
                ToolId::AlertsList => {
                    let (limit, filter) = parse_input::<AlertsListInput>(arguments)?.filter()?;
                    let transport = state.transport().await.map_err(AdapterError::Core)?;
                    let report = alerts_ops::list(transport, &filter, limit)
                        .await
                        .map_err(AdapterError::Core)?;
                    let returned = report.hits.len();
                    let alerts = report
                        .hits
                        .iter()
                        .map(project_alert)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(AdapterError::Core)?;
                    project(
                        AlertsListData { alerts },
                        Some(PageInfo {
                            limit,
                            returned,
                            total: report.total,
                            has_more: report.total.map(|total| total > returned as u64),
                            truncated: report.truncated,
                        }),
                        Some("alerts"),
                    )
                }
                ToolId::AlertsGet => {
                    let alert_id = parse_input::<AlertsGetInput>(arguments)?.alert_id()?;
                    let transport = state.transport().await.map_err(AdapterError::Core)?;
                    let alert = alerts_ops::get_one(transport, &alert_id)
                        .await
                        .map_err(AdapterError::Core)?;
                    project(
                        project_alert(&alert).map_err(AdapterError::Core)?,
                        None,
                        None,
                    )
                }
                ToolId::CasesList => {
                    let (limit, filter) = parse_input::<CasesListInput>(arguments)?.filter()?;
                    let transport = state.transport().await.map_err(AdapterError::Core)?;
                    let report = cases_ops::list(transport, &filter, limit)
                        .await
                        .map_err(AdapterError::Core)?;
                    let returned = report.cases.len();
                    let cases = report.cases.iter().map(project_case).collect();
                    project(
                        CasesListData { cases },
                        Some(PageInfo {
                            limit,
                            returned,
                            total: Some(report.total),
                            has_more: Some(report.truncated),
                            truncated: report.truncated,
                        }),
                        Some("cases"),
                    )
                }
                ToolId::CasesGet => {
                    let id = parse_input::<CasesGetInput>(arguments)?.id()?;
                    let transport = state.transport().await.map_err(AdapterError::Core)?;
                    let case = cases_ops::get_one(transport, &id)
                        .await
                        .map_err(AdapterError::Core)?;
                    project(project_case(&case), None, None)
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

fn project_alert(alert: &AlertHit) -> Result<AlertData, Error> {
    Ok(AlertData {
        id: alert.id.clone(),
        index: alert.index.clone(),
        source: AlertSourceData {
            timestamp: source_field(&alert.source, "@timestamp")?,
            rule_id: source_field(&alert.source, "kibana.alert.rule.rule_id")?,
            rule_name: source_field(&alert.source, "kibana.alert.rule.name")?,
            severity: source_field(&alert.source, "kibana.alert.severity")?,
            risk_score: source_field(&alert.source, "kibana.alert.risk_score")?,
            workflow_status: source_field(&alert.source, "kibana.alert.workflow_status")?,
            reason: source_field(&alert.source, "kibana.alert.reason")?,
            workflow_tags: source_field(&alert.source, "kibana.alert.workflow_tags")?,
        },
    })
}

fn source_field<T: DeserializeOwned>(source: &Value, key: &str) -> Result<Option<T>, Error> {
    let value = source.get(key).or_else(|| {
        let pointer = format!("/{}", key.replace('.', "/"));
        source.pointer(&pointer)
    });
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|_| projection_error()),
    }
}

fn project_case(case: &Case) -> CaseData {
    CaseData {
        id: case.id.clone(),
        title: case.title.clone(),
        status: case.status.clone(),
        severity: case.severity.clone(),
        tags: case.tags.clone(),
        description: case.description.clone(),
        created_at: case.created_at.clone(),
        updated_at: case.updated_at.clone(),
        total_comment: case.total_comment,
    }
}

fn projection_error() -> Error {
    Error::new(
        ErrorKind::Http,
        "the selected deployment returned an invalid triage projection",
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
