//! `alert_context`: triage context for one alert.
use super::*;
use crate::{
    result::{ToolFailure, ToolSuccess},
    server::validate_path_id,
    tools::triage::{AlertData, CaseData, project_alert, project_case},
};
use elasticctl_api::compose::{
    alert_context::{AlertContext, AlertFinding, RelatedCases, alert_context},
    validate_since,
};
use serde::Deserialize;

const DESCRIPTION: &str = "Triage context for one Elastic Security alert: the alert, the rule that fired it with its last execution, the rule's exception lists, cases that contain the alert, and the rule's alert volume in a time window. Read-only.";

fn default_since() -> String {
    "24h".into()
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AlertContextInput {
    /// Exact alert document id. Must contain non-whitespace text, be no more than 1,024 UTF-8 bytes, and not be exactly `.` or `..`; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    alert_id: String,
    /// Window for the rule's alert counts: one to four ASCII digits not starting with 0, followed by s, m, h, d, or w, such as 24h.
    #[serde(default = "default_since")]
    #[schemars(default = "default_since", length(min = 2, max = 5))]
    since: String,
}

/// One case that contains the alert; `case` is present only when `status` is `ok`.
#[derive(Debug, Serialize, JsonSchema)]
struct RelatedCaseData {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ToolError>,
    #[serde(rename = "case", skip_serializing_if = "Option::is_none")]
    detail: Option<CaseData>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct RelatedCasesData {
    total: usize,
    truncated: bool,
    cases: Vec<RelatedCaseData>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum FindingCode {
    AlertNotOpen,
    RuleMissing,
    RuleDisabled,
    RuleLastExecutionFailed,
    ExceptionListMissing,
    HasRelatedCase,
}

impl From<AlertFinding> for FindingCode {
    fn from(finding: AlertFinding) -> Self {
        match finding {
            AlertFinding::AlertNotOpen => Self::AlertNotOpen,
            AlertFinding::RuleMissing => Self::RuleMissing,
            AlertFinding::RuleDisabled => Self::RuleDisabled,
            AlertFinding::RuleLastExecutionFailed => Self::RuleLastExecutionFailed,
            AlertFinding::ExceptionListMissing => Self::ExceptionListMissing,
            AlertFinding::HasRelatedCase => Self::HasRelatedCase,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
struct AlertContextData {
    alert: AlertData,
    rule: PartData<RuleContextData>,
    exceptions: PartData<ExceptionCoverageData>,
    cases: PartData<RelatedCasesData>,
    activity: PartData<ActivityData>,
    partial: bool,
    findings: Vec<FindingCode>,
}

// Schema-only alternatives are never instantiated, so their sizes do not matter.
#[allow(dead_code, clippy::large_enum_variant)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum AlertContextOutput {
    Success(ToolSuccess<AlertContextData>),
    Failure(ToolFailure),
}

pub(super) fn definition() -> Tool {
    let tool = Tool::new("alert_context", DESCRIPTION, JsonObject::new())
        .with_input_schema::<AlertContextInput>()
        .with_output_schema::<AlertContextOutput>()
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
        .expect("typed schema")
        .as_ref()
        .clone();
    schema.insert("type".into(), serde_json::Value::String("object".into()));
    tool.with_raw_output_schema(std::sync::Arc::new(schema))
}

fn project_cases(cases: RelatedCases) -> RelatedCasesData {
    let rows = cases
        .cases
        .into_iter()
        .map(|row| {
            let (status, error, detail) = match row.detail {
                Ok(case) => ("ok", None, Some(project_case(&case))),
                Err(e) => ("unavailable", Some(tool_error(&e)), None),
            };
            RelatedCaseData {
                id: row.id,
                title: row.title,
                status,
                error,
                detail,
            }
        })
        .collect();
    RelatedCasesData {
        total: cases.total,
        truncated: cases.truncated,
        cases: rows,
    }
}

fn project(context: AlertContext) -> Result<AlertContextData, Error> {
    let findings = context.findings().into_iter().map(Into::into).collect();
    let partial = context.partial();
    let AlertContext {
        alert,
        rule,
        exceptions,
        cases,
        activity,
    } = context;
    Ok(AlertContextData {
        alert: project_alert(&alert)?,
        rule: part(rule, project_snapshot)?,
        exceptions: part(exceptions, |c| Ok(project_exceptions(c)))?,
        cases: part(cases, |c| Ok(project_cases(c)))?,
        activity: part(activity, |a| project_activity(a, false))?,
        partial,
        findings,
    })
}

pub(super) async fn call(
    arguments: Option<&JsonObject>,
    state: &ServerState,
    _cancellation: CancellationToken,
) -> Result<AdapterResult, AdapterError> {
    let input: AlertContextInput = serde_json::from_value(serde_json::Value::Object(
        arguments.cloned().unwrap_or_default(),
    ))
    .map_err(|_| AdapterError::InvalidArgument)?;
    validate_path_id("alert_id", &input.alert_id).map_err(|_| AdapterError::InvalidArgument)?;
    validate_since(&input.since).map_err(|_| AdapterError::InvalidArgument)?;
    let transport = state.transport().await.map_err(AdapterError::Core)?;
    let context = alert_context(transport, &input.alert_id, &input.since)
        .await
        .map_err(AdapterError::Core)?;
    let data = project(context).map_err(AdapterError::Core)?;
    let data = serde_json::to_value(data).map_err(|_| {
        AdapterError::Core(Error::new(
            ErrorKind::Http,
            "the selected deployment returned an invalid alert context",
        ))
    })?;
    Ok(AdapterResult {
        data,
        page: None,
        row_key: None,
    })
}
