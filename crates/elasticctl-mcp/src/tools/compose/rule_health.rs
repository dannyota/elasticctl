//! The `rule_health` task tool: validate, call, and project one rule's health.
use super::*;
use crate::server::validate_text;
use elasticctl_api::compose::{
    rule_health::{HealthFinding, RuleHealth, rule_health},
    validate_since,
};

const DESCRIPTION: &str = "Health of one Elastic Security rule: its definition, last execution status and message, alert counts by workflow status with the five newest alerts in a time window, and its exception lists with item counts. Read-only.";
const MAX_SELECTOR_BYTES: usize = 1_024;

fn default_since() -> String {
    "24h".to_string()
}

/// Inputs for one rule's health report.
#[derive(Debug, serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RuleHealthInput {
    /// Exact rule_id or display name. Must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    selector: String,
    /// Alert window ending now: one to four ASCII digits not starting with 0, followed by s, m, h, d, or w, such as 24h. Timestamps and date math are rejected.
    #[serde(default = "default_since")]
    #[schemars(default = "default_since", length(min = 2, max = 5))]
    since: String,
}

/// Static finding codes, in the order the report lists them.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum FindingCode {
    RuleDisabled,
    NeverExecuted,
    LastExecutionFailed,
    LastExecutionPartialFailure,
    ExecutionGap,
    NoAlertsInWindow,
    ExceptionListMissing,
}

impl From<HealthFinding> for FindingCode {
    fn from(finding: HealthFinding) -> Self {
        match finding {
            HealthFinding::RuleDisabled => Self::RuleDisabled,
            HealthFinding::NeverExecuted => Self::NeverExecuted,
            HealthFinding::LastExecutionFailed => Self::LastExecutionFailed,
            HealthFinding::LastExecutionPartialFailure => Self::LastExecutionPartialFailure,
            HealthFinding::ExecutionGap => Self::ExecutionGap,
            HealthFinding::NoAlertsInWindow => Self::NoAlertsInWindow,
            HealthFinding::ExceptionListMissing => Self::ExceptionListMissing,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
struct RuleHealthData {
    rule: RuleContextData,
    alerts: PartData<ActivityData>,
    exceptions: PartData<ExceptionCoverageData>,
    partial: bool,
    findings: Vec<FindingCode>,
}

#[allow(dead_code, clippy::large_enum_variant)] // Schema-only alternatives are never instantiated.
#[derive(JsonSchema)]
#[serde(untagged)]
enum RuleHealthOutput {
    Success(crate::result::ToolSuccess<RuleHealthData>),
    Failure(crate::result::ToolFailure),
}

pub(super) fn definition() -> Tool {
    let tool = Tool::new("rule_health", DESCRIPTION, JsonObject::new())
        .with_input_schema::<RuleHealthInput>()
        .with_output_schema::<RuleHealthOutput>()
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

pub(super) async fn call(
    arguments: Option<&JsonObject>,
    state: &ServerState,
    _cancellation: CancellationToken,
) -> Result<AdapterResult, AdapterError> {
    let input: RuleHealthInput = serde_json::from_value(serde_json::Value::Object(
        arguments.cloned().unwrap_or_default(),
    ))
    .map_err(|_| AdapterError::InvalidArgument)?;
    validate_text("selector", &input.selector, MAX_SELECTOR_BYTES)
        .map_err(|_| AdapterError::InvalidArgument)?;
    validate_since(&input.since).map_err(|_| AdapterError::InvalidArgument)?;
    let transport = state.transport().await.map_err(AdapterError::Core)?;
    let report = rule_health(transport, &input.selector, &input.since)
        .await
        .map_err(AdapterError::Core)?;
    let data = project(report).map_err(AdapterError::Core)?;
    serde_json::to_value(data)
        .map(|data| AdapterResult {
            data,
            page: None,
            row_key: None,
        })
        .map_err(|_| {
            AdapterError::Core(Error::new(
                ErrorKind::Http,
                "the selected deployment returned an invalid rule health projection",
            ))
        })
}

fn project(report: RuleHealth) -> Result<RuleHealthData, Error> {
    let findings = report.findings().into_iter().map(Into::into).collect();
    let partial = report.partial();
    let RuleHealth {
        rule,
        alerts,
        exceptions,
    } = report;
    Ok(RuleHealthData {
        rule: project_snapshot(rule)?,
        alerts: part(alerts, |activity| project_activity(activity, true))?,
        exceptions: part(exceptions, |coverage| Ok(project_exceptions(coverage)))?,
        partial,
        findings,
    })
}
