//! Shared projections for bounded composition reports.
#![allow(dead_code)]
use crate::{
    ServerState, ToolError,
    catalog::ToolId,
    tools::{AdapterError, AdapterResult, ToolAdapter},
};
use elasticctl_api::compose::{Part, SkipReason};
use elasticctl_core::{Error, ErrorKind};
use rmcp::{
    model::{JsonObject, Tool, ToolAnnotations},
    schemars::{self, JsonSchema},
};
use serde::Serialize;
use std::{future::Future, pin::Pin};
use tokio_util::sync::CancellationToken;
mod alert_context;
mod coverage;
mod readiness;
mod rule_health;
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct PartData<T> {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ToolError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<&'static str>,
}
pub(crate) fn tool_error(e: &Error) -> ToolError {
    crate::error::core(e)
}
pub(crate) fn part<T, U>(
    p: Part<T>,
    project: impl FnOnce(T) -> Result<U, Error>,
) -> Result<PartData<U>, Error> {
    Ok(match p {
        Part::Ok(v) => PartData {
            status: "ok",
            value: Some(project(v)?),
            error: None,
            skip_reason: None,
        },
        Part::Unavailable(e) => PartData {
            status: "unavailable",
            value: None,
            error: Some(tool_error(&e)),
            skip_reason: None,
        },
        Part::Skipped(r) => PartData {
            status: "skipped",
            value: None,
            error: None,
            skip_reason: Some(match r {
                SkipReason::NotApplicable => "not_applicable",
                SkipReason::DependencyUnavailable => "dependency_unavailable",
                SkipReason::NotConfigured => "not_configured",
            }),
        },
    })
}
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ExecutionMetricsData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_search_duration_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_indexing_duration_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_enrichment_duration_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_gap_duration_s: Option<f64>,
}
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct LastExecutionData {
    pub status: String,
    pub date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_order: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub message_truncated: bool,
    pub metrics: ExecutionMetricsData,
}
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct RuleContextData {
    #[serde(flatten)]
    pub rule: super::rules::RuleGetData,
    #[schemars(required)]
    pub execution: Option<LastExecutionData>,
}
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ListCoverageData {
    pub list_id: String,
    pub namespace_type: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub ref_type: Option<String>,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ToolError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_count: Option<u64>,
}
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ExceptionCoverageData {
    pub referenced: usize,
    pub truncated: bool,
    pub lists: Vec<ListCoverageData>,
}
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct StatusCountsData {
    pub open: u64,
    pub acknowledged: u64,
    pub closed: u64,
    pub other: u64,
}
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ActivityData {
    pub window: String,
    pub total: u64,
    pub by_status: StatusCountsData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent: Option<Vec<super::triage::AlertData>>,
}
struct ComposeAdapter;
static ADAPTER: ComposeAdapter = ComposeAdapter;
pub(crate) fn adapter() -> &'static dyn ToolAdapter {
    &ADAPTER
}
pub(crate) fn definitions() -> Vec<Tool> {
    vec![
        alert_context::definition(),
        coverage::definition(),
        rule_health::definition(),
        readiness::definition(),
    ]
}
impl ToolAdapter for ComposeAdapter {
    fn definitions(&self) -> Vec<Tool> {
        definitions()
    }
    fn call<'a>(
        &'a self,
        tool: ToolId,
        arguments: Option<&'a JsonObject>,
        state: &'a ServerState,
        cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<AdapterResult, AdapterError>> + Send + 'a>> {
        Box::pin(async move {
            match tool {
                ToolId::AlertContext => alert_context::call(arguments, state, cancellation).await,
                ToolId::DetectionCoverage => coverage::call(arguments, state, cancellation).await,
                ToolId::RuleHealth => rule_health::call(arguments, state, cancellation).await,
                ToolId::RuleReadiness => readiness::call(arguments, state, cancellation).await,
                _ => Err(AdapterError::InvalidArgument),
            }
        })
    }
}

pub(crate) fn project_snapshot(
    snapshot: elasticctl_api::compose::RuleSnapshot,
) -> Result<RuleContextData, Error> {
    use elasticctl_api::compose::LastExecution;
    let rule = super::rules::project_detail(&snapshot.rule)?;
    let execution = snapshot.execution.map(
        |LastExecution {
             status,
             date,
             status_order,
             message,
             message_truncated,
             metrics,
         }| LastExecutionData {
            status,
            date,
            status_order,
            message,
            message_truncated,
            metrics: ExecutionMetricsData {
                total_search_duration_ms: metrics.total_search_duration_ms,
                total_indexing_duration_ms: metrics.total_indexing_duration_ms,
                total_enrichment_duration_ms: metrics.total_enrichment_duration_ms,
                execution_gap_duration_s: metrics.execution_gap_duration_s,
            },
        },
    );
    Ok(RuleContextData { rule, execution })
}
pub(crate) fn project_exceptions(
    coverage: elasticctl_api::compose::ExceptionCoverage,
) -> ExceptionCoverageData {
    let lists = coverage
        .lists
        .into_iter()
        .map(|row| {
            let mut data = ListCoverageData {
                list_id: row.key.list_id,
                namespace_type: row.key.namespace_type,
                ref_type: (!row.ref_type.is_empty()).then_some(row.ref_type),
                status: "ok",
                error: None,
                name: None,
                list_type: None,
                item_count: None,
            };
            match row.facts {
                Ok(facts) => {
                    data.name = facts.name;
                    data.list_type = facts.list_type;
                    data.item_count = Some(facts.item_count);
                }
                Err(error) => {
                    data.status = "unavailable";
                    data.error = Some(tool_error(&error));
                }
            }
            data
        })
        .collect();
    ExceptionCoverageData {
        referenced: coverage.referenced,
        truncated: coverage.truncated,
        lists,
    }
}
pub(crate) fn project_activity(
    activity: elasticctl_api::compose::AlertActivity,
    include_recent: bool,
) -> Result<ActivityData, Error> {
    let recent = if include_recent {
        Some(
            activity
                .recent
                .iter()
                .map(super::triage::project_alert)
                .collect::<Result<Vec<_>, _>>()?,
        )
    } else {
        None
    };
    Ok(ActivityData {
        window: activity.window,
        total: activity.total,
        by_status: StatusCountsData {
            open: activity.open,
            acknowledged: activity.acknowledged,
            closed: activity.closed,
            other: activity.other,
        },
        recent,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parts_omit_inapplicable_fields_and_map_errors() {
        let ok = part(Part::Ok(7), Ok).unwrap();
        assert_eq!(
            serde_json::to_value(ok).unwrap(),
            serde_json::json!({"status":"ok","value":7})
        );
        for (reason, text) in [
            (SkipReason::NotApplicable, "not_applicable"),
            (SkipReason::DependencyUnavailable, "dependency_unavailable"),
            (SkipReason::NotConfigured, "not_configured"),
        ] {
            let skipped = part::<(), ()>(Part::Skipped(reason), Ok).unwrap();
            assert_eq!(
                serde_json::to_value(skipped).unwrap(),
                serde_json::json!({"status":"skipped","skip_reason":text})
            );
        }
        let error = Error::with_status(ErrorKind::Permission, 403, "secret");
        let unavailable = part::<(), ()>(Part::Unavailable(error), Ok).unwrap();
        let value = serde_json::to_value(unavailable).unwrap();
        assert_eq!(value["error"]["code"], "elastic_permission");
        assert!(!value.to_string().contains("secret"));
        assert!(value.get("value").is_none());
        assert!(
            part(Part::Ok(()), |_| Err::<(), _>(Error::new(
                ErrorKind::Http,
                "bad projection"
            )))
            .is_err()
        );
    }
}
