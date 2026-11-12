//! Case mutation planners.
use crate::{
    ServerState,
    catalog::ToolId,
    tools::{AdapterError, AdapterResult, CallContext, ToolAdapter},
};
use rmcp::model::{JsonObject, Tool};
use serde_json::json;
use std::{future::Future, pin::Pin};
use tokio_util::sync::CancellationToken;
struct Adapter;
static ADAPTER: Adapter = Adapter;
pub(crate) fn adapter() -> &'static dyn ToolAdapter {
    &ADAPTER
}
impl ToolAdapter for Adapter {
    fn definitions(&self) -> Vec<Tool> {
        vec![
            super::definition(
                "cases_comment_plan",
                "Plan one comment on a case. This changes nothing. A plan lasts 15 minutes, lives in this server process only, and is applied with plan_apply after a person confirms in the client.",
                json!({"type": "object", "properties": {"id": {"type": "string", "minLength": 1, "maxLength": 1024}, "message": {"type": "string", "minLength": 1, "maxLength": 4096}}, "required": ["id", "message"], "additionalProperties": false}),
            ),
            super::definition(
                "cases_create_plan",
                "Plan one new case. This changes nothing. A plan lasts 15 minutes, lives in this server process only, and is applied with plan_apply after a person confirms in the client.",
                json!({"type": "object", "properties": {"title": {"type": "string", "minLength": 1, "maxLength": 160}, "description": {"type": "string", "minLength": 1, "maxLength": 4096}, "tags": {"type": "array", "minItems": 0, "maxItems": 10, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 256}}, "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]}}, "required": ["title"], "additionalProperties": false}),
            ),
            super::definition(
                "cases_set_status_plan",
                "Plan closing or reopening cases. This changes nothing. A plan lasts 15 minutes, lives in this server process only, and is applied with plan_apply after a person confirms in the client.",
                json!({"type": "object", "properties": {"ids": {"type": "array", "minItems": 1, "maxItems": 20, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 1024}}, "status": {"type": "string", "enum": ["open", "closed"]}}, "required": ["ids", "status"], "additionalProperties": false}),
            ),
        ]
    }
    fn call<'a>(
        &'a self,
        tool: ToolId,
        arguments: Option<&'a JsonObject>,
        state: &'a ServerState,
        cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<AdapterResult, AdapterError>> + Send + 'a>> {
        self.call_with_context(tool, arguments, state, cancellation, CallContext::default())
    }
    fn call_with_context<'a>(
        &'a self,
        tool: ToolId,
        arguments: Option<&'a JsonObject>,
        state: &'a ServerState,
        _cancellation: CancellationToken,
        context: CallContext,
    ) -> Pin<Box<dyn Future<Output = Result<AdapterResult, AdapterError>> + Send + 'a>> {
        Box::pin(async move { create(tool, arguments, state, context).await })
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CommentInput {
    id: String,
    message: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateInput {
    title: String,
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    severity: Option<String>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusInput {
    ids: Vec<String>,
    status: String,
}

fn text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max
}
fn written(value: &str, max: usize) -> bool {
    text(value, max) && crate::plan::consent::displays_exactly(value)
}
fn unique(values: &[String], min: usize, max: usize, cap: usize, exact: bool) -> bool {
    let mut seen = std::collections::HashSet::new();
    (min..=max).contains(&values.len())
        && values
            .iter()
            .all(|v| (if exact { written(v, cap) } else { text(v, cap) }) && seen.insert(v))
}
enum Input {
    Create(CreateInput),
    Comment(CommentInput),
    Status(StatusInput, elasticctl_api::cases::CaseStatus),
}
fn input(tool: ToolId, arguments: Option<&JsonObject>) -> Result<Input, AdapterError> {
    let value = serde_json::Value::Object(arguments.cloned().unwrap_or_default());
    let invalid = || AdapterError::InvalidArgument;
    match tool {
        ToolId::CasesCreatePlan => {
            let v: CreateInput = serde_json::from_value(value).map_err(|_| invalid())?;
            if !written(&v.title, 160)
                || v.title.contains('\n')
                || v.description.as_ref().is_some_and(|d| !written(d, 4096))
                || !unique(&v.tags, 0, 10, 256, true)
                || v.severity
                    .as_ref()
                    .is_some_and(|s| !matches!(s.as_str(), "low" | "medium" | "high" | "critical"))
            {
                return Err(invalid());
            }
            Ok(Input::Create(v))
        }
        ToolId::CasesCommentPlan => {
            let v: CommentInput = serde_json::from_value(value).map_err(|_| invalid())?;
            if !text(&v.id, 1024) || !written(&v.message, 4096) {
                return Err(invalid());
            }
            Ok(Input::Comment(v))
        }
        ToolId::CasesSetStatusPlan => {
            let v: StatusInput = serde_json::from_value(value).map_err(|_| invalid())?;
            let status = match v.status.as_str() {
                "open" => elasticctl_api::cases::CaseStatus::Open,
                "closed" => elasticctl_api::cases::CaseStatus::Closed,
                _ => return Err(invalid()),
            };
            if !unique(&v.ids, 1, 20, 1024, false) {
                return Err(invalid());
            }
            Ok(Input::Status(v, status))
        }
        _ => Err(invalid()),
    }
}
async fn create(
    tool: ToolId,
    arguments: Option<&JsonObject>,
    state: &ServerState,
    context: CallContext,
) -> Result<AdapterResult, AdapterError> {
    use super::{drain_closed, local_error, output};
    use crate::plan::{
        PlanError, audit, hash,
        kind::{Operation, PlanKind, require_sync_alerts_off},
        store::{Plan, PlanContent},
        view,
    };
    use elasticctl_api::{cases_ops, health, observe::Preconditions};
    let input = input(tool, arguments)?;
    let t = state.transport().await.map_err(AdapterError::Core)?;
    let identity = health::credential_identity(t)
        .await
        .map_err(AdapterError::Core)?;
    let kind = match &input {
        Input::Create(_) => PlanKind::CasesCreate,
        Input::Comment(_) => PlanKind::CasesComment,
        Input::Status(..) => PlanKind::CasesSetStatus,
    };
    if !kind.credential_suitable(&identity) {
        return Err(local_error(PlanError::CredentialUnsuitable.tool_error()));
    }
    let (operation, seen, action, targets) = match input {
        Input::Create(v) => {
            let plan = cases_ops::plan_create(t, &v.title, v.description, v.tags, v.severity, &[])
                .await
                .map_err(AdapterError::Core)?;
            let action = plan.preview_action.clone();
            (
                Operation::CasesCreate { plan },
                Preconditions::default(),
                action,
                vec![],
            )
        }
        Input::Comment(v) => {
            let (plan, seen) = cases_ops::plan_comment_observed(t, &v.id, &v.message)
                .await
                .map_err(AdapterError::Core)?;
            let action = plan.preview_action.clone();
            let targets = vec![plan.case_id.clone()];
            (Operation::CasesComment { plan }, seen, action, targets)
        }
        Input::Status(v, target) => {
            let (plan, seen) = cases_ops::plan_status_observed(t, &v.ids, target)
                .await
                .map_err(AdapterError::Core)?;
            require_sync_alerts_off(&seen).map_err(local_error)?;
            let action = plan.preview_action.clone();
            let targets = seen.0.iter().map(|v| v.id.clone()).collect();
            (
                Operation::CasesSetStatus { plan, ids: v.ids },
                seen,
                action,
                targets,
            )
        }
    };
    let credential = hash::credential_hash(&identity);
    let content = PlanContent {
        kind: kind.name(),
        class: kind.class(),
        target: state.target().clone(),
        binding: state.plan_binding(),
        note: kind.consent_note(&credential),
        credential,
        operation: operation.json(),
        preconditions: seen
            .0
            .iter()
            .map(|v| serde_json::to_value(v).expect("observed state serializes"))
            .collect(),
        action,
        details: operation.details(),
        targets,
        cli_equivalent: operation.cli_arguments(),
        payload: operation,
    };
    let now = tokio::time::Instant::now();
    let plan = Plan::with_life(content, now, state.plan_life).map_err(local_error)?;
    let mut store = state.plans.lock().expect("plan store lock");
    let result = store.insert(plan.clone(), now);
    drain_closed(&state.audit, &mut store, context.protocol.as_str());
    result.map_err(local_error)?;
    state.audit.emit(&audit::line(
        audit::unix_seconds(),
        &plan,
        context.protocol.as_str(),
        audit::Event::PlanCreated,
    ));
    Ok(output(view::view(
        &plan,
        context.form_elicitation,
        false,
        now,
    )))
}
