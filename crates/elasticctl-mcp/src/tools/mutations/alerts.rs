//! Static mutation planner definitions.
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
                "alerts_set_status_plan",
                "Plan a status change for alerts by id. This changes nothing. A plan lasts 15 minutes, lives in this server process only, and is applied with plan_apply after a person confirms in the client.",
                json!({"type": "object", "properties": {"alert_ids": {"type": "array", "minItems": 1, "maxItems": 20, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 1024}}, "status": {"type": "string", "enum": ["open", "acknowledged", "closed"]}, "reason": {"type": "string", "enum": ["false_positive", "duplicate", "true_positive", "benign_positive", "automated_closure", "other"]}}, "required": ["alert_ids", "status"], "additionalProperties": false}),
            ),
            super::definition(
                "alerts_set_tags_plan",
                "Plan adding and removing alert tags by id. This changes nothing. A plan lasts 15 minutes, lives in this server process only, and is applied with plan_apply after a person confirms in the client.",
                json!({"type": "object", "properties": {"alert_ids": {"type": "array", "minItems": 1, "maxItems": 20, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 1024}}, "add": {"type": "array", "minItems": 0, "maxItems": 10, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 256}}, "remove": {"type": "array", "minItems": 0, "maxItems": 10, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 256}}}, "required": ["alert_ids"], "additionalProperties": false}),
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
struct StatusInput {
    alert_ids: Vec<String>,
    status: String,
    reason: Option<String>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TagsInput {
    alert_ids: Vec<String>,
    #[serde(default)]
    add: Vec<String>,
    #[serde(default)]
    remove: Vec<String>,
}

fn valid_items(items: &[String], max_count: usize, max_len: usize) -> bool {
    let mut unique = std::collections::HashSet::new();
    items.len() <= max_count
        && items
            .iter()
            .all(|s| !s.trim().is_empty() && s.len() <= max_len && unique.insert(s))
}

async fn create(
    tool: ToolId,
    arguments: Option<&JsonObject>,
    state: &ServerState,
    context: CallContext,
) -> Result<AdapterResult, AdapterError> {
    use super::{drain_closed, local_error, output};
    use crate::plan::{
        PlanError, audit, consent, hash,
        kind::{Operation, PlanKind},
        store::{Plan, PlanContent},
        view,
    };
    use elasticctl_api::{alerts::AlertStatus, alerts_ops, health};
    let value = serde_json::Value::Object(arguments.cloned().unwrap_or_default());
    enum Input {
        Status(StatusInput, AlertStatus),
        Tags(TagsInput),
    }
    let input = match tool {
        ToolId::AlertsSetStatusPlan => {
            let input: StatusInput =
                serde_json::from_value(value).map_err(|_| AdapterError::InvalidArgument)?;
            let status =
                AlertStatus::parse(&input.status).map_err(|_| AdapterError::InvalidArgument)?;
            if input.alert_ids.is_empty()
                || !valid_items(&input.alert_ids, 20, 1024)
                || input.reason.as_ref().is_some_and(|r| {
                    status != AlertStatus::Closed
                        || ![
                            "false_positive",
                            "duplicate",
                            "true_positive",
                            "benign_positive",
                            "automated_closure",
                            "other",
                        ]
                        .contains(&r.as_str())
                })
            {
                return Err(AdapterError::InvalidArgument);
            }
            Input::Status(input, status)
        }
        ToolId::AlertsSetTagsPlan => {
            let input: TagsInput =
                serde_json::from_value(value).map_err(|_| AdapterError::InvalidArgument)?;
            if input.alert_ids.is_empty()
                || !valid_items(&input.alert_ids, 20, 1024)
                || (input.add.is_empty() && input.remove.is_empty())
                || !valid_items(&input.add, 10, 256)
                || !valid_items(&input.remove, 10, 256)
                || input.add.iter().any(|t| input.remove.contains(t))
                || input
                    .add
                    .iter()
                    .chain(&input.remove)
                    .any(|t| !consent::displays_exactly(t))
            {
                return Err(AdapterError::InvalidArgument);
            }
            Input::Tags(input)
        }
        _ => return Err(AdapterError::InvalidArgument),
    };
    let t = state.transport().await.map_err(AdapterError::Core)?;
    let identity = health::credential_identity(t)
        .await
        .map_err(AdapterError::Core)?;
    let kind = match &input {
        Input::Status(..) => PlanKind::AlertsSetStatus,
        Input::Tags(..) => PlanKind::AlertsSetTags,
    };
    if !kind.credential_suitable(&identity) {
        return Err(local_error(PlanError::CredentialUnsuitable.tool_error()));
    }
    let (operation, seen, action, targets) = match input {
        Input::Status(input, status) => {
            let (plan, seen) =
                alerts_ops::plan_status_by_ids_observed(t, &input.alert_ids, status, input.reason)
                    .await
                    .map_err(AdapterError::Core)?;
            let action = plan.preview_action.clone();
            let targets = plan.targets.clone();
            (Operation::AlertsSetStatus { plan }, seen, action, targets)
        }
        Input::Tags(input) => {
            let (plan, seen) =
                alerts_ops::plan_tags_observed(t, &input.alert_ids, input.add, input.remove)
                    .await
                    .map_err(AdapterError::Core)?;
            let action = plan.preview_action.clone();
            let targets = plan.targets.clone();
            (Operation::AlertsSetTags { plan }, seen, action, targets)
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
        cli_equivalent: Some(operation.cli_equivalent()),
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
