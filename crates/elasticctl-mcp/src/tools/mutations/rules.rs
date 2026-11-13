use crate::{
    ServerState,
    catalog::ToolId,
    tools::{AdapterError, AdapterResult, CallContext, ToolAdapter, plans},
};
use rmcp::model::{JsonObject, Tool};
use serde_json::json;
use std::{future::Future, pin::Pin};
use tokio_util::sync::CancellationToken;

struct RulesAdapter;
static ADAPTER: RulesAdapter = RulesAdapter;
pub(crate) fn adapter() -> &'static dyn ToolAdapter {
    &ADAPTER
}

impl ToolAdapter for RulesAdapter {
    fn definitions(&self) -> Vec<Tool> {
        vec![plans::definition(
            "rules_set_enabled_plan",
            "Plan enabling or disabling rules. This changes nothing. A plan lasts 15 minutes, lives in this server process only, and is applied with plan_apply after a person confirms in the client.",
            json!({
                "type":"object", "properties":{
                    "selectors":{"type":"array","minItems":1,"maxItems":20,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":1024}},
                    "enabled":{"type":"boolean"}
                },"required":["selectors","enabled"],"additionalProperties":false
            }),
            false,
        )]
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
        _tool: ToolId,
        arguments: Option<&'a JsonObject>,
        state: &'a ServerState,
        _cancellation: CancellationToken,
        context: CallContext,
    ) -> Pin<Box<dyn Future<Output = Result<AdapterResult, AdapterError>> + Send + 'a>> {
        Box::pin(async move { create(arguments, state, context).await })
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    selectors: Vec<String>,
    enabled: bool,
}

async fn create(
    arguments: Option<&JsonObject>,
    state: &ServerState,
    context: CallContext,
) -> Result<AdapterResult, AdapterError> {
    use super::{drain_closed, local_error, output};
    use crate::plan::{
        PlanError, audit, hash,
        kind::{Operation, PlanKind},
        store::{Plan, PlanContent},
        view,
    };
    use elasticctl_api::{health, observe, rules_ops};
    let input: Input = serde_json::from_value(serde_json::Value::Object(
        arguments.cloned().unwrap_or_default(),
    ))
    .map_err(|_| AdapterError::InvalidArgument)?;
    let mut unique = std::collections::HashSet::new();
    if input.selectors.is_empty()
        || input.selectors.len() > 20
        || input
            .selectors
            .iter()
            .any(|s| s.trim().is_empty() || s.len() > 1024 || !unique.insert(s))
    {
        return Err(AdapterError::InvalidArgument);
    }
    let t = state.transport().await.map_err(AdapterError::Core)?;
    let identity = health::credential_identity(t)
        .await
        .map_err(AdapterError::Core)?;
    let kind = PlanKind::RulesSetEnabled;
    if !kind.credential_suitable(&identity) {
        return Err(local_error(PlanError::CredentialUnsuitable.tool_error()));
    }
    let (plan, seen) = rules_ops::plan_set_enabled_observed(t, &input.selectors, input.enabled)
        .await
        .map_err(AdapterError::Core)?;
    observe::require_rule_identity(&seen).map_err(AdapterError::Core)?;
    let mut unique = std::collections::HashSet::new();
    if plan.targets.iter().any(|id| !unique.insert(id)) {
        return Err(AdapterError::InvalidArgument);
    }
    let credential = hash::credential_hash(&identity);
    let operation = Operation::RulesSetEnabled {
        plan: plan.clone(),
        enable: input.enabled,
    };
    let content = PlanContent {
        kind: kind.name(),
        class: kind.class(),
        target: state.target().clone(),
        binding: state.plan_binding(),
        note: Some(kind.note(&credential)),
        credential,
        operation: operation.json(),
        preconditions: seen
            .0
            .iter()
            .map(|v| serde_json::to_value(v).expect("observed state serializes"))
            .collect(),
        action: plan.preview_action,
        details: plan.preview_details,
        targets: plan.targets,
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
