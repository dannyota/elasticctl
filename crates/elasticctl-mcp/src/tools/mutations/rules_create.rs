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
        vec![super::definition(
            "rules_create_plan",
            "Plan one new rule, created disabled. This changes nothing. A plan lasts 15 minutes, lives in this server process only, and is applied with plan_apply after a person confirms in the client.",
            json!({"type": "object", "properties": {"rule": {"type": "object"}}, "required": ["rule"], "additionalProperties": false}),
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
    rule: serde_json::Value,
}

fn validate(rule: &serde_json::Value) -> Result<(), AdapterError> {
    let invalid = || AdapterError::InvalidArgument;
    let map = rule.as_object().ok_or_else(invalid)?;
    let rendered = serde_json::to_string(rule).map_err(|_| invalid())?;
    if rendered.len() > 65_536
        || !crate::plan::consent::displays_exactly(&rendered)
        || ["rule_id", "name", "type"].iter().any(|key| {
            !map.get(*key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|v| !v.trim().is_empty())
        })
        || elasticctl_api::model::VOLATILE_FIELDS
            .iter()
            .any(|key| map.contains_key(*key))
        || map.get("enabled").is_some_and(|v| v != &json!(false))
        || ["exceptions_list", "actions", "response_actions"]
            .iter()
            .any(|key| {
                map.get(*key)
                    .is_some_and(|v| !v.as_array().is_some_and(Vec::is_empty))
            })
    {
        return Err(invalid());
    }
    Ok(())
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
    use elasticctl_api::{health, model::Rule, rules_ops};
    let input: Input = serde_json::from_value(serde_json::Value::Object(
        arguments.cloned().unwrap_or_default(),
    ))
    .map_err(|_| AdapterError::InvalidArgument)?;
    validate(&input.rule)?;
    let rule = Rule::from_value(input.rule).map_err(|_| AdapterError::InvalidArgument)?;
    let t = state.transport().await.map_err(AdapterError::Core)?;
    let identity = health::credential_identity(t)
        .await
        .map_err(AdapterError::Core)?;
    let kind = PlanKind::RulesCreate;
    if !kind.credential_suitable(&identity) {
        return Err(local_error(PlanError::CredentialUnsuitable.tool_error()));
    }
    let (plan, seen) = rules_ops::plan_create(t, rule)
        .await
        .map_err(AdapterError::Core)?;
    let action = plan.preview.preview_action.clone();
    let targets = plan.preview.targets.clone();
    let operation = Operation::RulesCreate { plan };
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
