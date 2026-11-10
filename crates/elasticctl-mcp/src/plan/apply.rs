//! Confirmed writes, detached from the lifetime of a tool request.
use super::{
    PlanError,
    audit::{self, Answer, Event},
    confirm, hash,
    kind::Operation,
    store::{Outcome, Plan, PlanState, PlanStore},
    view,
};
use crate::{
    ServerState, ToolError,
    error::{self, LocalError},
    result,
    server::admission,
    tools::{CallContext, CallProtocol},
};
use elasticctl_api::{health, observe};
use rmcp::{
    RoleServer,
    model::{
        CallToolRequestParams, CallToolResponse, ElicitRequest, InputRequest, InputRequiredResult,
    },
    service::RequestContext,
};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};
use tokio::{
    sync::{OwnedSemaphorePermit, oneshot},
    task::JoinSet,
    time::{self, Instant},
};
type Stored = Plan<Operation>;
type Store = PlanStore<Operation>;
type Result<T> = std::result::Result<T, ToolError>;
#[derive(Default)]
pub(crate) struct PendingWrites {
    pub(crate) tasks: JoinSet<()>,
    pub(crate) protocols: HashMap<String, &'static str>,
}
fn store<T>(
    s: &ServerState,
    c: &CallContext,
    f: impl FnOnce(&mut Store) -> Result<T>,
) -> Result<T> {
    let mut store = s.plans.lock().expect("plan store lock");
    let result = f(&mut store);
    for p in store.take_closed() {
        s.audit.emit(&audit::closed_line(
            audit::unix_seconds(),
            &p,
            c.protocol.as_str(),
        ));
    }
    result
}
fn event(s: &ServerState, c: &CallContext, p: &Stored, e: Event) {
    s.audit.emit(&audit::line(
        audit::unix_seconds(),
        p,
        c.protocol.as_str(),
        e,
    ));
}
fn get(s: &ServerState, c: &CallContext, id: &str) -> Result<Stored> {
    store(s, c, |st| st.get(id, Instant::now()).cloned())
}
fn close(s: &ServerState, c: &CallContext, id: &str, state: PlanState) -> Result<()> {
    store(s, c, |st| st.close(id, state, Instant::now()))?;
    event(s, c, &get(s, c, id)?, Event::PlanClosed);
    Ok(())
}
async fn check(s: &ServerState, c: &CallContext, p: &Stored) -> Result<()> {
    if s.plan_binding() != p.content.binding {
        close(s, c, &p.id, PlanState::Stale)?;
        return Err(PlanError::Stale.tool_error());
    }
    let t = s.transport().await.map_err(|e| error::core(&e))?;
    let identity = health::credential_identity(t)
        .await
        .map_err(|e| error::core(&e))?;
    if hash::credential_hash(&identity) != p.content.credential {
        close(s, c, &p.id, PlanState::Stale)?;
        return Err(PlanError::Stale.tool_error());
    }
    let seen = p
        .content
        .payload
        .observe(t)
        .await
        .map_err(|e| error::core(&e))?;
    let values: Vec<Value> = seen
        .clone()
        .sorted()
        .0
        .iter()
        .map(|v| serde_json::to_value(v).expect("observed state serializes"))
        .collect();
    if observe::require_rule_identity(&seen).is_err()
        || hash::canonical_bytes(&serde_json::json!(values))
            != hash::canonical_bytes(&serde_json::json!(p.content.preconditions))
    {
        close(s, c, &p.id, PlanState::Stale)?;
        return Err(PlanError::Stale.tool_error());
    }
    Ok(())
}
fn answer_open(state: PlanState) -> Result<()> {
    if state.replayed()? {
        return Err(PlanError::NotOpen.tool_error());
    }
    Ok(())
}
fn read_answer(s: &ServerState, c: &CallContext, id: &str, answer: Answer) -> Result<()> {
    let p = get(s, c, id)?;
    event(s, c, &p, Event::ConfirmationAnswered(answer));
    answer_open(p.state)?;
    match answer {
        Answer::Confirmed => Ok(()),
        Answer::Declined => {
            close(s, c, id, PlanState::Declined)?;
            Err(PlanError::Declined.tool_error())
        }
        Answer::Timeout => Err(PlanError::ConfirmationTimeout.tool_error()),
        Answer::Unavailable => Err(PlanError::ConfirmationUnavailable.tool_error()),
        Answer::NotConfirmed => Err(PlanError::NotConfirmed.tool_error()),
    }
}
fn failure(
    target: crate::TargetContext,
    error: ToolError,
    id: &rmcp::model::RequestId,
) -> std::result::Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
    result::failure(target.clone(), error, id)
        .or_else(|_| result::failure(target, error::local(LocalError::ResultTooLarge), id))
        .map_err(|_| rmcp::ErrorData::internal_error("MCP server error", None))
}
fn projection(
    s: &ServerState,
    c: &CallContext,
    p: &Stored,
    replayed: bool,
    id: &rmcp::model::RequestId,
) -> std::result::Result<CallToolResponse, rmcp::ErrorData> {
    result::success(
        s.target().clone(),
        view::view(p, c.form_elicitation, replayed, Instant::now()),
        None,
        id,
    )
    .map(Into::into)
    .or_else(|e| failure(s.target().clone(), error::local(e), id).map(Into::into))
}
pub(crate) async fn handle(
    s: Arc<ServerState>,
    request: CallToolRequestParams,
    context: RequestContext<RoleServer>,
    c: CallContext,
) -> std::result::Result<CallToolResponse, rmcp::ErrorData> {
    let outcome = run(s.clone(), request, &context, &c).await;
    match outcome {
        Ok(r) => Ok(r),
        Err(e) => failure(s.target().clone(), e, &context.id).map(Into::into),
    }
}
async fn bounded<T>(
    context: &RequestContext<RoleServer>,
    deadline: Instant,
    f: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! { biased;
        _=context.ct.cancelled()=>Err(PlanError::NotConfirmed.tool_error()),
        r=time::timeout_at(deadline,f)=>r.unwrap_or_else(|_|Err(error::local(LocalError::DeadlineExceeded))),
    }
}
async fn run(
    s: Arc<ServerState>,
    request: CallToolRequestParams,
    context: &RequestContext<RoleServer>,
    c: &CallContext,
) -> Result<CallToolResponse> {
    let mut permit = admission::acquire(&s).ok_or_else(|| error::local(LocalError::Busy))?;
    let deadline = Instant::now() + admission::timeout(&s);
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        plan_id: String,
    }
    let input: Input = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|_| PlanError::InvalidArgument.tool_error())?;
    crate::server::validate_text("plan_id", &input.plan_id, 1024)
        .map_err(|_| PlanError::InvalidArgument.tool_error())?;
    let id = input.plan_id;
    let p = get(&s, c, &id)?;
    if p.state.replayed()? {
        return projection(&s, c, &p, true, &context.id)
            .map_err(|_| PlanError::Randomness.tool_error());
    }
    if !c.form_elicitation {
        read_answer(&s, c, &id, Answer::Unavailable)?;
    }
    if matches!(c.protocol, CallProtocol::Current) && request.input_responses.is_some() {
        let taken = store(&s, c, |st| {
            st.take_handle(&id, request.request_state.as_deref(), Instant::now())
        });
        let answer = if taken.is_ok() {
            confirm::answer(
                request
                    .input_responses
                    .as_ref()
                    .and_then(|v| v.get("confirm")),
            )
        } else {
            Answer::NotConfirmed
        };
        read_answer(&s, c, &id, answer)?;
    } else {
        if p.prompt_count() >= super::MAX_PROMPTS_PER_PLAN {
            close(&s, c, &id, PlanState::Declined)?;
            return Err(PlanError::Declined.tool_error());
        }
        let legacy = if matches!(c.protocol, CallProtocol::Legacy) {
            Some(
                confirm::LegacyWait::take()
                    .ok_or_else(|| PlanError::ConfirmationPending.tool_error())?,
            )
        } else {
            None
        };
        bounded(context, deadline, check(&s, c, &p)).await?;
        let handle = store(&s, c, |st| {
            let before = st.get(&id, Instant::now()).cloned();
            for closed in st.take_closed() {
                s.audit.emit(&audit::closed_line(
                    audit::unix_seconds(),
                    &closed,
                    c.protocol.as_str(),
                ));
            }
            let was_open = before?.state == PlanState::Open;
            let result = st.issue_prompt(
                &id,
                matches!(c.protocol, CallProtocol::Current),
                Instant::now(),
            );
            for closed in st.take_closed() {
                s.audit.emit(&audit::closed_line(
                    audit::unix_seconds(),
                    &closed,
                    c.protocol.as_str(),
                ));
            }
            if was_open && result.as_ref().is_err_and(|e| e.code == "plan_declined") {
                let p = st.get(&id, Instant::now()).cloned();
                for closed in st.take_closed() {
                    s.audit.emit(&audit::closed_line(
                        audit::unix_seconds(),
                        &closed,
                        c.protocol.as_str(),
                    ));
                }
                event(&s, c, &p?, Event::PlanClosed);
            }
            result
        })?;
        let p = get(&s, c, &id)?;
        event(&s, c, &p, Event::ConfirmationRequested(p.prompt_count()));
        let params = confirm::form(p.consent_text(Instant::now()));
        if matches!(c.protocol, CallProtocol::Current) {
            let requests = [(
                "confirm".into(),
                InputRequest::Elicitation(ElicitRequest::new(params)),
            )]
            .into_iter()
            .collect();
            return Ok(InputRequiredResult::new(Some(requests), handle).into());
        }
        drop(permit);
        let answer = tokio::select! { biased;
            _=context.ct.cancelled()=>return Err(PlanError::NotConfirmed.tool_error()),
            r=time::timeout(s.legacy_wait,context.peer.create_elicitation_with_timeout(params,Some(s.legacy_wait)))=>match r {
                Err(_)=>Answer::Timeout,
                Ok(Ok(v))=>confirm::answer(serde_json::to_value(v).ok().as_ref()),
                Ok(Err(rmcp::service::ServiceError::Timeout{..}))=>Answer::Timeout,
                Ok(Err(_))=>Answer::NotConfirmed,
            }
        };
        drop(legacy);
        read_answer(&s, c, &id, answer)?;
        permit = tokio::select! { biased;
            _=context.ct.cancelled()=>return Err(PlanError::NotConfirmed.tool_error()),
            p=admission::reacquire(&s)=>p.ok_or_else(||error::local(LocalError::Busy))?,
        };
    }
    let deadline = if matches!(c.protocol, CallProtocol::Legacy) {
        Instant::now() + admission::timeout(&s)
    } else {
        deadline
    };
    let current = get(&s, c, &id)?;
    if current.state.replayed()? {
        return projection(&s, c, &current, true, &context.id)
            .map_err(|_| PlanError::Randomness.tool_error());
    }
    bounded(context, deadline, check(&s, c, &current)).await?;
    if context.ct.is_cancelled() {
        return Err(PlanError::NotConfirmed.tool_error());
    }
    if Instant::now() >= deadline {
        return Err(error::local(LocalError::DeadlineExceeded));
    }
    let Some(receiver) = commit(&s, c, &id, permit)? else {
        return projection(&s, c, &get(&s, c, &id)?, true, &context.id)
            .map_err(|_| PlanError::Randomness.tool_error());
    };
    tokio::select! { biased;
        _=context.ct.cancelled()=>Err(PlanError::NotConfirmed.tool_error()),
        r=time::timeout_at(deadline,receiver)=>match r {
            Ok(Ok(result))=>{result?;projection(&s,c,&get(&s,c,&id)?,false,&context.id).map_err(|_|PlanError::Randomness.tool_error())},
            _=>Err(PlanError::ApplyPending.tool_error()),
        }
    }
}
fn commit(
    s: &Arc<ServerState>,
    c: &CallContext,
    id: &str,
    permit: OwnedSemaphorePermit,
) -> Result<Option<oneshot::Receiver<Result<()>>>> {
    let mut st = s.plans.lock().expect("plan store lock");
    let existing = st.get(id, Instant::now()).cloned();
    for p in st.take_closed() {
        s.audit.emit(&audit::closed_line(
            audit::unix_seconds(),
            &p,
            c.protocol.as_str(),
        ));
    }
    if existing?.state.replayed()? {
        return Ok(None);
    }
    let r = st.begin_apply(id, Instant::now());
    for p in st.take_closed() {
        s.audit.emit(&audit::closed_line(
            audit::unix_seconds(),
            &p,
            c.protocol.as_str(),
        ));
    }
    r?;
    let p = st.get(id, Instant::now())?.clone();
    for p in st.take_closed() {
        s.audit.emit(&audit::closed_line(
            audit::unix_seconds(),
            &p,
            c.protocol.as_str(),
        ));
    }
    event(s, c, &p, Event::ApplyStarted);
    let (tx, rx) = oneshot::channel();
    let mut pending = s.pending_writes.lock().expect("pending writes lock");
    while pending.tasks.try_join_next().is_some() {}
    pending.protocols.insert(id.into(), c.protocol.as_str());
    let s = s.clone();
    let c = c.clone();
    pending.tasks.spawn(async move {
        let _permit = permit;
        let result = write(&s, &c, &p).await;
        s.pending_writes
            .lock()
            .expect("pending writes lock")
            .protocols
            .remove(&p.id);
        let _ = tx.send(result);
    });
    Ok(Some(rx))
}
async fn write(s: &ServerState, c: &CallContext, p: &Stored) -> Result<()> {
    let result = match s.mutation_transport().await {
        Ok(t) => p.content.payload.apply(t).await,
        Err(e) => Err(e),
    };
    let (state, outcome, status, error) = match result {
        Ok(r) => {
            let requested = p.content.targets.len() as u64;
            let failed = r.failed + r.skipped + requested.saturating_sub(r.total);
            (
                PlanState::Applied,
                Some(Outcome {
                    requested,
                    updated: r.succeeded,
                    unchanged: 0,
                    failed,
                    complete: r.succeeded == requested && failed == 0,
                    created: None,
                }),
                None,
                None,
            )
        }
        Err(e) => {
            let status = e.http_status;
            let failed = status.is_some_and(|s| (400..500).contains(&s));
            let error = if failed {
                error::core(&e)
            } else {
                let mut error = PlanError::ApplyOutcomeUnknown(e.kind).tool_error();
                error.http_status = status;
                error
            };
            (
                if failed {
                    PlanState::Failed
                } else {
                    PlanState::Unknown
                },
                None,
                status,
                Some(error),
            )
        }
    };
    store(s, c, |st| st.finish(&p.id, state, outcome, Instant::now()))?;
    event(s, c, &get(s, c, &p.id)?, Event::ApplyFinished(status));
    error.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_answer_cannot_start_another_check() {
        for (state, code) in [
            (PlanState::Expired, "plan_expired"),
            (PlanState::Discarded, "plan_discarded"),
            (PlanState::Declined, "plan_declined"),
            (PlanState::Stale, "plan_stale"),
        ] {
            assert_eq!(answer_open(state).unwrap_err().code, code);
        }
    }
}
