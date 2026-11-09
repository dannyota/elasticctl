//! Agent policy deletion planning and apply.

use super::{
    BTreeMap, Error, ErrorKind, LiveAgentPolicy, MutationPlan, Result, Serialize, Transport, Value,
    agent_policies, json, live_from_item, read_live, resolve_item,
};

#[derive(Debug, Clone, PartialEq)]
pub struct AgentPolicyDeleteTarget {
    pub id: String,
    pub name: String,
    pub snapshot: LiveAgentPolicy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentPolicyDeletePlan {
    pub preview: MutationPlan,
    pub targets: Vec<AgentPolicyDeleteTarget>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentPolicyDeleteReport {
    pub applied: bool,
    pub deleted: Vec<Value>,
    pub failed: Vec<Value>,
    pub total: usize,
    pub affected_agents: u64,
}

pub async fn plan_delete(
    transport: &Transport,
    selectors: &[String],
) -> Result<AgentPolicyDeletePlan> {
    if selectors.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "agent-policy delete needs at least one selector",
        ));
    }
    let mut resolved_items = BTreeMap::new();
    for selector in selectors {
        let resolved = resolve_item(transport, selector).await?;
        resolved_items.insert(resolved.summary.id, resolved.item);
    }
    let mut targets = Vec::new();
    let mut conflicts = Vec::new();
    for (id, item) in resolved_items {
        let live = live_from_item(&item, &id, transport.space())?;
        if live.agents > 0 {
            conflicts.push(format!(
                "agent policy '{id}' has {} assigned agents",
                live.agents
            ));
        }
        if !live.attached.is_empty() {
            conflicts.push(format!(
                "agent policy '{id}' has attached integrations: {}",
                live.attached.join(", ")
            ));
        }
        targets.push(AgentPolicyDeleteTarget {
            id: id.clone(),
            name: live.spec.name.clone(),
            snapshot: live,
        });
    }
    if !conflicts.is_empty() {
        return Err(Error::new(ErrorKind::Conflict, conflicts.join("; ")));
    }
    Ok(AgentPolicyDeletePlan {
        preview: delete_preview(&targets),
        targets,
    })
}

fn delete_preview(targets: &[AgentPolicyDeleteTarget]) -> MutationPlan {
    MutationPlan {
        preview_action: format!("Delete {} agent policy(ies)", targets.len()),
        preview_details: targets
            .iter()
            .map(|target| {
                format!(
                    "{}  {}  agents {}  integrations {}",
                    target.id,
                    target.name,
                    target.snapshot.agents,
                    target.snapshot.attached.len()
                )
            })
            .collect(),
        targets: targets.iter().map(|target| target.id.clone()).collect(),
    }
}

pub async fn apply_delete(
    transport: &Transport,
    plan: &AgentPolicyDeletePlan,
) -> Result<AgentPolicyDeleteReport> {
    validate_delete_plan(plan)?;
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    for target in &plan.targets {
        let live = match read_live(transport, &target.id).await {
            Ok(live) => live,
            Err(error) if error.kind == ErrorKind::NotFound => {
                failed.push(failed_delete_row(
                    &target.id,
                    false,
                    "agent policy disappeared since preview",
                ));
                continue;
            }
            Err(error) => {
                failed.push(failed_delete_row(&target.id, false, error.message));
                continue;
            }
        };
        if live != target.snapshot {
            failed.push(failed_delete_row(
                &target.id,
                false,
                "agent policy changed since preview",
            ));
            continue;
        }
        match agent_policies::delete(transport, &target.id).await {
            Ok(()) => deleted.push(json!({"id": target.id})),
            Err(error) => {
                // A 2xx echoing the wrong id means the server acknowledged
                // deleting something; only a non-2xx status (or none, for a
                // transport/decode failure) leaves the target untouched.
                let applied =
                    matches!(error.http_status, Some(status) if (200..300).contains(&status));
                failed.push(failed_delete_row(&target.id, applied, error.message));
            }
        }
    }
    Ok(AgentPolicyDeleteReport {
        applied: true,
        deleted,
        failed,
        total: plan.targets.len(),
        affected_agents: 0,
    })
}

fn failed_delete_row(id: &str, applied: bool, error: impl Into<String>) -> Value {
    json!({"id": id, "applied": applied, "error": error.into()})
}

fn validate_delete_plan(plan: &AgentPolicyDeletePlan) -> Result<()> {
    if plan.targets.is_empty() || plan.preview != delete_preview(&plan.targets) {
        return Err(Error::new(
            ErrorKind::Error,
            "invalid agent-policy delete plan",
        ));
    }
    let mut previous: Option<&str> = None;
    for target in &plan.targets {
        target.snapshot.spec.validate()?;
        if target.id != target.snapshot.spec.id
            || target.name != target.snapshot.spec.name
            || target.snapshot.agents != 0
            || !target.snapshot.attached.is_empty()
            || previous.is_some_and(|previous| previous >= target.id.as_str())
        {
            return Err(Error::new(
                ErrorKind::Error,
                "invalid agent-policy delete plan",
            ));
        }
        previous = Some(&target.id);
    }
    Ok(())
}
