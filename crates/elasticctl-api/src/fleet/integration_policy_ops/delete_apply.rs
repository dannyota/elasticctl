use super::common::*;
use super::delete_plan::{
    IntegrationPolicyDeletePlan, IntegrationPolicyDeleteTarget, delete_remote_error,
    validate_delete_plan,
};
use super::metadata::validate_package_metadata_snapshot;

/// The result of applying an integration-policy deletion plan.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IntegrationPolicyDeleteReport {
    pub applied: bool,
    pub deleted: Vec<Value>,
    pub failed: Vec<Value>,
    pub total: usize,
    pub affected_agents: u64,
}

/// Recheck the exact planning snapshots, then delete each independent target.
/// An acknowledged wrong-id response is deliberately not treated as a clean
/// deletion, and never advances shared parent expectations.
pub async fn apply_delete(
    transport: &Transport,
    plan: &IntegrationPolicyDeletePlan,
) -> Result<IntegrationPolicyDeleteReport> {
    validate_delete_plan(plan)?;
    if plan.host != transport.kibana_url() || plan.space != transport.space() {
        return Err(Error::new(
            ErrorKind::Conflict,
            "integration delete target changed since preview",
        ));
    }

    let mut expected_parents = plan.parent_snapshots.clone();
    let mut affected = BTreeMap::new();
    let mut deleted = Vec::new();
    let mut failed = Vec::new();

    for target in &plan.targets {
        match integration_policies::get(transport, &target.id).await {
            Ok(actual) if actual.item == target.item => {}
            Ok(_) => {
                failed.push(delete_failed_row(
                    &target.id,
                    false,
                    "integration policy changed since preview",
                ));
                continue;
            }
            Err(error) if error.kind == ErrorKind::NotFound => {
                failed.push(delete_failed_row(
                    &target.id,
                    false,
                    "integration policy disappeared since preview",
                ));
                continue;
            }
            Err(error) => {
                failed.push(delete_failed_row(
                    &target.id,
                    false,
                    delete_remote_error(error, "apply integration-policy read").message,
                ));
                continue;
            }
        }

        if let Err(error) = recheck_delete_parents(transport, target, &expected_parents).await {
            failed.push(delete_failed_row(&target.id, false, error.message));
            continue;
        }
        match read_dependencies(transport, &target.package).await {
            Ok(actual) if actual == target.dependency => {}
            Ok(_) => {
                failed.push(delete_failed_row(
                    &target.id,
                    false,
                    "integration policy package changed since preview",
                ));
                continue;
            }
            Err(error) => {
                failed.push(delete_failed_row(
                    &target.id,
                    false,
                    delete_remote_error(error, "apply package read").message,
                ));
                continue;
            }
        }
        if let Err(error) = recheck_delete_metadata(transport, target).await {
            failed.push(delete_failed_row(&target.id, false, error.message));
            continue;
        }

        match integration_policies::delete(transport, &target.id).await {
            Ok(()) => {
                record_delete_affected_parents(&mut affected, target, &expected_parents);
                advance_delete_parent_snapshots(&mut expected_parents, target);
                deleted.push(json!({"id": target.id}));
            }
            Err(error) => {
                let applied = error
                    .http_status
                    .is_some_and(|status| (200..300).contains(&status));
                let message = if applied {
                    "integration-policy delete response did not confirm the requested id"
                } else {
                    "integration-policy delete request failed"
                };
                failed.push(delete_failed_row(&target.id, applied, message));
            }
        }
    }

    Ok(IntegrationPolicyDeleteReport {
        applied: true,
        deleted,
        failed,
        total: plan.total,
        affected_agents: affected.values().sum(),
    })
}

async fn recheck_delete_parents(
    transport: &Transport,
    target: &IntegrationPolicyDeleteTarget,
    expected_parents: &BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
) -> Result<()> {
    for parent_id in target.parents.keys() {
        let expected = expected_parents.get(parent_id).ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                "integration delete lost a shared parent snapshot",
            )
        })?;
        match agent_policy_ops::read_parent_snapshot(transport, parent_id).await {
            Ok(actual) if actual == *expected => {}
            Ok(_) => {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "integration policy parent changed since preview",
                ));
            }
            Err(error) if error.kind == ErrorKind::NotFound => {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    "integration policy parent disappeared since preview",
                ));
            }
            Err(error) => return Err(delete_remote_error(error, "apply parent read")),
        }
    }
    Ok(())
}

async fn recheck_delete_metadata(
    transport: &Transport,
    target: &IntegrationPolicyDeleteTarget,
) -> Result<()> {
    let metadata = integration_policies::package_metadata(
        transport,
        &target.package.name,
        &target.package.version,
    )
    .await
    .map_err(|error| delete_remote_error(error, "apply package metadata read"))?
    .item;
    validate_package_metadata_snapshot(&metadata, &target.package)
        .map_err(|error| delete_remote_error(error, "apply package metadata read"))?;
    if metadata != target.metadata {
        return Err(Error::new(
            ErrorKind::Conflict,
            "integration policy package metadata changed since preview",
        ));
    }
    Ok(())
}

fn record_delete_affected_parents(
    affected: &mut BTreeMap<String, u64>,
    target: &IntegrationPolicyDeleteTarget,
    expected_parents: &BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
) {
    for parent_id in target.parents.keys() {
        let parent = expected_parents
            .get(parent_id)
            .expect("validated delete target parent exists in shared snapshots");
        affected.entry(parent.id.clone()).or_insert(parent.agents);
    }
}

fn advance_delete_parent_snapshots(
    parents: &mut BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
    target: &IntegrationPolicyDeleteTarget,
) {
    for parent_id in target.parents.keys() {
        let parent = parents
            .get_mut(parent_id)
            .expect("validated delete target parent exists in shared snapshots");
        parent
            .attached_integrations
            .retain(|attached| attached != &target.id);
    }
}

fn delete_failed_row(id: &str, applied: bool, error: impl Into<String>) -> Value {
    json!({"id": id, "applied": applied, "error": error.into()})
}
