use super::common::*;
use super::import_shared::{
    IntegrationPolicyImportPlan, IntegrationPolicyImportTarget, import_remote_error,
    relevant_name_owners,
};
use super::import_validation::validate_import_plan;
use super::normalization::normalize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IntegrationPolicyImportReport {
    pub applied: bool,
    pub succeeded: Vec<Value>,
    pub unchanged: Vec<Value>,
    pub skipped: Vec<Value>,
    pub failed: Vec<Value>,
    pub total: usize,
    pub affected_agents: u64,
    pub package_installs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportAction {
    Create,
    Replace,
    Unchanged,
}

pub async fn apply_import(
    transport: &Transport,
    plan: &IntegrationPolicyImportPlan,
) -> Result<IntegrationPolicyImportReport> {
    validate_import_plan(plan)?;
    if plan.host != transport.kibana_url() || plan.space != transport.space() {
        return Err(Error::new(
            ErrorKind::Conflict,
            "integration import target changed since preview",
        ));
    }
    let mut succeeded = Vec::new();
    let mut unchanged = Vec::new();
    let mut failed = Vec::new();
    let mut expected_groups = plan.package_groups.clone();
    let mut expected_parents = plan.parent_snapshots.clone();
    let mut blocked_packages = BTreeMap::<String, String>::new();
    let mut affected_parents = BTreeMap::<String, u64>::new();
    let mut observed_installs = BTreeSet::new();

    for target in &plan.targets {
        let package_name = &target.effective.package.name;
        if let Some(error) = blocked_packages.get(package_name) {
            failed.push(import_failed_row(
                &target.effective.id,
                false,
                format!("package dependency is unavailable: {error}"),
            ));
            continue;
        }

        let action = match recheck_import_object(transport, target).await {
            Ok(action) => action,
            Err(error) => {
                failed.push(import_failed_row(
                    &target.effective.id,
                    false,
                    error.message,
                ));
                continue;
            }
        };
        if let Err(error) = recheck_import_name_owner(transport, target, &plan.name_owners).await {
            failed.push(import_failed_row(
                &target.effective.id,
                false,
                error.message,
            ));
            continue;
        }
        if let Err(error) = recheck_import_parents(transport, target, &expected_parents).await {
            failed.push(import_failed_row(
                &target.effective.id,
                false,
                error.message,
            ));
            continue;
        }

        let group = expected_groups
            .get_mut(package_name)
            .expect("validated target package group");
        let actual_state = match read_dependencies(transport, &target.effective.package).await {
            Ok(state) if state == group.state => state,
            Ok(_) => {
                let message = "package changed since preview".to_owned();
                blocked_packages.insert(package_name.clone(), message.clone());
                failed.push(import_failed_row(&target.effective.id, false, message));
                continue;
            }
            Err(error) => {
                let message = import_remote_error(error, "apply package read").message;
                blocked_packages.insert(package_name.clone(), message.clone());
                failed.push(import_failed_row(&target.effective.id, false, message));
                continue;
            }
        };
        debug_assert_eq!(actual_state, group.state);

        if action == ImportAction::Unchanged {
            unchanged.push(json!({"id": target.effective.id}));
            continue;
        }

        let (label, applied, route_error) = match action {
            ImportAction::Create => {
                match integration_policies::create(transport, &target.effective).await {
                    Ok(_) => ("created", true, None),
                    Err(error) => (
                        "created",
                        false,
                        Some(import_remote_error(error, "create request").message),
                    ),
                }
            }
            ImportAction::Replace => {
                let _body = target
                    .replacement_body
                    .as_ref()
                    .expect("validated replacement body");
                match integration_policies::update(
                    transport,
                    &target.effective.id,
                    &target.effective,
                )
                .await
                {
                    Ok(_) => ("replaced", true, None),
                    Err(error) => (
                        "replaced",
                        false,
                        Some(import_remote_error(error, "update request").message),
                    ),
                }
            }
            ImportAction::Unchanged => unreachable!("unchanged rows continue above"),
        };

        if applied {
            record_affected_parents(&mut affected_parents, target);
            advance_parent_snapshots(&mut expected_parents, target);
        }

        let mut observed_after_create = None;
        let mut package_observation_error = None;
        if action == ImportAction::Create
            && matches!(group.state.state, PackageDependencyState::NotInstalled)
        {
            match read_dependencies(transport, &target.effective.package).await {
                Ok(after) => {
                    if is_exact_installed(&after, &target.effective.package) {
                        group.state = after.clone();
                        observed_installs.insert(format!(
                            "{}@{}",
                            target.effective.package.name, target.effective.package.version
                        ));
                    } else if !matches!(after.state, PackageDependencyState::NotInstalled) {
                        let message =
                            "package installed a different version after create".to_owned();
                        blocked_packages.insert(package_name.clone(), message.clone());
                        package_observation_error = Some(message);
                    }
                    observed_after_create = Some(after);
                }
                Err(error) => {
                    let message = import_remote_error(error, "post-create package read").message;
                    blocked_packages.insert(package_name.clone(), message.clone());
                    package_observation_error = Some(message);
                }
            }
        }

        let mut errors = route_error.into_iter().collect::<Vec<_>>();
        if applied {
            if let Err(error) = verify_import_stored(transport, &target.effective).await {
                errors.push(error.message);
            }
            let package_result = match observed_after_create.as_ref() {
                Some(after) => verify_exact_installed(after, &target.effective.package),
                None => match read_dependencies(transport, &target.effective.package).await {
                    Ok(after) => verify_exact_installed(&after, &target.effective.package),
                    Err(error) => Err(import_remote_error(error, "package verification").message),
                },
            };
            if let Err(message) = package_result {
                blocked_packages
                    .entry(package_name.clone())
                    .or_insert_with(|| message.clone());
                errors.push(message);
            }
        }
        if let Some(error) = package_observation_error
            && !errors.contains(&error)
        {
            errors.push(error);
        }

        if errors.is_empty() {
            succeeded.push(json!({"id": target.effective.id, "action": label}));
        } else {
            failed.push(import_failed_row(
                &target.effective.id,
                applied,
                errors.join("; "),
            ));
        }
    }

    Ok(IntegrationPolicyImportReport {
        applied: true,
        succeeded,
        unchanged,
        skipped: plan.skipped.clone(),
        failed,
        total: plan.total,
        affected_agents: affected_parents.values().sum(),
        package_installs: observed_installs.into_iter().collect(),
    })
}

async fn recheck_import_object(
    transport: &Transport,
    target: &IntegrationPolicyImportTarget,
) -> Result<ImportAction> {
    match &target.current {
        None => match integration_policies::get(transport, &target.effective.id).await {
            Err(error) if error.kind == ErrorKind::NotFound => Ok(ImportAction::Create),
            Ok(_) => Err(Error::new(
                ErrorKind::Conflict,
                "integration policy appeared since preview",
            )),
            Err(error) => Err(import_remote_error(error, "apply integration-policy read")),
        },
        Some(expected) => match integration_policies::get(transport, &target.effective.id).await {
            Ok(actual) if actual.item == expected.item => {
                if expected.spec == target.effective {
                    Ok(ImportAction::Unchanged)
                } else {
                    Ok(ImportAction::Replace)
                }
            }
            Ok(_) => Err(Error::new(
                ErrorKind::Conflict,
                "integration policy changed since preview",
            )),
            Err(error) if error.kind == ErrorKind::NotFound => Err(Error::new(
                ErrorKind::Conflict,
                "integration policy disappeared since preview",
            )),
            Err(error) => Err(import_remote_error(error, "apply integration-policy read")),
        },
    }
}

async fn recheck_import_name_owner(
    transport: &Transport,
    target: &IntegrationPolicyImportTarget,
    expected_owners: &BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    let names = BTreeSet::from([target.effective.name.clone()]);
    let owners = relevant_name_owners(transport, &names)
        .await
        .map_err(|error| import_remote_error(error, "apply name read"))?;
    if owners.get(&target.effective.name) == expected_owners.get(&target.effective.name) {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Conflict,
            "integration policy name ownership changed since preview",
        ))
    }
}

async fn recheck_import_parents(
    transport: &Transport,
    target: &IntegrationPolicyImportTarget,
    expected_parents: &BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
) -> Result<()> {
    for parent_id in target.parents.keys() {
        let expected = expected_parents.get(parent_id).ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                "integration import lost a shared parent snapshot",
            )
        })?;
        let actual = agent_policy_ops::read_parent_snapshot(transport, parent_id)
            .await
            .map_err(|error| import_remote_error(error, "apply parent read"))?;
        if actual != *expected {
            return Err(Error::new(
                ErrorKind::Conflict,
                "integration policy parent changed since preview",
            ));
        }
    }
    Ok(())
}

fn record_affected_parents(
    affected: &mut BTreeMap<String, u64>,
    target: &IntegrationPolicyImportTarget,
) {
    for parent in target.parents.values() {
        affected.entry(parent.id.clone()).or_insert(parent.agents);
    }
}

fn advance_parent_snapshots(
    parents: &mut BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot>,
    target: &IntegrationPolicyImportTarget,
) {
    let desired = target
        .effective
        .policy_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for parent_id in target.parents.keys() {
        let parent = parents
            .get_mut(parent_id)
            .expect("validated shared parent snapshot");
        if desired.contains(parent_id.as_str()) {
            if parent
                .attached_integrations
                .binary_search_by(|attached| attached.as_str().cmp(&target.effective.id))
                .is_err()
            {
                parent
                    .attached_integrations
                    .push(target.effective.id.clone());
                parent.attached_integrations.sort();
            }
        } else {
            parent
                .attached_integrations
                .retain(|attached| attached != &target.effective.id);
        }
    }
}

async fn verify_import_stored(
    transport: &Transport,
    desired: &IntegrationPolicySpec,
) -> Result<()> {
    let stored = integration_policies::get(transport, &desired.id)
        .await
        .map_err(|error| import_remote_error(error, "stored-policy read"))?;
    let stored = normalize(&stored.item, transport.space())
        .map_err(|error| import_remote_error(error, "stored-policy read"))?;
    if stored == *desired {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Http,
            "server stored a different integration-policy spec",
        ))
    }
}

fn import_failed_row(id: &str, applied: bool, error: impl Into<String>) -> Value {
    json!({"id": id, "applied": applied, "error": error.into()})
}
