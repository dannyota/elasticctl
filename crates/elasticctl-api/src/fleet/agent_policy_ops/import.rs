//! Agent policy import planning and apply.

use super::{
    AgentPolicySpec, AgentPolicySummary, BTreeMap, BTreeSet, Error, ErrorKind, LiveAgentPolicy,
    MutationPlan, Path, Result, Serialize, Transport, Value, agent_policies, collect, http, json,
    live_from_policy, read_live, validate,
};

/// What `plan_import` computed and `apply_import` uploads. Public fields are
/// the guard preview and the summary counts; the rest are the exact
/// snapshots and bodies `apply_import` rechecks against before every write.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentPolicyImportPlan {
    pub preview: MutationPlan,
    pub skipped: Vec<Value>,
    pub package_installs: Vec<String>,
    pub total: usize,
    source: std::path::PathBuf,
    specs: Vec<AgentPolicySpec>,
    before: BTreeMap<String, Option<LiveAgentPolicy>>,
    bodies: BTreeMap<String, Value>,
    monitoring_package: Option<agent_policies::PackageStatus>,
    overwrite: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentPolicyImportReport {
    pub applied: bool,
    pub succeeded: Vec<Value>,
    pub unchanged: Vec<Value>,
    pub skipped: Vec<Value>,
    pub failed: Vec<Value>,
    pub total: usize,
    pub affected_agents: u64,
    pub package_installs: Vec<String>,
}

const MONITORING_PACKAGE: &str = "elastic_agent";
const SERVER_SELECTED_INSTALL: &str = "elastic_agent@server-selected";

/// Build the full-spec PUT body for a merge-semantics update route.
pub fn build_replace_body(current: &AgentPolicySpec, desired: &AgentPolicySpec) -> Result<Value> {
    current.validate()?;
    desired.validate()?;
    if current.id != desired.id {
        return unsupported(
            "changing agent policy id is not supported by the agent-policy update API",
        );
    }
    let removed = [
        (
            "description",
            current.description.is_some() && desired.description.is_none(),
        ),
        (
            "unenroll_timeout",
            current.unenroll_timeout.is_some() && desired.unenroll_timeout.is_none(),
        ),
        (
            "monitoring_pprof_enabled",
            current.monitoring_pprof_enabled.is_some()
                && desired.monitoring_pprof_enabled.is_none(),
        ),
        (
            "advanced_settings",
            current.advanced_settings.is_some() && desired.advanced_settings.is_none(),
        ),
        (
            "monitoring_http",
            current.monitoring_http.is_some() && desired.monitoring_http.is_none(),
        ),
        (
            "monitoring_diagnostics",
            current.monitoring_diagnostics.is_some() && desired.monitoring_diagnostics.is_none(),
        ),
    ];
    if let Some((field, _)) = removed.iter().find(|(_, gone)| *gone) {
        return unsupported(format!(
            "removing {field} is not supported by the agent-policy update API"
        ));
    }
    // Nested objects need no removal check: Kibana maps them `flattened` and
    // replaces the stored object with the supplied one.
    let mut body = serde_json::to_value(desired)
        .map_err(|error| Error::new(ErrorKind::Error, format!("encoding agent policy: {error}")))?
        .as_object()
        .cloned()
        .expect("specs serialize to objects");
    body.remove("id");
    if current.overrides.is_some() && desired.overrides.is_none() {
        body.insert("overrides".into(), Value::Null);
    }
    if current.keep_monitoring_alive.is_some() && desired.keep_monitoring_alive.is_none() {
        body.insert("keep_monitoring_alive".into(), Value::Null);
    }
    Ok(Value::Object(body))
}

fn unsupported<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::new(ErrorKind::Unsupported, message))
}

pub async fn plan_import(
    transport: &Transport,
    path: &Path,
    overwrite: bool,
    skip_existing: bool,
) -> Result<AgentPolicyImportPlan> {
    let mut specs = validate(path)?;
    if specs.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "agent-policy import needs at least one agent policy",
        ));
    }
    if overwrite && skip_existing {
        return Err(Error::new(
            ErrorKind::Error,
            "--overwrite and --skip-existing cannot be used together",
        ));
    }
    let total = specs.len();

    // Read raw first: an existing policy that will only be skipped or
    // reported conflict must never pay `normalize`'s portability refusal.
    // Only a policy that survives to the overwrite path below is normalized.
    let mut before_raw = BTreeMap::new();
    let mut conflicts = Vec::new();
    for spec in &specs {
        match agent_policies::get(transport, &spec.id).await {
            Ok(policy) => {
                if !overwrite && !skip_existing {
                    conflicts.push(spec.id.clone());
                }
                before_raw.insert(spec.id.clone(), Some(policy));
            }
            Err(error) if error.kind == ErrorKind::NotFound => {
                before_raw.insert(spec.id.clone(), None);
            }
            Err(error) => return Err(error),
        }
    }
    // Fleet enforces unique names with a 409; catch it before the guard.
    let mut live_names = BTreeMap::new();
    for item in collect(transport).await? {
        let row = AgentPolicySummary::from_item(&item)?;
        if live_names
            .insert(row.name.clone(), row.id.clone())
            .is_some()
        {
            return Err(http(format!(
                "decoding agent policies list: duplicate name '{}'",
                row.name
            )));
        }
    }
    let taken: Vec<String> = specs
        .iter()
        .filter_map(|spec| {
            live_names
                .get(&spec.name)
                .filter(|owner| **owner != spec.id)
                .map(|owner| format!("{} ({owner})", spec.name))
        })
        .collect();
    if !taken.is_empty() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!("agent policy names already exist: {}", taken.join(", ")),
        ));
    }
    if !conflicts.is_empty() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!("agent policies already exist: {}", conflicts.join(", ")),
        ));
    }
    let mut skipped = Vec::new();
    if skip_existing {
        specs.retain(|spec| match before_raw.get(&spec.id) {
            Some(Some(_)) => {
                skipped.push(json!({"id": spec.id, "reason": "exists"}));
                false
            }
            _ => true,
        });
        before_raw.retain(|id, _| specs.iter().any(|spec| spec.id == *id));
    }

    // Every id remaining here is either absent or, having passed both the
    // conflict guard above and the skip filter, is about to be replaced:
    // `--overwrite` is required by this point for any `Some` entry. Only now
    // is the existing policy normalized, so an unsupported existing policy
    // still fails the plan here, exactly as it must for a replace.
    let mut before = BTreeMap::new();
    for (id, raw) in before_raw {
        let live = match raw {
            Some(policy) => Some(live_from_policy(&policy, &id, transport.space())?),
            None => None,
        };
        before.insert(id, live);
    }

    let mut bodies = BTreeMap::new();
    for spec in &specs {
        if let Some(Some(current)) = before.get(&spec.id)
            && current.spec != *spec
        {
            bodies.insert(spec.id.clone(), build_replace_body(&current.spec, spec)?);
        }
    }

    let mut package_installs = Vec::new();
    let needs_monitoring = specs
        .iter()
        .any(|spec| monitoring_can_install(before.get(&spec.id).and_then(Option::as_ref), spec));
    let monitoring_package = if needs_monitoring {
        let status = agent_policies::package_status(transport, MONITORING_PACKAGE).await?;
        if status.status != "installed" {
            package_installs.push(SERVER_SELECTED_INSTALL.to_string());
        }
        Some(status)
    } else {
        None
    };

    let preview = MutationPlan {
        preview_action: format!(
            "Import {} agent policy(ies) from {}",
            specs.len(),
            path.display()
        ),
        preview_details: import_details(&specs, &before, &package_installs),
        targets: specs.iter().map(|spec| spec.id.clone()).collect(),
    };
    Ok(AgentPolicyImportPlan {
        preview,
        skipped,
        package_installs,
        total,
        source: path.to_path_buf(),
        specs,
        before,
        bodies,
        monitoring_package,
        overwrite,
    })
}

fn monitoring_can_install(current: Option<&LiveAgentPolicy>, desired: &AgentPolicySpec) -> bool {
    !desired.monitoring_enabled.is_empty()
        && current.is_none_or(|current| current.spec.monitoring_enabled.is_empty())
}

fn import_details(
    specs: &[AgentPolicySpec],
    before: &BTreeMap<String, Option<LiveAgentPolicy>>,
    package_installs: &[String],
) -> Vec<String> {
    let mut details: Vec<String> = specs
        .iter()
        .filter_map(|spec| match before.get(&spec.id) {
            Some(None) => Some(format!("{}  create  {}", spec.id, spec.name)),
            Some(Some(current)) if current.spec == *spec => {
                Some(format!("{}  unchanged  {}", spec.id, spec.name))
            }
            Some(Some(current)) => {
                let name = if current.spec.name == spec.name {
                    spec.name.clone()
                } else {
                    format!("{} -> {}", current.spec.name, spec.name)
                };
                Some(format!(
                    "{}  replace  {name}  agents {}",
                    spec.id, current.agents
                ))
            }
            None => None,
        })
        .collect();
    details.extend(
        package_installs
            .iter()
            .map(|install| format!("package install  {install}")),
    );
    details
}

pub async fn apply_import(
    transport: &Transport,
    plan: &AgentPolicyImportPlan,
) -> Result<AgentPolicyImportReport> {
    validate_import_plan(plan)?;
    let mut succeeded = Vec::new();
    let mut unchanged = Vec::new();
    let mut failed = Vec::new();
    let mut affected_agents = 0;
    let mut expected_package = plan.monitoring_package.clone();
    let mut package_installs = Vec::new();

    for desired in &plan.specs {
        let Some(before) = plan.before.get(&desired.id) else {
            failed.push(failed_row(&desired.id, false, "missing preflight snapshot"));
            continue;
        };
        let current = match read_live(transport, &desired.id).await {
            Ok(live) => Some(live),
            Err(error) if error.kind == ErrorKind::NotFound => None,
            Err(error) => {
                failed.push(failed_row(&desired.id, false, error.message));
                continue;
            }
        };
        match (before, current) {
            (None, Some(_)) => failed.push(failed_row(
                &desired.id,
                false,
                "agent policy appeared since preview",
            )),
            (Some(_), None) => failed.push(failed_row(
                &desired.id,
                false,
                "agent policy disappeared since preview",
            )),
            (Some(before), Some(live)) if before != &live => failed.push(failed_row(
                &desired.id,
                false,
                "agent policy changed since preview",
            )),
            (before, current) => {
                let package_can_change = monitoring_can_install(before.as_ref(), desired);
                if package_can_change {
                    let Some(expected) = expected_package.as_ref() else {
                        failed.push(failed_row(
                            &desired.id,
                            false,
                            "missing monitoring package snapshot",
                        ));
                        continue;
                    };
                    match agent_policies::package_status(transport, MONITORING_PACKAGE).await {
                        Ok(actual) if actual == *expected => {}
                        Ok(_) => {
                            failed.push(failed_row(
                                &desired.id,
                                false,
                                "elastic_agent package changed since preview",
                            ));
                            continue;
                        }
                        Err(error) => {
                            failed.push(failed_row(&desired.id, false, error.message));
                            continue;
                        }
                    }
                }

                let (action, applied, route_error) = match (before, current) {
                    (None, None) => {
                        match other_owner_of_name(transport, &desired.name).await {
                            Ok(Some(owner)) => {
                                failed.push(failed_row(
                                    &desired.id,
                                    false,
                                    format!(
                                        "agent policy name appeared since preview: {} ({owner})",
                                        desired.name
                                    ),
                                ));
                                continue;
                            }
                            Ok(None) => {}
                            Err(error) => {
                                failed.push(failed_row(&desired.id, false, error));
                                continue;
                            }
                        }
                        match agent_policies::create(transport, desired).await {
                            Ok(_) => ("created", true, None),
                            Err(error) => ("created", false, Some(error.message)),
                        }
                    }
                    (Some(before), Some(_)) if before.spec == *desired => {
                        unchanged.push(json!({"id": desired.id}));
                        continue;
                    }
                    (Some(before), Some(_)) => {
                        let body = plan
                            .bodies
                            .get(&desired.id)
                            .expect("validated replacement body");
                        match agent_policies::update(transport, &desired.id, body).await {
                            Ok(_) => {
                                affected_agents += before.agents;
                                ("replaced", true, None)
                            }
                            Err(error) => ("replaced", false, Some(error.message)),
                        }
                    }
                    _ => unreachable!("appearance and disappearance handled above"),
                };

                let stored_error = if applied {
                    verify_stored(transport, desired).await.err()
                } else {
                    None
                };
                let package_error = if package_can_change {
                    let expected = expected_package
                        .as_ref()
                        .expect("validated package snapshot");
                    match observe_package_after_write(transport, expected).await {
                        Ok((after, installed)) => {
                            expected_package = Some(after);
                            if let Some(installed) = installed
                                && !package_installs.contains(&installed)
                            {
                                package_installs.push(installed);
                            }
                            None
                        }
                        Err(error) => Some(error),
                    }
                } else {
                    None
                };

                let errors = [route_error, stored_error, package_error]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                if errors.is_empty() {
                    succeeded.push(json!({"id": desired.id, "action": action}));
                } else {
                    failed.push(failed_row(&desired.id, applied, errors.join("; ")));
                }
            }
        }
    }
    Ok(AgentPolicyImportReport {
        applied: true,
        succeeded,
        unchanged,
        skipped: plan.skipped.clone(),
        failed,
        total: plan.total,
        affected_agents,
        package_installs,
    })
}

async fn verify_stored(
    transport: &Transport,
    desired: &AgentPolicySpec,
) -> std::result::Result<(), String> {
    match read_live(transport, &desired.id).await {
        Ok(live) if live.spec == *desired => Ok(()),
        Ok(_) => Err("server stored a different agent-policy spec".into()),
        Err(error) => Err(error.message),
    }
}

/// Recheck the live list for a policy name claimed by a different id, right
/// before a planned create's POST. Fleet enforces unique names with a 409 on
/// create, so a name another client claimed since planning must fail the row
/// locally rather than reach the server.
async fn other_owner_of_name(
    transport: &Transport,
    name: &str,
) -> std::result::Result<Option<String>, String> {
    let items = collect(transport).await.map_err(|error| error.message)?;
    for item in &items {
        let row = AgentPolicySummary::from_item(item).map_err(|error| error.message)?;
        if row.name == name {
            return Ok(Some(row.id));
        }
    }
    Ok(None)
}

/// Re-read the monitoring package after a write that could install it. The
/// install is an observation: Fleet's create path tolerates an install error,
/// and a replace installs only from an absent stored value, so a package that
/// stays absent is not a failure. Only the read itself can fail the row.
async fn observe_package_after_write(
    transport: &Transport,
    before: &agent_policies::PackageStatus,
) -> std::result::Result<(agent_policies::PackageStatus, Option<String>), String> {
    let after = agent_policies::package_status(transport, MONITORING_PACKAGE)
        .await
        .map_err(|error| error.message)?;
    if before.status != "installed" && after.status == "installed" {
        let version = after
            .installed_version
            .clone()
            .expect("decoder requires installed version");
        return Ok((after, Some(format!("{MONITORING_PACKAGE}@{version}"))));
    }
    Ok((after, None))
}

fn failed_row(id: &str, applied: bool, error: impl Into<String>) -> Value {
    json!({"id": id, "applied": applied, "error": error.into()})
}

fn validate_import_plan(plan: &AgentPolicyImportPlan) -> Result<()> {
    let invalid = |message: &str| {
        Err(Error::new(
            ErrorKind::Error,
            format!("invalid agent-policy import plan: {message}"),
        ))
    };
    if plan.total == 0 || plan.total != plan.specs.len() + plan.skipped.len() {
        return invalid("total does not equal pending and skipped agent policies");
    }
    let mut previous_id: Option<&str> = None;
    let mut names = BTreeSet::new();
    let mut expected_body_ids = BTreeSet::new();
    for spec in &plan.specs {
        spec.validate()?;
        if previous_id.is_some_and(|previous| previous >= spec.id.as_str()) {
            return invalid("pending agent policies must be unique and sorted by id");
        }
        previous_id = Some(&spec.id);
        if !names.insert(spec.name.as_str()) {
            return invalid("pending agent-policy names must be unique");
        }
        let Some(before) = plan.before.get(&spec.id) else {
            return invalid("preflight snapshots do not match pending agent policies");
        };
        if let Some(current) = before {
            current.spec.validate()?;
            if current.spec.id != spec.id {
                return invalid("live snapshot id does not match its pending policy");
            }
            if current.attached.windows(2).any(|ids| ids[0] >= ids[1]) {
                return invalid("attached integration ids must be unique and sorted");
            }
        }
        match before {
            None if plan.bodies.contains_key(&spec.id) => {
                return invalid("planned creates must not carry a replacement body");
            }
            None => {}
            Some(current) if current.spec == *spec => {
                if plan.bodies.contains_key(&spec.id) {
                    return invalid("unchanged agent policies must not carry a replacement body");
                }
            }
            Some(current) => {
                expected_body_ids.insert(spec.id.as_str());
                if !plan.overwrite {
                    return invalid("replacement plan requires overwrite");
                }
                if plan.bodies.get(&spec.id) != Some(&build_replace_body(&current.spec, spec)?) {
                    return invalid("replacement body does not match its snapshots");
                }
            }
        }
    }
    if plan.before.len() != plan.specs.len() {
        return invalid("preflight snapshots do not match pending agent policies");
    }
    if plan
        .bodies
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_body_ids
    {
        return invalid("replacement bodies do not match changed agent policies");
    }
    let mut previous_skipped: Option<&str> = None;
    for skipped in &plan.skipped {
        let object = skipped.as_object().ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                "invalid agent-policy import plan: skipped row must be an object",
            )
        })?;
        if object.len() != 2 || object.get("reason").and_then(Value::as_str) != Some("exists") {
            return invalid("skipped rows must contain only id and reason exists");
        }
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Error,
                    "invalid agent-policy import plan: skipped id must be non-empty",
                )
            })?;
        if previous_skipped.is_some_and(|previous| previous >= id) {
            return invalid("skipped agent policies must be unique and sorted by id");
        }
        if plan.before.contains_key(id) {
            return invalid("an agent policy cannot be both pending and skipped");
        }
        previous_skipped = Some(id);
    }

    let needs_monitoring = plan.specs.iter().any(|spec| {
        monitoring_can_install(plan.before.get(&spec.id).and_then(Option::as_ref), spec)
    });
    match (&plan.monitoring_package, needs_monitoring) {
        (Some(status), true) if status.name == MONITORING_PACKAGE => {
            let expected = if status.status == "installed" {
                Vec::new()
            } else {
                vec![SERVER_SELECTED_INSTALL.to_string()]
            };
            if status.status == "installed" && status.installed_version.is_none() {
                return invalid("installed monitoring package needs an exact version");
            }
            if plan.package_installs != expected {
                return invalid("monitoring package preview does not match its snapshot");
            }
        }
        (None, false) if plan.package_installs.is_empty() => {}
        _ => return invalid("monitoring package snapshot does not match pending transitions"),
    }

    let expected_preview = MutationPlan {
        preview_action: format!(
            "Import {} agent policy(ies) from {}",
            plan.specs.len(),
            plan.source.display()
        ),
        preview_details: import_details(&plan.specs, &plan.before, &plan.package_installs),
        targets: plan.specs.iter().map(|spec| spec.id.clone()).collect(),
    };
    if plan.preview != expected_preview {
        return invalid("preview does not match the canonical plan");
    }
    Ok(())
}
