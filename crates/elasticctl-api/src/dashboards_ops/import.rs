use super::{
    BTreeMap, BTreeSet, DashboardSpec, Error, ErrorKind, Path, Result, Serialize, Transport, Value,
    dashboards, data_views, invalid_plan, validate,
};

#[derive(Debug, Clone, PartialEq)]
pub struct DashboardImportPlan {
    pub preview: crate::ops::MutationPlan,
    pub specs: Vec<DashboardSpec>,
    pub before: BTreeMap<String, Option<DashboardSpec>>,
    pub skipped: Vec<Value>,
    pub total: usize,
    pub overwrite: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DashboardImportReport {
    pub applied: bool,
    pub succeeded: Vec<Value>,
    pub skipped: Vec<Value>,
    pub failed: Vec<Value>,
    pub lossy: Vec<Value>,
    pub total: usize,
}
pub async fn plan_import(
    transport: Option<&Transport>,
    path: &Path,
    overwrite: bool,
    skip_existing: bool,
) -> Result<DashboardImportPlan> {
    let mut specs = validate(path)?;
    if specs.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "dashboard import needs at least one dashboard",
        ));
    }
    if overwrite && skip_existing {
        return Err(Error::new(
            ErrorKind::Error,
            "--overwrite and --skip-existing cannot be used together",
        ));
    }

    let references: BTreeSet<_> = specs
        .iter()
        .flat_map(|spec| dashboards::collect_data_view_refs(&Value::Object(spec.data.clone())))
        .collect();
    let requires_server =
        overwrite || skip_existing || transport.is_some() || !references.is_empty();
    let transport = if requires_server { transport } else { None };
    if (overwrite || skip_existing || !references.is_empty()) && transport.is_none() {
        return Err(Error::new(
            ErrorKind::Error,
            "dashboard import preflight needs a transport",
        ));
    }

    let total = specs.len();
    let mut before = BTreeMap::new();
    let mut conflicts = Vec::new();
    if let Some(transport) = transport {
        for spec in &specs {
            match read_spec(transport, &spec.id).await {
                Ok(current) => {
                    if !overwrite && !skip_existing {
                        conflicts.push(spec.id.clone());
                    }
                    before.insert(spec.id.clone(), Some(current));
                }
                Err(error) if error.kind == ErrorKind::NotFound => {
                    before.insert(spec.id.clone(), None);
                }
                Err(error) => return Err(error),
            }
        }

        let mut missing = Vec::new();
        for id in references {
            match data_views::get(transport, &id).await {
                Ok(data_view) => match data_view.data_view.get("id").and_then(Value::as_str) {
                    Some(actual) if actual == id => {}
                    Some(actual) => {
                        return Err(Error::new(
                            ErrorKind::Http,
                            format!("decoding data view: expected id '{id}', got '{actual}'"),
                        ));
                    }
                    None => {
                        return Err(Error::new(
                            ErrorKind::Http,
                            format!(
                                "decoding data view: expected id '{id}', got missing or non-string id"
                            ),
                        ));
                    }
                },
                Err(error) if error.kind == ErrorKind::NotFound => missing.push(id),
                Err(error) => return Err(error),
            }
        }
        if !missing.is_empty() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("referenced data views do not exist: {}", missing.join(", ")),
            ));
        }
    } else {
        before.extend(specs.iter().map(|spec| (spec.id.clone(), None)));
    }

    if !conflicts.is_empty() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!("dashboards already exist: {}", conflicts.join(", ")),
        ));
    }

    let mut skipped = Vec::new();
    if skip_existing {
        specs.retain(|spec| match before.get(&spec.id) {
            Some(Some(_)) => {
                skipped.push(serde_json::json!({"id": spec.id, "reason": "exists"}));
                false
            }
            _ => true,
        });
        before.retain(|id, _| specs.iter().any(|spec| spec.id == *id));
    }

    let preview = crate::ops::MutationPlan {
        preview_action: format!("Import {} dashboard(s)", specs.len()),
        preview_details: import_preview_details(&specs, &before),
        targets: specs.iter().map(|spec| spec.id.clone()).collect(),
    };
    Ok(DashboardImportPlan {
        preview,
        specs,
        before,
        skipped,
        total,
        overwrite,
    })
}

pub async fn apply_import(
    transport: &Transport,
    plan: &DashboardImportPlan,
) -> Result<DashboardImportReport> {
    validate_import_plan(plan)?;
    let mut succeeded = Vec::new();
    let mut failed = Vec::new();
    let mut lossy = Vec::new();

    for desired in &plan.specs {
        let Some(before) = plan.before.get(&desired.id) else {
            failed.push(failed_row(&desired.id, false, "missing preflight snapshot"));
            continue;
        };
        let current = match read_spec(transport, &desired.id).await {
            Ok(current) => Some(current),
            Err(error) if error.kind == ErrorKind::NotFound => None,
            Err(error) => {
                failed.push(failed_row(&desired.id, false, error.message));
                continue;
            }
        };

        match (before, current) {
            (None, Some(_)) => {
                failed.push(failed_row(
                    &desired.id,
                    false,
                    "dashboard appeared since preview",
                ));
            }
            (Some(_), None) => {
                failed.push(failed_row(
                    &desired.id,
                    false,
                    "dashboard disappeared since preview",
                ));
            }
            (Some(before), Some(current)) if before != &current => {
                failed.push(failed_row(
                    &desired.id,
                    false,
                    "dashboard changed since preview",
                ));
            }
            (Some(_), Some(current)) if current == *desired => {
                succeeded.push(serde_json::json!({"id": desired.id, "action": "unchanged"}));
            }
            (None, None) => {
                apply_put(
                    transport,
                    desired,
                    "created",
                    &mut succeeded,
                    &mut failed,
                    &mut lossy,
                )
                .await;
            }
            (Some(_), Some(_)) => {
                apply_put(
                    transport,
                    desired,
                    "replaced",
                    &mut succeeded,
                    &mut failed,
                    &mut lossy,
                )
                .await;
            }
        }
    }

    Ok(DashboardImportReport {
        applied: true,
        succeeded,
        skipped: plan.skipped.clone(),
        failed,
        lossy,
        total: plan.total,
    })
}
async fn apply_put(
    transport: &Transport,
    desired: &DashboardSpec,
    action: &str,
    succeeded: &mut Vec<Value>,
    failed: &mut Vec<Value>,
    lossy: &mut Vec<Value>,
) {
    let response = match dashboards::put(transport, desired).await {
        Ok(response) => response,
        Err(error) => {
            failed.push(failed_row(&desired.id, false, error.message));
            return;
        }
    };
    if response.id != desired.id {
        failed.push(failed_row(
            &desired.id,
            true,
            format!(
                "dashboard PUT returned id '{}' instead of '{}'",
                response.id, desired.id
            ),
        ));
        return;
    }

    let mut paths: Vec<_> = dashboards::subset_losses(
        &Value::Object(desired.data.clone()),
        &Value::Object(response.data),
    )
    .into_iter()
    .map(|loss| loss.path)
    .collect();
    if paths.is_empty() {
        succeeded.push(serde_json::json!({"id": desired.id, "action": action}));
        return;
    }
    paths.sort();
    let warnings = match dashboards::get(transport, &desired.id).await {
        Ok(dashboard) if dashboard.id == desired.id => dashboard
            .warnings
            .into_iter()
            .map(|warning| warning.message)
            .collect(),
        Ok(dashboard) => {
            failed.push(failed_row(
                &desired.id,
                true,
                format!(
                    "dashboard loss audit returned id '{}' instead of '{}'",
                    dashboard.id, desired.id
                ),
            ));
            Vec::new()
        }
        Err(error) => {
            failed.push(failed_row(
                &desired.id,
                true,
                format!("dashboard loss audit failed: {}", error.message),
            ));
            Vec::new()
        }
    };
    lossy.push(serde_json::json!({
        "id": desired.id,
        "applied": true,
        "paths": paths,
        "warnings": warnings,
    }));
}

fn validate_import_plan(plan: &DashboardImportPlan) -> Result<()> {
    if plan.total == 0 {
        return invalid_plan("total must be greater than zero");
    }
    if plan.total != plan.specs.len() + plan.skipped.len() {
        return invalid_plan("total does not equal pending and skipped dashboards");
    }
    if !plan.skipped.is_empty() && plan.overwrite {
        return invalid_plan("skipped dashboards require skip-existing mode");
    }

    let mut ids = Vec::with_capacity(plan.specs.len());
    for spec in &plan.specs {
        dashboards::validate_spec(spec)?;
        if ids
            .last()
            .is_some_and(|previous: &String| previous >= &spec.id)
        {
            return invalid_plan("pending dashboards must be unique and sorted by id");
        }
        ids.push(spec.id.clone());
    }
    let pending: BTreeSet<_> = ids.iter().cloned().collect();
    if plan.preview.targets != ids {
        return invalid_plan("preview targets do not match pending dashboards");
    }
    if plan.preview.preview_action != format!("Import {} dashboard(s)", plan.specs.len()) {
        return invalid_plan("preview action does not match pending dashboards");
    }
    if plan.preview.preview_details != import_preview_details(&plan.specs, &plan.before) {
        return invalid_plan("preview details do not match pending dashboards");
    }

    if plan.before.keys().cloned().collect::<BTreeSet<_>>() != pending {
        return invalid_plan("preflight snapshots do not match pending dashboards");
    }
    for spec in &plan.specs {
        match plan.before.get(&spec.id).expect("checked key set") {
            None => {}
            Some(snapshot) => {
                dashboards::validate_spec(snapshot)?;
                if snapshot.id != spec.id {
                    return invalid_plan("preflight snapshot id does not match its target");
                }
                if !plan.overwrite {
                    return invalid_plan("replacement plan requires overwrite");
                }
            }
        }
    }

    let mut skipped_ids = BTreeSet::new();
    let mut previous = None;
    for row in &plan.skipped {
        let object = row
            .as_object()
            .filter(|object| object.len() == 2)
            .ok_or_else(|| Error::new(ErrorKind::Error, "invalid dashboard import skipped row"))?;
        if !object.keys().map(String::as_str).eq(["id", "reason"]) {
            return invalid_plan("invalid dashboard import skipped row order");
        }
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| Error::new(ErrorKind::Error, "invalid dashboard import skipped row"))?;
        if object.get("reason").and_then(Value::as_str) != Some("exists")
            || previous.is_some_and(|previous: &str| previous >= id)
            || !skipped_ids.insert(id.to_owned())
            || pending.contains(id)
        {
            return invalid_plan("invalid dashboard import skipped rows");
        }
        previous = Some(id);
    }
    Ok(())
}

fn failed_row(id: &str, applied: bool, error: impl Into<String>) -> Value {
    serde_json::json!({"id": id, "applied": applied, "error": error.into()})
}
async fn read_spec(transport: &Transport, id: &str) -> Result<DashboardSpec> {
    let dashboard = dashboards::get(transport, id).await?;
    if dashboard.id != id {
        return Err(Error::new(
            ErrorKind::Http,
            format!(
                "decoding dashboard: expected id '{id}', got '{}'",
                dashboard.id
            ),
        ));
    }
    let spec = DashboardSpec {
        id: dashboard.id,
        data: dashboard.data,
    };
    dashboards::validate_spec(&spec)?;
    Ok(spec)
}

fn import_preview_details(
    specs: &[DashboardSpec],
    before: &BTreeMap<String, Option<DashboardSpec>>,
) -> Vec<String> {
    specs
        .iter()
        .filter_map(|spec| match before.get(&spec.id) {
            Some(None) => Some(format!("{}  create  {}", spec.id, dashboard_title(spec))),
            Some(Some(current)) if current == spec => {
                Some(format!("{}  no-op  {}", spec.id, dashboard_title(spec)))
            }
            Some(Some(current)) => Some(format!(
                "{}  replace  {} -> {}",
                spec.id,
                dashboard_title(current),
                dashboard_title(spec)
            )),
            None => None,
        })
        .collect()
}

fn dashboard_title(spec: &DashboardSpec) -> &str {
    spec.data
        .get("title")
        .and_then(Value::as_str)
        .expect("validated dashboard specs have a title")
}
