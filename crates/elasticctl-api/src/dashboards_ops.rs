//! Dashboard selection and portable transfer orchestration.

use crate::content_codec::{self, ContentFormat};
use crate::dashboards::{self, Dashboard, DashboardSpec, DashboardSummary};
use crate::data_views;
use crate::ops::{DeleteOutcome, ExportOutcome, MutationPlan};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Dashboard list filters accepted by the portable command surface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DashboardFilter {
    pub search: Option<String>,
    pub tag: Option<String>,
    pub limit: Option<usize>,
}

/// Dashboard list output after collection, stable-id sorting, and limiting.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DashboardList {
    pub total: u64,
    pub dashboards: Vec<DashboardSummary>,
    pub truncated: bool,
}

/// The immutable, guard-ready import work computed from one portable
/// dashboard artifact.
#[derive(Debug, Clone, PartialEq)]
pub struct DashboardImportPlan {
    pub preview: crate::ops::MutationPlan,
    /// Canonical artifact descriptor captured before the mutation guard.
    pub source: String,
    pub specs: Vec<DashboardSpec>,
    pub before: BTreeMap<String, Option<DashboardSpec>>,
    pub skipped: Vec<Value>,
    pub total: usize,
    pub overwrite: bool,
}

/// The per-object result of applying a guarded dashboard import.
///
/// Field order is rendered JSON order and is contractual.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DashboardImportReport {
    pub applied: bool,
    pub succeeded: Vec<Value>,
    pub skipped: Vec<Value>,
    pub failed: Vec<Value>,
    pub lossy: Vec<Value>,
    pub total: usize,
}

/// The immutable, guard-ready targets for dashboard deletion.
#[derive(Debug, Clone, PartialEq)]
pub struct DashboardDeletePlan {
    pub preview: MutationPlan,
    pub targets: Vec<DashboardSummary>,
}

/// Resolve a selector from dashboard summaries.
///
/// Stable ids win over titles. A title is only a convenience selector and must
/// identify exactly one dashboard.
pub fn resolve_from_summaries(
    dashboards: &[DashboardSummary],
    selector: &str,
) -> Result<DashboardSummary> {
    if let Some(dashboard) = dashboards.iter().find(|dashboard| dashboard.id == selector) {
        return Ok(dashboard.clone());
    }

    let mut matches: Vec<_> = dashboards
        .iter()
        .filter(|dashboard| dashboard.title == selector)
        .cloned()
        .collect();
    matches.sort_by(|left, right| left.id.cmp(&right.id));
    match matches.as_slice() {
        [] => Err(Error::new(
            ErrorKind::NotFound,
            format!("no dashboard with id or title '{selector}'"),
        )),
        [dashboard] => Ok(dashboard.clone()),
        _ => Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "dashboard title '{selector}' is ambiguous: {}",
                matches
                    .iter()
                    .map(|dashboard| dashboard.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

/// Resolve a dashboard by exact id, then by exact title only after an id miss.
pub async fn resolve(transport: &Transport, selector: &str) -> Result<DashboardSummary> {
    match dashboards::get(transport, selector).await {
        Ok(dashboard) if dashboard.id == selector => summary_from_dashboard(dashboard),
        Ok(dashboard) => Err(Error::new(
            ErrorKind::Http,
            format!(
                "decoding dashboard get: expected id '{selector}', got '{}'",
                dashboard.id
            ),
        )),
        Err(error) if error.kind == ErrorKind::NotFound => {
            let listed = list_op(transport, &DashboardFilter::default()).await?;
            resolve_from_summaries(&listed.dashboards, selector)
        }
        Err(error) => Err(error),
    }
}

/// Page through dashboard summaries, apply filters, and sort by stable id.
pub async fn list_op(transport: &Transport, filter: &DashboardFilter) -> Result<DashboardList> {
    let tags = filter.tag.iter().cloned().collect::<Vec<_>>();
    let mut page_number = 1;
    let mut total = None;
    let mut dashboards = Vec::new();

    loop {
        let page =
            dashboards::search(transport, page_number, filter.search.as_deref(), &tags).await?;
        if page.page != page_number || page.per_page != 1000 {
            return Err(Error::new(
                ErrorKind::Http,
                "decoding dashboard search: unexpected page metadata",
            ));
        }
        if let Some(total) = total {
            if page.total != total {
                return Err(Error::new(
                    ErrorKind::Http,
                    "decoding dashboard search: total changed while paging",
                ));
            }
        } else {
            total = Some(page.total);
        }
        let page_len = page.data.len();
        dashboards.extend(page.data);
        let expected_total = total.expect("set from the first page");
        if dashboards.len() as u64 >= expected_total {
            break;
        }
        if page_len != 1000 {
            return Err(Error::new(
                ErrorKind::Http,
                "decoding dashboard search: page was short before total",
            ));
        }
        page_number += 1;
    }

    dashboards.sort_by(|left, right| left.id.cmp(&right.id));
    let total = total.unwrap_or(0);
    if dashboards.len() as u64 > total {
        return Err(Error::new(
            ErrorKind::Http,
            "decoding dashboard search: returned more dashboards than total",
        ));
    }
    let limit = filter.limit.unwrap_or(usize::MAX);
    let truncated = dashboards.len() > limit;
    dashboards.truncate(limit);
    Ok(DashboardList {
        total,
        dashboards,
        truncated,
    })
}

/// Resolve one selector, then read its complete dashboard.
pub async fn get_op(transport: &Transport, selector: &str) -> Result<Dashboard> {
    let dashboard = resolve(transport, selector).await?;
    dashboards::get(transport, &dashboard.id).await
}

/// Fully read and validate a portable dashboard artifact.
pub fn validate(path: &Path) -> Result<Vec<DashboardSpec>> {
    let body = std::fs::read_to_string(path).map_err(|error| {
        Error::new(
            ErrorKind::Error,
            format!("reading {}: {error}", path.display()),
        )
    })?;
    let mut specs = content_codec::decode_sequence::<DashboardSpec>(
        &body,
        ContentFormat::from_path(path),
        "dashboard",
    )?;
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for spec in &specs {
        dashboards::validate_spec(spec)?;
        if !seen.insert(spec.id.as_str()) {
            duplicates.insert(spec.id.as_str());
        }
    }
    if !duplicates.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            format!(
                "duplicate dashboard ids: {}",
                duplicates.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(specs)
}

/// Fully validate an artifact and collect the precise import work to show in
/// the mutation guard. The supplied transport is optional only for a local
/// no-conflict plan with no data-view references.
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

    let source = path.display().to_string();
    let preview = crate::ops::MutationPlan {
        preview_action: format!("Import {} dashboard(s) from {}", specs.len(), source),
        preview_details: import_preview_details(&specs, &before),
        targets: specs.iter().map(|spec| spec.id.clone()).collect(),
    };
    Ok(DashboardImportPlan {
        preview,
        source,
        specs,
        before,
        skipped,
        total,
        overwrite,
    })
}

/// Apply a guard-approved dashboard import without rereading its source file.
///
/// The final dashboard GET immediately precedes each possible PUT. Kibana has
/// no conditional-write token, so the interval after that read is the smallest
/// unavoidable race window. Independent objects continue after failures, and
/// successful earlier writes are never rolled back.
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

/// Resolve every dashboard selector and build the exact delete guard preview.
pub async fn plan_delete(
    transport: &Transport,
    selectors: &[String],
) -> Result<DashboardDeletePlan> {
    if selectors.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "dashboard delete needs at least one dashboard",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut targets = Vec::new();
    for selector in selectors {
        let dashboard = resolve(transport, selector).await?;
        if seen.insert(dashboard.id.clone()) {
            targets.push(dashboard);
        }
    }
    Ok(DashboardDeletePlan {
        preview: delete_preview(&targets),
        targets,
    })
}

/// Apply a guard-approved dashboard deletion without resolving selectors again.
pub async fn apply_delete(
    transport: &Transport,
    plan: &DashboardDeletePlan,
) -> Result<DeleteOutcome> {
    validate_delete_plan(plan)?;
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    for target in &plan.targets {
        match dashboards::delete(transport, &target.id).await {
            Ok(()) => deleted.push(serde_json::json!({"id": target.id})),
            Err(error) => failed.push(serde_json::json!({
                "id": target.id,
                "error": error.message,
            })),
        }
    }
    Ok(DeleteOutcome {
        applied: true,
        deleted,
        failed,
        total: plan.targets.len(),
    })
}

fn delete_preview(targets: &[DashboardSummary]) -> MutationPlan {
    MutationPlan {
        preview_action: format!("Delete {} dashboard(s)", targets.len()),
        preview_details: targets
            .iter()
            .map(|dashboard| format!("{}  {}", dashboard.id, dashboard.title))
            .collect(),
        targets: targets
            .iter()
            .map(|dashboard| dashboard.id.clone())
            .collect(),
    }
}

fn validate_delete_plan(plan: &DashboardDeletePlan) -> Result<()> {
    if plan.targets.is_empty() {
        return invalid_plan("dashboard delete plan needs at least one target");
    }
    let mut ids = BTreeSet::new();
    for target in &plan.targets {
        if target.id.trim().is_empty() || target.title.trim().is_empty() {
            return invalid_plan("dashboard delete target identity must not be empty");
        }
        if !ids.insert(target.id.clone()) {
            return invalid_plan("dashboard delete targets must be unique by id");
        }
    }
    if plan.preview != delete_preview(&plan.targets) {
        return invalid_plan("dashboard delete preview does not match guarded targets");
    }
    Ok(())
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
    if plan.source.is_empty()
        || plan.preview.preview_action
            != format!(
                "Import {} dashboard(s) from {}",
                plan.specs.len(),
                plan.source
            )
    {
        return invalid_plan("preview action does not match dashboard import source");
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

fn invalid_plan(message: impl Into<String>) -> Result<()> {
    Err(Error::new(ErrorKind::Error, message))
}

/// Export selected dashboards as a portable JSON or YAML artifact.
pub async fn export(
    transport: &Transport,
    selectors: &[String],
    format: ContentFormat,
) -> Result<ExportOutcome> {
    let selected = if selectors.is_empty() {
        list_op(transport, &DashboardFilter::default())
            .await?
            .dashboards
    } else {
        let mut selected = Vec::with_capacity(selectors.len());
        for selector in selectors {
            selected.push(resolve(transport, selector).await?);
        }
        selected
    };
    let selected: BTreeMap<_, _> = selected
        .into_iter()
        .map(|dashboard| (dashboard.id.clone(), dashboard))
        .collect();
    let mut specs = Vec::with_capacity(selected.len());
    for (id, _) in selected {
        let dashboard = dashboards::get(transport, &id).await?;
        if dashboard.id != id {
            return Err(Error::new(
                ErrorKind::Http,
                format!("dashboard export was short: expected id '{id}'"),
            ));
        }
        if !dashboard.warnings.is_empty() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "dashboard '{id}' cannot be exported through the typed API without loss: {}; use `dashboards bundle export {id}`",
                    dashboard
                        .warnings
                        .iter()
                        .map(|warning| warning.message.as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            ));
        }
        let spec = DashboardSpec {
            id: dashboard.id,
            data: dashboard.data,
        };
        dashboards::validate_spec(&spec)?;
        specs.push(spec);
    }
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    let body = content_codec::encode_sequence(&specs, format)?;
    Ok(ExportOutcome {
        body,
        exported: specs.len() as u64,
        missing: Vec::<Value>::new(),
    })
}

fn summary_from_dashboard(dashboard: Dashboard) -> Result<DashboardSummary> {
    let title = dashboard
        .data
        .get("title")
        .and_then(Value::as_str)
        .filter(|title| !title.trim().is_empty())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                "decoding dashboard get: data.title must be a non-empty string",
            )
        })?;
    Ok(DashboardSummary {
        id: dashboard.id,
        title: title.to_string(),
        description: dashboard
            .data
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        tags: dashboard
            .data
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| {
                tags.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            }),
    })
}

/// Read one live dashboard and rebuild the portable spec used for snapshot
/// comparisons. The response id is checked separately from its request path.
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
