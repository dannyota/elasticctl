//! Dashboard bundle export and import.

use super::{
    BTreeSet, DashboardFilter, Error, ErrorKind, ExportOutcome, Feature, Map, MutationPlan, Path,
    Result, Serialize, Transport, Value, invalid_plan, json, list_op, resolve, saved_objects,
};

/// The immutable, guard-ready work computed from one opaque Saved Objects
/// dashboard bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct BundleImportPlan {
    pub preview: MutationPlan,
    pub ndjson: String,
    pub scan: saved_objects::BundleScan,
    pub overwrite: bool,
}

/// The per-object report from applying an opaque Saved Objects bundle import.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BundleImportOutcome {
    pub applied: bool,
    pub succeeded: Vec<Value>,
    pub failed: Vec<Value>,
    pub total: usize,
}
/// Export selected dashboards and their deep Saved Objects references as
/// opaque NDJSON.
pub async fn export_bundle(transport: &Transport, selectors: &[String]) -> Result<ExportOutcome> {
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
    let ids: Vec<_> = selected
        .into_iter()
        .map(|dashboard| dashboard.id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let body = saved_objects::export(transport, &ids).await?;
    if !ids.is_empty() {
        let scan = saved_objects::scan_bundle(&body).map_err(|error| {
            Error::new(
                ErrorKind::Http,
                format!("decoding dashboard bundle export: {}", error.message),
            )
        })?;
        let exported: BTreeSet<_> = scan.dashboards.into_iter().collect();
        let missing: Vec<_> = ids
            .iter()
            .filter(|id| !exported.contains(*id))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(Error::new(
                ErrorKind::Http,
                format!(
                    "dashboard bundle export was short: missing {}",
                    missing.join(", ")
                ),
            ));
        }
    }
    Ok(ExportOutcome {
        body,
        exported: ids.len() as u64,
        missing: Vec::new(),
    })
}

/// Fully read and scan an opaque bundle before presenting its mutation guard.
pub fn plan_bundle_import(path: &Path, overwrite: bool) -> Result<BundleImportPlan> {
    let bytes = std::fs::read(path).map_err(|error| {
        Error::new(
            ErrorKind::Error,
            format!("reading {}: {error}", path.display()),
        )
    })?;
    let ndjson = String::from_utf8(bytes).map_err(|error| {
        Error::new(
            ErrorKind::Error,
            format!(
                "reading {}: bundle is not valid UTF-8: {error}",
                path.display()
            ),
        )
    })?;
    let scan = saved_objects::scan_bundle(&ndjson)?;
    let preview = bundle_import_preview(&scan, overwrite);
    Ok(BundleImportPlan {
        preview,
        ndjson,
        scan,
        overwrite,
    })
}

/// Apply a guard-approved opaque bundle without rereading its source file.
pub async fn apply_bundle_import(
    transport: &Transport,
    plan: &BundleImportPlan,
) -> Result<BundleImportOutcome> {
    validate_bundle_import_plan(plan)?;
    transport.require_feature(Feature::Dashboards).await?;
    let report = saved_objects::import(transport, &plan.ndjson, plan.overwrite).await?;
    Ok(BundleImportOutcome {
        applied: true,
        succeeded: sanitize_bundle_success_rows(&report.success_results)?,
        failed: sanitize_bundle_failure_rows(&report.errors)?,
        total: plan.scan.total,
    })
}

fn sanitize_bundle_success_rows(rows: &[Value]) -> Result<Vec<Value>> {
    rows.iter()
        .map(|row| {
            let object = bundle_report_object(row, "success result")?;
            let object_type = bundle_report_string(object, "type", "success result")?;
            let id = bundle_report_string(object, "id", "success result")?;
            Ok(json!({"type": object_type, "id": id}))
        })
        .collect()
}

fn sanitize_bundle_failure_rows(rows: &[Value]) -> Result<Vec<Value>> {
    rows.iter()
        .map(|row| {
            let object = bundle_report_object(row, "error result")?;
            let object_type = bundle_report_string(object, "type", "error result")?;
            let id = bundle_report_string(object, "id", "error result")?;
            let error = object
                .get("error")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    bundle_import_response_error("error result error must be an object")
                })?;
            let error_type = bundle_report_string(error, "type", "error result error")?;
            Ok(json!({"type": object_type, "id": id, "error": error_type}))
        })
        .collect()
}

fn bundle_report_object<'a>(row: &'a Value, kind: &str) -> Result<&'a Map<String, Value>> {
    row.as_object()
        .ok_or_else(|| bundle_import_response_error(&format!("{kind} must be an object")))
}

fn bundle_report_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    kind: &str,
) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            bundle_import_response_error(&format!("{kind} {field} must be a non-empty string"))
        })
}

fn bundle_import_response_error(message: &str) -> Error {
    Error::new(
        ErrorKind::Http,
        format!("decoding dashboard bundle import response: {message}"),
    )
}
fn bundle_import_preview(scan: &saved_objects::BundleScan, overwrite: bool) -> MutationPlan {
    let mut dashboards = scan.dashboards.clone();
    dashboards.sort();
    let mut preview_details = dashboards
        .iter()
        .map(|id| format!("dashboard/{id}"))
        .collect::<Vec<_>>();
    preview_details.extend(
        scan.counts
            .iter()
            .filter(|(object_type, _)| object_type.as_str() != "dashboard")
            .map(|(object_type, count)| format!("{object_type}  {count}")),
    );
    let dashboard_count = scan.dashboards.len();
    let related_count = scan.total.saturating_sub(dashboard_count);
    MutationPlan {
        preview_action: format!(
            "{} {} dashboard(s) and {related_count} related saved object(s)",
            if overwrite {
                "Import or replace"
            } else {
                "Import"
            },
            dashboard_count,
        ),
        preview_details,
        targets: scan.dashboards.clone(),
    }
}

fn validate_bundle_import_plan(plan: &BundleImportPlan) -> Result<()> {
    let scan = saved_objects::scan_bundle(&plan.ndjson)?;
    if scan != plan.scan {
        return invalid_plan("bundle scan does not match the planned NDJSON");
    }
    if plan.preview != bundle_import_preview(&scan, plan.overwrite) {
        return invalid_plan("bundle import preview does not match the planned NDJSON");
    }
    Ok(())
}
