//! CLI adapters for dashboard administration. API orchestration stays in
//! `elasticctl_api::dashboards_ops`; this module only supplies context, the
//! mutation guard, artifact delivery, and renderer values.

use crate::context::Context;
use crate::guard::{self, Preview};
use elasticctl_api::content_codec::ContentFormat;
use elasticctl_api::dashboards_ops::{self, DashboardFilter};
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Value, json};
use std::path::Path;

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value)
        .map_err(|error| Error::new(ErrorKind::Error, format!("encoding report: {error}")))
}

pub async fn list(ctx: &Context, filter: &DashboardFilter) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let report = dashboards_ops::list_op(transport, filter).await?;
    to_value(&report.dashboards)
}

pub async fn get(ctx: &Context, selector: &str) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let dashboard = dashboards_ops::get_op(transport, selector).await?;
    Ok(json!({
        "id": dashboard.id,
        "data": dashboard.data,
        "meta": dashboard.meta,
        "warnings": dashboard.warnings,
    }))
}

/// Check a portable file without building a context or transport.
pub fn validate(path: &Path) -> Result<Value> {
    let specs = dashboards_ops::validate(path)?;
    Ok(json!({"valid": true, "total": specs.len()}))
}

/// Validate the entire import artifact before configuration is consulted.
/// `plan_import` remains the authoritative plan builder and validates again.
pub fn validate_import_artifact(path: &Path) -> Result<()> {
    let specs = dashboards_ops::validate(path)?;
    if specs.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "dashboard import needs at least one dashboard",
        ));
    }
    Ok(())
}

pub async fn export(
    ctx: &Context,
    selectors: &[String],
    out: Option<&Path>,
    format: ContentFormat,
) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let outcome = dashboards_ops::export(transport, selectors, format).await?;
    write_artifact(out, outcome.body, outcome.exported, outcome.missing)
}

pub async fn export_bundle(
    ctx: &Context,
    selectors: &[String],
    out: Option<&Path>,
) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let outcome = dashboards_ops::export_bundle(transport, selectors).await?;
    write_artifact(out, outcome.body, outcome.exported, outcome.missing)
}

fn write_artifact(
    out: Option<&Path>,
    body: String,
    exported: u64,
    failed: Vec<Value>,
) -> Result<Value> {
    match out {
        Some(path) => {
            std::fs::write(path, body).map_err(|error| {
                Error::new(
                    ErrorKind::Error,
                    format!("writing {}: {error}", path.display()),
                )
            })?;
            Ok(json!({
                "exported": exported,
                "path": path.display().to_string(),
                "failed": failed,
            }))
        }
        None => Ok(json!({"text": body, "failed": failed})),
    }
}

pub async fn import(
    ctx: &Context,
    path: &Path,
    overwrite: bool,
    skip_existing: bool,
) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let plan = dashboards_ops::plan_import(Some(transport), path, overwrite, skip_existing).await?;
    let preview = Preview {
        action: plan.preview.preview_action.clone(),
        details: plan.preview.preview_details.clone(),
    };
    if !guard::check(ctx, "dashboards import", &preview) {
        return Ok(json!({
            "applied": false,
            "total": plan.total,
            "skipped": plan.skipped,
            "pending": plan.preview.targets.len(),
        }));
    }
    to_value(&dashboards_ops::apply_import(transport, &plan).await?)
}

pub async fn delete(ctx: &Context, selectors: &[String]) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let plan = dashboards_ops::plan_delete(transport, selectors).await?;
    let preview = Preview {
        action: plan.preview.preview_action.clone(),
        details: plan.preview.preview_details.clone(),
    };
    if guard::check(ctx, "dashboards delete", &preview) {
        to_value(&dashboards_ops::apply_delete(transport, &plan).await?)
    } else {
        Ok(json!({"applied": false, "total": plan.targets.len()}))
    }
}

pub async fn bundle_import(ctx: &Context, path: &Path, overwrite: bool) -> Result<Value> {
    let plan = dashboards_ops::plan_bundle_import(path, overwrite)?;
    let preview = Preview {
        action: plan.preview.preview_action.clone(),
        details: plan.preview.preview_details.clone(),
    };
    if !guard::check(ctx, "dashboards bundle import", &preview) {
        return Ok(json!({"applied": false, "total": plan.scan.total}));
    }
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    to_value(&dashboards_ops::apply_bundle_import(transport, &plan).await?)
}
