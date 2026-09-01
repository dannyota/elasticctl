//! CLI adapters for data-view administration. API orchestration stays in
//! `elasticctl_api::data_views_ops`; this module only supplies context, the
//! mutation guard, artifact delivery, and renderer values.

use crate::context::Context;
use crate::guard::{self, Preview};
use elasticctl_api::content_codec::ContentFormat;
use elasticctl_api::data_views_ops::{self, DataViewFilter};
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Value, json};
use std::path::Path;

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value)
        .map_err(|error| Error::new(ErrorKind::Error, format!("encoding report: {error}")))
}

pub async fn list(ctx: &Context, search: Option<String>) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let report = data_views_ops::list_op(transport, &DataViewFilter { search }).await?;
    Ok(Value::Array(
        report
            .data_views
            .iter()
            .map(|view| {
                json!({
                    "id": view.id,
                    "name": view.name,
                    "title": view.title,
                    "time_field_name": view.time_field_name,
                })
            })
            .collect(),
    ))
}

pub async fn get(ctx: &Context, selector: &str) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    Ok(Value::Object(
        data_views_ops::get_op(transport, selector).await?.data_view,
    ))
}

/// Check a portable file without building a context or transport.
pub fn validate(path: &Path) -> Result<Value> {
    let specs = data_views_ops::validate(path)?;
    Ok(json!({"valid": true, "total": specs.len()}))
}

/// Validate the entire import artifact before configuration is consulted.
/// `plan_import` remains the authoritative plan builder and validates again.
pub fn validate_import_artifact(path: &Path) -> Result<()> {
    let specs = data_views_ops::validate(path)?;
    if specs.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "data-view import needs at least one data view",
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
    let outcome = data_views_ops::export(transport, selectors, format).await?;
    match out {
        Some(path) => {
            std::fs::write(path, &outcome.body).map_err(|error| {
                Error::new(
                    ErrorKind::Error,
                    format!("writing {}: {error}", path.display()),
                )
            })?;
            Ok(json!({
                "exported": outcome.exported,
                "path": path.display().to_string(),
                "failed": outcome.missing,
            }))
        }
        None => Ok(json!({"text": outcome.body, "failed": outcome.missing})),
    }
}

pub async fn import(
    ctx: &Context,
    path: &Path,
    overwrite: bool,
    skip_existing: bool,
) -> Result<Value> {
    // A no-flag dry run is entirely local. Any mode that may apply or inspect
    // conflicts uses the authenticated preflight and retains its API plan.
    let needs_server_preflight = ctx.global.yes || overwrite || skip_existing;
    let transport = if needs_server_preflight {
        ctx.require_credential()?;
        Some(ctx.transport().await?)
    } else {
        None
    };
    let plan = data_views_ops::plan_import(transport, path, overwrite, skip_existing).await?;
    let preview = Preview {
        action: plan.preview.preview_action.clone(),
        details: plan.preview.preview_details.clone(),
    };
    if !guard::check(ctx, "data-views import", &preview) {
        return Ok(json!({
            "applied": false,
            "total": plan.total,
            "skipped": plan.skipped,
            "pending": plan.preview.targets.len(),
        }));
    }
    let transport = transport.expect("--yes requires an authenticated import preflight");
    to_value(&data_views_ops::apply_import(transport, &plan).await?)
}

pub async fn delete(
    ctx: &Context,
    selectors: &[String],
    replacement: Option<&str>,
) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let plan = data_views_ops::plan_delete(transport, selectors, replacement).await?;
    let preview = Preview {
        action: plan.preview.preview_action.clone(),
        details: plan.preview.preview_details.clone(),
    };
    if guard::check(ctx, "data-views delete", &preview) {
        to_value(&data_views_ops::apply_delete(transport, &plan).await?)
    } else {
        Ok(json!({"applied": false, "total": plan.targets.len()}))
    }
}

pub async fn default_get(ctx: &Context) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    Ok(json!({"data_view_id": elasticctl_api::data_views::get_default(transport).await?}))
}

pub async fn default_set(ctx: &Context, selector: &str) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let plan = data_views_ops::plan_default_set(transport, selector).await?;
    let preview = Preview {
        action: plan.preview.preview_action.clone(),
        details: plan.preview.preview_details.clone(),
    };
    if guard::check(ctx, "data-views default set", &preview) {
        data_views_ops::apply_default(transport, &plan).await?;
        Ok(json!({"applied": true, "data_view_id": plan.after}))
    } else {
        Ok(json!({"applied": false, "data_view_id": plan.after}))
    }
}

pub async fn default_unset(ctx: &Context) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let plan = data_views_ops::plan_default_unset(transport).await?;
    let preview = Preview {
        action: plan.preview.preview_action.clone(),
        details: plan.preview.preview_details.clone(),
    };
    if guard::check(ctx, "data-views default unset", &preview) {
        data_views_ops::apply_default(transport, &plan).await?;
        Ok(json!({"applied": true, "data_view_id": Value::Null}))
    } else {
        Ok(json!({"applied": false, "data_view_id": Value::Null}))
    }
}
