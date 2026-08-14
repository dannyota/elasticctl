//! Argument handling for the exceptions commands. Orchestration lives in
//! `elasticctl_api::exceptions`; this module resolves context, applies the
//! guard, and hands the result to render.

use crate::context::Context;
use crate::guard::{self, Preview};
use elasticctl_api::codec::Format as FileFormat;
use elasticctl_api::exceptions::{self, ListFilter};
use elasticctl_api::model::ExceptionList;
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Value, json};
use std::path::Path;

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v)
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding report: {e}")))
}

/// Summary shown by `exceptions list`. Use `exceptions get` or
/// `exceptions export` for full container bodies. `namespace_type` is part of
/// identity, so it is always shown (spec 4.5).
fn summarize(l: &ExceptionList) -> Value {
    json!({
        "list_id": l.list_id().unwrap_or(""),
        "name": l.name(),
        "type": l.list_type(),
        "namespace_type": l.namespace_type(),
        "tags": l.tags(),
    })
}

pub async fn list(ctx: &Context, filter: &ListFilter) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let report = exceptions::list_op(transport, filter).await?;
    Ok(Value::Array(report.lists.iter().map(summarize).collect()))
}

pub async fn get(ctx: &Context, list_id: &str, namespace: Option<&str>) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let detail = exceptions::get_op(transport, list_id, namespace).await?;
    to_value(&detail)
}

/// Check an exception file without contacting a server.
pub fn validate(path: &Path) -> Result<Value> {
    let bundle = exceptions::validate_op(path)?;
    Ok(json!({
        "valid": true,
        "lists": bundle.lists.len(),
        "items": bundle.items.len(),
    }))
}

pub async fn export(
    ctx: &Context,
    list_ids: &[String],
    tag: Option<&str>,
    namespace: Option<&str>,
    out: Option<&Path>,
    format: FileFormat,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let outcome = exceptions::export_op(t, list_ids, tag, namespace, format).await?;

    match out {
        Some(path) => {
            std::fs::write(path, &outcome.body).map_err(|e| {
                Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
            })?;
            Ok(json!({
                "exported": outcome.exported,
                "path": path.display().to_string(),
                "failed": outcome.missing,
            }))
        }
        // Spec 6.2: without `--out`, stdout is the file, verbatim under every
        // `--format`. The body is not a report, so return it for `main` to
        // write directly rather than routing it through `render::emit`.
        None => Ok(json!({"text": outcome.body, "failed": outcome.missing})),
    }
}

pub async fn delete(ctx: &Context, list_ids: &[String], namespace: Option<&str>) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let plan = exceptions::plan_delete_op(t, list_ids, namespace).await?;
    let preview = Preview {
        action: plan.preview.preview_action.clone(),
        details: plan.preview.preview_details.clone(),
    };
    if guard::check(ctx, "exceptions delete", &preview) {
        to_value(&exceptions::apply_delete_op(t, &plan).await?)
    } else {
        Ok(json!({"applied": false, "total": plan.preview.targets.len()}))
    }
}

pub async fn import(
    ctx: &Context,
    path: &Path,
    overwrite: bool,
    skip_existing: bool,
) -> Result<Value> {
    // A dry run that only reads the file must not require a credential. Build
    // the transport only for the --skip-existing read; the file itself is read
    // in `plan_import_op` before any server call.
    let t = if skip_existing {
        ctx.require_credential()?;
        Some(ctx.transport().await?)
    } else {
        None
    };
    let plan = exceptions::plan_import_op(t, path, overwrite, skip_existing).await?;

    let preview = Preview {
        action: plan.preview.preview_action.clone(),
        details: plan.preview.preview_details.clone(),
    };
    if !guard::check(ctx, "exceptions import", &preview) {
        let pending = plan.preview.targets.len();
        return Ok(json!({
            "applied": false,
            "total": plan.total,
            "skipped": plan.skipped,
            "pending": pending,
        }));
    }

    // The upload always reaches the server. The --skip-existing read already
    // built the transport; otherwise build it now.
    let t = match t {
        Some(t) => t,
        None => {
            ctx.require_credential()?;
            ctx.transport().await?
        }
    };
    let report = exceptions::apply_import_op(t, &plan.ndjson, overwrite).await?;
    Ok(json!({
        "applied": true,
        "succeeded": report.succeeded,
        "failed": report.failed,
        "skipped": plan.skipped,
        "total": plan.total,
    }))
}
