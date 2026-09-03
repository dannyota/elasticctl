//! CLI adapters for Fleet policy administration. API orchestration stays in
//! `elasticctl_api::fleet`; this module only supplies context, the mutation
//! guard, artifact delivery, and renderer values.

use crate::context::Context;
use crate::guard::{self, Preview};
use elasticctl_api::content_codec::ContentFormat;
use elasticctl_api::fleet::agent_policy_ops::{self, AgentPolicyFilter};
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Value, json};
use std::path::Path;

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value)
        .map_err(|error| Error::new(ErrorKind::Error, format!("encoding report: {error}")))
}

pub async fn list(ctx: &Context, filter: &AgentPolicyFilter) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let report = agent_policy_ops::list_op(transport, filter).await?;
    if report.truncated {
        eprintln!(
            "capped at {} rows",
            filter.limit.expect("truncated lists have a limit")
        );
    }
    to_value(&report.agent_policies)
}

pub async fn get(ctx: &Context, selector: &str) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    to_value(&agent_policy_ops::get_op(transport, selector).await?)
}

/// Check a portable file without building a context or transport.
pub fn validate(path: &Path) -> Result<Value> {
    let specs = agent_policy_ops::validate(path)?;
    Ok(json!({"valid": true, "total": specs.len()}))
}

/// Validate the entire import artifact before configuration is consulted.
pub fn validate_import_artifact(path: &Path) -> Result<()> {
    if agent_policy_ops::validate(path)?.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "agent-policy import needs at least one agent policy",
        ));
    }
    Ok(())
}

pub async fn export(
    ctx: &Context,
    selectors: &[String],
    all_custom: bool,
    out: Option<&Path>,
    format: ContentFormat,
) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let outcome = agent_policy_ops::export(transport, selectors, all_custom, format).await?;
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
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let plan = agent_policy_ops::plan_import(transport, path, overwrite, skip_existing).await?;
    let preview = Preview {
        action: plan.preview.preview_action.clone(),
        details: plan.preview.preview_details.clone(),
    };
    if !guard::check(ctx, "fleet agent-policies import", &preview) {
        return Ok(json!({
            "applied": false,
            "total": plan.total,
            "skipped": plan.skipped,
            "pending": plan.preview.targets.len(),
            "package_installs": plan.package_installs,
        }));
    }
    to_value(&agent_policy_ops::apply_import(transport, &plan).await?)
}

pub async fn delete(ctx: &Context, selectors: &[String]) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let plan = agent_policy_ops::plan_delete(transport, selectors).await?;
    let preview = Preview {
        action: plan.preview.preview_action.clone(),
        details: plan.preview.preview_details.clone(),
    };
    if guard::check(ctx, "fleet agent-policies delete", &preview) {
        to_value(&agent_policy_ops::apply_delete(transport, &plan).await?)
    } else {
        Ok(json!({"applied": false, "total": plan.targets.len()}))
    }
}
