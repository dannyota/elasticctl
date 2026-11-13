use crate::context::Context;
use crate::guard::{self, Preview};
use crate::resolve;
use elasticctl_api::codec::Format as FileFormat;
use elasticctl_api::model::Rule;
use elasticctl_api::prebuilt;
use elasticctl_api::rules::{RuleFilter, RuleSource};
use elasticctl_api::rules_ops;
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Value, json};
use std::path::Path;

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v)
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding report: {e}")))
}

const MAX_SAMPLE: u32 = 100;

fn summarize(r: &Rule) -> Value {
    json!({
        "rule_id": r.rule_id().unwrap_or(resolve::UNREADABLE_RULE_ID),
        "name": r.name(),
        "type": r.rule_type(),
        "enabled": r.enabled(),
        "severity": r.severity(),
        "risk_score": r.risk_score(),
        "tags": r.tags(),
    })
}

pub async fn list(ctx: &Context, filter: &RuleFilter) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let report = rules_ops::list(transport, filter).await?;
    Ok(Value::Array(report.rules.iter().map(summarize).collect()))
}

pub async fn get(ctx: &Context, selector: &str) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let rule = rules_ops::get_one(transport, selector).await?;
    to_value(&rule)
}

pub fn validate(path: &Path) -> Result<Value> {
    to_value(&rules_ops::validate(path)?)
}

pub async fn set_enabled(ctx: &Context, selectors: &[String], enable: bool) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let plan = rules_ops::plan_set_enabled(t, selectors, enable).await?;
    let preview = Preview {
        action: plan.preview_action.clone(),
        details: plan.preview_details.clone(),
    };
    let path = if enable {
        "rules enable"
    } else {
        "rules disable"
    };
    if guard::check(ctx, path, &preview) {
        to_value(&rules_ops::apply_set_enabled(t, &plan, enable).await?)
    } else {
        Ok(json!({"applied": false, "total": plan.targets.len()}))
    }
}

pub async fn delete(ctx: &Context, selectors: &[String]) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let plan = rules_ops::plan_delete(t, selectors).await?;
    let preview = Preview {
        action: plan.preview_action.clone(),
        details: plan.preview_details.clone(),
    };
    if guard::check(ctx, "rules delete", &preview) {
        to_value(&rules_ops::apply_delete(t, &plan).await?)
    } else {
        Ok(json!({"applied": false, "total": plan.targets.len()}))
    }
}

pub async fn export(
    ctx: &Context,
    selectors: &[String],
    tag: Option<&str>,
    source: RuleSource,
    out: Option<&Path>,
    format: FileFormat,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let outcome = rules_ops::export_rules(t, selectors, tag, source, format).await?;

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
        None => Ok(json!({"text": outcome.body, "failed": outcome.missing})),
    }
}

pub async fn import(
    ctx: &Context,
    path: &Path,
    overwrite: bool,
    skip_existing: bool,
) -> Result<Value> {
    let t = if skip_existing {
        ctx.require_credential()?;
        Some(ctx.transport().await?)
    } else {
        None
    };
    let plan = rules_ops::plan_import(t, path, overwrite, skip_existing).await?;

    let preview = Preview {
        action: plan.preview.preview_action.clone(),
        details: plan.preview.preview_details.clone(),
    };
    if !guard::check(ctx, "rules import", &preview) {
        let pending = plan.preview.targets.len();
        return Ok(json!({
            "applied": false,
            "total": plan.total,
            "skipped": plan.skipped,
            "pending": pending,
        }));
    }

    let t = match t {
        Some(t) => t,
        None => {
            ctx.require_credential()?;
            ctx.transport().await?
        }
    };
    let report = rules_ops::apply_import(t, &plan.ndjson, overwrite).await?;
    Ok(json!({
        "applied": true,
        "succeeded": report.succeeded,
        "failed": report.failed,
        "skipped": plan.skipped,
        "total": plan.total,
    }))
}

pub async fn preview(ctx: &Context, source: &str, invocations: u32, sample: u32) -> Result<Value> {
    ctx.require_credential()?;
    if sample > MAX_SAMPLE {
        return Err(Error::new(
            ErrorKind::Error,
            format!("--sample must be {MAX_SAMPLE} or fewer, got {sample}"),
        ));
    }
    let t = ctx.transport().await?;
    let space = ctx.resolved.profile.space.clone();
    to_value(&rules_ops::preview_rule(t, source, invocations, sample, &space).await?)
}

pub async fn prebuilt_status(ctx: &Context) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    to_value(&prebuilt::status(t).await?)
}

pub async fn prebuilt_install(ctx: &Context) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let (plan, status) = prebuilt::plan_install(t).await?;
    let preview = Preview {
        action: plan.preview_action.clone(),
        details: plan.preview_details.clone(),
    };
    if guard::check(ctx, "rules prebuilt install", &preview) {
        to_value(&prebuilt::apply_install(t).await?)
    } else {
        Ok(json!({
            "applied": false,
            "total": status.not_installed + status.not_updated,
        }))
    }
}
