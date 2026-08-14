//! Argument handling for the rules commands. Orchestration lives in
//! `elasticctl_api::rules_ops`; this module resolves context, applies the
//! guard, and hands the result to render.

use crate::context::Context;
use crate::guard::{self, Preview};
use crate::resolve;
use elasticctl_api::codec::Format as FileFormat;
use elasticctl_api::model::Rule;
use elasticctl_api::rules::RuleFilter;
use elasticctl_api::rules_ops;
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Value, json};
use std::path::Path;

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v)
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding report: {e}")))
}

/// Maximum matched documents returned with a preview.
const MAX_SAMPLE: u32 = 100;

/// Summary shown by `rules list`. Use `rules get` or `rules export` for full
/// rule bodies.
///
/// An unreadable `rule_id` is a server anomaly. Flag it as
/// `resolve::UNREADABLE_RULE_ID` instead of hiding it or failing the listing.
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
    // Check the credential first so a missing one names the profile instead
    // of returning Transport's generic error.
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

/// Check a rule file without contacting a server.
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
    // Derive the guard path from the flag that selects the verb so it cannot
    // name the wrong mutating command.
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
    out: Option<&Path>,
    format: FileFormat,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let outcome = rules_ops::export_rules(t, selectors, tag, format).await?;

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
        // Spec 6.2: without `--out`, stdout is the rule file, verbatim under
        // every `--format`. The body is not a report, so return it for `main`
        // to write directly rather than routing it through `render::emit`.
        None => Ok(json!({"text": outcome.body, "failed": outcome.missing})),
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
    // in `plan_import` before any server call.
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

    // The upload always reaches the server. The --skip-existing read already
    // built the transport; otherwise build it now.
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
    // Preview posts to the server for both local and stack rules. Check the
    // credential first so a missing one names the profile, then the sample cap
    // before building a transport.
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
