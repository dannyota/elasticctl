//! Argument handling for the state commands. Orchestration lives in
//! `elasticctl_api::state`; this module resolves context, applies the guard,
//! and hands the result to render.

use crate::context::Context;
use crate::guard::{self, Preview};
use elasticctl_api::codec::Format as FileFormat;
use elasticctl_api::rules::RuleSource;
use elasticctl_api::state;
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::Value;
use std::path::Path;

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v)
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding report: {e}")))
}

pub async fn pull(
    ctx: &Context,
    dir: &Path,
    format: FileFormat,
    selectors: &[String],
    tag: Option<&str>,
    source: RuleSource,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    to_value(&state::pull_with_source(t, dir, format, selectors, tag, source).await?)
}

pub async fn diff(
    ctx: &Context,
    dir: &Path,
    selectors: &[String],
    tag: Option<&str>,
    source: RuleSource,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    to_value(&state::diff_with_source(t, dir, selectors, tag, source).await?)
}

pub async fn push(
    ctx: &Context,
    dir: &Path,
    report_path: Option<&Path>,
    selectors: &[String],
    tag: Option<&str>,
    source: RuleSource,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let identity = state::StackIdentity {
        profile: ctx.resolved.name.clone(),
        host: ctx.resolved.profile.host(),
        space: ctx.resolved.profile.space.clone(),
    };
    let plan = state::plan_push_with_source(t, dir, selectors, tag, source, &identity).await?;

    let preview = Preview {
        action: plan.preview_action.clone(),
        details: plan.preview_details.clone(),
    };
    // `apply_push` takes no directory: it applies the rules the preview
    // described, not whatever is on disk once the operator answers.
    let plan = if guard::check(ctx, "state push", &preview) {
        state::apply_push(t, plan).await?
    } else {
        plan
    };

    // The change-evidence report is written on both paths. A dry run's report
    // is the reviewable artefact an operator attaches to a change ticket
    // *before* approving it, so skipping it there defeats its purpose.
    if let Some(path) = report_path {
        let body = serde_json::to_string_pretty(&plan.report)
            .map_err(|e| Error::new(ErrorKind::Error, format!("encoding report: {e}")))?;
        std::fs::write(path, body).map_err(|e| {
            Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
        })?;
    }

    to_value(&plan.summary)
}
