use crate::context::Context;
use crate::guard::{self, Preview};
use crate::report_file;
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
    search: Option<&str>,
    source: RuleSource,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    to_value(&state::pull(t, dir, format, selectors, tag, search, source).await?)
}

pub async fn diff(
    ctx: &Context,
    dir: &Path,
    selectors: &[String],
    tag: Option<&str>,
    search: Option<&str>,
    source: RuleSource,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    to_value(&state::diff(t, dir, selectors, tag, search, source).await?)
}

pub async fn push(
    ctx: &Context,
    dir: &Path,
    report_path: Option<&Path>,
    selectors: &[String],
    tag: Option<&str>,
    search: Option<&str>,
    source: RuleSource,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let identity = state::StackIdentity {
        profile: ctx.resolved.name.clone(),
        host: ctx.resolved.profile.host(),
        space: ctx.resolved.profile.space.clone(),
    };
    let plan = state::plan_push(t, dir, selectors, tag, search, source, &identity).await?;

    let prepared_report = report_path
        .map(|path| report_file::prepare_report(path, &plan.report))
        .transpose()?;

    let preview = Preview {
        action: plan.preview_action.clone(),
        details: plan.preview_details.clone(),
    };
    let plan = if guard::check(ctx, "state push", &preview) {
        state::apply_push(t, plan).await?
    } else {
        plan
    };

    if let Some(prepared) = prepared_report {
        let path = prepared.requested_path().to_path_buf();
        prepared.publish(&plan.report).map_err(|error| {
            report_file::report_publication_error(plan.report.applied, &path, error)
        })?;
    }

    to_value(&plan.summary)
}
