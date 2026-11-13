use crate::context::Context;
use crate::render;
use crate::report_file;
use elasticctl_api::codec::Format as FileFormat;
use elasticctl_api::rules::RuleSource;
use elasticctl_api::state;
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::Value;
use std::path::Path;

mod value_lists;

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

    let plan = if value_lists::check(ctx, &plan)? {
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

    let mut summary = to_value(&plan.summary)?;
    let failure = plan
        .value_list_outcomes
        .iter()
        .find_map(|list| list.error.as_ref());
    if value_lists::changed(&plan) || failure.is_some() {
        summary["value_lists"] = to_value(&plan.value_list_outcomes)?;
    }
    if let Some(failure) = failure {
        render::emit(&summary, &ctx.global)?;
        let kind = match failure.kind.as_str() {
            "auth" => ErrorKind::Auth,
            "permission" => ErrorKind::Permission,
            "not_found" => ErrorKind::NotFound,
            "conflict" => ErrorKind::Conflict,
            "unsupported" => ErrorKind::Unsupported,
            "http" => ErrorKind::Http,
            "connection" => ErrorKind::Connection,
            "timeout" => ErrorKind::Timeout,
            _ => ErrorKind::Error,
        };
        return Err(Error {
            kind,
            http_status: failure.status,
            message: failure.message.clone(),
        });
    }
    Ok(summary)
}
