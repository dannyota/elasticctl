//! Adapters for the `cases` command group.

use crate::context::Context;
use crate::guard::{self, Preview};
use elasticctl_api::cases::CaseStatus;
use elasticctl_api::cases_ops::{self, CaseFilter};
use elasticctl_core::Result;
use serde_json::{Value, json};

pub async fn list(
    ctx: &Context,
    status: Option<&str>,
    severity: Option<&str>,
    tag: Option<&str>,
    search: Option<&str>,
    limit: Option<usize>,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let filter = CaseFilter {
        status: status.map(CaseStatus::parse).transpose()?,
        severity: severity.map(str::to_owned),
        tag: tag.map(str::to_owned),
        search: search.map(str::to_owned),
    };
    if ctx.global.out.is_some() {
        let cases = cases_ops::export(t, &filter, limit).await?;
        return Ok(Value::Array(
            cases.iter().map(cases_ops::case_row).collect(),
        ));
    }
    let cap = limit.unwrap_or(100);
    let out = cases_ops::list(t, &filter, cap).await?;
    if out.truncated {
        eprintln!("capped at {cap} rows");
    }
    Ok(Value::Array(
        out.cases.iter().map(cases_ops::case_row).collect(),
    ))
}

pub async fn get(ctx: &Context, case_id: &str) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let case = cases_ops::get_one(t, case_id).await?;
    serde_json::to_value(&case).map_err(|e| {
        elasticctl_core::Error::new(
            elasticctl_core::ErrorKind::Error,
            format!("encoding case: {e}"),
        )
    })
}

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v).map_err(|e| {
        elasticctl_core::Error::new(
            elasticctl_core::ErrorKind::Error,
            format!("encoding report: {e}"),
        )
    })
}

fn preview_of(action: &str, details: &[String]) -> Preview {
    Preview {
        action: action.to_string(),
        details: details.to_vec(),
    }
}

pub async fn create(
    ctx: &Context,
    title: &str,
    description: Option<&str>,
    tags: &[String],
    severity: Option<&str>,
    assignees: &[String],
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let plan = cases_ops::plan_create(
        t,
        title,
        description.map(str::to_owned),
        tags.to_vec(),
        severity.map(str::to_owned),
        assignees,
    )
    .await?;
    let preview = preview_of(&plan.preview_action, &plan.preview_details);
    if guard::check(ctx, "cases create", &preview) {
        cases_ops::apply_create(t, &plan).await
    } else {
        Ok(json!({"applied": false, "title": plan.new.title}))
    }
}

/// Shared adapter for `cases close` and `cases open`.
pub async fn status(ctx: &Context, case_ids: &[String], target: CaseStatus) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    if case_ids.is_empty() {
        return Err(elasticctl_core::Error::new(
            elasticctl_core::ErrorKind::Error,
            "pass one or more case ids",
        ));
    }
    let plan = cases_ops::plan_status(t, case_ids, target).await?;
    let preview = preview_of(&plan.preview_action, &plan.preview_details);
    let guard_path = match target {
        CaseStatus::Closed => "cases close",
        _ => "cases open",
    };
    if guard::check(ctx, guard_path, &preview) {
        to_value(&cases_ops::apply_status(t, &plan).await?)
    } else {
        Ok(json!({"applied": false, "total": case_ids.len()}))
    }
}

pub async fn delete(ctx: &Context, case_ids: &[String]) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    if case_ids.is_empty() {
        return Err(elasticctl_core::Error::new(
            elasticctl_core::ErrorKind::Error,
            "pass one or more case ids",
        ));
    }
    let plan = cases_ops::plan_delete(t, case_ids).await?;
    let preview = preview_of(&plan.preview_action, &plan.preview_details);
    if guard::check(ctx, "cases delete", &preview) {
        to_value(&cases_ops::apply_delete(t, &plan).await?)
    } else {
        Ok(json!({"applied": false, "total": plan.targets.len()}))
    }
}

pub async fn attach(ctx: &Context, case_id: &str, alerts: &[String]) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let plan = cases_ops::plan_attach(t, case_id, alerts).await?;
    let preview = preview_of(&plan.preview_action, &plan.preview_details);
    if guard::check(ctx, "cases attach", &preview) {
        to_value(&cases_ops::apply_attach(t, &plan).await?)
    } else {
        Ok(json!({"applied": false, "total": alerts.len()}))
    }
}

pub async fn comment(ctx: &Context, case_id: &str, message: &str) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let plan = cases_ops::plan_comment(t, case_id, message).await?;
    let preview = preview_of(&plan.preview_action, &plan.preview_details);
    if guard::check(ctx, "cases comment", &preview) {
        to_value(&cases_ops::apply_comment(t, &plan).await?)
    } else {
        Ok(json!({"applied": false}))
    }
}
