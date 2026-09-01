//! Adapters for the `cases` command group.

use crate::context::Context;
use elasticctl_api::cases::CaseStatus;
use elasticctl_api::cases_ops::{self, CaseFilter};
use elasticctl_core::Result;
use serde_json::Value;

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
        let mut cases = cases_ops::export(t, &filter).await?;
        if let Some(limit) = limit {
            cases.truncate(limit);
        }
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
