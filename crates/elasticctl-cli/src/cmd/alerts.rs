//! Adapters for the `alerts` command group: flags to filters, and
//! serialization for render. Read-only in this task; the mutation adapters
//! (status, tags, assign) arrive in Task 7.

use crate::context::Context;
use elasticctl_api::alerts::{AlertHit, AlertStatus};
use elasticctl_api::alerts_ops::{self, AlertFilter};
use elasticctl_core::Result;
use serde_json::Value;

/// The rendered alert row is the hit's `_source`; `--with-meta` merges the
/// document `_id` — the identity every mutation takes — into the object.
fn alert_row(hit: &AlertHit, with_meta: bool) -> Value {
    if !with_meta {
        return hit.source.clone();
    }
    let mut row = hit.source.as_object().cloned().unwrap_or_default();
    row.insert("_id".into(), Value::String(hit.id.clone()));
    Value::Object(row)
}

#[allow(clippy::too_many_arguments)]
pub async fn list(
    ctx: &Context,
    status: Option<&str>,
    severity: Option<&str>,
    rule: Option<&str>,
    tag: Option<&str>,
    assignee: Option<&str>,
    since: Option<&str>,
    search: Option<&str>,
    limit: Option<usize>,
    with_meta: bool,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let filter = AlertFilter {
        status: status.map(AlertStatus::parse).transpose()?,
        severity: severity.map(str::to_owned),
        rule: rule.map(str::to_owned),
        tag: tag.map(str::to_owned),
        assignee: assignee.map(str::to_owned),
        since: since.map(str::to_owned),
        search: search.map(str::to_owned),
    };
    if ctx.global.out.is_some() {
        let hits = alerts_ops::export(t, &filter).await?;
        return Ok(Value::Array(
            hits.iter().map(|h| alert_row(h, with_meta)).collect(),
        ));
    }
    let cap = limit.unwrap_or(100);
    let out = alerts_ops::list(t, &filter, cap).await?;
    if out.truncated {
        // Match cmd/search.rs's peek truncation notice verbatim so the two
        // read paths report the same way.
        eprintln!("capped at {cap} rows");
    }
    Ok(Value::Array(
        out.hits.iter().map(|h| alert_row(h, with_meta)).collect(),
    ))
}

pub async fn get(ctx: &Context, alert_id: &str) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let hit = alerts_ops::get_one(t, alert_id).await?;
    // The id identifies the document the operator asked for; merge it always.
    Ok(alert_row(&hit, true))
}
