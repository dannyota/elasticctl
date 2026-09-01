//! Adapters for the `alerts` command group: flags to filters, and
//! serialization for render. Covers reads (`list`, `get`) and the guarded
//! mutations (status transitions, tags, assignees).

use crate::context::Context;
use crate::guard::{self, Preview};
use elasticctl_api::alerts::{AlertHit, AlertStatus, Conflicts};
use elasticctl_api::alerts_ops::{self, AlertFilter};
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Value, json};

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v)
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding report: {e}")))
}

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

/// `--query` takes inline JSON or `@path`, the `search dsl` convention.
fn parse_query(raw: &str) -> Result<Value> {
    let text = if let Some(path) = raw.strip_prefix('@') {
        std::fs::read_to_string(path)
            .map_err(|e| Error::new(ErrorKind::Error, format!("reading {path}: {e}")))?
    } else {
        raw.to_string()
    };
    serde_json::from_str(&text)
        .map_err(|e| Error::new(ErrorKind::Error, format!("parsing --query: {e}")))
}

fn guard_path(status: AlertStatus) -> &'static str {
    match status {
        AlertStatus::Open => "alerts open",
        AlertStatus::Acknowledged => "alerts ack",
        AlertStatus::Closed => "alerts close",
    }
}

/// Shared adapter for `ack`, `open`, and `close`.
pub async fn transition(
    ctx: &Context,
    alert_ids: &[String],
    query: Option<&str>,
    status: AlertStatus,
    reason: Option<&str>,
    conflicts: Option<&str>,
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let conflicts = conflicts
        .map(Conflicts::parse)
        .transpose()?
        .unwrap_or_default();
    match (alert_ids.is_empty(), query) {
        (false, None) => {
            let plan =
                alerts_ops::plan_status_by_ids(t, alert_ids, status, reason.map(str::to_owned))
                    .await?;
            let preview = Preview {
                action: plan.preview_action.clone(),
                details: plan.preview_details.clone(),
            };
            if guard::check(ctx, guard_path(status), &preview) {
                to_value(&alerts_ops::apply_status_by_ids(t, &plan).await?)
            } else {
                Ok(json!({"applied": false, "total": plan.targets.len()}))
            }
        }
        (true, Some(raw)) => {
            let query = parse_query(raw)?;
            let plan = alerts_ops::plan_status_by_query(
                t,
                query,
                status,
                conflicts,
                reason.map(str::to_owned),
            )
            .await?;
            let preview = Preview {
                action: plan.preview_action.clone(),
                details: plan.preview_details.clone(),
            };
            if guard::check(ctx, guard_path(status), &preview) {
                to_value(&alerts_ops::apply_status_by_query(t, &plan).await?)
            } else {
                Ok(json!({"applied": false, "matched": plan.matched}))
            }
        }
        (true, None) => Err(Error::new(
            ErrorKind::Error,
            "pass one or more alert ids, or --query",
        )),
        // clap's conflicts_with already blocks this; keep the guard honest.
        (false, Some(_)) => Err(Error::new(
            ErrorKind::Error,
            "--query and alert ids are mutually exclusive",
        )),
    }
}

pub async fn tag(
    ctx: &Context,
    alert_ids: &[String],
    add: &[String],
    remove: &[String],
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let plan = alerts_ops::plan_tags(t, alert_ids, add.to_vec(), remove.to_vec()).await?;
    let preview = Preview {
        action: plan.preview_action.clone(),
        details: plan.preview_details.clone(),
    };
    if guard::check(ctx, "alerts tag", &preview) {
        to_value(&alerts_ops::apply_tags(t, &plan).await?)
    } else {
        Ok(json!({"applied": false, "total": plan.targets.len()}))
    }
}

pub async fn assign(
    ctx: &Context,
    alert_ids: &[String],
    add: &[String],
    remove: &[String],
) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let plan = alerts_ops::plan_assign(t, alert_ids, add, remove).await?;
    let preview = Preview {
        action: plan.preview_action.clone(),
        details: plan.preview_details.clone(),
    };
    if guard::check(ctx, "alerts assign", &preview) {
        to_value(&alerts_ops::apply_assign(t, &plan).await?)
    } else {
        Ok(json!({"applied": false, "total": plan.targets.len()}))
    }
}
