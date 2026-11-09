use crate::cli::{AlertsAction, Cli};
use crate::cmd;
use crate::context::Context;
use elasticctl_api::alerts::AlertStatus;
use elasticctl_core::Error;
use serde_json::Value;

pub(crate) async fn alerts(args: &Cli, action: &AlertsAction) -> Result<Value, Error> {
    match action {
        AlertsAction::List {
            status,
            severity,
            rule,
            tag,
            assignee,
            since,
            search,
            limit,
            with_meta,
        } => match Context::build(&args.global) {
            Ok(ctx) => {
                cmd::alerts::list(
                    &ctx,
                    status.as_deref(),
                    severity.as_deref(),
                    rule.as_deref(),
                    tag.as_deref(),
                    assignee.as_deref(),
                    since.as_deref(),
                    search.as_deref(),
                    *limit,
                    *with_meta,
                )
                .await
            }
            Err(e) => Err(e),
        },
        AlertsAction::Get { alert_id } => match Context::build(&args.global) {
            Ok(ctx) => cmd::alerts::get(&ctx, alert_id).await,
            Err(e) => Err(e),
        },
        AlertsAction::Ack { alert_ids, query } => match Context::build(&args.global) {
            Ok(ctx) => {
                cmd::alerts::transition(
                    &ctx,
                    alert_ids,
                    query.as_deref(),
                    AlertStatus::Acknowledged,
                    None,
                    None,
                )
                .await
            }
            Err(e) => Err(e),
        },
        AlertsAction::Open { alert_ids, query } => match Context::build(&args.global) {
            Ok(ctx) => {
                cmd::alerts::transition(
                    &ctx,
                    alert_ids,
                    query.as_deref(),
                    AlertStatus::Open,
                    None,
                    None,
                )
                .await
            }
            Err(e) => Err(e),
        },
        AlertsAction::Close {
            alert_ids,
            query,
            reason,
            conflicts,
        } => match Context::build(&args.global) {
            Ok(ctx) => {
                cmd::alerts::transition(
                    &ctx,
                    alert_ids,
                    query.as_deref(),
                    AlertStatus::Closed,
                    reason.as_deref(),
                    conflicts.as_deref(),
                )
                .await
            }
            Err(e) => Err(e),
        },
        AlertsAction::Tag {
            alert_ids,
            add,
            remove,
        } => match Context::build(&args.global) {
            Ok(ctx) => cmd::alerts::tag(&ctx, alert_ids, add, remove).await,
            Err(e) => Err(e),
        },
        AlertsAction::Assign {
            alert_ids,
            add,
            remove,
        } => match Context::build(&args.global) {
            Ok(ctx) => cmd::alerts::assign(&ctx, alert_ids, add, remove).await,
            Err(e) => Err(e),
        },
    }
}
