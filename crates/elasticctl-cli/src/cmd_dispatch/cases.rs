use crate::cli::{CasesAction, Cli};
use crate::cmd;
use crate::context::Context;
use elasticctl_api::cases::CaseStatus;
use elasticctl_core::Error;
use serde_json::Value;

pub(crate) async fn cases(args: &Cli, action: &CasesAction) -> Result<Value, Error> {
    match action {
        CasesAction::List {
            status,
            severity,
            tag,
            search,
            limit,
        } => match Context::build(&args.global) {
            Ok(ctx) => {
                cmd::cases::list(
                    &ctx,
                    status.as_deref(),
                    severity.as_deref(),
                    tag.as_deref(),
                    search.as_deref(),
                    *limit,
                )
                .await
            }
            Err(e) => Err(e),
        },
        CasesAction::Get { case_id } => match Context::build(&args.global) {
            Ok(ctx) => cmd::cases::get(&ctx, case_id).await,
            Err(e) => Err(e),
        },
        CasesAction::Create {
            title,
            description,
            tag,
            severity,
            assignee,
        } => match Context::build(&args.global) {
            Ok(ctx) => {
                cmd::cases::create(
                    &ctx,
                    title,
                    description.as_deref(),
                    tag,
                    severity.as_deref(),
                    assignee,
                )
                .await
            }
            Err(e) => Err(e),
        },
        CasesAction::Close { case_ids } => match Context::build(&args.global) {
            Ok(ctx) => cmd::cases::status(&ctx, case_ids, CaseStatus::Closed).await,
            Err(e) => Err(e),
        },
        CasesAction::Open { case_ids } => match Context::build(&args.global) {
            Ok(ctx) => cmd::cases::status(&ctx, case_ids, CaseStatus::Open).await,
            Err(e) => Err(e),
        },
        CasesAction::Delete { case_ids } => match Context::build(&args.global) {
            Ok(ctx) => cmd::cases::delete(&ctx, case_ids).await,
            Err(e) => Err(e),
        },
        CasesAction::Attach { case_id, alert } => match Context::build(&args.global) {
            Ok(ctx) => cmd::cases::attach(&ctx, case_id, alert).await,
            Err(e) => Err(e),
        },
        CasesAction::Comment { case_id, message } => match Context::build(&args.global) {
            Ok(ctx) => cmd::cases::comment(&ctx, case_id, message).await,
            Err(e) => Err(e),
        },
    }
}
