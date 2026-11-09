use crate::cli::{Cli, SearchAction};
use crate::cmd;
use crate::context::Context;
use elasticctl_core::Error;
use serde_json::Value;

pub(crate) async fn search(args: &Cli, action: &SearchAction) -> Result<Value, Error> {
    match action {
        SearchAction::Esql {
            query,
            data_view,
            index,
            limit,
        } => match Context::build(&args.global) {
            Ok(ctx) => {
                cmd::search::esql(&ctx, query, data_view.as_deref(), index.as_deref(), *limit).await
            }
            Err(e) => Err(e),
        },
        SearchAction::Dsl {
            body,
            data_view,
            index,
            limit,
            with_meta,
        } => match Context::build(&args.global) {
            Ok(ctx) => {
                cmd::search::dsl(
                    &ctx,
                    body,
                    data_view.as_deref(),
                    index.as_deref(),
                    *limit,
                    *with_meta,
                )
                .await
            }
            Err(e) => Err(e),
        },
    }
}
