use super::{parse_file_format, source_to_api};
use crate::cli::{Cli, StateAction};
use crate::cmd;
use crate::context::Context;
use elasticctl_core::Error;
use serde_json::Value;

pub(crate) async fn state(args: &Cli, action: &StateAction) -> Result<Value, Error> {
    match action {
        StateAction::Pull {
            dir,
            format_file,
            selectors,
            tag,
            search,
            source,
        } => match parse_file_format(format_file) {
            Ok(format) => match Context::build(&args.global) {
                Ok(ctx) => {
                    cmd::state::pull(
                        &ctx,
                        dir,
                        format,
                        selectors,
                        tag.as_deref(),
                        search.as_deref(),
                        source_to_api(*source),
                    )
                    .await
                }
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        StateAction::Diff {
            dir,
            selectors,
            tag,
            search,
            source,
        } => match Context::build(&args.global) {
            Ok(ctx) => {
                cmd::state::diff(
                    &ctx,
                    dir,
                    selectors,
                    tag.as_deref(),
                    search.as_deref(),
                    source_to_api(*source),
                )
                .await
            }
            Err(e) => Err(e),
        },
        StateAction::Push {
            dir,
            report,
            selectors,
            tag,
            search,
            source,
        } => match Context::build(&args.global) {
            Ok(ctx) => {
                cmd::state::push(
                    &ctx,
                    dir,
                    report.as_deref(),
                    selectors,
                    tag.as_deref(),
                    search.as_deref(),
                    source_to_api(*source),
                )
                .await
            }
            Err(e) => Err(e),
        },
    }
}
