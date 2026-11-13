use super::parse_content_format;
use crate::cli::{Cli, DataViewDefaultAction, DataViewsAction};
use crate::cmd;
use crate::context::Context;
use elasticctl_core::Error;
use serde_json::Value;

pub(crate) async fn data_views(args: &Cli, action: &DataViewsAction) -> Result<Value, Error> {
    match action {
        DataViewsAction::List { search } => match Context::build(&args.global) {
            Ok(ctx) => cmd::data_views::list(&ctx, search.clone()).await,
            Err(e) => Err(e),
        },
        DataViewsAction::Get { selector } => match Context::build(&args.global) {
            Ok(ctx) => cmd::data_views::get(&ctx, selector).await,
            Err(e) => Err(e),
        },
        DataViewsAction::Validate { path } => cmd::data_views::validate(path),
        DataViewsAction::Export {
            selectors,
            format_file,
        } => match parse_content_format(format_file) {
            Ok(format) => match Context::build(&args.global) {
                Ok(ctx) => {
                    cmd::data_views::export(&ctx, selectors, args.global.out.as_deref(), format)
                        .await
                }
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        DataViewsAction::Import {
            path,
            overwrite,
            skip_existing,
        } => match cmd::data_views::validate_import_artifact(path) {
            Ok(()) => match Context::build(&args.global) {
                Ok(ctx) => cmd::data_views::import(&ctx, path, *overwrite, *skip_existing).await,
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        DataViewsAction::Delete {
            selectors,
            replace_with,
        } => match Context::build(&args.global) {
            Ok(ctx) => cmd::data_views::delete(&ctx, selectors, replace_with.as_deref()).await,
            Err(e) => Err(e),
        },
        DataViewsAction::Default { action } => match action {
            DataViewDefaultAction::Get => match Context::build(&args.global) {
                Ok(ctx) => cmd::data_views::default_get(&ctx).await,
                Err(e) => Err(e),
            },
            DataViewDefaultAction::Set { selector } => match Context::build(&args.global) {
                Ok(ctx) => cmd::data_views::default_set(&ctx, selector).await,
                Err(e) => Err(e),
            },
            DataViewDefaultAction::Unset => match Context::build(&args.global) {
                Ok(ctx) => cmd::data_views::default_unset(&ctx).await,
                Err(e) => Err(e),
            },
        },
    }
}
