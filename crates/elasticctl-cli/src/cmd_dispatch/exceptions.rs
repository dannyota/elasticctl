use super::parse_file_format;
use crate::cli::{Cli, ExceptionsAction};
use crate::cmd;
use crate::context::Context;
use elasticctl_api::exceptions::ListFilter;
use elasticctl_core::{Error, ErrorKind};
use serde_json::Value;

pub(crate) async fn exceptions(args: &Cli, action: &ExceptionsAction) -> Result<Value, Error> {
    match action {
        ExceptionsAction::List {
            list_type,
            tag,
            namespace,
            search,
        } => {
            let f = ListFilter {
                list_type: list_type.clone(),
                tag: tag.clone(),
                namespace: namespace.clone(),
                search: search.clone(),
            };
            match Context::build(&args.global) {
                Ok(ctx) => cmd::exceptions::list(&ctx, &f).await,
                Err(e) => Err(e),
            }
        }
        ExceptionsAction::Get { list_id, namespace } => match Context::build(&args.global) {
            Ok(ctx) => cmd::exceptions::get(&ctx, list_id, namespace.as_deref()).await,
            Err(e) => Err(e),
        },
        ExceptionsAction::Validate { path } => cmd::exceptions::validate(path),
        ExceptionsAction::Export {
            list_ids,
            tag,
            namespace,
            format_file,
        } => match parse_file_format(format_file) {
            Ok(format) => match Context::build(&args.global) {
                Ok(ctx) => {
                    cmd::exceptions::export(
                        &ctx,
                        list_ids,
                        tag.as_deref(),
                        namespace.as_deref(),
                        args.global.out.as_deref(),
                        format,
                    )
                    .await
                }
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        ExceptionsAction::Import {
            path,
            overwrite,
            skip_existing,
        } => match Context::build(&args.global) {
            Ok(ctx) => cmd::exceptions::import(&ctx, path, *overwrite, *skip_existing).await,
            Err(e) => Err(e),
        },
        ExceptionsAction::Delete {
            list_ids,
            namespace,
        } if list_ids.is_empty() => Err(Error::new(
            ErrorKind::Error,
            "Name at least one exception list to delete",
        )),
        ExceptionsAction::Delete {
            list_ids,
            namespace,
        } => match Context::build(&args.global) {
            Ok(ctx) => cmd::exceptions::delete(&ctx, list_ids, namespace.as_deref()).await,
            Err(e) => Err(e),
        },
    }
}
