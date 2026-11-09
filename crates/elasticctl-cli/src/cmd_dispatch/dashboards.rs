use super::parse_content_format;
use crate::cli::{Cli, DashboardBundleAction, DashboardsAction};
use crate::cmd;
use crate::context::Context;
use elasticctl_core::{Error, ErrorKind};
use serde_json::Value;

pub(crate) async fn dashboards(args: &Cli, action: &DashboardsAction) -> Result<Value, Error> {
    match action {
        DashboardsAction::List { search, tag, limit } => match Context::build(&args.global) {
            Ok(ctx) => {
                let filter = elasticctl_api::dashboards_ops::DashboardFilter {
                    search: search.clone(),
                    tag: tag.clone(),
                    limit: *limit,
                };
                cmd::dashboards::list(&ctx, &filter).await
            }
            Err(e) => Err(e),
        },
        DashboardsAction::Get { selector } => match Context::build(&args.global) {
            Ok(ctx) => cmd::dashboards::get(&ctx, selector).await,
            Err(e) => Err(e),
        },
        // Local artifact validation must not read config or construct a
        // transport, so it remains usable in an offline checkout.
        DashboardsAction::Validate { path } => cmd::dashboards::validate(path),
        DashboardsAction::Export {
            selectors,
            format_file,
        } => match parse_content_format(format_file) {
            Ok(format) => match Context::build(&args.global) {
                Ok(ctx) => {
                    cmd::dashboards::export(&ctx, selectors, args.global.out.as_deref(), format)
                        .await
                }
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        DashboardsAction::Import {
            path,
            overwrite,
            skip_existing,
        } => match cmd::dashboards::validate_import_artifact(path) {
            Ok(()) => match Context::build(&args.global) {
                Ok(ctx) => cmd::dashboards::import(&ctx, path, *overwrite, *skip_existing).await,
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        // Reject empty selectors before building a context so this cannot
        // express an unscoped mutation.
        DashboardsAction::Delete { selectors } if selectors.is_empty() => Err(Error::new(
            ErrorKind::Error,
            "Name at least one dashboard to delete",
        )),
        DashboardsAction::Delete { selectors } => match Context::build(&args.global) {
            Ok(ctx) => cmd::dashboards::delete(&ctx, selectors).await,
            Err(e) => Err(e),
        },
        DashboardsAction::Bundle { action } => match action {
            DashboardBundleAction::Export { selectors } => match Context::build(&args.global) {
                Ok(ctx) => {
                    cmd::dashboards::export_bundle(&ctx, selectors, args.global.out.as_deref())
                        .await
                }
                Err(e) => Err(e),
            },
            DashboardBundleAction::Import { path, overwrite } => {
                match Context::build(&args.global) {
                    Ok(ctx) => cmd::dashboards::bundle_import(&ctx, path, *overwrite).await,
                    Err(e) => Err(e),
                }
            }
        },
    }
}
