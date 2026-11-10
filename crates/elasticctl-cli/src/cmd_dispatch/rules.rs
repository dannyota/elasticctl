use super::{parse_file_format, source_to_api};
use crate::cli::{Cli, PrebuiltAction, RulesAction};
use crate::cmd;
use crate::context::Context;
use elasticctl_api::rules::RuleFilter;
use elasticctl_core::{Error, ErrorKind};
use serde_json::Value;

pub(crate) async fn rules(args: &Cli, action: &RulesAction) -> Result<Value, Error> {
    match action {
        RulesAction::List {
            enabled,
            disabled,
            rule_type,
            severity,
            tag,
            filter,
            search,
            source,
        } => {
            if *enabled && *disabled {
                Err(Error::new(
                    ErrorKind::Error,
                    "--enabled and --disabled are mutually exclusive",
                ))
            } else {
                let f = RuleFilter {
                    source: source_to_api(*source),
                    enabled: if *enabled {
                        Some(true)
                    } else if *disabled {
                        Some(false)
                    } else {
                        None
                    },
                    rule_type: rule_type.clone(),
                    severity: severity.clone(),
                    tag: tag.clone(),
                    name: None,
                    query: filter.clone(),
                    search: search.clone(),
                    ..Default::default()
                };
                match Context::build(&args.global) {
                    Ok(ctx) => cmd::rules::list(&ctx, &f).await,
                    Err(e) => Err(e),
                }
            }
        }
        RulesAction::Get { selector } => match Context::build(&args.global) {
            Ok(ctx) => cmd::rules::get(&ctx, selector).await,
            Err(e) => Err(e),
        },
        // Local only: no context, credential check, transport, or
        // capability probe.
        RulesAction::Validate { path } => cmd::rules::validate(path),
        // Reject empty selectors before building a context so this cannot
        // express an unscoped mutation.
        RulesAction::Enable { selectors } if selectors.is_empty() => Err(Error::new(
            ErrorKind::Error,
            "Name at least one rule to enable",
        )),
        RulesAction::Enable { selectors } => match Context::build(&args.global) {
            Ok(ctx) => cmd::rules::set_enabled(&ctx, selectors, true).await,
            Err(e) => Err(e),
        },
        RulesAction::Disable { selectors } if selectors.is_empty() => Err(Error::new(
            ErrorKind::Error,
            "Name at least one rule to disable",
        )),
        RulesAction::Disable { selectors } => match Context::build(&args.global) {
            Ok(ctx) => cmd::rules::set_enabled(&ctx, selectors, false).await,
            Err(e) => Err(e),
        },
        RulesAction::Delete { selectors } if selectors.is_empty() => Err(Error::new(
            ErrorKind::Error,
            "Name at least one rule to delete",
        )),
        RulesAction::Delete { selectors } => match Context::build(&args.global) {
            Ok(ctx) => cmd::rules::delete(&ctx, selectors).await,
            Err(e) => Err(e),
        },
        RulesAction::Export {
            selectors,
            tag,
            format_file,
            source,
        } => match parse_file_format(format_file) {
            Ok(format) => match Context::build(&args.global) {
                Ok(ctx) => {
                    cmd::rules::export(
                        &ctx,
                        selectors,
                        tag.as_deref(),
                        source_to_api(*source),
                        args.global.out.as_deref(),
                        format,
                    )
                    .await
                }
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        RulesAction::Import {
            path,
            overwrite,
            skip_existing,
        } => match Context::build(&args.global) {
            Ok(ctx) => cmd::rules::import(&ctx, path, *overwrite, *skip_existing).await,
            Err(e) => Err(e),
        },
        RulesAction::Preview {
            source,
            invocations,
            sample,
        } => match Context::build(&args.global) {
            Ok(ctx) => cmd::rules::preview(&ctx, source, *invocations, *sample).await,
            Err(e) => Err(e),
        },
        RulesAction::Prebuilt { action } => match action {
            PrebuiltAction::Status => match Context::build(&args.global) {
                Ok(ctx) => cmd::rules::prebuilt_status(&ctx).await,
                Err(e) => Err(e),
            },
            PrebuiltAction::Install => match Context::build(&args.global) {
                Ok(ctx) => cmd::rules::prebuilt_install(&ctx).await,
                Err(e) => Err(e),
            },
        },
    }
}
