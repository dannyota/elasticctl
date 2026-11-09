use super::parse_content_format;
use crate::cli::{AgentPoliciesAction, Cli, FleetAction, IntegrationPoliciesAction};
use crate::cmd;
use crate::context::Context;
use elasticctl_core::{Error, ErrorKind};
use serde_json::Value;

pub(crate) async fn fleet(args: &Cli, action: &FleetAction) -> Result<Value, Error> {
    match action {
        FleetAction::AgentPolicies { action } => match action {
            AgentPoliciesAction::List { search, limit } => match Context::build(&args.global) {
                Ok(ctx) => {
                    cmd::fleet::list(
                        &ctx,
                        &elasticctl_api::fleet::agent_policy_ops::AgentPolicyFilter {
                            search: search.clone(),
                            limit: *limit,
                        },
                    )
                    .await
                }
                Err(e) => Err(e),
            },
            AgentPoliciesAction::Get { selector } => match Context::build(&args.global) {
                Ok(ctx) => cmd::fleet::get(&ctx, selector).await,
                Err(e) => Err(e),
            },
            AgentPoliciesAction::Validate { path } => cmd::fleet::validate(path),
            AgentPoliciesAction::Export {
                selectors,
                all_custom,
                format_file,
            } => match parse_content_format(format_file) {
                Ok(format) => match Context::build(&args.global) {
                    Ok(ctx) => {
                        cmd::fleet::export(
                            &ctx,
                            selectors,
                            *all_custom,
                            args.global.out.as_deref(),
                            format,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            },
            AgentPoliciesAction::Import {
                path,
                overwrite,
                skip_existing,
            } => match cmd::fleet::validate_import_artifact(path) {
                Ok(()) => match Context::build(&args.global) {
                    Ok(ctx) => cmd::fleet::import(&ctx, path, *overwrite, *skip_existing).await,
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            },
            AgentPoliciesAction::Delete { selectors } => match Context::build(&args.global) {
                Ok(ctx) => cmd::fleet::delete(&ctx, selectors).await,
                Err(e) => Err(e),
            },
        },
        FleetAction::IntegrationPolicies { action } => match action {
            IntegrationPoliciesAction::List { search, limit } => {
                match Context::build(&args.global) {
                    Ok(ctx) => cmd::fleet::integration_list(
                        &ctx,
                        &elasticctl_api::fleet::integration_policy_ops::IntegrationPolicyFilter {
                            search: search.clone(),
                            limit: *limit,
                        },
                    )
                    .await,
                    Err(e) => Err(e),
                }
            }
            IntegrationPoliciesAction::Get { selector } => match Context::build(&args.global) {
                Ok(ctx) => cmd::fleet::integration_get(&ctx, selector).await,
                Err(e) => Err(e),
            },
            // Local only: no context, credential check, transport, or
            // capability probe.
            IntegrationPoliciesAction::Validate { path } => cmd::fleet::integration_validate(path),
            IntegrationPoliciesAction::Export {
                selectors,
                all_custom,
                ..
            } if selectors.is_empty() && !*all_custom => Err(Error::new(
                ErrorKind::Error,
                "integration-policy export needs selectors or --all-custom",
            )),
            IntegrationPoliciesAction::Export {
                selectors,
                all_custom,
                format_file,
            } => match parse_content_format(format_file) {
                Ok(format) => match Context::build(&args.global) {
                    Ok(ctx) => {
                        cmd::fleet::integration_export(
                            &ctx,
                            selectors,
                            *all_custom,
                            args.global.out.as_deref(),
                            format,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            },
            IntegrationPoliciesAction::Import {
                path,
                overwrite,
                skip_existing,
            } => match cmd::fleet::validate_integration_import_artifact(path) {
                Ok(artifact) => match Context::build(&args.global) {
                    Ok(ctx) => {
                        cmd::fleet::integration_import(&ctx, artifact, *overwrite, *skip_existing)
                            .await
                    }
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            },
            // Reject empty selectors before building a context so this cannot
            // express an unscoped mutation.
            IntegrationPoliciesAction::Delete { selectors } if selectors.is_empty() => {
                Err(Error::new(
                    ErrorKind::Error,
                    "integration-policy delete needs at least one selector",
                ))
            }
            IntegrationPoliciesAction::Delete { selectors } => match Context::build(&args.global) {
                Ok(ctx) => cmd::fleet::integration_delete(&ctx, selectors).await,
                Err(e) => Err(e),
            },
        },
    }
}
