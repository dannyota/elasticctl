#![forbid(unsafe_code)]

mod cli;
mod cmd;
mod context;
mod guard;
mod render;
mod resolve;

use clap::Parser;
use cli::{Cli, Command, ConfigAction, GlobalArgs, RulesAction};
use context::Context;
use elasticctl_api::rules::RuleFilter;
use elasticctl_core::{Config, Error, ErrorKind};
use serde_json::json;

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let result = match &args.command {
        Command::Config { action } => match action {
            // These three read only local files — no context, no network.
            ConfigAction::List => cmd::config_cmd::list(&args.global),
            ConfigAction::Show => cmd::config_cmd::show(&args.global),
            ConfigAction::Init { name, from_env } => {
                cmd::config_cmd::init(&args.global, name.as_deref(), *from_env)
            }
            ConfigAction::Test => match Context::build(&args.global) {
                Ok(ctx) => cmd::config_cmd::test(&ctx).await,
                Err(e) => Err(e),
            },
        },
        // doctor tolerates a failed context build — that is exactly when an
        // operator needs it most — so it takes GlobalArgs and builds its own
        // context internally rather than failing fast here. It also folds
        // the permissive-config-file warning into its own report instead of
        // the stderr side channel every other command uses below.
        Command::Doctor => cmd::doctor::run(&args.global).await,
        Command::Info => match Context::build(&args.global) {
            Ok(ctx) => cmd::info::run(&ctx).await,
            Err(e) => Err(e),
        },
        Command::Rules { action } => match action {
            RulesAction::List {
                enabled,
                disabled,
                rule_type,
                severity,
                tag,
                filter,
            } => {
                if *enabled && *disabled {
                    Err(Error::new(
                        ErrorKind::Error,
                        "--enabled and --disabled are mutually exclusive",
                    ))
                } else {
                    let f = RuleFilter {
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
                        query: filter.clone(),
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
            // Local only: no Context is built, so this path cannot reach a
            // credential check, transport, or capability probe.
            RulesAction::Validate { path } => cmd::rules::validate(path),
            // An empty selector list is refused before a context is even
            // built, so an unscoped mutation can never be expressed.
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
            RulesAction::Export { format_file } => match parse_file_format(format_file) {
                Ok(format) => match Context::build(&args.global) {
                    Ok(ctx) => cmd::rules::export(&ctx, args.global.out.as_deref(), format).await,
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            },
            RulesAction::Import { path, overwrite } => match Context::build(&args.global) {
                Ok(ctx) => cmd::rules::import(&ctx, path, *overwrite).await,
                Err(e) => Err(e),
            },
            RulesAction::Preview {
                source,
                invocations,
            } => match Context::build(&args.global) {
                Ok(ctx) => cmd::rules::preview(&ctx, source, *invocations).await,
                Err(e) => Err(e),
            },
        },
    };

    if result.is_ok() && !matches!(&args.command, Command::Doctor) {
        emit_permission_warning(&args.global);
    }

    match result {
        Ok(value) => {
            // `rules export --out <path>` already wrote the canonical file
            // itself (see cmd::rules::export) and returned a small
            // confirmation in its place. Rendering that confirmation through
            // the normal --out path a second time would re-encode it under
            // --format and clobber the file just written, so it always goes
            // to stdout instead.
            let out_already_written = matches!(
                &args.command,
                Command::Rules {
                    action: RulesAction::Export { .. }
                }
            ) && args.global.out.is_some();
            let render_global = if out_already_written {
                GlobalArgs {
                    out: None,
                    ..args.global.clone()
                }
            } else {
                args.global.clone()
            };

            match render::emit(&value, &render_global) {
                // The operator needs the report more than the code: render
                // the payload first, and only then act on a partial failure
                // it reports internally (e.g. `rules delete` naming which
                // rules survived a per-rule error).
                Ok(()) => {
                    let code = render::exit_code_for_value(&value);
                    if code != 0 {
                        std::process::exit(code);
                    }
                }
                Err(e) => {
                    eprintln!("{}", e.to_envelope());
                    std::process::exit(render::exit_code_for(&e));
                }
            }
        }
        Err(err) => {
            eprintln!("{}", err.to_envelope());
            std::process::exit(render::exit_code_for(&err));
        }
    }
}

/// `--format-file` selects the on-disk shape of an exported/imported rule
/// file. Kept distinct from the global `--format`, which renders a
/// command's *report* — the two must never be confused.
fn parse_file_format(s: &str) -> Result<elasticctl_api::codec::Format, Error> {
    use elasticctl_api::codec::Format;
    match s.to_ascii_lowercase().as_str() {
        "yaml" | "yml" => Ok(Format::Yaml),
        "ndjson" | "json" => Ok(Format::Ndjson),
        other => Err(Error::new(
            ErrorKind::Error,
            format!("unknown format-file '{other}'; expected ndjson or yaml"),
        )),
    }
}

/// A structured warning on stderr, matching the shape of the error envelope
/// so stderr stays uniformly JSON-parseable. `Config` only ever returns
/// data — this is the one place that decides how (and whether) the warning
/// it reports gets rendered.
fn emit_permission_warning(global: &GlobalArgs) {
    let path = context::config_path(global);
    if let Some(message) = Config::permission_warning(&path) {
        eprintln!(
            "{}",
            json!({"warning": {"kind": "insecure_config_permissions", "message": message}})
        );
    }
}
