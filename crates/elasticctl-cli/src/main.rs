#![forbid(unsafe_code)]

mod cli;
mod cmd;
mod context;
mod guard;
mod render;
mod report_file;
mod resolve;

use clap::Parser;
use cli::{
    AlertsAction, CasesAction, Cli, Command, ConfigAction, DashboardBundleAction, DashboardsAction,
    DataViewDefaultAction, DataViewsAction, ExceptionsAction, Format, GlobalArgs, PrebuiltAction,
    RulesAction, SearchAction, SourceArg, StateAction,
};
use context::Context;
use elasticctl_api::alerts::AlertStatus;
use elasticctl_api::cases::CaseStatus;
use elasticctl_api::exceptions::ListFilter;
use elasticctl_api::rules::{RuleFilter, RuleSource};
use elasticctl_core::{Config, Error, ErrorKind};
use serde_json::{Value, json};

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let result = match &args.command {
        Command::Config { action } => match action {
            // These commands use local configuration only; they do not build a
            // context or use the network.
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
        // `doctor` builds its own context so it can report broken
        // configuration. It includes permission warnings in its report.
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
        },
        Command::Exceptions { action } => match action {
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
            // Local only: no context, credential check, transport, or
            // capability probe.
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
            // Reject empty selectors before building a context so this cannot
            // express an unscoped mutation.
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
        },
        Command::DataViews { action } => match action {
            DataViewsAction::List { search } => match Context::build(&args.global) {
                Ok(ctx) => cmd::data_views::list(&ctx, search.clone()).await,
                Err(e) => Err(e),
            },
            DataViewsAction::Get { selector } => match Context::build(&args.global) {
                Ok(ctx) => cmd::data_views::get(&ctx, selector).await,
                Err(e) => Err(e),
            },
            // Local artifact validation must not read config or construct a
            // transport, so it remains usable in an offline checkout.
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
                    Ok(ctx) => {
                        cmd::data_views::import(&ctx, path, *overwrite, *skip_existing).await
                    }
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
        },
        Command::Dashboards { action } => match action {
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
                    Ok(ctx) => {
                        cmd::dashboards::import(&ctx, path, *overwrite, *skip_existing).await
                    }
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
        },
        Command::State { action } => match action {
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
        },
        Command::Search { action } => match action {
            SearchAction::Esql {
                query,
                data_view,
                index,
                limit,
            } => match Context::build(&args.global) {
                Ok(ctx) => {
                    cmd::search::esql(&ctx, query, data_view.as_deref(), index.as_deref(), *limit)
                        .await
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
        },
        Command::Alerts { action } => match action {
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
        },
        Command::Cases { action } => match action {
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
        },
        // Completion streams a shell script to stdout. Its null placeholder is
        // never rendered because the result match exits first.
        Command::Completion { shell } => cmd::meta::completion(*shell).map(|_| Value::Null),
        Command::Commands => cmd::meta::command_tree(),
    };

    // Meta commands do not read profiles or config, so permission warnings are
    // noise. `doctor` includes its warning in its own report.
    if result.is_ok()
        && !matches!(
            &args.command,
            Command::Doctor | Command::Completion { .. } | Command::Commands
        )
    {
        emit_permission_warning(&args.global);
    }

    match result {
        Ok(value) => {
            // Completion already wrote its script. Do not render the null
            // placeholder. Flush before exit because `process::exit` skips
            // stdout's destructor.
            if matches!(&args.command, Command::Completion { .. }) {
                use std::io::Write;
                std::io::stdout().flush().ok();
                std::process::exit(0);
            }
            // Export content is raw file text, not a report. Write it unchanged
            // so `--format` and `--json` cannot re-encode it. `failed` sets
            // the exit code but is not printed with the file.
            let export_to_stdout = matches!(
                &args.command,
                Command::Rules {
                    action: RulesAction::Export { .. }
                } | Command::Exceptions {
                    action: ExceptionsAction::Export { .. }
                } | Command::DataViews {
                    action: DataViewsAction::Export { .. }
                } | Command::Dashboards {
                    action: DashboardsAction::Export { .. }
                } | Command::Dashboards {
                    action: DashboardsAction::Bundle {
                        action: DashboardBundleAction::Export { .. }
                    }
                }
            ) && args.global.out.is_none();
            if export_to_stdout && let Some(text) = value.get("text").and_then(Value::as_str) {
                use std::io::Write;
                print!("{text}");
                std::io::stdout().flush().ok();
                std::process::exit(render::exit_code_for_value(&value));
            }
            // Export already wrote the file. Render its confirmation to stdout
            // so the normal `--out` path cannot overwrite it.
            let out_already_written = matches!(
                &args.command,
                Command::Rules {
                    action: RulesAction::Export { .. }
                } | Command::Exceptions {
                    action: ExceptionsAction::Export { .. }
                } | Command::DataViews {
                    action: DataViewsAction::Export { .. }
                } | Command::Dashboards {
                    action: DashboardsAction::Export { .. }
                } | Command::Dashboards {
                    action: DashboardsAction::Bundle {
                        action: DashboardBundleAction::Export { .. }
                    }
                }
            ) && args.global.out.is_some();
            let render_global = {
                let mut g = args.global.clone();
                if out_already_written {
                    g.out = None;
                }
                // `search --out`, `alerts list --out`, and `cases list --out`
                // write NDJSON (JSONL) by default; `--format` or `--json`
                // still override it.
                if matches!(
                    &args.command,
                    Command::Search { .. }
                        | Command::Alerts {
                            action: AlertsAction::List { .. }
                        }
                        | Command::Cases {
                            action: CasesAction::List { .. }
                        }
                ) && args.global.out.is_some()
                    && args.global.format.is_none()
                    && !args.global.json
                {
                    g.format = Some(Format::Jsonl);
                }
                g
            };

            // `alerts get` and `cases get` render raw server documents, not
            // elasticctl report shapes. A top-level `failed` key there belongs
            // to the document, not to the convention `exit_code_for_value`
            // reads, so it must never derive an exit code from these payloads.
            let payload_drives_exit_code = !matches!(
                &args.command,
                Command::Alerts {
                    action: AlertsAction::Get { .. }
                } | Command::Cases {
                    action: CasesAction::Get { .. }
                }
            );
            match render::emit(&value, &render_global) {
                // Render partial-failure details before returning their exit
                // code.
                Ok(()) => {
                    let code = if payload_drives_exit_code {
                        render::exit_code_for_value(&value)
                    } else {
                        0
                    };
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

/// Map the CLI's `--source` flag onto the `-api` value. The parsed `clap`
/// enum never crosses into `-api`.
fn source_to_api(source: SourceArg) -> RuleSource {
    match source {
        SourceArg::Custom => RuleSource::Custom,
        SourceArg::Customized => RuleSource::Customized,
        SourceArg::Prebuilt => RuleSource::Prebuilt,
        SourceArg::All => RuleSource::All,
    }
}

/// Parse the rule-file format. `--format-file` controls file content;
/// `--format` controls the command report.
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

/// Parse a portable data-view artifact format. `--format-file` controls this
/// file only; the global `--format` still selects report rendering.
fn parse_content_format(s: &str) -> Result<elasticctl_api::content_codec::ContentFormat, Error> {
    use elasticctl_api::content_codec::ContentFormat;
    match s.to_ascii_lowercase().as_str() {
        "json" => Ok(ContentFormat::Json),
        "yaml" | "yml" => Ok(ContentFormat::Yaml),
        other => Err(Error::new(
            ErrorKind::Error,
            format!("unknown format-file '{other}'; expected json or yaml"),
        )),
    }
}

/// Render permission warnings as JSON on stderr, matching error envelopes.
fn emit_permission_warning(global: &GlobalArgs) {
    let path = context::config_path(global);
    if let Some(message) = Config::permission_warning(&path) {
        eprintln!(
            "{}",
            json!({"warning": {"kind": "insecure_config_permissions", "message": message}})
        );
    }
}
