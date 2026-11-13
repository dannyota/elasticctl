#![forbid(unsafe_code)]

mod cli;
mod cmd;
mod cmd_dispatch;
mod context;
mod guard;
mod render;
mod report_file;
mod resolve;

use clap::{Parser, error::ErrorKind as ClapErrorKind};
use cli::{
    AgentPoliciesAction, AlertsAction, CasesAction, Cli, Command, DashboardBundleAction,
    DashboardsAction, DataViewsAction, ExceptionsAction, FleetAction, Format, GlobalArgs,
    IntegrationPoliciesAction, McpAction, RulesAction,
};
use elasticctl_core::Config;
use serde_json::{Value, json};

#[tokio::main]
async fn main() {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let mcp_invocation = cli::is_mcp_invocation(&argv);
    let args = match Cli::try_parse_from(&argv) {
        Ok(args) => args,
        Err(error)
            if mcp_invocation
                && !matches!(
                    error.kind(),
                    ClapErrorKind::DisplayHelp
                        | ClapErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                        | ClapErrorKind::DisplayVersion
                ) =>
        {
            cmd::mcp::exit_usage()
        }
        Err(error) => error.exit(),
    };

    if matches!(
        &args.command,
        Command::Mcp {
            action: McpAction::Serve { .. }
        }
    ) {
        let Command::Mcp {
            action:
                McpAction::Serve {
                    allow_query_tools,
                    allow_mutations,
                },
        } = &args.command
        else {
            unreachable!()
        };
        cmd::mcp::serve(&args.global, *allow_query_tools, allow_mutations).await;
    }

    let result = match &args.command {
        Command::Config { action } => cmd_dispatch::config(&args, action).await,
        Command::Doctor => cmd_dispatch::doctor(&args).await,
        Command::Info => cmd_dispatch::info(&args).await,
        Command::Rules { action } => cmd_dispatch::rules(&args, action).await,
        Command::Exceptions { action } => cmd_dispatch::exceptions(&args, action).await,
        Command::ValueLists { action } => cmd_dispatch::value_lists(&args, action).await,
        Command::DataViews { action } => cmd_dispatch::data_views(&args, action).await,
        Command::Dashboards { action } => cmd_dispatch::dashboards(&args, action).await,
        Command::Fleet { action } => cmd_dispatch::fleet(&args, action).await,
        Command::State { action } => cmd_dispatch::state(&args, action).await,
        Command::Search { action } => cmd_dispatch::search(&args, action).await,
        Command::Alerts { action } => cmd_dispatch::alerts(&args, action).await,
        Command::Cases { action } => cmd_dispatch::cases(&args, action).await,
        Command::Completion { shell } => cmd_dispatch::completion(&args, shell).await,
        Command::Commands => cmd_dispatch::commands(&args).await,
        Command::Mcp { .. } => cmd_dispatch::mcp(&args).await,
    };

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
            if matches!(&args.command, Command::Completion { .. }) {
                use std::io::Write;
                std::io::stdout().flush().ok();
                std::process::exit(0);
            }
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
                } | Command::Fleet {
                    action: FleetAction::AgentPolicies {
                        action: AgentPoliciesAction::Export { .. }
                    }
                } | Command::Fleet {
                    action: FleetAction::IntegrationPolicies {
                        action: IntegrationPoliciesAction::Export { .. }
                    }
                }
            ) && args.global.out.is_none();
            if export_to_stdout && let Some(text) = value.get("text").and_then(Value::as_str) {
                use std::io::Write;
                print!("{text}");
                std::io::stdout().flush().ok();
                std::process::exit(render::exit_code_for_value(&value));
            }
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
                } | Command::Fleet {
                    action: FleetAction::AgentPolicies {
                        action: AgentPoliciesAction::Export { .. }
                    }
                } | Command::Fleet {
                    action: FleetAction::IntegrationPolicies {
                        action: IntegrationPoliciesAction::Export { .. }
                    }
                }
            ) && args.global.out.is_some();
            let render_global = {
                let mut g = args.global.clone();
                if out_already_written {
                    g.out = None;
                }
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

            let payload_drives_exit_code = !matches!(
                &args.command,
                Command::Alerts {
                    action: AlertsAction::Get { .. }
                } | Command::Cases {
                    action: CasesAction::Get { .. }
                }
            );
            match render::emit(&value, &render_global) {
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

fn emit_permission_warning(global: &GlobalArgs) {
    let path = context::config_path(global);
    if let Some(message) = Config::permission_warning(&path) {
        eprintln!(
            "{}",
            json!({"warning": {"kind": "insecure_config_permissions", "message": message}})
        );
    }
}
