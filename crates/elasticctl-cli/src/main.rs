#![forbid(unsafe_code)]

mod cli;
mod cmd;
mod context;
mod guard;
mod render;

use clap::Parser;
use cli::{Cli, Command, ConfigAction, GlobalArgs};
use context::Context;
use elasticctl_core::Config;
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
    };

    if result.is_ok() && !matches!(&args.command, Command::Doctor) {
        emit_permission_warning(&args.global);
    }

    match result {
        Ok(value) => {
            if let Err(e) = render::emit(&value, &args.global) {
                eprintln!("{}", e.to_envelope());
                std::process::exit(render::exit_code_for(&e));
            }
        }
        Err(err) => {
            eprintln!("{}", err.to_envelope());
            std::process::exit(render::exit_code_for(&err));
        }
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
