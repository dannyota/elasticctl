#![forbid(unsafe_code)]

mod cli;
mod cmd;
mod context;
mod guard;
mod render;

use clap::Parser;
use cli::{Cli, Command, ConfigAction};
use context::Context;

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
        Command::Doctor => match Context::build(&args.global) {
            Ok(ctx) => cmd::doctor::run(&ctx).await,
            Err(e) => Err(e),
        },
        Command::Info => match Context::build(&args.global) {
            Ok(ctx) => cmd::info::run(&ctx).await,
            Err(e) => Err(e),
        },
    };

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
