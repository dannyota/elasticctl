#![forbid(unsafe_code)]

mod cli;
mod render;

use clap::Parser;
use cli::{Cli, Command};
use serde_json::json;

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let result = match args.command {
        Command::Info => render::emit(&json!({"version": env!("CARGO_PKG_VERSION")}), &args.global),
    };

    if let Err(err) = result {
        // One JSON object on stderr, always, so a script can parse failures
        // regardless of the requested output format.
        eprintln!("{}", err.to_envelope());
        std::process::exit(render::exit_code_for(&err));
    }
}
