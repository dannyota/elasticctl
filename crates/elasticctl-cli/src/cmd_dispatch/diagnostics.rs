use crate::cli::Cli;
use crate::cmd;
use crate::context::Context;
use elasticctl_core::Error;
use serde_json::Value;

pub(crate) async fn doctor(args: &Cli) -> Result<Value, Error> {
    cmd::doctor::run(&args.global).await
}

pub(crate) async fn info(args: &Cli) -> Result<Value, Error> {
    match Context::build(&args.global) {
        Ok(ctx) => cmd::info::run(&ctx).await,
        Err(e) => Err(e),
    }
}
