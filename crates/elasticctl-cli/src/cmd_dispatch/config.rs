use crate::cli::{Cli, ConfigAction};
use crate::cmd;
use crate::context::Context;
use elasticctl_core::Error;
use serde_json::Value;

pub(crate) async fn config(args: &Cli, action: &ConfigAction) -> Result<Value, Error> {
    match action {
        ConfigAction::List => cmd::config_cmd::list(&args.global),
        ConfigAction::Show => cmd::config_cmd::show(&args.global),
        ConfigAction::Init { name, from_env } => {
            cmd::config_cmd::init(&args.global, name.as_deref(), *from_env)
        }
        ConfigAction::Test => match Context::build(&args.global) {
            Ok(ctx) => cmd::config_cmd::test(&ctx).await,
            Err(e) => Err(e),
        },
    }
}
