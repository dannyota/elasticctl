use crate::cli::Cli;
use crate::cmd;
use elasticctl_core::Error;
use serde_json::Value;

// Completion streams a shell script to stdout. Its null placeholder is
// never rendered because the result match exits first.
pub(crate) async fn completion(_args: &Cli, shell: &clap_complete::Shell) -> Result<Value, Error> {
    cmd::meta::completion(*shell).map(|_| Value::Null)
}

pub(crate) async fn commands(_args: &Cli) -> Result<Value, Error> {
    cmd::meta::command_tree()
}

pub(crate) async fn mcp(_args: &Cli) -> Result<Value, Error> {
    unreachable!("MCP serve exits through its dedicated branch")
}
