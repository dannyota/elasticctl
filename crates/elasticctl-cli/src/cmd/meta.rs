//! Self-description: shell completion and a machine-readable command tree.

use crate::cli::Cli;
use clap::CommandFactory;
use clap_complete::Shell;
use elasticctl_core::Result;
use serde_json::{Value, json};

pub fn completion(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "elasticctl", &mut std::io::stdout());
    Ok(())
}

/// Commands that change remote state. Kept as an explicit list rather than
/// inferred, so adding a mutating command without declaring it here shows up
/// as a failing test rather than as an unguarded mutation.
const MUTATING: [&str; 6] = ["enable", "disable", "delete", "import", "push", "init"];

fn arg(a: &clap::Arg) -> Value {
    json!({
        "name": a.get_id().as_str(),
        "required": a.is_required_set(),
        "takes_value": a.get_num_args().map(|n| n.takes_values()).unwrap_or(false),
        "help": a.get_help().map(|h| h.to_string()),
    })
}

fn describe(cmd: &clap::Command) -> Value {
    let args: Vec<Value> = cmd
        .get_arguments()
        .filter(|a| !a.is_hide_set())
        .map(arg)
        .collect();
    let subcommands: Vec<Value> = cmd.get_subcommands().map(describe).collect();

    json!({
        "name": cmd.get_name(),
        "about": cmd.get_about().map(|a| a.to_string()),
        "mutates": MUTATING.contains(&cmd.get_name()),
        "args": args,
        "subcommands": subcommands,
    })
}

pub fn command_tree() -> Result<Value> {
    let cmd = Cli::command();
    // The global flags (`--profile`, `--json`, `--timeout`, ...) are declared
    // once on the root and propagate to every subcommand at parse time, so a
    // consumer modelling the full surface needs them alongside the tree. They
    // are walked from clap metadata like everything else — never a hand-kept
    // list, or a newly added global flag would drift out of the record.
    let global_args: Vec<Value> = cmd
        .get_arguments()
        .filter(|a| !a.is_hide_set())
        .map(arg)
        .collect();
    Ok(json!({
        "name": "elasticctl",
        "version": env!("CARGO_PKG_VERSION"),
        "global_args": global_args,
        "commands": cmd.get_subcommands().map(describe).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_tree_records_the_global_flags_on_the_root() {
        let tree = command_tree().unwrap();
        let names: Vec<&str> = tree["global_args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["name"].as_str().unwrap())
            .collect();
        for expected in [
            "profile", "config", "space", "json", "format", "fields", "out", "yes", "timeout",
            "debug",
        ] {
            assert!(
                names.contains(&expected),
                "global_args must list {expected}: {names:?}"
            );
        }
    }
}
