//! CLI metadata: shell completion and a machine-readable command tree.

use crate::cli::Cli;
use crate::guard::MUTATING;
use clap::CommandFactory;
use clap_complete::Shell;
use elasticctl_core::Result;
use serde_json::{Value, json};

pub fn completion(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "elasticctl", &mut std::io::stdout());
    Ok(())
}

fn arg(a: &clap::Arg) -> Value {
    json!({
        "name": a.get_id().as_str(),
        "required": a.is_required_set(),
        "takes_value": a.get_num_args().map(|n| n.takes_values()).unwrap_or(false),
        "help": a.get_help().map(|h| h.to_string()),
    })
}

/// `path` is the full, space-separated command path (`rules`, `rules delete`,
/// ...). It keys `mutates` by command location rather than leaf name.
fn describe(cmd: &clap::Command, path: &str) -> Value {
    let args: Vec<Value> = cmd
        .get_arguments()
        .filter(|a| !a.is_hide_set())
        .map(arg)
        .collect();
    let subcommands: Vec<Value> = cmd
        .get_subcommands()
        .map(|sub| {
            let sub_path = format!("{path} {}", sub.get_name());
            describe(sub, &sub_path)
        })
        .collect();

    json!({
        "name": cmd.get_name(),
        "about": cmd.get_about().map(|a| a.to_string()),
        "mutates": MUTATING.contains(&path),
        "args": args,
        "subcommands": subcommands,
    })
}

pub fn command_tree() -> Result<Value> {
    let cmd = Cli::command();
    // Global flags propagate from the root to every subcommand. Read them from
    // clap metadata so a new flag cannot drift from this record.
    let global_args: Vec<Value> = cmd
        .get_arguments()
        .filter(|a| !a.is_hide_set())
        .map(arg)
        .collect();
    let commands: Vec<Value> = cmd
        .get_subcommands()
        .map(|sub| describe(sub, sub.get_name()))
        .collect();
    Ok(json!({
        "name": "elasticctl",
        "version": env!("CARGO_PKG_VERSION"),
        "global_args": global_args,
        "commands": commands,
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

    /// Collect full paths of tree nodes marked `mutates: true`.
    fn mutating_paths(value: &Value, path: &str) -> Vec<String> {
        let mut found = Vec::new();
        if value["mutates"] == true {
            found.push(path.to_string());
        }
        for sub in value["subcommands"]
            .as_array()
            .map(|a| a.as_slice())
            .unwrap_or(&[])
        {
            let name = sub["name"].as_str().unwrap();
            let sub_path = if path.is_empty() {
                name.to_string()
            } else {
                format!("{path} {name}")
            };
            found.extend(mutating_paths(sub, &sub_path));
        }
        found
    }

    /// Keep `MUTATING` exact and reviewable. This test pins `mutates: true` to
    /// the declared paths and fails on an unreviewed addition, rename, or
    /// removal. It declares the expected paths independently of `MUTATING`.
    #[test]
    fn the_mutating_set_is_exactly_the_declared_paths() {
        let tree = command_tree().unwrap();
        let mut actual: Vec<String> = tree["commands"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|c| mutating_paths(c, c["name"].as_str().unwrap()))
            .collect();
        actual.sort();

        let mut expected = [
            "rules enable",
            "rules disable",
            "rules delete",
            "rules import",
            "exceptions delete",
            "exceptions import",
            "state push",
            "config init",
        ];
        expected.sort();

        assert_eq!(actual, expected, "the set of mutating commands drifted");
    }
}
