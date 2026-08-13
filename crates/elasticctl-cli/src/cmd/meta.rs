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

/// Commands that mutate: remote for the `rules`/`state` mutations, the local
/// config file for `config init`. Keyed on the full command path
/// (`rules delete`, `state push`, ...), never the bare leaf name, so a future
/// non-mutating `delete` or `import` under another group is not silently
/// mislabeled.
///
/// Two independent contracts keep this list honest:
/// - `guard::check` asserts its caller is declared here, so a remote mutation
///   that goes through the guard but was never declared fails its own tests
///   rather than shipping `mutates: false`.
/// - the exhaustive tree test in this module pins the declared set, so the
///   list cannot silently grow.
///
/// What is *not* detected: a mutating command that neither calls the guard
/// nor is declared here. `config init` is the one declared mutator that does
/// not call the guard — it writes a local file, not the stack — so
/// `guard ⊆ MUTATING` is the direction enforced: under-declaration, not
/// over-declaration.
pub(crate) const MUTATING: [&str; 6] = [
    "rules enable",
    "rules disable",
    "rules delete",
    "rules import",
    "state push",
    "config init",
];

fn arg(a: &clap::Arg) -> Value {
    json!({
        "name": a.get_id().as_str(),
        "required": a.is_required_set(),
        "takes_value": a.get_num_args().map(|n| n.takes_values()).unwrap_or(false),
        "help": a.get_help().map(|h| h.to_string()),
    })
}

/// `path` is the full, space-joined command path of `cmd` (`rules`,
/// `rules delete`, ...), accumulated while recursing so `mutates` is keyed on
/// where the command lives, not just its leaf name.
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

    /// Collect the full paths of every node in the tree marked `mutates: true`.
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

    /// The whole point of the explicit `MUTATING` list is that a reviewer can
    /// read the mutating surface at a glance — so it must stay exactly right.
    /// This walks the tree and pins the set of `mutates: true` paths to the
    /// six declared commands, failing if a seventh appears (a new mutating
    /// command nobody reviewed) or one of the six disappears (a rename or
    /// removal that broke a declared contract). The expected set is written
    /// out here rather than read back from `MUTATING`, so the test is an
    /// independent contract, not a tautology.
    #[test]
    fn the_mutating_set_is_exactly_the_six_declared_paths() {
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
            "state push",
            "config init",
        ];
        expected.sort();

        assert_eq!(actual, expected, "the set of mutating commands drifted");
    }
}
