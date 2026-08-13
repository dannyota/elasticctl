use assert_cmd::Command;

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

#[test]
fn completion_emits_a_script_for_each_supported_shell() {
    for shell in ["bash", "zsh", "fish"] {
        let out = bin().args(["completion", shell]).output().unwrap();
        assert!(out.status.success(), "{shell} completion must succeed");
        assert!(
            !out.stdout.is_empty(),
            "{shell} completion must emit a script"
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("elasticctl"),
            "{shell} script must reference the binary name"
        );
    }
}

#[test]
fn an_unsupported_shell_exits_two() {
    bin().args(["completion", "tcsh"]).assert().code(2);
}

#[test]
fn the_command_tree_lists_every_top_level_group() {
    let out = bin().args(["commands", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let names: Vec<&str> = v["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    for expected in [
        "config",
        "doctor",
        "info",
        "rules",
        "state",
        "completion",
        "commands",
    ] {
        assert!(
            names.contains(&expected),
            "command tree must list {expected}: {names:?}"
        );
    }
}

#[test]
fn the_command_tree_marks_which_commands_mutate() {
    let out = bin().args(["commands", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let rules = v["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "rules")
        .unwrap();
    let subs = rules["subcommands"].as_array().unwrap();

    let find = |n: &str| subs.iter().find(|s| s["name"] == n).unwrap();
    assert_eq!(
        find("delete")["mutates"],
        true,
        "delete must be marked as mutating"
    );
    assert_eq!(find("enable")["mutates"], true);
    assert_eq!(find("list")["mutates"], false, "list is read-only");
    assert_eq!(
        find("preview")["mutates"],
        false,
        "preview writes no alerts"
    );
}

#[test]
fn the_command_tree_records_arguments() {
    let out = bin().args(["commands", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let state = v["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "state")
        .unwrap();
    let push = state["subcommands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "push")
        .unwrap();
    let args: Vec<&str> = push["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert!(args.contains(&"dir"), "{args:?}");
    assert!(args.contains(&"report"), "{args:?}");
}
