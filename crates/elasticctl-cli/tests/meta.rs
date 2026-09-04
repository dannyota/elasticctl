use assert_cmd::Command;

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

/// Checking only nonempty output and an `elasticctl` token would accept the
/// wrong shell. Pin each shell to one unique token and one forbidden token.
#[test]
fn completion_emits_the_right_script_for_each_shell() {
    let cases = [
        ("bash", "complete -F _elasticctl", "#compdef"),
        ("zsh", "#compdef elasticctl", "complete -c elasticctl"),
        ("fish", "complete -c elasticctl", "#compdef"),
        (
            "elvish",
            "edit:completion:arg-completer[elasticctl]",
            "#compdef",
        ),
        ("powershell", "Register-ArgumentCompleter", "complete -F"),
    ];

    for (shell, must_contain, must_not_contain) in cases {
        let out = bin().args(["completion", shell]).output().unwrap();
        assert!(out.status.success(), "{shell} completion must succeed");
        let script = String::from_utf8_lossy(&out.stdout);
        assert!(
            script.contains(must_contain),
            "{shell} script must contain {must_contain:?}: {script}"
        );
        assert!(
            !script.contains(must_not_contain),
            "{shell} script must not contain another shell's marker \
             {must_not_contain:?}: {script}"
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
        "exceptions",
        "data-views",
        "dashboards",
        "state",
        "alerts",
        "cases",
        "fleet",
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
fn dashboard_command_tree_has_the_documented_guarded_paths() {
    let out = bin().args(["commands", "--json"]).output().unwrap();
    let tree: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let dashboards = tree["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|command| command["name"] == "dashboards")
        .expect("dashboards command");
    let children = dashboards["subcommands"].as_array().unwrap();
    let find = |name: &str| children.iter().find(|child| child["name"] == name).unwrap();
    assert_eq!(find("import")["mutates"], true);
    assert_eq!(find("delete")["mutates"], true);
    let bundle = find("bundle")["subcommands"].as_array().unwrap();
    let import = bundle
        .iter()
        .find(|child| child["name"] == "import")
        .expect("dashboards bundle import");
    assert_eq!(import["mutates"], true);
}

#[test]
fn data_view_command_tree_has_the_documented_guarded_paths() {
    let out = bin().args(["commands", "--json"]).output().unwrap();
    let tree: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let views = tree["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|command| command["name"] == "data-views")
        .expect("data-views command");
    let children = views["subcommands"].as_array().unwrap();
    let find = |name: &str| children.iter().find(|child| child["name"] == name).unwrap();
    assert_eq!(find("list")["mutates"], false);
    assert_eq!(find("get")["mutates"], false);
    assert_eq!(find("validate")["mutates"], false);
    assert_eq!(find("export")["mutates"], false);
    assert_eq!(find("import")["mutates"], true);
    assert_eq!(find("delete")["mutates"], true);
    let default = find("default")["subcommands"].as_array().unwrap();
    let default_find = |name: &str| default.iter().find(|child| child["name"] == name).unwrap();
    assert_eq!(default_find("get")["mutates"], false);
    assert_eq!(default_find("set")["mutates"], true);
    assert_eq!(default_find("unset")["mutates"], true);
}

#[test]
fn integration_policy_command_tree_has_all_verbs_and_exactly_thirty_one_mutations() {
    fn count_mutations(node: &serde_json::Value) -> usize {
        usize::from(node["mutates"] == true)
            + node["subcommands"]
                .as_array()
                .into_iter()
                .flatten()
                .map(count_mutations)
                .sum::<usize>()
    }

    let out = bin().args(["commands", "--json"]).output().unwrap();
    let tree: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let fleet = tree["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|command| command["name"] == "fleet")
        .expect("fleet command");
    let integrations = fleet["subcommands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|command| command["name"] == "integration-policies")
        .expect("integration-policies command");
    let children = integrations["subcommands"].as_array().unwrap();
    let find = |name: &str| children.iter().find(|child| child["name"] == name).unwrap();
    for verb in ["list", "get", "validate", "export"] {
        assert_eq!(find(verb)["mutates"], false, "{verb}");
    }
    for verb in ["import", "delete"] {
        assert_eq!(find(verb)["mutates"], true, "{verb}");
    }
    assert_eq!(
        tree["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(count_mutations)
            .sum::<usize>(),
        31
    );
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
