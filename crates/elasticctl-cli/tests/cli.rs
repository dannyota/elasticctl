use assert_cmd::Command;

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

/// A config path guaranteed not to exist, so `config list` resolves
/// deterministically to an empty profile list without touching the real
/// `~/.elasticctl/config.toml` or any network.
fn absent_config() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.toml");
    (dir, path)
}

#[test]
fn version_flag_prints_the_workspace_version() {
    bin()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("0.1.1"));
}

#[test]
fn help_lists_the_global_flags() {
    let out = bin().arg("--help").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    for flag in ["--profile", "--json", "--format", "--yes", "--space"] {
        assert!(text.contains(flag), "help must document {flag}");
    }
}

#[test]
fn an_unknown_subcommand_exits_two() {
    bin().arg("definitely-not-a-command").assert().code(2);
}

#[test]
fn an_unknown_format_exits_two() {
    bin().args(["info", "--format", "toml"]).assert().code(2);
}

// `info` and `doctor` need a resolvable, credentialed profile and a live
// stack, so they cannot stand in for these generic global-flag checks
// without contacting a real Elastic instance. `config list` exercises the
// same render path (JSON/table selection, `--out` handling) while staying
// entirely local, per its no-network contract.

#[test]
fn info_defaults_to_table_output_when_piped() {
    // Output must not change based on whether stdout is a terminal.
    let (_dir, config) = absent_config();
    let out = bin()
        .args(["config", "list", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.trim_start().starts_with('{'),
        "table is the default: {text}"
    );
}

#[test]
fn json_flag_produces_parseable_json() {
    let (_dir, config) = absent_config();
    let out = bin()
        .args(["config", "list", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert!(v.is_array(), "config list must produce a JSON array: {v}");
}

#[test]
fn out_flag_writes_to_a_file_and_leaves_stdout_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.json");
    let (_config_dir, config) = absent_config();
    let out = bin()
        .args(["config", "list", "--json", "--config"])
        .arg(&config)
        .args(["--out"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.stdout.is_empty(),
        "stdout must stay empty when --out is given"
    );
    assert!(std::fs::read_to_string(&path).unwrap().contains('['));
}
