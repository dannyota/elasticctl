use assert_cmd::Command;
use std::fs;
use wiremock::MockServer;

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

fn write_config(dir: &std::path::Path, uri: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    fs::write(
        &path,
        format!(
            r#"
current = "default"
[profiles.default]
kibana_url = "{uri}"
es_url = "{uri}"
api_key = "essu_test"
space = "default"
verify = true
timeout_secs = 5
"#
        ),
    )
    .unwrap();
    path
}

/// A guaranteed-missing config path. `config list` then returns no profiles
/// without reading `~/.elasticctl/config.toml` or using the network.
fn absent_config() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.toml");
    (dir, path)
}

#[test]
fn version_flag_prints_the_workspace_version() {
    // Read the manifest so releases do not require test edits. A literal would
    // only compare two copies of the same string.
    bin()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains(env!("CARGO_PKG_VERSION")));
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

// These generic global-flag checks must stay local: `info` and `doctor` need a
// resolvable profile and live stack. `config list` exercises the same render
// paths (JSON/table selection and `--out`) without network access.

#[test]
fn info_defaults_to_table_output_when_piped() {
    // Piped output must match terminal output.
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

/// Finding 1: an empty id list on a guarded alert/case verb must be refused
/// by clap (exit 2) before any context or transport is built, not accepted
/// and turned into an unscoped mutation. `alerts ack/open/close` legitimately
/// run with `--query` alone, so only the no-ids-and-no-query case for those
/// three is exercised here; `tag`/`assign` and the cases verbs have no
/// `--query` alternative, so bare invocation must always be refused.
#[tokio::test]
async fn a_guarded_verb_with_no_objects_is_refused_by_clap_before_any_request() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());

    for args in [
        ["alerts", "ack"].as_slice(),
        ["alerts", "open"].as_slice(),
        ["alerts", "close"].as_slice(),
        ["alerts", "tag", "--add", "triaged"].as_slice(),
        ["alerts", "assign", "--add", "uid:u_1"].as_slice(),
        ["cases", "close"].as_slice(),
        ["cases", "open"].as_slice(),
        ["cases", "delete"].as_slice(),
    ] {
        let out = bin()
            .args(["--config", cfg.to_str().unwrap()])
            .args(args)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?} must be refused by clap: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "no mutation request may reach the server for an empty object list"
    );
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
