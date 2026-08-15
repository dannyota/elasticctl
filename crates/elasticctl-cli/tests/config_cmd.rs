use assert_cmd::Command;
use std::fs;

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

fn write_config(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    fs::write(
        &path,
        r#"
current = "default"

[profiles.default]
kibana_url = "https://kb.example.com"
api_key = "essu_SUPERSECRET"
space = "default"
verify = true
timeout_secs = 30

[profiles.prod]
kibana_url = "https://prod.example.com"
api_key = "essu_PRODSECRET"
space = "soc"
verify = true
timeout_secs = 30
"#,
    )
    .unwrap();
    // Leave the mode to the process umask (usually 0644). These tests assert
    // stdout only; `tests/permission_warning.rs` covers the warning emitted
    // after successful commands.
    path
}

#[test]
fn config_list_names_every_profile_and_marks_the_current_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let out = bin()
        .args(["config", "list", "--json", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let names: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"default") && names.contains(&"prod"));
    let current = v
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["current"] == true)
        .unwrap();
    assert_eq!(current["name"], "default");
}

#[test]
fn config_show_never_prints_the_api_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let out = bin()
        .args(["config", "show", "--json", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("SUPERSECRET"),
        "the key must be redacted: {text}"
    );
    assert!(text.contains("***"), "redaction must be visible: {text}");
    assert!(text.contains("kb.example.com"), "non-secrets stay visible");
}

#[test]
fn config_list_never_prints_any_profiles_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let out = bin()
        .args(["config", "list", "--json", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("SUPERSECRET") && !text.contains("PRODSECRET"),
        "{text}"
    );
}

#[test]
fn config_list_never_prints_url_userinfo() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(
        &path,
        r#"
current = "default"

[profiles.default]
kibana_url = "https://user:hunter2@kb.example.com"
api_key = "essu_t"
space = "default"
verify = true
timeout_secs = 30
"#,
    )
    .unwrap();
    let out = bin()
        .args(["config", "list", "--json", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("hunter2") && !text.contains("user:"),
        "a credential in the URL must never reach list output: {text}"
    );
    assert!(text.contains("https://kb.example.com"), "{text}");
}

#[test]
fn config_show_honours_the_profile_flag() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let out = bin()
        .args(["config", "show", "--json", "--profile", "prod", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["kibana_url"], "https://prod.example.com");
    assert_eq!(v["space"], "soc");
}

#[test]
fn an_unknown_profile_fails_with_the_not_found_kind() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path());
    let out = bin()
        .args(["config", "show", "--json", "--profile", "ghost", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value =
        serde_json::from_slice(&out.stderr).expect("error envelope on stderr");
    assert_eq!(v["error"]["kind"], "not_found");
    assert!(v["error"]["message"].as_str().unwrap().contains("ghost"));
}

#[test]
fn a_missing_config_file_reports_no_profiles_rather_than_crashing() {
    let dir = tempfile::tempdir().unwrap();
    let out = bin()
        .args(["config", "list", "--json", "--config"])
        .arg(dir.path().join("absent.toml"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.as_array().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn config_init_writes_an_owner_only_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new.toml");
    bin()
        .args(["config", "init", "--from-env", "--config"])
        .arg(&path)
        .env("ELASTICCTL_KIBANA_URL", "https://kb.example.com")
        .env("ELASTICCTL_API_KEY", "essu_fromenv")
        .assert()
        .success();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("kb.example.com")
    );
}

#[test]
fn config_init_rejects_an_invalid_environment_timeout_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    bin()
        .args(["config", "init", "--from-env", "--json", "--config"])
        .arg(&path)
        .env("ELASTICCTL_KIBANA_URL", "https://kb.example.com")
        .env("ELASTICCTL_API_KEY", "dummy")
        .env("ELASTICCTL_TIMEOUT", "not-a-number")
        .assert()
        .failure();
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn config_init_rejects_non_utf8_environment_without_writing() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let out = bin()
        .args(["config", "init", "--from-env", "--json", "--config"])
        .arg(&path)
        .env("ELASTICCTL_KIBANA_URL", OsString::from_vec(vec![0xff]))
        .env("ELASTICCTL_API_KEY", "dummy")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ELASTICCTL_KIBANA_URL"),
        "error must name the variable: {stderr}"
    );
    assert!(
        !stderr.contains('\u{fffd}'),
        "error must not print the raw bytes: {stderr}"
    );
    assert!(!path.exists());
}

#[test]
fn init_never_writes_userinfo_into_the_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");

    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["config", "init", "--from-env", "--json", "--config"])
        .arg(&cfg)
        .env(
            "ELASTICCTL_KIBANA_URL",
            "https://user:hunter2@kb.example.com",
        )
        .env("ELASTICCTL_API_KEY", "essu_t")
        .assert()
        .success();

    let body = std::fs::read_to_string(&cfg).unwrap();
    assert!(
        !body.contains("hunter2") && !body.contains("user:"),
        "a credential in the URL must never reach disk: {body}"
    );
    assert!(body.contains("https://kb.example.com"), "{body}");
}

/// A `--timeout` flag supersedes `ELASTICCTL_TIMEOUT`, so a stale invalid
/// environment value must not fail a command whose flag already decides it.
#[test]
fn a_timeout_flag_supersedes_an_invalid_environment_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(
        &path,
        r#"
current = "default"

[profiles.default]
kibana_url = "https://kb.example.com"
space = "default"
verify = true
timeout_secs = 30
"#,
    )
    .unwrap();

    // `config test` reaches `require_credential` (which fails "no credential")
    // only if `Context::build` parsed the environment first.
    let out = bin()
        .args(["config", "test", "--json", "--timeout", "60", "--config"])
        .arg(&path)
        .env("ELASTICCTL_TIMEOUT", "not-a-number")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("ELASTICCTL_TIMEOUT"),
        "the flag must supersede the invalid env value: {stderr}"
    );
    assert!(
        stderr.contains("no credential"),
        "the command should reach the credential check, not fail on env parsing: {stderr}"
    );
}
