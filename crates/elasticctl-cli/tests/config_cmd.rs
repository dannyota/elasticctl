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
    // Deliberately left at whatever the process umask produces (typically
    // 0644, i.e. permissive): `Config::load` no longer prints anything, and
    // the CLI's permission warning only fires on a successful command —
    // these fixtures exercise failure paths, so no stray output reaches
    // stderr either way. See `tests/permission_warning.rs` for the success
    // path this used to paper over.
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
