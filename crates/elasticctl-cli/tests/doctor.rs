//! `doctor` must keep working when the configuration itself is broken —
//! that is exactly when an operator reaches for it. Unlike every other
//! command, it does not fail fast on `Context::build`; a build failure
//! becomes a failed `config` check in its JSON report instead of a bare
//! error envelope on stderr.

use assert_cmd::Command;
use std::fs;

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

/// Owner-only, matching what `config init`/`Config::save` produce. Without
/// this, the file inherits the process umask (typically 0644), which makes
/// `Config::load` print a permissive-file warning to stderr — polluting any
/// assertion that stderr carries nothing but a JSON error envelope, or
/// nothing at all.
fn chmod_owner_only(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn write_config(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    fs::write(&path, body).unwrap();
    chmod_owner_only(&path);
    path
}

fn two_profile_config(dir: &std::path::Path) -> std::path::PathBuf {
    write_config(
        dir,
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
}

fn find_check<'a>(v: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["check"] == name)
        .unwrap_or_else(|| panic!("no '{name}' check in {v}"))
}

#[test]
fn doctor_reports_a_failed_config_check_for_an_unknown_profile_rather_than_dying() {
    let dir = tempfile::tempdir().unwrap();
    let path = two_profile_config(dir.path());
    let out = bin()
        .args(["doctor", "--json", "--profile", "ghost", "--config"])
        .arg(&path)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "doctor must exit 0 and report the problem, not die: {:?}",
        out.status
    );
    assert!(
        out.stderr.is_empty(),
        "doctor must not emit a bare error envelope on stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON report on stdout");
    assert_eq!(v["ok"], false);
    let config_check = find_check(&v, "config");
    assert_eq!(config_check["status"], "fail");
    assert!(
        config_check["message"].as_str().unwrap().contains("ghost"),
        "message must name the unresolved profile: {config_check}"
    );
}

#[test]
fn doctor_reports_a_failed_config_check_for_a_profile_with_no_credential() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r#"
current = "nocreds"

[profiles.nocreds]
kibana_url = "https://kb.example.com"
space = "default"
verify = true
timeout_secs = 30
"#,
    );
    let out = bin()
        .args(["doctor", "--json", "--config"])
        .arg(&path)
        .output()
        .unwrap();

    assert!(out.status.success(), "doctor must exit 0: {:?}", out.status);
    assert!(
        out.stderr.is_empty(),
        "doctor must not emit a bare error envelope on stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON report on stdout");
    assert_eq!(v["ok"], false);
    assert_eq!(find_check(&v, "config")["status"], "fail");
}

#[test]
fn doctor_reports_a_failed_config_check_for_a_missing_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let out = bin()
        .args(["doctor", "--json", "--config"])
        .arg(dir.path().join("absent.toml"))
        .output()
        .unwrap();

    assert!(out.status.success(), "doctor must exit 0: {:?}", out.status);
    assert!(
        out.stderr.is_empty(),
        "doctor must not emit a bare error envelope on stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON report on stdout");
    assert_eq!(v["ok"], false);
    assert_eq!(find_check(&v, "config")["status"], "fail");
}

#[test]
fn an_unrelated_command_still_fails_fast_on_a_bad_profile() {
    // Proves the leniency added to doctor is scoped to doctor alone: every
    // other command still fails fast on `Context::build`.
    let dir = tempfile::tempdir().unwrap();
    let path = two_profile_config(dir.path());
    let out = bin()
        .args(["info", "--json", "--profile", "ghost", "--config"])
        .arg(&path)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1));
    assert!(
        out.stdout.is_empty(),
        "a fast-failing command must not print a partial report to stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stderr).expect("error envelope on stderr");
    assert_eq!(v["error"]["kind"], "not_found");
    assert!(v["error"]["message"].as_str().unwrap().contains("ghost"));
}
