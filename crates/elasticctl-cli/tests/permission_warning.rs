//! `Config::load` never prints. The layer that owns output reports a
//! permissive config mode: ordinary commands emit a structured warning
//! envelope on stderr, matching errors so stderr remains parseable JSON;
//! `doctor` includes the warning in its report instead.

#![cfg(unix)]

use assert_cmd::Command;
use std::fs;

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

fn write_config(dir: &std::path::Path, mode: u32) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    fs::write(
        &path,
        r#"
current = "default"

[profiles.default]
kibana_url = "https://kb.example.com"
api_key = "essu_test"
space = "default"
verify = true
timeout_secs = 30
"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }
    path
}

#[test]
fn a_permissive_config_file_produces_a_structured_warning_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), 0o644);
    let out = bin()
        .args(["config", "list", "--json", "--config"])
        .arg(&path)
        .output()
        .unwrap();

    assert!(out.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&out.stderr).expect("a structured warning, valid JSON, on stderr");
    assert_eq!(v["warning"]["kind"], "insecure_config_permissions");
    assert!(
        v["warning"]["message"].as_str().unwrap().contains("644"),
        "{v}"
    );
}

#[test]
fn an_owner_only_config_file_produces_no_warning() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), 0o600);
    let out = bin()
        .args(["config", "list", "--json", "--config"])
        .arg(&path)
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(
        out.stderr.is_empty(),
        "an owner-only file must produce no warning: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn doctor_folds_the_permission_warning_into_its_own_report_instead_of_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), 0o644);
    let out = bin()
        .args(["doctor", "--json", "--config"])
        .arg(&path)
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(
        out.stderr.is_empty(),
        "doctor must not also emit the stderr warning: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON report on stdout");
    let perm_check = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["check"] == "config_permissions")
        .unwrap_or_else(|| panic!("expected a config_permissions check in {v}"));
    assert_eq!(perm_check["status"], "warn");
}
