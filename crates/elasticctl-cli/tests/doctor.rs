//! `doctor` must keep working when the configuration itself is broken —
//! that is exactly when an operator reaches for it. Unlike every other
//! command, it does not fail fast on `Context::build`; a build failure
//! becomes a failed `config` check in its JSON report instead of a bare
//! error envelope on stderr.

use assert_cmd::Command;
use serde_json::json;
use std::fs;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

/// Deliberately left at whatever the process umask produces (typically
/// 0644, i.e. permissive). `doctor` folds a permissive file into its own
/// `config_permissions` check rather than the stderr side channel other
/// commands use, so its fixtures need no permission workaround — that is
/// exactly the case `tests/permission_warning.rs` exercises directly.
fn write_config(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    fs::write(&path, body).unwrap();
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

/// A config pointing the default profile at a mock stack.
fn config_for(dir: &std::path::Path, uri: &str) -> std::path::PathBuf {
    write_config(
        dir,
        &format!(
            r#"
current = "default"

[profiles.default]
kibana_url = "{uri}"
api_key = "essu_t"
space = "default"
verify = true
timeout_secs = 5
"#
        ),
    )
}

/// A mock stack serving just enough for `doctor` to reach the `auth` check:
/// the status probe, the identity call, and an empty rules page.
async fn doctor_server(username: &str, realm: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.6.0", "build_flavor": "serverless"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/_security/_authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "username": username,
            "authentication_realm": {"type": realm}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [], "total": 0
        })))
        .mount(&server)
        .await;
    server
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
    let config_check = find_check(&v, "config");
    assert_eq!(config_check["status"], "fail");
    // Must be `require_credential`'s message, not `Transport::new`'s generic
    // one — assert on content, not just status, since status alone doesn't
    // distinguish the two and is how this went unnoticed before.
    let msg = config_check["message"].as_str().unwrap();
    assert!(
        msg.contains("nocreds"),
        "message must name the profile: {msg}"
    );
    assert!(
        msg.contains("config init"),
        "message must point at the remedy: {msg}"
    );
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

#[tokio::test]
async fn doctor_does_not_print_the_full_api_key_id() {
    let server = doctor_server("2XTe9p8BLjNicQlhfc9W", "_es_api_key").await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    let out = bin()
        .args(["doctor", "--json", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();

    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("2XTe9p8BLjNicQlhfc9W"),
        "the full key id must not reach stdout: {text}"
    );
    assert!(
        text.contains("2XTe9p..."),
        "a truncated id must still identify the credential: {text}"
    );
    assert!(
        text.contains("_es_api_key"),
        "the realm is the useful signal and stays: {text}"
    );
}
