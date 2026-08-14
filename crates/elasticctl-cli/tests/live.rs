//! Run conformance tests against a real stack:
//!   ELASTICCTL_LIVE=1 cargo test -- --ignored

use assert_cmd::Command;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::{Mutex, MutexGuard};

/// Serialize tests that share one remote space. The round-trip test creates
/// and deletes a rule while the pull/diff test reads the remote twice; without
/// the lock, one test could change the other's results. Recover lock poisoning
/// so an assertion failure does not strand later tests.
static LIVE_LOCK: Mutex<()> = Mutex::new(());

fn serialize_live() -> MutexGuard<'static, ()> {
    LIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn live_enabled() -> bool {
    std::env::var("ELASTICCTL_LIVE").as_deref() == Ok("1")
}

fn skip_unless_live() -> bool {
    if !live_enabled() {
        eprintln!("skipping: set ELASTICCTL_LIVE=1 to run");
        return true;
    }
    false
}

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

/// Build a profile from environment variables so live tests never use the
/// operator's `~/.elasticctl/config.toml`. `ELASTICCTL_ES_URL` is optional:
/// self-managed single hosts use the Kibana URL for ES, while Cloud requires a
/// separate ES host.
fn write_live_config(dir: &Path) -> PathBuf {
    let kibana_url =
        std::env::var("ELASTICCTL_KIBANA_URL").expect("ELASTICCTL_KIBANA_URL must be set");
    let api_key = std::env::var("ELASTICCTL_API_KEY").expect("ELASTICCTL_API_KEY must be set");
    let es_url = std::env::var("ELASTICCTL_ES_URL").ok();

    let mut body =
        format!("current = \"default\"\n\n[profiles.default]\nkibana_url = \"{kibana_url}\"\n");
    if let Some(es) = &es_url {
        body.push_str(&format!("es_url = \"{es}\"\n"));
    }
    body.push_str(&format!(
        "api_key = \"{api_key}\"\nspace = \"default\"\nverify = true\ntimeout_secs = 60\n"
    ));

    let path = dir.join("config.toml");
    std::fs::write(&path, body).unwrap();
    // The tool rejects world-readable configs, so this fixture must be 0600.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn success(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed: {}\nstderr: {}\nstdout: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
#[ignore = "requires a live stack"]
fn doctor_reports_no_failed_checks() {
    if skip_unless_live() {
        return;
    }
    let _serial = serialize_live();
    let dir = tempfile::tempdir().unwrap();
    let config = write_live_config(dir.path());

    let out = bin()
        .args(["doctor", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    success(&out, "doctor");

    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("doctor did not emit JSON: {e}"));
    assert_eq!(v["ok"], true, "doctor must report ok: {v}");

    let key_scope = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["check"] == "key_scope")
        .unwrap_or_else(|| panic!("no key_scope check in report: {v}"));
    assert_eq!(
        key_scope["status"], "ok",
        "key_scope must not warn: an organization-level key would warn here: {key_scope}"
    );
}

#[test]
#[ignore = "requires a live stack"]
fn a_pull_followed_by_a_diff_is_clean() {
    if skip_unless_live() {
        return;
    }
    let _serial = serialize_live();
    let dir = tempfile::tempdir().unwrap();
    let config = write_live_config(dir.path());
    let state = dir.path().join("state");

    let pull = bin()
        .args(["state", "pull", "--source", "all", "--config"])
        .arg(&config)
        .arg("--dir")
        .arg(&state)
        .output()
        .unwrap();
    success(&pull, "state pull");

    let diff = bin()
        .args(["state", "diff", "--source", "all", "--json", "--config"])
        .arg(&config)
        .arg("--dir")
        .arg(&state)
        .output()
        .unwrap();
    success(&diff, "state diff");

    let v: serde_json::Value = serde_json::from_slice(&diff.stdout)
        .unwrap_or_else(|e| panic!("state diff did not emit JSON: {e}"));
    assert_eq!(
        v["clean"], true,
        "a fresh pull must diff clean against the live stack: {v}"
    );
}

/// Find the canonical export line containing `rule_id`.
/// Export writes one canonical rule per line, with sorted keys and no trailer.
fn rule_line_in_export(path: &Path, rule_id: &str) -> String {
    let body = std::fs::read_to_string(path).unwrap();
    let needle = format!("\"rule_id\":\"{rule_id}\"");
    body.lines()
        .find(|line| line.contains(&needle))
        .unwrap_or_else(|| panic!("exported file is missing rule {rule_id}: {body}"))
        .to_string()
}

#[test]
#[ignore = "requires a live stack"]
fn a_rule_survives_a_create_export_import_round_trip() {
    if skip_unless_live() {
        return;
    }
    let _serial = serialize_live();
    let dir = tempfile::tempdir().unwrap();
    let config = write_live_config(dir.path());

    // Use a fresh ID so a stale rule cannot satisfy the import or cause a
    // conflict.
    let rule_id = format!(
        "elasticctl-live-roundtrip-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    // Delete the rule on every exit path. Drop cleanup prevents failed
    // assertions from leaving state for the next run.
    struct Cleanup {
        rule_id: String,
        config: PathBuf,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            // Retry transient 429s. Report the final failure so a persistent
            // error does not silently leave a rule behind.
            for attempt in 0..3 {
                let out = bin()
                    .args(["rules", "delete", &self.rule_id, "--yes", "--config"])
                    .arg(&self.config)
                    .output();
                match out {
                    Ok(o) if o.status.success() => return,
                    Ok(o) => {
                        if attempt == 2 {
                            eprintln!(
                                "live cleanup: failed to delete {} after 3 attempts: {}",
                                self.rule_id,
                                String::from_utf8_lossy(&o.stderr)
                            );
                        }
                    }
                    Err(e) => {
                        if attempt == 2 {
                            eprintln!(
                                "live cleanup: failed to spawn delete for {}: {e}",
                                self.rule_id
                            );
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        }
    }
    let _cleanup = Cleanup {
        rule_id: rule_id.clone(),
        config: config.clone(),
    };

    // 1. Create the rule by importing a hand-authored file.
    let src = dir.path().join("in.ndjson");
    std::fs::write(
        &src,
        format!(
            "{{\"rule_id\":\"{rule_id}\",\"name\":\"elasticctl live round trip\",\"description\":\"Created by the live round-trip test. Safe to delete.\",\"type\":\"query\",\"language\":\"kuery\",\"query\":\"*:*\",\"index\":[\"logs-*\"],\"severity\":\"low\",\"risk_score\":21,\"enabled\":false,\"from\":\"now-6m\",\"interval\":\"5m\",\"tags\":[\"elasticctl\",\"live\"]}}\n"
        ),
    )
    .unwrap();
    let created = bin()
        .args(["rules", "import", "--yes", "--config"])
        .arg(&config)
        .arg("--path")
        .arg(&src)
        .output()
        .unwrap();
    success(&created, "rules import (create)");

    // 2. Export all rules and keep this rule's canonical line.
    let export1 = dir.path().join("export1.ndjson");
    let ex1 = bin()
        .args(["rules", "export", "--config"])
        .arg(&config)
        .arg("--out")
        .arg(&export1)
        .output()
        .unwrap();
    success(&ex1, "rules export (first)");
    let canonical_first = rule_line_in_export(&export1, &rule_id);

    // 3. Delete the rule.
    let deleted = bin()
        .args(["rules", "delete", &rule_id, "--yes", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    success(&deleted, "rules delete");

    // 4. Re-import the rule from its canonical exported line.
    let reimport = dir.path().join("reimport.ndjson");
    std::fs::write(&reimport, format!("{canonical_first}\n")).unwrap();
    let recreated = bin()
        .args(["rules", "import", "--yes", "--config"])
        .arg(&config)
        .arg("--path")
        .arg(&reimport)
        .output()
        .unwrap();
    success(&recreated, "rules import (re-import)");

    // 5. Export again and compare canonical lines byte for byte.
    let export2 = dir.path().join("export2.ndjson");
    let ex2 = bin()
        .args(["rules", "export", "--config"])
        .arg(&config)
        .arg("--out")
        .arg(&export2)
        .output()
        .unwrap();
    success(&ex2, "rules export (second)");
    let canonical_second = rule_line_in_export(&export2, &rule_id);

    assert_eq!(
        canonical_first, canonical_second,
        "the exported rule must round-trip through import unchanged"
    );
}
