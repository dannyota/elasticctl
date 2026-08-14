//! Run conformance tests against a real stack:
//!   ELASTICCTL_LIVE=1 cargo test -- --ignored

use assert_cmd::Command;
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

type TestResult<T = ()> = std::result::Result<T, String>;

const LIVE_PREFIX: &str = "elasticctl-live-";
const LIVE_TAG: &str = "elasticctl-live-marker";
/// Fact G, measured on Serverless 9.6.0: runtime exception matching follows
/// `list_id`, so replacing only the saved-object pointer still suppresses the
/// matching event.
const EXPECTED_STALE_POINTER_HITS: Option<u64> = Some(0);

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
    let space = std::env::var("ELASTICCTL_SPACE").unwrap_or_else(|_| "default".to_string());

    let mut body =
        format!("current = \"default\"\n\n[profiles.default]\nkibana_url = \"{kibana_url}\"\n");
    if let Some(es) = &es_url {
        body.push_str(&format!("es_url = \"{es}\"\n"));
    }
    body.push_str(&format!(
        "api_key = \"{api_key}\"\nspace = \"{space}\"\nverify = true\ntimeout_secs = 60\n"
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

fn live_profile() -> Profile {
    Profile {
        kibana_url: std::env::var("ELASTICCTL_KIBANA_URL")
            .expect("ELASTICCTL_KIBANA_URL must be set"),
        es_url: std::env::var("ELASTICCTL_ES_URL").ok(),
        api_key: Some(std::env::var("ELASTICCTL_API_KEY").expect("ELASTICCTL_API_KEY must be set")),
        username: None,
        password: None,
        space: std::env::var("ELASTICCTL_SPACE").unwrap_or_else(|_| "default".to_string()),
        verify: true,
        timeout_secs: 60,
    }
}

fn cli(config: &Path) -> Command {
    let mut command = bin();
    command.arg("--config").arg(config);
    command
}

fn checked(command: &mut Command, what: &str) -> TestResult<Output> {
    let out = command
        .output()
        .map_err(|e| format!("spawning {what}: {e}"))?;
    if out.status.success() {
        Ok(out)
    } else {
        Err(format!(
            "{what} exited {}\nstderr: {}\nstdout: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        ))
    }
}

fn json_output(out: &Output, what: &str) -> TestResult<Value> {
    serde_json::from_slice(&out.stdout).map_err(|e| format!("{what} did not emit JSON: {e}"))
}

fn unique_name(kind: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_nanos();
    format!("{LIVE_PREFIX}{kind}-{nanos}")
}

fn command_is_not_found(out: &Output) -> bool {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .to_ascii_lowercase();
    text.contains("not_found") || text.contains("not found")
}

/// Identities are registered before their writes. The guard runs the same CLI
/// deletion paths after an assertion panic and retries each transient failure.
struct LiveCleanup {
    config: PathBuf,
    profile: Profile,
    rules: BTreeSet<String>,
    lists: BTreeSet<String>,
    /// Items are deleted with their registered parent list because the CLI
    /// deliberately exposes list deletion, not an unsafe item-only delete.
    items: BTreeSet<(String, String)>,
    indices: BTreeSet<String>,
    finished: bool,
}

impl LiveCleanup {
    fn new(config: PathBuf, profile: Profile) -> Self {
        Self {
            config,
            profile,
            rules: BTreeSet::new(),
            lists: BTreeSet::new(),
            items: BTreeSet::new(),
            indices: BTreeSet::new(),
            finished: false,
        }
    }

    fn for_test() -> Self {
        Self::new(
            PathBuf::from("test-config.toml"),
            Profile {
                kibana_url: "https://example.invalid".to_string(),
                es_url: None,
                api_key: Some("test".to_string()),
                username: None,
                password: None,
                space: "default".to_string(),
                verify: true,
                timeout_secs: 1,
            },
        )
    }

    fn rule(&mut self, rule_id: impl Into<String>) {
        self.rules.insert(rule_id.into());
    }

    fn list(&mut self, list_id: impl Into<String>) {
        self.lists.insert(list_id.into());
    }

    fn item(&mut self, list_id: impl Into<String>, item_id: impl Into<String>) {
        self.items.insert((list_id.into(), item_id.into()));
    }

    fn index(&mut self, index: impl Into<String>) {
        self.indices.insert(index.into());
    }

    fn tracks(&self, rule_id: &str, list_id: &str) -> bool {
        self.rules.contains(rule_id) && self.lists.contains(list_id)
    }

    fn retry<F>(identity: &str, mut delete: F) -> TestResult
    where
        F: FnMut() -> TestResult,
    {
        let mut final_error = None;
        for attempt in 1..=3 {
            match delete() {
                Ok(()) => return Ok(()),
                Err(error) => final_error = Some(error),
            }
            if attempt < 3 {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        Err(format!(
            "cleanup left {identity} after 3 attempts: {}",
            final_error.unwrap_or_else(|| "unknown deletion failure".to_string())
        ))
    }

    fn delete_rule(&self, rule_id: &str) -> TestResult {
        let out = cli(&self.config)
            .args(["rules", "delete"])
            .arg(rule_id)
            .arg("--yes")
            .output()
            .map_err(|e| format!("spawning rule cleanup for {rule_id}: {e}"))?;
        if out.status.success() || command_is_not_found(&out) {
            Ok(())
        } else {
            Err(format!("rule delete exited {}", out.status))
        }
    }

    fn delete_list(&self, list_id: &str) -> TestResult {
        let out = cli(&self.config)
            .args(["exceptions", "delete"])
            .arg(list_id)
            .args(["--namespace", "single", "--yes"])
            .output()
            .map_err(|e| format!("spawning exception cleanup for {list_id}: {e}"))?;
        if out.status.success() || command_is_not_found(&out) {
            Ok(())
        } else {
            Err(format!("exception delete exited {}", out.status))
        }
    }

    fn delete_index(&self, index: &str) -> TestResult {
        let profile = self.profile.clone();
        let path = format!("/{index}");
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| format!("building index-cleanup runtime: {e}"))?;
        runtime.block_on(async move {
            let transport = Transport::new(&profile)
                .map_err(|e| format!("building index-cleanup transport: {}", e.message))?;
            match transport.delete_absolute_es(&path).await {
                Ok(_)
                | Err(elasticctl_core::Error {
                    kind: ErrorKind::NotFound,
                    ..
                }) => Ok(()),
                Err(e) => Err(format!("index delete failed: {}", e.message)),
            }
        })
    }

    fn clean(&self) -> TestResult {
        let mut failures = Vec::new();

        for rule_id in &self.rules {
            if let Err(error) =
                Self::retry(&format!("rule {rule_id}"), || self.delete_rule(rule_id))
            {
                failures.push(error);
            }
        }
        for list_id in &self.lists {
            if let Err(error) = Self::retry(&format!("exception list {list_id}"), || {
                self.delete_list(list_id)
            }) {
                failures.push(error);
            }
        }
        // The list deletion above is the only supported CLI path that removes
        // an item. Refuse a guard whose registered item lacks that parent,
        // rather than silently claiming the item has a cleanup route.
        for (list_id, item_id) in &self.items {
            if !self.lists.contains(list_id) {
                failures.push(format!(
                    "cleanup has no registered parent list for exception item {item_id} in {list_id}"
                ));
            }
        }
        for index in &self.indices {
            if let Err(error) = Self::retry(&format!("index {index}"), || self.delete_index(index))
            {
                failures.push(error);
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    fn finish(&mut self) -> TestResult {
        let result = self.clean();
        if result.is_ok() {
            self.finished = true;
        }
        result
    }
}

impl Drop for LiveCleanup {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.clean()));
        match cleanup {
            Ok(Ok(())) => {}
            Ok(Err(error)) => eprintln!("live cleanup fallback: {error}"),
            Err(_) => eprintln!("live cleanup fallback panicked"),
        }
    }
}

#[derive(Clone, Copy)]
struct LiveBaseline {
    custom: usize,
    prebuilt: usize,
    customized: usize,
}

fn listed_rules(config: &Path, source: &str) -> TestResult<Vec<Value>> {
    let out = checked(
        cli(config).args(["rules", "list", "--source", source, "--json"]),
        &format!("rules list --source {source}"),
    )?;
    json_output(&out, "rules list")?
        .as_array()
        .cloned()
        .ok_or_else(|| "rules list JSON must be an array".to_string())
}

fn listed_marked_rules(config: &Path) -> TestResult<Vec<Value>> {
    let out = checked(
        cli(config).args(["rules", "list", "--tag", LIVE_TAG, "--json"]),
        "rules list --tag live marker",
    )?;
    json_output(&out, "marked rules list")?
        .as_array()
        .cloned()
        .ok_or_else(|| "marked rules JSON must be an array".to_string())
}

fn listed_marked_lists(config: &Path) -> TestResult<Vec<Value>> {
    let out = checked(
        cli(config).args(["exceptions", "list", "--tag", LIVE_TAG, "--json"]),
        "exceptions list --tag live marker",
    )?;
    json_output(&out, "marked exceptions list")?
        .as_array()
        .cloned()
        .ok_or_else(|| "marked exception lists JSON must be an array".to_string())
}

fn marked_indices(profile: &Profile) -> TestResult<Vec<String>> {
    let profile = profile.clone();
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("building marked-index runtime: {e}"))?;
    runtime.block_on(async move {
        let transport = Transport::new(&profile)
            .map_err(|e| format!("building marked-index transport: {}", e.message))?;
        let body = match transport
            .get_absolute_es(&format!("/_resolve/index/{LIVE_PREFIX}*"))
            .await
        {
            Ok(body) => body,
            Err(elasticctl_core::Error {
                kind: ErrorKind::NotFound,
                ..
            }) => return Ok(Vec::new()),
            Err(e) => return Err(format!("listing marked indices: {}", e.message)),
        };
        Ok(body["indices"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|entry| entry["name"].as_str().map(str::to_string))
            .collect())
    })
}

fn capture_baseline(config: &Path) -> TestResult<LiveBaseline> {
    Ok(LiveBaseline {
        custom: listed_rules(config, "custom")?.len(),
        prebuilt: listed_rules(config, "prebuilt")?.len(),
        customized: listed_rules(config, "customized")?.len(),
    })
}

fn assert_clean_baseline(
    config: &Path,
    cleanup: &LiveCleanup,
    baseline: LiveBaseline,
) -> TestResult {
    let custom = listed_rules(config, "custom")?.len();
    let prebuilt = listed_rules(config, "prebuilt")?.len();
    let customized = listed_rules(config, "customized")?.len();
    if (custom, prebuilt, customized) != (baseline.custom, baseline.prebuilt, baseline.customized) {
        return Err(format!(
            "post-test rule counts changed: custom {custom}/{}, prebuilt {prebuilt}/{}, customized {customized}/{}",
            baseline.custom, baseline.prebuilt, baseline.customized
        ));
    }
    let rules = listed_marked_rules(config)?;
    if !rules.is_empty() {
        return Err(format!("marked rules remain after cleanup: {rules:?}"));
    }
    let lists = listed_marked_lists(config)?;
    if !lists.is_empty() {
        return Err(format!(
            "marked exception lists remain after cleanup: {lists:?}"
        ));
    }
    let indices = marked_indices(&cleanup.profile)?;
    if !indices.is_empty() {
        return Err(format!(
            "marked indices remain after cleanup: {}",
            indices.join(", ")
        ));
    }
    Ok(())
}

fn conclude<T>(result: TestResult<T>, cleanup: &mut LiveCleanup, baseline: LiveBaseline) -> T {
    if let Err(error) = cleanup.finish() {
        panic!("{error}");
    }
    if let Err(error) = assert_clean_baseline(&cleanup.config, cleanup, baseline) {
        panic!("{error}");
    }
    result.unwrap_or_else(|error| panic!("{error}"))
}

fn exception_bundle(list_id: &str, item_id: &str, entries: Value) -> String {
    let list = json!({
        "list_id": list_id,
        "type": "detection",
        "name": format!("{list_id} exception list"),
        "description": "Created by elasticctl's live conformance suite. Safe to delete.",
        "namespace_type": "single",
        "tags": [LIVE_TAG],
    });
    let item = json!({
        "item_id": item_id,
        "list_id": list_id,
        "type": "simple",
        "name": format!("{item_id} exception"),
        "description": "Created by elasticctl's live conformance suite. Safe to delete.",
        "namespace_type": "single",
        "entries": entries,
        "tags": [LIVE_TAG],
    });
    format!(
        "{}\n{}\n",
        serde_json::to_string(&list).expect("exception list serializes"),
        serde_json::to_string(&item).expect("exception item serializes")
    )
}

fn query_rule(rule_id: &str, index: &str, query: &str, exception_list_id: Option<&str>) -> String {
    let mut rule = json!({
        "rule_id": rule_id,
        "name": format!("{rule_id} rule"),
        "description": "Created by elasticctl's live conformance suite. Safe to delete.",
        "type": "query",
        "language": "kuery",
        "query": query,
        "index": [index],
        "severity": "low",
        "risk_score": 21,
        "enabled": false,
        "from": "now-6m",
        "interval": "5m",
        "tags": [LIVE_TAG],
    });
    if let Some(list_id) = exception_list_id {
        rule["exceptions_list"] = json!([{
            "list_id": list_id,
            "namespace_type": "single",
            "type": "detection",
        }]);
    }
    format!(
        "{}\n",
        serde_json::to_string(&rule).expect("live rule serializes")
    )
}

fn contains_rule(rules: &[Value], rule_id: &str) -> bool {
    rules
        .iter()
        .any(|rule| rule["rule_id"].as_str() == Some(rule_id))
}

fn preview_hits(config: &Path, rule_id: &str) -> TestResult<u64> {
    let out = checked(
        cli(config).args(["rules", "preview"]).arg(rule_id).args([
            "--invocations",
            "1",
            "--sample",
            "0",
            "--json",
        ]),
        "rules preview",
    )?;
    let report = json_output(&out, "rules preview")?;
    if let Some(error) = report["hits_error"].as_str() {
        return Err(format!("rules preview could not read hits: {error}"));
    }
    report["hits"]
        .as_u64()
        .ok_or_else(|| format!("rules preview did not report a hit count: {report}"))
}

fn current_rfc3339() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_secs();
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_prime = (5 * doy + 2) / 153;
    let day = doy - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        remainder / 3_600,
        (remainder % 3_600) / 60,
        remainder % 60,
    )
}

fn set_rule_pointer(
    profile: &Profile,
    rule_id: &str,
    pointer: &str,
) -> TestResult<elasticctl_api::model::Rule> {
    let profile = profile.clone();
    let rule_id = rule_id.to_string();
    let pointer = pointer.to_string();
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("building pointer-edit runtime: {e}"))?;
    runtime.block_on(async move {
        let transport = Transport::new(&profile)
            .map_err(|e| format!("building pointer-edit transport: {}", e.message))?;
        let mut rule = elasticctl_api::rules::get(&transport, &rule_id)
            .await
            .map_err(|e| format!("fetching rule for pointer edit: {}", e.message))?;
        let reference = rule
            .as_map_mut()
            .get_mut("exceptions_list")
            .and_then(Value::as_array_mut)
            .and_then(|references| references.first_mut())
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "live preview rule has no editable exception pointer".to_string())?;
        reference.insert("id".to_string(), Value::String(pointer));
        elasticctl_api::rules::update(&transport, &rule)
            .await
            .map_err(|e| format!("writing stale exception pointer: {}", e.message))?;
        elasticctl_api::rules::get(&transport, &rule_id)
            .await
            .map_err(|e| format!("reading stored stale pointer: {}", e.message))
    })
}

fn live_rule(profile: &Profile, rule_id: &str) -> TestResult<elasticctl_api::model::Rule> {
    let profile = profile.clone();
    let rule_id = rule_id.to_string();
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| format!("building rule-read runtime: {e}"))?;
    runtime.block_on(async move {
        let transport = Transport::new(&profile)
            .map_err(|e| format!("building rule-read transport: {}", e.message))?;
        elasticctl_api::rules::get(&transport, &rule_id)
            .await
            .map_err(|e| format!("reading live rule: {}", e.message))
    })
}

fn list_live_id(profile: &Profile, list_id: &str) -> TestResult<String> {
    let profile = profile.clone();
    let list_id = list_id.to_string();
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| format!("building list-id runtime: {e}"))?;
    runtime.block_on(async move {
        let transport = Transport::new(&profile)
            .map_err(|e| format!("building list-id transport: {}", e.message))?;
        let list = elasticctl_api::exceptions::get_list(
            &transport,
            &elasticctl_api::model::ListKey {
                list_id,
                namespace_type: "single".to_string(),
            },
        )
        .await
        .map_err(|e| format!("fetching live exception list: {}", e.message))?;
        list.as_map()["id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "live exception list response has no id".to_string())
    })
}

fn index_live_event(profile: &Profile, index: &str) -> TestResult {
    let profile = profile.clone();
    let index = index.to_string();
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| format!("building event-index runtime: {e}"))?;
    runtime.block_on(async move {
        let transport = Transport::new(&profile)
            .map_err(|e| format!("building event-index transport: {}", e.message))?;
        transport
            .post_absolute_es(
                &format!("/{index}/_doc?refresh=wait_for"),
                &json!({
                    "@timestamp": current_rfc3339(),
                    "event": {"dataset": "elasticctl-live-pointer"},
                    "message": "elasticctl live pointer fixture",
                }),
            )
            .await
            .map_err(|e| format!("indexing live pointer event: {}", e.message))?;
        Ok(())
    })
}

fn stored_pointer(rule: &elasticctl_api::model::Rule) -> TestResult<&str> {
    rule.as_map()["exceptions_list"]
        .as_array()
        .and_then(|references| references.first())
        .and_then(|reference| reference["id"].as_str())
        .ok_or_else(|| "stored rule has no exception pointer".to_string())
}

/// A guard has to know every identity before a mutation starts, otherwise a
/// panic between the remote write and the next statement leaks a live object.
#[test]
fn cleanup_guard_tracks_identities_registered_before_a_mutation() {
    let mut cleanup = LiveCleanup::for_test();
    cleanup.rule("elasticctl-live-rule");
    cleanup.list("elasticctl-live-list");
    assert!(cleanup.tracks("elasticctl-live-rule", "elasticctl-live-list"));
    cleanup.finished = true;
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
    let profile = live_profile();
    let baseline = capture_baseline(&config).unwrap();
    let mut cleanup = LiveCleanup::new(config.clone(), profile);

    let result = (|| -> TestResult {
        let out = checked(cli(&config).args(["doctor", "--json"]), "doctor")?;
        let report = json_output(&out, "doctor")?;
        if report["ok"] != true {
            return Err(format!("doctor must report ok: {report}"));
        }
        let key_scope = report["checks"]
            .as_array()
            .and_then(|checks| checks.iter().find(|check| check["check"] == "key_scope"))
            .ok_or_else(|| format!("no key_scope check in report: {report}"))?;
        if key_scope["status"] != "ok" {
            return Err(format!(
                "key_scope must not warn: an organization-level key would warn here: {key_scope}"
            ));
        }
        Ok(())
    })();
    conclude(result, &mut cleanup, baseline);
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
    let profile = live_profile();
    let baseline = capture_baseline(&config).unwrap();
    let mut cleanup = LiveCleanup::new(config.clone(), profile);
    let state = dir.path().join("state");

    let result = (|| -> TestResult {
        checked(
            cli(&config)
                .args(["state", "pull", "--source", "all", "--dir"])
                .arg(&state),
            "state pull",
        )?;
        let diff = checked(
            cli(&config)
                .args(["state", "diff", "--source", "all", "--json", "--dir"])
                .arg(&state),
            "state diff",
        )?;
        let report = json_output(&diff, "state diff")?;
        if report["clean"] != true {
            return Err(format!(
                "a fresh pull must diff clean against the live stack: {report}"
            ));
        }
        Ok(())
    })();
    conclude(result, &mut cleanup, baseline);
}

#[test]
#[ignore = "requires a live stack"]
fn exception_crud_and_bundle_round_trip_preserve_a_marked_list() {
    if skip_unless_live() {
        return;
    }
    let _serial = serialize_live();
    let dir = tempfile::tempdir().unwrap();
    let config = write_live_config(dir.path());
    let profile = live_profile();
    let baseline = capture_baseline(&config).unwrap();
    let list_id = unique_name("exceptions");
    let item_id = unique_name("exception-item");
    let mut cleanup = LiveCleanup::new(config.clone(), profile);
    // Register before the import can create either object.
    cleanup.list(list_id.clone());
    cleanup.item(list_id.clone(), item_id.clone());

    let result = (|| -> TestResult {
        let bundle = dir.path().join("exceptions.ndjson");
        std::fs::write(
            &bundle,
            exception_bundle(
                &list_id,
                &item_id,
                json!([{
                    "field": "host.name",
                    "operator": "included",
                    "type": "match",
                    "value": "elasticctl-live-crud",
                }]),
            ),
        )
        .map_err(|e| format!("writing exception bundle: {e}"))?;

        checked(
            cli(&config)
                .args(["exceptions", "import", "--path"])
                .arg(&bundle)
                .arg("--yes"),
            "exceptions import",
        )?;

        let lists = listed_marked_lists(&config)?;
        if !lists
            .iter()
            .any(|list| list["list_id"].as_str() == Some(&list_id))
        {
            return Err(format!(
                "exceptions list omitted imported {list_id}: {lists:?}"
            ));
        }

        let get = checked(
            cli(&config)
                .args(["exceptions", "get"])
                .arg(&list_id)
                .args(["--namespace", "single", "--json"]),
            "exceptions get",
        )?;
        let detail = json_output(&get, "exceptions get")?;
        if detail["list"]["list_id"].as_str() != Some(&list_id)
            || !detail["items"].as_array().is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item["item_id"].as_str() == Some(&item_id))
            })
        {
            return Err(format!(
                "exceptions get did not return the imported bundle: {detail}"
            ));
        }

        let exported = dir.path().join("exceptions-export.ndjson");
        checked(
            cli(&config)
                .args(["exceptions", "export"])
                .arg(&list_id)
                .args(["--namespace", "single", "--out"])
                .arg(&exported),
            "exceptions export",
        )?;
        let exported_body = std::fs::read_to_string(&exported)
            .map_err(|e| format!("reading exported exception bundle: {e}"))?;
        let decoded = elasticctl_api::codec::decode_bundle(&exported_body)
            .map_err(|e| format!("production bundle decoder rejected export: {}", e.message))?;
        if decoded.lists.len() != 1 || decoded.items.len() != 1 {
            return Err(format!(
                "exported exception bundle must hold one list and item, got {} lists and {} items",
                decoded.lists.len(),
                decoded.items.len()
            ));
        }

        let validated = checked(
            cli(&config)
                .args(["exceptions", "validate", "--path"])
                .arg(&exported)
                .arg("--json"),
            "exceptions validate",
        )?;
        let report = json_output(&validated, "exceptions validate")?;
        if report["valid"] != true || report["lists"] != 1 || report["items"] != 1 {
            return Err(format!(
                "exception validation lost bundle members: {report}"
            ));
        }

        checked(
            cli(&config)
                .args(["exceptions", "import", "--path"])
                .arg(&exported)
                .args(["--overwrite", "--yes"]),
            "exceptions overwrite import",
        )?;
        checked(
            cli(&config)
                .args(["exceptions", "delete"])
                .arg(&list_id)
                .args(["--namespace", "single", "--yes"]),
            "exceptions delete",
        )?;
        if listed_marked_lists(&config)?
            .iter()
            .any(|list| list["list_id"].as_str() == Some(&list_id))
        {
            return Err(format!(
                "sample tag still selects deleted exception list {list_id}"
            ));
        }
        Ok(())
    })();
    conclude(result, &mut cleanup, baseline);
}

#[test]
#[ignore = "requires a live stack"]
fn a_stale_exception_pointer_is_observed_repaired_and_rewritten_on_import() {
    if skip_unless_live() {
        return;
    }
    let _serial = serialize_live();
    let dir = tempfile::tempdir().unwrap();
    let config = write_live_config(dir.path());
    let profile = live_profile();
    let baseline = capture_baseline(&config).unwrap();
    let list_id = unique_name("pointer-list");
    let item_id = unique_name("pointer-item");
    let rule_id = unique_name("pointer-rule");
    let index = unique_name("pointer-index");
    let mut cleanup = LiveCleanup::new(config.clone(), profile.clone());
    // Every registration precedes its create/import operation.
    cleanup.list(list_id.clone());
    cleanup.item(list_id.clone(), item_id.clone());
    cleanup.rule(rule_id.clone());
    cleanup.index(index.clone());

    let result = (|| -> TestResult {
        let exceptions = dir.path().join("pointer-exceptions.ndjson");
        std::fs::write(
            &exceptions,
            exception_bundle(
                &list_id,
                &item_id,
                json!([{
                    "field": "event.dataset",
                    "operator": "included",
                    "type": "match",
                    "value": "elasticctl-live-pointer",
                }]),
            ),
        )
        .map_err(|e| format!("writing pointer exception bundle: {e}"))?;
        checked(
            cli(&config)
                .args(["exceptions", "import", "--path"])
                .arg(&exceptions)
                .arg("--yes"),
            "pointer exceptions import",
        )?;
        let original_list_id = list_live_id(&profile, &list_id)?;

        index_live_event(&profile, &index)?;
        let rule_path = dir.path().join("pointer-rule.ndjson");
        let mut rule: Value = serde_json::from_str(&query_rule(
            &rule_id,
            &index,
            "event.dataset: \"elasticctl-live-pointer\"",
            Some(&list_id),
        ))
        .map_err(|e| format!("decoding pointer rule fixture: {e}"))?;
        rule["exceptions_list"][0]["id"] = Value::String(original_list_id.clone());
        std::fs::write(
            &rule_path,
            format!(
                "{}\n",
                serde_json::to_string(&rule).expect("pointer rule serializes")
            ),
        )
        .map_err(|e| format!("writing pointer rule fixture: {e}"))?;
        checked(
            cli(&config)
                .args(["rules", "import", "--path"])
                .arg(&rule_path)
                .arg("--yes"),
            "pointer rule import",
        )?;

        if preview_hits(&config, &rule_id)? != 0 {
            return Err(
                "the live exception pointer did not suppress the matching event".to_string(),
            );
        }

        let state = dir.path().join("pointer-state");
        checked(
            cli(&config)
                .args(["state", "pull"])
                .arg(&rule_id)
                .args(["--dir"])
                .arg(&state)
                .arg("--json"),
            "state pull before pointer edit",
        )?;

        let zero_uuid = "00000000-0000-0000-0000-000000000000";
        let stale = set_rule_pointer(&profile, &rule_id, zero_uuid)?;
        if stored_pointer(&stale)? != zero_uuid {
            return Err("the stack did not retain the direct stale-pointer update".to_string());
        }
        let stale_hits = preview_hits(&config, &rule_id)?;

        let diff = checked(
            cli(&config)
                .args(["state", "diff"])
                .arg(&rule_id)
                .args(["--dir"])
                .arg(&state)
                .arg("--json"),
            "state diff after pointer edit",
        )?;
        let diff = json_output(&diff, "state diff after pointer edit")?;
        if diff["clean"] != false
            || !diff["exceptions"]["dangling"]
                .as_array()
                .is_some_and(|entries| {
                    entries
                        .iter()
                        .any(|entry| entry["rule_id"].as_str() == Some(&rule_id))
                })
        {
            return Err(format!(
                "state diff did not report the stale pointer: {diff}"
            ));
        }

        checked(
            cli(&config)
                .args(["state", "push"])
                .arg(&rule_id)
                .args(["--dir"])
                .arg(&state)
                .args(["--yes", "--json"]),
            "state push pointer repair",
        )?;
        let repaired = live_rule(&profile, &rule_id)?;
        if stored_pointer(&repaired)? != original_list_id {
            return Err(format!(
                "state push did not repair the pointer to live id {original_list_id}"
            ));
        }
        if preview_hits(&config, &rule_id)? != 0 {
            return Err("the repaired pointer did not suppress the matching event".to_string());
        }

        let exported = dir.path().join("pointer-export.ndjson");
        checked(
            cli(&config)
                .args(["rules", "export"])
                .arg(&rule_id)
                .arg("--out")
                .arg(&exported),
            "pointer rules export",
        )?;
        checked(
            cli(&config)
                .args(["exceptions", "delete"])
                .arg(&list_id)
                .args(["--namespace", "single", "--yes"]),
            "delete pointer exception list before import",
        )?;
        checked(
            cli(&config)
                .args(["rules", "import", "--path"])
                .arg(&exported)
                .args(["--overwrite", "--yes"]),
            "pointer rules overwrite import",
        )?;
        let recreated_list_id = list_live_id(&profile, &list_id)?;
        let imported = live_rule(&profile, &rule_id)?;
        if stored_pointer(&imported)? != recreated_list_id {
            return Err(format!(
                "rules import did not rewrite the pointer to recreated live id {recreated_list_id}"
            ));
        }
        if preview_hits(&config, &rule_id)? != 0 {
            return Err("the imported pointer did not suppress the matching event".to_string());
        }

        match EXPECTED_STALE_POINTER_HITS {
            Some(expected) if stale_hits == expected => Ok(()),
            Some(expected) => Err(format!(
                "Fact G changed: stale pointer preview produced {stale_hits} hits, expected {expected}"
            )),
            None => Err(format!(
                "Fact G pending: stale pointer preview produced {stale_hits} hits; set EXPECTED_STALE_POINTER_HITS and record it in spec section 13"
            )),
        }
    })();
    conclude(result, &mut cleanup, baseline);
}

fn tree_contains(root: &Path, needle: &str) -> TestResult<bool> {
    if root.is_file() {
        return std::fs::read_to_string(root)
            .map(|body| body.contains(needle))
            .map_err(|e| format!("reading {}: {e}", root.display()));
    }
    for entry in std::fs::read_dir(root).map_err(|e| format!("reading {}: {e}", root.display()))? {
        let path = entry
            .map_err(|e| format!("reading mirror entry: {e}"))?
            .path();
        if tree_contains(&path, needle)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[test]
#[ignore = "requires a live stack"]
fn source_defaults_keep_custom_rules_and_allow_selected_prebuilt_rules() {
    if skip_unless_live() {
        return;
    }
    let _serial = serialize_live();
    let dir = tempfile::tempdir().unwrap();
    let config = write_live_config(dir.path());
    let profile = live_profile();
    let baseline = capture_baseline(&config).unwrap();
    let rule_id = unique_name("source-rule");
    let mut cleanup = LiveCleanup::new(config.clone(), profile);
    cleanup.rule(rule_id.clone());

    let result = (|| -> TestResult {
        if baseline.custom != 0 {
            return Err(format!(
                "source conformance requires an empty custom baseline, found {} custom rules",
                baseline.custom
            ));
        }
        let selected_prebuilt = listed_rules(&config, "prebuilt")?
            .into_iter()
            .find_map(|rule| rule["rule_id"].as_str().map(str::to_string))
            .ok_or_else(|| {
                "no prebuilt rule is available for selected-pull coverage".to_string()
            })?;
        let source = dir.path().join("source-rule.ndjson");
        std::fs::write(&source, query_rule(&rule_id, "logs-*", "*:*", None))
            .map_err(|e| format!("writing source rule: {e}"))?;
        checked(
            cli(&config)
                .args(["rules", "import", "--path"])
                .arg(&source)
                .arg("--yes"),
            "source rule import",
        )?;

        let custom = listed_rules(&config, "custom")?;
        if !contains_rule(&custom, &rule_id) {
            return Err(format!("custom source omitted imported rule {rule_id}"));
        }
        if contains_rule(&listed_rules(&config, "prebuilt")?, &rule_id)
            || contains_rule(&listed_rules(&config, "customized")?, &rule_id)
        {
            return Err("a custom rule leaked into a prebuilt source selection".to_string());
        }

        let custom_state = dir.path().join("custom-state");
        checked(
            cli(&config)
                .args(["state", "pull", "--dir"])
                .arg(&custom_state)
                .arg("--json"),
            "default state pull",
        )?;
        if !tree_contains(&custom_state, &rule_id)? {
            return Err("default state pull did not write the custom rule".to_string());
        }
        let diff = checked(
            cli(&config)
                .args(["state", "diff", "--dir"])
                .arg(&custom_state)
                .arg("--json"),
            "default state diff",
        )?;
        if json_output(&diff, "default state diff")?["clean"] != true {
            return Err("a default pull was not clean on the following default diff".to_string());
        }

        let prebuilt_state = dir.path().join("prebuilt-state");
        checked(
            cli(&config)
                .args(["state", "pull", "--source", "prebuilt", "--dir"])
                .arg(&prebuilt_state)
                .arg("--json"),
            "prebuilt state pull",
        )?;
        if tree_contains(&prebuilt_state, &rule_id)? {
            return Err("prebuilt state pull wrote the custom source rule".to_string());
        }

        let selected_state = dir.path().join("selected-prebuilt-state");
        checked(
            cli(&config)
                .args(["state", "pull"])
                .arg(&selected_prebuilt)
                .arg("--dir")
                .arg(&selected_state)
                .arg("--json"),
            "selected prebuilt state pull",
        )?;
        if !tree_contains(&selected_state, &selected_prebuilt)? {
            return Err(
                "an explicit prebuilt selector did not override the custom default".to_string(),
            );
        }
        Ok(())
    })();
    conclude(result, &mut cleanup, baseline);
}

/// Find the canonical export line containing `rule_id`.
/// Export writes one canonical rule per line, with sorted keys and no trailer.
fn rule_line_in_export(path: &Path, rule_id: &str) -> TestResult<String> {
    let body =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let needle = format!("\"rule_id\":\"{rule_id}\"");
    body.lines()
        .find(|line| line.contains(&needle))
        .map(str::to_string)
        .ok_or_else(|| format!("exported file is missing rule {rule_id}: {body}"))
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
    let profile = live_profile();
    let baseline = capture_baseline(&config).unwrap();
    let rule_id = unique_name("roundtrip-rule");
    let mut cleanup = LiveCleanup::new(config.clone(), profile);
    cleanup.rule(rule_id.clone());

    let result = (|| -> TestResult {
        let src = dir.path().join("in.ndjson");
        std::fs::write(&src, query_rule(&rule_id, "logs-*", "*:*", None))
            .map_err(|e| format!("writing round-trip rule: {e}"))?;
        checked(
            cli(&config)
                .args(["rules", "import", "--path"])
                .arg(&src)
                .arg("--yes"),
            "rules import (create)",
        )?;

        let export1 = dir.path().join("export1.ndjson");
        checked(
            cli(&config)
                .args(["rules", "export"])
                .arg(&rule_id)
                .arg("--out")
                .arg(&export1),
            "rules export (first)",
        )?;
        let canonical_first = rule_line_in_export(&export1, &rule_id)?;

        checked(
            cli(&config)
                .args(["rules", "delete"])
                .arg(&rule_id)
                .arg("--yes"),
            "rules delete",
        )?;

        let reimport = dir.path().join("reimport.ndjson");
        std::fs::write(&reimport, format!("{canonical_first}\n"))
            .map_err(|e| format!("writing re-import rule: {e}"))?;
        checked(
            cli(&config)
                .args(["rules", "import", "--path"])
                .arg(&reimport)
                .arg("--yes"),
            "rules import (re-import)",
        )?;

        let export2 = dir.path().join("export2.ndjson");
        checked(
            cli(&config)
                .args(["rules", "export"])
                .arg(&rule_id)
                .arg("--out")
                .arg(&export2),
            "rules export (second)",
        )?;
        let canonical_second = rule_line_in_export(&export2, &rule_id)?;
        if canonical_first != canonical_second {
            return Err(
                "the exported rule did not round-trip through import unchanged".to_string(),
            );
        }
        Ok(())
    })();
    conclude(result, &mut cleanup, baseline);
}
