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
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

type TestResult<T = ()> = std::result::Result<T, String>;

const LIVE_PREFIX: &str = "elasticctl-live-";
const LIVE_TAG: &str = "elasticctl-live-marker";
const CONFORMANCE_CLASS_PREFIX: &str = "elasticctl-conformance-class:";

#[derive(Clone, Copy)]
enum ConformanceFailureClass {
    Contract,
    Cleanup,
    Harness,
}

fn conformance_marker(class: ConformanceFailureClass) -> &'static str {
    match class {
        ConformanceFailureClass::Contract => "elasticctl-conformance-class:contract",
        ConformanceFailureClass::Cleanup => "elasticctl-conformance-class:cleanup",
        ConformanceFailureClass::Harness => "elasticctl-conformance-class:harness",
    }
}

fn panic_conformance(class: ConformanceFailureClass, detail: impl std::fmt::Display) -> ! {
    panic!("{}\n{detail}", conformance_marker(class));
}
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

/// The open, rule-scoped alert filter shared by the poll loop, the final
/// sweep, and cleanup's close-then-verify step: every alert this marker rule
/// produced whose workflow status is not `closed`.
fn open_marker_rule_alerts_query(rule_id: &str) -> Value {
    json!({"bool": {
        "filter": [{"term": {"kibana.alert.rule.rule_id": rule_id}}],
        "must_not": [{"term": {"kibana.alert.workflow_status": "closed"}}],
    }})
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
    /// Case ids to delete. A 404 on delete is tolerated as already-clean.
    cases: BTreeSet<String>,
    /// Exact title/tag pairs known before case creation. If creation succeeds
    /// but its response cannot be decoded, this scope still discovers the id.
    case_scopes: BTreeSet<(String, String)>,
    /// `rule_id`s whose alerts must be closed by a marker-scoped query before
    /// the rest of cleanup runs. Alerts have no delete API (triage spec
    /// section 9), so "cleaned" means "closed", not "gone".
    alert_rules: BTreeSet<String>,
    dashboards: BTreeSet<String>,
    data_views: BTreeSet<String>,
    /// `None` means no content mutation can affect the default. `Some(None)`
    /// records an original no-default state.
    default_data_view: Option<Option<String>>,
    finished: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DefaultRestoreDecision {
    AlreadyRestored,
    Restore,
}

fn default_restore_decision(
    current: Option<&str>,
    original: Option<&str>,
    owned_data_views: &BTreeSet<String>,
) -> TestResult<DefaultRestoreDecision> {
    if current == original {
        return Ok(DefaultRestoreDecision::AlreadyRestored);
    }
    if current.is_some_and(|id| owned_data_views.contains(id)) {
        return Ok(DefaultRestoreDecision::Restore);
    }
    Err("data-view default is outside the cleanup lease".to_string())
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
            cases: BTreeSet::new(),
            case_scopes: BTreeSet::new(),
            alert_rules: BTreeSet::new(),
            dashboards: BTreeSet::new(),
            data_views: BTreeSet::new(),
            default_data_view: None,
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

    fn case(&mut self, case_id: impl Into<String>) {
        self.cases.insert(case_id.into());
    }

    fn case_scope(&mut self, title: impl Into<String>, tag: impl Into<String>) {
        self.case_scopes.insert((title.into(), tag.into()));
    }

    fn alert_rule(&mut self, rule_id: impl Into<String>) {
        self.alert_rules.insert(rule_id.into());
    }

    fn dashboard(&mut self, id: impl Into<String>) {
        self.dashboards.insert(id.into());
    }

    fn data_view(&mut self, id: impl Into<String>) {
        self.data_views.insert(id.into());
    }

    fn restore_default_data_view(&mut self, original: Option<String>) {
        match &self.default_data_view {
            None => self.default_data_view = Some(original),
            Some(registered) if registered == &original => {}
            Some(_) => panic!("data-view default cleanup baseline changed after registration"),
        }
    }

    fn tracks(&self, rule_id: &str, list_id: &str) -> bool {
        self.rules.contains(rule_id) && self.lists.contains(list_id)
    }

    fn tracks_triage(&self, case_id: &str, rule_id: &str) -> bool {
        self.cases.contains(case_id) && self.alert_rules.contains(rule_id)
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

    fn delete_dashboard(&self, id: &str) -> TestResult {
        let profile = self.profile.clone();
        let id = id.to_string();
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| format!("building dashboard-cleanup runtime: {e}"))?;
        runtime.block_on(async move {
            let transport = Transport::new(&profile).map_err(|e| {
                format!("building dashboard-cleanup transport: {}", e.kind.as_str())
            })?;
            match elasticctl_api::dashboards::delete(&transport, &id).await {
                Ok(())
                | Err(elasticctl_core::Error {
                    kind: ErrorKind::NotFound,
                    ..
                }) => Ok(()),
                Err(e) => Err(format!("dashboard delete failed: {}", e.kind.as_str())),
            }
        })
    }

    fn delete_data_view(&self, id: &str) -> TestResult {
        let profile = self.profile.clone();
        let id = id.to_string();
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| format!("building data-view-cleanup runtime: {e}"))?;
        runtime.block_on(async move {
            let transport = Transport::new(&profile).map_err(|e| {
                format!("building data-view-cleanup transport: {}", e.kind.as_str())
            })?;
            match elasticctl_api::data_views::delete(&transport, &id).await {
                Ok(())
                | Err(elasticctl_core::Error {
                    kind: ErrorKind::NotFound,
                    ..
                }) => Ok(()),
                Err(e) => Err(format!("data-view delete failed: {}", e.kind.as_str())),
            }
        })
    }

    fn restore_default(&mut self) -> TestResult {
        let Some(original) = self.default_data_view.clone() else {
            return Ok(());
        };
        let profile = self.profile.clone();
        let owned_data_views = self.data_views.clone();
        let restored = tokio::runtime::Runtime::new()
            .map_err(|e| format!("building default-cleanup runtime: {e}"))?
            .block_on(async move {
                let transport = Transport::new(&profile).map_err(|e| {
                    format!("building default-cleanup transport: {}", e.kind.as_str())
                })?;
                let current = elasticctl_api::data_views::get_default(&transport)
                    .await
                    .map_err(|e| format!("checking data-view default: {}", e.kind.as_str()))?;
                match default_restore_decision(
                    current.as_deref(),
                    original.as_deref(),
                    &owned_data_views,
                )? {
                    DefaultRestoreDecision::AlreadyRestored => Ok(()),
                    DefaultRestoreDecision::Restore => {
                        elasticctl_api::data_views::set_default(&transport, original.as_deref())
                            .await
                            .map_err(|e| {
                                format!("restoring data-view default: {}", e.kind.as_str())
                            })?;
                        let current = elasticctl_api::data_views::get_default(&transport)
                            .await
                            .map_err(|e| {
                                format!("verifying restored data-view default: {}", e.kind.as_str())
                            })?;
                        if current == original {
                            Ok(())
                        } else {
                            Err("data-view default did not restore to its baseline".to_string())
                        }
                    }
                }
            });
        if restored.is_ok() {
            self.default_data_view = None;
        }
        restored
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

    /// Close every open alert a marker rule generated, then verify none
    /// remain open. Alerts have no delete API (triage spec section 9), so a
    /// closed alert is the cleanup end state, not an intermediate one.
    fn close_marker_alerts(&self, rule_id: &str) -> TestResult {
        let profile = self.profile.clone();
        let rule_id = rule_id.to_string();
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| format!("building alert-cleanup runtime: {e}"))?;
        runtime.block_on(async move {
            let transport = Transport::new(&profile)
                .map_err(|e| format!("building alert-cleanup transport: {}", e.message))?;
            // Best-effort: the rule is still enabled at this point (its own
            // `rules delete` runs later in `clean()`), so without disabling
            // it here first, a 1-minute-interval execution can land a fresh
            // open alert between this close-by-query and the verify below.
            // Mirrors the recorder's `sweep_close_marker_alerts`
            // (xtask/src/main.rs). Errors are ignored: the rule may already
            // be deleted or never created, and the close-and-verify plus the
            // baseline backstop are the real guarantees, not this PATCH.
            let _ = transport
                .patch(
                    "/api/detection_engine/rules",
                    &json!({"rule_id": rule_id, "enabled": false}),
                )
                .await;
            elasticctl_api::alerts::status_by_query(
                &transport,
                &json!({"term": {"kibana.alert.rule.rule_id": rule_id}}),
                elasticctl_api::alerts::AlertStatus::Closed,
                elasticctl_api::alerts::Conflicts::Proceed,
                None,
            )
            .await
            .map_err(|e| format!("closing marker alerts for rule {rule_id}: {}", e.message))?;
            let remaining = elasticctl_api::alerts::search(
                &transport,
                &json!({
                    "query": open_marker_rule_alerts_query(&rule_id),
                    "size": 0,
                    "track_total_hits": true,
                }),
            )
            .await
            .map_err(|e| format!("verifying closed alerts for rule {rule_id}: {}", e.message))?;
            let open = required_alert_total(remaining.total, "verifying closed marker alerts")?;
            if open == 0 {
                Ok(())
            } else {
                Err(format!("{open} open alert(s) remain for rule {rule_id}"))
            }
        })
    }

    /// Delete a case. A 404 means it is already clean (e.g. the contract's
    /// own `plan_delete`/`apply_delete` already removed it).
    fn delete_case(&self, case_id: &str) -> TestResult {
        let profile = self.profile.clone();
        let case_id = case_id.to_string();
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| format!("building case-cleanup runtime: {e}"))?;
        runtime.block_on(async move {
            let transport = Transport::new(&profile)
                .map_err(|e| format!("building case-cleanup transport: {}", e.message))?;
            match elasticctl_api::cases::delete(&transport, std::slice::from_ref(&case_id)).await {
                Ok(())
                | Err(elasticctl_core::Error {
                    kind: ErrorKind::NotFound,
                    ..
                }) => Ok(()),
                Err(e) => Err(format!("case delete failed: {}", e.message)),
            }
        })
    }

    /// Resolve a case through the marker identity known before its POST, then
    /// delete only exact title/tag matches. The server-side search narrows the
    /// set; the exact client-side check prevents a substring match from
    /// widening cleanup.
    fn delete_case_scope(&self, title: &str, tag: &str) -> TestResult {
        let profile = self.profile.clone();
        let title = title.to_string();
        let tag = tag.to_string();
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| format!("building case-scope-cleanup runtime: {e}"))?;
        runtime.block_on(async move {
            let transport = Transport::new(&profile)
                .map_err(|e| format!("building case-scope-cleanup transport: {}", e.message))?;
            let filter = elasticctl_api::cases_ops::CaseFilter {
                tag: Some(tag.clone()),
                search: Some(title.clone()),
                ..Default::default()
            };
            let ids: Vec<String> = elasticctl_api::cases_ops::export(&transport, &filter, None)
                .await
                .map_err(|e| format!("finding marker case for cleanup: {}", e.message))?
                .into_iter()
                .filter(|case| case.title == title && case.tags.iter().any(|value| value == &tag))
                .map(|case| case.id)
                .collect();
            if ids.is_empty() {
                return Ok(());
            }
            elasticctl_api::cases::delete(&transport, &ids)
                .await
                .map_err(|e| format!("case scope delete failed: {}", e.message))
        })
    }

    fn clean(&mut self) -> TestResult {
        let mut failures = Vec::new();

        // Alerts are closed, and cases deleted, before the rule/list/index
        // deletions below. The alert-close retries 3x on its own, and the
        // contract's own final sweep (triage_probe step 9) already closes
        // this rule's alerts before cleanup ever runs; deleting the rule in
        // the loop below stops it from generating any more.
        for rule_id in &self.alert_rules {
            if let Err(error) = Self::retry(&format!("alerts for rule {rule_id}"), || {
                self.close_marker_alerts(rule_id)
            }) {
                failures.push(error);
            }
        }
        for case_id in &self.cases {
            if let Err(error) =
                Self::retry(&format!("case {case_id}"), || self.delete_case(case_id))
            {
                failures.push(error);
            }
        }
        for (title, tag) in &self.case_scopes {
            if let Err(error) = Self::retry(&format!("case titled {title}"), || {
                self.delete_case_scope(title, tag)
            }) {
                failures.push(error);
            }
        }

        // A remaining dashboard may still refer to a tracked data view. A
        // failed default restore may leave a tracked view as the active
        // default. Either failure retains every dependent view and index for a
        // later Drop retry rather than leaving broken shared-space state.
        let mut content_dependencies_clean = true;
        for dashboard in &self.dashboards {
            if let Err(error) = Self::retry(&format!("dashboard {dashboard}"), || {
                self.delete_dashboard(dashboard)
            }) {
                content_dependencies_clean = false;
                failures.push(error);
            }
        }
        if self.default_data_view.is_some()
            && let Err(error) = Self::retry("data-view default", || self.restore_default())
        {
            content_dependencies_clean = false;
            failures.push(error);
        }
        if content_dependencies_clean {
            for data_view in &self.data_views {
                if let Err(error) = Self::retry(&format!("data view {data_view}"), || {
                    self.delete_data_view(data_view)
                }) {
                    content_dependencies_clean = false;
                    failures.push(error);
                }
            }
        }

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
        if self.data_views.is_empty() || content_dependencies_clean {
            for index in &self.indices {
                if let Err(error) =
                    Self::retry(&format!("index {index}"), || self.delete_index(index))
                {
                    failures.push(error);
                }
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

#[derive(Clone)]
struct LiveBaseline {
    custom: usize,
    prebuilt: usize,
    customized: usize,
    default_data_view: Option<String>,
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

fn marked_data_view_ids(profile: &Profile) -> TestResult<Vec<String>> {
    let profile = profile.clone();
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("building marked-data-view runtime: {e}"))?;
    runtime.block_on(async move {
        let transport = Transport::new(&profile)
            .map_err(|e| format!("building marked-data-view transport: {}", e.kind.as_str()))?;
        let mut ids = elasticctl_api::data_views::list(&transport)
            .await
            .map_err(|e| format!("listing marked data views: {}", e.kind.as_str()))?
            .into_iter()
            .filter(|view| view.id.starts_with(LIVE_PREFIX))
            .map(|view| view.id)
            .collect::<Vec<_>>();
        ids.sort();
        Ok(ids)
    })
}

fn marked_dashboard_ids(profile: &Profile) -> TestResult<Vec<String>> {
    let profile = profile.clone();
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("building marked-dashboard runtime: {e}"))?;
    runtime.block_on(async move {
        let transport = Transport::new(&profile)
            .map_err(|e| format!("building marked-dashboard transport: {}", e.kind.as_str()))?;
        let mut ids = elasticctl_api::dashboards_ops::list_op(
            &transport,
            &elasticctl_api::dashboards_ops::DashboardFilter::default(),
        )
        .await
        .map_err(|e| format!("listing marked dashboards: {}", e.kind.as_str()))?
        .dashboards
        .into_iter()
        .filter(|dashboard| dashboard.id.starts_with(LIVE_PREFIX))
        .map(|dashboard| dashboard.id)
        .collect::<Vec<_>>();
        ids.sort();
        Ok(ids)
    })
}

fn validate_default_baseline_id(default: Option<&str>) -> TestResult {
    match default {
        Some(id) if id.trim().is_empty() => {
            Err("pre-test default data-view id is whitespace-only".to_string())
        }
        Some(id) if id.starts_with(LIVE_PREFIX) => {
            Err("pre-test default data view is a live marker".to_string())
        }
        _ => Ok(()),
    }
}

fn read_validated_default_data_view(profile: &Profile) -> TestResult<Option<String>> {
    let profile = profile.clone();
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("building default-baseline runtime: {e}"))?;
    runtime.block_on(async move {
        let transport = Transport::new(&profile)
            .map_err(|e| format!("building default-baseline transport: {}", e.kind.as_str()))?;
        let default = elasticctl_api::data_views::get_default(&transport)
            .await
            .map_err(|e| format!("reading pre-test default data view: {}", e.kind.as_str()))?;
        validate_default_baseline_id(default.as_deref())?;
        if let Some(id) = default.as_deref() {
            let view = elasticctl_api::data_views::get(&transport, id)
                .await
                .map_err(|e| {
                    format!("resolving pre-test default data view: {}", e.kind.as_str())
                })?;
            if view.data_view.get("id").and_then(Value::as_str) != Some(id) {
                return Err("resolving pre-test default data view: response id changed".to_string());
            }
        }
        Ok(default)
    })
}

fn read_default_data_view(profile: &Profile) -> TestResult<Option<String>> {
    let profile = profile.clone();
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("building default-read runtime: {e}"))?;
    runtime.block_on(async move {
        let transport = Transport::new(&profile)
            .map_err(|e| format!("building default-read transport: {}", e.kind.as_str()))?;
        elasticctl_api::data_views::get_default(&transport)
            .await
            .map_err(|e| format!("reading data-view default: {}", e.kind.as_str()))
    })
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

/// Open `elasticctl-live-*` marker alerts and `elasticctl-live-marker` cases
/// must be zero at baseline and after cleanup. Closed marker alerts are
/// tolerated: alerts have no delete API, so a closed residue row is inert
/// (triage spec section 9).
fn triage_residue_is_clean(open_marker_alerts: u64, marker_cases: u64) -> bool {
    open_marker_alerts == 0 && marker_cases == 0
}

fn content_residue_is_clean(
    marker_dashboards: usize,
    marker_data_views: usize,
    current_default: Option<&str>,
    original_default: Option<&str>,
) -> bool {
    marker_dashboards == 0 && marker_data_views == 0 && current_default == original_default
}

/// Count queries set `track_total_hits: true`; a response without the total
/// is malformed and cannot prove cleanup. `AlertPage` keeps this optional for
/// ordinary searches whose callers do not request a count, so count contexts
/// enforce the stronger contract here.
fn required_alert_total(total: Option<u64>, context: &str) -> TestResult<u64> {
    total.ok_or_else(|| format!("{context}: decoding alerts response field `hits.total.value`"))
}

/// Count open alerts across every marker rule, not just one contract's rule:
/// baseline verification must catch any live triage contract's leftovers.
fn open_marker_alert_count(profile: &Profile) -> TestResult<u64> {
    let profile = profile.clone();
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("building open-alert-count runtime: {e}"))?;
    runtime.block_on(async move {
        let transport = Transport::new(&profile)
            .map_err(|e| format!("building open-alert-count transport: {}", e.message))?;
        let page = elasticctl_api::alerts::search(
            &transport,
            &json!({
                "query": {"bool": {
                    "filter": [{"prefix": {"kibana.alert.rule.rule_id": LIVE_PREFIX}}],
                    "must_not": [{"term": {"kibana.alert.workflow_status": "closed"}}],
                }},
                "size": 0,
                "track_total_hits": true,
            }),
        )
        .await
        .map_err(|e| format!("counting open marker alerts: {}", e.message))?;
        required_alert_total(page.total, "counting open marker alerts")
    })
}

fn marker_case_count(profile: &Profile) -> TestResult<u64> {
    let profile = profile.clone();
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("building marker-case-count runtime: {e}"))?;
    runtime.block_on(async move {
        let transport = Transport::new(&profile)
            .map_err(|e| format!("building marker-case-count transport: {}", e.message))?;
        let query = elasticctl_api::cases_ops::find_query(
            &elasticctl_api::cases_ops::CaseFilter {
                tag: Some(LIVE_TAG.to_string()),
                ..Default::default()
            },
            1,
            1,
        );
        let (_cases, total) = elasticctl_api::cases::find_page(&transport, &query)
            .await
            .map_err(|e| format!("counting marker cases: {}", e.message))?;
        Ok(total)
    })
}

fn require_clean_triage_baseline(profile: &Profile) -> TestResult {
    let open_marker_alerts = open_marker_alert_count(profile)?;
    let marker_cases = marker_case_count(profile)?;
    if triage_residue_is_clean(open_marker_alerts, marker_cases) {
        Ok(())
    } else {
        Err(format!(
            "pre-test triage baseline is dirty: {open_marker_alerts} open marker alert(s), \
             {marker_cases} marker case(s)"
        ))
    }
}

fn capture_baseline(config: &Path, profile: &Profile) -> TestResult<LiveBaseline> {
    require_clean_triage_baseline(profile)?;
    let marked_data_views = marked_data_view_ids(profile)?;
    let marked_dashboards = marked_dashboard_ids(profile)?;
    if !marked_data_views.is_empty() || !marked_dashboards.is_empty() {
        return Err(format!(
            "pre-test content baseline is dirty: {} marker data view(s), {} marker dashboard(s)",
            marked_data_views.len(),
            marked_dashboards.len()
        ));
    }
    let default_data_view = read_validated_default_data_view(profile)?;
    Ok(LiveBaseline {
        custom: listed_rules(config, "custom")?.len(),
        prebuilt: listed_rules(config, "prebuilt")?.len(),
        customized: listed_rules(config, "customized")?.len(),
        default_data_view,
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
    let marker_data_views = marked_data_view_ids(&cleanup.profile)?;
    let marker_dashboards = marked_dashboard_ids(&cleanup.profile)?;
    let current_default = read_default_data_view(&cleanup.profile)?;
    if !content_residue_is_clean(
        marker_dashboards.len(),
        marker_data_views.len(),
        current_default.as_deref(),
        baseline.default_data_view.as_deref(),
    ) {
        return Err(format!(
            "content residue remains after cleanup: {} marker dashboard(s), {} marker data view(s), default restored: {}",
            marker_dashboards.len(),
            marker_data_views.len(),
            current_default == baseline.default_data_view
        ));
    }
    let open_marker_alerts = open_marker_alert_count(&cleanup.profile)?;
    let marker_cases = marker_case_count(&cleanup.profile)?;
    if !triage_residue_is_clean(open_marker_alerts, marker_cases) {
        return Err(format!(
            "triage residue remains after cleanup: {open_marker_alerts} open marker alert(s), \
             {marker_cases} marker case(s) (closed marker alerts are tolerated, see triage spec section 9)"
        ));
    }
    Ok(())
}

fn conclude<T>(result: TestResult<T>, cleanup: &mut LiveCleanup, baseline: LiveBaseline) -> T {
    if let Err(error) = cleanup.finish() {
        panic_conformance(ConformanceFailureClass::Cleanup, error);
    }
    if let Err(error) = assert_clean_baseline(&cleanup.config, cleanup, baseline) {
        panic_conformance(ConformanceFailureClass::Cleanup, error);
    }
    result.unwrap_or_else(|error| panic_conformance(ConformanceFailureClass::Contract, error))
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

fn panic_payload_text(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    "non-string panic".to_string()
}

#[test]
fn conformance_failure_marker_names_only_the_stable_class() {
    assert!(
        conformance_marker(ConformanceFailureClass::Contract).starts_with(CONFORMANCE_CLASS_PREFIX)
    );
    assert_eq!(
        conformance_marker(ConformanceFailureClass::Contract),
        "elasticctl-conformance-class:contract"
    );
    assert_eq!(
        conformance_marker(ConformanceFailureClass::Cleanup),
        "elasticctl-conformance-class:cleanup"
    );
    assert_eq!(
        conformance_marker(ConformanceFailureClass::Harness),
        "elasticctl-conformance-class:harness"
    );
}

#[test]
fn conformance_panic_keeps_private_detail_outside_the_class_marker() {
    let payload = std::panic::catch_unwind(|| {
        panic_conformance(ConformanceFailureClass::Contract, "private detail")
    })
    .expect_err("classified failure must panic");
    let message = panic_payload_text(payload);
    let mut lines = message.lines();
    assert_eq!(lines.next(), Some("elasticctl-conformance-class:contract"));
    assert_eq!(lines.next(), Some("private detail"));
    assert_eq!(lines.next(), None);
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

/// The triage contract registers a case and the rule whose alerts it must
/// close, mirroring `rule()`/`list()`'s registered-before-mutation contract.
#[test]
fn cleanup_guard_tracks_triage_identities_registered_before_a_mutation() {
    let mut cleanup = LiveCleanup::for_test();
    cleanup.case("elasticctl-live-case");
    cleanup.alert_rule("elasticctl-live-alert-rule");
    assert!(cleanup.tracks_triage("elasticctl-live-case", "elasticctl-live-alert-rule"));
    cleanup.finished = true;
}

#[test]
fn cleanup_tracks_content_and_original_default_once() {
    let mut cleanup = LiveCleanup::for_test();
    cleanup.dashboard("elasticctl-live-dashboard");
    cleanup.data_view("elasticctl-live-view");
    cleanup.restore_default_data_view(Some("original-view".to_string()));

    assert!(cleanup.dashboards.contains("elasticctl-live-dashboard"));
    assert!(cleanup.data_views.contains("elasticctl-live-view"));
    assert_eq!(
        cleanup.default_data_view,
        Some(Some("original-view".to_string()))
    );

    cleanup.restore_default_data_view(Some("original-view".to_string()));
    let changed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cleanup.restore_default_data_view(Some("another-view".to_string()));
    }));
    assert!(
        changed.is_err(),
        "a cleanup lease cannot change its baseline"
    );
    cleanup.finished = true;
}

#[test]
fn content_residue_requires_empty_markers_and_the_exact_default() {
    assert!(content_residue_is_clean(
        0,
        0,
        Some("original"),
        Some("original")
    ));
    assert!(content_residue_is_clean(0, 0, None, None));
    assert!(!content_residue_is_clean(
        1,
        0,
        Some("original"),
        Some("original")
    ));
    assert!(!content_residue_is_clean(
        0,
        1,
        Some("original"),
        Some("original")
    ));
    assert!(!content_residue_is_clean(
        0,
        0,
        Some("other"),
        Some("original")
    ));
    assert!(!content_residue_is_clean(0, 0, None, Some("original")));
}

#[test]
fn default_restore_decision_refuses_to_clobber_an_unowned_default() {
    let owned = BTreeSet::from([
        "elasticctl-live-data-view-a".to_string(),
        "elasticctl-live-data-view-b".to_string(),
    ]);

    assert_eq!(
        default_restore_decision(Some("original"), Some("original"), &owned),
        Ok(DefaultRestoreDecision::AlreadyRestored)
    );
    assert_eq!(
        default_restore_decision(
            Some("elasticctl-live-data-view-a"),
            Some("original"),
            &owned
        ),
        Ok(DefaultRestoreDecision::Restore)
    );
    assert_eq!(
        default_restore_decision(Some("other"), Some("original"), &owned),
        Err("data-view default is outside the cleanup lease".to_string())
    );
    assert_eq!(
        default_restore_decision(Some("other"), None, &owned),
        Err("data-view default is outside the cleanup lease".to_string())
    );
}

#[test]
fn default_baseline_rejects_marker_and_unsettable_ids() {
    assert_eq!(validate_default_baseline_id(None), Ok(()));
    assert_eq!(validate_default_baseline_id(Some("ordinary-view")), Ok(()));
    assert_eq!(
        validate_default_baseline_id(Some("  ")),
        Err("pre-test default data-view id is whitespace-only".to_string())
    );
    assert_eq!(
        validate_default_baseline_id(Some("elasticctl-live-leftover")),
        Err("pre-test default data view is a live marker".to_string())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_baseline_finds_marker_ids_with_nonmarker_titles() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.6.0", "build_flavor": "serverless"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": "elasticctl-live-renamed-dashboard",
                    "data": {"title": "Renamed by a failed run"},
                    "meta": {}
                },
                {
                    "id": "ordinary-dashboard",
                    "data": {"title": "Ordinary"},
                    "meta": {}
                }
            ],
            "meta": {"page": 1, "per_page": 1000, "total": 2}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let profile = Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("test".to_string()),
        username: None,
        password: None,
        space: "default".to_string(),
        verify: true,
        timeout_secs: 1,
    };

    let ids = tokio::task::spawn_blocking(move || marked_dashboard_ids(&profile))
        .await
        .expect("dashboard baseline task must not panic")
        .expect("dashboard baseline");
    assert_eq!(ids, ["elasticctl-live-renamed-dashboard"]);
    let requests = server.received_requests().await.expect("requests");
    let dashboard_request = requests
        .iter()
        .find(|request| request.url.path() == "/api/dashboards")
        .expect("dashboard list request");
    assert_eq!(dashboard_request.url.query(), Some("page=1&per_page=1000"));
}

#[tokio::test(flavor = "multi_thread")]
async fn default_baseline_refuses_an_unresolvable_nonmarker_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view_id": "missing-view"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/missing-view"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "private"})))
        .expect(1)
        .mount(&server)
        .await;
    let profile = Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("test".to_string()),
        username: None,
        password: None,
        space: "default".to_string(),
        verify: true,
        timeout_secs: 1,
    };

    let error = tokio::task::spawn_blocking(move || read_validated_default_data_view(&profile))
        .await
        .expect("default baseline task must not panic")
        .expect_err("a stale default must refuse the live baseline");
    assert_eq!(error, "resolving pre-test default data view: not_found");
    assert!(!error.contains("missing-view") && !error.contains("private"));
}

#[tokio::test(flavor = "multi_thread")]
async fn cleanup_does_not_rewrite_an_already_restored_default() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view_id": "original-view"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let profile = Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("test".to_string()),
        username: None,
        password: None,
        space: "default".to_string(),
        verify: true,
        timeout_secs: 1,
    };
    let mut cleanup = LiveCleanup::new(PathBuf::from("unused"), profile);
    cleanup.restore_default_data_view(Some("original-view".to_string()));

    let cleanup = tokio::task::spawn_blocking(move || {
        let result = cleanup.finish();
        (result, cleanup)
    })
    .await
    .expect("cleanup task must not panic");
    assert_eq!(cleanup.0, Ok(()));
    assert_eq!(cleanup.1.default_data_view, None);
    let requests = server.received_requests().await.expect("requests");
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() != "POST")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cleanup_restores_an_owned_default_before_deleting_its_data_view() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data_view_id": "elasticctl-live-view"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/default"))
        .and(body_json(json!({
            "data_view_id": "original-view",
            "force": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view_id": "original-view"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/data_views/data_view/elasticctl-live-view"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let profile = Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("test".to_string()),
        username: None,
        password: None,
        space: "default".to_string(),
        verify: true,
        timeout_secs: 1,
    };
    let mut cleanup = LiveCleanup::new(PathBuf::from("unused"), profile);
    cleanup.data_view("elasticctl-live-view");
    cleanup.restore_default_data_view(Some("original-view".to_string()));

    let (result, cleanup) = tokio::task::spawn_blocking(move || {
        let result = cleanup.finish();
        (result, cleanup)
    })
    .await
    .expect("cleanup task must not panic");
    assert_eq!(result, Ok(()));
    assert_eq!(cleanup.default_data_view, None);
    let requests = server.received_requests().await.expect("requests");
    let restore = requests
        .iter()
        .position(|request| {
            request.method.as_str() == "POST" && request.url.path() == "/api/data_views/default"
        })
        .expect("default restore");
    let delete = requests
        .iter()
        .position(|request| {
            request.method.as_str() == "DELETE"
                && request.url.path() == "/api/data_views/data_view/elasticctl-live-view"
        })
        .expect("data-view delete");
    assert!(
        restore < delete,
        "default restoration must precede deletion"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cleanup_refuses_an_unowned_default_without_deleting_dependencies() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view_id": "other-view"})),
        )
        .mount(&server)
        .await;
    let profile = Profile {
        kibana_url: server.uri(),
        es_url: Some(server.uri()),
        api_key: Some("test".to_string()),
        username: None,
        password: None,
        space: "default".to_string(),
        verify: true,
        timeout_secs: 1,
    };
    let mut cleanup = LiveCleanup::new(PathBuf::from("unused"), profile);
    cleanup.data_view("elasticctl-live-view");
    cleanup.index("elasticctl-live-index");
    cleanup.restore_default_data_view(Some("original-view".to_string()));

    let (result, mut cleanup) = tokio::task::spawn_blocking(move || {
        let result = cleanup.finish();
        (result, cleanup)
    })
    .await
    .expect("cleanup task must not panic");
    cleanup.finished = true;
    assert_eq!(
        result,
        Err("cleanup left data-view default after 3 attempts: data-view default is outside the cleanup lease".to_string())
    );
    let requests = server.received_requests().await.expect("requests");
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() != "POST")
    );
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() != "DELETE")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cleanup_keeps_data_views_and_indices_when_dashboard_delete_fails() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.6.0", "build_flavor": "serverless"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/dashboards/elasticctl-live-dashboard"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"unexpected": true})))
        .expect(3)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view_id": "original-view"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let profile = Profile {
        kibana_url: server.uri(),
        es_url: Some(server.uri()),
        api_key: Some("test".to_string()),
        username: None,
        password: None,
        space: "default".to_string(),
        verify: true,
        timeout_secs: 1,
    };
    let mut cleanup = LiveCleanup::new(PathBuf::from("unused"), profile);
    cleanup.dashboard("elasticctl-live-dashboard");
    cleanup.data_view("elasticctl-live-view");
    cleanup.index("elasticctl-live-index");
    cleanup.restore_default_data_view(Some("original-view".to_string()));

    let (result, mut cleanup) = tokio::task::spawn_blocking(move || {
        let result = cleanup.finish();
        (result, cleanup)
    })
    .await
    .expect("cleanup task must not panic");
    cleanup.finished = true;
    assert!(result.is_err(), "dashboard response loss must fail cleanup");
    let requests = server.received_requests().await.expect("requests");
    assert!(requests.iter().all(|request| {
        request.url.path() != "/api/data_views/data_view/elasticctl-live-view"
            && request.url.path() != "/elasticctl-live-index"
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn cleanup_keeps_an_index_when_its_data_view_delete_fails() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view_id": "original-view"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/data_views/data_view/elasticctl-live-view"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"unexpected": true})))
        .expect(3)
        .mount(&server)
        .await;
    let profile = Profile {
        kibana_url: server.uri(),
        es_url: Some(server.uri()),
        api_key: Some("test".to_string()),
        username: None,
        password: None,
        space: "default".to_string(),
        verify: true,
        timeout_secs: 1,
    };
    let mut cleanup = LiveCleanup::new(PathBuf::from("unused"), profile);
    cleanup.data_view("elasticctl-live-view");
    cleanup.index("elasticctl-live-index");
    cleanup.restore_default_data_view(Some("original-view".to_string()));

    let (result, mut cleanup) = tokio::task::spawn_blocking(move || {
        let result = cleanup.finish();
        (result, cleanup)
    })
    .await
    .expect("cleanup task must not panic");
    cleanup.finished = true;
    assert!(result.is_err(), "data-view response loss must fail cleanup");
    let requests = server.received_requests().await.expect("requests");
    assert!(
        requests
            .iter()
            .all(|request| request.url.path() != "/elasticctl-live-index")
    );
}

/// Open marker alerts and marker cases must both be zero; a closed marker
/// alert is not a valid input to this function at all (see comment on
/// `triage_residue_is_clean`), so it has no row in this table.
#[test]
fn triage_residue_is_clean_truth_table() {
    assert!(triage_residue_is_clean(0, 0));
    assert!(!triage_residue_is_clean(1, 0));
    assert!(!triage_residue_is_clean(0, 1));
    assert!(!triage_residue_is_clean(3, 2));
}

/// A count request sets `track_total_hits: true`, so a successful response
/// without `hits.total.value` is malformed. Treating the missing count as
/// zero would let standalone live cleanup certify unknown residue as clean.
#[tokio::test(flavor = "multi_thread")]
async fn open_marker_alert_count_refuses_a_response_without_total() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"hits": []}
        })))
        .mount(&server)
        .await;
    let profile = Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("test".to_string()),
        username: None,
        password: None,
        space: "default".to_string(),
        verify: true,
        timeout_secs: 1,
    };

    let result = tokio::task::spawn_blocking(move || open_marker_alert_count(&profile))
        .await
        .expect("count task must not panic");

    let error = result.expect_err("a missing total must fail closed");
    assert!(
        error.contains("hits.total.value"),
        "unexpected error: {error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pre_mutation_triage_baseline_refuses_existing_open_marker_alerts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 1, "relation": "eq"}, "hits": []}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cases": [], "page": 1, "per_page": 1, "total": 0
        })))
        .mount(&server)
        .await;
    let profile = Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("test".to_string()),
        username: None,
        password: None,
        space: "default".to_string(),
        verify: true,
        timeout_secs: 1,
    };

    let result = tokio::task::spawn_blocking(move || require_clean_triage_baseline(&profile))
        .await
        .expect("baseline task must not panic");
    let error = result.expect_err("a dirty target must be refused before mutation");
    assert!(
        error.contains("pre-test triage baseline") && error.contains("1 open marker alert"),
        "unexpected error: {error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cleanup_guard_scopes_pages_and_retries_case_discovery_without_an_id() {
    let server = MockServer::start().await;
    let title = "elasticctl-live-case-with-unreadable-create-response";
    let mut first_page = vec![json!({
        "id": "c-exact-first", "version": "WzEsMV0=", "title": title,
        "status": "open", "tags": [LIVE_TAG]
    })];
    for n in 0..98 {
        first_page.push(json!({
            "id": format!("c-near-{n}"), "version": "WzEsMV0=",
            "title": format!("{title}-near-{n}"), "status": "open",
            "tags": [LIVE_TAG]
        }));
    }
    first_page.push(json!({
        "id": "c-wrong-tag", "version": "WzEsMV0=", "title": title,
        "status": "open", "tags": ["not-the-live-marker"]
    }));
    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .and(query_param("page", "1"))
        .and(query_param("perPage", "100"))
        .and(query_param("tags", LIVE_TAG))
        .and(query_param("search", title))
        .and(query_param("searchFields", "title"))
        .and(query_param("searchFields", "description"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cases": first_page, "page": 1, "per_page": 100, "total": 101
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/cases/_find"))
        .and(query_param("page", "2"))
        .and(query_param("perPage", "100"))
        .and(query_param("tags", LIVE_TAG))
        .and(query_param("search", title))
        .and(query_param("searchFields", "title"))
        .and(query_param("searchFields", "description"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cases": [{
                "id": "c-exact-second", "version": "WzEsMV0=", "title": title,
                "status": "open", "tags": [LIVE_TAG]
            }],
            "page": 2, "per_page": 100, "total": 101
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/cases"))
        .and(query_param("ids", r#"["c-exact-first","c-exact-second"]"#))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "statusCode": 400, "error": "Bad Request", "message": "transient cleanup failure"
        })))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/cases"))
        .and(query_param("ids", r#"["c-exact-first","c-exact-second"]"#))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let profile = Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("test".to_string()),
        username: None,
        password: None,
        space: "default".to_string(),
        verify: true,
        timeout_secs: 1,
    };
    let mut cleanup = LiveCleanup::new(PathBuf::from("unused-config.toml"), profile);
    cleanup.case_scope(title, LIVE_TAG);

    tokio::task::spawn_blocking(move || cleanup.finish())
        .await
        .expect("cleanup task must not panic")
        .expect("the scoped marker case must be deleted");
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
    let baseline = capture_baseline(&config, &profile).unwrap();
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
    let baseline = capture_baseline(&config, &profile).unwrap();
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
    let baseline = capture_baseline(&config, &profile).unwrap();
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
    let baseline = capture_baseline(&config, &profile).unwrap();
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
    let baseline = capture_baseline(&config, &profile).unwrap();
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
    let baseline = capture_baseline(&config, &profile).unwrap();
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

/// Seed three marker-scoped documents and read them back through the ES|QL and
/// Query DSL production paths. The index uses the `elasticctl-live-` prefix so
/// the cleanup audit catches any leak.
fn search_probe(profile: &Profile, index: &str) -> TestResult {
    let profile = profile.clone();
    let index = index.to_string();
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| format!("building search runtime: {e}"))?;
    runtime.block_on(async move {
        let transport = Transport::new(&profile)
            .map_err(|e| format!("building search transport: {}", e.message))?;

        for seq in 1..=3_i64 {
            transport
                .post_absolute_es(
                    &format!("/{index}/_doc?refresh=wait_for"),
                    &json!({
                        "seq": seq,
                        "message": format!("elasticctl live search {seq}"),
                        "marker": LIVE_TAG,
                    }),
                )
                .await
                .map_err(|e| format!("seeding search document {seq}: {}", e.message))?;
        }

        let request = elasticctl_api::search::SearchRequest {
            index: Some(index.clone()),
            data_view: None,
            limit: None,
        };

        let query = elasticctl_api::search::resolve_esql_query(
            &transport,
            "SORT seq ASC | LIMIT 2",
            &request,
        )
        .await
        .map_err(|e| format!("resolving esql query: {}", e.message))?;
        let sync = elasticctl_api::search::esql::run_sync(&transport, &query)
            .await
            .map_err(|e| format!("esql sync: {}", e.message))?;
        if sync.values.len() != 2 {
            return Err(format!(
                "esql sync must return 2 rows, got {}",
                sync.values.len()
            ));
        }
        let async_rows = elasticctl_api::search::esql::run_async(&transport, &query)
            .await
            .map_err(|e| format!("esql async: {}", e.message))?;
        if async_rows.values.len() != 2 {
            return Err(format!(
                "esql async must return 2 rows, got {}",
                async_rows.values.len()
            ));
        }

        let dsl_index = elasticctl_api::search::resolve_dsl_index(&transport, &request)
            .await
            .map_err(|e| format!("resolving dsl index: {}", e.message))?;
        let page = elasticctl_api::search::dsl::run_sync(
            &transport,
            &dsl_index,
            &json!({"query": {"match_all": {}}}),
        )
        .await
        .map_err(|e| format!("dsl sync: {}", e.message))?;
        if page.total != Some(3) || page.hits.len() != 3 {
            return Err(format!(
                "dsl sync must return 3 hits, got total {:?} and {} hits",
                page.total,
                page.hits.len()
            ));
        }
        let streamed = elasticctl_api::search::dsl::run_stream(
            &transport,
            &dsl_index,
            &json!({"match_all": {}}),
            &json!([{"seq": "asc"}, {"_shard_doc": "asc"}]),
            None,
        )
        .await
        .map_err(|e| format!("dsl stream: {}", e.message))?;
        if streamed.len() != 3 {
            return Err(format!(
                "dsl stream must return 3 hits, got {}",
                streamed.len()
            ));
        }

        Ok(())
    })
}

#[test]
#[ignore = "requires a live stack"]
fn search_reads_marked_documents_through_esql_and_dsl() {
    if skip_unless_live() {
        return;
    }
    let _serial = serialize_live();
    let dir = tempfile::tempdir().unwrap();
    let config = write_live_config(dir.path());
    let profile = live_profile();
    let baseline = capture_baseline(&config, &profile).unwrap();
    let index = unique_name("search");
    let mut cleanup = LiveCleanup::new(config.clone(), profile.clone());
    cleanup.index(index.clone());

    let result = (|| -> TestResult {
        search_probe(&profile, &index)?;
        Ok(())
    })();
    conclude(result, &mut cleanup, baseline);
}

/// ~5-minute alert budget, the recorder's proven cadence
/// (`xtask/src/main.rs`'s `ALERT_POLL_ATTEMPTS`/`ALERT_POLL_INTERVAL`).
const TRIAGE_POLL_ATTEMPTS: u32 = 30;
const TRIAGE_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Seed a marker index, enable a marker rule over it, wait for the alert it
/// generates, then drive every shipped alerts/cases plan-apply pair over
/// that one alert: by-id and query-scoped status transitions, tags,
/// assignment, and a full case round trip that attaches, comments, closes,
/// and deletes. `cleanup.rule(rule_id)`/`cleanup.alert_rule(rule_id)` and
/// `cleanup.index(index)` plus the case's exact title/tag cleanup scope are
/// registered by the caller before this runs; `cleanup.case(id)` is added
/// immediately once the create response supplies the id.
fn triage_probe(
    profile: &Profile,
    index: &str,
    rule_id: &str,
    case_title: &str,
    cleanup: &mut LiveCleanup,
) -> TestResult {
    let profile = profile.clone();
    let index = index.to_string();
    let rule_id = rule_id.to_string();
    let case_title = case_title.to_string();
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| format!("building triage runtime: {e}"))?;
    runtime.block_on(async move {
        let transport = Transport::new(&profile)
            .map_err(|e| format!("building triage transport: {}", e.message))?;

        // 1. Seed three marker-scoped documents the marker rule will match.
        for seq in 1..=3_i64 {
            transport
                .post_absolute_es(
                    &format!("/{index}/_doc?refresh=wait_for"),
                    &json!({
                        "@timestamp": current_rfc3339(),
                        "seq": seq,
                        "message": format!("elasticctl live triage {seq}"),
                        "marker": LIVE_TAG,
                    }),
                )
                .await
                .map_err(|e| format!("seeding triage document {seq}: {}", e.message))?;
        }

        // 2. Create the marker rule, enabled, over the seeded index.
        let rule_body = json!({
            "rule_id": rule_id,
            "name": rule_id,
            "description": "Created by elasticctl's live conformance suite. Safe to delete.",
            "type": "query",
            "language": "kuery",
            "query": format!("marker: \"{LIVE_TAG}\""),
            "index": [index],
            "severity": "low",
            "risk_score": 21,
            "enabled": true,
            "from": "now-10m",
            "interval": "1m",
            "tags": [LIVE_TAG],
        });
        let rule = elasticctl_api::model::Rule::from_value(rule_body)
            .map_err(|e| format!("building triage marker rule: {}", e.message))?;
        elasticctl_api::rules::create(&transport, &rule)
            .await
            .map_err(|e| format!("creating triage marker rule: {}", e.message))?;

        // 3. Poll for the alert the marker rule generates.
        let mut alert_id: Option<String> = None;
        for attempt in 0..TRIAGE_POLL_ATTEMPTS {
            let page = elasticctl_api::alerts::search(
                &transport,
                &json!({
                    "query": open_marker_rule_alerts_query(&rule_id),
                    "sort": elasticctl_api::alerts_ops::default_sort(),
                    "size": 10,
                    "track_total_hits": true,
                    "_source": elasticctl_api::alerts_ops::RESOLVE_SOURCE_FIELDS,
                }),
            )
            .await
            .map_err(|e| format!("polling for triage alert: {}", e.message))?;
            if let Some(hit) = page.hits.first() {
                alert_id = Some(hit.id.clone());
                break;
            }
            if attempt + 1 < TRIAGE_POLL_ATTEMPTS {
                tokio::time::sleep(TRIAGE_POLL_INTERVAL).await;
            }
        }
        let alert_id = alert_id.ok_or_else(|| {
            format!(
                "no alert appeared for rule {rule_id} after {TRIAGE_POLL_ATTEMPTS} attempts \
                 ({TRIAGE_POLL_ATTEMPTS} x {TRIAGE_POLL_INTERVAL:?})"
            )
        })?;

        // 4. By-id transitions: open -> acknowledged -> closed.
        let plan = elasticctl_api::alerts_ops::plan_status_by_ids(
            &transport,
            std::slice::from_ref(&alert_id),
            elasticctl_api::alerts::AlertStatus::Acknowledged,
            None,
        )
        .await
        .map_err(|e| format!("planning acknowledge by id: {}", e.message))?;
        let report = elasticctl_api::alerts_ops::apply_status_by_ids(&transport, &plan)
            .await
            .map_err(|e| format!("acknowledging alert by id: {}", e.message))?;
        if report.updated != 1 || report.failed != 0 {
            return Err(format!(
                "acknowledge by id must update exactly 1 alert with no failures: {report:?}"
            ));
        }

        let plan = elasticctl_api::alerts_ops::plan_status_by_ids(
            &transport,
            std::slice::from_ref(&alert_id),
            elasticctl_api::alerts::AlertStatus::Closed,
            None,
        )
        .await
        .map_err(|e| format!("planning close by id: {}", e.message))?;
        let report = elasticctl_api::alerts_ops::apply_status_by_ids(&transport, &plan)
            .await
            .map_err(|e| format!("closing alert by id: {}", e.message))?;
        if report.updated != 1 || report.failed != 0 {
            return Err(format!(
                "close by id must update exactly 1 alert with no failures: {report:?}"
            ));
        }

        // 5. Query-scoped transitions: re-open, then close again.
        let query = json!({"term": {"kibana.alert.rule.rule_id": rule_id}});
        let plan = elasticctl_api::alerts_ops::plan_status_by_query(
            &transport,
            query.clone(),
            elasticctl_api::alerts::AlertStatus::Open,
            elasticctl_api::alerts::Conflicts::Abort,
            None,
        )
        .await
        .map_err(|e| format!("planning open by query: {}", e.message))?;
        if plan.matched < 1 {
            return Err(format!(
                "query-scoped plan must match at least 1 alert: {plan:?}"
            ));
        }
        if plan.preview_details.is_empty() {
            return Err("query-scoped plan preview must not be empty".to_string());
        }
        if plan.preview_details.last().map(String::as_str)
            != Some("The set is resolved again at apply time; this count is advisory.")
        {
            return Err(format!(
                "query-scoped plan preview must end with the advisory line: {:?}",
                plan.preview_details
            ));
        }
        let report = elasticctl_api::alerts_ops::apply_status_by_query(&transport, &plan)
            .await
            .map_err(|e| format!("opening alert by query: {}", e.message))?;
        if report.failed != 0 {
            return Err(format!("open by query must have no failures: {report:?}"));
        }

        let plan = elasticctl_api::alerts_ops::plan_status_by_query(
            &transport,
            query.clone(),
            elasticctl_api::alerts::AlertStatus::Closed,
            elasticctl_api::alerts::Conflicts::Abort,
            None,
        )
        .await
        .map_err(|e| format!("planning close by query: {}", e.message))?;
        let report = elasticctl_api::alerts_ops::apply_status_by_query(&transport, &plan)
            .await
            .map_err(|e| format!("closing alert by query: {}", e.message))?;
        if report.failed != 0 {
            return Err(format!("close by query must have no failures: {report:?}"));
        }

        // 6. Tag and untag.
        let plan = elasticctl_api::alerts_ops::plan_tags(
            &transport,
            std::slice::from_ref(&alert_id),
            vec!["elasticctl-live-triage-check".to_string()],
            vec![],
        )
        .await
        .map_err(|e| format!("planning tag add: {}", e.message))?;
        let report = elasticctl_api::alerts_ops::apply_tags(&transport, &plan)
            .await
            .map_err(|e| format!("adding tag: {}", e.message))?;
        if report.updated != 1 {
            return Err(format!("tag add must update exactly 1 alert: {report:?}"));
        }

        let plan = elasticctl_api::alerts_ops::plan_tags(
            &transport,
            std::slice::from_ref(&alert_id),
            vec![],
            vec!["elasticctl-live-triage-check".to_string()],
        )
        .await
        .map_err(|e| format!("planning tag remove: {}", e.message))?;
        let report = elasticctl_api::alerts_ops::apply_tags(&transport, &plan)
            .await
            .map_err(|e| format!("removing tag: {}", e.message))?;
        if report.updated != 1 {
            return Err(format!(
                "tag remove must update exactly 1 alert: {report:?}"
            ));
        }

        // 7. Resolve an activated profile and assign/unassign it. This also
        // exercises the per-flavor profile-suggest route switch.
        let flavor = transport
            .capabilities()
            .await
            .map_err(|e| format!("probing capabilities: {}", e.message))?
            .flavor;
        let profiles = elasticctl_api::profiles::suggest(&transport, flavor, "")
            .await
            .map_err(|e| format!("suggesting profiles: {}", e.message))?;
        let assignee_uid = profiles.first().map(|p| p.uid.clone()).ok_or_else(|| {
            "no activated user profile is available for assignment; every conformance leg \
             boots with at least one activated profile"
                .to_string()
        })?;

        let report = elasticctl_api::alerts::set_assignees(
            &transport,
            std::slice::from_ref(&alert_id),
            std::slice::from_ref(&assignee_uid),
            &[],
        )
        .await
        .map_err(|e| format!("assigning alert: {}", e.message))?;
        if report.updated != 1 {
            return Err(format!("assign must update exactly 1 alert: {report:?}"));
        }

        let report = elasticctl_api::alerts::set_assignees(
            &transport,
            std::slice::from_ref(&alert_id),
            &[],
            std::slice::from_ref(&assignee_uid),
        )
        .await
        .map_err(|e| format!("unassigning alert: {}", e.message))?;
        if report.updated != 1 {
            return Err(format!("unassign must update exactly 1 alert: {report:?}"));
        }

        // 8. Case round trip: create, attach, comment, close, delete.
        let plan = elasticctl_api::cases_ops::plan_create(
            &transport,
            &case_title,
            None,
            vec![LIVE_TAG.to_string()],
            None,
            &[],
        )
        .await
        .map_err(|e| format!("planning case create: {}", e.message))?;
        let created = elasticctl_api::cases_ops::apply_create(&transport, &plan)
            .await
            .map_err(|e| format!("creating case: {}", e.message))?;
        let case_id = created["id"]
            .as_str()
            .ok_or_else(|| format!("case create response has no id: {created}"))?
            .to_string();
        cleanup.case(case_id.clone());

        let plan = elasticctl_api::cases_ops::plan_attach(
            &transport,
            &case_id,
            std::slice::from_ref(&alert_id),
        )
        .await
        .map_err(|e| format!("planning case attach: {}", e.message))?;
        let report = elasticctl_api::cases_ops::apply_attach(&transport, &plan)
            .await
            .map_err(|e| format!("attaching alert to case: {}", e.message))?;
        if report.updated != 1 {
            return Err(format!(
                "case attach must update exactly 1 alert: {report:?}"
            ));
        }

        let plan = elasticctl_api::cases_ops::plan_comment(
            &transport,
            &case_id,
            "elasticctl live conformance check",
        )
        .await
        .map_err(|e| format!("planning case comment: {}", e.message))?;
        elasticctl_api::cases_ops::apply_comment(&transport, &plan)
            .await
            .map_err(|e| format!("commenting on case: {}", e.message))?;

        let plan = elasticctl_api::cases_ops::plan_status(
            &transport,
            std::slice::from_ref(&case_id),
            elasticctl_api::cases::CaseStatus::Closed,
        )
        .await
        .map_err(|e| format!("planning case close: {}", e.message))?;
        let report = elasticctl_api::cases_ops::apply_status(&transport, &plan)
            .await
            .map_err(|e| format!("closing case: {}", e.message))?;
        if report.updated != 1 {
            return Err(format!("case close must update exactly 1 case: {report:?}"));
        }

        let plan =
            elasticctl_api::cases_ops::plan_delete(&transport, std::slice::from_ref(&case_id))
                .await
                .map_err(|e| format!("planning case delete: {}", e.message))?;
        let report = elasticctl_api::cases_ops::apply_delete(&transport, &plan)
            .await
            .map_err(|e| format!("deleting case: {}", e.message))?;
        if report.updated != 1 {
            return Err(format!(
                "case delete must update exactly 1 case: {report:?}"
            ));
        }
        match elasticctl_api::cases::get(&transport, &case_id).await {
            Err(elasticctl_core::Error {
                kind: ErrorKind::NotFound,
                ..
            }) => {}
            Ok(case) => {
                return Err(format!(
                    "deleted case {case_id} is still retrievable: {case:?}"
                ));
            }
            Err(e) => return Err(format!("verifying case delete: {}", e.message)),
        }

        // 9. Final sweep: close every straggler alert this rule produced and
        // confirm none stay open. Cleanup's rule deletion disables the rule,
        // so one in-flight execution may still land an alert after step 5's
        // close; this absorbs that race.
        elasticctl_api::alerts::status_by_query(
            &transport,
            &json!({"term": {"kibana.alert.rule.rule_id": rule_id}}),
            elasticctl_api::alerts::AlertStatus::Closed,
            elasticctl_api::alerts::Conflicts::Proceed,
            None,
        )
        .await
        .map_err(|e| format!("final sweep closing alerts: {}", e.message))?;

        let mut open_remaining = u64::MAX;
        for attempt in 0..5 {
            let page = elasticctl_api::alerts::search(
                &transport,
                &json!({
                    "query": open_marker_rule_alerts_query(&rule_id),
                    "size": 0,
                    "track_total_hits": true,
                }),
            )
            .await
            .map_err(|e| format!("final sweep verifying closed alerts: {}", e.message))?;
            open_remaining =
                required_alert_total(page.total, "final sweep verifying closed alerts")?;
            if open_remaining == 0 {
                break;
            }
            if attempt + 1 < 5 {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
        if open_remaining != 0 {
            return Err(format!(
                "{open_remaining} open alert(s) remain for rule {rule_id} after the final sweep"
            ));
        }

        Ok(())
    })
}

#[test]
#[ignore = "requires a live stack"]
fn triage_transitions_alerts_and_cases_and_leaves_only_closed_residue() {
    if skip_unless_live() {
        return;
    }
    let _serial = serialize_live();
    let dir = tempfile::tempdir().unwrap();
    let config = write_live_config(dir.path());
    let profile = live_profile();
    let baseline = capture_baseline(&config, &profile).unwrap();
    let index = unique_name("triage-index");
    let rule_id = unique_name("triage-rule");
    let case_title = unique_name("case");
    let mut cleanup = LiveCleanup::new(config.clone(), profile.clone());
    // Registered before triage_probe can create either object.
    cleanup.index(index.clone());
    cleanup.rule(rule_id.clone());
    cleanup.alert_rule(rule_id.clone());
    cleanup.case_scope(case_title.clone(), LIVE_TAG);

    let result = (|| -> TestResult {
        triage_probe(&profile, &index, &rule_id, &case_title, &mut cleanup)?;
        Ok(())
    })();
    conclude(result, &mut cleanup, baseline);
}
