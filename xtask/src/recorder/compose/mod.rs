//! Compose recording: the request shapes behind the cross-vertical task
//! tools, recorded from marker objects only.
//!
//! The step creates a marker index, list, two items, two rules, and a case
//! under fixed marker identities, each with a create-only request. Its own
//! cleanup removes exactly what this run created and closes this run's
//! alerts by id; the shared cleanup of `cargo xtask record` is not used.
//! A create whose answer was lost is watched for a settle window before its
//! claim clears. Cleanup runs after success, failure, a panic, or Ctrl-C,
//! under a time bound, and the baseline audit then requires the state
//! captured before the first write. Fixtures are written only when all of
//! them succeed.

mod alert_search;
mod baseline;
mod cleanup;
mod evidence;
mod guard;
mod provision;
mod requests;
mod settle;
mod steps;

use crate::diagnostics::{
    recording_error, safe_recording_error_summary, safe_recording_transport_error,
};
use crate::environment::{activate_traditional_recorder_profile, transport_from_env};
use crate::fixtures::{Recording, write_recording};
use crate::recorder::agent_policies::reduce_package_status_item;
use crate::recorder::session::{CleanupOwnership, RecordingSession};
use baseline::Baseline;
use cleanup::Failure;
use elasticctl_core::Transport;
use evidence::{Exchanges, PrivateLog};
use guard::{Ended, guarded};
use serde_json::json;
use settle::{Timing, Unresolved};
use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

/// The second compose rule: enabled over a marker index that never exists.
const MISSING_RULE_ID: &str = "elasticctl-sample-compose-missing-index";
const MISSING_RULE_NAME: &str = "elasticctl sample compose missing index";
/// Name of the alerting compose rule, created under the alert probe rule id.
const COMPOSE_RULE_NAME: &str = "elasticctl sample compose rule";
/// The second item on the marker list.
const COMPOSE_ITEM_ID: &str = "elasticctl-sample-exception-item-2";
/// A concrete marker index name that is never created.
const MISSING_INDEX: &str = "elasticctl-sample-compose-missing";
/// The alert probe index as a pattern.
const MATCH_PATTERN: &str = "elasticctl-sample-alert-events*";
/// A marker wildcard that matches nothing.
const NO_MATCH_PATTERN: &str = "elasticctl-sample-compose-none-*";
/// An exclusion as a rule's index list holds it. Measured privately.
const EXCLUSION_PATTERN: &str = "-elasticctl-sample-alert-events*";
/// A marker alert id that never exists.
const ABSENT_ALERT_ID: &str = "elasticctl-sample-absent-alert";
/// Marker documents, and so session alerts. At least the activity page size,
/// so every recorded hit is a session alert.
const ALERT_DOCS: usize = 5;
/// The `since` default of the task tools.
const ACTIVITY_SINCE: &str = "24h";
/// The `rule_health` activity page size.
const ACTIVITY_SIZE: u64 = 5;
const TECHNIQUE: &str = "T1059";
/// The tactic and subtechnique of the marker rule, probed privately.
const TACTIC: &str = "TA0002";
const SUBTECHNIQUE: &str = "T1059.001";
/// The verified corpus page size.
const SORTED_PAGE_SIZE: u32 = 500;
/// The `rules_list` default limit.
const TECHNIQUE_PAGE_SIZE: u32 = 50;
/// Packages tried, in order, for one that is not installed.
const PACKAGE_CANDIDATES: [&str; 3] = ["apache", "nginx", "mysql"];
/// Reads of the case attachment, and of the attached alert before the
/// case-ids answer is logged.
const CASE_IDS_ATTEMPTS: u32 = 3;
/// The bound on cleanup and the baseline audit together.
const TEARDOWN_LIMIT: Duration = Duration::from_secs(600);

/// Server ids this run learned for the objects it created. They stay in
/// memory: cleanup's re-reads must still show them, and fixtures hold only
/// placeholders.
#[derive(Default)]
struct ServerIds {
    list: Option<String>,
    item: Option<String>,
    compose_item: Option<String>,
    rule: Option<String>,
    missing_rule: Option<String>,
    case: Option<String>,
    /// The UUID of the marker index this run created. The index is written
    /// to and deleted only while it still reports this UUID.
    index_uuid: Option<String>,
}

/// The session's ownership flags plus what this run learned. The step and
/// cleanup both borrow it, so a panic or an interrupt leaves it as it stood.
struct ComposeSession<'a> {
    session: RecordingSession<'a>,
    ids: ServerIds,
    /// Captured before the first write; the audit requires it again.
    baseline: Option<Baseline>,
    /// Owned objects whose create answer was lost.
    unresolved: Unresolved,
    /// The alerts of this run's alerting rule. Set with the rule's claim,
    /// cleared once the rule is gone and a complete search has found none
    /// of them open for the whole settle window.
    alerts: bool,
}

impl<'a> ComposeSession<'a> {
    fn new(transport: &'a Transport) -> Self {
        Self {
            session: RecordingSession {
                transport,
                ownership: CleanupOwnership::default(),
            },
            ids: ServerIds::default(),
            baseline: None,
            unresolved: Unresolved::default(),
            alerts: false,
        }
    }
}

fn fixture_dir(flavor: &str, version: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests/fixtures")
        .join(format!("{flavor}-{version}"))
}

async fn record_steps(
    compose: &mut ComposeSession<'_>,
    log: &mut PrivateLog,
    fixture_flavor: Option<String>,
    interval: Duration,
) -> elasticctl_core::Result<Recording> {
    let t = compose.session.transport;
    let status = t
        .get("/api/status")
        .await
        .map_err(|error| safe_recording_transport_error("reading stack status failed", error))?;
    let version = status["version"]["number"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let flavor = fixture_flavor.unwrap_or_else(|| {
        status["version"]["build_flavor"]
            .as_str()
            .unwrap_or("default")
            .to_string()
    });
    log.set_target(&flavor, &version);

    compose.baseline = Some(baseline::capture(t).await?);
    let (package, package_body) = provision::probe_not_installed_package(t).await?;
    log.add("responses", "package_not_installed", package_body.clone());
    provision::require_installed_system(t, log).await?;

    let mut exchanges = Exchanges::default();
    provision::create_index(compose).await?;
    steps::record_resolve(t, &mut exchanges, log).await?;
    provision::create_objects(compose).await?;
    let ids = &compose.ids;
    let rule_uuid = ids
        .rule
        .clone()
        .ok_or_else(|| recording_error("the marker rule id is unknown"))?;
    let mut placeholders = BTreeMap::new();
    for (id, placeholder) in [
        (&ids.list, "elasticctl-fixture-exception-list"),
        (&ids.rule, "elasticctl-fixture-rule-uuid"),
        (&ids.missing_rule, "elasticctl-fixture-rule-uuid-2"),
    ] {
        if let Some(id) = id {
            placeholders.insert(id.clone(), placeholder.to_string());
        }
    }
    steps::record_rules(t, &mut exchanges, log, interval).await?;
    let alert = steps::record_activity(
        t,
        &mut exchanges,
        log,
        &mut placeholders,
        &rule_uuid,
        interval,
    )
    .await?;
    steps::record_cases(
        compose,
        &mut exchanges,
        log,
        &mut placeholders,
        &alert,
        interval,
    )
    .await?;

    let reduced = reduce_package_status_item(&package_body)
        .ok_or_else(|| recording_error("package status did not carry a reducible item"))?;
    exchanges.response(
        "package_not_installed",
        &requests::package_status(package),
        json!({"item": reduced}),
    );

    Ok(Recording {
        dir: fixture_dir(&flavor, &version),
        fixtures: exchanges.into_fixtures(&flavor, &version, &placeholders),
    })
}

/// What cleanup and the baseline audit returned.
struct Teardown {
    failures: Vec<Failure>,
    /// `None` when the step stopped before it captured a baseline, and so
    /// before any write.
    audit: Option<elasticctl_core::Result<()>>,
}

/// Everything `finish` needs to decide whether fixtures may be written.
struct RunOutcome {
    step: Ended<elasticctl_core::Result<Recording>>,
    teardown: Ended<Teardown>,
    still_owned: Vec<&'static str>,
    /// Owned objects whose create answer was lost and that did not settle.
    unresolved: Vec<&'static str>,
}

/// Cleanup, with its settle windows, and then the baseline audit.
async fn teardown(compose: &mut ComposeSession<'_>, timing: Timing) -> Teardown {
    let failures = cleanup::cleanup(compose, &timing).await;
    let audit = match &compose.baseline {
        Some(baseline) => Some(
            baseline::audit(
                compose.session.transport,
                baseline,
                compose.ids.rule.as_deref(),
            )
            .await,
        ),
        None => None,
    };
    Teardown { failures, audit }
}

/// Cleanup and the audit, outside whatever ended the step. A second
/// interrupt or the time bound stops them, and the objects still owned are
/// reported.
async fn conclude(
    compose: &mut ComposeSession<'_>,
    step: Ended<elasticctl_core::Result<Recording>>,
    timing: Timing,
    interrupt: impl Future<Output = ()>,
) -> RunOutcome {
    let teardown = guarded(teardown(compose, timing), Some(TEARDOWN_LIMIT), interrupt).await;
    RunOutcome {
        step,
        teardown,
        still_owned: cleanup::still_owned(compose),
        unresolved: cleanup::still_unresolved(compose),
    }
}

/// Run the step so that a panic or an interrupt still reaches cleanup.
/// `interrupt` is called once for the step and once for cleanup.
async fn run<I, F>(
    compose: &mut ComposeSession<'_>,
    log: &mut PrivateLog,
    fixture_flavor: Option<String>,
    timing: Timing,
    mut interrupt: I,
) -> RunOutcome
where
    I: FnMut() -> F,
    F: Future<Output = ()>,
{
    let step = guarded(
        record_steps(compose, log, fixture_flavor, timing.poll),
        None,
        interrupt(),
    )
    .await;
    conclude(compose, step, timing, interrupt()).await
}

/// Decide the result and the lines to print. Fixtures are written only when
/// the step, cleanup, and the baseline audit all succeeded and nothing is
/// still owned or unresolved. Each line holds static text, constants, or an
/// error's class and status.
fn finish(
    outcome: RunOutcome,
    write: impl FnOnce(Recording) -> elasticctl_core::Result<()>,
) -> (bool, Vec<String>) {
    let mut lines = Vec::new();
    let recording = match outcome.step {
        Ended::Finished(Ok(recording)) => Some(recording),
        Ended::Finished(Err(error)) => {
            lines.push(format!(
                "record-compose failed: {} ({})",
                error.message,
                safe_recording_error_summary(&error)
            ));
            None
        }
        Ended::Panicked => {
            lines.push("record-compose failed: the step panicked".to_string());
            None
        }
        Ended::Interrupted => {
            lines.push("record-compose interrupted".to_string());
            None
        }
        Ended::TimedOut => {
            lines.push("record-compose failed: the step timed out".to_string());
            None
        }
    };
    let mut clean = match outcome.teardown {
        Ended::Finished(teardown) => {
            for failure in &teardown.failures {
                lines.push(format!("record-compose cleanup: {failure}"));
            }
            let audited = match teardown.audit {
                Some(Ok(())) => true,
                Some(Err(error)) => {
                    lines.push(format!(
                        "record-compose baseline audit failed: {} ({})",
                        error.message,
                        safe_recording_error_summary(&error)
                    ));
                    false
                }
                None => false,
            };
            teardown.failures.is_empty() && audited
        }
        Ended::Panicked => {
            lines.push("record-compose cleanup panicked".to_string());
            false
        }
        Ended::Interrupted => {
            lines.push("record-compose cleanup interrupted".to_string());
            false
        }
        Ended::TimedOut => {
            lines.push("record-compose cleanup stopped at its time bound".to_string());
            false
        }
    };
    if !outcome.still_owned.is_empty() {
        lines.push(format!(
            "record-compose cleanup left in place: {}",
            outcome.still_owned.join(", ")
        ));
        clean = false;
    }
    if !outcome.unresolved.is_empty() {
        lines.push(format!(
            "record-compose needs manual recovery: {} may still be created by a request whose answer was lost",
            outcome.unresolved.join(", ")
        ));
        clean = false;
    }
    match recording {
        Some(recording) if clean => match write(recording) {
            Ok(()) => {
                lines.push("recorded compose fixtures".to_string());
                (true, lines)
            }
            Err(error) => {
                lines.push(format!(
                    "record-compose failed after cleanup: {}",
                    error.message
                ));
                (false, lines)
            }
        },
        _ => (false, lines),
    }
}

/// `cargo xtask record-compose`: record the compose fixtures from the target
/// that `cargo xtask record` reads, then clean every marker object.
pub(crate) async fn record_compose() {
    if let Err(error) = activate_traditional_recorder_profile().await {
        eprintln!("record-compose setup failed: {}", error.message);
        std::process::exit(1);
    }
    // A panic message can quote a value it was handling. Print a fixed line;
    // the step's own result reports which phase stopped.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("record-compose: a panic stopped the current operation");
    }));
    let transport = transport_from_env(60);
    let mut compose = ComposeSession::new(&transport);
    let mut log = PrivateLog::default();
    let fixture_flavor = std::env::var("ELASTICCTL_FIXTURE_FLAVOR").ok();
    let outcome = run(
        &mut compose,
        &mut log,
        fixture_flavor,
        Timing::LIVE,
        guard::ctrl_c,
    )
    .await;

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    match log.write(&workspace) {
        Ok(path) => println!(
            "wrote private log {}",
            path.strip_prefix(&workspace).unwrap_or(&path).display()
        ),
        Err(message) => eprintln!("{message}"),
    }

    let (succeeded, lines) = finish(outcome, write_recording);
    for line in &lines {
        if succeeded {
            println!("{line}");
        } else {
            eprintln!("{line}");
        }
    }
    if !succeeded {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod fake_stack {
    //! A stateful fake of every route the compose step and its cleanup send.
    //! Creates apply before an injected failure answers, which models a
    //! create whose answer was lost.

    use crate::recorder::compose::requests::{LISTS_FIND_PATH, PREBUILT_STATUS_PATH};
    use crate::recorder::compose::{ALERT_DOCS, COMPOSE_RULE_NAME};
    use crate::recorder::markers::{ALERT_MARKER_TAG, ALERT_PROBE_INDEX, ALERT_RULE_ID, LIST_ID};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::Notify;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    pub(super) const ALERT_INDEX: &str = ".internal.alerts-security.alerts-default-000001";
    pub(super) const PREBUILT_RULES: u64 = 2263;
    pub(super) const SESSION_RULE_UUID: &str = "so-elasticctl-sample-alert-probe";
    /// The UUID of a marker index another run created.
    pub(super) const FOREIGN_INDEX_UUID: &str = "uuid-foreign";
    /// What a server can write in its own words: an authorization failure
    /// that quotes a user, an email, an API key id, a host, and an index.
    pub(super) const IDENTITY_PROSE: &str = "action [indices:data/read/search] is unauthorized for API key id [kq3Rb-identity-key] of user [jdoe-operator] (jdoe@example.com) on kb.private.example.internal for index [prod-secrets-000001]";
    /// Each identity the prose above quotes.
    pub(super) const IDENTITY_TOKENS: [&str; 5] = [
        "kq3Rb-identity-key",
        "jdoe-operator",
        "jdoe@example.com",
        "kb.private.example.internal",
        "prod-secrets-000001",
    ];

    #[derive(Default)]
    pub(super) struct State {
        /// The marker index documents, by id.
        pub(super) index: BTreeMap<String, Value>,
        /// The marker index UUID while the index exists.
        pub(super) index_uuid: Option<String>,
        index_creates: u32,
        /// Another run's marker index, without document 1, appears right
        /// after the preflight.
        pub(super) index_after_preflight: bool,
        /// Another run's marker index, with a marker document 1, replaces
        /// this run's index just before cleanup reaches it.
        pub(super) index_replaced_before_cleanup: bool,
        /// The request line after whose answer another run's marker index
        /// replaces this run's.
        pub(super) index_replaced_after: Option<String>,
        pub(super) list: Option<Value>,
        pub(super) items: BTreeMap<String, Value>,
        pub(super) rules: BTreeMap<String, Value>,
        rule_reads: BTreeMap<String, u32>,
        pub(super) alerts: Vec<Value>,
        pub(super) cases: BTreeMap<String, Value>,
        attached: Vec<String>,
        prebuilt_reads: u32,
        pub(super) log: Vec<String>,
        /// The label of every create request received.
        pub(super) creates: Vec<String>,
        pub(super) unexpected: Vec<String>,
        pub(super) status_requests: Vec<Value>,
        pub(super) installed: Vec<&'static str>,
        /// A create label answered 400 after the create applied.
        pub(super) fail_on: Option<String>,
        /// A create label answered 503 after the create applied.
        pub(super) unavailable_after_create: Option<String>,
        /// A create label answered 503 before it applies. The object lands
        /// right after the next read of its identity; a marker document
        /// lands once the index is gone, and creates it again.
        pub(super) late_create: Option<String>,
        /// A create label answered 503 that never lands.
        pub(super) lost_create: Option<String>,
        pending: Option<(String, Request)>,
        /// A fault on every cleanup search for open session alerts:
        /// `timed_out`, `shard`, or `inexact`. The fault answers no hits.
        pub(super) alert_search_fault: Option<&'static str>,
        /// After a close, the first open-alert search that finds none is
        /// followed by one more open session alert, as the rule's last
        /// execution writes it late.
        pub(super) late_alert: bool,
        late_alert_written: bool,
        /// An inventory, `rules`, `lists`, or `indices`, whose reads after
        /// the first report one more marker object.
        pub(super) inventory_change: Option<&'static str>,
        inventory_reads: BTreeMap<&'static str, u32>,
        /// A create label whose identity another run takes just before this
        /// run's create arrives: a foreign object is stored and the create
        /// answers 409.
        pub(super) conflict_on: Option<String>,
        /// A delete label answered 200 while the object stays.
        pub(super) sticky_delete: Option<String>,
        /// A delete label answered 500 with server text naming a host.
        pub(super) failing_delete: Option<String>,
        /// A create label whose object loses its marker tag right after.
        pub(super) retag_after_create: Option<String>,
        /// A create label answered only after two seconds.
        pub(super) slow_create: Option<String>,
        /// A delete label answered only after two seconds.
        pub(super) slow_delete: Option<String>,
        /// A create label that fires the interrupt while its answer waits.
        pub(super) interrupt_on: Option<(String, Arc<Notify>)>,
        pub(super) resolve_match_body: Option<Value>,
        /// The prebuilt count every read after the first reports.
        pub(super) prebuilt_after: Option<u64>,
        /// An open alert of the same rule id from an earlier run.
        pub(super) historical_alert: bool,
        pub(super) foreign_hits: bool,
        pub(super) foreign_rule: bool,
        pub(super) foreign_case: bool,
        pub(super) attachment_lag: u32,
        pub(super) existing_rule: bool,
    }

    impl State {
        pub(super) fn is_empty(&self) -> bool {
            self.index.is_empty()
                && self.index_uuid.is_none()
                && self.list.is_none()
                && self.items.is_empty()
                && self.rules.is_empty()
                && self.cases.is_empty()
        }

        pub(super) fn open_alerts(&self, rule_uuid: &str) -> usize {
            self.alerts
                .iter()
                .filter(|alert| {
                    alert["_source"]["kibana.alert.rule.uuid"] == rule_uuid
                        && alert["_source"]["kibana.alert.workflow_status"] != "closed"
                })
                .count()
        }

        pub(super) fn mutations(&self) -> Vec<String> {
            self.log
                .iter()
                .filter(|line| !line.starts_with("GET "))
                .cloned()
                .collect()
        }
    }

    fn json_response(status: u16, body: Value) -> ResponseTemplate {
        ResponseTemplate::new(status).set_body_json(body)
    }

    fn missing() -> ResponseTemplate {
        json_response(
            404,
            json!({"statusCode": 404, "error": "Not Found", "message": "not found"}),
        )
    }

    fn query_value(request: &Request, key: &str) -> Option<String> {
        request
            .url
            .query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
    }

    fn rule_view(state: &mut State, rule_id: &str) -> Option<Value> {
        let reads = state.rule_reads.entry(rule_id.to_string()).or_default();
        *reads += 1;
        let reads = *reads;
        let mut rule = state.rules.get(rule_id)?.clone();
        if reads >= 2 {
            let (status, message) = if rule_id == ALERT_RULE_ID {
                ("succeeded", "Rule execution completed successfully")
            } else {
                ("partial failure", IDENTITY_PROSE)
            };
            rule["execution_summary"] = json!({"last_execution": {
                "date": "2026-11-10T01:03:00.000Z", "status": status, "status_order": 20,
                "message": message, "metrics": {"total_search_duration_ms": 7}
            }});
        }
        Some(rule)
    }

    fn alert(n: usize, rule_uuid: &str, list_so: &Value) -> Value {
        json!({
            "_id": format!("zz-alert-{n}"), "_index": ALERT_INDEX, "sort": [n, format!("zz-alert-{n}")],
            "_source": {
                "@timestamp": "2026-11-10T01:03:00.000Z",
                "kibana.alert.uuid": format!("zz-alert-{n}"),
                "kibana.alert.rule.uuid": rule_uuid,
                "kibana.alert.rule.rule_id": ALERT_RULE_ID,
                "kibana.alert.rule.name": COMPOSE_RULE_NAME,
                "kibana.alert.workflow_status": "open",
                "kibana.alert.reason": IDENTITY_PROSE,
                "kibana.alert.rule.parameters": {"exceptions_list": [{"id": list_so}]},
                "kibana.alert.url": "https://private.example.internal/app/zz-alert-1"
            }
        })
    }

    fn create_rule(state: &mut State, body: &Value) -> Value {
        let rule_id = body["rule_id"].as_str().unwrap_or_default().to_string();
        let mut rule = body.clone();
        rule["id"] = json!(format!("so-{rule_id}"));
        rule["created_at"] = json!("2026-11-10T01:02:00.000Z");
        rule["updated_at"] = json!("2026-11-10T01:02:00.000Z");
        if rule_id == ALERT_RULE_ID {
            let list_so = state
                .list
                .as_ref()
                .map(|l| l["id"].clone())
                .unwrap_or_default();
            for n in 1..=ALERT_DOCS {
                state.alerts.push(alert(n, SESSION_RULE_UUID, &list_so));
            }
        }
        state.rules.insert(rule_id, rule.clone());
        rule
    }

    fn signals(state: &mut State, body: &Value) -> Value {
        if body.get("aggs").is_some() {
            // Newest first, as the activity sort asks.
            let mut hits: Vec<Value> = state.alerts.iter().rev().take(5).cloned().collect();
            if state.foreign_hits && !hits.is_empty() {
                hits[0]["_source"]["kibana.alert.rule.uuid"] = json!("so-older");
            }
            return json!({"took": 2, "timed_out": false,
                "hits": {"total": {"value": state.alerts.len(), "relation": "eq"}, "hits": hits},
                "aggregations": {"status": {"doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0,
                    "buckets": [{"key": "open", "doc_count": state.alerts.len()}]}}});
        }
        if let Some(values) = body.pointer("/query/ids/values").and_then(Value::as_array) {
            let id = values[0].as_str().unwrap_or_default();
            let mut source = json!({});
            if state.attached.iter().any(|a| a == id) {
                source["kibana.alert.case_ids"] = json!(state.cases.keys().collect::<Vec<_>>());
            }
            return json!({"hits": {"total": {"value": 1, "relation": "eq"},
                "hits": [{"_id": id, "_index": ALERT_INDEX, "_source": source}]}});
        }
        let terms: Vec<(String, Value)> = body
            .pointer("/query/bool/filter")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|clause| clause.get("term")?.as_object()?.iter().next())
            .map(|(field, value)| (field.clone(), value.clone()))
            .collect();
        let open_only = body.pointer("/query/bool/must_not").is_some();
        if open_only && let Some(fault) = state.alert_search_fault {
            let mut page = json!({"took": 1, "timed_out": false,
                "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
                "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}});
            match fault {
                "timed_out" => page["timed_out"] = json!(true),
                "shard" => {
                    page["_shards"]["successful"] = json!(0);
                    page["_shards"]["failed"] = json!(1);
                }
                _ => page["hits"]["total"]["relation"] = json!("gte"),
            }
            return page;
        }
        let matching: Vec<Value> = state
            .alerts
            .iter()
            .filter(|alert| {
                terms
                    .iter()
                    .all(|(field, value)| &alert["_source"][field.as_str()] == value)
            })
            .filter(|alert| {
                !open_only || alert["_source"]["kibana.alert.workflow_status"] != "closed"
            })
            .map(|alert| json!({"_id": alert["_id"], "_index": ALERT_INDEX}))
            .collect();
        let size = body["size"].as_u64().unwrap_or(0) as usize;
        if open_only
            && matching.is_empty()
            && state.late_alert
            && !state.late_alert_written
            && !state.status_requests.is_empty()
        {
            state.late_alert_written = true;
            state
                .alerts
                .push(alert(ALERT_DOCS + 1, SESSION_RULE_UUID, &Value::Null));
        }
        json!({"took": 1, "timed_out": false,
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "hits": {"total": {"value": matching.len(), "relation": "eq"},
            "hits": matching.into_iter().take(size).collect::<Vec<_>>()}})
    }

    fn close_alerts(state: &mut State, body: &Value) -> ResponseTemplate {
        state.status_requests.push(body.clone());
        let ids: Vec<&str> = body["signal_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let by_query = body
            .pointer("/query/term/kibana.alert.rule.rule_id")
            .cloned();
        let mut updated = 0;
        for alert in &mut state.alerts {
            let named = alert["_id"].as_str().is_some_and(|id| ids.contains(&id));
            let queried = by_query
                .as_ref()
                .is_some_and(|rule_id| &alert["_source"]["kibana.alert.rule.rule_id"] == rule_id);
            if named || queried {
                alert["_source"]["kibana.alert.workflow_status"] = json!("closed");
                updated += 1;
            }
        }
        json_response(
            200,
            json!({"total": updated, "updated": updated, "version_conflicts": 0,
                "noops": 0, "failures": []}),
        )
    }

    fn create_label(method: &str, path: &str, body: &Value) -> Option<String> {
        let marker_create = format!("/{ALERT_PROBE_INDEX}/_create/");
        match (method, path) {
            ("PUT", p) if p == format!("/{ALERT_PROBE_INDEX}") => Some("index".into()),
            ("POST", p) if p.starts_with(&marker_create) => {
                Some(format!("doc:{}", &p[marker_create.len()..]))
            }
            ("POST", "/api/exception_lists") => Some("list".into()),
            ("POST", "/api/exception_lists/items") => Some(format!(
                "item:{}",
                body["item_id"].as_str().unwrap_or_default()
            )),
            ("POST", "/api/detection_engine/rules") => Some(format!(
                "rule:{}",
                body["rule_id"].as_str().unwrap_or_default()
            )),
            ("POST", "/api/cases") => Some("case".into()),
            _ => None,
        }
    }

    fn delete_label(path: &str, request: &Request) -> Option<String> {
        match path {
            "/api/detection_engine/rules" => {
                Some(format!("rule:{}", query_value(request, "rule_id")?))
            }
            "/api/exception_lists/items" => {
                Some(format!("item:{}", query_value(request, "item_id")?))
            }
            "/api/exception_lists" => Some("list".into()),
            "/api/cases" => Some("case".into()),
            p if p == format!("/{ALERT_PROBE_INDEX}") => Some("index".into()),
            _ => None,
        }
    }

    /// The identity a cleanup or preflight read names.
    fn read_label(path: &str, request: &Request) -> Option<String> {
        match path {
            "/api/detection_engine/rules" => {
                Some(format!("rule:{}", query_value(request, "rule_id")?))
            }
            "/api/exception_lists/items" => {
                Some(format!("item:{}", query_value(request, "item_id")?))
            }
            "/api/exception_lists" => Some("list".into()),
            "/api/cases/_find" => Some("case".into()),
            p if p == format!("/{ALERT_PROBE_INDEX}/_settings/index.uuid") => Some("index".into()),
            _ => None,
        }
    }

    /// The Elasticsearch answer to an index create whose name is taken.
    fn index_exists(uuid: &str) -> ResponseTemplate {
        let reason = format!("index [{ALERT_PROBE_INDEX}/{uuid}] already exists");
        let cause = json!({"type": "resource_already_exists_exception", "reason": reason,
            "index_uuid": uuid, "index": ALERT_PROBE_INDEX});
        let mut error = cause.clone();
        error["root_cause"] = json!([cause]);
        json_response(400, json!({"error": error, "status": 400}))
    }

    fn index_not_found() -> ResponseTemplate {
        json_response(
            404,
            json!({"error": {"type": "index_not_found_exception",
                "reason": format!("no such index [{ALERT_PROBE_INDEX}]")}, "status": 404}),
        )
    }

    fn foreign_document() -> Value {
        json!({"marker": ALERT_MARKER_TAG, "owner": "another run"})
    }

    fn unavailable() -> ResponseTemplate {
        json_response(
            503,
            json!({"message": "private.example.internal unavailable"}),
        )
    }

    /// One more marker object in an inventory's reads after the first.
    fn inventory_extra(state: &mut State, kind: &'static str) -> usize {
        let reads = state.inventory_reads.entry(kind).or_default();
        *reads += 1;
        usize::from(state.inventory_change == Some(kind) && *reads > 1)
    }

    /// Store the object another run created under this run's fixed identity.
    /// It carries the marker, so only the create answer shows it is not ours.
    fn plant_foreign(state: &mut State, label: &str) {
        let tags = json!(["elasticctl", "fixture", ALERT_MARKER_TAG]);
        match label.split_once(':') {
            None if label == "index" => {
                state.index_uuid = Some(FOREIGN_INDEX_UUID.into());
                state.index.insert("1".into(), foreign_document());
            }
            None => {
                state.list = Some(json!({"list_id": LIST_ID, "namespace_type": "single",
                    "tags": tags, "id": "list-foreign"}));
            }
            Some(("doc", id)) => {
                state.index.insert(id.to_string(), foreign_document());
            }
            Some(("item", item_id)) => {
                state.items.insert(
                    item_id.to_string(),
                    json!({"item_id": item_id, "list_id": LIST_ID, "namespace_type": "single",
                        "tags": tags, "id": "item-foreign"}),
                );
            }
            Some((_, rule_id)) => {
                state.rules.insert(
                    rule_id.to_string(),
                    json!({"rule_id": rule_id, "tags": [ALERT_MARKER_TAG], "id": "so-foreign"}),
                );
            }
        }
    }

    pub(super) fn foreign_present(state: &State, label: &str) -> bool {
        match label.split_once(':') {
            None if label == "index" => state.index_uuid.as_deref() == Some(FOREIGN_INDEX_UUID),
            Some(("doc", id)) => state
                .index
                .get(id)
                .is_some_and(|doc| doc["owner"] == "another run"),
            None => state
                .list
                .as_ref()
                .is_some_and(|list| list["id"] == "list-foreign"),
            Some(("item", item_id)) => state
                .items
                .get(item_id)
                .is_some_and(|item| item["id"] == "item-foreign"),
            Some((_, rule_id)) => state
                .rules
                .get(rule_id)
                .is_some_and(|rule| rule["id"] == "so-foreign"),
        }
    }

    fn retag(state: &mut State, label: &str) {
        let other = json!(["other"]);
        match label.split_once(':') {
            Some(("item", item_id)) => {
                if let Some(item) = state.items.get_mut(item_id) {
                    item["tags"] = other;
                }
            }
            Some((_, rule_id)) => {
                if let Some(rule) = state.rules.get_mut(rule_id) {
                    rule["tags"] = other;
                }
            }
            None => {}
        }
    }

    fn handle(state: &mut State, request: &Request) -> ResponseTemplate {
        let method = request.method.to_string();
        let path = request.url.path().to_string();
        let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        state.log.push(match request.url.query() {
            Some(query) => format!("{method} {path}?{query}"),
            None => format!("{method} {path}"),
        });
        let created = create_label(&method, &path, &body);
        state.creates.extend(created.clone());
        let deleting = if method == "DELETE" {
            delete_label(&path, request)
        } else {
            None
        };
        let is = |label: &Option<String>, injected: &Option<String>| {
            label.is_some() && label == injected
        };
        if state.index_after_preflight
            && state.index_uuid.is_none()
            && path == "/api/fleet/epm/packages/system"
        {
            state.index_uuid = Some(FOREIGN_INDEX_UUID.into());
        }
        if is(&created, &state.conflict_on) {
            let label = created.unwrap_or_default();
            plant_foreign(state, &label);
            if label == "index" {
                return index_exists(FOREIGN_INDEX_UUID);
            }
            return json_response(
                409,
                json!({"statusCode": 409, "error": "Conflict",
                    "message": "private.example.internal: already exists"}),
            );
        }
        if is(&created, &state.late_create) {
            state.pending = created.clone().map(|label| (label, request.clone()));
            return unavailable();
        }
        if is(&created, &state.lost_create) {
            return unavailable();
        }
        let read = read_label(&path, request);
        let landing = method == "GET"
            && match state.pending.as_ref() {
                // A delayed document write lands once the index is gone, and
                // creates it again as automatic index creation does.
                Some((label, _)) if label.starts_with("doc:") => {
                    read.as_deref() == Some("index") && state.index_uuid.is_none()
                }
                Some((label, _)) => Some(label) == read.as_ref(),
                None => false,
            };
        if is(&deleting, &state.sticky_delete) {
            return json_response(200, json!({"acknowledged": true}));
        }
        if is(&deleting, &state.failing_delete) {
            return json_response(
                500,
                json!({"message": "https://private.example.internal:9243/x refused for operator@example.com"}),
            );
        }
        let mut response = route(state, &method, &path, &body, request);
        if state.index_replaced_after.is_some()
            && state.index_replaced_after.as_ref() == state.log.last()
        {
            state.index_replaced_after = None;
            state.index_uuid = Some("uuid-other-run".into());
            state.index = BTreeMap::from([("1".to_string(), foreign_document())]);
        }
        if state.index_replaced_before_cleanup && deleting.as_deref() == Some("list") {
            state.index_uuid = Some("uuid-other-run".into());
            state.index = BTreeMap::from([("1".to_string(), foreign_document())]);
        }
        if landing && let Some((label, pending)) = state.pending.take() {
            let pending_body: Value = serde_json::from_slice(&pending.body).unwrap_or(Value::Null);
            let pending_method = pending.method.to_string();
            let _ = route(
                state,
                &pending_method,
                pending.url.path(),
                &pending_body,
                &pending,
            );
            if Some(&label) == state.retag_after_create.as_ref() {
                retag(state, &label);
            }
        }
        if is(&created, &state.retag_after_create) {
            retag(state, created.as_deref().unwrap_or_default());
        }
        if is(&created, &state.unavailable_after_create) {
            response = unavailable();
        }
        if is(&created, &state.fail_on) {
            response = json_response(
                400,
                json!({"message": "private.example.internal lost reply"}),
            );
        }
        if is(&created, &state.slow_create) || is(&deleting, &state.slow_delete) {
            response = response.set_delay(Duration::from_secs(2));
        }
        let label = created.or(deleting);
        if let Some((interrupt_label, notify)) = &state.interrupt_on
            && label.as_deref() == Some(interrupt_label.as_str())
        {
            notify.notify_one();
            response = response.set_delay(Duration::from_secs(1));
        }
        response
    }

    fn route(
        state: &mut State,
        method: &str,
        path: &str,
        body: &Value,
        request: &Request,
    ) -> ResponseTemplate {
        let marker_doc = format!("/{ALERT_PROBE_INDEX}/_doc/");
        let marker_create = format!("/{ALERT_PROBE_INDEX}/_create/");
        match (method, path) {
            ("GET", "/api/status") => json_response(
                200,
                json!({"version": {"number": "9.7.0", "build_flavor": "serverless"}}),
            ),
            ("GET", PREBUILT_STATUS_PATH) => {
                state.prebuilt_reads += 1;
                let count = match state.prebuilt_after {
                    Some(after) if state.prebuilt_reads > 1 => after,
                    _ => PREBUILT_RULES,
                };
                json_response(
                    200,
                    json!({"rules_installed": count, "rules_not_installed": 0,
                        "rules_not_updated": 0, "rules_custom_installed": 0}),
                )
            }
            ("PUT", p) if p == format!("/{ALERT_PROBE_INDEX}") => {
                if let Some(uuid) = &state.index_uuid {
                    return index_exists(uuid);
                }
                state.index_creates += 1;
                state.index_uuid = Some(format!("uuid-{}", state.index_creates));
                json_response(
                    200,
                    json!({"acknowledged": true, "shards_acknowledged": true,
                        "index": ALERT_PROBE_INDEX}),
                )
            }
            ("GET", p) if p == format!("/{ALERT_PROBE_INDEX}/_settings/index.uuid") => {
                match &state.index_uuid {
                    Some(uuid) => json_response(
                        200,
                        json!({(ALERT_PROBE_INDEX): {"settings": {"index": {"uuid": uuid}}}}),
                    ),
                    None => index_not_found(),
                }
            }
            ("POST", p) if p.starts_with(&marker_create) => {
                // Elasticsearch creates a missing index on a document write.
                if state.index_uuid.is_none() {
                    state.index_uuid = Some("uuid-auto".into());
                }
                let id = p[marker_create.len()..].to_string();
                if state.index.contains_key(&id) {
                    return json_response(
                        409,
                        json!({"error": {"type": "version_conflict_engine_exception",
                            "reason": "private.example.internal document exists"}, "status": 409}),
                    );
                }
                state.index.insert(id.clone(), body.clone());
                json_response(201, json!({"_id": id, "result": "created"}))
            }
            ("GET", p) if p.starts_with(&marker_doc) => {
                match state.index.get(&p[marker_doc.len()..]) {
                    Some(doc) => json_response(200, json!({"_source": doc})),
                    None => missing(),
                }
            }
            ("POST", p) if p == format!("/{ALERT_PROBE_INDEX}/_refresh") => {
                if state.index_uuid.is_none() {
                    return index_not_found();
                }
                json_response(200, json!({"_shards": {}}))
            }
            ("GET", p) if p == format!("/{ALERT_PROBE_INDEX}") => {
                if state.index_uuid.is_none() {
                    index_not_found()
                } else {
                    json_response(200, json!({}))
                }
            }
            ("DELETE", p) if p == format!("/{ALERT_PROBE_INDEX}") => {
                if state.index_uuid.take().is_none() {
                    return index_not_found();
                }
                state.index.clear();
                json_response(200, json!({"acknowledged": true}))
            }
            ("GET", "/_resolve/index/elasticctl-sample-alert-events%2A") => json_response(
                200,
                state.resolve_match_body.clone().unwrap_or_else(|| {
                    json!({"indices": [{"name": ALERT_PROBE_INDEX, "attributes": ["open"]}],
                        "aliases": [], "data_streams": []})
                }),
            ),
            ("GET", "/_resolve/index/elasticctl-sample-compose-none-%2A")
            | ("GET", "/_resolve/index/-elasticctl-sample-alert-events%2A") => json_response(
                200,
                json!({"indices": [], "aliases": [], "data_streams": []}),
            ),
            ("GET", "/_resolve/index/elasticctl-sample-compose-missing")
            | ("GET", "/elasticctl-sample-compose-missing") => json_response(
                404,
                json!({"error": {"type": "index_not_found_exception",
                    "reason": IDENTITY_PROSE}, "status": 404}),
            ),
            ("GET", p) if p.starts_with("/api/fleet/epm/packages/") => {
                let name = &p["/api/fleet/epm/packages/".len()..];
                let status = if state.installed.contains(&name) {
                    "installed"
                } else {
                    "not_installed"
                };
                json_response(
                    200,
                    json!({"item": {"name": name, "version": "1.2.3",
                    "status": status, "readme": "/package/readme.md"}}),
                )
            }
            ("POST", "/api/exception_lists") => {
                let mut list = body.clone();
                list["id"] = json!("list-so-id");
                state.list = Some(list.clone());
                json_response(200, list)
            }
            ("GET", "/api/exception_lists") => match &state.list {
                Some(list) => json_response(200, list.clone()),
                None => missing(),
            },
            ("DELETE", "/api/exception_lists") => match state.list.take() {
                Some(list) => {
                    state.items.retain(|_, item| item["list_id"] != LIST_ID);
                    json_response(200, list)
                }
                None => missing(),
            },
            ("POST", "/api/exception_lists/items") => {
                let mut item = body.clone();
                item["id"] = json!(format!("item-so-{}", state.items.len() + 1));
                let id = body["item_id"].as_str().unwrap_or_default().to_string();
                state.items.insert(id, item.clone());
                json_response(200, item)
            }
            ("GET", "/api/exception_lists/items") | ("DELETE", "/api/exception_lists/items") => {
                let id = query_value(request, "item_id").unwrap_or_default();
                let found = if method == "GET" {
                    state.items.get(&id).cloned()
                } else {
                    state.items.remove(&id)
                };
                found.map_or_else(missing, |item| json_response(200, item))
            }
            ("GET", "/api/exception_lists/items/_find") => {
                let list_id = json!(query_value(request, "list_id").unwrap_or_default());
                let on_list: Vec<Value> = state
                    .items
                    .values()
                    .filter(|item| item["list_id"] == list_id)
                    .cloned()
                    .collect();
                let data: Vec<Value> = on_list.iter().take(1).cloned().collect();
                json_response(
                    200,
                    json!({"data": data, "page": 1, "per_page": 1, "total": on_list.len()}),
                )
            }
            ("POST", "/api/detection_engine/rules") => {
                let rule = create_rule(state, body);
                json_response(200, rule)
            }
            ("GET", "/api/detection_engine/rules") => {
                let id = query_value(request, "rule_id").unwrap_or_default();
                if state.existing_rule && id == ALERT_RULE_ID {
                    return json_response(200, json!({"rule_id": id, "tags": []}));
                }
                rule_view(state, &id).map_or_else(missing, |rule| json_response(200, rule))
            }
            ("DELETE", "/api/detection_engine/rules") => {
                let id = query_value(request, "rule_id").unwrap_or_default();
                state
                    .rules
                    .remove(&id)
                    .map_or_else(missing, |rule| json_response(200, rule))
            }
            ("GET", "/api/detection_engine/rules/_find")
                if query_value(request, "filter")
                    .is_some_and(|filter| filter.contains("ruleId: elasticctl-sample*")) =>
            {
                let marker = |rule: &Value| {
                    rule["rule_id"]
                        .as_str()
                        .is_some_and(|id| id.starts_with("elasticctl-sample"))
                        || rule["tags"]
                            .as_array()
                            .is_some_and(|tags| tags.contains(&json!(ALERT_MARKER_TAG)))
                };
                let total = state.rules.values().filter(|rule| marker(rule)).count()
                    + inventory_extra(state, "rules");
                json_response(
                    200,
                    json!({"page": 1, "perPage": 1, "total": total, "data": []}),
                )
            }
            ("GET", LISTS_FIND_PATH) => {
                let total = usize::from(state.list.is_some()) + inventory_extra(state, "lists");
                json_response(
                    200,
                    json!({"page": 1, "per_page": 1, "total": total, "data": []}),
                )
            }
            ("GET", "/_resolve/index/%2Aelasticctl-sample%2A") => {
                let mut indices = Vec::new();
                if state.index_uuid.is_some() {
                    indices.push(json!({"name": ALERT_PROBE_INDEX, "attributes": ["open"]}));
                }
                if inventory_extra(state, "indices") > 0 {
                    indices
                        .push(json!({"name": "elasticctl-sample-other", "attributes": ["open"]}));
                }
                json_response(
                    200,
                    json!({"indices": indices, "aliases": [], "data_streams": []}),
                )
            }
            ("GET", "/api/detection_engine/rules/_find") => {
                let filter = query_value(request, "filter").unwrap_or_default();
                let technique = filter.contains(".threat.");
                let mut data: Vec<Value> = state
                    .rules
                    .values()
                    .filter(|r| filter.contains(r["rule_id"].as_str().unwrap_or("?")))
                    .filter(|r| !technique || r.get("threat").is_some())
                    .cloned()
                    .collect();
                if state.foreign_rule {
                    data.push(json!({"rule_id": "prebuilt-rule", "name": "Prebuilt"}));
                }
                json_response(
                    200,
                    json!({"page": 1, "perPage": 500, "total": data.len(), "data": data}),
                )
            }
            ("POST", "/api/detection_engine/signals/search") => {
                let response = signals(state, body);
                json_response(200, response)
            }
            ("POST", "/api/detection_engine/signals/status") => close_alerts(state, body),
            ("GET", "/api/cases/_find") => {
                let cases: Vec<Value> = state.cases.values().cloned().collect();
                json_response(
                    200,
                    json!({"cases": cases, "total": state.cases.len(),
                    "page": 1, "per_page": 100}),
                )
            }
            ("POST", "/api/cases") => {
                let mut case = body.clone();
                case["id"] = json!("case-real-1");
                case["version"] = json!("WzEsMV0=");
                case["status"] = json!("open");
                case["created_at"] = json!("2026-11-10T01:04:00.000Z");
                state.cases.insert("case-real-1".into(), case.clone());
                json_response(200, case)
            }
            ("POST", "/api/cases/case-real-1/comments") => {
                state.attached.extend(
                    body["alertId"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_owned),
                );
                let mut case = state.cases.get("case-real-1").cloned().unwrap_or_default();
                case["version"] = json!("WzIsMV0=");
                case["comments"] = json!([{"id": "comment-real-1", "version": "WzMsMV0=",
                    "type": "alert", "alertId": body["alertId"].clone()}]);
                json_response(200, case)
            }
            ("GET", p) if p.starts_with("/api/cases/alerts/") => {
                let id = &p["/api/cases/alerts/".len()..];
                if state.attachment_lag > 0 && state.attached.iter().any(|a| a == id) {
                    state.attachment_lag -= 1;
                    return json_response(200, json!([]));
                }
                let mut rows: Vec<Value> = if state.attached.iter().any(|a| a == id) {
                    state
                        .cases
                        .values()
                        .map(|case| {
                            json!({"id": case["id"], "title": case["title"],
                        "description": case["description"], "status": "open",
                        "createdAt": "2026-11-10T01:04:00.000Z",
                        "totals": {"alerts": 1, "userComments": 0}})
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                if state.foreign_case && !rows.is_empty() {
                    rows.push(json!({"id": "other-case", "title": "Someone else's case"}));
                }
                json_response(200, json!(rows))
            }
            ("GET", p) if p.starts_with("/api/cases/") => state
                .cases
                .get(&p["/api/cases/".len()..])
                .cloned()
                .map_or_else(missing, |case| json_response(200, case)),
            ("DELETE", "/api/cases") => {
                let ids: Vec<String> = query_value(request, "ids")
                    .and_then(|ids| serde_json::from_str(&ids).ok())
                    .unwrap_or_default();
                for id in ids {
                    state.cases.remove(&id);
                }
                ResponseTemplate::new(204)
            }
            _ => {
                state.unexpected.push(format!("{method} {path}"));
                missing()
            }
        }
    }

    pub(super) async fn fake_stack(
        configure: impl FnOnce(&mut State),
    ) -> (MockServer, Arc<Mutex<State>>) {
        let server = MockServer::start().await;
        let mut state = State {
            installed: vec!["apache", "system"],
            ..State::default()
        };
        configure(&mut state);
        if state.historical_alert {
            state.alerts.push(alert(0, "so-older", &Value::Null));
        }
        let state = Arc::new(Mutex::new(state));
        let shared = Arc::clone(&state);
        Mock::given(any())
            .respond_with(move |request: &Request| {
                handle(&mut shared.lock().expect("state"), request)
            })
            .mount(&server)
            .await;
        (server, state)
    }
}

#[cfg(test)]
mod tests {
    use super::fake_stack::{
        ALERT_INDEX, IDENTITY_PROSE, IDENTITY_TOKENS, SESSION_RULE_UUID, State, fake_stack,
        foreign_present,
    };
    use super::*;
    use crate::recorder::markers::{
        ALERT_PROBE_INDEX, ALERT_RULE_ID, CASE_ID_PLACEHOLDER, ITEM_ID, LIST_ID,
    };
    use crate::recorder::test_support::mock_transport;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::Notify;
    use wiremock::MockServer;

    const ALL_FIXTURES: [&str; 12] = [
        "rule_get_executed",
        "rule_get_failed_execution",
        "rules_find_sorted_page",
        "rules_find_by_technique",
        "signals_search_rule_activity",
        "cases_by_alert",
        "cases_by_alert_none",
        "exception_items_count",
        "resolve_index_match",
        "resolve_index_no_match",
        "resolve_index_not_found",
        "package_not_installed",
    ];

    /// Text that must never reach a printed line.
    const PRIVATE_TEXT: [&str; 7] = [
        "private.example",
        "https://",
        "http://",
        "127.0.0.1",
        "operator@",
        "refused for",
        "lost reply",
    ];

    struct Outcome {
        step_error: Option<elasticctl_core::Error>,
        failures: Vec<String>,
        ownership_before_cleanup: BTreeMap<&'static str, bool>,
        ownership_after_cleanup: BTreeMap<&'static str, bool>,
        unresolved_before_cleanup: BTreeMap<&'static str, bool>,
        alerts_after_cleanup: bool,
        teardown_time: Duration,
        log: PrivateLog,
        succeeded: bool,
        lines: Vec<String>,
        written: Option<Recording>,
    }

    fn unresolved_flags(unresolved: &Unresolved) -> BTreeMap<&'static str, bool> {
        BTreeMap::from([
            ("alert_index", unresolved.alert_index),
            ("index_recreation", unresolved.index_recreation),
            ("list", unresolved.list),
            ("item", unresolved.item),
            ("compose_item", unresolved.compose_item),
            ("alert_rule", unresolved.alert_rule),
            ("compose_rule", unresolved.compose_rule),
            ("case", unresolved.case),
        ])
    }

    /// A settle window short enough for the suite and long enough for
    /// several reads.
    fn short_settle(window_ms: u64) -> Timing {
        Timing {
            poll: Duration::ZERO,
            settle_window: Duration::from_millis(window_ms),
            settle_interval: Duration::from_millis(10),
        }
    }

    fn flags(ownership: &CleanupOwnership) -> BTreeMap<&'static str, bool> {
        BTreeMap::from([
            ("alert_index", ownership.alert_index),
            ("list", ownership.list),
            ("item", ownership.item),
            ("compose_item", ownership.compose_item),
            ("alert_rule", ownership.alert_rule),
            ("compose_rule", ownership.compose_rule),
            ("case", ownership.case),
        ])
    }

    fn released(flags: &BTreeMap<&'static str, bool>) -> bool {
        flags.values().all(|owned| !owned)
    }

    fn settle(
        outcome: RunOutcome,
        ownership_before_cleanup: BTreeMap<&'static str, bool>,
        ownership_after_cleanup: BTreeMap<&'static str, bool>,
        log: PrivateLog,
    ) -> Outcome {
        let step_error = match &outcome.step {
            Ended::Finished(Err(error)) => Some(error.clone()),
            _ => None,
        };
        let failures = match &outcome.teardown {
            Ended::Finished(teardown) => {
                teardown.failures.iter().map(ToString::to_string).collect()
            }
            _ => Vec::new(),
        };
        let mut written = None;
        let (succeeded, lines) = finish(outcome, |recording| {
            written = Some(recording);
            Ok(())
        });
        Outcome {
            step_error,
            failures,
            ownership_before_cleanup,
            ownership_after_cleanup,
            unresolved_before_cleanup: BTreeMap::new(),
            alerts_after_cleanup: false,
            teardown_time: Duration::ZERO,
            log,
            succeeded,
            lines,
            written,
        }
    }

    /// The two halves of `run`, with the ownership flags read in between.
    async fn record_against(transport: &Transport) -> Outcome {
        record_with(transport, Timing::INSTANT).await
    }

    async fn record_with(transport: &Transport, timing: Timing) -> Outcome {
        let mut compose = ComposeSession::new(transport);
        let mut log = PrivateLog::default();
        let step = guarded(
            record_steps(&mut compose, &mut log, None, timing.poll),
            None,
            std::future::pending(),
        )
        .await;
        let before = flags(&compose.session.ownership);
        let unresolved_before = unresolved_flags(&compose.unresolved);
        let started = Instant::now();
        let outcome = conclude(&mut compose, step, timing, std::future::pending()).await;
        let teardown_time = started.elapsed();
        let mut outcome = settle(outcome, before, flags(&compose.session.ownership), log);
        outcome.unresolved_before_cleanup = unresolved_before;
        outcome.alerts_after_cleanup = compose.alerts;
        outcome.teardown_time = teardown_time;
        outcome
    }

    fn short_timeout_transport(server: &MockServer) -> Transport {
        Transport::new(&elasticctl_core::Profile {
            kibana_url: server.uri(),
            es_url: Some(server.uri()),
            api_key: Some("test".into()),
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 1,
        })
        .expect("transport")
    }

    fn fixture_names(recording: &Recording) -> Vec<&'static str> {
        recording.fixtures.iter().map(|f| f.name).collect()
    }

    fn assert_clean_lines(lines: &[String]) {
        for line in lines {
            for private in PRIVATE_TEXT {
                assert!(!line.contains(private), "{line}");
            }
        }
    }

    #[tokio::test]
    async fn records_exactly_the_twelve_fixtures_and_cleans_every_marker_object() {
        let (server, state) = fake_stack(|_| {}).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        assert!(outcome.succeeded, "{:?}", outcome.lines);
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        assert!(
            outcome.unresolved_before_cleanup.values().all(|lost| !lost),
            "{:?}",
            outcome.unresolved_before_cleanup
        );
        let recording = outcome.written.expect("written");
        let mut names = fixture_names(&recording);
        names.sort();
        let mut expected = ALL_FIXTURES.to_vec();
        expected.sort();
        assert_eq!(names, expected);
        assert!(recording.dir.ends_with("tests/fixtures/serverless-9.7.0"));
        assert!(released(&outcome.ownership_after_cleanup));
        let state = state.lock().expect("state");
        assert!(state.is_empty(), "marker objects remain");
        assert!(state.unexpected.is_empty(), "{:?}", state.unexpected);
        assert_eq!(state.open_alerts(SESSION_RULE_UUID), 0);

        let document = |name: &str| {
            recording
                .fixtures
                .iter()
                .find(|f| f.name == name)
                .map(|f| f.document.clone())
                .expect("fixture")
        };
        let executed = document("rule_get_executed");
        assert_eq!(
            executed["request"]["query"],
            "rule_id=elasticctl-sample-alert-probe"
        );
        assert_eq!(
            executed["response"]["threat"][0]["technique"][0]["id"],
            "T1059"
        );
        assert_eq!(
            executed["response"]["execution_summary"]["last_execution"]["status"],
            "succeeded"
        );
        assert_eq!(
            document("rule_get_failed_execution")["response"]["execution_summary"]["last_execution"]
                ["status"],
            "partial failure"
        );
        assert_eq!(
            document("signals_search_rule_activity")["request"]["body"],
            requests::signals_activity().body.expect("body")
        );
        assert_eq!(
            document("cases_by_alert")["request"]["path"],
            "/api/cases/alerts/elasticctl-fixture-alert-1"
        );
        assert_eq!(
            document("cases_by_alert")["response"][0]["id"],
            CASE_ID_PLACEHOLDER
        );
        assert_eq!(document("cases_by_alert_none")["response"], json!([]));
        assert_eq!(document("exception_items_count")["response"]["total"], 2);
        assert_eq!(
            document("resolve_index_not_found")["error"]["kind"],
            "not_found"
        );
        assert_eq!(
            document("package_not_installed")["response"],
            json!({"item": {"name": "nginx", "version": "1.2.3", "status": "not_installed"}})
        );

        let public = serde_json::to_string(
            &recording
                .fixtures
                .iter()
                .map(|f| &f.document)
                .collect::<Vec<_>>(),
        )
        .expect("encode");
        for private in [
            "kibana.alert.case_ids",
            "zz-alert",
            "case-real-1",
            "comment-real-1",
            "list-so-id",
            "so-elasticctl",
            "private.example",
            "WzIsMV0=",
            "2026-11-10",
            ALERT_INDEX,
            "alerts-security",
        ] {
            assert!(!public.contains(private), "a fixture holds {private}");
        }
        assert_eq!(
            outcome.log.get("kibana_alert_case_ids_present"),
            Some(&json!(true))
        );
        assert_eq!(
            outcome.log.get("responses").expect("responses")["package_system"]["status"],
            "installed"
        );
    }

    #[tokio::test]
    async fn every_object_is_claimed_before_the_request_that_creates_it() {
        for (label, owner) in [
            ("doc:1", "alert_index"),
            ("list", "list"),
            ("item:elasticctl-sample-exception-item", "item"),
            ("item:elasticctl-sample-exception-item-2", "compose_item"),
            ("rule:elasticctl-sample-alert-probe", "alert_rule"),
            (
                "rule:elasticctl-sample-compose-missing-index",
                "compose_rule",
            ),
            ("case", "case"),
        ] {
            let (server, state) = fake_stack(|s| s.fail_on = Some(label.to_string())).await;
            let t = mock_transport(&server);

            let outcome = record_against(&t).await;

            assert!(outcome.step_error.is_some(), "{label}");
            assert!(
                outcome.ownership_before_cleanup[owner],
                "{owner} was not claimed before its create"
            );
            assert!(
                outcome.failures.is_empty(),
                "{label}: {:?}",
                outcome.failures
            );
            assert!(released(&outcome.ownership_after_cleanup), "{label}");
            assert!(!outcome.succeeded && outcome.written.is_none(), "{label}");
            let state = state.lock().expect("state");
            assert!(
                state.is_empty(),
                "{label}: a created object survived cleanup"
            );
            assert!(
                state.unexpected.is_empty(),
                "{label}: {:?}",
                state.unexpected
            );
            assert_eq!(state.open_alerts(SESSION_RULE_UUID), 0, "{label}");
        }
    }

    #[tokio::test]
    async fn creates_run_in_order_after_every_preflight_read() {
        let (server, state) = fake_stack(|_| {}).await;
        let t = mock_transport(&server);
        assert!(record_against(&t).await.succeeded);

        let state = state.lock().expect("state");
        let position = |needle: &str| {
            state
                .log
                .iter()
                .position(|line| line.starts_with(needle))
                .unwrap_or_else(|| panic!("{needle} not sent"))
        };
        let first_write = position(&format!("PUT /{ALERT_PROBE_INDEX}"));
        let settings = format!("GET /{ALERT_PROBE_INDEX}/_settings/index.uuid");
        let mut index_writes = vec![format!("PUT /{ALERT_PROBE_INDEX}"), settings.clone()];
        for seq in 1..=ALERT_DOCS {
            index_writes.push(settings.clone());
            index_writes.push(format!("POST /{ALERT_PROBE_INDEX}/_create/{seq}"));
        }
        index_writes.extend([
            format!("GET /{ALERT_PROBE_INDEX}/_doc/1"),
            settings,
            format!("POST /{ALERT_PROBE_INDEX}/_refresh"),
        ]);
        assert_eq!(
            state.log[first_write..first_write + index_writes.len()],
            index_writes,
            "the index is created and its UUID read, then read again before every write"
        );
        for preflight in [
            "GET /api/detection_engine/rules/_find?page=1&per_page=1&filter=",
            "GET /api/exception_lists/_find?page=1&per_page=1&namespace_type=single&filter=",
            "GET /_resolve/index/%2Aelasticctl-sample%2A",
            "GET /api/detection_engine/rules?rule_id=elasticctl-sample-alert-probe",
            "GET /api/detection_engine/rules?rule_id=elasticctl-sample-compose-missing-index",
            "GET /api/exception_lists?",
            &format!("GET /api/exception_lists/items?item_id={ITEM_ID}"),
            "GET /api/exception_lists/items?item_id=elasticctl-sample-exception-item-2",
            &format!("GET /{ALERT_PROBE_INDEX}"),
            "GET /elasticctl-sample-compose-missing",
            "GET /api/cases/_find",
            "GET /api/detection_engine/rules/prepackaged/_status",
            "GET /api/fleet/epm/packages/apache",
            "GET /api/fleet/epm/packages/system",
        ] {
            assert!(position(preflight) < first_write, "{preflight}");
        }
        let creates: Vec<&String> = state
            .log
            .iter()
            .filter(|line| {
                line.starts_with("POST /api/exception_lists")
                    || line.starts_with("POST /api/detection_engine/rules")
                    || line.starts_with("POST /api/cases")
            })
            .collect();
        assert_eq!(
            creates,
            [
                "POST /api/exception_lists",
                "POST /api/exception_lists/items",
                "POST /api/exception_lists/items",
                "POST /api/detection_engine/rules",
                "POST /api/detection_engine/rules",
                "POST /api/cases",
                "POST /api/cases/case-real-1/comments",
            ]
        );
        let replacing: Vec<&String> = state
            .log
            .iter()
            .filter(|line| line.starts_with("PUT ") || line.starts_with("PATCH "))
            .collect();
        assert_eq!(replacing, [&format!("PUT /{ALERT_PROBE_INDEX}")]);
        assert!(
            !state
                .log
                .iter()
                .any(|line| line.contains("/_find") && !line.contains("elasticctl-sample")),
            "an unscoped _find was sent"
        );
    }

    #[tokio::test]
    async fn a_failed_read_step_still_cleans_every_object() {
        for configure in [
            (|s: &mut State| s.foreign_rule = true) as fn(&mut State),
            |s: &mut State| s.foreign_hits = true,
            |s: &mut State| s.foreign_case = true,
        ] {
            let (server, state) = fake_stack(configure).await;
            let t = mock_transport(&server);

            let outcome = record_against(&t).await;

            let error = outcome.step_error.expect("refused");
            assert!(
                error.message.contains("refusing to record"),
                "{}",
                error.message
            );
            assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
            assert!(released(&outcome.ownership_after_cleanup));
            assert!(state.lock().expect("state").is_empty());
        }
    }

    #[tokio::test]
    async fn a_lagging_attachment_is_read_again_within_its_bound() {
        let (server, state) = fake_stack(|s| s.attachment_lag = 2).await;
        let t = mock_transport(&server);
        assert!(record_against(&t).await.succeeded);
        let reads = |state: &State| {
            state
                .log
                .iter()
                .filter(|line| line.starts_with("GET /api/cases/alerts/zz-alert"))
                .count()
        };
        assert_eq!(reads(&state.lock().expect("state")), 3);

        let (server, state) = fake_stack(|s| s.attachment_lag = 3).await;
        let t = mock_transport(&server);
        let outcome = record_against(&t).await;
        assert!(outcome.step_error.is_some());
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        let state = state.lock().expect("state");
        assert_eq!(reads(&state), 3);
        assert!(state.is_empty());
    }

    #[tokio::test]
    async fn a_preflight_refusal_sends_no_mutation_and_never_touches_the_existing_rule() {
        let (server, state) = fake_stack(|s| s.existing_rule = true).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        let error = outcome.step_error.expect("refused");
        assert!(
            error.message.contains("refusing to record"),
            "{}",
            error.message
        );
        assert!(released(&outcome.ownership_before_cleanup));
        assert!(!outcome.succeeded && outcome.written.is_none());
        let state = state.lock().expect("state");
        assert_eq!(state.mutations(), Vec::<String>::new());
        assert_eq!(
            state.log,
            [
                "GET /api/status",
                "GET /api/detection_engine/rules?rule_id=elasticctl-sample-alert-probe",
            ],
            "cleanup after a refusal sends nothing"
        );
    }

    #[tokio::test]
    async fn no_installed_candidate_left_fails_before_any_write() {
        let (server, state) = fake_stack(|s| s.installed = vec!["apache", "nginx", "mysql"]).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        assert!(outcome.step_error.is_some());
        let state = state.lock().expect("state");
        assert_eq!(state.mutations(), Vec::<String>::new());
        assert!(state.is_empty());
    }

    #[tokio::test]
    async fn an_uninstalled_system_package_fails_before_any_write() {
        let (server, state) = fake_stack(|s| s.installed = vec!["apache"]).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        let error = outcome.step_error.expect("refused");
        assert_eq!(
            error.message,
            "refusing to record: the system package is not installed"
        );
        assert_eq!(
            state.lock().expect("state").mutations(),
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn without_an_elasticsearch_url_the_resolve_recordings_are_skipped() {
        let (server, state) = fake_stack(|_| {}).await;
        let t = Transport::new(&elasticctl_core::Profile {
            kibana_url: server.uri(),
            es_url: None,
            api_key: Some("test".into()),
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 5,
        })
        .expect("transport");

        let outcome = record_against(&t).await;

        assert!(outcome.succeeded, "{:?}", outcome.lines);
        let recording = outcome.written.expect("written");
        let names = fixture_names(&recording);
        assert_eq!(names.len(), 9);
        assert!(names.iter().all(|name| !name.starts_with("resolve_index")));
        assert!(
            !state
                .lock()
                .expect("state")
                .log
                .iter()
                .any(|line| line.contains("_resolve")),
        );
    }

    #[tokio::test]
    async fn a_conflicting_create_releases_its_claim_and_leaves_the_object() {
        for (label, owner) in [
            ("index", "alert_index"),
            ("list", "list"),
            ("item:elasticctl-sample-exception-item", "item"),
            ("item:elasticctl-sample-exception-item-2", "compose_item"),
            ("rule:elasticctl-sample-alert-probe", "alert_rule"),
            (
                "rule:elasticctl-sample-compose-missing-index",
                "compose_rule",
            ),
        ] {
            let (server, state) = fake_stack(|s| s.conflict_on = Some(label.to_string())).await;
            let t = mock_transport(&server);

            let outcome = record_against(&t).await;

            let error = outcome.step_error.expect("refused");
            assert!(
                error.message.contains("already exists"),
                "{label}: {}",
                error.message
            );
            assert!(!outcome.ownership_before_cleanup[owner], "{label}");
            assert!(!outcome.succeeded && outcome.written.is_none(), "{label}");
            let state = state.lock().expect("state");
            assert!(
                foreign_present(&state, label),
                "{label}: the foreign object was touched"
            );
            let touches_foreign =
                |line: &String| match label.split_once(':') {
                    None if label == "index" => line == &format!("DELETE /{ALERT_PROBE_INDEX}"),
                    None => line.starts_with("DELETE /api/exception_lists?"),
                    Some(("item", id)) => line
                        .starts_with(&format!("DELETE /api/exception_lists/items?item_id={id}&")),
                    Some((_, id)) => line
                        .starts_with(&format!("DELETE /api/detection_engine/rules?rule_id={id}")),
                };
            assert!(
                !state
                    .log
                    .iter()
                    .any(|line| line.starts_with("PATCH ") || touches_foreign(line)),
                "{label}: {:?}",
                state.log
            );
        }
    }

    #[tokio::test]
    async fn a_delete_answered_ok_while_the_object_remains_keeps_ownership() {
        for (label, owner, object) in [
            (
                "item:elasticctl-sample-exception-item",
                "item",
                "exception item 1 is still present",
            ),
            ("list", "list", "the marker exception list is still present"),
        ] {
            let (server, _state) = fake_stack(|s| s.sticky_delete = Some(label.to_string())).await;
            let t = mock_transport(&server);

            let outcome = record_against(&t).await;

            assert!(
                outcome.failures.iter().any(|f| f == object),
                "{label}: {:?}",
                outcome.failures
            );
            assert!(outcome.ownership_after_cleanup[owner], "{label}");
            assert!(!outcome.succeeded && outcome.written.is_none(), "{label}");
            assert!(
                outcome
                    .lines
                    .iter()
                    .any(|line| line.starts_with("record-compose cleanup left in place:")),
                "{label}: {:?}",
                outcome.lines
            );
        }
    }

    #[tokio::test]
    async fn a_changed_child_keeps_its_parent_list() {
        let (server, state) = fake_stack(|s| {
            s.retag_after_create = Some("item:elasticctl-sample-exception-item-2".into())
        })
        .await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        assert!(outcome.ownership_after_cleanup["compose_item"]);
        assert!(outcome.ownership_after_cleanup["list"]);
        assert!(!outcome.succeeded && outcome.written.is_none());
        let state = state.lock().expect("state");
        assert!(state.list.is_some(), "the parent list was deleted");
        assert!(
            !state.log.iter().any(|line| {
                line.starts_with("DELETE /api/exception_lists?")
                || line.starts_with(
                    "DELETE /api/exception_lists/items?item_id=elasticctl-sample-exception-item-2"
                )
            }),
            "{:?}",
            state.log
        );
    }

    #[tokio::test]
    async fn a_baseline_mismatch_writes_no_fixture() {
        let (server, state) = fake_stack(|s| s.prebuilt_after = Some(2262)).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        assert!(outcome.step_error.is_none());
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        assert!(!outcome.succeeded);
        assert!(outcome.written.is_none(), "a fixture was written");
        assert!(
            outcome.lines.iter().any(|line| line.starts_with(
                "record-compose baseline audit failed: the prebuilt rule count changed"
            )),
            "{:?}",
            outcome.lines
        );
        assert!(state.lock().expect("state").is_empty());
    }

    #[tokio::test]
    async fn only_this_runs_alerts_are_closed_and_only_by_id() {
        let (server, state) = fake_stack(|s| s.historical_alert = true).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        assert!(outcome.succeeded, "{:?}", outcome.lines);
        let state = state.lock().expect("state");
        assert_eq!(state.open_alerts(SESSION_RULE_UUID), 0);
        assert_eq!(
            state.open_alerts("so-older"),
            1,
            "an earlier run's alert was closed"
        );
        assert!(!state.status_requests.is_empty());
        for request in &state.status_requests {
            assert!(request.get("query").is_none(), "{request}");
            let ids = request["signal_ids"].as_array().expect("explicit ids");
            assert!(
                ids.iter()
                    .all(|id| id.as_str().is_some_and(|id| id != "zz-alert-0")),
                "{request}"
            );
        }
    }

    #[tokio::test]
    async fn the_signals_fixture_holds_no_alert_index_name() {
        let (server, _state) = fake_stack(|_| {}).await;
        let t = mock_transport(&server);

        let recording = record_against(&t).await.written.expect("written");

        let signals = recording
            .fixtures
            .iter()
            .find(|f| f.name == "signals_search_rule_activity")
            .expect("signals fixture");
        assert_eq!(
            signals.document["response"]["hits"]["hits"][0]["_index"],
            evidence::ALERT_INDEX_PLACEHOLDER
        );
        let text = signals.document.to_string();
        assert!(!text.contains("alerts-security"), "{text}");
        assert!(!text.contains(".internal."), "{text}");
    }

    #[tokio::test]
    async fn a_resolve_body_naming_a_nested_non_marker_is_refused() {
        for body in [
            json!({"indices": [{"name": ALERT_PROBE_INDEX, "aliases": ["prod-secrets"],
                "attributes": ["open"]}], "aliases": [], "data_streams": []}),
            json!({"indices": [{"name": ALERT_PROBE_INDEX, "attributes": ["open"]}],
                "aliases": [{"name": "elasticctl-sample-a", "indices": ["customer-data"]}],
                "data_streams": []}),
            json!({"indices": [], "aliases": [], "data_streams": [{
                "name": "elasticctl-sample-ds", "timestamp_field": "@timestamp",
                "backing_indices": [".ds-logs-private-2026.11.10-000001"]}]}),
        ] {
            let (server, state) = fake_stack(|s| s.resolve_match_body = Some(body.clone())).await;
            let t = mock_transport(&server);

            let outcome = record_against(&t).await;

            let error = outcome.step_error.expect("refused");
            assert!(
                error.message.contains("resolve_index_match"),
                "{}",
                error.message
            );
            assert!(outcome.written.is_none());
            assert!(state.lock().expect("state").is_empty());
        }
    }

    #[tokio::test]
    async fn printed_lines_hold_no_host_url_or_server_text() {
        let (server, _state) =
            fake_stack(|s| s.failing_delete = Some("rule:elasticctl-sample-alert-probe".into()))
                .await;
        let t = mock_transport(&server);
        let outcome = record_against(&t).await;
        assert!(
            outcome
                .failures
                .iter()
                .any(|f| f == "deleting rule elasticctl-sample-alert-probe: class=http status=500"),
            "{:?}",
            outcome.failures
        );
        assert!(!outcome.succeeded);
        assert_clean_lines(&outcome.lines);

        // A timed-out request's transport message names the URL.
        let (server, _state) = fake_stack(|s| {
            s.slow_create = Some("item:elasticctl-sample-exception-item".into());
            s.slow_delete = Some("list".into());
        })
        .await;
        let t = short_timeout_transport(&server);
        let outcome = record_against(&t).await;
        let error = outcome.step_error.as_ref().expect("timed out");
        assert_eq!(error.kind, elasticctl_core::ErrorKind::Timeout);
        assert!(
            outcome
                .failures
                .iter()
                .any(|f| f == "deleting the marker exception list: class=timeout status=none"),
            "{:?}",
            outcome.failures
        );
        assert!(!outcome.succeeded);
        assert_clean_lines(&outcome.lines);
    }

    #[tokio::test]
    async fn the_exclusion_pattern_resolve_is_logged_privately_only() {
        let (server, _state) = fake_stack(|_| {}).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        let recording = outcome.written.expect("written");
        assert_eq!(recording.fixtures.len(), 12);
        assert!(
            fixture_names(&recording)
                .iter()
                .all(|name| !name.contains("exclusion"))
        );
        assert_eq!(
            outcome.log.get("responses").expect("responses")["resolve_index_exclusion"],
            json!({"indices": [], "aliases": [], "data_streams": []})
        );
    }

    #[tokio::test]
    async fn a_create_that_times_out_stays_owned_and_cleanup_removes_it() {
        let (server, state) = fake_stack(|s| {
            s.slow_create = Some("rule:elasticctl-sample-compose-missing-index".into())
        })
        .await;
        let t = short_timeout_transport(&server);

        let outcome = record_against(&t).await;

        let error = outcome.step_error.expect("timed out");
        assert_eq!(error.kind, elasticctl_core::ErrorKind::Timeout);
        assert!(outcome.ownership_before_cleanup["compose_rule"]);
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        assert!(released(&outcome.ownership_after_cleanup));
        assert!(state.lock().expect("state").is_empty());
    }

    #[tokio::test]
    async fn an_interrupt_mid_provisioning_still_runs_cleanup() {
        let notify = Arc::new(Notify::new());
        let fired = Arc::clone(&notify);
        let (server, state) = fake_stack(move |s| {
            s.interrupt_on = Some(("rule:elasticctl-sample-alert-probe".into(), fired));
        })
        .await;
        let t = mock_transport(&server);
        let mut compose = ComposeSession::new(&t);
        let mut log = PrivateLog::default();
        let mut calls = 0;

        let outcome = run(&mut compose, &mut log, None, Timing::INSTANT, || {
            calls += 1;
            let first = calls == 1;
            let notify = Arc::clone(&notify);
            async move {
                if first {
                    notify.notified().await;
                } else {
                    std::future::pending::<()>().await;
                }
            }
        })
        .await;

        assert!(matches!(outcome.step, Ended::Interrupted));
        let after = flags(&compose.session.ownership);
        let outcome = settle(outcome, BTreeMap::new(), after, log);
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        assert!(released(&outcome.ownership_after_cleanup));
        assert!(!outcome.succeeded && outcome.written.is_none());
        assert_eq!(
            outcome.lines.first().map(String::as_str),
            Some("record-compose interrupted")
        );
        let state = state.lock().expect("state");
        assert!(state.is_empty(), "the in-flight rule survived");
        assert_eq!(state.open_alerts(SESSION_RULE_UUID), 0);
    }

    #[tokio::test]
    async fn a_panic_mid_provisioning_still_runs_cleanup() {
        let (server, state) = fake_stack(|_| {}).await;
        let t = mock_transport(&server);
        let mut compose = ComposeSession::new(&t);

        let step = guarded(
            async {
                provision::create_index(&mut compose).await?;
                provision::create_objects(&mut compose).await?;
                if compose.session.ownership.compose_rule {
                    panic!("injected panic mid-provisioning");
                }
                Err::<Recording, _>(recording_error("not reached"))
            },
            None,
            std::future::pending(),
        )
        .await;
        assert!(matches!(step, Ended::Panicked));
        let before = flags(&compose.session.ownership);
        assert!(before.values().filter(|owned| **owned).count() >= 6);

        let outcome = conclude(&mut compose, step, Timing::INSTANT, std::future::pending()).await;

        let after = flags(&compose.session.ownership);
        let outcome = settle(outcome, before, after, PrivateLog::default());
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        assert!(released(&outcome.ownership_after_cleanup));
        assert!(!outcome.succeeded && outcome.written.is_none());
        let state = state.lock().expect("state");
        assert!(state.is_empty());
        assert_eq!(state.open_alerts(SESSION_RULE_UUID), 0);
    }

    #[tokio::test]
    async fn a_second_interrupt_stops_cleanup_and_names_what_is_still_owned() {
        let (server, state) = fake_stack(|_| {}).await;
        let t = mock_transport(&server);
        let mut compose = ComposeSession::new(&t);
        let mut log = PrivateLog::default();
        let mut calls = 0;

        let outcome = run(&mut compose, &mut log, None, Timing::INSTANT, || {
            calls += 1;
            let second = calls == 2;
            async move {
                if !second {
                    std::future::pending::<()>().await;
                }
            }
        })
        .await;

        assert!(matches!(outcome.step, Ended::Finished(Ok(_))));
        assert!(matches!(outcome.teardown, Ended::Interrupted));
        let after = flags(&compose.session.ownership);
        let outcome = settle(outcome, BTreeMap::new(), after, log);
        assert!(!outcome.succeeded && outcome.written.is_none());
        assert!(
            outcome
                .lines
                .contains(&"record-compose cleanup interrupted".to_string()),
            "{:?}",
            outcome.lines
        );
        assert!(
            outcome.lines.iter().any(|line| line
                == "record-compose cleanup left in place: the marker case, rule elasticctl-sample-alert-probe, rule elasticctl-sample-compose-missing-index, the session alerts, exception item 2, exception item 1, the marker exception list, index elasticctl-sample-alert-events"),
            "{:?}",
            outcome.lines
        );
        assert!(!state.lock().expect("state").is_empty());
    }

    /// Every create sent once through `post_once`, with its label and
    /// ownership flag.
    const KIBANA_CREATES: [(&str, &str); 6] = [
        ("list", "list"),
        ("item:elasticctl-sample-exception-item", "item"),
        ("item:elasticctl-sample-exception-item-2", "compose_item"),
        ("rule:elasticctl-sample-alert-probe", "alert_rule"),
        (
            "rule:elasticctl-sample-compose-missing-index",
            "compose_rule",
        ),
        ("case", "case"),
    ];

    fn deletes_of(state: &State, label: &str) -> usize {
        let prefix = match label.split_once(':') {
            None if label == "list" => "DELETE /api/exception_lists?".to_string(),
            None => "DELETE /api/cases?".to_string(),
            Some(("item", id)) => format!("DELETE /api/exception_lists/items?item_id={id}&"),
            Some((_, id)) => format!("DELETE /api/detection_engine/rules?rule_id={id}"),
        };
        state
            .log
            .iter()
            .filter(|line| line.starts_with(&prefix))
            .count()
    }

    #[tokio::test]
    async fn a_503_after_an_applied_create_leaves_the_claim_unresolved_until_cleanup_removes_it() {
        for (label, owner) in KIBANA_CREATES {
            let (server, state) =
                fake_stack(|s| s.unavailable_after_create = Some(label.to_string())).await;
            let t = mock_transport(&server);

            let outcome = record_against(&t).await;

            let error = outcome.step_error.as_ref().expect("failed create");
            assert_eq!(error.http_status, Some(503), "{label}");
            assert!(outcome.ownership_before_cleanup[owner], "{label}: released");
            assert!(
                outcome.unresolved_before_cleanup[owner],
                "{label}: the lost answer was not marked unresolved"
            );
            assert!(
                outcome.failures.is_empty(),
                "{label}: {:?}",
                outcome.failures
            );
            assert!(released(&outcome.ownership_after_cleanup), "{label}");
            assert!(!outcome.succeeded && outcome.written.is_none(), "{label}");
            let state = state.lock().expect("state");
            assert!(state.is_empty(), "{label}: the applied create survived");
            assert_eq!(deletes_of(&state, label), 1, "{label}");
            assert_eq!(
                state.creates.iter().filter(|c| c.as_str() == label).count(),
                1,
                "{label}: a create was sent twice"
            );
            assert_clean_lines(&outcome.lines);
        }
    }

    #[tokio::test]
    async fn a_create_that_lands_after_cleanups_first_read_is_found_in_the_window_and_removed() {
        for (label, owner) in KIBANA_CREATES {
            let (server, state) = fake_stack(|s| s.late_create = Some(label.to_string())).await;
            let t = mock_transport(&server);

            let outcome = record_with(&t, short_settle(100)).await;

            assert!(outcome.step_error.is_some(), "{label}");
            assert!(outcome.unresolved_before_cleanup[owner], "{label}");
            assert!(
                outcome.failures.is_empty(),
                "{label}: {:?}",
                outcome.failures
            );
            assert!(released(&outcome.ownership_after_cleanup), "{label}");
            assert!(!outcome.alerts_after_cleanup, "{label}");
            assert!(!outcome.succeeded && outcome.written.is_none(), "{label}");
            let state = state.lock().expect("state");
            assert!(
                state.is_empty(),
                "{label}: the late create survived cleanup"
            );
            assert_eq!(deletes_of(&state, label), 1, "{label}");
            assert_eq!(state.open_alerts(SESSION_RULE_UUID), 0, "{label}");
            assert!(state.unexpected.is_empty(), "{:?}", state.unexpected);
        }
    }

    #[tokio::test]
    async fn an_object_that_never_appears_clears_only_after_the_full_window() {
        let label = "rule:elasticctl-sample-compose-missing-index";
        let (server, state) = fake_stack(|s| s.lost_create = Some(label.into())).await;
        let t = mock_transport(&server);

        let outcome = record_with(&t, short_settle(150)).await;

        assert!(outcome.unresolved_before_cleanup["compose_rule"]);
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        assert!(released(&outcome.ownership_after_cleanup));
        assert!(
            outcome.teardown_time >= Duration::from_millis(150),
            "{:?}",
            outcome.teardown_time
        );
        let state = state.lock().expect("state");
        let create = state
            .log
            .iter()
            .rposition(|line| line == "POST /api/detection_engine/rules")
            .expect("create sent");
        let reads = state.log[create..]
            .iter()
            .filter(|line| {
                line.as_str()
                    == "GET /api/detection_engine/rules?rule_id=elasticctl-sample-compose-missing-index"
            })
            .count();
        assert!(reads >= 3, "read {reads} times");
        assert_eq!(deletes_of(&state, label), 0);
        assert!(state.is_empty());
    }

    #[tokio::test]
    async fn an_unresolved_claim_fails_the_step_names_the_object_and_writes_no_fixture() {
        let label = "rule:elasticctl-sample-compose-missing-index";
        let (server, state) = fake_stack(|s| {
            s.late_create = Some(label.into());
            s.retag_after_create = Some(label.into());
        })
        .await;
        let t = mock_transport(&server);

        let outcome = record_with(&t, short_settle(100)).await;

        assert!(outcome.ownership_after_cleanup["compose_rule"]);
        assert!(!outcome.succeeded && outcome.written.is_none());
        assert!(
            outcome.lines.iter().any(|line| line.starts_with(
                "record-compose needs manual recovery: rule elasticctl-sample-compose-missing-index "
            )),
            "{:?}",
            outcome.lines
        );
        assert_clean_lines(&outcome.lines);
        let state = state.lock().expect("state");
        assert_eq!(
            deletes_of(&state, label),
            0,
            "an unmarked object was deleted"
        );
    }

    #[test]
    fn an_unresolved_claim_alone_blocks_the_fixtures() {
        let outcome = RunOutcome {
            step: Ended::Finished(Ok(Recording {
                dir: PathBuf::from("unused"),
                fixtures: Vec::new(),
            })),
            teardown: Ended::Finished(Teardown {
                failures: Vec::new(),
                audit: Some(Ok(())),
            }),
            still_owned: Vec::new(),
            unresolved: vec![cleanup::CASE],
        };
        let mut written = false;
        let (succeeded, lines) = finish(outcome, |_| {
            written = true;
            Ok(())
        });
        assert!(!succeeded && !written);
        assert_eq!(
            lines,
            [
                "record-compose needs manual recovery: the marker case may still be created by a request whose answer was lost"
            ]
        );
    }

    #[tokio::test]
    async fn an_incomplete_alert_search_fails_cleanup_and_keeps_the_alerts_owned() {
        for (fault, reason) in [
            ("timed_out", "it timed out"),
            ("shard", "a shard failed"),
            ("inexact", "its total is not exact"),
        ] {
            let (server, state) = fake_stack(|s| s.alert_search_fault = Some(fault)).await;
            let t = mock_transport(&server);

            let outcome = record_against(&t).await;

            assert!(
                outcome.failures.iter().any(|failure| failure
                    == &format!("the search for the session alerts was incomplete: {reason}")),
                "{fault}: {:?}",
                outcome.failures
            );
            assert!(outcome.alerts_after_cleanup, "{fault}");
            assert!(!outcome.succeeded && outcome.written.is_none(), "{fault}");
            assert!(
                outcome.lines.iter().any(|line| line
                    .starts_with("record-compose cleanup left in place:")
                    && line.contains("the session alerts")),
                "{fault}: {:?}",
                outcome.lines
            );
            assert!(state.lock().expect("state").status_requests.is_empty());
        }
    }

    #[tokio::test]
    async fn alerts_that_appear_after_the_first_close_are_closed_on_the_retry() {
        let (server, state) = fake_stack(|s| s.late_alert = true).await;
        let t = mock_transport(&server);

        let outcome = record_with(&t, short_settle(60)).await;

        assert!(outcome.succeeded, "{:?}", outcome.lines);
        assert!(!outcome.alerts_after_cleanup);
        let state = state.lock().expect("state");
        assert_eq!(state.open_alerts(SESSION_RULE_UUID), 0);
        assert_eq!(state.status_requests.len(), 2);
        assert_eq!(
            state.status_requests[1],
            json!({"signal_ids": ["zz-alert-6"], "status": "closed"})
        );
    }

    #[tokio::test]
    async fn an_open_session_alert_after_cleanup_fails_the_audit() {
        // A zero window lets cleanup accept its first empty search, so the
        // late alert is left for the audit to find.
        let (server, state) = fake_stack(|s| s.late_alert = true).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        assert!(!outcome.succeeded && outcome.written.is_none());
        assert!(
            outcome.lines.iter().any(|line| line.starts_with(
                "record-compose baseline audit failed: open session alerts remain after cleanup"
            )),
            "{:?}",
            outcome.lines
        );
        assert_eq!(
            state.lock().expect("state").open_alerts(SESSION_RULE_UUID),
            1
        );
    }

    #[tokio::test]
    async fn a_marker_inventory_change_fails_the_audit() {
        for (kind, message) in [
            ("rules", "the marker rule inventory changed"),
            ("lists", "the marker exception list inventory changed"),
            ("indices", "the marker index inventory changed"),
        ] {
            let (server, state) = fake_stack(|s| s.inventory_change = Some(kind)).await;
            let t = mock_transport(&server);

            let outcome = record_against(&t).await;

            assert!(outcome.step_error.is_none(), "{kind}");
            assert!(
                outcome.failures.is_empty(),
                "{kind}: {:?}",
                outcome.failures
            );
            assert!(!outcome.succeeded && outcome.written.is_none(), "{kind}");
            assert!(
                outcome.lines.iter().any(|line| line
                    .starts_with(&format!("record-compose baseline audit failed: {message}"))),
                "{kind}: {:?}",
                outcome.lines
            );
            assert!(state.lock().expect("state").is_empty(), "{kind}");
        }
    }

    #[tokio::test]
    async fn the_tactic_and_subtechnique_probes_go_to_the_private_log_only() {
        let (server, state) = fake_stack(|_| {}).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        let recording = outcome.written.expect("written");
        assert_eq!(recording.fixtures.len(), 12);
        assert!(
            fixture_names(&recording)
                .iter()
                .all(|name| { !name.contains("tactic") && !name.contains("subtechnique") })
        );
        let public = serde_json::to_string(
            &recording
                .fixtures
                .iter()
                .map(|f| &f.document)
                .collect::<Vec<_>>(),
        )
        .expect("encode");
        assert!(
            !public.contains("TA0002\\\" AND"),
            "a probe reached a fixture"
        );
        assert_eq!(
            outcome.log.get("threat_probes"),
            Some(&json!({
                "rules_find_by_tactic": {"result": "ok", "total": 1},
                "rules_find_by_subtechnique": {"result": "ok", "total": 1}
            }))
        );
        let state = state.lock().expect("state");
        for planned in [
            requests::rules_find_by_tactic(),
            requests::rules_find_by_subtechnique(),
        ] {
            let line = format!("GET {}", planned.target());
            assert!(state.log.contains(&line), "{line} not sent");
        }
    }

    fn writes_or_deletes_the_index(state: &State) -> bool {
        state.log.iter().any(|line| {
            line.starts_with(&format!("POST /{ALERT_PROBE_INDEX}/"))
                || line == &format!("DELETE /{ALERT_PROBE_INDEX}")
        })
    }

    #[tokio::test]
    async fn an_index_that_appears_after_the_preflight_is_never_written_to_or_deleted() {
        let (server, state) = fake_stack(|s| s.index_after_preflight = true).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        let error = outcome.step_error.expect("refused");
        assert_eq!(
            error.message,
            "refusing to record: index elasticctl-sample-alert-events already exists and is not this run's"
        );
        assert!(!outcome.ownership_before_cleanup["alert_index"]);
        assert!(!outcome.succeeded && outcome.written.is_none());
        assert_clean_lines(&outcome.lines);
        let state = state.lock().expect("state");
        assert!(
            foreign_present(&state, "index"),
            "the foreign index changed"
        );
        assert!(
            state.index.is_empty(),
            "a document reached the foreign index"
        );
        assert!(!writes_or_deletes_the_index(&state), "{:?}", state.log);
    }

    #[tokio::test]
    async fn an_index_whose_uuid_changed_before_the_delete_is_kept_and_fails_the_run() {
        let (server, state) = fake_stack(|s| s.index_replaced_before_cleanup = true).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        assert!(outcome.step_error.is_none());
        assert_eq!(
            outcome.failures,
            [
                "refusing to delete index elasticctl-sample-alert-events: its marker fields or id do not match"
            ]
        );
        assert!(outcome.ownership_after_cleanup["alert_index"]);
        assert!(!outcome.succeeded && outcome.written.is_none());
        let state = state.lock().expect("state");
        assert_eq!(state.index_uuid.as_deref(), Some("uuid-other-run"));
        assert!(foreign_present(&state, "doc:1"));
        assert!(
            !state.log.contains(&format!("DELETE /{ALERT_PROBE_INDEX}")),
            "{:?}",
            state.log
        );
    }

    #[tokio::test]
    async fn a_conflicting_marker_document_keeps_the_index_owned_until_cleanup_removes_it() {
        let (server, state) = fake_stack(|s| s.conflict_on = Some("doc:1".into())).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        let error = outcome.step_error.expect("failed write");
        assert_eq!(error.kind, elasticctl_core::ErrorKind::Conflict);
        assert_eq!(error.message, "writing a marker document failed");
        assert!(
            outcome.ownership_before_cleanup["alert_index"],
            "the conflict released the index"
        );
        assert!(!outcome.unresolved_before_cleanup["alert_index"]);
        assert!(
            !outcome.unresolved_before_cleanup["index_recreation"],
            "a conflict is a definite answer"
        );
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        assert!(released(&outcome.ownership_after_cleanup));
        assert!(!outcome.succeeded && outcome.written.is_none());
        let state = state.lock().expect("state");
        assert!(state.is_empty(), "the index survived cleanup");
        let delete = format!("DELETE /{ALERT_PROBE_INDEX}");
        let deletes: Vec<usize> = (0..state.log.len())
            .filter(|n| state.log[*n] == delete)
            .collect();
        assert_eq!(deletes.len(), 1, "{:?}", state.log);
        assert_eq!(
            state.log[deletes[0] - 1],
            format!("GET /{ALERT_PROBE_INDEX}/_settings/index.uuid"),
            "the delete was not preceded by the UUID read"
        );
    }

    #[tokio::test]
    async fn an_unresolved_index_that_appears_is_left_for_manual_recovery_and_never_deleted() {
        for configure in [
            (|s: &mut State| s.unavailable_after_create = Some("index".into())) as fn(&mut State),
            |s: &mut State| s.late_create = Some("index".into()),
        ] {
            let (server, state) = fake_stack(configure).await;
            let t = mock_transport(&server);

            let outcome = record_with(&t, short_settle(100)).await;

            let error = outcome.step_error.as_ref().expect("failed create");
            assert_eq!(error.http_status, Some(503));
            assert!(outcome.ownership_before_cleanup["alert_index"]);
            assert!(outcome.unresolved_before_cleanup["alert_index"]);
            assert_eq!(
                outcome.failures,
                [
                    "index elasticctl-sample-alert-events is present without a UUID this run recorded and needs manual recovery"
                ]
            );
            assert!(outcome.ownership_after_cleanup["alert_index"]);
            assert!(!outcome.succeeded && outcome.written.is_none());
            assert!(
                outcome.lines.iter().any(|line| line.starts_with(
                    "record-compose needs manual recovery: index elasticctl-sample-alert-events "
                )),
                "{:?}",
                outcome.lines
            );
            assert_clean_lines(&outcome.lines);
            let state = state.lock().expect("state");
            assert!(state.index_uuid.is_some(), "the index did not land");
            assert!(state.index.is_empty(), "a document was written");
            assert!(!writes_or_deletes_the_index(&state), "{:?}", state.log);
            assert_eq!(
                state.creates.iter().filter(|c| *c == "index").count(),
                1,
                "the create was sent twice"
            );
        }
    }

    #[tokio::test]
    async fn a_replaced_index_stops_the_next_write_and_the_refresh() {
        let index_line = |rest: &str| format!("{ALERT_PROBE_INDEX}{rest}");
        for (trigger, written) in [
            (format!("POST /{}", index_line("/_create/1")), 1),
            (format!("POST /{}", index_line("/_create/3")), 3),
            (format!("GET /{}", index_line("/_doc/1")), ALERT_DOCS),
        ] {
            let (server, state) =
                fake_stack(|s| s.index_replaced_after = Some(trigger.clone())).await;
            let t = mock_transport(&server);

            let outcome = record_against(&t).await;

            let error = outcome.step_error.expect("refused");
            assert_eq!(
                error.message,
                "refusing to write: index elasticctl-sample-alert-events is not the one this run created",
                "{trigger}"
            );
            assert!(outcome.ownership_before_cleanup["alert_index"], "{trigger}");
            assert!(outcome.ownership_after_cleanup["alert_index"], "{trigger}");
            assert_eq!(
                outcome.failures,
                [
                    "refusing to delete index elasticctl-sample-alert-events: its marker fields or id do not match"
                ],
                "{trigger}"
            );
            assert!(!outcome.succeeded && outcome.written.is_none(), "{trigger}");
            let state = state.lock().expect("state");
            let writes: Vec<&String> = state
                .log
                .iter()
                .filter(|line| line.starts_with(&format!("POST /{ALERT_PROBE_INDEX}/")))
                .collect();
            assert_eq!(writes.len(), written, "{trigger}: {writes:?}");
            assert!(
                writes.iter().all(|line| line.contains("/_create/")),
                "{trigger}: the refresh was sent"
            );
            let at = state
                .log
                .iter()
                .position(|line| *line == trigger)
                .expect("sent");
            assert_eq!(
                state.log[at + 1],
                format!("GET /{ALERT_PROBE_INDEX}/_settings/index.uuid"),
                "{trigger}: the next request is not the UUID read"
            );
            assert_eq!(state.index_uuid.as_deref(), Some("uuid-other-run"));
            assert!(foreign_present(&state, "doc:1"), "{trigger}");
            assert!(
                !state.log.contains(&format!("DELETE /{ALERT_PROBE_INDEX}")),
                "{trigger}"
            );
        }
    }

    #[tokio::test]
    async fn a_document_write_whose_answer_was_lost_is_watched_after_the_index_delete() {
        let label = "doc:2";
        let (server, state) = fake_stack(|s| s.lost_create = Some(label.into())).await;
        let t = mock_transport(&server);

        let outcome = record_with(&t, short_settle(150)).await;

        assert_eq!(
            outcome.step_error.as_ref().expect("lost").http_status,
            Some(503)
        );
        assert!(outcome.unresolved_before_cleanup["index_recreation"]);
        assert!(!outcome.unresolved_before_cleanup["alert_index"]);
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
        assert!(released(&outcome.ownership_after_cleanup));
        assert!(!outcome.succeeded && outcome.written.is_none());
        assert!(
            outcome.lines.iter().any(|line| line.starts_with(
                "record-compose needs manual recovery: index elasticctl-sample-alert-events "
            )),
            "{:?}",
            outcome.lines
        );
        assert!(
            outcome.teardown_time >= Duration::from_millis(150),
            "{:?}",
            outcome.teardown_time
        );
        let state = state.lock().expect("state");
        assert!(state.is_empty());
        let delete = state
            .log
            .iter()
            .position(|line| *line == format!("DELETE /{ALERT_PROBE_INDEX}"))
            .expect("deleted");
        let reads = state.log[delete..]
            .iter()
            .filter(|line| **line == format!("GET /{ALERT_PROBE_INDEX}/_settings/index.uuid"))
            .count();
        assert!(reads >= 3, "read {reads} times");
        assert_eq!(
            state.creates.iter().filter(|c| c.as_str() == label).count(),
            1,
            "the write was sent twice"
        );
    }

    #[tokio::test]
    async fn an_index_recreated_by_a_late_document_write_is_never_deleted() {
        let label = "doc:2";
        let (server, state) = fake_stack(|s| s.late_create = Some(label.into())).await;
        let t = mock_transport(&server);

        let outcome = record_with(&t, short_settle(100)).await;

        assert!(outcome.unresolved_before_cleanup["index_recreation"]);
        assert_eq!(
            outcome.failures,
            [
                "index elasticctl-sample-alert-events appeared again after this run deleted it and needs manual recovery"
            ]
        );
        assert!(!outcome.succeeded && outcome.written.is_none());
        assert!(
            outcome.lines.iter().any(|line| line.starts_with(
                "record-compose needs manual recovery: index elasticctl-sample-alert-events "
            )),
            "{:?}",
            outcome.lines
        );
        assert_clean_lines(&outcome.lines);
        let state = state.lock().expect("state");
        assert_eq!(state.index_uuid.as_deref(), Some("uuid-auto"));
        assert!(state.index.contains_key("2"), "the late write did not land");
        assert_eq!(
            state
                .log
                .iter()
                .filter(|line| **line == format!("DELETE /{ALERT_PROBE_INDEX}"))
                .count(),
            1,
            "the recreated index was deleted: {:?}",
            state.log
        );
    }

    #[tokio::test]
    async fn server_prose_never_reaches_a_fixture_and_stays_in_the_private_log() {
        let (server, _state) = fake_stack(|_| {}).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        let recording = outcome.written.expect("written");
        let public = serde_json::to_string(
            &recording
                .fixtures
                .iter()
                .map(|f| &f.document)
                .collect::<Vec<_>>(),
        )
        .expect("encode");
        for token in IDENTITY_TOKENS {
            assert!(!public.contains(token), "a fixture holds {token}");
        }
        let document = |name: &str| {
            recording
                .fixtures
                .iter()
                .find(|f| f.name == name)
                .map(|f| f.document.clone())
                .expect("fixture")
        };
        let last = &document("rule_get_failed_execution")["response"]["execution_summary"]["last_execution"];
        assert_eq!(last["message"], evidence::SERVER_TEXT_PLACEHOLDER);
        assert_eq!(last["status"], "partial failure");
        assert_eq!(last["status_order"], 20);
        let not_found = &document("resolve_index_not_found")["error"];
        assert_eq!(not_found["kind"], "not_found");
        assert_eq!(not_found["http_status"], 404);
        assert_eq!(not_found["message"], evidence::SERVER_TEXT_PLACEHOLDER);
        assert_eq!(
            document("signals_search_rule_activity")["response"]["hits"]["hits"][0]["_source"]["kibana.alert.reason"],
            evidence::SERVER_TEXT_PLACEHOLDER
        );

        let responses = outcome.log.get("responses").expect("responses");
        assert_eq!(
            responses["rule_get_failed_execution"]["execution_summary"]["last_execution"]["message"],
            IDENTITY_PROSE
        );
        assert_eq!(
            outcome.log.get("errors").expect("errors")["resolve_index_not_found"]["message"],
            IDENTITY_PROSE
        );
    }

    #[test]
    fn fixture_list_matches_the_spec_and_the_marker_constants() {
        assert_eq!(ALL_FIXTURES.len(), 12);
        assert_eq!(MATCH_PATTERN, format!("{ALERT_PROBE_INDEX}*"));
        assert_eq!(EXCLUSION_PATTERN, format!("-{MATCH_PATTERN}"));
        for name in [
            MISSING_RULE_ID,
            COMPOSE_ITEM_ID,
            MISSING_INDEX,
            MATCH_PATTERN,
            NO_MATCH_PATTERN,
            ABSENT_ALERT_ID,
            LIST_ID,
            ALERT_RULE_ID,
        ] {
            assert!(name.starts_with("elasticctl-sample-"), "{name}");
        }
        assert!(ACTIVITY_SIZE as usize <= ALERT_DOCS);
    }
}
