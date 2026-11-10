//! Compose recording: the request shapes behind the cross-vertical task
//! tools, recorded from marker objects only.
//!
//! The step reuses the shared marker slots for the index (alert probe
//! index), the alerting rule (alert probe rule id), the exception list and
//! its first item, and the case. Its second rule and second item have their
//! own `CleanupOwnership` flags. Session cleanup runs after the step on
//! success and on every failure.

mod evidence;
mod provision;
mod requests;
mod steps;

use crate::diagnostics::{recording_error, safe_recording_transport_error};
use crate::environment::{activate_traditional_recorder_profile, transport_from_env};
use crate::fixtures::{Recording, write_recording};
use crate::recorder::agent_policies::reduce_package_status_item;
use crate::recorder::markers::ALERT_POLL_INTERVAL;
use crate::recorder::session::{CleanupOwnership, CleanupResponses, RecordingSession};
use evidence::{Exchanges, PrivateLog};
use serde_json::{Value, json};
use std::collections::BTreeMap;
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
/// The verified corpus page size.
const SORTED_PAGE_SIZE: u32 = 500;
/// The `rules_list` default limit.
const TECHNIQUE_PAGE_SIZE: u32 = 50;
/// Packages tried, in order, for one that is not installed.
const PACKAGE_CANDIDATES: [&str; 3] = ["apache", "nginx", "mysql"];
/// Reads of the case attachment, and of the attached alert before the
/// case-ids answer is logged.
const CASE_IDS_ATTEMPTS: u32 = 3;

fn fixture_dir(flavor: &str, version: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests/fixtures")
        .join(format!("{flavor}-{version}"))
}

async fn log_installed_package(t: &elasticctl_core::Transport, log: &mut PrivateLog) {
    let planned = requests::package_status("system");
    match t.get(&planned.target()).await {
        Ok(body) => log.add(
            "responses",
            "package_system",
            reduce_package_status_item(&body).unwrap_or(Value::Null),
        ),
        Err(error) => log.add(
            "errors",
            "package_system",
            json!({"kind": error.kind.as_str(), "http_status": error.http_status}),
        ),
    }
}

async fn record_steps(
    session: &mut RecordingSession<'_>,
    log: &mut PrivateLog,
    fixture_flavor: Option<String>,
    interval: Duration,
) -> elasticctl_core::Result<Recording> {
    let t = session.transport;
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

    provision::preflight(t).await?;
    let (package, package_body) = provision::probe_not_installed_package(t).await?;
    log.add("responses", "package_not_installed", package_body.clone());
    log_installed_package(t, log).await;

    let mut exchanges = Exchanges::default();
    provision::create_index(session).await?;
    steps::record_resolve(t, &mut exchanges, log).await?;
    let ids = provision::create_objects(session).await?;
    let mut placeholders = BTreeMap::from([
        (
            ids.list_id.clone(),
            "elasticctl-fixture-exception-list".to_string(),
        ),
        (
            ids.rule_uuid.clone(),
            "elasticctl-fixture-rule-uuid".to_string(),
        ),
        (
            ids.missing_rule_uuid.clone(),
            "elasticctl-fixture-rule-uuid-2".to_string(),
        ),
    ]);
    steps::record_rules(t, &mut exchanges, log, interval).await?;
    let alert = steps::record_activity(
        t,
        &mut exchanges,
        log,
        &mut placeholders,
        &ids.rule_uuid,
        interval,
    )
    .await?;
    steps::record_cases(
        session,
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

/// Run the compose step, then session cleanup whatever the step returned.
async fn run(
    session: &mut RecordingSession<'_>,
    log: &mut PrivateLog,
    fixture_flavor: Option<String>,
    interval: Duration,
) -> (
    elasticctl_core::Result<Recording>,
    elasticctl_core::Result<CleanupResponses>,
) {
    let recorded = record_steps(session, log, fixture_flavor, interval).await;
    let cleanup = session.cleanup().await;
    (recorded, cleanup)
}

/// `cargo xtask record-compose`: record the compose fixtures from the target
/// that `cargo xtask record` reads, then clean every marker object.
pub(crate) async fn record_compose() {
    if let Err(error) = activate_traditional_recorder_profile().await {
        eprintln!("record-compose setup failed: {}", error.message);
        std::process::exit(1);
    }
    let transport = transport_from_env(60);
    let mut session = RecordingSession {
        transport: &transport,
        ownership: CleanupOwnership::default(),
    };
    let mut log = PrivateLog::default();
    let fixture_flavor = std::env::var("ELASTICCTL_FIXTURE_FLAVOR").ok();
    let (recorded, cleanup) =
        run(&mut session, &mut log, fixture_flavor, ALERT_POLL_INTERVAL).await;

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    match log.write(&workspace) {
        Ok(path) => println!(
            "wrote private log {}",
            path.strip_prefix(&workspace).unwrap_or(&path).display()
        ),
        Err(message) => eprintln!("{message}"),
    }

    let recording = match (recorded, cleanup) {
        (Ok(recording), Ok(_)) => recording,
        (Err(record_error), Ok(_)) => {
            eprintln!(
                "record-compose failed after cleanup: {}",
                record_error.message
            );
            std::process::exit(1);
        }
        (Ok(_), Err(cleanup_error)) => {
            eprintln!("record-compose cleanup failed: {}", cleanup_error.message);
            std::process::exit(1);
        }
        (Err(record_error), Err(cleanup_error)) => {
            eprintln!(
                "record-compose failed after cleanup: {}; cleanup also failed: {}",
                record_error.message, cleanup_error.message
            );
            std::process::exit(1);
        }
    };
    if let Err(error) = write_recording(recording) {
        eprintln!("record-compose failed after cleanup: {}", error.message);
        std::process::exit(1);
    }
    println!("recorded compose fixtures");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::markers::{
        ALERT_PROBE_INDEX, ALERT_RULE_ID, CASE_ID_PLACEHOLDER, ITEM_ID, LIST_ID,
    };
    use crate::recorder::test_support::mock_transport;
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const ALERT_INDEX: &str = ".internal.alerts-security.alerts-default-000001";

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

    /// What the fake stack holds. Creates apply before an injected failure
    /// answers, which models a create whose response was lost.
    #[derive(Default)]
    struct State {
        index: BTreeMap<String, Value>,
        list: Option<Value>,
        items: BTreeMap<String, Value>,
        rules: BTreeMap<String, Value>,
        rule_reads: BTreeMap<String, u32>,
        alerts: Vec<Value>,
        cases: BTreeMap<String, Value>,
        attached: Vec<String>,
        log: Vec<String>,
        unexpected: Vec<String>,
        fail_on: Option<String>,
        foreign_hits: bool,
        foreign_rule: bool,
        foreign_case: bool,
        attachment_lag: u32,
        existing_rule: bool,
        installed: Vec<&'static str>,
    }

    impl State {
        fn is_empty(&self) -> bool {
            self.index.is_empty()
                && self.list.is_none()
                && self.items.is_empty()
                && self.rules.is_empty()
                && self.cases.is_empty()
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
                (
                    "partial failure",
                    "no index matching elasticctl-sample-compose-missing",
                )
            };
            rule["execution_summary"] = json!({"last_execution": {
                "date": "2026-11-10T01:03:00.000Z", "status": status, "status_order": 20,
                "message": message, "metrics": {"total_search_duration_ms": 7}
            }});
        }
        Some(rule)
    }

    fn create_rule(state: &mut State, body: &Value) -> Value {
        let rule_id = body["rule_id"].as_str().unwrap_or_default().to_string();
        let mut rule = body.clone();
        rule["id"] = json!(format!("so-{rule_id}"));
        rule["created_at"] = json!("2026-11-10T01:02:00.000Z");
        rule["updated_at"] = json!("2026-11-10T01:02:00.000Z");
        if rule_id == ALERT_RULE_ID {
            let uuid = "so-elasticctl-sample-alert-probe";
            let list_so = state
                .list
                .as_ref()
                .map(|l| l["id"].clone())
                .unwrap_or_default();
            for n in 1..=ALERT_DOCS {
                state.alerts.push(json!({
                    "_id": format!("zz-alert-{n}"), "_index": ALERT_INDEX, "sort": [n, format!("zz-alert-{n}")],
                    "_source": {
                        "@timestamp": "2026-11-10T01:03:00.000Z",
                        "kibana.alert.uuid": format!("zz-alert-{n}"),
                        "kibana.alert.rule.uuid": uuid,
                        "kibana.alert.rule.rule_id": ALERT_RULE_ID,
                        "kibana.alert.rule.name": COMPOSE_RULE_NAME,
                        "kibana.alert.workflow_status": "open",
                        "kibana.alert.rule.parameters": {"exceptions_list": [{"id": list_so}]},
                        "kibana.alert.url": "https://private.example.internal/app/zz-alert-1"
                    }
                }));
            }
        }
        state.rules.insert(rule_id, rule.clone());
        rule
    }

    fn signals(state: &mut State, body: &Value) -> Value {
        if body.get("aggs").is_some() {
            let mut hits: Vec<Value> = state.alerts.iter().take(5).cloned().collect();
            if state.foreign_hits && !hits.is_empty() {
                // An older alert of the same rule id from an earlier session.
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
        if body.pointer("/query/bool/must_not").is_some() {
            return json!({"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}});
        }
        let uuid = body.pointer("/query/bool/filter/1/term/kibana.alert.rule.uuid");
        let count = state
            .alerts
            .iter()
            .filter(|a| Some(&a["_source"]["kibana.alert.rule.uuid"]) == uuid)
            .count();
        json!({"hits": {"total": {"value": count, "relation": "eq"}, "hits": []}})
    }

    fn create_label(method: &str, path: &str, body: &Value) -> Option<String> {
        match (method, path) {
            ("POST", p) if p.starts_with(&format!("/{ALERT_PROBE_INDEX}/_doc/")) => {
                Some("index".into())
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

    fn handle(state: &mut State, request: &Request) -> ResponseTemplate {
        let method = request.method.to_string();
        let path = request.url.path().to_string();
        let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        state.log.push(match request.url.query() {
            Some(query) => format!("{method} {path}?{query}"),
            None => format!("{method} {path}"),
        });
        let label = create_label(&method, &path, &body);
        let response = route(state, &method, &path, &body, request);
        if label.is_some() && label == state.fail_on {
            return json_response(
                400,
                json!({"message": "private.example.internal lost reply"}),
            );
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
        match (method, path) {
            ("GET", "/api/status") => json_response(
                200,
                json!({"version": {"number": "9.7.0", "build_flavor": "serverless"}}),
            ),
            ("POST", p) if p.starts_with(&marker_doc) => {
                state
                    .index
                    .insert(p[marker_doc.len()..].to_string(), body.clone());
                json_response(201, json!({"result": "created"}))
            }
            ("GET", p) if p.starts_with(&marker_doc) => {
                match state.index.get(&p[marker_doc.len()..]) {
                    Some(doc) => json_response(200, json!({"_source": doc})),
                    None => missing(),
                }
            }
            ("GET", p) if p == format!("/{ALERT_PROBE_INDEX}/_refresh") => {
                json_response(200, json!({"_shards": {}}))
            }
            ("GET", p) if p == format!("/{ALERT_PROBE_INDEX}") => {
                if state.index.is_empty() {
                    missing()
                } else {
                    json_response(200, json!({}))
                }
            }
            ("DELETE", p) if p == format!("/{ALERT_PROBE_INDEX}") => {
                state.index.clear();
                json_response(200, json!({"acknowledged": true}))
            }
            ("GET", "/_resolve/index/elasticctl-sample-alert-events%2A") => json_response(
                200,
                json!({"indices": [{"name": ALERT_PROBE_INDEX, "attributes": ["open"]}],
                    "aliases": [], "data_streams": []}),
            ),
            ("GET", "/_resolve/index/elasticctl-sample-compose-none-%2A") => json_response(
                200,
                json!({"indices": [], "aliases": [], "data_streams": []}),
            ),
            ("GET", "/_resolve/index/elasticctl-sample-compose-missing")
            | ("GET", "/elasticctl-sample-compose-missing") => json_response(
                404,
                json!({"error": {"type": "index_not_found_exception",
                    "reason": "no such index [elasticctl-sample-compose-missing]"}, "status": 404}),
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
                    state.items.clear();
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
                let data: Vec<Value> = state.items.values().take(1).cloned().collect();
                json_response(
                    200,
                    json!({"data": data, "page": 1, "per_page": 1,
                    "total": state.items.len()}),
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
            ("PATCH", "/api/detection_engine/rules") => {
                let id = body["rule_id"].as_str().unwrap_or_default();
                state
                    .rules
                    .get(id)
                    .cloned()
                    .map_or_else(missing, |rule| json_response(200, rule))
            }
            ("GET", "/api/detection_engine/rules/_find") => {
                let filter = query_value(request, "filter").unwrap_or_default();
                let technique = filter.contains("threat.technique.id");
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
            ("GET", "/api/cases/case-real-1") => state
                .cases
                .get("case-real-1")
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

    async fn fake_stack(configure: impl FnOnce(&mut State)) -> (MockServer, Arc<Mutex<State>>) {
        let server = MockServer::start().await;
        let mut state = State {
            installed: vec!["apache", "system"],
            ..State::default()
        };
        configure(&mut state);
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

    struct Outcome {
        recorded: elasticctl_core::Result<Recording>,
        cleanup: elasticctl_core::Result<CleanupResponses>,
        ownership_before_cleanup: Vec<(&'static str, bool)>,
        ownership_after_cleanup: Vec<(&'static str, bool)>,
        log: PrivateLog,
    }

    fn flags(ownership: &CleanupOwnership) -> Vec<(&'static str, bool)> {
        vec![
            ("alert_index", ownership.alert_index),
            ("list", ownership.list),
            ("item", ownership.item),
            ("compose_item", ownership.compose_item),
            ("alert_rule", ownership.alert_rule),
            ("compose_rule", ownership.compose_rule),
            ("case", ownership.case),
        ]
    }

    /// Session cleanup sweeps marker cases by title and tag but leaves the
    /// `case` flag set, so the fake stack's state proves the case is gone.
    fn released(after: &[(&'static str, bool)]) -> bool {
        after.iter().all(|(name, owned)| *name == "case" || !owned)
    }

    async fn record_against(transport: &elasticctl_core::Transport) -> Outcome {
        let mut session = RecordingSession {
            transport,
            ownership: CleanupOwnership::default(),
        };
        let mut log = PrivateLog::default();
        let recorded = record_steps(&mut session, &mut log, None, Duration::ZERO).await;
        let ownership_before_cleanup = flags(&session.ownership);
        let cleanup = session.cleanup().await;
        Outcome {
            recorded,
            cleanup,
            ownership_before_cleanup,
            ownership_after_cleanup: flags(&session.ownership),
            log,
        }
    }

    fn fixture_names(recording: &Recording) -> Vec<&'static str> {
        recording.fixtures.iter().map(|f| f.name).collect()
    }

    #[tokio::test]
    async fn records_exactly_the_twelve_fixtures_and_cleans_every_marker_object() {
        let (server, state) = fake_stack(|_| {}).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        let recording = outcome.recorded.expect("recorded");
        outcome.cleanup.expect("cleanup");
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
        ] {
            assert!(!public.contains(private), "a fixture holds {private}");
        }
        assert_eq!(
            outcome.log.get("kibana_alert_case_ids_present"),
            Some(&json!(true))
        );
    }

    #[tokio::test]
    async fn every_object_is_claimed_before_the_request_that_creates_it() {
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
            ("case", "case"),
        ] {
            let (server, state) = fake_stack(|s| s.fail_on = Some(label.to_string())).await;
            let t = mock_transport(&server);

            let outcome = record_against(&t).await;

            assert!(outcome.recorded.is_err(), "{label}");
            let before: BTreeMap<_, _> = outcome.ownership_before_cleanup.into_iter().collect();
            assert!(before[owner], "{owner} was not claimed before its create");
            outcome
                .cleanup
                .unwrap_or_else(|e| panic!("{label}: {}", e.message));
            assert!(released(&outcome.ownership_after_cleanup), "{label}");
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
        }
    }

    #[tokio::test]
    async fn creates_run_in_order_after_every_preflight_read() {
        let (server, state) = fake_stack(|_| {}).await;
        let t = mock_transport(&server);
        record_against(&t).await.recorded.expect("recorded");

        let state = state.lock().expect("state");
        let position = |needle: &str| {
            state
                .log
                .iter()
                .position(|line| line.starts_with(needle))
                .unwrap_or_else(|| panic!("{needle} not sent"))
        };
        let first_write = position(&format!("POST /{ALERT_PROBE_INDEX}/_doc/1"));
        for preflight in [
            "GET /api/detection_engine/rules?rule_id=elasticctl-sample-alert-probe",
            &format!("GET /{ALERT_PROBE_INDEX}"),
            "GET /api/exception_lists?",
            &format!("GET /api/exception_lists/items?item_id={ITEM_ID}"),
            "GET /api/exception_lists/items?item_id=elasticctl-sample-exception-item-2",
            "GET /api/detection_engine/rules?rule_id=elasticctl-sample-compose-missing-index",
            "GET /elasticctl-sample-compose-missing",
            "GET /api/cases/_find",
            "GET /api/fleet/epm/packages/apache",
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
        assert!(!state.log.iter().any(|line| line.starts_with("PUT ")));
        assert!(
            !state
                .log
                .iter()
                .any(|line| line.contains("/api/detection_engine/rules/_find")
                    && !line.contains("elasticctl-sample-alert-probe")),
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

            let error = outcome.recorded.err().expect("refused");
            assert!(
                error.message.contains("refusing to record"),
                "{}",
                error.message
            );
            outcome.cleanup.expect("cleanup");
            assert!(released(&outcome.ownership_after_cleanup));
            assert!(state.lock().expect("state").is_empty());
        }
    }

    #[tokio::test]
    async fn a_lagging_attachment_is_read_again_within_its_bound() {
        let (server, state) = fake_stack(|s| s.attachment_lag = 2).await;
        let t = mock_transport(&server);
        record_against(&t).await.recorded.expect("recorded");
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
        assert!(outcome.recorded.is_err());
        outcome.cleanup.expect("cleanup");
        let state = state.lock().expect("state");
        assert_eq!(reads(&state), 3);
        assert!(state.is_empty());
    }

    #[tokio::test]
    async fn a_preflight_refusal_creates_nothing() {
        let (server, state) = fake_stack(|s| s.existing_rule = true).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        let error = outcome.recorded.err().expect("refused");
        assert!(
            error.message.contains("refusing to record"),
            "{}",
            error.message
        );
        assert!(
            outcome
                .ownership_before_cleanup
                .iter()
                .all(|(_, owned)| !owned)
        );
        let state = state.lock().expect("state");
        assert!(
            !state.log.iter().any(|line| line.starts_with("POST /api/")
                && !line.starts_with("POST /api/detection_engine/signals/search")),
            "{:?}",
            state.log
        );
        assert!(!state.log.iter().any(|line| line.starts_with("DELETE ")));
    }

    #[tokio::test]
    async fn no_installed_candidate_left_fails_before_any_write() {
        let (server, state) = fake_stack(|s| s.installed = vec!["apache", "nginx", "mysql"]).await;
        let t = mock_transport(&server);

        let outcome = record_against(&t).await;

        assert!(outcome.recorded.is_err());
        let state = state.lock().expect("state");
        assert!(
            !state
                .log
                .iter()
                .any(|line| line.starts_with(&format!("POST /{ALERT_PROBE_INDEX}")))
        );
        assert!(state.is_empty());
    }

    #[tokio::test]
    async fn without_an_elasticsearch_url_the_resolve_recordings_are_skipped() {
        let (server, state) = fake_stack(|_| {}).await;
        let t = elasticctl_core::Transport::new(&elasticctl_core::Profile {
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

        let recording = outcome.recorded.expect("recorded");
        outcome.cleanup.expect("cleanup");
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

    #[test]
    fn fixture_list_matches_the_spec_and_the_marker_constants() {
        assert_eq!(ALL_FIXTURES.len(), 12);
        assert_eq!(MATCH_PATTERN, format!("{ALERT_PROBE_INDEX}*"));
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
