//! The compose recordings, in the order the step sends them.

use crate::diagnostics::{recording_error, safe_recording_transport_error};
use crate::recorder::cases::register_case_extras;
use crate::recorder::compose::evidence::{
    ALERT_INDEX_PLACEHOLDER, CASE_IDS_FIELD, Exchanges, PrivateLog, normalize_alert_search,
    normalize_cases_by_alert, normalize_items, normalize_rule, normalize_rule_page,
    resolve_names_are_markers,
};
use crate::recorder::compose::provision::{create_case, owns_missing_rule};
use crate::recorder::compose::requests::{
    MARKER_RULE_IDS, Planned, case_ids_probe_body, cases_by_alert, exception_items_count,
    resolve_index, rule_get, rules_find_by_technique, rules_find_sorted_page,
    session_alert_count_body, signals_activity,
};
use crate::recorder::compose::{
    ABSENT_ALERT_ID, ALERT_DOCS, CASE_IDS_ATTEMPTS, COMPOSE_RULE_NAME, ComposeSession,
    EXCLUSION_PATTERN, MATCH_PATTERN, MISSING_INDEX, MISSING_RULE_ID, NO_MATCH_PATTERN,
};
use crate::recorder::markers::{ALERT_POLL_ATTEMPTS, ALERT_RULE_ID, CASE_ID_PLACEHOLDER, LIST_ID};
use crate::recorder::ownership::owns_alert_rule;
use elasticctl_core::{ErrorKind, Transport};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

type Placeholders = BTreeMap<String, String>;

/// The newest session alert, which the marker case attaches.
pub(super) struct SessionAlert {
    pub(super) id: String,
    index: String,
    rule_uuid: String,
    rule_name: String,
}

fn safe(context: &'static str) -> impl FnOnce(elasticctl_core::Error) -> elasticctl_core::Error {
    move |error| safe_recording_transport_error(context, error)
}

/// Send one recorded GET and keep its raw body and wall time privately.
async fn recorded_get(
    t: &Transport,
    log: &mut PrivateLog,
    name: &'static str,
    planned: &Planned,
    elasticsearch: bool,
) -> elasticctl_core::Result<Value> {
    let started = Instant::now();
    let result = if elasticsearch {
        t.get_absolute_es(&planned.target()).await
    } else {
        t.get(&planned.target()).await
    };
    log.add(
        "timings_ms",
        name,
        json!(started.elapsed().as_millis() as u64),
    );
    match &result {
        Ok(body) => log.add("responses", name, body.clone()),
        Err(error) => log.add(
            "errors",
            name,
            json!({"kind": error.kind.as_str(), "http_status": error.http_status,
                "message": error.message}),
        ),
    }
    result
}

fn finished_execution(rule: &Value) -> bool {
    let last = &rule["execution_summary"]["last_execution"];
    last["date"].is_string()
        && last["status"]
            .as_str()
            .is_some_and(|status| !matches!(status, "running" | "going to run"))
}

/// Poll one marker rule until it reports a finished execution, within the
/// alert probe's attempt budget.
async fn wait_for_execution(
    t: &Transport,
    log: &mut PrivateLog,
    rule_id: &'static str,
    owns: fn(&Value) -> bool,
    interval: Duration,
) -> elasticctl_core::Result<Value> {
    let planned = rule_get(rule_id);
    let started = Instant::now();
    for attempt in 0..ALERT_POLL_ATTEMPTS {
        let rule = t
            .get(&planned.target())
            .await
            .map_err(safe("reading a marker rule failed"))?;
        if !owns(&rule) {
            return Err(recording_error(format!(
                "rule {rule_id} does not carry its marker fields"
            )));
        }
        if finished_execution(&rule) {
            log.add(
                "execution_waits",
                rule_id,
                json!({"polls": attempt + 1, "seconds": started.elapsed().as_secs()}),
            );
            return Ok(rule);
        }
        if attempt + 1 < ALERT_POLL_ATTEMPTS {
            tokio::time::sleep(interval).await;
        }
    }
    Err(recording_error(format!(
        "rule {rule_id} reported no finished execution after {ALERT_POLL_ATTEMPTS} polls"
    )))
}

/// The number of top-level entries in a resolve body.
fn resolved_entries(body: &Value) -> usize {
    ["indices", "aliases", "data_streams"]
        .iter()
        .filter_map(|key| body.get(*key).and_then(Value::as_array))
        .map(Vec::len)
        .sum()
}

/// The three `_resolve/index` recordings, and the exclusion pattern in the
/// private log only. Only marker names are sent, and a response naming
/// anything else at any depth is refused.
pub(super) async fn record_resolve(
    t: &Transport,
    exchanges: &mut Exchanges,
    log: &mut PrivateLog,
) -> elasticctl_core::Result<()> {
    if !t.has_es_url() {
        println!("record-compose: no Elasticsearch URL; skipping the _resolve/index recordings");
        return Ok(());
    }

    let planned = resolve_index(MATCH_PATTERN);
    let body = recorded_get(t, log, "resolve_index_match", &planned, true)
        .await
        .map_err(safe("resolving the marker index pattern failed"))?;
    if resolved_entries(&body) == 0 || !resolve_names_are_markers(&body) {
        return Err(recording_error(
            "refusing to record resolve_index_match: the response is not only marker names",
        ));
    }
    exchanges.response("resolve_index_match", &planned, body);

    let planned = resolve_index(NO_MATCH_PATTERN);
    let body = recorded_get(t, log, "resolve_index_no_match", &planned, true)
        .await
        .map_err(safe("resolving the no-match marker pattern failed"))?;
    if resolved_entries(&body) != 0 || !resolve_names_are_markers(&body) {
        return Err(recording_error(
            "refusing to record resolve_index_no_match: the response is not three empty arrays",
        ));
    }
    exchanges.response("resolve_index_no_match", &planned, body);

    // Whatever the exclusion pattern answers is a measurement, not a
    // fixture; `recorded_get` keeps the body or the error privately.
    let _ = recorded_get(
        t,
        log,
        "resolve_index_exclusion",
        &resolve_index(EXCLUSION_PATTERN),
        true,
    )
    .await;

    let planned = resolve_index(MISSING_INDEX);
    match recorded_get(t, log, "resolve_index_not_found", &planned, true).await {
        Err(error) if error.kind == ErrorKind::NotFound => {
            exchanges.error("resolve_index_not_found", &planned, error);
            Ok(())
        }
        Ok(_) => Err(recording_error(
            "refusing to record resolve_index_not_found: the missing marker name resolved",
        )),
        Err(error) => Err(safe_recording_transport_error(
            "resolving the missing marker name failed",
            error,
        )),
    }
}

fn page_rule_ids(page: &Value, name: &'static str) -> elasticctl_core::Result<Vec<String>> {
    page.get("data")
        .and_then(Value::as_array)
        .and_then(|rules| {
            rules
                .iter()
                .map(|rule| {
                    rule.get("rule_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| recording_error(format!("refusing to record {name}: unexpected page shape")))
}

/// Both rule reads after one execution, both `_find` pages, and the item
/// count on the marker list.
pub(super) async fn record_rules(
    t: &Transport,
    exchanges: &mut Exchanges,
    log: &mut PrivateLog,
    interval: Duration,
) -> elasticctl_core::Result<()> {
    for (name, rule_id, owns) in [
        (
            "rule_get_executed",
            ALERT_RULE_ID,
            owns_alert_rule as fn(&Value) -> bool,
        ),
        (
            "rule_get_failed_execution",
            MISSING_RULE_ID,
            owns_missing_rule,
        ),
    ] {
        let mut rule = wait_for_execution(t, log, rule_id, owns, interval).await?;
        log.add("responses", name, rule.clone());
        normalize_rule(&mut rule);
        exchanges.response(name, &rule_get(rule_id), rule);
    }

    let planned = rules_find_sorted_page();
    let mut page = recorded_get(t, log, "rules_find_sorted_page", &planned, false)
        .await
        .map_err(safe("reading the sorted marker page failed"))?;
    let mut ids = page_rule_ids(&page, "rules_find_sorted_page")?;
    ids.sort();
    let mut expected: Vec<String> = MARKER_RULE_IDS.iter().map(|id| id.to_string()).collect();
    expected.sort();
    if ids != expected {
        return Err(recording_error(
            "refusing to record rules_find_sorted_page: it does not hold exactly the two marker rules",
        ));
    }
    normalize_rule_page(&mut page);
    exchanges.response("rules_find_sorted_page", &planned, page);

    let planned = rules_find_by_technique();
    let mut page = recorded_get(t, log, "rules_find_by_technique", &planned, false)
        .await
        .map_err(safe("reading the technique marker page failed"))?;
    let ids = page_rule_ids(&page, "rules_find_by_technique")?;
    if !ids.iter().all(|id| MARKER_RULE_IDS.contains(&id.as_str())) {
        return Err(recording_error(
            "refusing to record rules_find_by_technique: it holds a rule that is not a marker",
        ));
    }
    normalize_rule_page(&mut page);
    exchanges.response("rules_find_by_technique", &planned, page);

    let planned = exception_items_count();
    let mut items = recorded_get(t, log, "exception_items_count", &planned, false)
        .await
        .map_err(safe("counting the marker list items failed"))?;
    let scoped = items
        .get("data")
        .and_then(Value::as_array)
        .is_some_and(|data| {
            data.iter()
                .all(|item| item.get("list_id").and_then(Value::as_str) == Some(LIST_ID))
        });
    if !scoped {
        return Err(recording_error(
            "refusing to record exception_items_count: it holds an item outside the marker list",
        ));
    }
    normalize_items(&mut items);
    exchanges.response("exception_items_count", &planned, items);
    Ok(())
}

/// Wait until every marker document has produced a session alert, then
/// record the alert activity search. Every hit must come from this
/// session's rule, so no older alert reaches the fixture.
pub(super) async fn record_activity(
    t: &Transport,
    exchanges: &mut Exchanges,
    log: &mut PrivateLog,
    placeholders: &mut Placeholders,
    rule_uuid: &str,
    interval: Duration,
) -> elasticctl_core::Result<SessionAlert> {
    let count_body = session_alert_count_body(rule_uuid);
    let started = Instant::now();
    let mut ready = false;
    for attempt in 0..ALERT_POLL_ATTEMPTS {
        let response = t
            .post(elasticctl_api::alerts::SEARCH_PATH, Some(&count_body))
            .await
            .map_err(safe("counting session alerts failed"))?;
        let total = response
            .pointer("/hits/total/value")
            .and_then(Value::as_u64);
        if total.is_some_and(|total| total >= ALERT_DOCS as u64) {
            log.add(
                "execution_waits",
                "session_alerts",
                json!({"polls": attempt + 1, "seconds": started.elapsed().as_secs()}),
            );
            ready = true;
            break;
        }
        if attempt + 1 < ALERT_POLL_ATTEMPTS {
            tokio::time::sleep(interval).await;
        }
    }
    if !ready {
        return Err(recording_error(format!(
            "fewer than {ALERT_DOCS} session alerts after {ALERT_POLL_ATTEMPTS} polls"
        )));
    }

    let planned = signals_activity();
    let started = Instant::now();
    let mut response = t
        .post(&planned.path, planned.body.as_ref())
        .await
        .map_err(safe("reading alert activity failed"))?;
    log.add(
        "timings_ms",
        "signals_search_rule_activity",
        json!(started.elapsed().as_millis() as u64),
    );
    log.add(
        "responses",
        "signals_search_rule_activity",
        response.clone(),
    );
    let page = elasticctl_api::alerts::decode_page(&response)
        .map_err(|_| recording_error("alert activity response failed hit decoding"))?;
    let session_hit = |source: &Value| {
        source["kibana.alert.rule.uuid"].as_str() == Some(rule_uuid)
            && source["kibana.alert.rule.rule_id"].as_str() == Some(ALERT_RULE_ID)
    };
    if page.hits.is_empty() || !page.hits.iter().all(|hit| session_hit(&hit.source)) {
        return Err(recording_error(
            "refusing to record signals_search_rule_activity: a hit is missing or not from this session",
        ));
    }
    for (n, hit) in page.hits.iter().enumerate() {
        let placeholder = format!("elasticctl-fixture-alert-{}", n + 1);
        placeholders.insert(hit.id.clone(), placeholder.clone());
        if let Some(uuid) = hit.source["kibana.alert.uuid"].as_str() {
            placeholders.insert(uuid.to_string(), placeholder);
        }
        // The backing index is not a marker name; the placeholder replaces
        // it wherever it appears, not only in `_index`.
        if let Some(index) = &hit.index {
            placeholders.insert(index.clone(), ALERT_INDEX_PLACEHOLDER.to_string());
        }
    }
    let first = &page.hits[0];
    let alert = SessionAlert {
        id: first.id.clone(),
        index: first
            .index
            .clone()
            .ok_or_else(|| recording_error("session alert has no _index to attach"))?,
        rule_uuid: rule_uuid.to_string(),
        rule_name: first.source["kibana.alert.rule.name"]
            .as_str()
            .unwrap_or(COMPOSE_RULE_NAME)
            .to_string(),
    };
    normalize_alert_search(&mut response);
    exchanges.response("signals_search_rule_activity", &planned, response);
    Ok(alert)
}

/// Read whether the attached alert's source holds the case-ids field. The
/// answer goes only to the private log.
async fn measure_case_ids(
    t: &Transport,
    log: &mut PrivateLog,
    alert_id: &str,
    interval: Duration,
) -> elasticctl_core::Result<()> {
    let body = case_ids_probe_body(alert_id);
    let mut present = false;
    for attempt in 0..CASE_IDS_ATTEMPTS {
        let response = t
            .post(elasticctl_api::alerts::SEARCH_PATH, Some(&body))
            .await
            .map_err(safe("reading the attached alert failed"))?;
        log.add("responses", "case_ids_probe", response.clone());
        present = response
            .pointer("/hits/hits/0/_source")
            .and_then(Value::as_object)
            .is_some_and(|source| source.contains_key(CASE_IDS_FIELD));
        if present {
            break;
        }
        if attempt + 1 < CASE_IDS_ATTEMPTS {
            tokio::time::sleep(interval).await;
        }
    }
    log.set("kibana_alert_case_ids_present", json!(present));
    Ok(())
}

/// Create the marker case, attach the session alert, record both case
/// reads, and measure the case-ids field privately. Cleanup removes the
/// case.
pub(super) async fn record_cases(
    compose: &mut ComposeSession<'_>,
    exchanges: &mut Exchanges,
    log: &mut PrivateLog,
    placeholders: &mut Placeholders,
    alert: &SessionAlert,
    interval: Duration,
) -> elasticctl_core::Result<()> {
    let t = compose.session.transport;
    let created = create_case(compose).await?;
    let case = elasticctl_api::cases::decode_case(&created)
        .map_err(|_| recording_error("case create response failed decoding"))?;
    placeholders.insert(case.id.clone(), CASE_ID_PLACEHOLDER.to_string());
    let mut next_comment = 0usize;
    register_case_extras(&created, placeholders, &mut next_comment);

    let attach = json!({
        "type": "alert",
        "alertId": [alert.id],
        "index": [alert.index],
        "rule": {"id": alert.rule_uuid, "name": alert.rule_name},
        "owner": elasticctl_api::cases::OWNER,
    });
    let attached = t
        .post_once(
            &elasticctl_api::cases::comments_path(&case.id),
            Some(&attach),
        )
        .await
        .map_err(safe("attaching the session alert failed"))?;
    elasticctl_api::cases::decode_case(&attached)
        .map_err(|_| recording_error("case attach response failed decoding"))?;
    register_case_extras(&attached, placeholders, &mut next_comment);

    // The attachment can take a moment to become searchable, so an empty
    // answer is read again within a small bound.
    let planned = cases_by_alert(&alert.id);
    let mut rows = Value::Null;
    for attempt in 0..CASE_IDS_ATTEMPTS {
        rows = recorded_get(t, log, "cases_by_alert", &planned, false)
            .await
            .map_err(safe("reading cases by alert failed"))?;
        if rows.as_array().is_none_or(|rows| !rows.is_empty()) {
            break;
        }
        if attempt + 1 < CASE_IDS_ATTEMPTS {
            tokio::time::sleep(interval).await;
        }
    }
    let only_marker_case = rows.as_array().is_some_and(|rows| {
        !rows.is_empty()
            && rows
                .iter()
                .all(|row| row.get("id").and_then(Value::as_str) == Some(case.id.as_str()))
    });
    if !only_marker_case {
        return Err(recording_error(
            "refusing to record cases_by_alert: it does not hold only the marker case",
        ));
    }
    normalize_cases_by_alert(&mut rows);
    exchanges.response("cases_by_alert", &planned, rows);

    let planned = cases_by_alert(ABSENT_ALERT_ID);
    let rows = recorded_get(t, log, "cases_by_alert_none", &planned, false)
        .await
        .map_err(safe("reading cases by an absent alert failed"))?;
    if rows.as_array().is_none_or(|rows| !rows.is_empty()) {
        return Err(recording_error(
            "refusing to record cases_by_alert_none: the absent marker id returned rows",
        ));
    }
    exchanges.response("cases_by_alert_none", &planned, rows);

    measure_case_ids(t, log, &alert.id, interval).await
}
