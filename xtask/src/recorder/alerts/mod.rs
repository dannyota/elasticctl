//! Recording helpers.

pub(crate) mod cleanup;

use crate::clock::now_rfc3339;
use crate::diagnostics::{record_trace, recording_error, safe_recording_error_summary};
use crate::fixtures::{Recording, error_fixture, exchange_fixture, response_fixture};
use crate::recorder::alerts::cleanup::{alert_probe_open_filter, require_no_open_marker_alerts};
use crate::recorder::markers::{
    ALERT_MARKER_TAG, ALERT_POLL_ATTEMPTS, ALERT_POLL_INTERVAL, ALERT_PROBE_INDEX, ALERT_RULE_ID,
    ALERT_RULE_NAME, ALERT_SEARCH_VOLATILE_FIELDS, TRIAGE_ENVELOPE_VOLATILE_FIELDS,
};
use crate::recorder::ownership::{
    owns_alert_index, owns_alert_rule, require_absent_alert_index, require_absent_alert_rule,
};
use crate::recorder::session::RecordingSession;
use crate::scrub::{
    scrub_alert_timestamps, scrub_alert_urls, scrub_placeholder_values, strip_volatile,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// What `record_alerts_probe` hands to `record_cases` (to attach against)
/// and to `close_and_clean_alerts` (to finish the close-by-query exchange).
pub(crate) struct AlertsProbe {
    /// The real `_id` of the still-open marker alert `record_cases` attaches.
    pub(crate) first_id: String,
    /// Real alert doc id (and uuid, when present) -> fixed placeholder.
    pub(crate) id_map: BTreeMap<String, String>,
    /// The first activated profile uid, used as the case's assignee.
    pub(crate) assignee_uid: String,
    /// Real profile uid -> fixed placeholder.
    pub(crate) uid_map: BTreeMap<String, String>,
}

/// Record the alerts probe: a marker rule over a marker index, generating an
/// alert the recorder transitions, tags, and assigns through every triage
/// route (triage spec section 9). Runs after `record_search`, and stops with
/// one open marker alert still live so `record_cases` has a real alert to
/// attach. Split out of the original single-function `record_alerts` (now
/// `record_alerts_probe` + `close_and_clean_alerts`) so `record_session` can
/// run `record_cases` between the two; every pre-write ownership claim and
/// marker check below is unchanged from the single-function version.
pub(super) async fn record_alerts_probe(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    flavor: &str,
    version: &str,
) -> elasticctl_core::Result<AlertsProbe> {
    record_trace("alerts-preflight-rule");
    require_absent_alert_rule(session.transport).await?;
    record_trace("alerts-preflight-index");
    require_absent_alert_index(session.transport).await?;
    record_trace("alerts-preflight-open");
    require_no_open_marker_alerts(session.transport).await?;

    let t = session.transport;

    // Claim ownership before issuing the write, not after a successful
    // response: a transport failure on a create the server actually applied
    // (e.g. the response is lost but the write landed) must not orphan an
    // enabled, 1-minute-interval rule or a scratch index. `cleanup` already
    // re-verifies the marker fields before deleting anything, so claiming
    // early cannot cause it to delete a foreign object.
    session.ownership.alert_index = true;
    session.ownership.alert_index_claimed = true;
    record_trace("alerts-index-write");
    for (id, seq) in [("1", 1_i64), ("2", 2), ("3", 3)] {
        let doc = json!({
            "@timestamp": now_rfc3339(),
            "marker": ALERT_MARKER_TAG,
            "message": format!("elasticctl sample alert event {seq}"),
        });
        t.post_absolute_es(&format!("/{ALERT_PROBE_INDEX}/_doc/{id}"), &doc)
            .await?;
    }
    let proof = t
        .get_absolute_es(&format!("/{ALERT_PROBE_INDEX}/_doc/1"))
        .await?;
    record_trace("alerts-index-proof");
    if !owns_alert_index(&proof) {
        return Err(recording_error(
            "alert index write did not prove the fixed marker identity",
        ));
    }
    // `_refresh` rejects a body, so use the GET form, which sends none.
    record_trace("alerts-index-refresh");
    t.get_absolute_es(&format!("/{ALERT_PROBE_INDEX}/_refresh"))
        .await?;

    let rule_body = json!({
        "rule_id": ALERT_RULE_ID,
        "name": ALERT_RULE_NAME,
        "description": "Recorded by cargo xtask record. Safe to delete.",
        "type": "query",
        "language": "kuery",
        "query": "marker: elasticctl-sample",
        "index": [ALERT_PROBE_INDEX],
        "severity": "low",
        "risk_score": 21,
        "enabled": true,
        "from": "now-10m",
        "interval": "1m",
        "tags": [ALERT_MARKER_TAG],
    });
    session.ownership.alert_rule = true;
    session.ownership.alert_rule_claimed = true;
    record_trace("alerts-rule-create");
    let created_rule = t
        .post("/api/detection_engine/rules", Some(&rule_body))
        .await?;
    if !owns_alert_rule(&created_rule) {
        return Err(recording_error(
            "alert rule create response did not prove the fixed marker identity",
        ));
    }

    // Poll on the *open* filter, not the bare rule-id filter: closed residue
    // from an earlier run (the accepted deviation, spec section 9) would
    // otherwise satisfy the readiness check before this session's rule ever
    // fires, and the same query becomes the recorded `signals_search`
    // exchange, so it must capture only this session's own alerts.
    //
    // The rest of the body is the PRODUCTION body, not a hand-rolled probe
    // shape: `alerts_ops::default_sort()` and `RESOLVE_SOURCE_FIELDS` are the
    // exact sort and `_source` include `alerts_ops` sends on every read, so
    // this recording proves — for the first time against a live stack —
    // that the `kibana.alert.uuid` sort tiebreaker doesn't error and that a
    // dotted `_source` include actually returns flat dotted keys (triage
    // spec section 10). Composed from the `-api` crate so recorder and
    // production cannot drift apart.
    let search_request = json!({
        "query": alert_probe_open_filter(),
        "sort": elasticctl_api::alerts_ops::default_sort(),
        "size": 10,
        "track_total_hits": true,
        "_source": elasticctl_api::alerts_ops::RESOLVE_SOURCE_FIELDS,
    });
    let mut search_response = Value::Null;
    let mut found = false;
    record_trace("alerts-poll");
    for attempt in 0..ALERT_POLL_ATTEMPTS {
        search_response = t
            .post(elasticctl_api::alerts::SEARCH_PATH, Some(&search_request))
            .await?;
        let total = search_response
            .pointer("/hits/total/value")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if total > 0 {
            found = true;
            break;
        }
        if attempt + 1 < ALERT_POLL_ATTEMPTS {
            tokio::time::sleep(ALERT_POLL_INTERVAL).await;
        }
    }
    if !found {
        let minutes = ALERT_POLL_ATTEMPTS * ALERT_POLL_INTERVAL.as_secs() as u32 / 60;
        return Err(recording_error(format!(
            "no alerts appeared for rule_id {ALERT_RULE_ID} after {ALERT_POLL_ATTEMPTS} \
             attempts over ~{minutes} minutes; the rule scheduler may be lagging — rerun this \
             flavor"
        )));
    }

    let page = elasticctl_api::alerts::decode_page(&search_response).map_err(|error| {
        recording_error(format!(
            "decoding signals_search response: {}",
            error.message
        ))
    })?;
    record_trace("alerts-page");
    if page.hits.is_empty() {
        return Err(recording_error(
            "signals_search reported a positive total but decoded zero hits",
        ));
    }
    // Prove the dotted `_source` include actually returns the requested
    // fields against flat dotted keys — an assumption `resolve_ids` (and so
    // every mutation preview) rests on, never before exercised against a
    // live stack (triage spec section 10). A hit whose restricted `_source`
    // is missing a requested field would otherwise pass silently: `hits` is
    // still non-empty, decode still succeeds, and the fixture would record
    // broken behavior as if it were proven.
    for hit in &page.hits {
        for field in elasticctl_api::alerts_ops::RESOLVE_SOURCE_FIELDS {
            if hit.source.get(*field).is_none() {
                return Err(recording_error(format!(
                    "signals_search's `_source` include did not return `{field}` on hit {}: \
                     the dotted _source include may not work against flat dotted keys",
                    hit.id
                )));
            }
        }
    }
    record_trace("alerts-source");
    let mut id_map: BTreeMap<String, String> = BTreeMap::new();
    for (i, hit) in page.hits.iter().enumerate() {
        let placeholder = format!("elasticctl-fixture-alert-{}", i + 1);
        id_map.insert(hit.id.clone(), placeholder.clone());
        if let Some(uuid) = hit.source.get("kibana.alert.uuid").and_then(Value::as_str) {
            id_map.insert(uuid.to_string(), placeholder);
        }
    }
    let first_id = page.hits[0].id.clone();

    {
        let mut request = search_request.clone();
        let mut response = search_response.clone();
        strip_volatile(&mut response, ALERT_SEARCH_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &id_map);
        scrub_placeholder_values(&mut response, &id_map);
        scrub_alert_timestamps(&mut response);
        scrub_alert_urls(&mut response);
        recording.fixtures.push(exchange_fixture(
            "signals_search",
            flavor,
            version,
            request,
            response,
        ));
    }

    // Acknowledge the first alert by id. The live response settles whether
    // the `signal_ids` form accepts `reason` (triage spec section 10).
    let with_reason = json!({
        "signal_ids": [first_id.clone()],
        "status": "acknowledged",
        "reason": "false_positive",
    });
    record_trace("alerts-status");
    let (ids_status_request, ids_status_response, ids_reason_accepted) = match t
        .post(elasticctl_api::alerts::STATUS_PATH, Some(&with_reason))
        .await
    {
        Ok(response) => (with_reason, response, true),
        Err(error) => {
            println!(
                "signals/status signal_ids+reason failed: {}; retrying without reason",
                safe_recording_error_summary(&error)
            );
            let without_reason = json!({
                "signal_ids": [first_id.clone()],
                "status": "acknowledged",
            });
            let response = t
                .post(elasticctl_api::alerts::STATUS_PATH, Some(&without_reason))
                .await?;
            (without_reason, response, false)
        }
    };
    println!("signals/status signal_ids-form reason accepted: {ids_reason_accepted}");
    elasticctl_api::alerts::decode_outcome(&ids_status_response).map_err(|error| {
        recording_error(format!(
            "decoding signals_status_ids response: {}",
            error.message
        ))
    })?;
    {
        let mut request = ids_status_request;
        let mut response = ids_status_response;
        strip_volatile(&mut response, TRIAGE_ENVELOPE_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &id_map);
        scrub_placeholder_values(&mut response, &id_map);
        recording.fixtures.push(exchange_fixture(
            "signals_status_ids",
            flavor,
            version,
            request,
            response,
        ));
    }

    // Add then remove a tag on the same alert; record the add.
    let add_tags_request = json!({
        "ids": [first_id.clone()],
        "tags": {"tags_to_add": ["triage-check"], "tags_to_remove": []},
    });
    record_trace("alerts-tags-add");
    let add_tags_response = t
        .post(elasticctl_api::alerts::TAGS_PATH, Some(&add_tags_request))
        .await?;
    elasticctl_api::alerts::decode_outcome(&add_tags_response).map_err(|error| {
        recording_error(format!("decoding signals_tags response: {}", error.message))
    })?;
    let remove_tags_request = json!({
        "ids": [first_id.clone()],
        "tags": {"tags_to_add": [], "tags_to_remove": ["triage-check"]},
    });
    record_trace("alerts-tags-remove");
    t.post(
        elasticctl_api::alerts::TAGS_PATH,
        Some(&remove_tags_request),
    )
    .await?;
    {
        let mut request = add_tags_request;
        let mut response = add_tags_response;
        strip_volatile(&mut response, TRIAGE_ENVELOPE_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &id_map);
        scrub_placeholder_values(&mut response, &id_map);
        recording.fixtures.push(exchange_fixture(
            "signals_tags",
            flavor,
            version,
            request,
            response,
        ));
    }

    // Activated user profiles. `uid` is rewritten to a per-profile
    // placeholder, never blanket-redacted: the assignees exchange below
    // needs it to stay a decodable, distinguishable value.
    record_trace("alerts-users");
    let users_body = t
        .get_internal(&elasticctl_api::profiles::internal_find_path(""))
        .await?;
    let profiles_list =
        elasticctl_api::profiles::decode_internal(&users_body).map_err(|error| {
            recording_error(format!("decoding users_find response: {}", error.message))
        })?;
    let assignee_uid = profiles_list
        .first()
        .ok_or_else(|| {
            recording_error(
                "users_find returned no activated profiles; the assignees probe needs at least one",
            )
        })?
        .uid
        .clone();
    let mut uid_map: BTreeMap<String, String> = BTreeMap::new();
    for (i, profile) in profiles_list.iter().enumerate() {
        uid_map.insert(profile.uid.clone(), format!("u_REDACTED_{}", i + 1));
    }
    {
        let mut response = users_body;
        scrub_placeholder_values(&mut response, &uid_map);
        recording.fixtures.push(response_fixture(
            "users_find",
            flavor,
            version,
            response,
            None,
        ));
    }

    // Assign then unassign the first activated uid; record the add.
    let add_assignees_request = json!({
        "ids": [first_id.clone()],
        "assignees": {"add": [assignee_uid.clone()], "remove": []},
    });
    record_trace("alerts-assignees-add");
    let add_assignees_response = t
        .post(
            elasticctl_api::alerts::ASSIGNEES_PATH,
            Some(&add_assignees_request),
        )
        .await?;
    elasticctl_api::alerts::decode_outcome(&add_assignees_response).map_err(|error| {
        recording_error(format!(
            "decoding signals_assignees response: {}",
            error.message
        ))
    })?;
    let remove_assignees_request = json!({
        "ids": [first_id.clone()],
        "assignees": {"add": [], "remove": [assignee_uid.clone()]},
    });
    record_trace("alerts-assignees-remove");
    t.post(
        elasticctl_api::alerts::ASSIGNEES_PATH,
        Some(&remove_assignees_request),
    )
    .await?;
    {
        let mut request = add_assignees_request;
        let mut response = add_assignees_response;
        strip_volatile(&mut response, TRIAGE_ENVELOPE_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &id_map);
        scrub_placeholder_values(&mut response, &id_map);
        scrub_placeholder_values(&mut request, &uid_map);
        scrub_placeholder_values(&mut response, &uid_map);
        recording.fixtures.push(exchange_fixture(
            "signals_assignees",
            flavor,
            version,
            request,
            response,
        ));
    }

    // Profile suggest, public route. Serverless answers 410; record
    // whichever shape the live route actually returns.
    record_trace("alerts-profile-suggest");
    match t
        .post_absolute_es(
            elasticctl_api::profiles::PUBLIC_SUGGEST_PATH,
            &json!({"name": "", "size": 10}),
        )
        .await
    {
        Ok(mut response) => {
            let suggested =
                elasticctl_api::profiles::decode_public(&response).map_err(|error| {
                    recording_error(format!(
                        "decoding profile_suggest response: {}",
                        error.message
                    ))
                })?;
            let mut next_index = uid_map.len();
            for profile in &suggested {
                if !uid_map.contains_key(&profile.uid) {
                    next_index += 1;
                    uid_map.insert(profile.uid.clone(), format!("u_REDACTED_{next_index}"));
                }
            }
            strip_volatile(&mut response, TRIAGE_ENVELOPE_VOLATILE_FIELDS);
            scrub_placeholder_values(&mut response, &uid_map);
            recording.fixtures.push(response_fixture(
                "profile_suggest",
                flavor,
                version,
                response,
                None,
            ));
        }
        Err(error) => {
            recording
                .fixtures
                .push(error_fixture("profile_suggest", flavor, version, error))
        }
    }

    // Disable the rule now, at the end of the probe, not at the start of the
    // close: every triage exchange this function needs is already recorded,
    // and `record_cases` runs next, driving several more live HTTP round
    // trips before `close_and_clean_alerts` gets a turn. Leaving the rule
    // enabled for that whole interval lets its 1-minute schedule keep firing
    // and stacking up fresh alerts underneath `record_cases`, which both
    // inflates the final close-by-query's `total` well past what
    // `sweep_close_marker_alerts`'s 15-second retry budget was sized for and
    // invites a genuine version-conflict race between an in-flight execution
    // and that close. Disabling here bounds the alert volume to what this
    // probe itself produced, the same as the single-function original.
    record_trace("alerts-rule-disable");
    t.patch(
        "/api/detection_engine/rules",
        &json!({"rule_id": ALERT_RULE_ID, "enabled": false}),
    )
    .await?;

    Ok(AlertsProbe {
        first_id,
        id_map,
        assignee_uid,
        uid_map,
    })
}
