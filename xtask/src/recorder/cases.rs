//! Cases helpers.

use crate::diagnostics::recording_error;
use crate::fixtures::{Recording, error_fixture, exchange_fixture, response_fixture};
use crate::recorder::alerts::AlertsProbe;
use crate::recorder::markers::{
    CASE_COMMENT, CASE_DURATION_VOLATILE_FIELDS, CASE_ID_PLACEHOLDER, CASE_RULE_UUID_PLACEHOLDER,
    CASE_TAG, CASE_TITLE, CASE_VERSION_PLACEHOLDER,
};
use crate::recorder::ownership::owns_case;
use crate::recorder::session::RecordingSession;
use crate::scrub::{scrub_alert_timestamps, scrub_placeholder_values, strip_volatile};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// The `_find` filter that names every marker case: the fixed title AND the
/// fixed tag together, matching `owns_case`'s AND semantics.
fn case_marker_filter() -> elasticctl_api::cases_ops::CaseFilter {
    elasticctl_api::cases_ops::CaseFilter {
        search: Some(CASE_TITLE.to_string()),
        tag: Some(CASE_TAG.to_string()),
        ..Default::default()
    }
}

pub(super) async fn find_marker_cases(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<(Vec<elasticctl_api::cases::Case>, u64)> {
    let query = elasticctl_api::cases_ops::find_query(
        &case_marker_filter(),
        1,
        elasticctl_api::cases_ops::PAGE_SIZE,
    );
    elasticctl_api::cases::find_page(t, &query).await
}

pub(super) async fn require_no_marker_cases(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    let (cases, total) = find_marker_cases(t).await?;
    if total > 0 || !cases.is_empty() {
        return Err(recording_error(format!(
            "refusing to record: {total} case(s) already carry title {CASE_TITLE:?} and tag \
             {CASE_TAG}. Manual remediation: find the id(s) via GET {}?{} then DELETE {} with \
             the matching ?ids=[...] query.",
            elasticctl_api::cases::FIND_PATH,
            elasticctl_api::cases_ops::find_query(
                &case_marker_filter(),
                1,
                elasticctl_api::cases_ops::PAGE_SIZE
            ),
            elasticctl_api::cases::CASES_PATH,
        )));
    }
    Ok(())
}

/// Delete every marker case found by title+tag, then re-verify none remain.
/// Cases tolerate zero residue (spec section 9) — unlike the alerts probe's
/// accepted closed-alert deviation, there is no "closed is fine" escape
/// hatch here. Shared by `record_cases`'s own delete step and `cleanup`'s
/// last-resort sweep.
pub(crate) async fn sweep_delete_marker_cases(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    let (cases, _) = find_marker_cases(t).await?;
    let ids: Vec<String> = cases
        .into_iter()
        .filter(|c| c.title == CASE_TITLE && c.tags.iter().any(|tag| tag == CASE_TAG))
        .map(|c| c.id)
        .collect();
    if !ids.is_empty() {
        elasticctl_api::cases::delete(t, &ids).await?;
    }
    require_no_marker_cases(t).await
}

/// Register every id/version a case-shaped response carries into `case_map`,
/// so this step's own fixture and every later one scrub consistently.
/// Comment ids are discovered, not assumed: whatever shape the live
/// `comments` array actually carries is what gets a placeholder.
pub(super) fn register_case_extras(
    value: &Value,
    case_map: &mut BTreeMap<String, String>,
    next_comment: &mut usize,
) {
    // `case_update_status`'s response is a bare array of cases rather than
    // one case object — recurse into each element so a future call site that
    // passes the array directly (instead of unwrapping it first) still
    // registers every version, defense in depth against the exact bug this
    // function had before: passing the array itself found nothing, since
    // `Value::get` on an array never matches an object key.
    if let Some(array) = value.as_array() {
        for item in array {
            register_case_extras(item, case_map, next_comment);
        }
        return;
    }
    if let Some(version) = value.get("version").and_then(Value::as_str) {
        case_map
            .entry(version.to_string())
            .or_insert_with(|| CASE_VERSION_PLACEHOLDER.to_string());
    }
    if let Some(comments) = value.get("comments").and_then(Value::as_array) {
        for comment in comments {
            if let Some(id) = comment.get("id").and_then(Value::as_str)
                && !case_map.contains_key(id)
            {
                *next_comment += 1;
                case_map.insert(
                    id.to_string(),
                    format!("elasticctl-fixture-case-comment-{next_comment}"),
                );
            }
            if let Some(version) = comment.get("version").and_then(Value::as_str) {
                case_map
                    .entry(version.to_string())
                    .or_insert_with(|| CASE_VERSION_PLACEHOLDER.to_string());
            }
        }
    }
    // `cases_find`'s response nests each case one level deeper, under
    // `cases`, rather than being a case itself — recurse into each one so
    // its own version/comments still get registered regardless of step
    // order.
    if let Some(cases) = value.get("cases").and_then(Value::as_array) {
        for case in cases {
            register_case_extras(case, case_map, next_comment);
        }
    }
}

/// The cases probe (triage spec section 9): create a marker case, drive it
/// through every mutation route — including attaching `probe.first_id`, the
/// alerts probe's still-open marker alert — then delete it and prove zero
/// residue. Runs between `record_alerts_probe` and `close_and_clean_alerts`
/// so that alert is still open when the attach exchange needs it.
pub(super) async fn record_cases(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    flavor: &str,
    version: &str,
    probe: &AlertsProbe,
) -> elasticctl_core::Result<()> {
    require_no_marker_cases(session.transport).await?;

    let t = session.transport;
    let mut case_map: BTreeMap<String, String> = BTreeMap::new();
    let mut next_comment = 0usize;

    // Claim ownership before issuing the write, not after a successful
    // response: unlike the rule/list/item probes, a case has no fixed,
    // caller-chosen id to re-check later, so if the response is lost after
    // the server applied the write, only a title+tag search
    // (`sweep_delete_marker_cases`) can find it regardless of when ownership
    // was claimed — the same reasoning `record_alerts_probe` uses for the
    // alert rule and index.
    session.ownership.case = true;
    let create_request = json!({
        "title": CASE_TITLE,
        "description": CASE_TITLE,
        "tags": [CASE_TAG],
        "severity": "low",
        "assignees": [{"uid": probe.assignee_uid}],
        "connector": {"id": "none", "name": "none", "type": ".none", "fields": null},
        "settings": {"syncAlerts": false},
        "owner": elasticctl_api::cases::OWNER,
    });
    let create_response = t
        .post(elasticctl_api::cases::CASES_PATH, Some(&create_request))
        .await?;
    if !owns_case(&create_response) {
        return Err(recording_error(
            "case create response did not prove the fixed marker identity",
        ));
    }
    let created = elasticctl_api::cases::decode_case(&create_response).map_err(|error| {
        recording_error(format!("decoding case_create response: {}", error.message))
    })?;
    let case_id = created.id.clone();
    case_map.insert(case_id.clone(), CASE_ID_PLACEHOLDER.to_string());
    register_case_extras(&create_response, &mut case_map, &mut next_comment);
    {
        let mut request = create_request;
        let mut response = create_response;
        scrub_alert_timestamps(&mut response);
        strip_volatile(&mut response, CASE_DURATION_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &case_map);
        scrub_placeholder_values(&mut response, &case_map);
        scrub_placeholder_values(&mut request, &probe.uid_map);
        scrub_placeholder_values(&mut response, &probe.uid_map);
        recording.fixtures.push(exchange_fixture(
            "case_create",
            flavor,
            version,
            request,
            response,
        ));
    }

    // case_get
    let get_response = t.get(&elasticctl_api::cases::case_path(&case_id)).await?;
    elasticctl_api::cases::decode_case(&get_response).map_err(|error| {
        recording_error(format!("decoding case_get response: {}", error.message))
    })?;
    register_case_extras(&get_response, &mut case_map, &mut next_comment);
    {
        let mut response = get_response;
        scrub_alert_timestamps(&mut response);
        strip_volatile(&mut response, CASE_DURATION_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut response, &case_map);
        scrub_placeholder_values(&mut response, &probe.uid_map);
        recording.fixtures.push(response_fixture(
            "case_get", flavor, version, response, None,
        ));
    }

    // cases_find: scoped by the fixed title AND tag together, composed from
    // the real `cases_ops::find_query` (so recorder and production cannot
    // drift apart) — never an unscoped `_find`; this measures the exact
    // filter params the CLI sends.
    let find_query_string = elasticctl_api::cases_ops::find_query(
        &case_marker_filter(),
        1,
        elasticctl_api::cases_ops::PAGE_SIZE,
    );
    let find_response = t
        .get(&format!(
            "{}?{find_query_string}",
            elasticctl_api::cases::FIND_PATH
        ))
        .await?;
    let (found, found_total) =
        elasticctl_api::cases::decode_find(&find_response).map_err(|error| {
            recording_error(format!("decoding cases_find response: {}", error.message))
        })?;
    if found_total == 0 || !found.iter().any(|c| c.id == case_id) {
        return Err(recording_error(
            "scoped cases_find did not contain the marker case",
        ));
    }
    register_case_extras(&find_response, &mut case_map, &mut next_comment);
    {
        let mut request = json!({"query": find_query_string});
        let mut response = find_response;
        scrub_alert_timestamps(&mut response);
        strip_volatile(&mut response, CASE_DURATION_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &case_map);
        scrub_placeholder_values(&mut response, &case_map);
        scrub_placeholder_values(&mut response, &probe.uid_map);
        recording.fixtures.push(exchange_fixture(
            "cases_find",
            flavor,
            version,
            request,
            response,
        ));
    }

    // case_comment
    let comment_request = json!({
        "type": "user",
        "comment": CASE_COMMENT,
        "owner": elasticctl_api::cases::OWNER,
    });
    let comment_response = t
        .post(
            &elasticctl_api::cases::comments_path(&case_id),
            Some(&comment_request),
        )
        .await?;
    elasticctl_api::cases::decode_case(&comment_response).map_err(|error| {
        recording_error(format!("decoding case_comment response: {}", error.message))
    })?;
    register_case_extras(&comment_response, &mut case_map, &mut next_comment);
    {
        let mut request = comment_request;
        let mut response = comment_response;
        scrub_alert_timestamps(&mut response);
        strip_volatile(&mut response, CASE_DURATION_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &case_map);
        scrub_placeholder_values(&mut response, &case_map);
        scrub_placeholder_values(&mut response, &probe.uid_map);
        recording.fixtures.push(exchange_fixture(
            "case_comment",
            flavor,
            version,
            request,
            response,
        ));
    }

    // case_attach: the still-open marker alert from `record_alerts_probe`.
    // `plan_attach` is the real production function (composed from -api so
    // recorder and production cannot drift apart), used here only to
    // resolve the alert's rule id/name/index — `record_alerts_probe`'s own
    // signals_search fixture deliberately restricts `_source` to
    // `RESOLVE_SOURCE_FIELDS` (proving that minimal shape works, spec
    // section 10) and does not carry the rule uuid this needs. The comment
    // POST itself is issued directly so the exact request body is recorded.
    let attach_plan =
        elasticctl_api::cases_ops::plan_attach(t, &case_id, std::slice::from_ref(&probe.first_id))
            .await
            .map_err(|error| recording_error(format!("planning case attach: {}", error.message)))?;
    let group = attach_plan.groups.first().ok_or_else(|| {
        recording_error("case attach plan produced no rule group for the marker alert")
    })?;
    // The alert's `kibana.alert.rule.uuid` — the same server-owned,
    // per-rule-creation uuid `is_sensitive` already redacts under its own
    // dotted key elsewhere, but here it appears under a plain `id` key.
    case_map.insert(
        group.rule_id.clone(),
        CASE_RULE_UUID_PLACEHOLDER.to_string(),
    );
    let attach_request = json!({
        "type": "alert",
        "alertId": group.alert_ids,
        "index": group.indices,
        "rule": {"id": group.rule_id, "name": group.rule_name},
        "owner": elasticctl_api::cases::OWNER,
    });
    let attach_response = t
        .post(
            &elasticctl_api::cases::comments_path(&case_id),
            Some(&attach_request),
        )
        .await?;
    let attached = elasticctl_api::cases::decode_case(&attach_response).map_err(|error| {
        recording_error(format!("decoding case_attach response: {}", error.message))
    })?;
    register_case_extras(&attach_response, &mut case_map, &mut next_comment);
    {
        let mut request = attach_request;
        let mut response = attach_response;
        scrub_alert_timestamps(&mut response);
        strip_volatile(&mut response, CASE_DURATION_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &case_map);
        scrub_placeholder_values(&mut response, &case_map);
        scrub_placeholder_values(&mut request, &probe.id_map);
        scrub_placeholder_values(&mut response, &probe.id_map);
        scrub_placeholder_values(&mut response, &probe.uid_map);
        recording.fixtures.push(exchange_fixture(
            "case_attach",
            flavor,
            version,
            request,
            response,
        ));
    }

    // case_update_status: close with the latest known version.
    let close_version = attached.version.clone();
    let close_request = json!({
        "cases": [{"id": case_id, "version": close_version, "status": "closed"}],
    });
    let close_response = t
        .patch(elasticctl_api::cases::CASES_PATH, &close_request)
        .await?;
    let closed_array = close_response.as_array().ok_or_else(|| {
        recording_error("decoding case_update_status response: expected an array")
    })?;
    let closed_first = closed_array
        .first()
        .ok_or_else(|| recording_error("case_update_status response array is empty"))?;
    let closed = elasticctl_api::cases::decode_case(closed_first).map_err(|error| {
        recording_error(format!(
            "decoding case_update_status response: {}",
            error.message
        ))
    })?;
    if closed.status != "closed" {
        return Err(recording_error(format!(
            "case_update_status did not close the case (status: {})",
            closed.status
        )));
    }
    register_case_extras(closed_first, &mut case_map, &mut next_comment);
    {
        let mut request = close_request;
        let mut response = close_response;
        scrub_alert_timestamps(&mut response);
        strip_volatile(&mut response, CASE_DURATION_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &case_map);
        scrub_placeholder_values(&mut response, &case_map);
        scrub_placeholder_values(&mut response, &probe.uid_map);
        recording.fixtures.push(exchange_fixture(
            "case_update_status",
            flavor,
            version,
            request,
            response,
        ));
    }

    // case_conflict: reuse the now-stale pre-close version, attempting
    // `open`. This measures the optimistic-concurrency contract (triage
    // spec section 10): a stale version must answer 409.
    let conflict_request = json!({
        "cases": [{"id": case_id, "version": close_version, "status": "open"}],
    });
    match t
        .patch(elasticctl_api::cases::CASES_PATH, &conflict_request)
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::Conflict => {
            let mut sanitized = error;
            for (real, placeholder) in &case_map {
                if !real.is_empty() {
                    sanitized.message = sanitized
                        .message
                        .replace(real.as_str(), placeholder.as_str());
                }
            }
            recording
                .fixtures
                .push(error_fixture("case_conflict", flavor, version, sanitized));
        }
        Err(error) => {
            return Err(recording_error(format!(
                "case_conflict: stale-version PATCH failed with an unexpected error \
                 (kind={:?}, status={:?}) instead of 409 — this is a discovery about the \
                 optimistic-concurrency contract, not a transient failure: {}",
                error.kind, error.http_status, error.message
            )));
        }
        Ok(response) => {
            return Err(recording_error(format!(
                "case_conflict: stale-version PATCH SUCCEEDED instead of 409 (response: \
                 {response}) — the API does not enforce optimistic concurrency the way the \
                 spec documents. Update the spec and `apply_status`'s remediation text before \
                 recording further flavors."
            )));
        }
    }

    // case_delete
    let delete_ids = vec![case_id.clone()];
    let delete_url = elasticctl_api::cases::delete_path(&delete_ids)?;
    let delete_response = t.delete(&delete_url).await?;
    {
        let mut request = json!({"ids": delete_ids, "path": delete_url});
        let mut response = delete_response;
        scrub_placeholder_values(&mut request, &case_map);
        scrub_placeholder_values(&mut response, &case_map);
        recording.fixtures.push(exchange_fixture(
            "case_delete",
            flavor,
            version,
            request,
            response,
        ));
    }

    match t.get(&elasticctl_api::cases::case_path(&case_id)).await {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {}
        Ok(_) => return Err(recording_error("case still exists after case_delete")),
        Err(error) => {
            return Err(recording_error(format!(
                "verifying case deleted: {}",
                error.message
            )));
        }
    }
    require_no_marker_cases(t).await?;
    session.ownership.case = false;

    Ok(())
}
