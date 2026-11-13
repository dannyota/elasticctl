use crate::diagnostics::{
    recording_error, safe_recording_error_summary, safe_recording_transport_error,
};
use crate::fixtures::{Recording, exchange_fixture};
use crate::recorder::markers::{
    ALERT_RULE_ID, CLOSE_BY_QUERY_RUNTIME_FIELDS, TRIAGE_ENVELOPE_VOLATILE_FIELDS,
};
use crate::scrub::{scrub_placeholder_values, strip_volatile};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn alert_probe_filter() -> Value {
    json!({"term": {"kibana.alert.rule.rule_id": ALERT_RULE_ID}})
}

pub(super) fn alert_probe_open_filter() -> Value {
    json!({
        "bool": {
            "filter": [alert_probe_filter()],
            "must_not": [{"term": {"kibana.alert.workflow_status": "closed"}}]
        }
    })
}

pub(super) async fn require_no_open_marker_alerts(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    let body = json!({"query": alert_probe_open_filter(), "size": 0, "track_total_hits": true});
    let response = t
        .post(elasticctl_api::alerts::SEARCH_PATH, Some(&body))
        .await?;
    let total = response
        .pointer("/hits/total/value")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if total > 0 {
        return Err(recording_error(format!(
            "refusing to record: {total} non-closed alert(s) already carry rule_id {ALERT_RULE_ID}"
        )));
    }
    Ok(())
}

pub(crate) async fn sweep_close_marker_alerts(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    let _ = t
        .patch(
            "/api/detection_engine/rules",
            &json!({"rule_id": ALERT_RULE_ID, "enabled": false}),
        )
        .await;
    let close_query_request = json!({
        "query": alert_probe_filter(),
        "status": "closed",
        "conflicts": "abort",
        "reason": "automated_closure",
    });
    for _ in 0..5 {
        if require_no_open_marker_alerts(t).await.is_ok() {
            return Ok(());
        }
        t.post(
            elasticctl_api::alerts::STATUS_PATH,
            Some(&close_query_request),
        )
        .await
        .map_err(|error| {
            safe_recording_transport_error("close-by-query sweep retry failed", error)
        })?;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    require_no_open_marker_alerts(t).await.map_err(|error| {
        safe_recording_transport_error("checking close-by-query sweep result failed", error)
    })
}

fn canonicalize_close_by_query_outcome(response: &mut Value) -> elasticctl_core::Result<()> {
    let outcome = elasticctl_api::alerts::decode_outcome(response)
        .map_err(|_| recording_error("close-by-query response failed strict outcome decoding"))?;
    if outcome.updated == 0
        || outcome.total != outcome.updated
        || outcome.version_conflicts != 0
        || outcome.noops != 0
        || !outcome.failures.is_empty()
    {
        return Err(recording_error(
            "close-by-query response did not prove a successful marker cleanup outcome",
        ));
    }
    response["updated"] = json!(1);
    response["total"] = json!(1);
    response["version_conflicts"] = json!(0);
    response["noops"] = json!(0);
    strip_volatile(response, CLOSE_BY_QUERY_RUNTIME_FIELDS);
    Ok(())
}

pub(crate) async fn close_and_clean_alerts(
    t: &elasticctl_core::Transport,
    recording: &mut Recording,
    flavor: &str,
    version: &str,
    id_map: &BTreeMap<String, String>,
) -> elasticctl_core::Result<()> {
    let _ = t
        .patch(
            "/api/detection_engine/rules",
            &json!({"rule_id": ALERT_RULE_ID, "enabled": false}),
        )
        .await;

    let close_query_request = json!({
        "query": alert_probe_filter(),
        "status": "closed",
        "conflicts": "abort",
        "reason": "automated_closure",
    });
    let mut close_query_response = None;
    for attempt in 1..=5 {
        match t
            .post(
                elasticctl_api::alerts::STATUS_PATH,
                Some(&close_query_request),
            )
            .await
        {
            Ok(response) => {
                close_query_response = Some(response);
                break;
            }
            Err(error) if attempt < 5 => {
                println!(
                    "signals/status close-by-query attempt {attempt} failed: {}; retrying",
                    safe_recording_error_summary(&error)
                );
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
            Err(error) => {
                return Err(safe_recording_transport_error(
                    "close-by-query failed",
                    error,
                ));
            }
        }
    }
    let mut close_query_response =
        close_query_response.expect("loop above returns Some or an Err before exiting");
    canonicalize_close_by_query_outcome(&mut close_query_response)?;
    {
        let mut request = close_query_request;
        let mut response = close_query_response;
        strip_volatile(&mut response, TRIAGE_ENVELOPE_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, id_map);
        scrub_placeholder_values(&mut response, id_map);
        recording.fixtures.push(exchange_fixture(
            "signals_status_query",
            flavor,
            version,
            request,
            response,
        ));
    }

    sweep_close_marker_alerts(t).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn close_by_query_fixture_canonicalizes_cumulative_counters_with_a_valid_outcome() {
        let mut response = json!({
            "total": 7,
            "updated": 7,
            "version_conflicts": 0,
            "noops": 0,
            "failures": [],
            "took": 7,
            "_shards": {"total": 3},
            "batches": 2,
            "deleted": 4,
            "requests_per_second": -1.0,
            "retries": {"bulk": 1, "search": 1},
            "throttled_millis": 9,
            "throttled_until_millis": 10
        });

        canonicalize_close_by_query_outcome(&mut response)
            .expect("a decoded successful cumulative outcome");
        let outcome = elasticctl_api::alerts::decode_outcome(&response)
            .expect("the canonical fixture must remain production-decodable");

        assert_eq!(outcome.updated, 1);
        assert_eq!(
            outcome.total,
            outcome.updated + outcome.version_conflicts + outcome.noops
        );
        assert_eq!(outcome.version_conflicts, 0);
        assert_eq!(outcome.noops, 0);
        for field in [
            "took",
            "_shards",
            "batches",
            "deleted",
            "requests_per_second",
            "retries",
            "throttled_millis",
            "throttled_until_millis",
        ] {
            assert!(
                response.get(field).is_none(),
                "{field} is response runtime state"
            );
        }

        let mut conflicted = json!({
            "total": 2,
            "updated": 1,
            "version_conflicts": 1,
            "noops": 0,
            "failures": []
        });
        assert!(
            canonicalize_close_by_query_outcome(&mut conflicted).is_err(),
            "a conflict-free cleanup outcome is required before canonicalization"
        );
    }
}
