//! Preview probes and exchanges.

use crate::diagnostics::recording_error;
use crate::recorder::markers::{MARKER_TAGS, SCRATCH_DOC_ID, SCRATCH_MARKER};
use crate::recorder::ownership::{owns_scratch_index, require_absent_scratch_index};
use crate::recorder::session::RecordingSession;
use elasticctl_core::urlencode;
use serde_json::{Value, json};

/// Scratch index queried by the preview probe. It carries the
/// `elasticctl-sample` marker and avoids the `logs-` prefix: `logs-*-*` matches
/// Elastic's template and would reject a plain document write.
pub(crate) const PREVIEW_PROBE_INDEX: &str = "elasticctl-sample-fixture";

/// Base name for the preview probe. Append a per-run suffix because preview
/// alerts are never deleted; the fallback must not match a stale alert.
const PREVIEW_PROBE_NAME: &str = "elasticctl fixture preview probe";

/// Fixed instead of "now": the probe document falls inside this window, so the
/// recording is reproducible and needs no date arithmetic.
pub(super) const PREVIEW_TIMEFRAME_END: &str = "2026-08-12T18:00:00.000Z";

const PREVIEW_DOC_TIMESTAMP: &str = "2026-08-12T17:57:00.000Z";

/// Scratch index queried by the search probe. Like `PREVIEW_PROBE_INDEX`, it
/// avoids the `logs-` prefix; each document carries the `elasticctl-sample`
/// marker in its `marker` field.
pub(crate) const SEARCH_PROBE_INDEX: &str = "elasticctl-sample-search";

/// Value of the `marker` field every search probe document carries.
pub(crate) const SEARCH_MARKER: &str = "elasticctl-sample";

/// ES|QL response fields that vary per run. They are dropped before writing a
/// fixture so a re-record of the same data is byte-identical (spec §8).
pub(crate) const ESQL_VOLATILE_FIELDS: &[&str] = &[
    "took",
    "start_time_in_millis",
    "completion_time_in_millis",
    "expiration_time_in_millis",
    "cpu_nanos",
    "read_nanos",
    "bytes_read",
    "values_loaded",
    "documents_found",
    "rows_emitted",
    "is_partial",
    "is_running",
];

/// Query DSL response fields that vary per run (spec §8).
pub(crate) const DSL_VOLATILE_FIELDS: &[&str] = &["took", "_shards", "_score", "sort", "pit_id"];

/// Server-owned fields on rules, lists, and items that change on every create:
/// the saved-object `id` and the `created_at`/`updated_at` timestamps. They must
/// not survive a fixture (spec §8). A space or data-view `id` is stable and
/// meaningful, so this strip applies only to rule, list, and item fixtures.
pub(crate) const RULE_VOLATILE_FIELDS: &[&str] =
    &["id", "created_at", "updated_at", "execution_summary"];

/// Per-run fields in a preview and its alert hits: the preview id, execution
/// timestamps and uuids, the generated rule id, and the per-run name/reason
/// suffix. A preview writes fresh alerts each run, so these must not survive a
/// fixture (spec §8); the fixture keeps the alert structure and hit count.
pub(crate) const PREVIEW_VOLATILE_FIELDS: &[&str] = &[
    "previewId",
    "duration",
    "_id",
    "rule_id",
    "kibana.alert.uuid",
    "kibana.alert.rule.rule_id",
    "kibana.alert.rule.execution.uuid",
    "kibana.alert.rule.execution.timestamp",
    "kibana.alert.rule.created_at",
    "kibana.alert.rule.updated_at",
    "kibana.alert.rule.name",
    "kibana.alert.reason",
    "kibana.alert.url",
    "kibana.alert.start",
    "kibana.alert.last_detected",
];

/// Response-only Elasticsearch search fields from preview-hit readback. The
/// request keeps its sort because it proves the production query; this list
/// applies only to the response so re-recording does not preserve runtime or
/// rollover state as fixture evidence.
pub(crate) const PREVIEW_HITS_RESPONSE_VOLATILE_FIELDS: &[&str] =
    &["took", "timed_out", "_shards", "_index", "_score", "sort"];

/// Return a per-run suffix so a re-record cannot match leftover preview alerts.
fn run_token() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().to_string())
        .unwrap_or_else(|_| std::process::id().to_string())
}

/// Request and response that found preview hits. Keep them separate from the
/// fixture write so the caller can clean up first.
pub(super) struct PreviewHitsExchange {
    pub(super) request: Value,
    pub(super) response: Value,
}

pub(super) async fn record_preview_hits(
    session: &mut RecordingSession<'_>,
    space: &str,
) -> elasticctl_core::Result<PreviewHitsExchange> {
    require_absent_scratch_index(session.transport).await?;
    let t = session.transport;
    let doc = json!({
        "@timestamp": PREVIEW_DOC_TIMESTAMP,
        SCRATCH_MARKER: true,
        "event": {"category": ["process"], "type": ["start"], "code": "1"},
        "process": {
            "name": "elasticctl-sample.exe",
            "executable": "C:\\elasticctl-sample\\elasticctl-sample.exe",
            "command_line": "elasticctl-sample.exe --fixture"
        },
        "host": {"name": "elasticctl-sample-host"}
    });
    t.post_absolute_es(
        &format!("/{PREVIEW_PROBE_INDEX}/_doc/{SCRATCH_DOC_ID}?refresh=wait_for"),
        &doc,
    )
    .await?;
    let proof = t
        .get_absolute_es(&format!("/{PREVIEW_PROBE_INDEX}/_doc/{SCRATCH_DOC_ID}"))
        .await?;
    if !owns_scratch_index(&proof) {
        return Err(recording_error(
            "scratch index write did not prove the fixed marker identity",
        ));
    }
    session.ownership.scratch_index = true;

    let probe_name = format!("{PREVIEW_PROBE_NAME} {}", run_token());
    let preview_body = json!({
        "name": probe_name,
        "description": "Recorded by cargo xtask record. Safe to delete.",
        "type": "query",
        "language": "kuery",
        "query": "*:*",
        "index": [PREVIEW_PROBE_INDEX],
        "severity": "low",
        "risk_score": 21,
        "from": "now-6m",
        "interval": "5m",
        "tags": MARKER_TAGS,
        "invocationCount": 1,
        "timeframeEnd": PREVIEW_TIMEFRAME_END
    });
    let preview = t
        .post("/api/detection_engine/rules/preview", Some(&preview_body))
        .await?;
    let preview_id = preview["previewId"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let index = format!(
        ".preview.alerts-security.alerts-{}",
        urlencode(if space.is_empty() { "default" } else { space })
    );
    let by_uuid = json!({
        "size": 3,
        "track_total_hits": true,
        "query": {"term": {"kibana.alert.rule.uuid": preview_id}},
        "sort": [{"@timestamp": {"order": "desc"}}]
    });
    let hits_of = |value: &Value| value["hits"]["total"]["value"].as_u64().unwrap_or(0);

    let mut response = t
        .post_absolute_es(
            &format!("/{index}/_search?ignore_unavailable=true"),
            &by_uuid,
        )
        .await?;
    let mut uuid_attempts = 1;
    if hits_of(&response) == 0 {
        tokio::time::sleep(std::time::Duration::from_millis(1_000)).await;
        response = t
            .post_absolute_es(
                &format!("/{index}/_search?ignore_unavailable=true"),
                &by_uuid,
            )
            .await?;
        uuid_attempts = 2;
    }
    if hits_of(&response) > 0 {
        return Ok(PreviewHitsExchange {
            request: json!({
                "index": index,
                "body": by_uuid,
                "matched_by": "kibana.alert.rule.uuid",
                "attempts_until_hits": uuid_attempts,
            }),
            response,
        });
    }

    let by_name = json!({
        "size": 3,
        "track_total_hits": true,
        "query": {"match_phrase": {"kibana.alert.rule.name": probe_name}}
    });
    let fallback = t
        .post_absolute_es(
            &format!("/{index}/_search?ignore_unavailable=true"),
            &by_name,
        )
        .await?;
    if hits_of(&fallback) > 0 {
        return Ok(PreviewHitsExchange {
            request: json!({
                "index": index,
                "body": by_name,
                "matched_by": "kibana.alert.rule.name",
                "attempts_until_hits": 1,
            }),
            response: fallback,
        });
    }

    Err(recording_error(format!(
        "no preview alerts found in {index}: kibana.alert.rule.uuid \
         ({uuid_attempts} search(es)) and kibana.alert.rule.name (1 search) \
         both returned zero hits"
    )))
}
