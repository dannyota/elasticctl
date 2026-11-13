use crate::diagnostics::recording_error;
use crate::recorder::markers::{MARKER_TAGS, SCRATCH_DOC_ID, SCRATCH_MARKER};
use crate::recorder::ownership::{owns_scratch_index, require_absent_scratch_index};
use crate::recorder::session::RecordingSession;
use elasticctl_core::urlencode;
use serde_json::{Value, json};

pub(crate) const PREVIEW_PROBE_INDEX: &str = "elasticctl-sample-fixture";

const PREVIEW_PROBE_NAME: &str = "elasticctl fixture preview probe";

pub(super) const PREVIEW_TIMEFRAME_END: &str = "2026-08-12T18:00:00.000Z";

const PREVIEW_DOC_TIMESTAMP: &str = "2026-08-12T17:57:00.000Z";

pub(crate) const SEARCH_PROBE_INDEX: &str = "elasticctl-sample-search";

pub(crate) const SEARCH_MARKER: &str = "elasticctl-sample";

pub(crate) const ESQL_VOLATILE_FIELDS: &[&str] = &[
    "took",
    "start_time_in_millis",
    "completion_time_in_millis",
    "expiration_time_in_millis",
    "cpu_nanos",
    "read_nanos",
    "read_cpu_nanos",
    "driver_nanos",
    "bytes_read",
    "values_loaded",
    "documents_found",
    "rows_emitted",
    "is_partial",
    "is_running",
];

pub(crate) const ESQL_ASYNC_VOLATILE_FIELDS: &[&str] = &[
    "took",
    "start_time_in_millis",
    "completion_time_in_millis",
    "expiration_time_in_millis",
    "cpu_nanos",
    "read_nanos",
    "read_cpu_nanos",
    "driver_nanos",
    "bytes_read",
    "values_loaded",
    "documents_found",
    "rows_emitted",
];

pub(crate) const DSL_VOLATILE_FIELDS: &[&str] = &["took", "_shards", "_score", "sort", "pit_id"];

pub(crate) const RULE_VOLATILE_FIELDS: &[&str] =
    &["id", "created_at", "updated_at", "execution_summary"];

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

pub(crate) const PREVIEW_HITS_RESPONSE_VOLATILE_FIELDS: &[&str] =
    &["took", "timed_out", "_shards", "_index", "_score", "sort"];

fn run_token() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().to_string())
        .unwrap_or_else(|_| std::process::id().to_string())
}

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
