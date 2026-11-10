//! Search helpers.

use crate::diagnostics::recording_error;
use crate::fixtures::{Recording, exchange_fixture, response_fixture};
use crate::recorder::esql_async::{POLL_INTERVAL, record_esql_async};
use crate::recorder::ownership::{owns_search_index, require_absent_search_index};
use crate::recorder::preview::{
    DSL_VOLATILE_FIELDS, ESQL_VOLATILE_FIELDS, SEARCH_MARKER, SEARCH_PROBE_INDEX,
};
use crate::recorder::session::RecordingSession;
use crate::scrub::{redact_data_views, strip_pit_token, strip_volatile};
use serde_json::json;

/// Record the search probe: a marker-scoped scratch index seeded with three
/// documents, the sync and async ES|QL and Query DSL exchanges over them, then
/// the Kibana data-view and default-index lookups. The index is deleted by `cleanup`.
pub(super) async fn record_search(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    flavor: &str,
    version: &str,
) -> elasticctl_core::Result<()> {
    require_absent_search_index(session.transport).await?;
    let t = session.transport;

    for (id, seq) in [("1", 1_i64), ("2", 2), ("3", 3)] {
        let doc = json!({
            "seq": seq,
            "message": format!("elasticctl sample search document {seq}"),
            "marker": SEARCH_MARKER,
        });
        t.post_absolute_es(&format!("/{SEARCH_PROBE_INDEX}/_doc/{id}"), &doc)
            .await?;
    }
    let proof = t
        .get_absolute_es(&format!("/{SEARCH_PROBE_INDEX}/_doc/1"))
        .await?;
    if !owns_search_index(&proof) {
        return Err(recording_error(
            "search index write did not prove the fixed marker identity",
        ));
    }
    session.ownership.search_index = true;
    // `_refresh` rejects a body, so use the GET form, which sends none.
    t.get_absolute_es(&format!("/{SEARCH_PROBE_INDEX}/_refresh"))
        .await?;

    let esql_query = format!("FROM {SEARCH_PROBE_INDEX} | SORT seq ASC | LIMIT 2");
    let mut esql_response = t
        .post_absolute_es("/_query", &json!({"query": esql_query}))
        .await?;
    strip_volatile(&mut esql_response, ESQL_VOLATILE_FIELDS);
    recording.fixtures.push(response_fixture(
        "esql_query",
        flavor,
        version,
        esql_response,
        None,
    ));
    recording
        .fixtures
        .extend(record_esql_async(t, &esql_query, flavor, version, POLL_INTERVAL).await?);

    let mut pit_open = t
        .post_absolute_es(
            &format!("/{SEARCH_PROBE_INDEX}/_pit?keep_alive=1m"),
            &json!({}),
        )
        .await?;
    let pit_id = pit_open["id"]
        .as_str()
        .ok_or_else(|| recording_error("pit open response is missing id"))?
        .to_string();
    strip_volatile(&mut pit_open, DSL_VOLATILE_FIELDS);
    strip_pit_token(&mut pit_open);
    recording.fixtures.push(exchange_fixture(
        "search_pit_open",
        flavor,
        version,
        json!({"index": SEARCH_PROBE_INDEX, "keep_alive": "1m"}),
        pit_open,
    ));

    let mut pit_page_request = json!({
        "size": 2,
        "sort": [{"seq": "asc"}, {"_shard_doc": "asc"}],
        "pit": {"id": pit_id, "keep_alive": "1m"},
        "query": {"match_all": {}}
    });
    let mut pit_page = t.post_absolute_es("/_search", &pit_page_request).await?;
    strip_volatile(&mut pit_page, DSL_VOLATILE_FIELDS);
    strip_pit_token(&mut pit_page_request);
    recording.fixtures.push(exchange_fixture(
        "search_pit_page",
        flavor,
        version,
        pit_page_request,
        pit_page,
    ));

    let pit_close = t
        .delete_absolute_es_json("/_pit", &json!({"id": pit_id}))
        .await?;
    recording.fixtures.push(response_fixture(
        "search_pit_close",
        flavor,
        version,
        pit_close,
        None,
    ));

    let mut data_views = t.get("/api/data_views").await?;
    redact_data_views(&mut data_views);
    recording.fixtures.push(response_fixture(
        "data_views",
        flavor,
        version,
        data_views,
        None,
    ));
    recording.fixtures.push(response_fixture(
        "detection_engine_index",
        flavor,
        version,
        t.get("/api/detection_engine/index").await?,
        None,
    ));

    Ok(())
}
