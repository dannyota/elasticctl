//! Recording helpers.

pub(crate) mod defaults;
pub(crate) mod fixtures;

use crate::diagnostics::{record_trace, recording_error};
use crate::fixtures::{Recording, error_fixture};
use crate::recorder::data_views::defaults::{
    capture_data_view_default_snapshot, create_source_with_pending_default_lease,
    data_view_spec_from_response, raw_scripted_field_present, record_empty_data_view_self_preview,
    recorder_get_data_view_default, recorder_post_data_view_default, require_acknowledged,
    require_data_view_fields_success, require_empty_or_acknowledged_delete_success,
    require_pending_data_view_default_state, require_persisted_data_view_metadata,
    restore_pending_data_view_default,
};
use crate::recorder::data_views::fixtures::{
    data_view_exchange_fixture, data_view_fixture, owns_data_view_index, require_absent_data_view,
    require_absent_data_view_index, verify_data_view_index_deleted,
};
use crate::recorder::markers::{
    DATA_VIEW_DOC_ID, DATA_VIEW_INDEX, DATA_VIEW_METADATA_DESCRIPTION, DATA_VIEW_REPLACEMENT_ID,
    DATA_VIEW_SOURCE_ID,
};
use crate::recorder::session::{PendingDefaultRestorePhase, RecordingSession};
use serde_json::{Value, json};

/// Record the full marker-scoped data-view lifecycle. Responses remain in
/// memory until the source, replacement, backing index, and original default
/// have all been restored or deleted.
pub(super) async fn record_data_views(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    flavor: &str,
    version: &str,
) -> elasticctl_core::Result<()> {
    let t = session.transport;
    record_trace("data-views-preflight-source");
    require_absent_data_view(t, DATA_VIEW_SOURCE_ID).await?;
    record_trace("data-views-preflight-replacement");
    require_absent_data_view(t, DATA_VIEW_REPLACEMENT_ID).await?;
    record_trace("data-views-preflight-index");
    require_absent_data_view_index(t).await?;

    // The direct get is deliberately recorded as a classified 404, proving
    // the stable route before this run creates its marker source.
    record_trace("data-views-source-not-found");
    match t
        .get(&format!("/api/data_views/data_view/{DATA_VIEW_SOURCE_ID}"))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => recording
            .fixtures
            .push(error_fixture("data_view_not_found", flavor, version, error)),
        Ok(_) => return Err(recording_error("marker data view appeared before create")),
        Err(error) => return Err(error),
    }

    session.ownership.data_view_index = true;
    record_trace("data-views-index-create");
    t.post_absolute_es(
        &format!("/{DATA_VIEW_INDEX}/_doc/{DATA_VIEW_DOC_ID}?refresh=wait_for"),
        &json!({"marker": "elasticctl-sample", "probe": "data-view"}),
    )
    .await?;
    record_trace("data-views-index-check");
    let index_proof = t
        .get_absolute_es(&format!("/{DATA_VIEW_INDEX}/_doc/{DATA_VIEW_DOC_ID}"))
        .await?;
    record_trace("data-views-index-proof-check");
    if !owns_data_view_index(&index_proof) {
        return Err(recording_error(
            "data-view index write did not prove the fixed marker identity",
        ));
    }

    // Validate and resolve the read-only baseline only after the source
    // direct-404 and backing-index setup. A second exact raw GET immediately
    // before create becomes the pending cleanup lease and fixture evidence.
    record_trace("data-views-default-snapshot");
    let (baseline_raw, original_default) = capture_data_view_default_snapshot(t).await?;

    let source = json!({
        "id": DATA_VIEW_SOURCE_ID,
        "title": "elasticctl-sample-data-view-*",
        "name": "elasticctl sample source view",
        "timeFieldName": "@timestamp",
        "allowNoIndex": true,
        "allowHidden": true,
        "sourceFilters": [{"value": "elasticctl.private.*"}],
        "fieldFormats": {"bytes": {"id": "bytes"}},
        "runtimeFieldMap": {
            "elasticctl.runtime": {"type": "keyword", "script": {"source": "emit('elasticctl-sample');"}}
        },
        "fieldAttrs": {"host.name": {"customLabel": "elasticctl sample host"}},
        "fields": {
            "elasticctl.legacy": {"name": "elasticctl.legacy", "scripted": true, "type": "number", "script": "return 1;"}
        }
    });
    let create_body = json!({"data_view": source, "override": false});
    let created = create_source_with_pending_default_lease(
        session,
        recording,
        flavor,
        version,
        &baseline_raw,
        &original_default,
        &create_body,
    )
    .await?;
    record_trace("data-views-source-get");
    let got = t
        .get(&format!("/api/data_views/data_view/{DATA_VIEW_SOURCE_ID}"))
        .await?;
    record_trace("data-views-scripted-check");
    let create_scripted = raw_scripted_field_present(&created);
    let get_scripted = raw_scripted_field_present(&got);
    if create_scripted != get_scripted {
        return Err(recording_error(
            "data-view raw scripted create and get observations disagree",
        ));
    }
    record_trace("data-views-create-check");
    if created["data_view"]["id"].as_str() != Some(DATA_VIEW_SOURCE_ID)
        || got["data_view"]["allowHidden"].as_bool() != Some(true)
    {
        return Err(recording_error(
            "data-view create did not preserve the marker id and allowHidden: true",
        ));
    }
    recording.fixtures.push(data_view_exchange_fixture(
        "data_view_create",
        flavor,
        version,
        create_body,
        created,
    ));

    record_trace("data-views-list");
    let mut listed = t.get("/api/data_views").await?;
    let views = listed
        .get_mut("data_view")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| recording_error("data-view list response must carry data_view array"))?;
    views.retain(|view| view["id"].as_str() == Some(DATA_VIEW_SOURCE_ID));
    record_trace("data-views-list-check");
    if views.len() != 1 {
        return Err(recording_error(
            "scoped data-view list did not contain exactly the marker source",
        ));
    }
    recording.fixtures.push(data_view_fixture(
        "data_views_list",
        flavor,
        version,
        listed,
    ));

    recording
        .fixtures
        .push(data_view_fixture("data_view_get", flavor, version, got));

    let update_body = json!({
        "data_view": {
            "title": "elasticctl-sample-data-view-updated-*",
            "name": "elasticctl sample updated view",
            "sourceFilters": [{"value": "elasticctl.private.updated.*"}]
        },
        "refresh_fields": true
    });
    record_trace("data-views-update");
    let updated = t
        .post(
            &format!("/api/data_views/data_view/{DATA_VIEW_SOURCE_ID}"),
            Some(&update_body),
        )
        .await?;
    record_trace("data-views-update-check");
    if updated["data_view"]["allowHidden"].as_bool() != Some(true)
        || updated["data_view"]["title"].as_str() != Some("elasticctl-sample-data-view-updated-*")
    {
        return Err(recording_error(
            "data-view update did not preserve allowHidden or its documented base update",
        ));
    }
    recording.fixtures.push(data_view_exchange_fixture(
        "data_view_update",
        flavor,
        version,
        update_body,
        updated,
    ));

    let metadata_body = json!({
        "fields": {
            "host.name": {"count": 2, "customLabel": null},
            "elasticctl.metadata": {
                "count": 1,
                "customDescription": DATA_VIEW_METADATA_DESCRIPTION
            }
        }
    });
    record_trace("data-views-fields");
    let metadata = t
        .post(
            &format!("/api/data_views/data_view/{DATA_VIEW_SOURCE_ID}/fields"),
            Some(&metadata_body),
        )
        .await?;
    record_trace("data-views-fields-check");
    if let Some(metadata_envelope) =
        require_data_view_fields_success(&metadata, DATA_VIEW_SOURCE_ID)?
    {
        require_persisted_data_view_metadata(metadata_envelope)?;
    }
    recording.fixtures.push(data_view_exchange_fixture(
        "data_view_fields",
        flavor,
        version,
        metadata_body,
        metadata,
    ));
    record_trace("data-views-fields-get");
    let metadata_get = t
        .get(&format!("/api/data_views/data_view/{DATA_VIEW_SOURCE_ID}"))
        .await?;
    record_trace("data-views-fields-get-check");
    require_persisted_data_view_metadata(&metadata_get)?;
    recording.fixtures.push(data_view_fixture(
        "data_view_fields_get",
        flavor,
        version,
        metadata_get,
    ));

    let hidden_update = json!({"data_view": {"allowHidden": false}, "refresh_fields": true});
    record_trace("data-views-hidden-update");
    match t
        .post(
            &format!("/api/data_views/data_view/{DATA_VIEW_SOURCE_ID}"),
            Some(&hidden_update),
        )
        .await
    {
        Err(error) if error.http_status == Some(400) => recording.fixtures.push(error_fixture(
            "data_view_allow_hidden_rejected",
            flavor,
            version,
            error,
        )),
        Ok(response) => {
            return Err(recording_error(format!(
                "data-view update unexpectedly accepted allowHidden: {response}"
            )));
        }
        Err(error) => return Err(error),
    }
    record_trace("data-views-hidden-get");
    let after_rejection = t
        .get(&format!("/api/data_views/data_view/{DATA_VIEW_SOURCE_ID}"))
        .await?;
    record_trace("data-views-hidden-check");
    if after_rejection["data_view"]["allowHidden"].as_bool() != Some(true) {
        return Err(recording_error(
            "rejected allowHidden update changed the stored data view",
        ));
    }

    record_trace("data-views-default-before");
    let default_before =
        recorder_get_data_view_default(t, "reading data-view default before mutation failed")
            .await?;
    record_trace("data-views-default-before-check");
    let lease = session
        .ownership
        .pending_data_view_default_restore
        .as_ref()
        .ok_or_else(|| recording_error("missing pending data-view default restore lease"))?;
    require_pending_data_view_default_state(lease, &default_before)?;
    let default_set = json!({"data_view_id": DATA_VIEW_SOURCE_ID, "force": true});
    record_trace("data-views-default-claim");
    session
        .ownership
        .pending_data_view_default_restore
        .as_mut()
        .ok_or_else(|| recording_error("missing pending data-view default restore lease"))?
        .phase = PendingDefaultRestorePhase::ExplicitDefaultMutationMayHaveChanged;
    record_trace("data-views-default-set");
    let default_set_response =
        recorder_post_data_view_default(t, &default_set, "setting marker data-view default failed")
            .await?;
    record_trace("data-views-default-set-check");
    require_acknowledged(&default_set_response, "data-view default set")?;
    recording.fixtures.push(data_view_exchange_fixture(
        "data_view_default_set",
        flavor,
        version,
        default_set,
        default_set_response,
    ));
    let default_unset = json!({"data_view_id": null, "force": true});
    record_trace("data-views-default-unset");
    let default_unset_response = recorder_post_data_view_default(
        t,
        &default_unset,
        "unsetting marker data-view default failed",
    )
    .await?;
    record_trace("data-views-default-unset-check");
    require_acknowledged(&default_unset_response, "data-view default unset")?;
    recording.fixtures.push(data_view_exchange_fixture(
        "data_view_default_unset",
        flavor,
        version,
        default_unset,
        default_unset_response,
    ));
    let default_before_swap = json!({"data_view_id": DATA_VIEW_SOURCE_ID, "force": true});
    record_trace("data-views-default-before-swap");
    let default_before_swap_response = recorder_post_data_view_default(
        t,
        &default_before_swap,
        "setting marker data-view default before swap failed",
    )
    .await?;
    record_trace("data-views-default-before-swap-check");
    require_acknowledged(
        &default_before_swap_response,
        "data-view default set before swap",
    )?;
    recording.fixtures.push(data_view_exchange_fixture(
        "data_view_default_set_before_swap",
        flavor,
        version,
        default_before_swap,
        default_before_swap_response,
    ));

    record_trace("data-views-preview");
    let (preview_request, preview) = record_empty_data_view_self_preview(t).await?;
    recording.fixtures.push(data_view_exchange_fixture(
        "data_view_swap_preview",
        flavor,
        version,
        preview_request,
        preview,
    ));

    record_trace("data-views-replacement-build");
    let replacement: elasticctl_api::data_views::DataViewSpec = serde_json::from_value(json!({
        "id": DATA_VIEW_REPLACEMENT_ID,
        "title": "elasticctl-sample-data-view-replacement-*",
        "name": "elasticctl sample replacement view",
        "allowNoIndex": true
    }))
    .map_err(|error| recording_error(format!("building replacement data view: {error}")))?;
    let replacement_request = json!({"data_view": replacement, "override": false});
    session.ownership.data_view_replacement = true;
    record_trace("data-views-replacement-create");
    let replacement_created = t
        .post("/api/data_views/data_view", Some(&replacement_request))
        .await?;
    record_trace("data-views-replacement-check");
    if data_view_spec_from_response(&replacement_created, "replacement create")?.id
        != DATA_VIEW_REPLACEMENT_ID
    {
        return Err(recording_error(
            "replacement create did not preserve its marker id",
        ));
    }
    recording.fixtures.push(data_view_exchange_fixture(
        "data_view_replacement_create",
        flavor,
        version,
        replacement_request,
        replacement_created,
    ));

    let swap_request = json!({
        "delete": true,
        "fromId": DATA_VIEW_SOURCE_ID,
        "toId": DATA_VIEW_REPLACEMENT_ID
    });
    record_trace("data-views-swap");
    let swapped = t
        .post("/api/data_views/swap_references", Some(&swap_request))
        .await?;
    record_trace("data-views-swap-check");
    if swapped["result"] != Value::Array(Vec::new())
        || swapped["deleteStatus"]["deletePerformed"].as_bool() != Some(true)
        || swapped["deleteStatus"]["remainingRefs"].as_u64() != Some(0)
    {
        return Err(recording_error(
            "data-view swap did not report deleted source with zero remaining references",
        ));
    }
    recording.fixtures.push(data_view_exchange_fixture(
        "data_view_swap",
        flavor,
        version,
        swap_request,
        swapped,
    ));
    record_trace("data-views-source-after-swap");
    match t
        .get(&format!("/api/data_views/data_view/{DATA_VIEW_SOURCE_ID}"))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
            recording.fixtures.push(error_fixture(
                "data_view_swap_source_not_found",
                flavor,
                version,
                error,
            ));
            session.ownership.data_view_source = false;
        }
        Ok(_) => return Err(recording_error("source data view still exists after swap")),
        Err(error) => return Err(error),
    }

    record_trace("data-views-default-after-swap");
    let default_after_swap =
        recorder_get_data_view_default(t, "reading data-view default after swap failed").await?;
    record_trace("data-views-default-after-swap-check");
    if default_after_swap["data_view_id"].as_str() != Some(DATA_VIEW_SOURCE_ID) {
        return Err(recording_error(
            "data-view swap changed the default instead of retaining the deleted source id",
        ));
    }
    recording.fixtures.push(data_view_fixture(
        "data_view_default_after_swap",
        flavor,
        version,
        default_after_swap,
    ));

    record_trace("data-views-default-restore");
    let (restore_request, restored, restored_get) =
        restore_pending_data_view_default(session).await?;
    record_trace("data-views-default-restore-check");
    record_trace("data-views-default-restored-get");
    record_trace("data-views-default-restored-check");
    recording.fixtures.push(data_view_exchange_fixture(
        "data_view_default_restore",
        flavor,
        version,
        restore_request,
        restored,
    ));
    recording.fixtures.push(data_view_fixture(
        "data_view_default_restored_get",
        flavor,
        version,
        restored_get,
    ));

    record_trace("data-views-replacement-delete");
    let deleted = t
        .delete(&format!(
            "/api/data_views/data_view/{DATA_VIEW_REPLACEMENT_ID}"
        ))
        .await?;
    record_trace("data-views-replacement-delete-check");
    require_empty_or_acknowledged_delete_success(&deleted)?;
    recording.fixtures.push(data_view_fixture(
        "data_view_delete",
        flavor,
        version,
        deleted,
    ));
    record_trace("data-views-replacement-gone-check");
    match t
        .get(&format!(
            "/api/data_views/data_view/{DATA_VIEW_REPLACEMENT_ID}"
        ))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
            recording.fixtures.push(error_fixture(
                "data_view_delete_not_found",
                flavor,
                version,
                error,
            ));
            session.ownership.data_view_replacement = false;
        }
        Ok(_) => {
            return Err(recording_error(
                "data view still exists after direct delete",
            ));
        }
        Err(error) => return Err(error),
    }

    record_trace("data-views-index-delete");
    t.delete_absolute_es(&format!("/{DATA_VIEW_INDEX}")).await?;
    record_trace("data-views-index-delete-check");
    verify_data_view_index_deleted(t).await?;
    session.ownership.data_view_index = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::Recording;

    use crate::recorder::markers::{
        DATA_VIEW_DOC_ID, DATA_VIEW_INDEX, DATA_VIEW_REPLACEMENT_ID, DATA_VIEW_SOURCE_ID,
    };
    use crate::recorder::session::{CleanupOwnership, RecordingSession};
    use crate::recorder::test_support::mock_transport;
    use serde_json::json;
    use std::path::PathBuf;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn data_view_recording_default_error_does_not_leak_the_server_envelope() {
        let server = MockServer::start().await;
        for id in [DATA_VIEW_SOURCE_ID, DATA_VIEW_REPLACEMENT_ID] {
            Mock::given(method("GET"))
                .and(path(format!("/api/data_views/data_view/{id}")))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(format!("/{DATA_VIEW_INDEX}")))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/{DATA_VIEW_INDEX}/_doc/{DATA_VIEW_DOC_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": "created"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/{DATA_VIEW_INDEX}/_doc/{DATA_VIEW_DOC_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "_source": {"marker": "elasticctl-sample", "probe": "data-view"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/default"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "message": "private-main-default-id",
                "opaque": {"raw": "private-main-envelope"}
            })))
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let mut recording = Recording {
            dir: PathBuf::new(),
            fixtures: Vec::new(),
        };

        let error = record_data_views(&mut session, &mut recording, "test", "test")
            .await
            .expect_err("initial default error must stop recording");

        assert_eq!(error.kind, elasticctl_core::ErrorKind::Http);
        assert_eq!(error.http_status, Some(500));
        assert!(
            !error.message.contains("private-main-default-id")
                && !error.message.contains("private-main-envelope")
                && !error.message.contains("opaque"),
            "recording error leaked default server evidence: {}",
            error.message
        );
        assert!(
            session
                .ownership
                .pending_data_view_default_restore
                .is_none()
        );
    }
}
