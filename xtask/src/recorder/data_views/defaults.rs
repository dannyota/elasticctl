//! Defaults helpers.

use crate::diagnostics::{record_trace, recording_error, safe_recording_transport_error};
use crate::fixtures::Recording;
use crate::recorder::data_views::fixtures::data_view_fixture;
use crate::recorder::markers::{
    DATA_VIEW_METADATA_DESCRIPTION, DATA_VIEW_REPLACEMENT_ID, DATA_VIEW_SOURCE_ID,
};
use crate::recorder::session::{
    PendingDefaultRestore, PendingDefaultRestorePhase, RecordingSession,
};
use serde_json::{Value, json};

pub(crate) async fn recorder_get_data_view_default(
    t: &elasticctl_core::Transport,
    context: &'static str,
) -> elasticctl_core::Result<Value> {
    t.get("/api/data_views/default")
        .await
        .map_err(|error| safe_recording_transport_error(context, error))
}

pub(crate) async fn recorder_post_data_view_default(
    t: &elasticctl_core::Transport,
    body: &Value,
    context: &'static str,
) -> elasticctl_core::Result<Value> {
    t.post("/api/data_views/default", Some(body))
        .await
        .map_err(|error| safe_recording_transport_error(context, error))
}

pub(crate) fn data_view_spec_from_response(
    body: &Value,
    context: &str,
) -> elasticctl_core::Result<elasticctl_api::data_views::DataViewSpec> {
    elasticctl_api::data_views_ops::normalize(&body["data_view"])
        .map_err(|error| recording_error(format!("{context}: {}", error.message)))
}

pub(crate) fn require_acknowledged(body: &Value, context: &str) -> elasticctl_core::Result<()> {
    if matches!(
        body,
        Value::Object(values)
            if values.len() == 1 && values.get("acknowledged") == Some(&Value::Bool(true))
    ) {
        Ok(())
    } else {
        Err(recording_error(format!(
            "{context}: response must carry acknowledged: true"
        )))
    }
}

/// Decode the raw default response the recorder puts in a public fixture.
/// Production canonicalizes the same two no-default values; this separate
/// strict decoder preserves their raw shape for fixture evidence.
pub(crate) fn decode_raw_data_view_default(
    body: &Value,
) -> elasticctl_core::Result<Option<String>> {
    let Value::Object(values) = body else {
        return Err(recording_error(
            "data-view default GET: expected a one-key object envelope",
        ));
    };
    if values.len() != 1 {
        return Err(recording_error(
            "data-view default GET: expected exactly data_view_id",
        ));
    }
    match values.get("data_view_id") {
        Some(Value::Null) => Ok(None),
        Some(Value::String(id)) if id.is_empty() => Ok(None),
        Some(Value::String(id)) => Ok(Some(id.clone())),
        _ => Err(recording_error(
            "data-view default GET: data_view_id must be string or null",
        )),
    }
}

pub(crate) fn require_restored_raw_data_view_default(
    expected_raw: &Value,
    restored_raw: &Value,
    expected_canonical: &Option<String>,
) -> elasticctl_core::Result<()> {
    if restored_raw == expected_raw
        && decode_raw_data_view_default(restored_raw)? == *expected_canonical
    {
        Ok(())
    } else {
        Err(recording_error(
            "data-view default did not restore to its exact raw snapshot",
        ))
    }
}

pub(crate) fn data_view_default_restore_request(id: Option<&str>) -> Value {
    json!({"data_view_id": id, "force": true})
}

pub(crate) async fn capture_data_view_default_snapshot(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<(Value, Option<String>)> {
    let raw = recorder_get_data_view_default(t, "reading initial data-view default failed").await?;
    let original_default = decode_raw_data_view_default(&raw)?;
    if matches!(
        original_default.as_deref(),
        Some(DATA_VIEW_SOURCE_ID | DATA_VIEW_REPLACEMENT_ID)
    ) {
        return Err(recording_error(
            "refusing to record: marker data view is the current default",
        ));
    }
    if original_default
        .as_deref()
        .is_some_and(|id| id.trim().is_empty())
    {
        return Err(recording_error(
            "refusing to record: default data view id is whitespace-only",
        ));
    }
    if let Some(id) = original_default.as_deref() {
        elasticctl_api::data_views::get(t, id)
            .await
            .map_err(|error| {
                safe_recording_transport_error("resolving initial data-view default failed", error)
            })?;
    }
    Ok((raw, original_default))
}

pub(crate) fn require_data_view_fields_success<'a>(
    body: &'a Value,
    requested_id: &str,
) -> elasticctl_core::Result<Option<&'a Value>> {
    let Value::Object(values) = body else {
        return Err(recording_error(
            "data-view field metadata update: expected acknowledged or data_view envelope",
        ));
    };
    if values.len() != 1 {
        return Err(recording_error(
            "data-view field metadata update: expected exactly one success envelope key",
        ));
    }
    if values.get("acknowledged") == Some(&Value::Bool(true)) {
        return Ok(None);
    }
    let Some(Value::Object(data_view)) = values.get("data_view") else {
        return Err(recording_error(
            "data-view field metadata update: expected acknowledged: true or data_view object",
        ));
    };
    match data_view.get("id") {
        Some(Value::String(id)) if !id.is_empty() && id == requested_id => Ok(Some(body)),
        _ => Err(recording_error(
            "data-view field metadata update: data_view id must be a non-empty request-matching string",
        )),
    }
}

pub(crate) fn require_persisted_data_view_metadata(body: &Value) -> elasticctl_core::Result<()> {
    let field_attrs = body
        .pointer("/data_view/fieldAttrs")
        .and_then(Value::as_object)
        .ok_or_else(|| recording_error("data-view metadata GET did not return fieldAttrs"))?;
    let host = field_attrs
        .get("host.name")
        .and_then(Value::as_object)
        .ok_or_else(|| recording_error("data-view metadata GET did not retain host.name"))?;
    let metadata = field_attrs
        .get("elasticctl.metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            recording_error("data-view metadata GET did not retain elasticctl.metadata")
        })?;
    if host.get("count").and_then(Value::as_u64) != Some(2)
        || host.contains_key("customLabel")
        || metadata.get("count").and_then(Value::as_u64) != Some(1)
        || metadata.get("customDescription").and_then(Value::as_str)
            != Some(DATA_VIEW_METADATA_DESCRIPTION)
    {
        return Err(recording_error(
            "data-view metadata GET did not preserve the documented marker values",
        ));
    }
    Ok(())
}

pub(crate) fn raw_scripted_field_present(body: &Value) -> bool {
    body.pointer("/data_view/fields/elasticctl.legacy/scripted")
        .and_then(Value::as_bool)
        == Some(true)
}

pub(crate) fn require_empty_or_acknowledged_delete_success(
    body: &Value,
) -> elasticctl_core::Result<()> {
    match body {
        Value::Null => Ok(()),
        Value::Object(values)
            if values.len() == 1 && values["acknowledged"] == Value::Bool(true) =>
        {
            Ok(())
        }
        _ => Err(recording_error(
            "data-view direct delete: expected empty response body or acknowledged: true",
        )),
    }
}

pub(crate) fn require_pending_data_view_default_state(
    lease: &PendingDefaultRestore,
    current_raw: &Value,
) -> elasticctl_core::Result<()> {
    let current = decode_raw_data_view_default(current_raw)?;
    let source = current.as_deref() == Some(DATA_VIEW_SOURCE_ID);
    let no_default = current.is_none();
    let allowed = current_raw == &lease.raw
        || match lease.phase {
            PendingDefaultRestorePhase::CreateMayImplicitlySetSource => {
                lease.canonical.is_none() && source
            }
            PendingDefaultRestorePhase::ExplicitDefaultMutationMayHaveChanged => {
                source || no_default
            }
        };
    if allowed {
        Ok(())
    } else {
        Err(recording_error(
            "data-view default is outside the pending restore lease",
        ))
    }
}

pub(crate) fn require_pending_data_view_default_restore_state(
    lease: &PendingDefaultRestore,
    current_raw: &Value,
) -> elasticctl_core::Result<()> {
    // Source create that displaced a preexisting default is a main-flow
    // failure, but cleanup owns that source and must still be able to restore
    // the preexisting default without widening normal-flow acceptance.
    if lease.phase == PendingDefaultRestorePhase::CreateMayImplicitlySetSource
        && decode_raw_data_view_default(current_raw)?.as_deref() == Some(DATA_VIEW_SOURCE_ID)
    {
        return Ok(());
    }
    require_pending_data_view_default_state(lease, current_raw)
}

pub(crate) async fn restore_pending_data_view_default(
    session: &mut RecordingSession<'_>,
) -> elasticctl_core::Result<(Value, Value, Value)> {
    let lease = session
        .ownership
        .pending_data_view_default_restore
        .clone()
        .ok_or_else(|| recording_error("missing pending data-view default restore lease"))?;
    let current = recorder_get_data_view_default(
        session.transport,
        "checking pending data-view default before restore failed",
    )
    .await?;
    require_pending_data_view_default_restore_state(&lease, &current)?;

    let request = data_view_default_restore_request(lease.canonical.as_deref());
    let response = recorder_post_data_view_default(
        session.transport,
        &request,
        "restoring original data-view default failed",
    )
    .await?;
    require_acknowledged(&response, "data-view default restore")?;
    let restored = recorder_get_data_view_default(
        session.transport,
        "checking restored data-view default failed",
    )
    .await?;
    require_restored_raw_data_view_default(&lease.raw, &restored, &lease.canonical)?;
    session.ownership.pending_data_view_default_restore = None;
    Ok((request, response, restored))
}

pub(crate) async fn record_empty_data_view_self_preview(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<(Value, Value)> {
    let request = json!({"fromId": DATA_VIEW_SOURCE_ID, "toId": DATA_VIEW_SOURCE_ID});
    record_trace("data-views-preview-request");
    let response = t
        .post("/api/data_views/swap_references/_preview", Some(&request))
        .await?;
    record_trace("data-views-preview-check");
    let references = serde_json::from_value::<Vec<elasticctl_api::data_views::DataViewReference>>(
        response["result"].clone(),
    )
    .map_err(|error| recording_error(format!("data-view self-swap preview: {error}")))?;
    if !references.is_empty() {
        return Err(recording_error(
            "data-view self-swap preview returned unexpected references",
        ));
    }
    Ok((request, response))
}

/// Claim the validated raw default immediately before creating the fixed
/// source. Source create may implicitly set that source as default, so this
/// pending lease and source ownership must exist before the POST can start.
pub(crate) async fn create_source_with_pending_default_lease(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    flavor: &str,
    version: &str,
    baseline_raw: &Value,
    original_default: &Option<String>,
    create_body: &Value,
) -> elasticctl_core::Result<Value> {
    let t = session.transport;
    record_trace("data-views-default-before-create");
    let raw_before_create = recorder_get_data_view_default(
        t,
        "rereading data-view default before source create failed",
    )
    .await?;
    record_trace("data-views-default-before-create-check");
    if raw_before_create != *baseline_raw
        || decode_raw_data_view_default(&raw_before_create)? != *original_default
    {
        return Err(recording_error(
            "data-view default changed since read-only preflight",
        ));
    }
    session.ownership.pending_data_view_default_restore = Some(PendingDefaultRestore {
        raw: raw_before_create.clone(),
        canonical: original_default.clone(),
        phase: PendingDefaultRestorePhase::CreateMayImplicitlySetSource,
    });
    recording.fixtures.push(data_view_fixture(
        "data_view_default_get",
        flavor,
        version,
        raw_before_create,
    ));
    session.ownership.data_view_source = true;
    record_trace("data-views-source-create");
    let created = t
        .post("/api/data_views/data_view", Some(create_body))
        .await?;
    record_trace("data-views-default-after-create");
    let default_after_create =
        recorder_get_data_view_default(t, "checking data-view default after source create failed")
            .await?;
    record_trace("data-views-default-after-create-check");
    let lease = session
        .ownership
        .pending_data_view_default_restore
        .as_ref()
        .ok_or_else(|| recording_error("missing pending data-view default restore lease"))?;
    require_pending_data_view_default_state(lease, &default_after_create)?;
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::Recording;
    use crate::recorder::markers::{
        DATA_VIEW_METADATA_DESCRIPTION, DATA_VIEW_REPLACEMENT_ID, DATA_VIEW_SOURCE_ID,
    };
    use crate::recorder::session::{
        CleanupOwnership, PendingDefaultRestore, PendingDefaultRestorePhase, RecordingSession,
    };
    use crate::recorder::test_support::mock_transport;
    use serde_json::{Value, json};
    use std::path::PathBuf;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn default_snapshot_resolver_error_does_not_leak_or_mutate() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/default"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data_view_id": "private-resolver-default"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/data_view/private-resolver-default"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "message": "private-resolver-default",
                "opaque": {"raw": "private-resolver-envelope"}
            })))
            .mount(&server)
            .await;

        let error = capture_data_view_default_snapshot(&mock_transport(&server))
            .await
            .expect_err("unresolvable default must stop preflight");

        assert_eq!(error.kind, elasticctl_core::ErrorKind::Http);
        assert_eq!(error.http_status, Some(500));
        for private in [
            "private-resolver-default",
            "private-resolver-envelope",
            "opaque",
        ] {
            assert!(
                !error.message.contains(private),
                "resolver error leaked {private}: {}",
                error.message
            );
        }
        assert!(
            server
                .received_requests()
                .await
                .expect("requests")
                .iter()
                .all(|request| request.method.as_str() == "GET"),
            "read-only snapshot resolution must not mutate"
        );
    }

    #[tokio::test]
    async fn exact_pending_default_restore_clears_the_lease() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/default"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data_view_id": DATA_VIEW_SOURCE_ID})),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/default"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view_id": ""})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/data_views/default"))
            .and(body_json(json!({"data_view_id": null, "force": true})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
            .expect(1)
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                pending_data_view_default_restore: Some(PendingDefaultRestore {
                    raw: json!({"data_view_id": ""}),
                    canonical: None,
                    phase: PendingDefaultRestorePhase::ExplicitDefaultMutationMayHaveChanged,
                }),
                ..Default::default()
            },
        };

        restore_pending_data_view_default(&mut session)
            .await
            .expect("exact raw restore");
        assert!(
            session
                .ownership
                .pending_data_view_default_restore
                .is_none()
        );
    }

    #[tokio::test]
    async fn nonempty_self_preview_stops_before_replacement_or_swap() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/data_views/swap_references/_preview"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{"id": "unrelated", "type": "dashboard"}]
            })))
            .mount(&server)
            .await;

        record_empty_data_view_self_preview(&mock_transport(&server))
            .await
            .expect_err("nonempty preview must refuse");

        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method.as_str(), "POST");
        assert_eq!(
            requests[0].url.path(),
            "/api/data_views/swap_references/_preview"
        );
    }

    #[test]
    fn data_view_metadata_get_requires_persisted_documented_values() {
        let value = json!({
            "data_view": {
                "fieldAttrs": {
                    "host.name": {"count": 2},
                    "elasticctl.metadata": {
                        "count": 1,
                        "customDescription": "elasticctl sample metadata"
                    }
                }
            }
        });
        require_persisted_data_view_metadata(&value).expect("persisted metadata");

        for invalid in [
            json!({"data_view": {"fieldAttrs": {}}}),
            json!({"data_view": {"fieldAttrs": {
                "host.name": {"count": 2, "customLabel": null},
                "elasticctl.metadata": {"count": 1, "customDescription": "elasticctl sample metadata"}
            }}}),
            json!({"data_view": {"fieldAttrs": {
                "host.name": {"count": 2},
                "elasticctl.metadata": {"count": 1, "customDescription": "wrong"}
            }}}),
        ] {
            assert!(
                require_persisted_data_view_metadata(&invalid).is_err(),
                "invalid persisted metadata must stop before default mutation"
            );
        }
    }

    #[test]
    fn data_view_fields_success_requires_the_closed_union_and_matching_id() {
        assert!(
            require_data_view_fields_success(&json!({"acknowledged": true}), DATA_VIEW_SOURCE_ID)
                .expect("acknowledgement")
                .is_none()
        );
        let envelope = json!({
            "data_view": {
                "id": DATA_VIEW_SOURCE_ID,
                "fieldAttrs": {
                    "host.name": {"count": 2},
                    "elasticctl.metadata": {
                        "count": 1,
                        "customDescription": DATA_VIEW_METADATA_DESCRIPTION
                    }
                }
            }
        });
        assert!(
            require_data_view_fields_success(&envelope, DATA_VIEW_SOURCE_ID)
                .expect("matching envelope")
                .is_some()
        );
        for malformed in [
            json!({"acknowledged": false}),
            json!({"acknowledged": true, "extra": true}),
            json!({"acknowledged": true, "data_view": {"id": DATA_VIEW_SOURCE_ID}}),
            json!({"data_view": {"id": DATA_VIEW_SOURCE_ID}, "extra": true}),
            json!({"data_view": {"id": "other"}}),
            json!({"data_view": {}}),
            json!({"data_view": {"id": 1}}),
            json!({"data_view": {"id": ""}}),
            json!({"data_view": []}),
            json!({}),
            json!([]),
            json!("ok"),
            json!(1),
            json!(true),
            Value::Null,
        ] {
            assert!(
                require_data_view_fields_success(&malformed, DATA_VIEW_SOURCE_ID).is_err(),
                "malformed response must fail"
            );
        }
    }

    #[test]
    fn raw_data_view_default_decoder_preserves_only_the_allowed_shapes() {
        for (body, expected) in [
            (json!({"data_view_id": null}), None),
            (json!({"data_view_id": ""}), None),
            (json!({"data_view_id": "original"}), Some("original")),
            (json!({"data_view_id": "  "}), Some("  ")),
        ] {
            assert_eq!(
                decode_raw_data_view_default(&body).expect("default envelope"),
                expected.map(str::to_string)
            );
        }
        for malformed in [
            json!({}),
            json!({"data_view_id": 1}),
            json!({"data_view_id": null, "extra": true}),
            json!({"data_view_id": "", "extra": true}),
        ] {
            assert!(
                decode_raw_data_view_default(&malformed).is_err(),
                "malformed raw default envelope must fail"
            );
        }
    }

    #[test]
    fn pending_default_lease_create_phase_accepts_only_original_or_source_for_no_default() {
        let lease = PendingDefaultRestore {
            raw: json!({"data_view_id": ""}),
            canonical: None,
            phase: PendingDefaultRestorePhase::CreateMayImplicitlySetSource,
        };
        require_pending_data_view_default_state(&lease, &json!({"data_view_id": ""}))
            .expect("exact original empty default");
        require_pending_data_view_default_state(
            &lease,
            &json!({"data_view_id": DATA_VIEW_SOURCE_ID}),
        )
        .expect("source may become the default during create");
        for rejected in [
            json!({"data_view_id": null}),
            json!({"data_view_id": DATA_VIEW_REPLACEMENT_ID}),
            json!({"data_view_id": "private-nonmarker"}),
        ] {
            let error = require_pending_data_view_default_state(&lease, &rejected)
                .expect_err("unexpected create-phase default must refuse");
            assert!(
                !error.message.contains("private-nonmarker")
                    && !error.message.contains("data_view_id")
            );
        }
    }

    #[test]
    fn pending_default_lease_create_phase_requires_exact_original_for_existing_default() {
        let lease = PendingDefaultRestore {
            raw: json!({"data_view_id": "private-original"}),
            canonical: Some("private-original".to_string()),
            phase: PendingDefaultRestorePhase::CreateMayImplicitlySetSource,
        };
        require_pending_data_view_default_state(&lease, &lease.raw)
            .expect("exact original nonmarker default");
        for rejected in [
            json!({"data_view_id": DATA_VIEW_SOURCE_ID}),
            json!({"data_view_id": null}),
            json!({"data_view_id": "private-other"}),
        ] {
            let error = require_pending_data_view_default_state(&lease, &rejected)
                .expect_err("create must not displace an existing default");
            assert!(
                !error.message.contains("private-original")
                    && !error.message.contains("private-other")
                    && !error.message.contains("data_view_id")
            );
        }
    }

    #[test]
    fn pending_default_lease_explicit_phase_allows_only_original_source_or_no_default() {
        let lease = PendingDefaultRestore {
            raw: json!({"data_view_id": "private-original"}),
            canonical: Some("private-original".to_string()),
            phase: PendingDefaultRestorePhase::ExplicitDefaultMutationMayHaveChanged,
        };
        for allowed in [
            lease.raw.clone(),
            json!({"data_view_id": DATA_VIEW_SOURCE_ID}),
            json!({"data_view_id": null}),
            json!({"data_view_id": ""}),
        ] {
            require_pending_data_view_default_state(&lease, &allowed)
                .expect("explicit default lifecycle state");
        }
        assert!(
            require_pending_data_view_default_state(
                &lease,
                &json!({"data_view_id": DATA_VIEW_REPLACEMENT_ID})
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn empty_raw_default_snapshot_is_canonical_and_never_resolved() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/default"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view_id": ""})))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            capture_data_view_default_snapshot(&mock_transport(&server))
                .await
                .expect("empty raw default"),
            (json!({"data_view_id": ""}), None)
        );
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1, "empty defaults must not be resolved");
        assert_eq!(requests[0].url.path(), "/api/data_views/default");
    }

    #[tokio::test]
    async fn source_create_claims_the_default_lease_before_the_exact_marker_post() {
        let server = MockServer::start().await;
        let claimed_raw = json!({"data_view_id": ""});
        let create_body = json!({
            "data_view": {"id": DATA_VIEW_SOURCE_ID, "title": "elasticctl-sample-data-view-*"},
            "override": false
        });
        Mock::given(method("GET"))
            .and(path("/api/data_views/default"))
            .respond_with(ResponseTemplate::new(200).set_body_json(claimed_raw.clone()))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/data_views/data_view"))
            .and(body_json(create_body.clone()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data_view": {"id": DATA_VIEW_SOURCE_ID}})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/default"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data_view_id": DATA_VIEW_SOURCE_ID})),
            )
            .expect(1)
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
        create_source_with_pending_default_lease(
            &mut session,
            &mut recording,
            "test",
            "test",
            &claimed_raw,
            &None,
            &create_body,
        )
        .await
        .expect("claimed source create");

        let requests = server.received_requests().await.expect("requests");
        assert_eq!(
            requests
                .iter()
                .map(|request| (request.method.as_str(), request.url.path()))
                .collect::<Vec<_>>(),
            [
                ("GET", "/api/data_views/default"),
                ("POST", "/api/data_views/data_view"),
                ("GET", "/api/data_views/default"),
            ]
        );
        let fixture = recording
            .fixtures
            .iter()
            .find(|fixture| fixture.name == "data_view_default_get")
            .expect("claimed-default fixture");
        assert_eq!(fixture.document["response"], claimed_raw);
        assert!(session.ownership.data_view_source);
        assert_eq!(
            session
                .ownership
                .pending_data_view_default_restore
                .as_ref()
                .expect("pending lease")
                .raw,
            json!({"data_view_id": ""})
        );
    }

    #[tokio::test]
    async fn whitespace_default_snapshot_refuses_before_any_recorder_write_or_resolution() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/default"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view_id": " \t "})))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            capture_data_view_default_snapshot(&mock_transport(&server))
                .await
                .is_err(),
            "whitespace default must refuse"
        );
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1, "whitespace default must not be resolved");
        assert_eq!(requests[0].url.path(), "/api/data_views/default");
    }

    #[test]
    fn data_view_default_acknowledgement_is_exact() {
        require_acknowledged(&json!({"acknowledged": true}), "default").expect("exact ack");
        for malformed in [
            json!({}),
            json!({"acknowledged": false}),
            json!({"acknowledged": true, "extra": true}),
            json!({"acknowledged": true, "data_view": {}}),
            json!([]),
            json!(true),
            json!(null),
        ] {
            assert!(
                require_acknowledged(&malformed, "default").is_err(),
                "default acknowledgement must be exact"
            );
        }
    }

    #[test]
    fn restored_raw_default_requires_exact_pre_mutation_shape() {
        require_restored_raw_data_view_default(
            &json!({"data_view_id": ""}),
            &json!({"data_view_id": ""}),
            &None,
        )
        .expect("matching empty default");
        assert!(
            require_restored_raw_data_view_default(
                &json!({"data_view_id": ""}),
                &json!({"data_view_id": null}),
                &None,
            )
            .is_err(),
            "canonical None must not hide raw null-to-empty drift"
        );
    }

    #[test]
    fn default_restore_request_uses_null_for_canonical_no_default() {
        assert_eq!(
            data_view_default_restore_request(None),
            json!({"data_view_id": null, "force": true})
        );
    }
}
