//! Recording helpers.

pub(crate) mod fixtures;

use crate::diagnostics::{
    dashboard_transport, record_trace, recording_error, safe_recording_transport_error,
};
use crate::fixtures::{Recording, error_fixture};
use crate::recorder::dashboards::fixtures::{
    dashboard_data, dashboard_exchange_fixture, dashboard_fixture, dashboard_spec,
    require_absent_dashboard, require_absent_dashboard_data_view, require_dashboard_response,
    require_dashboard_search_response, require_saved_objects_import, scrub_dashboard_bundle_ndjson,
};
use crate::recorder::data_views::defaults::require_empty_or_acknowledged_delete_success;
use crate::recorder::markers::{
    DASHBOARD_DATA_VIEW_ID, DASHBOARD_DATA_VIEW_NAME, DASHBOARD_DATA_VIEW_TITLE, DASHBOARD_ID,
    DASHBOARD_LOSS_ID, DASHBOARD_MARKER, DASHBOARD_TITLE, DASHBOARD_UPDATED_DESCRIPTION,
};
use crate::recorder::session::RecordingSession;
use crate::scrub::hosts::recording_hosts;
use elasticctl_core::urlencode;
use serde_json::{Value, json};

/// Record the marker dashboard lifecycle without reusing the data-view probe's
/// source id. That source is deliberately swapped away by the 0.5.0 contract;
/// this fixed companion view makes the dashboard bundle independently
/// portable, while still leaving a zero-residue data-view result.
pub(super) async fn record_dashboards(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    flavor: &str,
    version: &str,
) -> elasticctl_core::Result<()> {
    let t = session.transport;
    record_trace("dashboards-preflight");
    require_absent_dashboard(t, DASHBOARD_ID).await?;
    require_absent_dashboard(t, DASHBOARD_LOSS_ID).await?;
    require_absent_dashboard_data_view(t).await?;

    // Claim the dashboard first, then its data view, before the first
    // mutation. Cleanup deletes in this same dependency order even if a
    // request below fails midway.
    session.ownership.dashboard = true;
    session.ownership.dashboard_data_view = true;
    let dashboard_data_view_request = json!({
        "data_view": {
            "id": DASHBOARD_DATA_VIEW_ID,
            "title": DASHBOARD_DATA_VIEW_TITLE,
            "name": DASHBOARD_DATA_VIEW_NAME,
            "allowNoIndex": true
        },
        "override": false
    });
    record_trace("dashboards-data-view-create");
    let dashboard_data_view = dashboard_transport(
        "creating dashboard companion data view failed",
        t.post(
            "/api/data_views/data_view",
            Some(&dashboard_data_view_request),
        )
        .await,
    )?;
    record_trace("dashboards-data-view-check");
    if dashboard_data_view
        .pointer("/data_view/id")
        .and_then(Value::as_str)
        != Some(DASHBOARD_DATA_VIEW_ID)
    {
        return Err(recording_error(
            "dashboard data-view create did not preserve the marker id",
        ));
    }

    // This direct route probe intentionally bypasses `DashboardSpec`
    // validation. The public import path rejects time_range.mode before a
    // mutation; the recorder proves the server's accepted-but-dropped shape.
    let mut loss_data = dashboard_data();
    loss_data["title"] = json!("elasticctl sample dashboard loss");
    loss_data["time_range"] = json!({"from": "now-15m", "to": "now", "mode": "relative"});
    let loss_request = dashboard_spec(DASHBOARD_LOSS_ID, loss_data)?;
    session.ownership.dashboard_loss = true;
    record_trace("dashboards-loss-create");
    let loss_response = dashboard_transport(
        "creating dashboard loss probe failed",
        t.put(
            &format!("/api/dashboards/{}", urlencode(DASHBOARD_LOSS_ID)),
            &loss_request["data"],
        )
        .await,
    )?;
    record_trace("dashboards-loss-check");
    if loss_response.get("id").and_then(Value::as_str) != Some(DASHBOARD_LOSS_ID)
        || !loss_response.get("meta").is_some_and(Value::is_object)
        || loss_response
            .pointer("/data/time_range")
            .and_then(Value::as_object)
            .is_none()
        || loss_response.pointer("/data/time_range/mode").is_some()
    {
        return Err(recording_error(
            "loss probe did not return the expected accepted dashboard envelope",
        ));
    }
    let losses =
        elasticctl_api::dashboards::subset_losses(&loss_request["data"], &loss_response["data"]);
    if losses
        .iter()
        .map(|loss| loss.path.as_str())
        .collect::<Vec<_>>()
        != vec!["$.time_range.mode"]
    {
        return Err(recording_error(
            "loss probe did not report exactly $.time_range.mode",
        ));
    }
    recording.fixtures.push(dashboard_exchange_fixture(
        "dashboard_loss",
        flavor,
        version,
        loss_request,
        loss_response,
    ));
    record_trace("dashboards-loss-delete");
    if dashboard_transport(
        "deleting dashboard loss probe failed",
        t.delete(&format!("/api/dashboards/{}", urlencode(DASHBOARD_LOSS_ID)))
            .await,
    )? != Value::Null
    {
        return Err(recording_error(
            "loss probe dashboard delete did not return an empty body",
        ));
    }
    record_trace("dashboards-loss-gone-check");
    match t
        .get(&format!("/api/dashboards/{}", urlencode(DASHBOARD_LOSS_ID)))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
            session.ownership.dashboard_loss = false;
        }
        Ok(_) => {
            return Err(recording_error(
                "loss probe dashboard still exists after delete",
            ));
        }
        Err(error) => {
            return Err(safe_recording_transport_error(
                "verifying dashboard loss probe deletion failed",
                error,
            ));
        }
    }

    let create_request = dashboard_spec(DASHBOARD_ID, dashboard_data())?;
    record_trace("dashboards-create");
    let created = dashboard_transport(
        "creating dashboard failed",
        t.put(
            &format!("/api/dashboards/{}", urlencode(DASHBOARD_ID)),
            &create_request["data"],
        )
        .await,
    )?;
    record_trace("dashboards-create-check");
    require_dashboard_response(&created, DASHBOARD_ID, DASHBOARD_MARKER, "dashboard create")?;
    recording.fixtures.push(dashboard_exchange_fixture(
        "dashboard_create",
        flavor,
        version,
        create_request,
        created,
    ));

    record_trace("dashboards-get");
    let got = dashboard_transport(
        "getting dashboard failed",
        t.get(&format!("/api/dashboards/{}", urlencode(DASHBOARD_ID)))
            .await,
    )?;
    record_trace("dashboards-get-check");
    require_dashboard_response(&got, DASHBOARD_ID, DASHBOARD_MARKER, "dashboard get")?;
    recording
        .fixtures
        .push(dashboard_fixture("dashboard_get", flavor, version, got));

    let search_request = json!({"query": DASHBOARD_TITLE});
    record_trace("dashboards-search");
    let searched = dashboard_transport(
        "searching dashboard failed",
        t.get(&format!(
            "/api/dashboards?page=1&per_page=1000&query={}",
            urlencode(DASHBOARD_TITLE)
        ))
        .await,
    )?;
    record_trace("dashboards-search-check");
    require_dashboard_search_response(&searched)?;
    recording.fixtures.push(dashboard_exchange_fixture(
        "dashboard_search",
        flavor,
        version,
        search_request,
        searched,
    ));

    let mut updated_data = dashboard_data();
    updated_data["description"] = json!(DASHBOARD_UPDATED_DESCRIPTION);
    let update_request = dashboard_spec(DASHBOARD_ID, updated_data)?;
    record_trace("dashboards-update");
    let updated = dashboard_transport(
        "updating dashboard failed",
        t.put(
            &format!("/api/dashboards/{}", urlencode(DASHBOARD_ID)),
            &update_request["data"],
        )
        .await,
    )?;
    record_trace("dashboards-update-check");
    require_dashboard_response(
        &updated,
        DASHBOARD_ID,
        DASHBOARD_UPDATED_DESCRIPTION,
        "dashboard update",
    )?;
    recording.fixtures.push(dashboard_exchange_fixture(
        "dashboard_update",
        flavor,
        version,
        update_request,
        updated,
    ));

    let export_request = json!({
        "objects": [{"type": "dashboard", "id": DASHBOARD_ID}],
        "includeReferencesDeep": true,
        "excludeExportDetails": false,
    });
    record_trace("dashboards-export");
    let bundle = dashboard_transport(
        "exporting dashboard bundle failed",
        t.post_text("/api/saved_objects/_export", Some(&export_request))
            .await,
    )?;
    record_trace("dashboards-export-check");
    let scan = elasticctl_api::saved_objects::scan_bundle(&bundle)
        .map_err(|_| recording_error("scanning dashboard deep export failed"))?;
    if scan.dashboards != vec![DASHBOARD_ID.to_string()]
        || scan.counts.get("dashboard") != Some(&1)
        || scan.counts.get("index-pattern") != Some(&1)
        || scan.total != 2
        || !scan.has_export_details
    {
        return Err(recording_error(
            "deep dashboard export did not contain exactly the marker dashboard, data view, and trailer",
        ));
    }
    let hosts = recording_hosts();
    recording.fixtures.push(dashboard_exchange_fixture(
        "dashboard_bundle_export",
        flavor,
        version,
        export_request,
        json!({"ndjson": scrub_dashboard_bundle_ndjson(&bundle, &hosts)}),
    ));

    record_trace("dashboards-delete");
    let deleted = dashboard_transport(
        "deleting dashboard failed",
        t.delete(&format!("/api/dashboards/{}", urlencode(DASHBOARD_ID)))
            .await,
    )?;
    record_trace("dashboards-delete-check");
    if deleted != Value::Null {
        return Err(recording_error(
            "dashboard delete did not return an empty response body",
        ));
    }
    recording.fixtures.push(dashboard_fixture(
        "dashboard_delete",
        flavor,
        version,
        deleted,
    ));

    record_trace("dashboards-data-view-delete");
    let deleted_data_view = dashboard_transport(
        "deleting dashboard companion data view failed",
        t.delete(&format!(
            "/api/data_views/data_view/{DASHBOARD_DATA_VIEW_ID}"
        ))
        .await,
    )?;
    record_trace("dashboards-data-view-delete-check");
    require_empty_or_acknowledged_delete_success(&deleted_data_view)?;

    record_trace("dashboards-import");
    let imported = dashboard_transport(
        "importing dashboard bundle failed",
        t.post_multipart_ndjson_named(
            "/api/saved_objects/_import?overwrite=true",
            "dashboards.ndjson",
            &bundle,
        )
        .await,
    )?;
    record_trace("dashboards-import-check");
    require_saved_objects_import(&imported, true, "dashboard import")?;
    recording.fixtures.push(dashboard_exchange_fixture(
        "dashboard_import",
        flavor,
        version,
        json!({"overwrite": true}),
        imported,
    ));

    record_trace("dashboards-import-conflict");
    let conflict = dashboard_transport(
        "checking dashboard bundle import conflict failed",
        t.post_multipart_ndjson_named(
            "/api/saved_objects/_import?overwrite=false",
            "dashboards.ndjson",
            &bundle,
        )
        .await,
    )?;
    record_trace("dashboards-import-conflict-check");
    require_saved_objects_import(&conflict, false, "dashboard import conflict")?;
    recording.fixtures.push(dashboard_exchange_fixture(
        "dashboard_import_conflict",
        flavor,
        version,
        json!({"overwrite": false}),
        conflict,
    ));

    record_trace("dashboards-final-delete");
    if dashboard_transport(
        "deleting recreated dashboard failed",
        t.delete(&format!("/api/dashboards/{}", urlencode(DASHBOARD_ID)))
            .await,
    )? != Value::Null
    {
        return Err(recording_error(
            "recreated dashboard delete did not return an empty response body",
        ));
    }
    record_trace("dashboards-final-delete-check");
    record_trace("dashboards-final-data-view-delete");
    let deleted_data_view = dashboard_transport(
        "deleting recreated dashboard companion data view failed",
        t.delete(&format!(
            "/api/data_views/data_view/{DASHBOARD_DATA_VIEW_ID}"
        ))
        .await,
    )?;
    record_trace("dashboards-final-data-view-delete-check");
    require_empty_or_acknowledged_delete_success(&deleted_data_view)?;

    record_trace("dashboards-not-found");
    match t
        .get(&format!("/api/dashboards/{}", urlencode(DASHBOARD_ID)))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
            recording
                .fixtures
                .push(error_fixture("dashboard_not_found", flavor, version, error));
            session.ownership.dashboard = false;
        }
        Ok(_) => return Err(recording_error("dashboard still exists after final delete")),
        Err(error) => {
            return Err(safe_recording_transport_error(
                "verifying dashboard deletion failed",
                error,
            ));
        }
    }
    record_trace("dashboards-data-view-not-found");
    match t
        .get(&format!(
            "/api/data_views/data_view/{DASHBOARD_DATA_VIEW_ID}"
        ))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
            recording.fixtures.push(error_fixture(
                "dashboard_data_view_not_found",
                flavor,
                version,
                error,
            ));
            session.ownership.dashboard_data_view = false;
        }
        Ok(_) => {
            return Err(recording_error(
                "dashboard data view still exists after final delete",
            ));
        }
        Err(error) => {
            return Err(safe_recording_transport_error(
                "verifying dashboard companion data-view deletion failed",
                error,
            ));
        }
    }

    Ok(())
}
