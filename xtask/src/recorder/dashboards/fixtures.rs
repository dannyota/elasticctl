use crate::diagnostics::{recording_error, safe_recording_transport_error};
use crate::fixtures::{RecordedFixture, exchange_fixture, response_fixture};
use crate::recorder::markers::{
    DASHBOARD_DATA_VIEW_ID, DASHBOARD_DATA_VIEW_NAME, DASHBOARD_DATA_VIEW_TITLE, DASHBOARD_ID,
    DASHBOARD_MARKER, DASHBOARD_PANEL_ID_PLACEHOLDER_PREFIX, DASHBOARD_TITLE,
    DASHBOARD_VOLATILE_FIELDS,
};
use crate::scrub::hosts::scrub_hosts;
use crate::scrub::{scrub, strip_volatile};
use elasticctl_core::urlencode;
use serde_json::{Value, json};

pub(super) async fn require_absent_dashboard(
    t: &elasticctl_core::Transport,
    id: &str,
) -> elasticctl_core::Result<()> {
    match t.get(&format!("/api/dashboards/{}", urlencode(id))).await {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: dashboard {id} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(safe_recording_transport_error(
            "checking dashboard absence failed",
            error,
        )),
    }
}

pub(super) async fn require_absent_dashboard_data_view(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    match elasticctl_api::data_views::get(t, DASHBOARD_DATA_VIEW_ID).await {
        Ok(_) => Err(recording_error(
            "refusing to record: dashboard companion data view already exists and is not cleanup-owned",
        )),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(safe_recording_transport_error(
            "checking dashboard companion data-view absence failed",
            error,
        )),
    }
}

pub(super) fn dashboard_data() -> Value {
    json!({
        "title": DASHBOARD_TITLE,
        "description": DASHBOARD_MARKER,
        "panels": [{
            "type": "vis",
            "grid": {"x": 0, "y": 0, "w": 12, "h": 8},
            "config": {
                "title": "Sample count",
                "type": "metric",
                "data_source": {
                    "type": "data_view_reference",
                    "ref_id": DASHBOARD_DATA_VIEW_ID
                },
                "metrics": [{"type": "primary", "operation": "count"}]
            }
        }]
    })
}

pub(super) fn dashboard_spec(id: &str, data: Value) -> elasticctl_core::Result<Value> {
    let spec = json!({"id": id, "data": data});
    elasticctl_api::dashboards::DashboardSpec::try_from(spec.clone()).map_err(|error| {
        recording_error(format!("building marker dashboard {id}: {}", error.message))
    })?;
    Ok(spec)
}

pub(super) fn require_dashboard_response(
    body: &Value,
    id: &str,
    description: &str,
    context: &str,
) -> elasticctl_core::Result<()> {
    let data = body.get("data").and_then(Value::as_object).ok_or_else(|| {
        recording_error(format!(
            "{context}: dashboard response data must be an object"
        ))
    })?;
    if body.get("id").and_then(Value::as_str) != Some(id)
        || data.get("title").and_then(Value::as_str) != Some(DASHBOARD_TITLE)
        || data.get("description").and_then(Value::as_str) != Some(description)
        || !body.get("meta").is_some_and(Value::is_object)
    {
        return Err(recording_error(format!(
            "{context}: dashboard response did not preserve the marker identity and envelope"
        )));
    }
    Ok(())
}

pub(super) fn require_dashboard_search_response(body: &Value) -> elasticctl_core::Result<()> {
    let data = body
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| recording_error("dashboard search response data must be an array"))?;
    let meta = body
        .get("meta")
        .and_then(Value::as_object)
        .ok_or_else(|| recording_error("dashboard search response meta must be an object"))?;
    if data.len() != 1 {
        return Err(recording_error(
            "exact-title dashboard search returned a non-singleton scoped result",
        ));
    }
    if data[0].get("id").and_then(Value::as_str) != Some(DASHBOARD_ID) {
        return Err(recording_error(
            "exact-title dashboard search returned a nonmarker id",
        ));
    }
    if data[0].pointer("/data/title").and_then(Value::as_str) != Some(DASHBOARD_TITLE) {
        return Err(recording_error(
            "exact-title dashboard search returned a nonmarker nested title",
        ));
    }
    if meta.get("page").and_then(Value::as_u64) != Some(1)
        || meta.get("per_page").and_then(Value::as_u64) != Some(1000)
    {
        return Err(recording_error(
            "dashboard search metadata did not preserve the requested page",
        ));
    }
    if meta.get("total").and_then(Value::as_u64) != Some(1) {
        return Err(recording_error(
            "exact-title dashboard search total did not equal the marker result",
        ));
    }
    Ok(())
}

pub(crate) fn owns_dashboard(value: &Value, id: &str) -> bool {
    value.get("id").and_then(Value::as_str) == Some(id)
        && value
            .pointer("/data/description")
            .and_then(Value::as_str)
            .is_some_and(|description| description.contains(DASHBOARD_MARKER))
}

pub(crate) fn owns_recorded_data_view(value: &serde_json::Map<String, Value>, id: &str) -> bool {
    value.get("id").and_then(Value::as_str) == Some(id)
        && (id != DASHBOARD_DATA_VIEW_ID
            || (value.get("title").and_then(Value::as_str) == Some(DASHBOARD_DATA_VIEW_TITLE)
                && value.get("name").and_then(Value::as_str) == Some(DASHBOARD_DATA_VIEW_NAME)))
}

pub(super) fn require_saved_objects_import(
    body: &Value,
    expected_success: bool,
    context: &str,
) -> elasticctl_core::Result<()> {
    let object = body.as_object().ok_or_else(|| {
        recording_error(format!(
            "{context}: Saved Objects import response must be an object"
        ))
    })?;
    let success = object
        .get("success")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            recording_error(format!(
                "{context}: Saved Objects import success must be boolean"
            ))
        })?;
    let success_count = object
        .get("successCount")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            recording_error(format!(
                "{context}: Saved Objects import successCount must be unsigned"
            ))
        })?;
    let success_results = match object.get("successResults") {
        None => &[][..],
        Some(value) => value.as_array().ok_or_else(|| {
            recording_error(format!("{context}: successResults must be an array"))
        })?,
    };
    let errors = match object.get("errors") {
        None => &[][..],
        Some(value) => value
            .as_array()
            .ok_or_else(|| recording_error(format!("{context}: errors must be an array")))?,
    };
    if success != expected_success
        || success_count != success_results.len() as u64
        || (success && !errors.is_empty())
        || (!success && errors.is_empty())
    {
        return Err(recording_error(format!(
            "{context}: Saved Objects import response did not match the measured success contract"
        )));
    }
    Ok(())
}

fn scrub_dashboard_panel_ids(value: &mut Value) {
    fn is_canonical_uuid(value: &str) -> bool {
        value.len() == 36
            && value.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            })
    }

    fn remember_panel_id(value: &Value, ids: &mut Vec<String>) {
        let Some(id) = value.as_str() else {
            return;
        };
        if is_canonical_uuid(id) && !ids.iter().any(|known| known == id) {
            ids.push(id.to_string());
        }
    }

    fn collect_from_panels(value: &Value, ids: &mut Vec<String>) {
        let Some(panels) = value.as_array() else {
            return;
        };
        for panel in panels {
            if let Some(panel) = panel.as_object() {
                for key in ["id", "panelIndex"] {
                    if let Some(id) = panel.get(key) {
                        remember_panel_id(id, ids);
                    }
                }
                if let Some(grid_data) = panel.get("gridData").and_then(Value::as_object)
                    && let Some(id) = grid_data.get("i")
                {
                    remember_panel_id(id, ids);
                }
            }
            collect_panel_ids(panel, ids);
        }
    }

    fn collect_panel_ids(value: &Value, ids: &mut Vec<String>) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    if key == "panels" {
                        collect_from_panels(value, ids);
                    } else if key == "panelsJSON" {
                        if let Some(text) = value.as_str()
                            && let Ok(panels) = serde_json::from_str::<Value>(text)
                        {
                            collect_from_panels(&panels, ids);
                        }
                    } else {
                        collect_panel_ids(value, ids);
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    collect_panel_ids(value, ids);
                }
            }
            _ => {}
        }
    }

    fn replace_in_string(value: &mut String, replacements: &[(String, String)]) {
        for (generated, placeholder) in replacements {
            if value.contains(generated) {
                *value = value.replace(generated, placeholder);
            }
        }
    }

    fn rewrite_panels(value: &mut Value, replacements: &[(String, String)]) {
        let Some(panels) = value.as_array_mut() else {
            return;
        };
        for panel in panels {
            if let Some(panel_map) = panel.as_object_mut() {
                for key in ["id", "panelIndex"] {
                    if let Some(Value::String(id)) = panel_map.get_mut(key) {
                        replace_in_string(id, replacements);
                    }
                }
                if let Some(grid_data) =
                    panel_map.get_mut("gridData").and_then(Value::as_object_mut)
                    && let Some(Value::String(id)) = grid_data.get_mut("i")
                {
                    replace_in_string(id, replacements);
                }
            }
            rewrite_panel_ids(panel, replacements);
        }
    }

    fn rewrite_references(value: &mut Value, replacements: &[(String, String)]) {
        let Some(references) = value.as_array_mut() else {
            return;
        };
        for reference in references {
            if let Some(reference_map) = reference.as_object_mut()
                && let Some(Value::String(name)) = reference_map.get_mut("name")
            {
                replace_in_string(name, replacements);
            }
            rewrite_panel_ids(reference, replacements);
        }
    }

    fn rewrite_panel_ids(value: &mut Value, replacements: &[(String, String)]) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    if key == "panels" {
                        rewrite_panels(value, replacements);
                    } else if key == "panelsJSON" {
                        if let Value::String(text) = value {
                            replace_in_string(text, replacements);
                        }
                    } else if key == "references" {
                        rewrite_references(value, replacements);
                    } else {
                        rewrite_panel_ids(value, replacements);
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    rewrite_panel_ids(value, replacements);
                }
            }
            _ => {}
        }
    }

    let mut generated_ids = Vec::new();
    collect_panel_ids(value, &mut generated_ids);
    let replacements = generated_ids
        .into_iter()
        .enumerate()
        .map(|(index, id)| {
            (
                id,
                format!("{DASHBOARD_PANEL_ID_PLACEHOLDER_PREFIX}{}", index + 1),
            )
        })
        .collect::<Vec<_>>();
    rewrite_panel_ids(value, &replacements);
}

fn scrub_dashboard(value: &mut Value) {
    strip_volatile(value, DASHBOARD_VOLATILE_FIELDS);
    scrub_dashboard_panel_ids(value);
}

pub(super) fn dashboard_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    mut body: Value,
) -> RecordedFixture {
    scrub_dashboard(&mut body);
    response_fixture(name, flavor, version, body, None)
}

pub(super) fn dashboard_exchange_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    mut request: Value,
    mut body: Value,
) -> RecordedFixture {
    scrub_dashboard(&mut request);
    scrub_dashboard(&mut body);
    exchange_fixture(name, flavor, version, request, body)
}

pub(super) fn scrub_dashboard_bundle_ndjson(text: &str, hosts: &[String]) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut value: Value = serde_json::from_str(line).expect("dashboard export line is JSON");
        scrub(&mut value);
        scrub_hosts(&mut value, hosts);
        scrub_dashboard(&mut value);
        out.push_str(
            &serde_json::to_string(&value).expect("encode scrubbed dashboard export line"),
        );
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::markers::{DASHBOARD_ID, DASHBOARD_MARKER, DASHBOARD_TITLE};
    use crate::recorder::test_support::mock_transport;
    use serde_json::{Value, json};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn dashboard_scrub_normalizes_generated_panel_ids_in_response_and_bundle() {
        const PANEL_ID: &str = "12345678-1234-1234-1234-123456789abc";
        const PLACEHOLDER: &str = "elasticctl-fixture-dashboard-panel-1";

        let mut response = json!({
            "id": DASHBOARD_ID,
            "data": {
                "title": DASHBOARD_TITLE,
                "panels": [{"id": PANEL_ID, "type": "vis"}]
            }
        });
        scrub_dashboard(&mut response);
        assert_eq!(response["id"], DASHBOARD_ID);
        assert_eq!(response["data"]["panels"][0]["id"], PLACEHOLDER);

        let panels_json = serde_json::to_string(&json!([
            {
                "panelIndex": PANEL_ID,
                "gridData": {"i": PANEL_ID, "x": 0, "y": 0},
                "type": "visualization"
            }
        ]))
        .expect("encode test panelsJSON");
        let bundle_line = serde_json::to_string(&json!({
            "id": DASHBOARD_ID,
            "type": "dashboard",
            "attributes": {"panelsJSON": panels_json},
            "references": [{"name": format!("panel_{PANEL_ID}")}]
        }))
        .expect("encode test bundle line");
        let scrubbed = scrub_dashboard_bundle_ndjson(&format!("{bundle_line}\n"), &[]);
        assert!(!scrubbed.contains(PANEL_ID));
        let bundle: Value = serde_json::from_str(scrubbed.trim()).expect("decode scrubbed bundle");
        let panels: Value = serde_json::from_str(
            bundle["attributes"]["panelsJSON"]
                .as_str()
                .expect("scrubbed panelsJSON string"),
        )
        .expect("decode scrubbed panelsJSON");
        assert_eq!(panels[0]["panelIndex"], PLACEHOLDER);
        assert_eq!(panels[0]["gridData"]["i"], PLACEHOLDER);
        assert_eq!(
            bundle["references"][0]["name"],
            format!("panel_{PLACEHOLDER}")
        );
    }

    #[test]
    fn dashboard_update_response_requires_the_updated_description() {
        let response = json!({
            "id": DASHBOARD_ID,
            "data": {
                "title": DASHBOARD_TITLE,
                "description": DASHBOARD_MARKER
            },
            "meta": {}
        });

        assert!(
            require_dashboard_response(
                &response,
                DASHBOARD_ID,
                "elasticctl-sample updated",
                "dashboard update"
            )
            .is_err(),
            "a replacement response must prove it retained the new description"
        );
    }

    #[tokio::test]
    async fn dashboard_recording_transport_error_omits_server_message() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/api/dashboards/{DASHBOARD_ID}")))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "message": "private dashboard server identity"
            })))
            .mount(&server)
            .await;

        let error = require_absent_dashboard(&mock_transport(&server), DASHBOARD_ID)
            .await
            .expect_err("a dashboard preflight transport failure");

        assert_eq!(error.message, "checking dashboard absence failed");
        assert!(!error.message.contains("private"));
    }
}
