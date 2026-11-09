//! Fixtures helpers.

use crate::diagnostics::recording_error;
use crate::fixtures::{RecordedFixture, exchange_fixture, response_fixture};
use crate::recorder::markers::{
    DATA_VIEW_DEFAULT_PLACEHOLDER, DATA_VIEW_INDEX, DATA_VIEW_REPLACEMENT_ID, DATA_VIEW_SOURCE_ID,
};
use serde_json::Value;

pub(crate) async fn require_absent_data_view(
    t: &elasticctl_core::Transport,
    id: &str,
) -> elasticctl_core::Result<()> {
    match elasticctl_api::data_views::get(t, id).await {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: data view {id} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) async fn require_absent_data_view_index(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    match t.get_absolute_es(&format!("/{DATA_VIEW_INDEX}")).await {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: data-view index {DATA_VIEW_INDEX} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) async fn verify_data_view_index_deleted(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    match t.get_absolute_es(&format!("/{DATA_VIEW_INDEX}")).await {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(recording_error(format!(
            "data-view index {DATA_VIEW_INDEX} still exists after delete"
        ))),
        Err(error) => Err(error),
    }
}

pub(crate) fn owns_data_view_index(value: &Value) -> bool {
    value["_source"]["marker"].as_str() == Some("elasticctl-sample")
        && value["_source"]["probe"].as_str() == Some("data-view")
}

/// Remove server-owned data-view details while preserving the portable
/// configuration and any legacy scripted entry. Mapped fields are generated
/// cache data and must not turn a fixture into a snapshot of a deployment.
pub(crate) fn scrub_data_view(value: &mut Value) {
    let Some(view) = value.get_mut("data_view").and_then(Value::as_object_mut) else {
        return;
    };
    view.remove("version");
    view.remove("namespaces");
    for key in [
        "created_at",
        "updated_at",
        "originId",
        "updatedAt",
        "createdAt",
    ] {
        view.remove(key);
    }
    if let Some(Value::Object(fields)) = view.get_mut("fields") {
        fields.retain(|_, field| field.get("scripted").and_then(Value::as_bool) == Some(true));
    }
}

pub(crate) fn scrub_data_view_default(value: &mut Value) {
    if let Some(Value::String(id)) = value.get_mut("data_view_id")
        && !id.is_empty()
        && id != DATA_VIEW_SOURCE_ID
        && id != DATA_VIEW_REPLACEMENT_ID
    {
        *id = DATA_VIEW_DEFAULT_PLACEHOLDER.to_string();
    }
}

pub(crate) fn data_view_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    mut body: Value,
) -> RecordedFixture {
    scrub_data_view(&mut body);
    scrub_data_view_default(&mut body);
    response_fixture(name, flavor, version, body, None)
}

pub(crate) fn data_view_exchange_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    mut request: Value,
    mut body: Value,
) -> RecordedFixture {
    scrub_data_view(&mut request);
    scrub_data_view(&mut body);
    scrub_data_view_default(&mut request);
    scrub_data_view_default(&mut body);
    exchange_fixture(name, flavor, version, request, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::markers::{
        DATA_VIEW_DEFAULT_PLACEHOLDER, DATA_VIEW_INDEX, DATA_VIEW_SOURCE_ID,
    };
    use crate::recorder::test_support::mock_transport;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn data_view_index_preflight_refuses_an_existing_empty_or_nonmarker_index() {
        for root in [
            json!({"settings": {}}),
            json!({"_source": {"marker": "someone-else"}}),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(format!("/{DATA_VIEW_INDEX}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(root))
                .mount(&server)
                .await;
            let error = require_absent_data_view_index(&mock_transport(&server))
                .await
                .expect_err("existing root index must refuse");
            assert!(error.message.contains("already exists"));
            let requests = server.received_requests().await.expect("requests");
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].url.path(), format!("/{DATA_VIEW_INDEX}"));
        }
    }

    #[tokio::test]
    async fn data_view_index_delete_verification_retains_ownership_when_root_remains() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/{DATA_VIEW_INDEX}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"settings": {}})))
            .mount(&server)
            .await;
        let error = verify_data_view_index_deleted(&mock_transport(&server))
            .await
            .expect_err("root index still exists");
        assert!(error.message.contains("still exists"));
    }

    #[test]
    fn scrub_data_view_retains_scripted_probe_evidence_and_drops_generated_fields() {
        let mut value = json!({
            "data_view": {
                "id": DATA_VIEW_SOURCE_ID,
                "version": "opaque",
                "namespaces": ["default"],
                "created_at": "2026-09-01T00:00:00.000Z",
                "updated_at": "2026-09-01T00:01:00.000Z",
                "originId": "opaque-origin",
                "createdAt": "2026-09-01T00:00:00.000Z",
                "updatedAt": "2026-09-01T00:01:00.000Z",
                "fields": {
                    "host.name": {"name": "host.name", "scripted": false},
                    "elasticctl.legacy": {"scripted": true, "script": "return 1;"}
                }
            }
        });

        scrub_data_view(&mut value);

        assert_eq!(
            value,
            json!({
                "data_view": {
                    "id": DATA_VIEW_SOURCE_ID,
                    "fields": {
                        "elasticctl.legacy": {"scripted": true, "script": "return 1;"}
                    }
                }
            })
        );
    }

    #[test]
    fn scrub_data_view_default_preserves_shape_without_real_default_id() {
        let mut nonmarker = json!({"data_view_id": "private-default"});
        scrub_data_view_default(&mut nonmarker);
        assert_eq!(nonmarker["data_view_id"], DATA_VIEW_DEFAULT_PLACEHOLDER);

        let mut marker = json!({"data_view_id": DATA_VIEW_SOURCE_ID});
        scrub_data_view_default(&mut marker);
        assert_eq!(marker["data_view_id"], DATA_VIEW_SOURCE_ID);

        let mut absent = json!({"data_view_id": null});
        scrub_data_view_default(&mut absent);
        assert!(absent["data_view_id"].is_null());

        let mut empty = json!({"data_view_id": ""});
        scrub_data_view_default(&mut empty);
        assert_eq!(empty["data_view_id"], "");
    }
}
