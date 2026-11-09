//! Recording orchestration and command entry.

mod agent_policies;
pub(crate) mod alerts;
pub(crate) mod cases;
pub(crate) mod dashboards;
pub(crate) mod data_views;
pub(crate) mod integration;
pub(crate) mod markers;
pub(crate) mod ownership;
pub(crate) mod preview;
mod rules;
mod search;
pub(crate) mod session;

use crate::diagnostics::{record_trace, recording_error};
use crate::environment::{activate_traditional_recorder_profile, transport_from_env};
use crate::fixtures::{
    Recording, error_fixture, preview_exchange_fixture, preview_fixture, response_fixture,
    rule_exchange_fixture, rule_fixture, write_recording,
};
use crate::record_integration_policies;
use crate::recorder::agent_policies::record_agent_policies;
use crate::recorder::alerts::cleanup::close_and_clean_alerts;
use crate::recorder::alerts::record_alerts_probe;
use crate::recorder::cases::record_cases;
use crate::recorder::dashboards::record_dashboards;
use crate::recorder::data_views::record_data_views;
use crate::recorder::markers::{ITEM_ID, LIST_ID, NAMESPACE_TYPE, RULE_ID};
use crate::recorder::preview::{PREVIEW_TIMEFRAME_END, record_preview_hits};
use crate::recorder::rules::{create_marked_item, create_marked_list, create_marked_rule};
use crate::recorder::search::record_search;
use crate::recorder::session::{CleanupOwnership, RecordingSession};
use crate::scrub::hosts::recording_hosts;
use crate::scrub::{
    LICENSE_VOLATILE_FIELDS, redact_authenticate_metadata, scrub_ndjson, scrub_status,
    strip_volatile,
};
use crate::seed::{prebuilt_install_is_noop, prebuilt_is_current};
use elasticctl_core::urlencode;
use serde_json::{Value, json};
use std::path::PathBuf;

async fn record_session(session: &mut RecordingSession<'_>) -> elasticctl_core::Result<Recording> {
    record_trace("bootstrap");
    let responded = session.transport.get_with_headers("/api/status").await?;
    let mut status = responded.body.clone();
    // Instance name/UUID identify the deployment and `metrics` is a runtime
    // snapshot. Drop all three; flavor and version come from the stable
    // product-build object.
    scrub_status(&mut status);
    let version = status["version"]["number"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let flavor = std::env::var("ELASTICCTL_FIXTURE_FLAVOR").unwrap_or_else(|_| {
        status["version"]["build_flavor"]
            .as_str()
            .unwrap_or("default")
            .to_string()
    });
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests/fixtures")
        .join(format!("{flavor}-{version}"));
    let mut recording = Recording {
        dir,
        fixtures: vec![response_fixture(
            "status",
            &flavor,
            &version,
            status,
            Some(&responded.headers),
        )],
    };
    let t = session.transport;

    let mut authenticate = t.get_absolute_es("/_security/_authenticate").await?;
    redact_authenticate_metadata(&mut authenticate);
    recording.fixtures.push(response_fixture(
        "authenticate",
        &flavor,
        &version,
        authenticate,
        None,
    ));
    recording.fixtures.push(response_fixture(
        "spaces",
        &flavor,
        &version,
        t.get("/api/spaces/space").await?,
        None,
    ));
    if let Ok(mut license) = t.get_absolute_es("/_license").await {
        strip_volatile(&mut license, LICENSE_VOLATILE_FIELDS);
        recording.fixtures.push(response_fixture(
            "license", &flavor, &version, license, None,
        ));
    }

    match t.get("/api/lists/index").await {
        Ok(response) => recording.fixtures.push(response_fixture(
            "lists_index",
            &flavor,
            &version,
            response,
            None,
        )),
        Err(error) => {
            recording
                .fixtures
                .push(error_fixture("lists_index", &flavor, &version, error))
        }
    }

    record_trace("prebuilt");
    record_trace("prebuilt-status-before");
    let prebuilt_before = t
        .get("/api/detection_engine/rules/prepackaged/_status")
        .await?;
    record_trace("prebuilt-status-before-check");
    if !prebuilt_is_current(&prebuilt_before)? {
        return Err(recording_error(
            "prebuilt rules or timelines are missing or outdated; run the separately guarded `cargo xtask seed` before recording",
        ));
    }
    recording.fixtures.push(response_fixture(
        "prebuilt_status",
        &flavor,
        &version,
        prebuilt_before.clone(),
        None,
    ));
    record_trace("prebuilt-install");
    let prebuilt_install = t
        .put("/api/detection_engine/rules/prepackaged", &Value::Null)
        .await?;
    record_trace("prebuilt-install-check");
    if !prebuilt_install_is_noop(&prebuilt_install)? {
        return Err(recording_error(
            "prebuilt install changed the stack despite a no-op status; refusing to record a mutation",
        ));
    }
    record_trace("prebuilt-status-after");
    let prebuilt_after = t
        .get("/api/detection_engine/rules/prepackaged/_status")
        .await?;
    record_trace("prebuilt-status-compare");
    if prebuilt_after != prebuilt_before {
        return Err(recording_error(
            "prebuilt status changed after the measured no-op install",
        ));
    }
    recording.fixtures.push(response_fixture(
        "prebuilt_install",
        &flavor,
        &version,
        prebuilt_install,
        None,
    ));

    record_trace("exceptions-rules");
    let list = create_marked_list(session).await?;
    let list_server_id = list["id"]
        .as_str()
        .ok_or_else(|| recording_error("exception list create response is missing id"))?
        .to_string();
    recording.fixtures.push(rule_fixture(
        "exception_list_create",
        &flavor,
        &version,
        list,
    ));
    let item = create_marked_item(session).await?;
    recording.fixtures.push(rule_fixture(
        "exception_item_create",
        &flavor,
        &version,
        item,
    ));
    let (rule_body, rule) = create_marked_rule(session, &list_server_id).await?;
    recording
        .fixtures
        .push(rule_fixture("rules_create", &flavor, &version, rule));

    let list_filter = format!("exception-list.attributes.list_id: \"{LIST_ID}\"");
    let lists_find = t
        .get(&format!(
            "/api/exception_lists/_find?page=1&per_page=2&namespace_type={NAMESPACE_TYPE}&filter={}",
            urlencode(&list_filter)
        ))
        .await?;
    recording.fixtures.push(rule_exchange_fixture(
        "exception_lists_find",
        &flavor,
        &version,
        json!({"filter": list_filter}),
        lists_find,
    ));
    recording.fixtures.push(rule_fixture(
        "exception_list_get",
        &flavor,
        &version,
        t.get(&format!(
            "/api/exception_lists?list_id={}&namespace_type={NAMESPACE_TYPE}",
            urlencode(LIST_ID)
        ))
        .await?,
    ));
    recording.fixtures.push(rule_fixture(
        "exception_list_items_find",
        &flavor,
        &version,
        t.get(&format!(
            "/api/exception_lists/items/_find?list_id={}&namespace_type={NAMESPACE_TYPE}&page=1&per_page=2",
            urlencode(LIST_ID)
        ))
        .await?,
    ));

    let rule_filter = format!("alert.attributes.params.ruleId: \"{RULE_ID}\"");
    let rules_find = t
        .get(&format!(
            "/api/detection_engine/rules/_find?page=1&per_page=2&filter={}",
            urlencode(&rule_filter)
        ))
        .await?;
    recording
        .fixtures
        .push(rule_fixture("rules_find", &flavor, &version, rules_find));
    let name_filter = "alert.attributes.name: \"elasticctl fixture probe\"";
    recording.fixtures.push(rule_exchange_fixture(
        "rules_find_by_name",
        &flavor,
        &version,
        json!({"filter": name_filter}),
        t.get(&format!(
            "/api/detection_engine/rules/_find?page=1&per_page=2&filter={}",
            urlencode(name_filter)
        ))
        .await?,
    ));
    for (name, source_filter) in [
        (
            "rules_find_source_custom",
            format!("alert.attributes.params.immutable: false AND {rule_filter}"),
        ),
        (
            "rules_find_source_prebuilt",
            format!("alert.attributes.params.immutable: true AND {rule_filter}"),
        ),
        (
            "rules_find_source_customized",
            format!("alert.attributes.params.ruleSource.isCustomized: true AND {rule_filter}"),
        ),
    ] {
        let response = t
            .get(&format!(
                "/api/detection_engine/rules/_find?page=1&per_page=2&filter={}",
                urlencode(&source_filter)
            ))
            .await?;
        recording.fixtures.push(rule_exchange_fixture(
            name,
            &flavor,
            &version,
            json!({"filter": source_filter}),
            response,
        ));
    }

    recording.fixtures.push(rule_fixture(
        "rules_get",
        &flavor,
        &version,
        t.get(&format!("/api/detection_engine/rules?rule_id={RULE_ID}"))
            .await?,
    ));
    recording.fixtures.push(rule_fixture(
        "rules_patch",
        &flavor,
        &version,
        t.patch(
            "/api/detection_engine/rules",
            &json!({"rule_id": RULE_ID, "enabled": true}),
        )
        .await?,
    ));
    recording.fixtures.push(rule_fixture(
        "rules_bulk_disable",
        &flavor,
        &version,
        t.post(
            "/api/detection_engine/rules/_bulk_action",
            Some(&json!({"action": "disable", "query": rule_filter})),
        )
        .await?,
    ));

    let preview_body = {
        let mut body = rule_body
            .as_object()
            .cloned()
            .expect("rule body is an object");
        body.remove("rule_id");
        body.insert("invocationCount".into(), json!(1));
        body.insert("timeframeEnd".into(), json!(PREVIEW_TIMEFRAME_END));
        Value::Object(body)
    };
    recording.fixtures.push(preview_fixture(
        "rules_preview",
        &flavor,
        &version,
        t.post("/api/detection_engine/rules/preview", Some(&preview_body))
            .await?,
    ));
    let space = std::env::var("ELASTICCTL_SPACE").unwrap_or_else(|_| "default".into());
    let preview_hits = record_preview_hits(session, &space).await?;
    recording.fixtures.push(preview_exchange_fixture(
        "rules_preview_hits",
        &flavor,
        &version,
        preview_hits.request,
        preview_hits.response,
    ));

    let exception_export_path = format!(
        "/api/exception_lists/_export?id={}&list_id={}&namespace_type={NAMESPACE_TYPE}&include_expired_exceptions=true",
        urlencode(&list_server_id),
        urlencode(LIST_ID)
    );
    let exception_export = t.post_text(&exception_export_path, None).await?;
    let exception_bundle = elasticctl_api::codec::decode_bundle(&exception_export)?;
    if exception_bundle.lists.len() != 1
        || exception_bundle.items.len() != 1
        || exception_bundle.lists[0].list_id()? != LIST_ID
        || exception_bundle.items[0].item_id()? != ITEM_ID
        || exception_bundle.items[0].list_id()? != LIST_ID
    {
        return Err(recording_error(
            "scoped exception export did not contain exactly the marker list and item",
        ));
    }
    let hosts = recording_hosts();
    recording.fixtures.push(response_fixture(
        "exception_list_export",
        &flavor,
        &version,
        json!({"ndjson": scrub_ndjson(&exception_export, &hosts)}),
        None,
    ));
    recording.fixtures.push(rule_exchange_fixture(
        "exception_list_import",
        &flavor,
        &version,
        json!({"overwrite": true, "list_id": LIST_ID, "namespace_type": NAMESPACE_TYPE}),
        t.post_multipart_ndjson(
            "/api/exception_lists/_import?overwrite=true",
            &exception_export,
        )
        .await?,
    ));

    let rule_export = t
        .post_text(
            "/api/detection_engine/rules/_export",
            Some(&json!({"objects": [{"rule_id": RULE_ID}]})),
        )
        .await?;
    let rule_bundle = elasticctl_api::codec::decode_bundle(&rule_export)?;
    if rule_bundle.rules.len() != 1
        || rule_bundle.lists.len() != 1
        || rule_bundle.items.len() != 1
        || rule_bundle.rules[0].rule_id()? != RULE_ID
        || rule_bundle.lists[0].list_id()? != LIST_ID
        || rule_bundle.items[0].item_id()? != ITEM_ID
        || rule_bundle.items[0].list_id()? != LIST_ID
    {
        return Err(recording_error(
            "scoped rule export did not contain exactly the marker rule, list, and item",
        ));
    }
    let scrubbed_rule_export = scrub_ndjson(&rule_export, &hosts);
    recording.fixtures.push(response_fixture(
        "rules_export",
        &flavor,
        &version,
        json!({"ndjson": scrubbed_rule_export.clone()}),
        None,
    ));
    recording.fixtures.push(response_fixture(
        "rules_export_bundle",
        &flavor,
        &version,
        json!({"ndjson": scrubbed_rule_export}),
        None,
    ));
    recording.fixtures.push(rule_exchange_fixture(
        "rules_import_bundle",
        &flavor,
        &version,
        json!({"overwrite": true, "objects": [{"rule_id": RULE_ID}]}),
        t.post_multipart_ndjson(
            "/api/detection_engine/rules/_import?overwrite=true",
            &rule_export,
        )
        .await?,
    ));

    record_trace("search");
    record_search(session, &mut recording, &flavor, &version).await?;
    record_trace("data-views");
    record_data_views(session, &mut recording, &flavor, &version).await?;
    record_trace("dashboards");
    record_dashboards(session, &mut recording, &flavor, &version).await?;
    record_trace("agent-policies");
    record_agent_policies(session, &mut recording, &flavor, &version).await?;
    record_trace("integration-policies");
    record_integration_policies(session, &mut recording, &flavor, &version).await?;
    record_trace("alerts");
    let probe = record_alerts_probe(session, &mut recording, &flavor, &version).await?;
    record_trace("cases");
    record_cases(session, &mut recording, &flavor, &version, &probe).await?;
    record_trace("alerts-close");
    close_and_clean_alerts(
        session.transport,
        &mut recording,
        &flavor,
        &version,
        &probe.id_map,
    )
    .await?;

    Ok(recording)
}

pub(super) async fn record() {
    if let Err(error) = activate_traditional_recorder_profile().await {
        // The activation preflight returns only named local-input errors or a
        // fixed transport-safe context, never server text or credential data.
        eprintln!("record setup failed: {}", error.message);
        std::process::exit(1);
    }
    let transport = transport_from_env(60);
    let mut session = RecordingSession {
        transport: &transport,
        ownership: CleanupOwnership::default(),
    };
    let recorded = record_session(&mut session).await;
    let cleanup = session.cleanup().await;

    let recording = match (recorded, cleanup) {
        (Ok(recording), Ok(cleanup)) => {
            if let Some(rule) = cleanup.rule {
                let flavor = recording
                    .fixtures
                    .first()
                    .and_then(|fixture| fixture.document["flavor"].as_str())
                    .unwrap_or("default")
                    .to_string();
                let version = recording
                    .fixtures
                    .first()
                    .and_then(|fixture| fixture.document["version"].as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let mut recording = recording;
                recording
                    .fixtures
                    .push(rule_fixture("rules_delete", &flavor, &version, rule));
                recording
            } else {
                recording
            }
        }
        (Err(record_error), Ok(_)) => {
            eprintln!("record failed after cleanup: {}", record_error.message);
            std::process::exit(1);
        }
        (Ok(_), Err(cleanup_error)) => {
            eprintln!("record cleanup failed: {}", cleanup_error.message);
            std::process::exit(1);
        }
        (Err(record_error), Err(cleanup_error)) => {
            eprintln!(
                "record failed after cleanup: {}; cleanup also failed: {}",
                record_error.message, cleanup_error.message
            );
            std::process::exit(1);
        }
    };

    let flavor = recording
        .fixtures
        .first()
        .and_then(|fixture| fixture.document["flavor"].as_str())
        .unwrap_or("default")
        .to_string();
    let version = recording
        .fixtures
        .first()
        .and_then(|fixture| fixture.document["version"].as_str())
        .unwrap_or("unknown")
        .to_string();
    if let Err(error) = write_recording(recording) {
        eprintln!("record failed after cleanup: {}", error.message);
        std::process::exit(1);
    }
    println!("recorded {flavor} {version}");
}

#[cfg(test)]
pub(crate) mod test_support {

    use crate::recorder::integration::inputs::{
        marker_integration_create_body, marker_integration_create_body_with_nonce_and_inputs,
        marker_integration_parent_create_body, marker_integration_update_body,
        marker_integration_update_body_with_nonce_and_inputs,
    };
    use crate::recorder::markers::{
        INTEGRATION_POLICY_DESCRIPTION, INTEGRATION_POLICY_DUP_ID, INTEGRATION_POLICY_ID,
        INTEGRATION_POLICY_NAME, INTEGRATION_POLICY_NAMESPACE, INTEGRATION_POLICY_PACKAGE,
        INTEGRATION_POLICY_PARENT_ID, INTEGRATION_POLICY_PARENT_NAME,
        INTEGRATION_POLICY_UPDATED_DESCRIPTION, TEST_INTEGRATION_RECORDING_NONCE,
    };

    use crate::recorder::markers::{
        marker_integration_description, marker_integration_parent_description,
        nonce_bearing_integration_description,
    };
    use crate::recorder::session::CleanupOwnership;
    use serde_json::{Map, Value, json};

    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub(crate) fn mock_transport(server: &MockServer) -> elasticctl_core::Transport {
        elasticctl_core::Transport::new(&elasticctl_core::Profile {
            kibana_url: server.uri(),
            es_url: Some(server.uri()),
            api_key: Some("test".into()),
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 5,
        })
        .expect("transport")
    }

    pub(crate) fn installed_system_inventory() -> Value {
        json!({
            "items": [{
                "name": INTEGRATION_POLICY_PACKAGE,
                "status": "installed",
                "version": "2.0.0"
            }],
            "total": 1
        })
    }

    pub(crate) fn installed_system_status() -> Value {
        json!({
            "item": {
                "name": INTEGRATION_POLICY_PACKAGE,
                "version": "2.0.0",
                "status": "installed",
                "installationInfo": {"version": "2.0.0"}
            }
        })
    }

    pub(crate) fn system_package_metadata() -> Value {
        json!({
            "item": {
                "name": INTEGRATION_POLICY_PACKAGE,
                "version": "2.0.0",
                "status": "installed",
                "vars": [],
                "policy_templates": []
            }
        })
    }

    pub(crate) fn integration_package_metadata_fixture(
        package: &str,
        templates: Value,
        data_streams: Value,
    ) -> Value {
        json!({
            "item": {
                "name": package,
                "version": "1.0.0",
                "status": "installed",
                "vars": [],
                "policy_templates": templates,
                "data_streams": data_streams
            }
        })
    }

    pub(crate) const OTHER_INTEGRATION_RECORDING_NONCE: &str = "other-integration-recording-nonce";

    pub(crate) fn marker_integration_response_with_nonce(description: &str, nonce: &str) -> Value {
        json!({
            "item": {
                "id": INTEGRATION_POLICY_ID,
                "name": INTEGRATION_POLICY_NAME,
                "namespace": "default",
                "description": nonce_bearing_integration_description(description, nonce),
                "policy_ids": [INTEGRATION_POLICY_PARENT_ID],
                "package": {"name": INTEGRATION_POLICY_PACKAGE, "version": "2.0.0"},
                "inputs": {},
                "enabled": true
            }
        })
    }

    pub(crate) fn marker_integration_response(description: &str) -> Value {
        marker_integration_response_with_nonce(description, TEST_INTEGRATION_RECORDING_NONCE)
    }

    pub(crate) fn materialized_marker_inputs() -> serde_json::Map<String, Value> {
        serde_json::Map::from_iter([("system-log".to_string(), json!({"enabled": true}))])
    }

    pub(crate) fn marker_integration_response_with_inputs(
        description: &str,
        nonce: &str,
        inputs: &serde_json::Map<String, Value>,
    ) -> Value {
        let mut response = marker_integration_response_with_nonce(description, nonce);
        response["item"]["inputs"] = Value::Object(inputs.clone());
        response
    }

    pub(crate) fn materialized_system_package_metadata() -> Value {
        json!({
            "item": {
                "name": INTEGRATION_POLICY_PACKAGE,
                "version": "2.0.0",
                "status": "installed",
                "vars": [],
                "policy_templates": [{
                    "name": "system",
                    "inputs": [{"type": "log", "vars": []}]
                }],
                "data_streams": []
            }
        })
    }

    pub(crate) fn materialized_bootstrap_item(inputs: &Map<String, Value>) -> Map<String, Value> {
        marker_integration_response_with_inputs(
            INTEGRATION_POLICY_DESCRIPTION,
            TEST_INTEGRATION_RECORDING_NONCE,
            inputs,
        )["item"]
            .as_object()
            .expect("marker response item")
            .clone()
    }

    pub(crate) fn exported_marker_spec(
        inputs: Map<String, Value>,
    ) -> elasticctl_api::fleet::integration_policies::IntegrationPolicySpec {
        elasticctl_api::fleet::integration_policies::IntegrationPolicySpec::try_from(json!({
            "id": INTEGRATION_POLICY_ID,
            "name": INTEGRATION_POLICY_NAME,
            "description": marker_integration_description(TEST_INTEGRATION_RECORDING_NONCE),
            "namespace": INTEGRATION_POLICY_NAMESPACE,
            "policy_ids": [INTEGRATION_POLICY_PARENT_ID],
            "package": {"name": INTEGRATION_POLICY_PACKAGE, "version": "2.0.0"},
            "inputs": inputs,
        }))
        .expect("test exported integration policy")
    }

    pub(crate) fn marker_integration_parent_response_with_nonce(nonce: &str) -> Value {
        json!({
            "item": {
                "id": INTEGRATION_POLICY_PARENT_ID,
                "name": INTEGRATION_POLICY_PARENT_NAME,
                "namespace": "default",
                "description": marker_integration_parent_description(nonce),
                "monitoring_enabled": [],
                "inactivity_timeout": 1_209_600,
                "agents": 0
            }
        })
    }

    pub(crate) fn marker_integration_parent_response() -> Value {
        marker_integration_parent_response_with_nonce(TEST_INTEGRATION_RECORDING_NONCE)
    }

    pub(crate) fn integration_cleanup_ownership() -> CleanupOwnership {
        CleanupOwnership {
            integration_package_inventory: Some(std::collections::BTreeSet::from([(
                INTEGRATION_POLICY_PACKAGE.to_string(),
                "2.0.0".to_string(),
            )])),
            integration_system_package_version: Some("2.0.0".to_string()),
            integration_recording_nonce: Some(TEST_INTEGRATION_RECORDING_NONCE.to_string()),
            ..Default::default()
        }
    }

    pub(crate) fn merge_marker_item_fields(response: &mut Value, fields: &Value) {
        let item = response["item"]
            .as_object_mut()
            .expect("marker response item is an object");
        for (field, value) in fields.as_object().expect("marker field patch is an object") {
            item.insert(field.clone(), value.clone());
        }
    }

    pub(crate) fn unsafe_marker_integration_fields() -> Vec<(&'static str, Value)> {
        vec![
            ("managed", json!({"is_managed": true})),
            ("agentless", json!({"supports_agentless": true})),
            (
                "cloud connector support",
                json!({"supports_cloud_connector": true}),
            ),
            ("output reference", json!({"output_id": "foreign-output"})),
            (
                "cloud connector id",
                json!({"cloud_connector_id": "foreign-connector"}),
            ),
            (
                "cloud connector name",
                json!({"cloud_connector_name": "foreign-connector"}),
            ),
            (
                "inconsistent deprecated parent id",
                json!({"policy_id": "foreign-parent"}),
            ),
            ("malformed deprecated parent id", json!({"policy_id": {}})),
            (
                "secret references",
                json!({"secret_references": [{"id": "foreign-secret"}]}),
            ),
            (
                "malformed secret references",
                json!({"secret_references": {"id": "foreign-secret"}}),
            ),
            ("cross-space camel case", json!({"spaceIds": ["other"]})),
            ("malformed camel case spaces", json!({"spaceIds": {}})),
            ("cross-space snake case", json!({"space_ids": ["other"]})),
            ("malformed snake case spaces", json!({"space_ids": {}})),
            ("disabled", json!({"enabled": false})),
            ("variables", json!({"vars": {"token": "foreign"}})),
            ("malformed variables", json!({"vars": []})),
            (
                "variable group selections",
                json!({"var_group_selections": {"group": "foreign"}}),
            ),
            (
                "malformed variable group selections",
                json!({"var_group_selections": []}),
            ),
            ("condition", json!({"condition": "host.name == 'foreign'"})),
            ("malformed condition", json!({"condition": {}})),
            (
                "additional permissions",
                json!({"additional_datastreams_permissions": ["foreign"]}),
            ),
            (
                "malformed additional permissions",
                json!({"additional_datastreams_permissions": {}}),
            ),
            (
                "global data tags",
                json!({"global_data_tags": [{"name": "foreign"}]}),
            ),
            (
                "malformed global data tags",
                json!({"global_data_tags": {}}),
            ),
        ]
    }

    pub(crate) fn unsafe_marker_parent_fields() -> Vec<(&'static str, Value)> {
        let mut fields = vec![
            ("default policy", "is_default"),
            ("default Fleet Server policy", "is_default_fleet_server"),
            ("Fleet Server policy", "has_fleet_server"),
            ("managed parent", "is_managed"),
            ("preconfigured parent", "is_preconfigured"),
            ("agentless parent", "supports_agentless"),
            ("verifier parent", "is_verifier"),
            ("protected parent", "is_protected"),
        ]
        .into_iter()
        .map(|(label, field)| (label, json!({field: true})))
        .collect::<Vec<_>>();
        fields.extend([
            ("agentless configuration", json!({"agentless": {}})),
            (
                "data output reference",
                json!({"data_output_id": "foreign-output"}),
            ),
            (
                "monitoring output reference",
                json!({"monitoring_output_id": "foreign-output"}),
            ),
            (
                "download source reference",
                json!({"download_source_id": "foreign-source"}),
            ),
            (
                "Fleet Server host reference",
                json!({"fleet_server_host_id": "foreign-host"}),
            ),
            ("required versions", json!({"required_versions": []})),
            ("attached agents", json!({"agents": 1})),
            ("cross-space parent", json!({"space_ids": ["other"]})),
            ("malformed parent spaces", json!({"space_ids": {}})),
            ("cross-space camel parent", json!({"spaceIds": ["other"]})),
            ("malformed camel parent spaces", json!({"spaceIds": {}})),
            (
                "parent global data tags",
                json!({"global_data_tags": [{"name": "foreign"}]}),
            ),
            (
                "malformed parent global data tags",
                json!({"global_data_tags": {}}),
            ),
            (
                "agent features",
                json!({"agent_features": [{"name": "foreign", "enabled": true}]}),
            ),
            ("malformed agent features", json!({"agent_features": {}})),
            (
                "advanced settings",
                json!({"advanced_settings": {"token": "foreign"}}),
            ),
            (
                "malformed advanced settings",
                json!({"advanced_settings": []}),
            ),
            ("overrides", json!({"overrides": {"token": "foreign"}})),
            ("malformed overrides", json!({"overrides": []})),
            (
                "keep monitoring alive",
                json!({"keep_monitoring_alive": true}),
            ),
            (
                "malformed keep monitoring alive",
                json!({"keep_monitoring_alive": {}}),
            ),
            (
                "monitoring pprof",
                json!({"monitoring_pprof_enabled": true}),
            ),
            (
                "malformed monitoring pprof",
                json!({"monitoring_pprof_enabled": {}}),
            ),
            (
                "monitoring http",
                json!({"monitoring_http": {"token": "foreign"}}),
            ),
            ("malformed monitoring http", json!({"monitoring_http": []})),
            (
                "monitoring diagnostics",
                json!({"monitoring_diagnostics": {"token": "foreign"}}),
            ),
            (
                "malformed monitoring diagnostics",
                json!({"monitoring_diagnostics": []}),
            ),
            ("unenroll timeout", json!({"unenroll_timeout": 1})),
            (
                "malformed unenroll timeout",
                json!({"unenroll_timeout": false}),
            ),
        ]);
        fields
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum IntegrationLifecycleFailure {
        None,
        Update,
        Delete,
        ParentDelete,
        DuplicateCreate,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum IntegrationCreatePreflightDrift {
        BootstrapMissing,
        BootstrapMalformed,
        BootstrapMetadataNotInstalled,
        RecordedVersionChanged,
        DuplicateInventoryChanged,
        DuplicateInventoryReadFailure,
    }

    #[derive(Clone, Copy, Debug)]
    pub(crate) enum BootstrapExportFailure {
        Transport,
        Secret,
        SensitiveName,
        ChangedNormalizedInputs,
    }

    pub(crate) async fn mount_bootstrap_export_failure_lifecycle(
        server: &MockServer,
        failure: BootstrapExportFailure,
    ) {
        let mut bootstrap_inputs = materialized_marker_inputs();
        if matches!(failure, BootstrapExportFailure::Secret) {
            bootstrap_inputs.insert(
                "system-log".to_string(),
                json!({"enabled": true, "vars": {"cert": "private-bootstrap-secret"}}),
            );
        }
        if matches!(failure, BootstrapExportFailure::SensitiveName) {
            bootstrap_inputs.insert(
                "system-log".to_string(),
                json!({"enabled": true, "access_token": "private-bootstrap-value"}),
            );
        }
        let mut export_inputs = bootstrap_inputs.clone();
        if matches!(failure, BootstrapExportFailure::ChangedNormalizedInputs) {
            export_inputs.insert("system-log".to_string(), json!({"enabled": false}));
        }
        let metadata = if matches!(failure, BootstrapExportFailure::Secret) {
            json!({
                "item": {
                    "name": INTEGRATION_POLICY_PACKAGE,
                    "version": "2.0.0",
                    "status": "installed",
                    "vars": [],
                    "policy_templates": [{
                        "name": "system",
                        "inputs": [{
                            "type": "log",
                            "vars": [{"name": "cert", "secret": true}]
                        }]
                    }],
                    "data_streams": []
                }
            })
        } else {
            materialized_system_package_metadata()
        };
        let primary_exists = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let primary_exists_for_reads = primary_exists.clone();
        let live_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let live_reads_for_response = live_reads.clone();
        let bootstrap_inputs_for_reads = bootstrap_inputs.clone();
        let export_inputs_for_reads = export_inputs.clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                if !primary_exists_for_reads.load(std::sync::atomic::Ordering::SeqCst) {
                    return ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}));
                }
                let read =
                    live_reads_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let inputs = if matches!(failure, BootstrapExportFailure::ChangedNormalizedInputs)
                    && read == 1
                {
                    &export_inputs_for_reads
                } else {
                    &bootstrap_inputs_for_reads
                };
                ResponseTemplate::new(200).set_body_json(marker_integration_response_with_inputs(
                    INTEGRATION_POLICY_DESCRIPTION,
                    TEST_INTEGRATION_RECORDING_NONCE,
                    inputs,
                ))
            })
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_DUP_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})))
            .mount(server)
            .await;

        let parent_exists = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let parent_exists_for_reads = parent_exists.clone();
        let primary_exists_for_parent_reads = primary_exists.clone();
        let detached_parent_seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let detached_parent_seen_for_reads = detached_parent_seen.clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                if !parent_exists_for_reads.load(std::sync::atomic::Ordering::SeqCst) {
                    return ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}));
                }
                let attached =
                    primary_exists_for_parent_reads.load(std::sync::atomic::Ordering::SeqCst);
                if !attached {
                    detached_parent_seen_for_reads.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                let mut parent = marker_integration_parent_response();
                parent["item"]["package_policies"] = if attached {
                    json!([INTEGRATION_POLICY_ID])
                } else {
                    json!([])
                };
                ResponseTemplate::new(200).set_body_json(parent)
            })
            .mount(server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortOrder", "asc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_inventory()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_status()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(if matches!(failure, BootstrapExportFailure::Transport) {
                ResponseTemplate::new(500).set_body_json(json!({
                    "message": "private bootstrap export transport body"
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "version": {"number": "9.6.0", "build_flavor": "serverless"}
                }))
            })
            .expect(if matches!(failure, BootstrapExportFailure::Transport) {
                3
            } else {
                1
            })
            .mount(server)
            .await;

        let parent_exists_for_create = parent_exists.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies"))
            .and(query_param("sys_monitoring", "false"))
            .and(body_json(marker_integration_parent_create_body()))
            .respond_with(move |_: &wiremock::Request| {
                parent_exists_for_create.store(true, std::sync::atomic::Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(marker_integration_parent_response())
            })
            .expect(1)
            .mount(server)
            .await;
        let primary_exists_for_create = primary_exists.clone();
        let bootstrap_inputs_for_create = bootstrap_inputs.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(marker_integration_create_body("2.0.0")))
            .respond_with(move |_: &wiremock::Request| {
                primary_exists_for_create.store(true, std::sync::atomic::Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(marker_integration_response_with_inputs(
                    INTEGRATION_POLICY_DESCRIPTION,
                    TEST_INTEGRATION_RECORDING_NONCE,
                    &bootstrap_inputs_for_create,
                ))
            })
            .expect(1)
            .mount(server)
            .await;
        let primary_exists_for_delete = primary_exists.clone();
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                primary_exists_for_delete.store(false, std::sync::atomic::Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(json!({"id": INTEGRATION_POLICY_ID}))
            })
            .expect(1)
            .mount(server)
            .await;
        let parent_exists_for_delete = parent_exists.clone();
        let primary_exists_for_parent_delete = primary_exists.clone();
        let detached_parent_seen_for_delete = detached_parent_seen.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies/delete"))
            .and(body_json(
                json!({"agentPolicyId": INTEGRATION_POLICY_PARENT_ID}),
            ))
            .respond_with(move |_: &wiremock::Request| {
                if primary_exists_for_parent_delete.load(std::sync::atomic::Ordering::SeqCst)
                    || !detached_parent_seen_for_delete.load(std::sync::atomic::Ordering::SeqCst)
                {
                    return ResponseTemplate::new(409).set_body_json(json!({"statusCode": 409}));
                }
                parent_exists_for_delete.store(false, std::sync::atomic::Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(json!({
                    "id": INTEGRATION_POLICY_PARENT_ID,
                    "name": INTEGRATION_POLICY_PARENT_NAME,
                }))
            })
            .expect(1)
            .mount(server)
            .await;
    }

    pub(crate) async fn mount_integration_lifecycle(
        server: &MockServer,
        failure: IntegrationLifecycleFailure,
    ) {
        let _ = mount_integration_lifecycle_with_recorded_create(server, failure, None, None, None)
            .await;
    }

    pub(crate) async fn mount_integration_lifecycle_with_recorded_create(
        server: &MockServer,
        failure: IntegrationLifecycleFailure,
        ambiguous_recorded_create: Option<(AmbiguousCreateOutcome, String)>,
        concurrent_duplicate_nonce: Option<String>,
        create_preflight_drift: Option<IntegrationCreatePreflightDrift>,
    ) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        let inputs = materialized_marker_inputs();
        let policy_state = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let parent_exists = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let parent_foreign = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let duplicate_exists = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let bootstrap_deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let duplicate_preflight_ready =
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let duplicate_inventory_drift_served =
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": {"number": "9.6.0", "build_flavor": "serverless"}
            })))
            .expect(
                if matches!(
                    create_preflight_drift,
                    Some(
                        IntegrationCreatePreflightDrift::BootstrapMissing
                            | IntegrationCreatePreflightDrift::BootstrapMalformed
                            | IntegrationCreatePreflightDrift::BootstrapMetadataNotInstalled
                    )
                ) {
                    0
                } else {
                    1
                },
            )
            .mount(server)
            .await;
        let duplicate_preflight_ready_for_inventory = duplicate_preflight_ready.clone();
        let duplicate_inventory_drift_served_for_inventory =
            duplicate_inventory_drift_served.clone();
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortOrder", "asc"))
            .respond_with(move |_: &wiremock::Request| {
                match create_preflight_drift {
                    Some(IntegrationCreatePreflightDrift::DuplicateInventoryChanged)
                        if duplicate_preflight_ready_for_inventory
                            .load(std::sync::atomic::Ordering::SeqCst)
                            && !duplicate_inventory_drift_served_for_inventory
                                .swap(true, std::sync::atomic::Ordering::SeqCst) =>
                    {
                        ResponseTemplate::new(200).set_body_json(json!({
                            "items": [
                                {"name": "endpoint", "status": "installed", "version": "8.0.0"},
                                {"name": INTEGRATION_POLICY_PACKAGE, "status": "installed", "version": "2.0.0"}
                            ],
                            "total": 2
                        }))
                    }
                    Some(IntegrationCreatePreflightDrift::DuplicateInventoryReadFailure)
                        if duplicate_preflight_ready_for_inventory
                            .load(std::sync::atomic::Ordering::SeqCst) =>
                    {
                        ResponseTemplate::new(500).set_body_json(json!({"statusCode": 500}))
                    }
                    _ => ResponseTemplate::new(200).set_body_json(installed_system_inventory()),
                }
            })
            .mount(server)
            .await;
        let parent_exists_for_status = parent_exists.clone();
        let bootstrap_deleted_for_status = bootstrap_deleted.clone();
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(move |_: &wiremock::Request| match create_preflight_drift {
                Some(IntegrationCreatePreflightDrift::BootstrapMissing)
                    if parent_exists_for_status.load(std::sync::atomic::Ordering::SeqCst)
                        && !bootstrap_deleted_for_status
                            .load(std::sync::atomic::Ordering::SeqCst) =>
                {
                    ResponseTemplate::new(200).set_body_json(json!({"item": {
                        "name": INTEGRATION_POLICY_PACKAGE,
                        "version": "2.0.0",
                        "status": "not_installed"
                    }}))
                }
                Some(IntegrationCreatePreflightDrift::BootstrapMalformed)
                    if parent_exists_for_status.load(std::sync::atomic::Ordering::SeqCst)
                        && !bootstrap_deleted_for_status
                            .load(std::sync::atomic::Ordering::SeqCst) =>
                {
                    ResponseTemplate::new(200).set_body_json(json!({"item": {
                        "name": INTEGRATION_POLICY_PACKAGE,
                        "version": "2.0.0",
                        "status": "installed"
                    }}))
                }
                Some(IntegrationCreatePreflightDrift::RecordedVersionChanged)
                    if bootstrap_deleted_for_status.load(std::sync::atomic::Ordering::SeqCst) =>
                {
                    ResponseTemplate::new(200).set_body_json(json!({"item": {
                        "name": INTEGRATION_POLICY_PACKAGE,
                        "version": "2.1.0",
                        "status": "installed",
                        "installationInfo": {"version": "2.1.0"}
                    }}))
                }
                _ => ResponseTemplate::new(200).set_body_json(installed_system_status()),
            })
            .mount(server)
            .await;
        let metadata = if matches!(
            create_preflight_drift,
            Some(IntegrationCreatePreflightDrift::BootstrapMetadataNotInstalled)
        ) {
            let mut metadata = materialized_system_package_metadata();
            metadata["item"]["status"] = json!("not_installed");
            metadata
        } else {
            materialized_system_package_metadata()
        };
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(server)
            .await;

        let primary_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let primary_reads_for_response = primary_reads.clone();
        let policy_state_for_reads = policy_state.clone();
        let inputs_for_reads = inputs.clone();
        let foreign_inputs = inputs.clone();
        let ambiguous_for_reads = ambiguous_recorded_create.clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                primary_reads_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                match policy_state_for_reads.load(std::sync::atomic::Ordering::SeqCst) {
                    0 | 4 => ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})),
                    1 | 2 => ResponseTemplate::new(200).set_body_json(
                        marker_integration_response_with_inputs(
                            INTEGRATION_POLICY_DESCRIPTION,
                            TEST_INTEGRATION_RECORDING_NONCE,
                            &inputs_for_reads,
                        ),
                    ),
                    3 => ResponseTemplate::new(200).set_body_json(
                        marker_integration_response_with_inputs(
                            INTEGRATION_POLICY_UPDATED_DESCRIPTION,
                            TEST_INTEGRATION_RECORDING_NONCE,
                            &inputs_for_reads,
                        ),
                    ),
                    5 => ResponseTemplate::new(200).set_body_json(
                        marker_integration_response_with_inputs(
                            INTEGRATION_POLICY_UPDATED_DESCRIPTION,
                            OTHER_INTEGRATION_RECORDING_NONCE,
                            &foreign_inputs,
                        ),
                    ),
                    6 => {
                        let (_, winner_nonce) = ambiguous_for_reads
                            .as_ref()
                            .expect("state 6 is only used by an ambiguous recorded create");
                        ResponseTemplate::new(200).set_body_json(
                            marker_integration_response_with_inputs(
                                INTEGRATION_POLICY_DESCRIPTION,
                                winner_nonce,
                                &inputs_for_reads,
                            ),
                        )
                    }
                    _ => ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})),
                }
            })
            .mount(server)
            .await;
        let duplicate_exists_for_reads = duplicate_exists.clone();
        let duplicate_nonce_for_reads = concurrent_duplicate_nonce.clone();
        let inputs_for_duplicate_reads = inputs.clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_DUP_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                let Some(nonce) = duplicate_nonce_for_reads.as_deref() else {
                    return ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}));
                };
                if !duplicate_exists_for_reads.load(std::sync::atomic::Ordering::SeqCst) {
                    return ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}));
                }
                let mut duplicate = marker_integration_response_with_inputs(
                    INTEGRATION_POLICY_DESCRIPTION,
                    nonce,
                    &inputs_for_duplicate_reads,
                );
                duplicate["item"]["id"] = json!(INTEGRATION_POLICY_DUP_ID);
                ResponseTemplate::new(200).set_body_json(duplicate)
            })
            .mount(server)
            .await;

        let parent_exists_for_reads = parent_exists.clone();
        let parent_foreign_for_reads = parent_foreign.clone();
        let policy_state_for_parent_reads = policy_state.clone();
        let duplicate_exists_for_parent_reads = duplicate_exists.clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                if !parent_exists_for_reads.load(std::sync::atomic::Ordering::SeqCst) {
                    return ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}));
                }
                let mut parent = if parent_foreign_for_reads
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    marker_integration_parent_response_with_nonce(OTHER_INTEGRATION_RECORDING_NONCE)
                } else {
                    marker_integration_parent_response()
                };
                let mut attachments =
                    match policy_state_for_parent_reads.load(std::sync::atomic::Ordering::SeqCst) {
                        0 | 4 => Vec::new(),
                        _ => vec![Value::String(INTEGRATION_POLICY_ID.to_string())],
                    };
                if duplicate_exists_for_parent_reads.load(std::sync::atomic::Ordering::SeqCst) {
                    attachments.push(Value::String(INTEGRATION_POLICY_DUP_ID.to_string()));
                }
                parent["item"]["package_policies"] = Value::Array(attachments);
                ResponseTemplate::new(200).set_body_json(parent)
            })
            .mount(server)
            .await;
        let parent_exists_for_create = parent_exists.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies"))
            .and(query_param("sys_monitoring", "false"))
            .and(body_json(marker_integration_parent_create_body()))
            .respond_with(move |_: &wiremock::Request| {
                parent_exists_for_create.store(true, std::sync::atomic::Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(marker_integration_parent_response())
            })
            .mount(server)
            .await;

        let bootstrap_state = policy_state.clone();
        let inputs_for_bootstrap = inputs.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(marker_integration_create_body("2.0.0")))
            .respond_with(move |_: &wiremock::Request| {
                assert_eq!(
                    bootstrap_state.swap(1, std::sync::atomic::Ordering::SeqCst),
                    0,
                    "bootstrap must be the first primary create"
                );
                ResponseTemplate::new(200).set_body_json(marker_integration_response_with_inputs(
                    INTEGRATION_POLICY_DESCRIPTION,
                    TEST_INTEGRATION_RECORDING_NONCE,
                    &inputs_for_bootstrap,
                ))
            })
            .mount(server)
            .await;
        let recorded_body = marker_integration_create_body_with_nonce_and_inputs(
            "2.0.0",
            TEST_INTEGRATION_RECORDING_NONCE,
            &inputs,
        );
        let recorded_state = policy_state.clone();
        let inputs_for_recorded = inputs.clone();
        let ambiguous_for_recorded = ambiguous_recorded_create.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(recorded_body.clone()))
            .respond_with(move |_: &wiremock::Request| {
                assert_eq!(
                    recorded_state.swap(2, std::sync::atomic::Ordering::SeqCst),
                    0,
                    "recorded create must follow bootstrap absence"
                );
                if let Some((outcome, winner_nonce)) = &ambiguous_for_recorded {
                    recorded_state.store(6, std::sync::atomic::Ordering::SeqCst);
                    return ambiguous_create_response(
                        *outcome,
                        marker_integration_response_with_inputs(
                            INTEGRATION_POLICY_DESCRIPTION,
                            winner_nonce,
                            &inputs_for_recorded,
                        )["item"]
                            .clone(),
                    );
                }
                ResponseTemplate::new(200).set_body_json(marker_integration_response_with_inputs(
                    INTEGRATION_POLICY_DESCRIPTION,
                    TEST_INTEGRATION_RECORDING_NONCE,
                    &inputs_for_recorded,
                ))
            })
            .mount(server)
            .await;
        let mut duplicate_body = recorded_body;
        duplicate_body["id"] = json!(INTEGRATION_POLICY_DUP_ID);
        let duplicate_exists_for_create = duplicate_exists.clone();
        let concurrent_duplicate_for_create = concurrent_duplicate_nonce.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(duplicate_body))
            .respond_with(move |_: &wiremock::Request| {
                if concurrent_duplicate_for_create.is_some() {
                    duplicate_exists_for_create.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                if failure == IntegrationLifecycleFailure::DuplicateCreate {
                    ResponseTemplate::new(500).set_body_json(json!({
                        "message": "private POST duplicate integration identity"
                    }))
                } else {
                    ResponseTemplate::new(409).set_body_json(json!({
                        "statusCode": 409,
                        "message": "marker integration name already exists"
                    }))
                }
            })
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("page", "1"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortField", "created_at"))
            .and(query_param("sortOrder", "asc"))
            .and(query_param("format", "simplified"))
            .respond_with({
                let policy_state_for_list = policy_state.clone();
                let inputs_for_list = inputs.clone();
                let duplicate_preflight_ready_for_list = duplicate_preflight_ready.clone();
                move |_: &wiremock::Request| {
                    assert_eq!(
                        policy_state_for_list.load(std::sync::atomic::Ordering::SeqCst),
                        2,
                        "the list must read the recorded marker"
                    );
                    duplicate_preflight_ready_for_list
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    ResponseTemplate::new(200).set_body_json(json!({
                        "items": [marker_integration_response_with_inputs(
                            INTEGRATION_POLICY_DESCRIPTION,
                            TEST_INTEGRATION_RECORDING_NONCE,
                            &inputs_for_list,
                        )["item"].clone()],
                        "total": 1,
                        "page": 1,
                        "perPage": 1000,
                    }))
                }
            })
            .mount(server)
            .await;

        let update_state = policy_state.clone();
        let inputs_for_update = inputs.clone();
        Mock::given(method("PUT"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .and(body_json(
                marker_integration_update_body_with_nonce_and_inputs(
                    "2.0.0",
                    TEST_INTEGRATION_RECORDING_NONCE,
                    &inputs,
                ),
            ))
            .respond_with(move |_: &wiremock::Request| {
                assert_eq!(
                    update_state.load(std::sync::atomic::Ordering::SeqCst),
                    2,
                    "update must preserve the recorded marker state"
                );
                if failure == IntegrationLifecycleFailure::Update {
                    update_state.store(5, std::sync::atomic::Ordering::SeqCst);
                    ResponseTemplate::new(500).set_body_json(json!({
                        "message": "private PUT integration policy identity"
                    }))
                } else {
                    update_state.store(3, std::sync::atomic::Ordering::SeqCst);
                    ResponseTemplate::new(200).set_body_json(
                        marker_integration_response_with_inputs(
                            INTEGRATION_POLICY_UPDATED_DESCRIPTION,
                            TEST_INTEGRATION_RECORDING_NONCE,
                            &inputs_for_update,
                        ),
                    )
                }
            })
            .mount(server)
            .await;

        let policy_state_for_parent_delete = policy_state.clone();
        let parent_exists_for_delete = parent_exists.clone();
        let parent_foreign_for_delete = parent_foreign.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies/delete"))
            .and(body_json(
                json!({"agentPolicyId": INTEGRATION_POLICY_PARENT_ID}),
            ))
            .respond_with(move |_: &wiremock::Request| {
                if failure == IntegrationLifecycleFailure::ParentDelete {
                    parent_foreign_for_delete.store(true, std::sync::atomic::Ordering::SeqCst);
                    ResponseTemplate::new(500).set_body_json(json!({
                        "message": "private POST parent delete identity"
                    }))
                } else if matches!(
                    policy_state_for_parent_delete.load(std::sync::atomic::Ordering::SeqCst),
                    0 | 4
                ) {
                    parent_exists_for_delete.store(false, std::sync::atomic::Ordering::SeqCst);
                    ResponseTemplate::new(200).set_body_json(json!({
                        "id": INTEGRATION_POLICY_PARENT_ID,
                        "name": INTEGRATION_POLICY_PARENT_NAME,
                    }))
                } else {
                    ResponseTemplate::new(409).set_body_json(json!({"statusCode": 409}))
                }
            })
            .mount(server)
            .await;

        let delete_state = policy_state.clone();
        let bootstrap_deleted_for_delete = bootstrap_deleted.clone();
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                match delete_state.load(std::sync::atomic::Ordering::SeqCst) {
                    1 => {
                        delete_state.store(0, std::sync::atomic::Ordering::SeqCst);
                        bootstrap_deleted_for_delete
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        ResponseTemplate::new(200)
                            .set_body_json(json!({"id": INTEGRATION_POLICY_ID}))
                    }
                    3 if failure == IntegrationLifecycleFailure::Delete => {
                        delete_state.store(5, std::sync::atomic::Ordering::SeqCst);
                        ResponseTemplate::new(500).set_body_json(json!({
                            "message": "private DELETE integration policy identity"
                        }))
                    }
                    2 | 3 | 6 => {
                        delete_state.store(4, std::sync::atomic::Ordering::SeqCst);
                        ResponseTemplate::new(200)
                            .set_body_json(json!({"id": INTEGRATION_POLICY_ID}))
                    }
                    _ => ResponseTemplate::new(409).set_body_json(json!({"statusCode": 409})),
                }
            })
            .mount(server)
            .await;

        primary_reads
    }

    #[derive(Clone, Copy, Debug)]
    pub(crate) enum IntegrationLifecycleSwap {
        Update,
        IntegrationDelete,
        FinalParentDelete,
    }

    /// This mock schedule contains the revalidation reads the normal lifecycle
    /// must make before each destructive mutation. With the old lifecycle, the
    /// swapped response arrives only after the unsafe write; with the fixed
    /// lifecycle, it arrives immediately before the write and stops it.
    pub(crate) async fn mount_integration_lifecycle_with_revalidation_changes(
        server: &MockServer,
        swap: IntegrationLifecycleSwap,
        integration_fields: &Value,
        parent_fields: &Value,
        integration_response_override: Option<Value>,
        parent_response_override: Option<Value>,
    ) {
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortOrder", "asc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_inventory()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_status()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(system_package_metadata()))
            .mount(server)
            .await;

        let integration_deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let integration_deleted_for_reads = integration_deleted.clone();
        let integration_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let integration_reads_for_response = integration_reads.clone();
        let integration = marker_integration_response(INTEGRATION_POLICY_DESCRIPTION);
        let updated = marker_integration_response(INTEGRATION_POLICY_UPDATED_DESCRIPTION);
        let mut swapped_integration = marker_integration_response(INTEGRATION_POLICY_DESCRIPTION);
        merge_marker_item_fields(&mut swapped_integration, integration_fields);
        let swapped_integration = integration_response_override.unwrap_or(swapped_integration);
        let integration_swap_at = match swap {
            IntegrationLifecycleSwap::Update => Some(2),
            IntegrationLifecycleSwap::IntegrationDelete => Some(4),
            IntegrationLifecycleSwap::FinalParentDelete => None,
        };
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                let read = integration_reads_for_response
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if integration_swap_at == Some(read) {
                    return ResponseTemplate::new(200).set_body_json(swapped_integration.clone());
                }
                match read {
                    0 => ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})),
                    1 | 2 => ResponseTemplate::new(200).set_body_json(integration.clone()),
                    3 | 4 => ResponseTemplate::new(200).set_body_json(updated.clone()),
                    5 if integration_deleted_for_reads
                        .load(std::sync::atomic::Ordering::SeqCst) =>
                    {
                        ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}))
                    }
                    _ => ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})),
                }
            })
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_DUP_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})))
            .mount(server)
            .await;

        let parent_deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let parent_deleted_for_reads = parent_deleted.clone();
        let integration_deleted_for_parent_reads = integration_deleted.clone();
        let parent_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let parent_reads_for_response = parent_reads.clone();
        let mut attached_parent = marker_integration_parent_response();
        attached_parent["item"]["package_policies"] = json!([INTEGRATION_POLICY_ID]);
        let mut detached_parent = marker_integration_parent_response();
        detached_parent["item"]["package_policies"] = json!([]);
        let mut swapped_parent = attached_parent.clone();
        merge_marker_item_fields(&mut swapped_parent, parent_fields);
        let swapped_parent = parent_response_override.unwrap_or(swapped_parent);
        let parent_swap_at = match swap {
            IntegrationLifecycleSwap::FinalParentDelete => Some(2),
            IntegrationLifecycleSwap::Update | IntegrationLifecycleSwap::IntegrationDelete => None,
        };
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                let read =
                    parent_reads_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if parent_swap_at == Some(read) {
                    return ResponseTemplate::new(200).set_body_json(swapped_parent.clone());
                }
                match read {
                    0 => ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})),
                    1 => ResponseTemplate::new(200).set_body_json(attached_parent.clone()),
                    2 if integration_deleted_for_parent_reads
                        .load(std::sync::atomic::Ordering::SeqCst) =>
                    {
                        ResponseTemplate::new(200).set_body_json(detached_parent.clone())
                    }
                    3 if parent_deleted_for_reads.load(std::sync::atomic::Ordering::SeqCst) => {
                        ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}))
                    }
                    _ => ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})),
                }
            })
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies"))
            .and(query_param("sys_monitoring", "false"))
            .and(body_json(marker_integration_parent_create_body()))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(marker_integration_parent_response()),
            )
            .mount(server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(marker_integration_create_body("2.0.0")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(marker_integration_response(INTEGRATION_POLICY_DESCRIPTION)),
            )
            .mount(server)
            .await;
        let mut duplicate_body = marker_integration_create_body("2.0.0");
        duplicate_body["id"] = json!(INTEGRATION_POLICY_DUP_ID);
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(duplicate_body))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({"statusCode": 409})))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("page", "1"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortField", "created_at"))
            .and(query_param("sortOrder", "asc"))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [marker_integration_response(INTEGRATION_POLICY_DESCRIPTION)["item"].clone()],
                "total": 1,
                "page": 1,
                "perPage": 1000,
            })))
            .mount(server)
            .await;

        Mock::given(method("PUT"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .and(body_json(marker_integration_update_body("2.0.0")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(marker_integration_response(
                    INTEGRATION_POLICY_UPDATED_DESCRIPTION,
                )),
            )
            .mount(server)
            .await;

        let integration_deleted_for_parent_delete = integration_deleted.clone();
        let parent_deleted_for_response = parent_deleted.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies/delete"))
            .and(body_json(
                json!({"agentPolicyId": INTEGRATION_POLICY_PARENT_ID}),
            ))
            .respond_with(move |_: &wiremock::Request| {
                if integration_deleted_for_parent_delete.load(std::sync::atomic::Ordering::SeqCst) {
                    parent_deleted_for_response.store(true, std::sync::atomic::Ordering::SeqCst);
                    ResponseTemplate::new(200).set_body_json(json!({
                        "id": INTEGRATION_POLICY_PARENT_ID,
                        "name": INTEGRATION_POLICY_PARENT_NAME,
                    }))
                } else {
                    ResponseTemplate::new(409).set_body_json(json!({"statusCode": 409}))
                }
            })
            .mount(server)
            .await;
        let integration_deleted_for_response = integration_deleted.clone();
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                integration_deleted_for_response.store(true, std::sync::atomic::Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(json!({"id": INTEGRATION_POLICY_ID}))
            })
            .mount(server)
            .await;
    }

    pub(crate) async fn mount_integration_lifecycle_with_revalidation_race(
        server: &MockServer,
        swap: IntegrationLifecycleSwap,
    ) {
        mount_integration_lifecycle_with_revalidation_changes(
            server,
            swap,
            &json!({"inputs": {"untrusted": {"token": "private"}}}),
            &json!({"monitoring_enabled": ["logs"]}),
            None,
            None,
        )
        .await;
    }

    #[derive(Clone, Copy, Debug)]
    pub(crate) enum AmbiguousCreateOutcome {
        Conflict,
        ServerError,
        RootItem,
    }

    fn ambiguous_create_response(
        outcome: AmbiguousCreateOutcome,
        root_item: Value,
    ) -> ResponseTemplate {
        match outcome {
            AmbiguousCreateOutcome::Conflict => {
                ResponseTemplate::new(409).set_body_json(json!({"statusCode": 409}))
            }
            AmbiguousCreateOutcome::ServerError => {
                ResponseTemplate::new(500).set_body_json(json!({"statusCode": 500}))
            }
            AmbiguousCreateOutcome::RootItem => ResponseTemplate::new(200).set_body_json(root_item),
        }
    }

    pub(crate) async fn mount_parent_create_ambiguous_winner(
        server: &MockServer,
        outcome: AmbiguousCreateOutcome,
        winner_nonce: &str,
    ) {
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortOrder", "asc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_inventory()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_status()))
            .mount(server)
            .await;
        for id in [INTEGRATION_POLICY_ID, INTEGRATION_POLICY_DUP_ID] {
            Mock::given(method("GET"))
                .and(path(format!("/api/fleet/package_policies/{id}")))
                .and(query_param("format", "simplified"))
                .respond_with(ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})))
                .mount(server)
                .await;
        }

        let parent_deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let parent_deleted_for_reads = parent_deleted.clone();
        let parent_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let parent_reads_for_response = parent_reads.clone();
        let mut winner = marker_integration_parent_response_with_nonce(winner_nonce);
        winner["item"]["package_policies"] = json!([]);
        let root_item = winner["item"].clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                if parent_reads_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
                    || parent_deleted_for_reads.load(std::sync::atomic::Ordering::SeqCst)
                {
                    ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}))
                } else {
                    ResponseTemplate::new(200).set_body_json(winner.clone())
                }
            })
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies"))
            .and(query_param("sys_monitoring", "false"))
            .and(body_json(marker_integration_parent_create_body()))
            .respond_with(ambiguous_create_response(outcome, root_item))
            .mount(server)
            .await;
        let parent_deleted_for_response = parent_deleted.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies/delete"))
            .and(body_json(
                json!({"agentPolicyId": INTEGRATION_POLICY_PARENT_ID}),
            ))
            .respond_with(move |_: &wiremock::Request| {
                parent_deleted_for_response.store(true, std::sync::atomic::Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(json!({
                    "id": INTEGRATION_POLICY_PARENT_ID,
                }))
            })
            .mount(server)
            .await;
    }

    #[cfg(any())]
    async fn mount_primary_create_ambiguous_winner_legacy(
        server: &MockServer,
        outcome: AmbiguousCreateOutcome,
        winner_nonce: &str,
    ) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortOrder", "asc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_inventory()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_status()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(system_package_metadata()))
            .mount(server)
            .await;

        let primary_deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let primary_deleted_for_reads = primary_deleted.clone();
        let primary_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let primary_reads_for_response = primary_reads.clone();
        let winner =
            marker_integration_response_with_nonce(INTEGRATION_POLICY_DESCRIPTION, winner_nonce);
        let root_item = winner["item"].clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                if primary_reads_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
                    || primary_deleted_for_reads.load(std::sync::atomic::Ordering::SeqCst)
                {
                    ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}))
                } else {
                    ResponseTemplate::new(200).set_body_json(winner.clone())
                }
            })
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_DUP_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})))
            .mount(server)
            .await;

        let parent_deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let parent_deleted_for_reads = parent_deleted.clone();
        let primary_deleted_for_parent_reads = primary_deleted.clone();
        let parent_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let parent_reads_for_response = parent_reads.clone();
        let mut attached_parent = marker_integration_parent_response();
        attached_parent["item"]["package_policies"] = json!([INTEGRATION_POLICY_ID]);
        let mut detached_parent = marker_integration_parent_response();
        detached_parent["item"]["package_policies"] = json!([]);
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                if parent_reads_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
                    || parent_deleted_for_reads.load(std::sync::atomic::Ordering::SeqCst)
                {
                    ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}))
                } else if primary_deleted_for_parent_reads.load(std::sync::atomic::Ordering::SeqCst)
                {
                    ResponseTemplate::new(200).set_body_json(detached_parent.clone())
                } else {
                    ResponseTemplate::new(200).set_body_json(attached_parent.clone())
                }
            })
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies"))
            .and(query_param("sys_monitoring", "false"))
            .and(body_json(marker_integration_parent_create_body()))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(marker_integration_parent_response()),
            )
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(marker_integration_create_body("2.0.0")))
            .respond_with(ambiguous_create_response(outcome, root_item))
            .mount(server)
            .await;

        let primary_deleted_for_response = primary_deleted.clone();
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                primary_deleted_for_response.store(true, std::sync::atomic::Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(json!({"id": INTEGRATION_POLICY_ID}))
            })
            .mount(server)
            .await;
        let primary_deleted_for_parent_delete = primary_deleted.clone();
        let parent_deleted_for_response = parent_deleted.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies/delete"))
            .and(body_json(
                json!({"agentPolicyId": INTEGRATION_POLICY_PARENT_ID}),
            ))
            .respond_with(move |_: &wiremock::Request| {
                if primary_deleted_for_parent_delete.load(std::sync::atomic::Ordering::SeqCst) {
                    parent_deleted_for_response.store(true, std::sync::atomic::Ordering::SeqCst);
                    ResponseTemplate::new(200).set_body_json(json!({
                        "id": INTEGRATION_POLICY_PARENT_ID,
                    }))
                } else {
                    ResponseTemplate::new(409).set_body_json(json!({"statusCode": 409}))
                }
            })
            .mount(server)
            .await;

        primary_reads
    }

    pub(crate) async fn mount_primary_create_ambiguous_winner(
        server: &MockServer,
        outcome: AmbiguousCreateOutcome,
        winner_nonce: &str,
    ) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        mount_integration_lifecycle_with_recorded_create(
            server,
            IntegrationLifecycleFailure::None,
            Some((outcome, winner_nonce.to_owned())),
            None,
            None,
        )
        .await
    }

    pub(crate) async fn mount_primary_create_with_failed_inventory_observation(
        server: &MockServer,
    ) {
        let inventory_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let inventory_reads_for_response = inventory_reads.clone();
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortOrder", "asc"))
            .respond_with(move |_: &wiremock::Request| {
                let read =
                    inventory_reads_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if (2..=4).contains(&read) {
                    ResponseTemplate::new(500).set_body_json(json!({"statusCode": 500}))
                } else {
                    ResponseTemplate::new(200).set_body_json(installed_system_inventory())
                }
            })
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_status()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(system_package_metadata()))
            .mount(server)
            .await;

        let primary_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let primary_reads_for_response = primary_reads.clone();
        let primary = marker_integration_response(INTEGRATION_POLICY_DESCRIPTION);
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                match primary_reads_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                    0 => ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})),
                    1 => ResponseTemplate::new(200).set_body_json(primary.clone()),
                    _ => ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})),
                }
            })
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_DUP_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})))
            .mount(server)
            .await;

        let parent_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let parent_reads_for_response = parent_reads.clone();
        let mut detached_parent = marker_integration_parent_response();
        detached_parent["item"]["package_policies"] = json!([]);
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                match parent_reads_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                    0 => ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})),
                    1 => ResponseTemplate::new(200).set_body_json(detached_parent.clone()),
                    _ => ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})),
                }
            })
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies"))
            .and(query_param("sys_monitoring", "false"))
            .and(body_json(marker_integration_parent_create_body()))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(marker_integration_parent_response()),
            )
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(marker_integration_create_body("2.0.0")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(marker_integration_response(INTEGRATION_POLICY_DESCRIPTION)),
            )
            .mount(server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"id": INTEGRATION_POLICY_ID})),
            )
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies/delete"))
            .and(body_json(
                json!({"agentPolicyId": INTEGRATION_POLICY_PARENT_ID}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"id": INTEGRATION_POLICY_PARENT_ID})),
            )
            .expect(1)
            .mount(server)
            .await;
    }
}
