//! Offline checks for recorded fixtures.
//!
//! A fixture is recorded traffic. These tests fail when an Elastic upgrade
//! changes a response shape or bypasses the live client's decode path.

use elasticctl_api::Rule;
use elasticctl_api::codec;
use elasticctl_api::dashboards::{self, DashboardSpec};
use elasticctl_api::data_views::{DataViewReference, DataViewSummary};
use elasticctl_api::data_views_ops;
use elasticctl_api::rules;
use elasticctl_api::saved_objects;
use elasticctl_core::{Profile, Transport};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const V0_2_FIXTURES: [&str; 15] = [
    "exception_lists_find.json",
    "exception_list_get.json",
    "exception_list_items_find.json",
    "exception_list_create.json",
    "exception_item_create.json",
    "exception_list_export.json",
    "exception_list_import.json",
    "rules_export_bundle.json",
    "rules_import_bundle.json",
    "prebuilt_status.json",
    "prebuilt_install.json",
    "lists_index.json",
    "rules_find_source_custom.json",
    "rules_find_source_prebuilt.json",
    "rules_find_source_customized.json",
];

/// Search fixtures added in 0.3. They are recorded together by the search
/// probe; the decode test below reads their responses.
const V0_3_SEARCH_FIXTURES: [&str; 6] = [
    "esql_query.json",
    "search_pit_open.json",
    "search_pit_page.json",
    "search_pit_close.json",
    "data_views.json",
    "detection_engine_index.json",
];

/// Triage fixtures added in 0.4, recorded by the alerts probe.
const V0_4_ALERT_FIXTURES: [&str; 7] = [
    "signals_search.json",
    "signals_status_ids.json",
    "signals_status_query.json",
    "signals_tags.json",
    "signals_assignees.json",
    "users_find.json",
    "profile_suggest.json",
];

/// Case fixtures added in 0.4.1, recorded by the cases probe.
const V0_4_1_CASE_FIXTURES: [&str; 8] = [
    "cases_find.json",
    "case_get.json",
    "case_create.json",
    "case_update_status.json",
    "case_conflict.json",
    "case_comment.json",
    "case_attach.json",
    "case_delete.json",
];

/// Data-view fixtures added in 0.5.0. They are all marker-scoped and retain
/// the live route envelopes after the recorder removes server-owned cache and
/// identity values.
const V0_5_DATA_VIEW_FIXTURES: [&str; 21] = [
    "data_view_not_found.json",
    "data_view_create.json",
    "data_views_list.json",
    "data_view_get.json",
    "data_view_update.json",
    "data_view_fields.json",
    "data_view_fields_get.json",
    "data_view_allow_hidden_rejected.json",
    "data_view_default_get.json",
    "data_view_default_set.json",
    "data_view_default_unset.json",
    "data_view_default_set_before_swap.json",
    "data_view_swap_preview.json",
    "data_view_replacement_create.json",
    "data_view_swap.json",
    "data_view_swap_source_not_found.json",
    "data_view_default_after_swap.json",
    "data_view_default_restore.json",
    "data_view_default_restored_get.json",
    "data_view_delete.json",
    "data_view_delete_not_found.json",
];

/// Dashboard fixtures added in 0.5.1. They are recorded from the complete
/// marker lifecycle, including the opaque deep-export import round trip and
/// a low-level accepted-loss probe that the public import path rejects.
const V0_5_DASHBOARD_FIXTURES: [&str; 11] = [
    "dashboard_create.json",
    "dashboard_get.json",
    "dashboard_search.json",
    "dashboard_update.json",
    "dashboard_bundle_export.json",
    "dashboard_delete.json",
    "dashboard_import.json",
    "dashboard_import_conflict.json",
    "dashboard_not_found.json",
    "dashboard_data_view_not_found.json",
    "dashboard_loss.json",
];

/// Agent-policy fixtures added in 0.6.0, recorded from the marker lifecycle.
const V0_6_AGENT_POLICY_FIXTURES: [&str; 12] = [
    "fleet_setup.json",
    "agent_policy_not_found.json",
    "package_elastic_agent.json",
    "agent_policy_create.json",
    "agent_policy_get.json",
    "agent_policies_list.json",
    "agent_policy_name_conflict.json",
    "agent_policy_update.json",
    "agent_policy_update_omitted.json",
    "agent_policy_get_after_omit.json",
    "agent_policy_delete.json",
    "agent_policy_delete_not_found.json",
];

/// Integration-policy fixtures added in 0.6.1, recorded from the marker
/// integration and its marker parent lifecycle.
const V0_6_INTEGRATION_POLICY_FIXTURES: [&str; 16] = [
    "integration_policy_not_found.json",
    "integration_policy_parent_not_found.json",
    "package_system.json",
    "integration_policy_parent_create.json",
    "package_system_metadata.json",
    "integration_policy_create.json",
    "integration_policy_get.json",
    "integration_policies_list.json",
    "integration_policy_name_conflict.json",
    "integration_policy_parent_get.json",
    "integration_policy_update.json",
    "integration_policy_round_trip.json",
    "integration_policy_delete.json",
    "integration_policy_delete_not_found.json",
    "integration_policy_parent_delete.json",
    "integration_policy_parent_delete_not_found.json",
];

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn fixture_sets() -> Vec<PathBuf> {
    let mut sets = Vec::new();
    for entry in fs::read_dir(fixtures_root()).expect("fixtures root") {
        let path = entry.expect("fixtures entry").path();
        if path.is_dir() {
            sets.push(path);
        }
    }
    sets.sort();
    sets
}

fn nontraditional_default_restore_request_is_correlated(
    initial: &Value,
    restore_request: &Value,
) -> bool {
    match initial {
        Value::Null => restore_request.is_null(),
        Value::String(id) if id.is_empty() => restore_request.is_null(),
        Value::String(id) if id == "elasticctl-fixture-original-default" => {
            restore_request == initial
        }
        _ => false,
    }
}

/// The rule that every recorded set creates and deletes.
fn probe_rule(rules: &[Rule]) -> &Rule {
    rules
        .iter()
        .find(|r| r.rule_id().ok() == Some("elasticctl-fixture-probe"))
        .expect("the probe rule must be present")
}

#[test]
fn every_fixture_parses_and_carries_its_metadata() {
    let sets = fixture_sets();
    assert!(!sets.is_empty(), "no fixture sets under tests/fixtures");

    for set in &sets {
        let mut files = Vec::new();
        for entry in fs::read_dir(set).expect("fixture set") {
            let path = entry.expect("fixture set entry").path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                files.push(path);
            }
        }
        assert!(!files.is_empty(), "{} has no JSON fixtures", set.display());
        files.sort();

        for file in files {
            let body = fs::read_to_string(&file).expect("read fixture");
            let value: Value = serde_json::from_str(&body)
                .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", file.display()));
            for field in ["flavor", "version", "operation"] {
                assert!(
                    value.get(field).and_then(Value::as_str).is_some(),
                    "{} must carry a string `{field}`",
                    file.display()
                );
            }
        }

        // The search fixtures are recorded as a set; a set missing any of them
        // predates the search probe.
        let missing: Vec<&str> = V0_3_SEARCH_FIXTURES
            .iter()
            .copied()
            .filter(|name| !set.join(name).is_file())
            .collect();
        assert!(
            missing.is_empty(),
            "{} lacks search fixture(s): {}",
            set.display(),
            missing.join(", ")
        );

        // The alert fixtures are recorded as a set; a set missing any of them
        // predates the alerts probe.
        let missing: Vec<&str> = V0_4_ALERT_FIXTURES
            .iter()
            .copied()
            .filter(|name| !set.join(name).is_file())
            .collect();
        assert!(
            missing.is_empty(),
            "{} lacks alert fixture(s): {}",
            set.display(),
            missing.join(", ")
        );

        // The case fixtures are recorded as a set; a set missing any of them
        // predates the cases probe.
        let missing: Vec<&str> = V0_4_1_CASE_FIXTURES
            .iter()
            .copied()
            .filter(|name| !set.join(name).is_file())
            .collect();
        assert!(
            missing.is_empty(),
            "{} lacks case fixture(s): {}",
            set.display(),
            missing.join(", ")
        );

        let missing: Vec<&str> = V0_5_DATA_VIEW_FIXTURES
            .iter()
            .copied()
            .filter(|name| !set.join(name).is_file())
            .collect();
        assert!(
            missing.is_empty(),
            "{} lacks data-view fixture(s): {}",
            set.display(),
            missing.join(", ")
        );

        let missing: Vec<&str> = V0_5_DASHBOARD_FIXTURES
            .iter()
            .copied()
            .filter(|name| !set.join(name).is_file())
            .collect();
        assert!(
            missing.is_empty(),
            "{} lacks dashboard fixture(s): {}",
            set.display(),
            missing.join(", ")
        );

        let missing: Vec<&str> = V0_6_AGENT_POLICY_FIXTURES
            .iter()
            .copied()
            .filter(|name| !set.join(name).is_file())
            .collect();
        assert!(
            missing.is_empty(),
            "{} lacks agent-policy fixture(s): {}",
            set.display(),
            missing.join(", ")
        );

        let missing: Vec<&str> = V0_6_INTEGRATION_POLICY_FIXTURES
            .iter()
            .copied()
            .filter(|name| !set.join(name).is_file())
            .collect();
        assert!(
            missing.is_empty(),
            "{} lacks integration-policy fixture(s): {}",
            set.display(),
            missing.join(", ")
        );
    }
}

#[test]
fn rules_export_decodes_to_the_probe_rule_and_trailer() {
    for set in fixture_sets() {
        let body = fs::read_to_string(set.join("rules_export.json")).expect("rules_export fixture");
        let value: Value = serde_json::from_str(&body).expect("rules_export is JSON");
        let ndjson = value["response"]["ndjson"]
            .as_str()
            .expect("rules_export must carry response.ndjson as a string");

        let (rules, summary) = codec::decode_ndjson(ndjson).expect("decode export ndjson");
        let summary = summary.expect("export must carry the exported_count trailer");
        assert_eq!(
            summary.exported_count, 3,
            "the bundle total counts its rule, list, and item"
        );
        assert_eq!(
            summary.exported_rules_count, 1,
            "a scoped export holds one rule"
        );
        assert_eq!(summary.exported_exception_list_count, 1);
        assert_eq!(summary.exported_exception_list_item_count, 1);
        assert_eq!(rules.len(), 1, "a scoped export holds one rule line");
        let probe = probe_rule(&rules);
        assert_eq!(probe.name(), "elasticctl fixture probe");
    }
}

#[test]
fn rules_find_decodes_to_the_probe_rule() {
    for set in fixture_sets() {
        let body = fs::read_to_string(set.join("rules_find.json")).expect("rules_find fixture");
        let value: Value = serde_json::from_str(&body).expect("rules_find is JSON");

        let (rules, total) = rules::decode_find(&value["response"]).expect("decode find response");
        assert!(total >= 1, "a scoped find must report at least one rule");
        let probe = probe_rule(&rules);
        assert_eq!(probe.name(), "elasticctl fixture probe");
    }
}

/// Fixture sets recorded before an exchange lack its file. The self-managed
/// set is re-recorded from the local lab on demand. Assert each new exchange
/// where recorded and assert that it exists in at least one set.
fn sets_with(file: &str) -> Vec<PathBuf> {
    fixture_sets()
        .into_iter()
        .filter(|s| s.join(file).exists())
        .collect()
}

fn fixture_body(path: &Path) -> Value {
    let body = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()))
}

fn assert_object_fields_are_exact(value: &Value, expected: &[&str], context: &str) {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("{context}: expected an object"));
    let actual: std::collections::BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected: std::collections::BTreeSet<&str> = expected.iter().copied().collect();
    assert_eq!(actual, expected, "{context}: exact object field shape");
}

fn assert_package_metadata_shape(value: &Value, name: &str, version: &str, context: &str) {
    let item = value
        .get("item")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{context}: response.item must be an object"));
    let fields: std::collections::BTreeSet<&str> = item.keys().map(String::as_str).collect();
    let expected: std::collections::BTreeSet<&str> =
        ["name", "version", "status", "vars", "policy_templates"]
            .into_iter()
            .collect();
    assert_eq!(fields, expected, "{context}: exact package metadata shape");
    assert_eq!(
        item.get("name").and_then(Value::as_str),
        Some(name),
        "{}",
        context
    );
    assert_eq!(
        item.get("version").and_then(Value::as_str),
        Some(version),
        "{context}: package version"
    );
    assert!(
        matches!(
            item.get("status").and_then(Value::as_str),
            Some("installed" | "not_installed")
        ),
        "{context}: status must be installed or not_installed"
    );

    let vars = item
        .get("vars")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{context}: vars must be an array"));
    for (index, variable) in vars.iter().enumerate() {
        let variable_context = format!("{context}.vars[{index}]");
        assert_object_fields_are_exact(variable, &["name", "secret"], &variable_context);
        assert!(
            variable
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "{variable_context}: name must be a non-empty string"
        );
        assert!(
            variable.get("secret").and_then(Value::as_bool).is_some(),
            "{variable_context}: secret must be boolean"
        );
    }

    let templates = item
        .get("policy_templates")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{context}: policy_templates must be an array"));
    for (template_index, template) in templates.iter().enumerate() {
        let template_context = format!("{context}.policy_templates[{template_index}]");
        assert_object_fields_are_exact(template, &["name", "inputs"], &template_context);
        assert!(
            template
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "{template_context}: name must be a non-empty string"
        );
        let inputs = template
            .get("inputs")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{template_context}: inputs must be an array"));
        for (input_index, input) in inputs.iter().enumerate() {
            let input_context = format!("{template_context}.inputs[{input_index}]");
            assert_object_fields_are_exact(input, &["type", "vars", "streams"], &input_context);
            assert!(
                input
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty()),
                "{input_context}: type must be a non-empty string"
            );
            let vars = input["vars"]
                .as_array()
                .unwrap_or_else(|| panic!("{input_context}: vars must be an array"));
            for (index, variable) in vars.iter().enumerate() {
                let variable_context = format!("{input_context}.vars[{index}]");
                assert_object_fields_are_exact(variable, &["name", "secret"], &variable_context);
                assert!(
                    variable
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.trim().is_empty()),
                    "{variable_context}: name must be a non-empty string"
                );
                assert!(
                    variable.get("secret").and_then(Value::as_bool).is_some(),
                    "{variable_context}: secret must be boolean"
                );
            }
            let streams = input["streams"]
                .as_array()
                .unwrap_or_else(|| panic!("{input_context}: streams must be an array"));
            for (stream_index, stream) in streams.iter().enumerate() {
                let stream_context = format!("{input_context}.streams[{stream_index}]");
                assert_object_fields_are_exact(stream, &["data_stream", "vars"], &stream_context);
                let data_stream = stream
                    .get("data_stream")
                    .and_then(Value::as_object)
                    .unwrap_or_else(|| panic!("{stream_context}: data_stream must be an object"));
                let data_stream_fields: std::collections::BTreeSet<&str> =
                    data_stream.keys().map(String::as_str).collect();
                assert_eq!(
                    data_stream_fields,
                    std::collections::BTreeSet::from(["dataset"]),
                    "{stream_context}: exact data_stream shape"
                );
                assert!(
                    data_stream
                        .get("dataset")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.trim().is_empty()),
                    "{stream_context}: dataset must be a non-empty string"
                );
                let vars = stream["vars"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{stream_context}: vars must be an array"));
                for (index, variable) in vars.iter().enumerate() {
                    let variable_context = format!("{stream_context}.vars[{index}]");
                    assert_object_fields_are_exact(
                        variable,
                        &["name", "secret"],
                        &variable_context,
                    );
                    assert!(
                        variable
                            .get("name")
                            .and_then(Value::as_str)
                            .is_some_and(|value| !value.trim().is_empty()),
                        "{variable_context}: name must be a non-empty string"
                    );
                    assert!(
                        variable.get("secret").and_then(Value::as_bool).is_some(),
                        "{variable_context}: secret must be boolean"
                    );
                }
            }
        }
    }
}

fn fixture_transport(server: &MockServer) -> Transport {
    Transport::new(&Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("essu_fixture".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .expect("fixture transport")
}

#[tokio::test]
async fn dashboard_search_decodes_the_measured_nested_data_row() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "version": {"number": "9.6.0", "build_flavor": "serverless"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/dashboards"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{
                "id": "elasticctl-sample-dashboard",
                "data": {
                    "title": "elasticctl sample dashboard",
                    "description": "elasticctl-sample",
                    "tags": ["elasticctl-sample"]
                },
                "meta": {}
            }],
            "meta": {"page": 1, "per_page": 1000, "total": 1}
        })))
        .mount(&server)
        .await;

    let page = dashboards::search(
        &fixture_transport(&server),
        1,
        Some("elasticctl sample dashboard"),
        &[],
    )
    .await
    .expect("measured dashboard search row decodes");

    assert_eq!(page.data[0].id, "elasticctl-sample-dashboard");
    assert_eq!(page.data[0].title, "elasticctl sample dashboard");
    assert_eq!(
        page.data[0].description.as_deref(),
        Some("elasticctl-sample")
    );
    assert_eq!(
        page.data[0].tags,
        Some(vec!["elasticctl-sample".to_string()])
    );
}

#[test]
fn every_flavor_carries_every_v0_2_exchange() {
    for set in fixture_sets() {
        let missing: Vec<&str> = V0_2_FIXTURES
            .iter()
            .copied()
            .filter(|name| !set.join(name).is_file())
            .collect();
        assert!(
            missing.is_empty(),
            "{} lacks v0.2 fixture exchange(s): {}",
            set.display(),
            missing.join(", ")
        );
    }
}

#[test]
fn data_view_fixtures_decode_through_the_production_models() {
    for set in fixture_sets() {
        let create = fixture_body(&set.join("data_view_create.json"));
        let got = fixture_body(&set.join("data_view_get.json"));
        assert_eq!(
            create["request"]["data_view"]["fields"]["elasticctl.legacy"]["scripted"],
            true,
            "{}: raw request carries the legacy scripted-field probe",
            set.display()
        );
        let create_scripted = create["response"]["data_view"]["fields"]
            .get("elasticctl.legacy")
            .is_some();
        let get_scripted = got["response"]["data_view"]["fields"]
            .get("elasticctl.legacy")
            .is_some();
        assert_eq!(create_scripted, get_scripted, "{}", set.display());
        match create["flavor"].as_str() {
            Some("serverless") => assert!(
                !create_scripted,
                "{}: Serverless drops the raw scripted field",
                set.display()
            ),
            Some("ech" | "traditional") => assert!(
                create_scripted,
                "{}: Hosted and traditional retain the raw scripted field",
                set.display()
            ),
            flavor => panic!("{}: unexpected fixture flavor {flavor:?}", set.display()),
        }
        assert_eq!(
            create["response"]["data_view"]["allowHidden"],
            true,
            "{}: create preserves allowHidden: true",
            set.display()
        );
        assert_eq!(
            got["response"]["data_view"]["allowHidden"],
            true,
            "{}: immediate GET preserves allowHidden: true",
            set.display()
        );
        for response in [&create["response"], &got["response"]] {
            if create_scripted {
                let error = data_views_ops::normalize(&response["data_view"])
                    .expect_err("live scripted field is unsupported");
                assert_eq!(error.kind, elasticctl_core::ErrorKind::Unsupported);
            } else {
                let created = data_views_ops::normalize(&response["data_view"])
                    .expect("normalize a scripted-field-free response");
                assert!(created.fields.is_empty());
            }
        }

        let updated = fixture_body(&set.join("data_view_update.json"));
        assert_eq!(
            updated["response"]["data_view"]["allowHidden"],
            true,
            "{}",
            set.display()
        );
        assert_eq!(
            updated["response"]["data_view"]["title"],
            "elasticctl-sample-data-view-updated-*"
        );

        let listed = fixture_body(&set.join("data_views_list.json"));
        let listed: Vec<DataViewSummary> =
            serde_json::from_value(listed["response"]["data_view"].clone())
                .expect("decode marker-scoped data-view list");
        assert_eq!(listed.len(), 1, "{}", set.display());
        assert_eq!(listed[0].id, "elasticctl-sample-data-view-source");

        let fields = fixture_body(&set.join("data_view_fields.json"));
        let fields_acknowledged = fields["response"] == serde_json::json!({"acknowledged": true});
        let fields_envelope = fields["response"].as_object().is_some_and(|response| {
            response.len() == 1
                && response["data_view"]["id"] == "elasticctl-sample-data-view-source"
        });
        assert!(
            fields_acknowledged || fields_envelope,
            "{}: field metadata must use the closed success union",
            set.display()
        );
        assert!(
            fields_envelope,
            "{}: every measured flavor returns the full data-view envelope",
            set.display()
        );
        assert_eq!(
            fields["request"]["fields"]["host.name"]["customLabel"],
            Value::Null,
            "{}: field metadata null is the removal contract",
            set.display()
        );
        assert_eq!(
            fields["request"]["fields"]["elasticctl.metadata"]["customDescription"],
            "elasticctl sample metadata",
            "{}: use Kibana's documented metadata key",
            set.display()
        );
        let persisted_fields = fixture_body(&set.join("data_view_fields_get.json"));
        let field_attrs = &persisted_fields["response"]["data_view"]["fieldAttrs"];
        assert_eq!(field_attrs["host.name"]["count"], 2, "{}", set.display());
        assert!(
            field_attrs["host.name"].get("customLabel").is_none(),
            "{}: null removes the stored label",
            set.display()
        );
        assert_eq!(
            field_attrs["elasticctl.metadata"]["count"],
            1,
            "{}",
            set.display()
        );
        assert_eq!(
            field_attrs["elasticctl.metadata"]["customDescription"],
            "elasticctl sample metadata",
            "{}",
            set.display()
        );

        let rejected = fixture_body(&set.join("data_view_allow_hidden_rejected.json"));
        assert_eq!(rejected["error"]["http_status"], 400);
        assert_eq!(
            rejected["error"]["kind"],
            "http",
            "{}: unsupported main-route allowHidden update remains a 400",
            set.display()
        );

        let preview = fixture_body(&set.join("data_view_swap_preview.json"));
        let preview_references: Vec<DataViewReference> =
            serde_json::from_value(preview["response"]["result"].clone())
                .expect("decode self-swap references");
        assert!(preview_references.is_empty());
        assert_eq!(
            preview["request"]["fromId"],
            "elasticctl-sample-data-view-source"
        );
        assert_eq!(
            preview["request"]["toId"],
            "elasticctl-sample-data-view-source"
        );

        let swap = fixture_body(&set.join("data_view_swap.json"));
        let swap_references: Vec<DataViewReference> =
            serde_json::from_value(swap["response"]["result"].clone())
                .expect("decode swap references");
        assert!(swap_references.is_empty());
        assert_eq!(swap["response"]["deleteStatus"]["deletePerformed"], true);
        assert_eq!(swap["response"]["deleteStatus"]["remainingRefs"], 0);
        let source = fixture_body(&set.join("data_view_swap_source_not_found.json"));
        assert_eq!(source["error"]["kind"], "not_found");
        let after_swap = fixture_body(&set.join("data_view_default_after_swap.json"));
        assert_eq!(
            after_swap["response"]["data_view_id"],
            "elasticctl-sample-data-view-source",
            "{}: Kibana retains the deleted source as default after swap",
            set.display()
        );
        let deleted = fixture_body(&set.join("data_view_delete.json"));
        assert!(
            deleted["response"].is_null(),
            "{}: every measured flavor returns an empty delete body",
            set.display()
        );
        let deleted = fixture_body(&set.join("data_view_delete_not_found.json"));
        assert_eq!(deleted["error"]["kind"], "not_found");

        let initial_default = fixture_body(&set.join("data_view_default_get.json"));
        let restore = fixture_body(&set.join("data_view_default_restore.json"));
        let restored_default = fixture_body(&set.join("data_view_default_restored_get.json"));
        assert_eq!(
            initial_default["response"]["data_view_id"],
            restored_default["response"]["data_view_id"],
            "{}: raw initial and restored defaults must match",
            set.display()
        );
        for fixture in [&initial_default, &restore, &restored_default] {
            for id in [
                fixture.pointer("/response/data_view_id"),
                fixture.pointer("/request/data_view_id"),
            ]
            .into_iter()
            .flatten()
            {
                assert!(
                    id.is_null()
                        || id.as_str() == Some("")
                        || matches!(
                            id.as_str(),
                            Some("elasticctl-sample-data-view-source")
                                | Some("elasticctl-sample-data-view-replacement")
                                | Some("elasticctl-fixture-original-default")
                        ),
                    "{}: default fixture leaked a nonmarker id",
                    set.display()
                );
            }
        }
        if initial_default["flavor"] == "traditional" {
            assert_eq!(initial_default["response"]["data_view_id"], "");
            assert!(restore["request"]["data_view_id"].is_null());
            assert_eq!(restored_default["response"]["data_view_id"], "");
        } else {
            for id in [
                &initial_default["response"]["data_view_id"],
                &restore["request"]["data_view_id"],
                &restored_default["response"]["data_view_id"],
            ] {
                assert_eq!(
                    id,
                    "elasticctl-fixture-original-default",
                    "{}: cloud defaults use the fixed scrubbed placeholder",
                    set.display()
                );
            }
        }
        assert_eq!(restore["request"]["force"], true, "{}", set.display());
        assert_eq!(
            restore["response"],
            serde_json::json!({"acknowledged": true}),
            "{}: default restore must carry the exact acknowledgement",
            set.display()
        );
    }
}

#[tokio::test]
async fn dashboard_fixtures_decode_through_the_production_paths() {
    for set in fixture_sets() {
        let create = fixture_body(&set.join("dashboard_create.json"));
        let get = fixture_body(&set.join("dashboard_get.json"));
        let search = fixture_body(&set.join("dashboard_search.json"));
        let update = fixture_body(&set.join("dashboard_update.json"));
        let deleted = fixture_body(&set.join("dashboard_delete.json"));
        let loss = fixture_body(&set.join("dashboard_loss.json"));
        let id = create["request"]["id"]
            .as_str()
            .expect("dashboard create request id");
        let title = create["request"]["data"]["title"]
            .as_str()
            .expect("dashboard create request title");

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "version": {"number": "9.6.0", "build_flavor": "serverless"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(format!("/api/dashboards/{id}")))
            .respond_with(ResponseTemplate::new(201).set_body_json(create["response"].clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/dashboards/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(get["response"].clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/dashboards"))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "1000"))
            .and(query_param("query", title))
            .respond_with(ResponseTemplate::new(200).set_body_json(search["response"].clone()))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(format!("/api/dashboards/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(update["response"].clone()))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("/api/dashboards/{id}")))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let transport = fixture_transport(&server);
        let create_spec = DashboardSpec::try_from(create["request"].clone())
            .expect("dashboard create request is a portable spec");
        let created = dashboards::put(&transport, &create_spec)
            .await
            .unwrap_or_else(|error| panic!("{}: decode dashboard create: {error}", set.display()));
        assert_eq!(created.id, id, "{}", set.display());
        let fetched = dashboards::get(&transport, id)
            .await
            .unwrap_or_else(|error| panic!("{}: decode dashboard get: {error}", set.display()));
        assert_eq!(fetched.id, id, "{}", set.display());
        let page = dashboards::search(&transport, 1, Some(title), &[])
            .await
            .unwrap_or_else(|error| panic!("{}: decode dashboard search: {error}", set.display()));
        assert_eq!(page.data.len(), 1, "{}", set.display());
        assert_eq!(page.data[0].id, id, "{}", set.display());
        let update_spec = DashboardSpec::try_from(update["request"].clone())
            .expect("dashboard update request is a portable spec");
        let updated = dashboards::put(&transport, &update_spec)
            .await
            .unwrap_or_else(|error| panic!("{}: decode dashboard update: {error}", set.display()));
        assert_eq!(updated.id, id, "{}", set.display());
        dashboards::delete(&transport, id)
            .await
            .unwrap_or_else(|error| panic!("{}: decode dashboard delete: {error}", set.display()));
        assert!(deleted["response"].is_null(), "{}", set.display());

        let losses = dashboards::subset_losses(&loss["request"]["data"], &loss["response"]["data"]);
        assert_eq!(
            losses
                .iter()
                .map(|loss| loss.path.as_str())
                .collect::<Vec<_>>(),
            vec!["$.time_range.mode"],
            "{}: accepted dashboard loss path",
            set.display()
        );

        let export = fixture_body(&set.join("dashboard_bundle_export.json"));
        let ndjson = export["response"]["ndjson"]
            .as_str()
            .expect("dashboard export is opaque NDJSON");
        let scan = saved_objects::scan_bundle(ndjson)
            .unwrap_or_else(|error| panic!("{}: decode dashboard export: {error}", set.display()));
        assert_eq!(scan.dashboards, vec![id.to_string()], "{}", set.display());
        assert_eq!(scan.counts.get("dashboard"), Some(&1), "{}", set.display());
        assert_eq!(
            scan.counts.get("index-pattern"),
            Some(&1),
            "{}",
            set.display()
        );
        assert_eq!(scan.total, 2, "{}", set.display());
        assert!(scan.has_export_details, "{}", set.display());

        for (name, overwrite, expected_success) in [
            ("dashboard_import.json", true, true),
            ("dashboard_import_conflict.json", false, false),
        ] {
            let imported = fixture_body(&set.join(name));
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/api/saved_objects/_import"))
                .and(query_param("overwrite", overwrite.to_string()))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(imported["response"].clone()),
                )
                .mount(&server)
                .await;
            let report = saved_objects::import(&fixture_transport(&server), ndjson, overwrite)
                .await
                .unwrap_or_else(|error| panic!("{}: decode {name}: {error}", set.display()));
            assert_eq!(report.success, expected_success, "{}", set.display());
        }

        let missing = fixture_body(&set.join("dashboard_not_found.json"));
        assert_eq!(missing["error"]["kind"], "not_found", "{}", set.display());
        let missing = fixture_body(&set.join("dashboard_data_view_not_found.json"));
        assert_eq!(missing["error"]["kind"], "not_found", "{}", set.display());
    }
}

#[test]
fn nontraditional_default_restore_request_must_correlate_with_initial_default() {
    let placeholder = Value::String("elasticctl-fixture-original-default".to_string());
    assert!(nontraditional_default_restore_request_is_correlated(
        &Value::Null,
        &Value::Null
    ));
    assert!(nontraditional_default_restore_request_is_correlated(
        &Value::String(String::new()),
        &Value::Null
    ));
    assert!(nontraditional_default_restore_request_is_correlated(
        &placeholder,
        &placeholder
    ));
    assert!(!nontraditional_default_restore_request_is_correlated(
        &Value::Null,
        &Value::String(String::new())
    ));
    assert!(!nontraditional_default_restore_request_is_correlated(
        &Value::String(String::new()),
        &placeholder
    ));
    assert!(!nontraditional_default_restore_request_is_correlated(
        &placeholder,
        &Value::Null
    ));
}

#[test]
fn exception_export_bundle_decodes_to_the_fixed_list_and_item() {
    for set in fixture_sets() {
        let value = fixture_body(&set.join("exception_list_export.json"));
        let ndjson = value["response"]["ndjson"]
            .as_str()
            .expect("exception_list_export must carry response.ndjson as a string");
        let bundle = codec::decode_bundle(ndjson).expect("decode exception export NDJSON");

        assert!(
            bundle.rules.is_empty(),
            "{}: exception export has no rules",
            set.display()
        );
        assert_eq!(
            bundle.lists.len(),
            1,
            "{}: one scoped exception list",
            set.display()
        );
        assert_eq!(
            bundle.items.len(),
            1,
            "{}: one scoped exception item",
            set.display()
        );
        assert_eq!(
            bundle.lists[0].list_id().expect("list id"),
            "elasticctl-sample-exceptions",
            "{}: export must retain the fixed list id",
            set.display()
        );
        assert_eq!(
            bundle.items[0].item_id().expect("item id"),
            "elasticctl-sample-exception-item",
            "{}: export must retain the fixed item id",
            set.display()
        );
        assert_eq!(
            bundle.items[0].list_id().expect("item list id"),
            "elasticctl-sample-exceptions",
            "{}: item must point to the fixed list",
            set.display()
        );
    }
}

#[test]
fn rule_export_bundle_decodes_to_the_fixed_rule_list_and_item() {
    for set in fixture_sets() {
        let value = fixture_body(&set.join("rules_export_bundle.json"));
        let ndjson = value["response"]["ndjson"]
            .as_str()
            .expect("rules_export_bundle must carry response.ndjson as a string");
        let bundle = codec::decode_bundle(ndjson).expect("decode rule export NDJSON");

        assert_eq!(bundle.rules.len(), 1, "{}: one scoped rule", set.display());
        assert_eq!(
            bundle.lists.len(),
            1,
            "{}: one referenced list",
            set.display()
        );
        assert_eq!(
            bundle.items.len(),
            1,
            "{}: one referenced item",
            set.display()
        );
        assert_eq!(
            bundle.rules[0].rule_id().expect("rule id"),
            "elasticctl-fixture-probe",
            "{}: export must retain the fixed rule id",
            set.display()
        );
        assert_eq!(
            bundle.lists[0].list_id().expect("list id"),
            "elasticctl-sample-exceptions",
            "{}: export must retain the fixed list id",
            set.display()
        );
        assert_eq!(
            bundle.items[0].item_id().expect("item id"),
            "elasticctl-sample-exception-item",
            "{}: export must retain the fixed item id",
            set.display()
        );
    }
}

#[test]
fn source_find_fixtures_keep_the_exact_scoped_kql() {
    let expected = [
        (
            "rules_find_source_custom.json",
            "alert.attributes.params.immutable: false AND alert.attributes.params.ruleId: \"elasticctl-fixture-probe\"",
        ),
        (
            "rules_find_source_prebuilt.json",
            "alert.attributes.params.immutable: true AND alert.attributes.params.ruleId: \"elasticctl-fixture-probe\"",
        ),
        (
            "rules_find_source_customized.json",
            "alert.attributes.params.ruleSource.isCustomized: true AND alert.attributes.params.ruleId: \"elasticctl-fixture-probe\"",
        ),
    ];

    for set in fixture_sets() {
        for (file, filter) in expected {
            let value = fixture_body(&set.join(file));
            assert_eq!(
                value["request"]["filter"].as_str(),
                Some(filter),
                "{} must retain the exact scoped source filter",
                set.join(file).display()
            );
        }
    }
}

#[test]
fn source_partition_is_exhaustive_for_the_scoped_probe_corpus() {
    for set in fixture_sets() {
        let all = fixture_body(&set.join("rules_find.json"));
        let custom = fixture_body(&set.join("rules_find_source_custom.json"));
        let prebuilt = fixture_body(&set.join("rules_find_source_prebuilt.json"));
        let total = |fixture: &Value| {
            fixture["response"]["total"]
                .as_u64()
                .expect("source fixture response.total")
        };

        assert_eq!(
            total(&custom) + total(&prebuilt),
            total(&all),
            "{}: immutable must partition the scoped probe corpus",
            set.display()
        );
    }
}

#[test]
fn lists_index_records_either_the_valid_result_or_classified_404() {
    for set in fixture_sets() {
        let value = fixture_body(&set.join("lists_index.json"));
        match (value.get("response"), value.get("error")) {
            (Some(response), None) => {
                assert!(
                    response["list_index"].is_boolean(),
                    "{}: successful list index response needs list_index bool",
                    set.display()
                );
                assert!(
                    response["list_item_index"].is_boolean(),
                    "{}: successful list index response needs list_item_index bool",
                    set.display()
                );
            }
            (None, Some(error)) => {
                assert_eq!(
                    error["kind"].as_str(),
                    Some("not_found"),
                    "{}: absent list indices must remain a classified 404",
                    set.display()
                );
                assert_eq!(
                    error["http_status"].as_u64(),
                    Some(404),
                    "{}: absent list indices must retain their HTTP status",
                    set.display()
                );
            }
            _ => panic!(
                "{}: lists_index requires exactly one response or error envelope",
                set.display()
            ),
        }
    }
}

fn is_identity_key(key: &str) -> bool {
    matches!(
        key.rsplit('.').next().unwrap_or(key),
        "created_by" | "updated_by" | "closed_by" | "pushed_by" | "tie_breaker_id" | "_version"
    )
}

/// A string leaf under an identity key must be a redaction placeholder, not
/// real identity: either the blanket `"REDACTED"` `scrub` writes when the
/// key itself is sensitive, or a per-profile `u_REDACTED_<n>` uid placeholder
/// `scrub_placeholder_values` writes in its place (uid is deliberately never
/// blanket-redacted — see `SCRUB_FIELDS`'s comment in `xtask/src/main.rs`).
/// Substring match, not exact equality, so both shapes pass: a real,
/// unredacted value never contains the literal word "REDACTED".
fn is_redacted_placeholder(value: &str) -> bool {
    value.contains("REDACTED")
}

fn assert_identity_value_redacted(value: &Value, context: &str) {
    match value {
        Value::Null => {}
        Value::String(value) => assert!(
            is_redacted_placeholder(value),
            "{context}: expected a redacted placeholder, found {value:?}"
        ),
        Value::Array(values) => {
            for value in values {
                assert_identity_value_redacted(value, context);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                assert_identity_value_redacted(value, context);
            }
        }
        other => panic!("{context}: unredacted identity value {other}"),
    }
}

fn assert_no_real_identity_values(value: &Value, context: &str) {
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                let child_context = format!("{context}.{key}");
                if is_identity_key(key) {
                    assert_identity_value_redacted(value, &child_context);
                } else if key == "ndjson" {
                    let text = value.as_str().unwrap_or_else(|| {
                        panic!("{child_context}: NDJSON response must be a string")
                    });
                    for (line, body) in text
                        .lines()
                        .filter(|line| !line.trim().is_empty())
                        .enumerate()
                    {
                        let nested: Value = serde_json::from_str(body).unwrap_or_else(|error| {
                            panic!("{child_context} line {} is not JSON: {error}", line + 1)
                        });
                        assert_no_real_identity_values(
                            &nested,
                            &format!("{child_context} line {}", line + 1),
                        );
                    }
                } else {
                    assert_no_real_identity_values(value, &child_context);
                }
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                assert_no_real_identity_values(value, &format!("{context}[{index}]"));
            }
        }
        _ => {}
    }
}

#[test]
fn fixture_identity_and_version_fields_are_recursively_redacted() {
    for set in fixture_sets() {
        for entry in fs::read_dir(&set).expect("fixture set") {
            let path = entry.expect("fixture set entry").path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
                assert_no_real_identity_values(&fixture_body(&path), &path.display().to_string());
            }
        }
    }
}

#[test]
fn status_fixtures_remove_deployment_identity_and_runtime_metrics() {
    for set in fixture_sets() {
        let status = fixture_body(&set.join("status.json"));
        let response = status["response"]
            .as_object()
            .unwrap_or_else(|| panic!("{}: status response must be an object", set.display()));
        for field in ["name", "uuid", "metrics"] {
            assert!(
                !response.contains_key(field),
                "{}: status response leaked `{field}`",
                set.display()
            );
        }
    }
}

#[test]
fn preview_hits_decode_through_the_production_path_and_carry_the_matched_field() {
    let sets = sets_with("rules_preview_hits.json");
    assert!(
        !sets.is_empty(),
        "no set records rules_preview_hits; the preview hit count rests on it"
    );

    for set in sets {
        let v = fixture_body(&set.join("rules_preview_hits.json"));
        for field in ["took", "timed_out", "_shards"] {
            assert!(
                v["response"].get(field).is_none(),
                "{}: preview-hit response retained runtime field `{field}`",
                set.display()
            );
        }
        for hit in v["response"]["hits"]["hits"]
            .as_array()
            .unwrap_or_else(|| panic!("{}: preview-hit response has no hits array", set.display()))
        {
            for field in ["_index", "_score", "sort"] {
                assert!(
                    hit.get(field).is_none(),
                    "{}: preview-hit retained runtime hit field `{field}`",
                    set.display()
                );
            }
        }
        let index = v["request"]["index"].as_str().expect("request.index");
        assert!(
            index.starts_with(".preview.alerts-security.alerts-"),
            "{} recorded an unexpected preview index: {index}",
            set.display()
        );

        // The production query hardcodes this field. A fallback to `name` must
        // not pass the fixture check.
        let matched_by = v["request"]["matched_by"]
            .as_str()
            .expect("request.matched_by");
        assert_eq!(
            matched_by,
            "kibana.alert.rule.uuid",
            "{}: production preview_hits queries this field; a fallback recording \
             would no longer match the live client. Re-record.",
            set.display()
        );

        // Decode the recorded response through the checked live-client path.
        let hits = rules::decode_preview_hits_checked(&v["response"])
            .unwrap_or_else(|error| panic!("{}: {error}", set.display()));
        assert!(
            hits.total >= 1,
            "{}: a recording with zero hits proves nothing — a wrong field name \
             looks exactly the same. Re-record.",
            set.display()
        );

        // The returned document must contain the queried field and value.
        // Otherwise the match is coincidental.
        let carried = hits
            .sample
            .first()
            .and_then(|s| s.get("_source"))
            .and_then(|s| s.get(matched_by));
        assert!(
            carried.is_some(),
            "{}: the returned document must carry the matched field {matched_by}",
            set.display()
        );
        assert_eq!(
            carried,
            v["request"]["body"]["query"]["term"].get(matched_by),
            "{}: the returned document's {matched_by} must equal the queried value",
            set.display()
        );
    }
}

#[test]
fn close_by_query_fixtures_use_canonical_counters_and_keep_the_outcome_invariant() {
    use elasticctl_api::alerts;

    for set in sets_with("signals_status_query.json") {
        let fixture = fixture_body(&set.join("signals_status_query.json"));
        let outcome = alerts::decode_outcome(&fixture["response"])
            .unwrap_or_else(|error| panic!("{}: {error}", set.display()));

        assert_eq!(
            outcome.updated,
            1,
            "{}: close-by-query updated must be canonical",
            set.display()
        );
        assert_eq!(
            outcome.total,
            outcome.updated + outcome.version_conflicts + outcome.noops,
            "{}: close-by-query counters must retain the decoded outcome invariant",
            set.display()
        );
        assert_eq!(
            outcome.version_conflicts,
            0,
            "{}: close-by-query must be conflict-free",
            set.display()
        );
        assert_eq!(
            outcome.noops,
            0,
            "{}: close-by-query must not canonicalize a no-op",
            set.display()
        );
        assert!(
            outcome.failures.is_empty(),
            "{}: close-by-query must not carry failed writes",
            set.display()
        );
        for field in [
            "took",
            "timed_out",
            "_shards",
            "batches",
            "deleted",
            "requests_per_second",
            "retries",
            "throttled_millis",
            "throttled_until_millis",
        ] {
            assert!(
                fixture["response"].get(field).is_none(),
                "{}: close-by-query response retained runtime field `{field}`",
                set.display()
            );
        }
    }
}

#[test]
fn the_name_filter_find_returns_the_probe_rule() {
    let sets = sets_with("rules_find_by_name.json");
    assert!(!sets.is_empty(), "no set records rules_find_by_name");

    for set in sets {
        let v = fixture_body(&set.join("rules_find_by_name.json"));
        assert!(
            v["request"]["filter"]
                .as_str()
                .expect("request.filter")
                .starts_with("alert.attributes.name:"),
            "{} must record the KQL path the name lookup uses",
            set.display()
        );
        let (rules, total) = rules::decode_find(&v["response"]).expect("decode find response");
        assert!(
            total >= 1,
            "{}: a name filter matching nothing proves nothing about the path",
            set.display()
        );
        assert_eq!(probe_rule(&rules).name(), "elasticctl fixture probe");
    }
}

#[test]
fn the_spaces_probe_returns_ids() {
    let sets = sets_with("spaces.json");
    assert!(!sets.is_empty(), "no set records spaces");

    for set in sets {
        let v = fixture_body(&set.join("spaces.json"));
        let spaces = v["response"]
            .as_array()
            .expect("spaces response is an array");
        assert!(!spaces.is_empty(), "{}", set.display());
        for space in spaces {
            assert!(
                space["id"].as_str().is_some(),
                "{} every space must carry a string id: {space}",
                set.display()
            );
        }
    }
}

#[test]
fn search_fixtures_decode_through_the_production_paths() {
    for set in fixture_sets() {
        let esql_value = fixture_body(&set.join("esql_query.json"));
        let esql = elasticctl_api::search::esql::decode(&esql_value["response"])
            .expect("decode esql_query response");
        let seq = esql
            .columns
            .iter()
            .position(|column| column.name == "seq")
            .unwrap_or_else(|| panic!("{}: esql_query has no seq column", set.display()));
        assert_eq!(
            esql.values.len(),
            2,
            "{}: LIMIT 2 must return two rows",
            set.display()
        );
        assert_eq!(
            esql.values[0][seq].as_i64(),
            Some(1),
            "{}: sorted ascending",
            set.display()
        );
        assert_eq!(
            esql.values[1][seq].as_i64(),
            Some(2),
            "{}: sorted ascending",
            set.display()
        );

        let page_value = fixture_body(&set.join("search_pit_page.json"));
        assert!(
            page_value["request"]["pit"].is_object()
                && page_value["request"]["sort"].is_array()
                && page_value["request"]["query"].is_object(),
            "{}: search_pit_page must retain its exchange request",
            set.display()
        );
        let page = elasticctl_api::search::dsl::decode(&page_value["response"])
            .expect("decode search_pit_page response");
        assert_eq!(
            page.total,
            Some(3),
            "{}: three seeded documents",
            set.display()
        );
        assert_eq!(
            page.hits.len(),
            2,
            "{}: a size-2 page returns two hits",
            set.display()
        );
        assert!(
            page.hits.iter().all(|hit| hit.source["seq"].is_number()),
            "{}: hits must carry their seq source",
            set.display()
        );
    }
}

#[test]
fn alert_fixtures_decode_through_the_typed_decoders() {
    use elasticctl_api::{alerts, profiles};
    for set in fixture_sets() {
        let read = |name: &str| -> Value {
            serde_json::from_str(&fs::read_to_string(set.join(name)).expect(name)).expect(name)
        };

        let search = read("signals_search.json");
        let page = alerts::decode_page(&search["response"]).expect("signals_search decodes");
        assert!(
            !page.hits.is_empty(),
            "{}: the recorded search must carry alert rows",
            set.display()
        );

        for name in [
            "signals_status_ids.json",
            "signals_status_query.json",
            "signals_tags.json",
            "signals_assignees.json",
        ] {
            let doc = read(name);
            alerts::decode_outcome(&doc["response"])
                .unwrap_or_else(|e| panic!("{}/{name}: {e}", set.display()));
        }

        let users = read("users_find.json");
        profiles::decode_internal(&users["response"]).expect("users_find decodes");

        let suggest = read("profile_suggest.json");
        if let Some(response) = suggest.get("response") {
            profiles::decode_public(response).expect("profile_suggest decodes");
        } else {
            // Serverless: the public route answers 410; the fixture records
            // the error envelope instead of a response.
            assert_eq!(suggest["error"]["http_status"], serde_json::json!(410));
        }
    }
}

#[test]
fn case_fixtures_decode_through_the_typed_decoders() {
    use elasticctl_api::cases;
    for set in fixture_sets() {
        let read = |name: &str| -> Value {
            serde_json::from_str(&fs::read_to_string(set.join(name)).expect(name)).expect(name)
        };
        let (cases, total) =
            cases::decode_find(&read("cases_find.json")["response"]).expect("find");
        assert!(total >= cases.len() as u64);
        assert!(
            !cases.is_empty(),
            "{}: the recorded find must carry the marker case",
            set.display()
        );
        for name in [
            "case_get.json",
            "case_create.json",
            "case_comment.json",
            "case_attach.json",
        ] {
            cases::decode_case(&read(name)["response"])
                .unwrap_or_else(|e| panic!("{}/{name}: {e}", set.display()));
        }
        let updated = read("case_update_status.json");
        assert!(
            updated["response"].is_array(),
            "bulk update returns an array"
        );
        cases::decode_case(&updated["response"][0]).expect("updated case decodes");
        let conflict = read("case_conflict.json");
        assert!(
            conflict.get("error").is_some(),
            "the stale-version exchange records an error fixture"
        );
        assert_eq!(
            conflict["error"]["kind"],
            serde_json::json!("conflict"),
            "{}: the stale-version PATCH must classify as a conflict",
            set.display()
        );
        assert_eq!(
            conflict["error"]["http_status"],
            serde_json::json!(409),
            "{}: the stale-version PATCH must record the real 409",
            set.display()
        );

        // case_delete: a 204 has no body, so the response side is empty; the
        // request path carries the id array, JSON-encoded then URL-encoded
        // (`elasticctl_api::cases::delete_path`) — assert on a stable
        // substring rather than the whole path, since the placeholder id is
        // itself a scrubbing artifact, not a documented contract.
        let deleted = read("case_delete.json");
        assert!(
            deleted["response"].is_null(),
            "{}: a 204 delete has no recorded body",
            set.display()
        );
        let deleted_id = deleted["request"]["ids"][0]
            .as_str()
            .expect("case_delete request carries the deleted id");
        let deleted_path = deleted["request"]["path"]
            .as_str()
            .expect("case_delete request carries the issued path");
        assert!(
            deleted_path.contains(&format!("%5B%22{deleted_id}")),
            "{}: the delete path must carry the URL-encoded JSON id array: {deleted_path}",
            set.display()
        );
    }
}

#[tokio::test]
async fn agent_policy_fixtures_decode_through_the_production_paths() {
    use elasticctl_api::fleet::agent_policies::{self, AgentPolicySpec};
    use elasticctl_api::fleet::agent_policy_ops;
    for set in fixture_sets() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(fixture_body(&set.join("status.json"))["response"].clone()),
            )
            .mount(&server)
            .await;
        let list = fixture_body(&set.join("agent_policies_list.json"));
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies"))
            .and(query_param("sortField", "created_at"))
            .respond_with(ResponseTemplate::new(200).set_body_json(list["response"].clone()))
            .mount(&server)
            .await;
        let got = fixture_body(&set.join("agent_policy_get.json"));
        Mock::given(method("GET"))
            .and(path(
                "/api/fleet/agent_policies/elasticctl-sample-agent-policy",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(got["response"].clone()))
            .mount(&server)
            .await;
        let package = fixture_body(&set.join("package_elastic_agent.json"));
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/elastic_agent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(package["response"].clone()))
            .mount(&server)
            .await;
        let delete = fixture_body(&set.join("agent_policy_delete.json"));
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies/delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(delete["response"].clone()))
            .mount(&server)
            .await;
        let transport = fixture_transport(&server);

        let package_status = agent_policies::package_status(&transport, "elastic_agent")
            .await
            .expect("package status decodes through the production path");
        assert_eq!(
            package_status,
            agent_policies::PackageStatus {
                name: "elastic_agent".into(),
                status: "not_installed".into(),
                installed_version: None,
            },
            "{}",
            set.display()
        );

        let items = agent_policy_ops::collect(&transport)
            .await
            .expect("collect");
        assert_eq!(items.len(), 1, "{}", set.display());
        assert_eq!(items[0]["id"], "elasticctl-sample-agent-policy");

        let live = agent_policies::get(&transport, "elasticctl-sample-agent-policy")
            .await
            .expect("get");
        let spec = agent_policy_ops::normalize(&live.item, "default").expect("normalize");
        assert_eq!(spec.inactivity_timeout, 1209600, "{}", set.display());
        assert!(spec.monitoring_enabled.is_empty());

        let create = fixture_body(&set.join("agent_policy_create.json"));
        assert_eq!(
            create["request"]["monitoring_enabled"],
            serde_json::json!([])
        );
        assert_eq!(
            create["response"]["item"]["id"],
            "elasticctl-sample-agent-policy"
        );
        // The default table is complete only if the stored policy, normalized,
        // equals the spec that was sent. This is the offline round-trip proof.
        let requested = AgentPolicySpec::try_from(create["request"].clone())
            .expect("recorded create request is a valid spec");
        let stored = agent_policy_ops::normalize(
            create["response"]["item"]
                .as_object()
                .expect("created item"),
            "default",
        )
        .expect("normalize the created policy");
        assert_eq!(
            stored,
            requested,
            "{}: the create response carries a server default the table lacks",
            set.display()
        );

        let updated = fixture_body(&set.join("agent_policy_update.json"));
        assert_eq!(
            updated["response"]["item"]["unenroll_timeout"],
            3600,
            "{}",
            set.display()
        );
        let after_omit = fixture_body(&set.join("agent_policy_get_after_omit.json"));
        assert_eq!(
            after_omit["response"]["item"]["unenroll_timeout"],
            3600,
            "{}: the update route merges, so an omitted field survives",
            set.display()
        );

        let deleted = fixture_body(&set.join("agent_policy_delete.json"));
        assert_eq!(deleted["response"]["id"], "elasticctl-sample-agent-policy");
        agent_policies::delete(&transport, "elasticctl-sample-agent-policy")
            .await
            .expect("delete decodes through the production path");
        let conflict = fixture_body(&set.join("agent_policy_name_conflict.json"));
        assert_eq!(conflict["error"]["kind"], "conflict", "{}", set.display());
    }
}

#[tokio::test]
async fn integration_policy_fixtures_decode_through_the_production_paths() {
    use elasticctl_api::content_codec::ContentFormat;
    use elasticctl_api::fleet::agent_policies::{self, AgentPolicySpec};
    use elasticctl_api::fleet::integration_policies::{self, IntegrationPolicySpec};
    use elasticctl_api::fleet::integration_policy_ops::{self, IntegrationPolicyFilter};
    use elasticctl_core::urlencode;

    for set in fixture_sets() {
        let read = |name: &str| fixture_body(&set.join(name));
        let integration_not_found = read("integration_policy_not_found.json");
        let parent_not_found = read("integration_policy_parent_not_found.json");
        let package_status_fixture = read("package_system.json");
        let parent_create = read("integration_policy_parent_create.json");
        let package_metadata_fixture = read("package_system_metadata.json");
        let create = read("integration_policy_create.json");
        let got_fixture = read("integration_policy_get.json");
        let list_fixture = read("integration_policies_list.json");
        let conflict = read("integration_policy_name_conflict.json");
        let parent_get = read("integration_policy_parent_get.json");
        let update = read("integration_policy_update.json");
        let round_trip = read("integration_policy_round_trip.json");
        let integration_delete = read("integration_policy_delete.json");
        let integration_delete_not_found = read("integration_policy_delete_not_found.json");
        let parent_delete = read("integration_policy_parent_delete.json");
        let parent_delete_not_found = read("integration_policy_parent_delete_not_found.json");

        for (fixture, kind, status) in [
            (&integration_not_found, "not_found", 404),
            (&parent_not_found, "not_found", 404),
            (&integration_delete_not_found, "not_found", 404),
            (&parent_delete_not_found, "not_found", 404),
            (&conflict, "conflict", 409),
        ] {
            assert_eq!(fixture["error"]["kind"], kind, "{}", set.display());
            assert_eq!(fixture["error"]["http_status"], status, "{}", set.display());
            let error = fixture["error"]
                .as_object()
                .unwrap_or_else(|| panic!("{}: error envelope must be an object", set.display()));
            assert_eq!(
                error.keys().map(String::as_str).collect::<BTreeSet<_>>(),
                ["http_status", "kind", "message"]
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                "{}: error envelope must contain only safe fields",
                set.display()
            );
            assert_eq!(
                error["message"],
                "Fleet integration-policy recording endpoint returned an error",
                "{}: error envelope message",
                set.display()
            );
        }

        let create_request = create["request"].clone();
        let requested =
            IntegrationPolicySpec::try_from(create_request.clone()).unwrap_or_else(|error| {
                panic!("{}: integration create request: {error}", set.display())
            });
        let marker_id = requested.id.clone();
        assert!(
            marker_id.starts_with("elasticctl-sample-"),
            "{}: integration create must use a marker id",
            set.display()
        );
        assert_eq!(create_request["id"], marker_id, "{}", set.display());
        assert!(
            create_request.get("force").is_none(),
            "{}: integration create must not send force",
            set.display()
        );
        assert!(
            create_request.get("create_dataset_templates").is_none(),
            "{}: integration create must not send create_dataset_templates",
            set.display()
        );

        let parent_request = parent_create["request"].clone();
        let parent_spec = AgentPolicySpec::try_from(parent_request.clone())
            .unwrap_or_else(|error| panic!("{}: parent create request: {error}", set.display()));
        let parent_id = parent_spec.id.clone();
        assert!(
            parent_id.starts_with("elasticctl-sample-"),
            "{}: parent create must use a marker id",
            set.display()
        );
        assert_eq!(requested.policy_ids, vec![parent_id.clone()]);
        assert!(
            parent_request.get("force").is_none(),
            "{}: parent create must not send force",
            set.display()
        );

        let mut update_spec_value = update["request"].clone();
        let update_object = update_spec_value
            .as_object_mut()
            .unwrap_or_else(|| panic!("{}: update request must be an object", set.display()));
        assert!(
            update_object.get("id").is_none(),
            "{}: integration update must omit id from its wire body",
            set.display()
        );
        assert_eq!(update_object.get("enabled"), Some(&serde_json::json!(true)));
        assert!(
            update_object.get("force").is_none(),
            "{}: integration update must not send force",
            set.display()
        );
        assert!(
            update_object.get("create_dataset_templates").is_none(),
            "{}: integration update must not send create_dataset_templates",
            set.display()
        );
        update_object.remove("enabled");
        update_object.insert("id".into(), serde_json::json!(marker_id));
        let updated_spec =
            IntegrationPolicySpec::try_from(update_spec_value).unwrap_or_else(|error| {
                panic!("{}: integration update request: {error}", set.display())
            });

        assert_package_metadata_shape(
            &package_metadata_fixture["response"],
            &requested.package.name,
            &requested.package.version,
            &format!("{}: package_system_metadata", set.display()),
        );
        let package_status_item = package_status_fixture["response"]["item"]
            .as_object()
            .unwrap_or_else(|| panic!("{}: package status item", set.display()));
        assert_eq!(
            package_status_item.get("name").and_then(Value::as_str),
            Some(requested.package.name.as_str()),
            "{}: package status name",
            set.display()
        );

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(fixture_body(&set.join("status.json"))["response"].clone()),
            )
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies"))
            .and(query_param("sys_monitoring", "false"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(parent_create["response"].clone()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{}",
                urlencode(&parent_id)
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(parent_get["response"].clone()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies/delete"))
            .and(body_json(serde_json::json!({"agentPolicyId": parent_id})))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(parent_delete["response"].clone()),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/epm/packages/{}",
                urlencode(&requested.package.name)
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(package_status_fixture["response"].clone()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/epm/packages/{}/{}",
                urlencode(&requested.package.name),
                urlencode(&requested.package.version)
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(package_metadata_fixture["response"].clone()),
            )
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(body_json(create_request.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(create["response"].clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{}",
                urlencode(&marker_id)
            )))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(got_fixture["response"].clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("page", "1"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortField", "created_at"))
            .and(query_param("sortOrder", "asc"))
            .and(query_param("format", "simplified"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(list_fixture["response"].clone()),
            )
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(format!(
                "/api/fleet/package_policies/{}",
                urlencode(&marker_id)
            )))
            .and(body_json(update["request"].clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(update["response"].clone()))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/fleet/package_policies/{}",
                urlencode(&marker_id)
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(integration_delete["response"].clone()),
            )
            .mount(&server)
            .await;

        let transport = fixture_transport(&server);
        let parent = agent_policies::create(&transport, &parent_spec)
            .await
            .unwrap_or_else(|error| panic!("{}: decode parent create: {error}", set.display()));
        assert_eq!(
            parent.item.get("id").and_then(Value::as_str),
            Some(parent_id.as_str())
        );

        let package_status = agent_policies::package_status(&transport, &requested.package.name)
            .await
            .unwrap_or_else(|error| panic!("{}: decode package status: {error}", set.display()));
        assert_eq!(
            package_status.name,
            requested.package.name,
            "{}",
            set.display()
        );
        assert_eq!(
            package_status.status,
            package_status_item["status"].as_str().unwrap_or_default(),
            "{}",
            set.display()
        );
        let expected_installed_version = package_status_item
            .get("installationInfo")
            .and_then(Value::as_object)
            .and_then(|info| info.get("version"))
            .and_then(Value::as_str);
        assert_eq!(
            package_status.installed_version.as_deref(),
            expected_installed_version,
            "{}: package status installed version",
            set.display()
        );

        let metadata = integration_policies::package_metadata(
            &transport,
            &requested.package.name,
            &requested.package.version,
        )
        .await
        .unwrap_or_else(|error| panic!("{}: decode package metadata: {error}", set.display()));
        let _ = metadata;

        let created = integration_policies::create(&transport, &requested)
            .await
            .unwrap_or_else(|error| {
                panic!("{}: decode integration create: {error}", set.display())
            });
        assert_eq!(
            created.item.get("id").and_then(Value::as_str),
            Some(marker_id.as_str())
        );
        let normalized = integration_policy_ops::normalize(&created.item, transport.space())
            .unwrap_or_else(|error| {
                panic!("{}: normalize integration create: {error}", set.display())
            });
        assert_eq!(
            normalized,
            requested,
            "{}: create/normalize round trip",
            set.display()
        );

        let got = integration_policies::get(&transport, &marker_id)
            .await
            .unwrap_or_else(|error| panic!("{}: decode integration get: {error}", set.display()));
        assert_eq!(
            got.item.get("id").and_then(Value::as_str),
            Some(marker_id.as_str())
        );

        let parent_item = parent_get["response"]["item"]
            .as_object()
            .unwrap_or_else(|| panic!("{}: parent get item", set.display()));
        let attached = parent_item["package_policies"]
            .as_array()
            .unwrap_or_else(|| panic!("{}: parent package_policies", set.display()));
        assert!(
            attached.iter().any(|entry| {
                entry.as_str() == Some(marker_id.as_str())
                    || entry.get("id").and_then(Value::as_str) == Some(marker_id.as_str())
            }),
            "{}: parent get must retain the marker attachment",
            set.display()
        );
        let parent_read = agent_policies::get(&transport, &parent_id)
            .await
            .unwrap_or_else(|error| panic!("{}: decode parent get: {error}", set.display()));
        assert_eq!(
            parent_read.item.get("id").and_then(Value::as_str),
            Some(parent_id.as_str()),
            "{}",
            set.display()
        );

        let listed_raw = list_fixture["response"]["items"]
            .as_array()
            .unwrap_or_else(|| panic!("{}: integration list items", set.display()));
        assert_eq!(
            list_fixture["response"]["total"],
            1,
            "{}: integration list must report only the marker",
            set.display()
        );
        assert_eq!(
            listed_raw.len(),
            1,
            "{}: marker-only integration list",
            set.display()
        );
        assert_eq!(
            listed_raw[0].get("id").and_then(Value::as_str),
            Some(marker_id.as_str()),
            "{}: integration list id",
            set.display()
        );
        let listed =
            integration_policy_ops::list_op(&transport, &IntegrationPolicyFilter::default())
                .await
                .unwrap_or_else(|error| {
                    panic!("{}: decode integration list: {error}", set.display())
                });
        assert_eq!(listed.total, 1, "{}", set.display());
        assert_eq!(listed.integration_policies.len(), 1, "{}", set.display());
        assert_eq!(
            listed.integration_policies[0].id,
            marker_id,
            "{}",
            set.display()
        );

        let detail = integration_policy_ops::get_op(&transport, &marker_id)
            .await
            .unwrap_or_else(|error| {
                panic!("{}: decode integration detail: {error}", set.display())
            });
        assert_eq!(detail.id, marker_id, "{}", set.display());
        assert_eq!(
            detail.policy_ids,
            vec![parent_id.clone()],
            "{}",
            set.display()
        );
        assert_eq!(detail.package, requested.package, "{}", set.display());
        assert_eq!(detail.blocked_by, Vec::<String>::new(), "{}", set.display());

        let exported = integration_policy_ops::export(
            &transport,
            std::slice::from_ref(&marker_id),
            false,
            ContentFormat::Json,
        )
        .await;
        match package_status.status.as_str() {
            "installed"
                if package_status.installed_version.as_deref()
                    == Some(&requested.package.version) =>
            {
                let exported = exported.unwrap_or_else(|error| {
                    panic!("{}: decode integration export: {error}", set.display())
                });
                assert_eq!(exported.exported, 1, "{}", set.display());
                let specs: Vec<IntegrationPolicySpec> = serde_json::from_str(&exported.body)
                    .unwrap_or_else(|error| {
                        panic!("{}: decode exported integration: {error}", set.display())
                    });
                assert_eq!(specs, vec![requested.clone()], "{}", set.display());
            }
            "not_installed" => {
                assert_eq!(
                    exported
                        .expect_err("an absent package cannot prove a live integration export")
                        .kind,
                    elasticctl_core::ErrorKind::Conflict,
                    "{}",
                    set.display()
                );
            }
            status => panic!("{}: unexpected package status {status:?}", set.display()),
        }

        let updated = integration_policies::update(&transport, &marker_id, &updated_spec)
            .await
            .unwrap_or_else(|error| {
                panic!("{}: decode integration update: {error}", set.display())
            });
        assert_eq!(
            updated.item.get("id").and_then(Value::as_str),
            Some(marker_id.as_str())
        );
        let normalized_round_trip = integration_policy_ops::normalize(
            round_trip["response"]["item"]
                .as_object()
                .unwrap_or_else(|| panic!("{}: round-trip item", set.display())),
            transport.space(),
        )
        .unwrap_or_else(|error| {
            panic!(
                "{}: normalize integration round trip: {error}",
                set.display()
            )
        });
        assert_eq!(
            normalized_round_trip,
            updated_spec,
            "{}: update must replace omitted fields rather than merge them",
            set.display()
        );
        for field in [
            "description",
            "vars",
            "var_group_selections",
            "condition",
            "additional_datastreams_permissions",
        ] {
            if create_request.get(field).is_some() && update["request"].get(field).is_none() {
                assert!(
                    round_trip["response"]
                        .get("item")
                        .and_then(|item| item.get(field))
                        .is_none(),
                    "{}: omitted update field {field} survived a full replacement",
                    set.display()
                );
            }
        }

        let integration_delete_id = integration_delete["response"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{}: integration delete id", set.display()));
        assert_eq!(integration_delete_id, marker_id, "{}", set.display());
        integration_policies::delete(&transport, &marker_id)
            .await
            .unwrap_or_else(|error| {
                panic!("{}: decode integration delete: {error}", set.display())
            });

        let parent_delete_id = parent_delete["response"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{}: parent delete id", set.display()));
        assert_eq!(parent_delete_id, parent_id, "{}", set.display());
        agent_policies::delete(&transport, &parent_id)
            .await
            .unwrap_or_else(|error| panic!("{}: decode parent delete: {error}", set.display()));
    }
}
