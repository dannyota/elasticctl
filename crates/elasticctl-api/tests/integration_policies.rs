use elasticctl_api::content_codec::{self, ContentFormat};
use elasticctl_api::fleet::integration_policies::{self, IntegrationPolicySpec};
use elasticctl_api::fleet::integration_policy_ops::{self, IntegrationPolicyFilter};
use elasticctl_core::{ErrorKind, Feature, Profile, Transport};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn verified_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.5.1", "build_flavor": "traditional"}
        })))
        .mount(&server)
        .await;
    server
}

fn transport_for(server: &MockServer) -> Transport {
    Transport::new(&Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .expect("transport")
}

fn spec_json(id: &str) -> Value {
    json!({
        "id": id,
        "name": format!("Integration {id}"),
        "namespace": "default",
        "policy_ids": ["parent-1"],
        "package": {"name": "system", "version": "2.0.0"},
        "inputs": {}
    })
}

fn set_path(value: &mut Value, path: &str, replacement: Value) {
    let mut segments = path.split('.').peekable();
    let mut current = value;
    while let Some(segment) = segments.next() {
        if segments.peek().is_none() {
            current[segment] = replacement;
            return;
        }
        current = current
            .get_mut(segment)
            .expect("canonical helper path must exist");
    }
}

#[test]
fn integration_policy_spec_rejects_noncanonical_identity_and_parent_lists() {
    for (field, value) in [
        ("id", json!(" ")),
        ("name", json!("")),
        ("package.name", json!("")),
        ("package.version", json!(" ")),
    ] {
        let mut raw = spec_json("integration-1");
        set_path(&mut raw, field, value);
        assert!(
            IntegrationPolicySpec::try_from(raw).is_err(),
            "{field} must be rejected"
        );
    }
    for ids in [
        json!([]),
        json!(["parent-1", "parent-1"]),
        json!(["parent-2", "parent-1"]),
    ] {
        let mut raw = spec_json("integration-1");
        raw["policy_ids"] = ids;
        assert!(IntegrationPolicySpec::try_from(raw).is_err());
    }
}

#[test]
fn integration_policy_spec_rejects_unknown_or_malformed_portable_fields() {
    for (field, value) in [
        ("unknown", json!(true)),
        ("inputs", json!([])),
        ("var_group_selections", json!({"group": false})),
        ("additional_datastreams_permissions", json!(["logs-*", 4])),
    ] {
        let mut raw = spec_json("integration-1");
        raw[field] = value;
        assert!(
            IntegrationPolicySpec::try_from(raw).is_err(),
            "{field} must be rejected"
        );
    }
}

#[test]
fn integration_policy_spec_round_trips_json_yaml_and_open_package_owned_maps() {
    let mut raw = spec_json("integration-1");
    raw["vars"] = json!({
        "nested": {"arbitrary": [true, {"deep": "value"}]}
    });
    raw["var_group_selections"] = json!({"group": "selected"});
    raw["inputs"] = json!({
        "system-system/metrics": {
            "enabled": true,
            "vars": {"period": {"value": "10s", "package_future": [1, 2]}},
            "streams": {"system.cpu": {"enabled": true, "vars": {"top_n": 5}}}
        }
    });
    raw["additional_datastreams_permissions"] = json!(["logs-system.*"]);
    let spec = IntegrationPolicySpec::try_from(raw).expect("portable spec");
    for format in [ContentFormat::Json, ContentFormat::Yaml] {
        let body =
            content_codec::encode_sequence(std::slice::from_ref(&spec), format).expect("encode");
        let decoded: Vec<IntegrationPolicySpec> =
            content_codec::decode_sequence(&body, format, "integration policy").expect("decode");
        assert_eq!(decoded, vec![spec.clone()]);
    }
    assert_eq!(
        spec.inputs["system-system/metrics"]["vars"]["period"]["package_future"],
        json!([1, 2])
    );
}

fn item(id: &str) -> Value {
    json!({
        "id": id,
        "name": format!("Integration {id}"),
        "namespace": "default",
        "policy_ids": ["parent-1"],
        "package": {"name": "system", "version": "2.0.0"},
        "inputs": {}
    })
}

fn live_item(id: &str) -> serde_json::Map<String, Value> {
    let mut item = item(id).as_object().expect("item object").clone();
    item.insert("enabled".into(), json!(true));
    item
}

async fn mount_integration_pages(server: &MockServer, pages: Vec<(u64, Vec<Value>, u64)>) {
    for (page, items, total) in pages {
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("page", page.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": items, "total": total, "page": page, "perPage": 1000
            })))
            .mount(server)
            .await;
    }
}

#[tokio::test]
async fn list_collects_pages_then_sorts_searches_and_limits_locally() {
    let server = verified_server().await;
    let mut decorated = item("z");
    decorated["package"]["title"] = json!("System");
    mount_integration_pages(&server, vec![(1, vec![decorated, item("a")], 2)]).await;

    let result = integration_policy_ops::list_op(
        &transport_for(&server),
        &IntegrationPolicyFilter {
            search: Some("INT".into()),
            limit: Some(1),
        },
    )
    .await
    .expect("list");
    assert_eq!(result.total, 2);
    assert_eq!(result.integration_policies[0].id, "a");
    assert!(result.truncated);
}

#[tokio::test]
async fn collect_rejects_paging_contradictions() {
    let duplicate = verified_server().await;
    mount_integration_pages(
        &duplicate,
        vec![(1, vec![item("integration-1"), item("integration-1")], 2)],
    )
    .await;
    let error = integration_policy_ops::collect(&transport_for(&duplicate))
        .await
        .expect_err("duplicate id");
    assert_eq!(error.kind, ErrorKind::Http);
    assert!(error.message.contains("duplicate integration policy id"));

    let short = verified_server().await;
    mount_integration_pages(&short, vec![(1, vec![item("integration-1")], 2)]).await;
    let error = integration_policy_ops::collect(&transport_for(&short))
        .await
        .expect_err("short page");
    assert_eq!(error.kind, ErrorKind::Http);
    assert!(error.message.contains("page was short before total"));

    let changed_total = verified_server().await;
    let first: Vec<Value> = (0..1000).map(|index| item(&format!("i-{index}"))).collect();
    mount_integration_pages(
        &changed_total,
        vec![(1, first, 1001), (2, vec![item("final")], 1002)],
    )
    .await;
    let error = integration_policy_ops::collect(&transport_for(&changed_total))
        .await
        .expect_err("changed total");
    assert_eq!(error.kind, ErrorKind::Http);
    assert!(error.message.contains("total changed while paging"));

    for (page, per_page) in [(2, 1000), (1, 10)] {
        let metadata = verified_server().await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [], "total": 0, "page": page, "perPage": per_page
            })))
            .mount(&metadata)
            .await;
        let error = integration_policy_ops::collect(&transport_for(&metadata))
            .await
            .expect_err("mismatched page metadata");
        assert_eq!(error.kind, ErrorKind::Http);
        assert!(error.message.contains("unexpected page metadata"));
    }
}

#[tokio::test]
async fn resolve_prefers_id_then_uses_exact_name_and_rejects_ambiguity() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item": item("integration-1")})),
        )
        .expect(1)
        .mount(&server)
        .await;
    for selector in ["A%20named%20integration", "Twin"] {
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/package_policies/{selector}")))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(json!({"statusCode": 404, "message": "missing"})),
            )
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/by-name"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("by-name")})))
        .expect(1)
        .mount(&server)
        .await;
    let mut named = item("by-name");
    named["name"] = json!("A named integration");
    let mut twin_a = item("twin-a");
    twin_a["name"] = json!("Twin");
    let mut twin_b = item("twin-b");
    twin_b["name"] = json!("Twin");
    mount_integration_pages(&server, vec![(1, vec![named, twin_a, twin_b], 3)]).await;

    let transport = transport_for(&server);
    assert_eq!(
        integration_policy_ops::resolve(&transport, "integration-1")
            .await
            .unwrap()
            .id,
        "integration-1"
    );
    assert_eq!(
        integration_policy_ops::resolve(&transport, "A named integration")
            .await
            .unwrap()
            .id,
        "by-name"
    );
    let error = integration_policy_ops::resolve(&transport, "Twin")
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert!(error.message.contains("twin-a, twin-b"));
}

#[test]
fn normalize_builds_a_portable_value_and_refuses_unsafe_live_state() {
    let mut raw = live_item("integration-1");
    raw.extend(
        json!({
            "enabled": true,
            "revision": 1,
            "version": "WzEsMV0=",
            "created_at": "now",
            "created_by": "user",
            "updated_at": "later",
            "updated_by": "user",
            "policy_id": "parent-1",
            "spaceIds": ["default"],
            "agents": 2,
            "secret_references": [],
            "is_managed": false,
            "supports_agentless": false,
            "supports_cloud_connector": false,
            "cloud_connector_id": null,
            "cloud_connector_name": null,
            "output_id": null
        })
        .as_object()
        .expect("object")
        .clone(),
    );
    raw.get_mut("package").unwrap().as_object_mut().unwrap().extend(
        json!({"title": "System", "requires_root": false, "fips_compatible": false, "package_agent_version_condition": ""})
            .as_object().unwrap().clone(),
    );
    let normalized = integration_policy_ops::normalize(&raw, "default").expect("normalize");
    assert_eq!(
        normalized,
        IntegrationPolicySpec::try_from(spec_json("integration-1")).unwrap()
    );

    for (field, value) in [
        ("enabled", json!(false)),
        ("is_managed", json!(true)),
        ("supports_agentless", json!(true)),
        ("supports_cloud_connector", json!(true)),
        ("output_id", json!("output-1")),
        ("cloud_connector_id", json!("connector-1")),
        ("secret_references", json!([{"id": "secret"}])),
        ("spaceIds", json!(["other"])),
    ] {
        let mut unsafe_item = live_item("integration-1");
        unsafe_item.insert(field.into(), value);
        let error = integration_policy_ops::normalize(&unsafe_item, "default").unwrap_err();
        assert_eq!(
            error.kind,
            ErrorKind::Unsupported,
            "{field}: {}",
            error.message
        );
    }
}

#[test]
fn normalize_rejects_malformed_server_shapes_and_unknown_top_level_fields() {
    for (field, value) in [
        ("enabled", json!(null)),
        ("is_managed", json!("false")),
        ("spaceIds", json!("default")),
        ("inputs", json!([])),
        ("secret_references", json!({})),
    ] {
        let mut raw = live_item("integration-1");
        raw.insert(field.into(), value);
        let error = integration_policy_ops::normalize(&raw, "default").unwrap_err();
        assert_eq!(error.kind, ErrorKind::Http, "{field}: {}", error.message);
    }
    let mut package = live_item("integration-1");
    package.insert("package".into(), json!({"name": "system", "version": 2}));
    assert_eq!(
        integration_policy_ops::normalize(&package, "default")
            .unwrap_err()
            .kind,
        ErrorKind::Http
    );
    let mut decoration = live_item("integration-1");
    decoration["package"]["title"] = json!(false);
    assert_eq!(
        integration_policy_ops::normalize(&decoration, "default")
            .unwrap_err()
            .kind,
        ErrorKind::Http
    );

    let mut unknown = live_item("integration-1");
    unknown.insert("future_field".into(), json!(true));
    let error = integration_policy_ops::normalize(&unknown, "default").unwrap_err();
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert!(error.message.contains("future_field"));
}

#[test]
fn validate_decodes_json_and_yaml_rejects_duplicates_and_sorts() {
    let dir = tempfile::tempdir().unwrap();
    let duplicate_ids = dir.path().join("duplicate-ids.json");
    std::fs::write(&duplicate_ids, r#"[{"id":"a","name":"A","policy_ids":["parent-1"],"package":{"name":"system","version":"2.0.0"},"inputs":{}},{"id":"a","name":"B","policy_ids":["parent-1"],"package":{"name":"system","version":"2.0.0"},"inputs":{}}]"#).unwrap();
    let error = integration_policy_ops::validate(&duplicate_ids).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Error);
    assert!(
        error
            .message
            .contains("duplicate integration policy ids: a")
    );

    let duplicate_names = dir.path().join("duplicate-names.json");
    std::fs::write(&duplicate_names, r#"[{"id":"a","name":"Same","policy_ids":["parent-1"],"package":{"name":"system","version":"2.0.0"},"inputs":{}},{"id":"b","name":"Same","policy_ids":["parent-1"],"package":{"name":"system","version":"2.0.0"},"inputs":{}}]"#).unwrap();
    let error = integration_policy_ops::validate(&duplicate_names).unwrap_err();
    assert!(
        error
            .message
            .contains("duplicate integration policy names: Same")
    );

    let yaml = dir.path().join("policies.yaml");
    std::fs::write(&yaml, "- id: b\n  name: B\n  policy_ids: [parent-1]\n  package: {name: system, version: 2.0.0}\n  inputs: {}\n- id: a\n  name: A\n  policy_ids: [parent-1]\n  package: {name: system, version: 2.0.0}\n  inputs: {}\n").unwrap();
    let specs = integration_policy_ops::validate(&yaml).expect("offline validation");
    assert_eq!(
        specs
            .iter()
            .map(|spec| spec.id.as_str())
            .collect::<Vec<_>>(),
        ["a", "b"]
    );
}

fn spec(id: &str) -> IntegrationPolicySpec {
    IntegrationPolicySpec::try_from(spec_json(id)).expect("spec")
}

#[tokio::test]
async fn list_page_pins_simplified_query_and_strict_page_envelope() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies"))
        .and(query_param("page", "1"))
        .and(query_param("perPage", "1000"))
        .and(query_param("sortField", "created_at"))
        .and(query_param("sortOrder", "asc"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [item("integration-1")], "total": 1, "page": 1, "perPage": 1000
        })))
        .mount(&server)
        .await;
    let page = integration_policies::list_page(&transport_for(&server), 1)
        .await
        .expect("page");
    assert_eq!((page.total, page.page, page.per_page), (1, 1, 1000));
    assert_eq!(page.items[0]["id"], "integration-1");
}

#[tokio::test]
async fn list_page_rejects_missing_mistyped_and_extra_envelope_fields() {
    for response in [
        json!({"items": [], "total": 0, "page": 1}),
        json!({"items": {}, "total": 0, "page": 1, "perPage": 1000}),
        json!({"items": [], "total": 0, "page": 1, "perPage": 1000, "extra": true}),
    ] {
        let server = verified_server().await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
        let error = integration_policies::list_page(&transport_for(&server), 1)
            .await
            .expect_err("malformed list envelope");
        assert_eq!(error.kind, ErrorKind::Http);
    }
}

#[tokio::test]
async fn get_uses_encoded_simplified_route_and_rejects_bad_item_envelopes() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration%2F1"))
        .and(query_param("format", "simplified"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item": item("integration/1")})),
        )
        .mount(&server)
        .await;
    integration_policies::get(&transport_for(&server), "integration/1")
        .await
        .expect("encoded get");

    for response in [
        json!({}),
        json!({"item": []}),
        json!({"item": {}, "extra": true}),
    ] {
        let server = verified_server().await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/integration-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
        let error = integration_policies::get(&transport_for(&server), "integration-1")
            .await
            .expect_err("malformed item envelope");
        assert_eq!(error.kind, ErrorKind::Http);
    }
}

#[tokio::test]
async fn create_and_update_use_exact_safe_wire_shapes() {
    let server = verified_server().await;
    let create_body = serde_json::to_value(spec("integration-1")).expect("serialize");
    Mock::given(method("POST"))
        .and(path("/api/fleet/package_policies"))
        .and(body_json(create_body))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item": item("integration-1")})),
        )
        .mount(&server)
        .await;
    integration_policies::create(&transport_for(&server), &spec("integration-1"))
        .await
        .expect("create");

    let update_body = json!({
        "name": "Integration integration-1",
        "namespace": "default",
        "policy_ids": ["parent-1"],
        "package": {"name": "system", "version": "2.0.0"},
        "inputs": {},
        "enabled": true
    });
    Mock::given(method("PUT"))
        .and(path("/api/fleet/package_policies/integration%2F1"))
        .and(body_json(update_body))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item": item("integration/1")})),
        )
        .mount(&server)
        .await;
    integration_policies::update(
        &transport_for(&server),
        "integration/1",
        &spec("integration-1"),
    )
    .await
    .expect("update");
}

#[tokio::test]
async fn delete_requires_the_exact_single_id_success_body() {
    let server = verified_server().await;
    Mock::given(method("DELETE"))
        .and(path("/api/fleet/package_policies/integration%2F1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "integration/1"})))
        .mount(&server)
        .await;
    integration_policies::delete(&transport_for(&server), "integration/1")
        .await
        .expect("delete");

    for response in [
        json!({"id": "other"}),
        json!({"id": "integration-1", "name": "extra"}),
    ] {
        let server = verified_server().await;
        Mock::given(method("DELETE"))
            .and(path("/api/fleet/package_policies/integration-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
        let error = integration_policies::delete(&transport_for(&server), "integration-1")
            .await
            .expect_err("wrong delete body");
        assert_eq!(error.kind, ErrorKind::Http);
    }
}

#[tokio::test]
async fn package_metadata_requires_the_exact_encoded_coordinate() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system%2Flogs/2.0.0%2Bbuild"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "system/logs", "version": "2.0.0+build", "policy_templates": []
        }})))
        .mount(&server)
        .await;
    integration_policies::package_metadata(&transport_for(&server), "system/logs", "2.0.0+build")
        .await
        .expect("metadata");

    for item in [
        json!({"name": "other", "version": "2.0.0"}),
        json!({"name": "system", "version": "other"}),
    ] {
        let server = verified_server().await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item})))
            .mount(&server)
            .await;
        let error =
            integration_policies::package_metadata(&transport_for(&server), "system", "2.0.0")
                .await
                .expect_err("invalid metadata");
        assert_eq!(error.kind, ErrorKind::Http);
    }
}

#[tokio::test]
async fn package_metadata_rejects_blank_requested_coordinates_before_the_route() {
    for (name, version) in [
        ("", "2.0.0"),
        (" ", "2.0.0"),
        ("system", ""),
        ("system", " "),
    ] {
        let server = verified_server().await;
        let transport = transport_for(&server);
        transport
            .require_feature(Feature::FleetPolicies)
            .await
            .expect("feature gate");

        let error = integration_policies::package_metadata(&transport, name, version)
            .await
            .expect_err("blank requested coordinate");
        assert_eq!(error.kind, ErrorKind::Error);
        assert_eq!(server.received_requests().await.expect("requests").len(), 1);
    }
}
