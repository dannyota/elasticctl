use elasticctl_api::content_codec::{self, ContentFormat};
use elasticctl_api::fleet::agent_policies::PLATFORM_FLAGS;
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

fn parent_item(id: &str, namespace: &str, agents: u64, attached: Value) -> Value {
    json!({
        "id": id,
        "name": format!("Parent {id}"),
        "namespace": namespace,
        "agents": agents,
        "package_policies": attached,
    })
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

fn installed_package(version: &str) -> Value {
    json!({
        "name": "system",
        "status": "installed",
        "installationInfo": {"version": version},
    })
}

fn package_metadata(vars: Value, policy_templates: Value) -> Value {
    json!({
        "name": "system",
        "version": "2.0.0",
        "vars": vars,
        "policy_templates": policy_templates,
    })
}

fn safe_package_metadata() -> Value {
    package_metadata(json!([]), json!([]))
}

fn secret_matrix_metadata() -> Value {
    package_metadata(
        json!([
            {"name": "package_secret", "secret": true},
            {"name": "package_plain", "secret": false},
        ]),
        json!([
            {
                "name": "system",
                "inputs": [
                    {
                        "type": "system",
                        "vars": [
                            {"name": "input_secret", "secret": true},
                            {"name": "input_plain", "secret": false},
                        ],
                        "streams": [
                            {
                                "data_stream": {"dataset": "system.cpu"},
                                "vars": [
                                    {"name": "stream_secret", "secret": true},
                                    {"name": "stream_plain", "secret": false},
                                ],
                            },
                        ],
                    },
                ],
            },
        ]),
    )
}

async fn mount_export_dependencies(
    server: &MockServer,
    id: &str,
    policy: serde_json::Map<String, Value>,
    parents: Vec<Value>,
    package: Value,
    metadata: Value,
) {
    Mock::given(method("GET"))
        .and(path(format!("/api/fleet/package_policies/{id}")))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": policy})))
        .mount(server)
        .await;
    for parent in parents {
        let parent_id = parent["id"]
            .as_str()
            .expect("test parent has an id")
            .to_owned();
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/agent_policies/{parent_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": parent})))
            .mount(server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": package})))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": metadata})))
        .mount(server)
        .await;
}

async fn request_count(server: &MockServer, route: &str) -> usize {
    server
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|request| request.url.path() == route)
        .count()
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

    let overfull = verified_server().await;
    let overfull_items = (0..1001)
        .map(|index| item(&format!("overfull-{index}")))
        .collect();
    mount_integration_pages(&overfull, vec![(1, overfull_items, 1001)]).await;
    let error = integration_policy_ops::collect(&transport_for(&overfull))
        .await
        .expect_err("overfull page");
    assert_eq!(error.kind, ErrorKind::Http);
    assert!(error.message.contains("more items than requested"));
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

#[tokio::test]
async fn resolve_prefers_an_id_over_a_name_collision() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/collision"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("collision")})))
        .expect(1)
        .mount(&server)
        .await;
    let mut same_name = item("other-id");
    same_name["name"] = json!("collision");
    mount_integration_pages(&server, vec![(1, vec![same_name], 1)]).await;

    let resolved = integration_policy_ops::resolve(&transport_for(&server), "collision")
        .await
        .expect("id wins");
    assert_eq!(resolved.id, "collision");
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
            "output_id": null,
            "package_agent_version_condition": ""
        })
        .as_object()
        .expect("object")
        .clone(),
    );
    raw.get_mut("package")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .extend(
            json!({"title": "System", "requires_root": false, "fips_compatible": false})
                .as_object()
                .unwrap()
                .clone(),
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
fn normalize_removes_each_named_server_field_and_equates_null_false_platform_state() {
    let expected = IntegrationPolicySpec::try_from(spec_json("integration-1")).unwrap();
    for (field, value) in [
        ("enabled", json!(true)),
        ("revision", json!(1)),
        ("version", json!("saved-object-version")),
        ("created_at", json!("now")),
        ("created_by", json!("user")),
        ("updated_at", json!("later")),
        ("updated_by", json!("user")),
        ("policy_id", json!("parent-1")),
        ("spaceIds", json!(["default"])),
        ("elasticsearch", json!({"privileges": {"cluster": []}})),
        ("agents", json!(0)),
        ("secret_references", json!([])),
        ("is_managed", json!(false)),
        ("supports_agentless", json!(false)),
        ("supports_cloud_connector", json!(false)),
        ("cloud_connector_id", Value::Null),
        ("cloud_connector_name", Value::Null),
        ("output_id", Value::Null),
        ("cloud_connector_id", json!(false)),
        ("cloud_connector_name", json!(false)),
        ("output_id", json!(false)),
        ("package_agent_version_condition", json!(">= 9.0.0")),
    ] {
        let mut raw = live_item("integration-1");
        raw.insert(field.into(), value);
        assert_eq!(
            integration_policy_ops::normalize(&raw, "default").expect(field),
            expected,
            "{field} must normalize away"
        );
    }
    for field in [
        "is_managed",
        "supports_agentless",
        "supports_cloud_connector",
    ] {
        let mut raw = live_item("integration-1");
        raw.insert(field.into(), Value::Null);
        assert_eq!(
            integration_policy_ops::normalize(&raw, "default").expect(field),
            expected,
            "{field}: null must equal false and absent"
        );
    }
    let mut raw = live_item("integration-1");
    raw.insert("policy_id".into(), Value::Null);
    assert_eq!(
        integration_policy_ops::normalize(&raw, "default").expect("null policy_id"),
        expected
    );
}

#[test]
fn normalize_removes_valid_generated_nested_content_and_rejects_bad_outer_shapes() {
    let mut raw = live_item("integration-1");
    raw.insert(
        "elasticsearch".into(),
        json!({"privileges": {"cluster": ["monitor"]}}),
    );
    raw.insert(
        "inputs".into(),
        json!({
            "input": {
                "id": "generated-input-id",
                "compiled_input": {"server": "content"},
                "streams": {
                    "stream": {
                        "id": "generated-stream-id",
                        "compiled_stream": {"server": "content"}
                    }
                }
            }
        }),
    );
    let normalized = integration_policy_ops::normalize(&raw, "default").expect("normalize");
    let normalized = serde_json::to_value(normalized).unwrap();
    assert!(normalized.get("elasticsearch").is_none());
    assert!(normalized["inputs"]["input"].get("id").is_none());
    assert!(
        normalized["inputs"]["input"]
            .get("compiled_input")
            .is_none()
    );
    assert!(
        normalized["inputs"]["input"]["streams"]["stream"]
            .get("id")
            .is_none()
    );
    assert!(
        normalized["inputs"]["input"]["streams"]["stream"]
            .get("compiled_stream")
            .is_none()
    );

    for (path, value) in [
        ("input.id", json!([])),
        ("input.compiled_input", json!(false)),
        ("stream.id", json!([])),
        ("stream.compiled_stream", json!(1)),
        ("elasticsearch", json!("bad")),
    ] {
        let mut malformed = raw.clone();
        match path {
            "input.id" => malformed["inputs"]["input"]["id"] = value,
            "input.compiled_input" => malformed["inputs"]["input"]["compiled_input"] = value,
            "stream.id" => malformed["inputs"]["input"]["streams"]["stream"]["id"] = value,
            "stream.compiled_stream" => {
                malformed["inputs"]["input"]["streams"]["stream"]["compiled_stream"] = value
            }
            "elasticsearch" => malformed["elasticsearch"] = value,
            _ => unreachable!("fixed test paths"),
        }
        let error = integration_policy_ops::normalize(&malformed, "default").unwrap_err();
        assert_eq!(error.kind, ErrorKind::Http, "{path}: {}", error.message);
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

    let mut unknown_package = live_item("integration-1");
    unknown_package["package"]["future"] = json!(true);
    let error = integration_policy_ops::normalize(&unknown_package, "default").unwrap_err();
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert!(error.message.contains("unknown package field 'future'"));

    let mut connector_name = live_item("integration-1");
    connector_name.insert("cloud_connector_name".into(), json!("connector"));
    let error = integration_policy_ops::normalize(&connector_name, "default").unwrap_err();
    assert_eq!(error.kind, ErrorKind::Unsupported);
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

#[tokio::test]
async fn get_reads_exact_parent_snapshot_and_returns_only_safe_detail() {
    let server = verified_server().await;
    let policy = live_item("integration-1");
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": policy})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "id": "parent-1", "name": "Parent", "namespace": "default", "agents": 3,
            "package_policies": ["integration-1"], "is_managed": false, "is_protected": false,
            "data_output_id": "environment-only"
        }})))
        .mount(&server)
        .await;

    let detail = integration_policy_ops::get_op(&transport_for(&server), "integration-1")
        .await
        .expect("safe detail");
    assert_eq!(detail.id, "integration-1");
    assert_eq!(detail.affected_agents, 3);
    assert!(detail.blocked_by.is_empty());
    let rendered = serde_json::to_value(detail).unwrap().to_string();
    assert!(!rendered.contains("inputs"));
    assert!(!rendered.contains("environment-only"));
}

#[tokio::test]
async fn export_rejects_bare_selection_before_transport_io() {
    let server = verified_server().await;
    let error =
        integration_policy_ops::export(&transport_for(&server), &[], false, ContentFormat::Json)
            .await
            .expect_err("bare export");
    assert_eq!(error.kind, ErrorKind::Error);
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn export_rejects_contradictory_package_state_before_metadata() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item": live_item("integration-1")})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "id": "parent-1", "name": "Parent", "namespace": "default", "agents": 0,
            "package_policies": ["integration-1"]
        }})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "system", "status": "not_installed",
            "installationInfo": {"version": "2.0.0"}
        }})))
        .mount(&server)
        .await;
    let error = integration_policy_ops::export(
        &transport_for(&server),
        &["integration-1".into()],
        false,
        ContentFormat::Json,
    )
    .await
    .expect_err("contradictory package state");
    assert_eq!(error.kind, ErrorKind::Http);
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.url.path().contains("/system/2.0.0"))
    );
}

#[tokio::test]
async fn export_refuses_package_declared_secrets_without_leaking_values_or_references() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert("vars".into(), json!({"password": "plaintext-secret"}));
    policy.insert("secret_references".into(), json!([]));
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": policy})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "id": "parent-1", "name": "Parent", "namespace": "default", "agents": 0,
            "package_policies": ["integration-1"]
        }})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "system", "status": "installed",
            "installationInfo": {"version": "2.0.0"}
        }})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "system", "version": "2.0.0",
            "vars": [{"name": "password", "secret": true}], "policy_templates": []
        }})))
        .mount(&server)
        .await;
    let error = integration_policy_ops::export(
        &transport_for(&server),
        &["integration-1".into()],
        false,
        ContentFormat::Json,
    )
    .await
    .expect_err("secret");
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert!(error.message.contains("integration-1:vars.password"));
    assert!(!error.message.contains("plaintext-secret"));
    assert!(!error.message.contains("secret_references"));
}

#[tokio::test]
async fn get_reports_disabled_policy_as_a_safe_blocker() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert("enabled".into(), json!(false));
    policy.insert("vars".into(), json!({"password": "must-not-leak"}));
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": policy})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "id": "parent-1", "name": "Parent", "namespace": "default", "agents": 0,
            "package_policies": ["integration-1"]
        }})))
        .mount(&server)
        .await;
    let detail = integration_policy_ops::get_op(&transport_for(&server), "integration-1")
        .await
        .expect("safe disabled detail");
    assert_eq!(detail.blocked_by, vec!["enabled"]);
    assert!(
        !serde_json::to_string(&detail)
            .unwrap()
            .contains("must-not-leak")
    );
}

#[tokio::test]
async fn all_custom_skips_rows_that_become_managed_on_the_full_read() {
    let server = verified_server().await;
    mount_integration_pages(&server, vec![(1, vec![item("integration-1")], 1)]).await;
    let mut managed = live_item("integration-1");
    managed.insert("is_managed".into(), json!(true));
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": managed})))
        .mount(&server)
        .await;
    let result =
        integration_policy_ops::export(&transport_for(&server), &[], true, ContentFormat::Json)
            .await
            .expect("managed row skipped");
    assert_eq!(result.exported, 0);
    let requests = server.received_requests().await.unwrap();
    assert!(
        !requests
            .iter()
            .any(|request| request.url.path().contains("agent_policies"))
    );
    assert!(
        !requests
            .iter()
            .any(|request| request.url.path().contains("epm/packages"))
    );
}

#[tokio::test]
async fn export_rejects_duplicate_metadata_input_keys_before_secret_classification() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert(
        "inputs".into(),
        json!({"system-system": {"vars": {"password": "must-not-leak"}}}),
    );
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": policy})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "id": "parent-1", "name": "Parent", "namespace": "default", "agents": 0,
            "package_policies": ["integration-1"]
        }})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "system", "status": "installed", "installationInfo": {"version": "2.0.0"}
        }})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "system", "version": "2.0.0", "policy_templates": [
                {"name": "system", "inputs": [{"type": "system", "vars": [{"name": "password", "secret": false}]}]},
                {"name": "system", "inputs": [{"type": "system", "vars": [{"name": "password", "secret": true}]}]}
            ]
        }})))
        .mount(&server)
        .await;
    let error = integration_policy_ops::export(
        &transport_for(&server),
        &["integration-1".into()],
        false,
        ContentFormat::Json,
    )
    .await
    .expect_err("duplicate metadata key");
    assert_eq!(error.kind, ErrorKind::Http);
    assert!(
        error
            .message
            .contains("duplicate input key 'system-system'")
    );
    assert!(!error.message.contains("must-not-leak"));
}

#[tokio::test]
async fn get_blocks_namespace_that_differs_from_its_parent_without_exposing_inputs() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert("namespace".into(), json!("integration-space"));
    policy.insert(
        "inputs".into(),
        json!({"hidden": {"value": "must-not-leak"}}),
    );
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": policy})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "id": "parent-1", "name": "Parent", "namespace": "default", "agents": 2,
            "package_policies": ["integration-1"], "data_output_id": "ignored-environment-id"
        }})))
        .mount(&server)
        .await;
    let detail = integration_policy_ops::get_op(&transport_for(&server), "integration-1")
        .await
        .expect("safe detail");
    assert_eq!(detail.blocked_by, vec!["namespace"]);
    assert_eq!(detail.affected_agents, 2);
    let rendered = serde_json::to_string(&detail).unwrap();
    assert!(!rendered.contains("must-not-leak"));
    assert!(!rendered.contains("ignored-environment-id"));
}

#[tokio::test]
async fn export_package_dependency_state_matrix_stops_before_metadata_when_unsafe() {
    let cases = [
        ("installed", Some("2.0.0"), None, true),
        ("not_installed", None, Some(ErrorKind::Conflict), false),
        ("installed", None, Some(ErrorKind::Http), false),
        ("not_installed", Some("2.0.0"), Some(ErrorKind::Http), false),
        ("installing", None, Some(ErrorKind::Http), false),
        ("failed", None, Some(ErrorKind::Http), false),
        ("future", None, Some(ErrorKind::Http), false),
        ("installed", Some("3.0.0"), Some(ErrorKind::Conflict), false),
    ];
    for (status, version, expected_error, metadata_expected) in cases {
        let server = verified_server().await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/integration-1"))
            .and(query_param("format", "simplified"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"item": live_item("integration-1")})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
                "id": "parent-1", "name": "Parent", "namespace": "default", "agents": 0,
                "package_policies": ["integration-1"]
            }})))
            .mount(&server)
            .await;
        let mut package = json!({"name": "system", "status": status});
        if let Some(version) = version {
            package["installationInfo"] = json!({"version": version});
        }
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": package})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
                "name": "system", "version": "2.0.0", "policy_templates": []
            }})))
            .mount(&server)
            .await;
        let result = integration_policy_ops::export(
            &transport_for(&server),
            &["integration-1".into()],
            false,
            ContentFormat::Json,
        )
        .await;
        match expected_error {
            Some(kind) => assert_eq!(result.expect_err(status).kind, kind, "{status}/{version:?}"),
            None => assert_eq!(result.expect(status).exported, 1),
        }
        let metadata_seen = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.url.path() == "/api/fleet/epm/packages/system/2.0.0");
        assert_eq!(metadata_seen, metadata_expected, "{status}/{version:?}");
    }
}

#[tokio::test]
async fn get_rejects_malformed_parent_snapshots_and_sanitizes_parent_ownership() {
    let cases = [
        ("agents", Value::Null, ErrorKind::Permission),
        ("agents", json!(-1), ErrorKind::Http),
        ("agents", json!(1.5), ErrorKind::Http),
        ("agents", json!("1"), ErrorKind::Http),
        ("id", Value::Null, ErrorKind::Http),
        ("id", json!(""), ErrorKind::Http),
        ("id", json!("wrong"), ErrorKind::Http),
        ("id", json!(1), ErrorKind::Http),
        ("name", Value::Null, ErrorKind::Http),
        ("name", json!(""), ErrorKind::Http),
        ("name", json!(1), ErrorKind::Http),
        ("namespace", Value::Null, ErrorKind::Http),
        ("namespace", json!(""), ErrorKind::Http),
        ("namespace", json!(1), ErrorKind::Http),
        ("package_policies", Value::Null, ErrorKind::Http),
        ("package_policies", json!({}), ErrorKind::Http),
        ("package_policies", json!([""]), ErrorKind::Http),
        ("package_policies", json!([{}]), ErrorKind::Http),
        ("package_policies", json!([{"id": ""}]), ErrorKind::Http),
        (
            "package_policies",
            json!(["integration-1", "integration-1"]),
            ErrorKind::Http,
        ),
        ("is_managed", json!("false"), ErrorKind::Http),
        ("agentless", json!(true), ErrorKind::Http),
        ("is_protected", json!("false"), ErrorKind::Http),
    ];
    for (field, value, kind) in cases {
        let server = verified_server().await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/integration-1"))
            .and(query_param("format", "simplified"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"item": live_item("integration-1")})),
            )
            .mount(&server)
            .await;
        let mut parent = json!({"id":"parent-1","name":"Parent","namespace":"default","agents":1,"package_policies":["integration-1"]});
        if value.is_null() {
            parent.as_object_mut().unwrap().remove(field);
        } else {
            parent[field] = value;
        }
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item":parent})))
            .mount(&server)
            .await;
        assert_eq!(
            integration_policy_ops::get_op(&transport_for(&server), "integration-1")
                .await
                .expect_err(field)
                .kind,
            kind,
            "{field}"
        );
    }
}

#[tokio::test]
async fn parent_ownership_markers_block_safe_get_and_explicit_export_before_packages() {
    let mut cases: Vec<(&str, Value)> = PLATFORM_FLAGS
        .iter()
        .map(|flag| (*flag, json!(true)))
        .collect();
    cases.extend([
        ("agentless", json!({"environment": "must-not-leak"})),
        ("is_protected", json!(true)),
    ]);
    for (field, value) in cases {
        let server = verified_server().await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/integration-1"))
            .and(query_param("format", "simplified"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"item": live_item("integration-1")})),
            )
            .mount(&server)
            .await;
        let mut parent = json!({"id":"parent-1","name":"Parent","namespace":"default","agents":1,"package_policies":["integration-1"],"data_output_id":"ignored"});
        parent[field] = value;
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item":parent})))
            .mount(&server)
            .await;
        let transport = transport_for(&server);
        let detail = integration_policy_ops::get_op(&transport, "integration-1")
            .await
            .unwrap();
        let expected = if field == "is_protected" {
            "parent:parent-1.is_protected"
        } else {
            "parent:parent-1.platform_owned"
        };
        assert_eq!(detail.blocked_by, vec![expected]);
        assert!(
            !serde_json::to_string(&detail)
                .unwrap()
                .contains("must-not-leak")
        );
        assert_eq!(
            integration_policy_ops::export(
                &transport,
                &["integration-1".into()],
                false,
                ContentFormat::Json
            )
            .await
            .unwrap_err()
            .kind,
            ErrorKind::Unsupported
        );
        assert!(
            !server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| request.url.path().contains("epm/packages"))
        );
    }
}

#[tokio::test]
async fn get_fails_before_parent_reads_for_duplicate_ids_and_rejects_parent_attachment_races() {
    for (ids, attachment, kind) in [
        (
            json!(["parent-1", "parent-1"]),
            json!(["integration-1"]),
            ErrorKind::Http,
        ),
        (
            json!(["parent-1"]),
            json!(["integration-1", "integration-1"]),
            ErrorKind::Http,
        ),
        (json!(["parent-1"]), json!(["other"]), ErrorKind::Http),
    ] {
        let server = verified_server().await;
        let mut policy = live_item("integration-1");
        policy.insert("policy_ids".into(), ids);
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/integration-1"))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item":policy})))
            .mount(&server)
            .await;
        Mock::given(method("GET")).and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item":{"id":"parent-1","name":"Parent","namespace":"default","agents":1,"package_policies":attachment}}))).mount(&server).await;
        assert_eq!(
            integration_policy_ops::get_op(&transport_for(&server), "integration-1")
                .await
                .unwrap_err()
                .kind,
            kind
        );
    }
}

#[tokio::test]
async fn export_canonicalizes_unsorted_live_parents_and_reads_each_parent_once() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert("policy_ids".into(), json!(["parent-z", "parent-a"]));
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": policy})))
        .expect(1)
        .mount(&server)
        .await;

    let mut first_parent = parent_item("parent-a", "default", 2, json!(["integration-1"]));
    first_parent["data_output_id"] = json!("environment-only");
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-a"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": first_parent})))
        .expect(1)
        .mount(&server)
        .await;
    let mut second_parent = parent_item("parent-z", "default", 3, json!(["integration-1"]));
    second_parent["monitoring_output_id"] = json!("environment-only-too");
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-z"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": second_parent})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "system", "status": "installed", "installationInfo": {"version": "2.0.0"}
        }})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "system", "version": "2.0.0", "policy_templates": []
        }})))
        .expect(1)
        .mount(&server)
        .await;

    let result = integration_policy_ops::export(
        &transport_for(&server),
        &["integration-1".into()],
        false,
        ContentFormat::Json,
    )
    .await
    .expect("portable integration");
    assert_eq!(result.exported, 1);
    let expected = IntegrationPolicySpec::try_from(json!({
        "id": "integration-1",
        "name": "Integration integration-1",
        "namespace": "default",
        "policy_ids": ["parent-a", "parent-z"],
        "package": {"name": "system", "version": "2.0.0"},
        "inputs": {}
    }))
    .expect("canonical expected spec");
    assert_eq!(
        result.body,
        content_codec::encode_sequence(&[expected], ContentFormat::Json).expect("canonical body")
    );
}

#[tokio::test]
async fn get_refuses_unknown_and_malformed_live_content_before_reporting_safe_detail() {
    for (field, value, expected_kind) in [
        (
            "future_field",
            json!("must-not-be-silent"),
            ErrorKind::Unsupported,
        ),
        ("inputs", json!([]), ErrorKind::Http),
    ] {
        let server = verified_server().await;
        let mut policy = live_item("integration-1");
        policy.insert(field.into(), value);
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/integration-1"))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": policy})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"item": parent_item(
                    "parent-1", "default", 1, json!(["integration-1"])
                )})),
            )
            .expect(0)
            .mount(&server)
            .await;

        let error = integration_policy_ops::get_op(&transport_for(&server), "integration-1")
            .await
            .expect_err(field);
        assert_eq!(error.kind, expected_kind, "{field}: {}", error.message);
    }
}

#[tokio::test]
async fn get_reports_parent_namespace_disagreement_and_export_refuses_it() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert("policy_ids".into(), json!(["parent-z", "parent-a"]));
    mount_export_dependencies(
        &server,
        "integration-1",
        policy,
        vec![
            parent_item("parent-z", "operations", 3, json!(["integration-1"])),
            parent_item("parent-a", "default", 2, json!(["integration-1"])),
        ],
        installed_package("2.0.0"),
        safe_package_metadata(),
    )
    .await;
    let transport = transport_for(&server);

    let detail = integration_policy_ops::get_op(&transport, "integration-1")
        .await
        .expect("safe detail with a namespace blocker");
    assert_eq!(detail.policy_ids, vec!["parent-a", "parent-z"]);
    assert_eq!(detail.affected_agents, 5);
    assert_eq!(detail.blocked_by, vec!["namespace"]);

    let error = integration_policy_ops::export(
        &transport,
        &["integration-1".into()],
        false,
        ContentFormat::Json,
    )
    .await
    .expect_err("different parent namespaces are not portable");
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(
        request_count(&server, "/api/fleet/epm/packages/system/2.0.0").await,
        0
    );
}

#[tokio::test]
async fn get_sums_unsorted_safe_parents_once_without_exposing_environment_data() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert("policy_ids".into(), json!(["parent-z", "parent-a"]));
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": policy})))
        .expect(1)
        .mount(&server)
        .await;
    let mut parent_a = parent_item("parent-a", "default", 2, json!(["integration-1"]));
    parent_a["data_output_id"] = json!("parent-a-environment-id");
    let mut parent_z = parent_item("parent-z", "default", 3, json!(["integration-1"]));
    parent_z["fleet_server_host_id"] = json!("parent-z-environment-id");
    for parent in [parent_a, parent_z] {
        let parent_id = parent["id"].as_str().unwrap().to_owned();
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/agent_policies/{parent_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": parent})))
            .expect(1)
            .mount(&server)
            .await;
    }

    let detail = integration_policy_ops::get_op(&transport_for(&server), "integration-1")
        .await
        .expect("safe parent detail");
    assert_eq!(detail.policy_ids, vec!["parent-a", "parent-z"]);
    assert_eq!(detail.affected_agents, 5);
    assert!(detail.blocked_by.is_empty());
    let rendered = serde_json::to_string(&detail).expect("safe serialization");
    assert!(!rendered.contains("parent-a-environment-id"));
    assert!(!rendered.contains("parent-z-environment-id"));
}

#[tokio::test]
async fn export_reports_a_missing_named_parent_without_package_preflight() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/missing-parent"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let mut policy = live_item("integration-1");
    policy.insert("policy_ids".into(), json!(["missing-parent"]));
    mount_export_dependencies(
        &server,
        "integration-1",
        policy,
        Vec::new(),
        installed_package("2.0.0"),
        safe_package_metadata(),
    )
    .await;

    let error = integration_policy_ops::export(
        &transport_for(&server),
        &["integration-1".into()],
        false,
        ContentFormat::Json,
    )
    .await
    .expect_err("missing parent");
    assert_eq!(error.kind, ErrorKind::NotFound);
    assert_eq!(
        request_count(&server, "/api/fleet/epm/packages/system").await,
        0
    );
    assert_eq!(
        request_count(&server, "/api/fleet/epm/packages/system/2.0.0").await,
        0
    );
}

#[tokio::test]
async fn export_deduplicates_resolved_selectors_and_orders_multiple_artifacts_by_id() {
    let server = verified_server().await;
    let mut integration_a = live_item("integration-a");
    integration_a.insert("policy_ids".into(), json!(["parent-a"]));
    mount_export_dependencies(
        &server,
        "integration-a",
        integration_a,
        vec![parent_item(
            "parent-a",
            "default",
            1,
            json!(["integration-a"]),
        )],
        installed_package("2.0.0"),
        safe_package_metadata(),
    )
    .await;
    let mut integration_b = live_item("integration-b");
    integration_b.insert("policy_ids".into(), json!(["parent-b"]));
    mount_export_dependencies(
        &server,
        "integration-b",
        integration_b,
        vec![parent_item(
            "parent-b",
            "default",
            1,
            json!(["integration-b"]),
        )],
        installed_package("2.0.0"),
        safe_package_metadata(),
    )
    .await;

    let result = integration_policy_ops::export(
        &transport_for(&server),
        &[
            "integration-b".into(),
            "integration-a".into(),
            "integration-b".into(),
        ],
        false,
        ContentFormat::Json,
    )
    .await
    .expect("deduplicated export");
    assert_eq!(result.exported, 2);
    let specs: Vec<IntegrationPolicySpec> =
        content_codec::decode_sequence(&result.body, ContentFormat::Json, "integration policy")
            .expect("canonical artifact");
    assert_eq!(
        specs
            .iter()
            .map(|spec| spec.id.as_str())
            .collect::<Vec<_>>(),
        ["integration-a", "integration-b"]
    );
    assert_eq!(
        request_count(&server, "/api/fleet/agent_policies/parent-a").await,
        1
    );
    assert_eq!(
        request_count(&server, "/api/fleet/agent_policies/parent-b").await,
        1
    );
}

#[tokio::test]
async fn export_requires_an_unambiguous_package_installation_state_before_metadata() {
    let cases = [
        (
            "installed-null-installation-info",
            json!({"name": "system", "status": "installed", "installationInfo": null}),
            ErrorKind::Http,
        ),
        (
            "installed-missing-installation-info",
            json!({"name": "system", "status": "installed"}),
            ErrorKind::Http,
        ),
        (
            "installed-missing-version",
            json!({"name": "system", "status": "installed", "installationInfo": {}}),
            ErrorKind::Http,
        ),
        (
            "installed-null-version",
            json!({"name": "system", "status": "installed", "installationInfo": {"version": null}}),
            ErrorKind::Http,
        ),
        (
            "installed-blank-version",
            json!({"name": "system", "status": "installed", "installationInfo": {"version": " "}}),
            ErrorKind::Http,
        ),
        (
            "not-installed-null-installation-info",
            json!({"name": "system", "status": "not_installed", "installationInfo": null}),
            ErrorKind::Conflict,
        ),
        (
            "not-installed-missing-installation-info",
            json!({"name": "system", "status": "not_installed"}),
            ErrorKind::Conflict,
        ),
    ];
    for (case, package, expected_kind) in cases {
        let server = verified_server().await;
        mount_export_dependencies(
            &server,
            "integration-1",
            live_item("integration-1"),
            vec![parent_item(
                "parent-1",
                "default",
                0,
                json!(["integration-1"]),
            )],
            package,
            safe_package_metadata(),
        )
        .await;

        let error = integration_policy_ops::export(
            &transport_for(&server),
            &["integration-1".into()],
            false,
            ContentFormat::Json,
        )
        .await
        .expect_err(case);
        assert_eq!(error.kind, expected_kind, "{case}: {}", error.message);
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system").await,
            1,
            "{case} must read the package state exactly once"
        );
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system/2.0.0").await,
            0,
            "{case} must stop before exact metadata"
        );
    }
}

#[tokio::test]
async fn export_refuses_configured_package_input_and_stream_secrets_without_leaks() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert(
        "vars".into(),
        json!({"package_secret": {"id": "package-reference-id", "value": "package-secret-value"}}),
    );
    policy.insert(
        "inputs".into(),
        json!({
            "system-system": {
                "vars": {"input_secret": {"id": "input-reference-id", "value": "input-secret-value"}},
                "streams": {
                    "system.cpu": {
                        "vars": {"stream_secret": {"id": "stream-reference-id", "value": "stream-secret-value"}}
                    }
                }
            }
        }),
    );
    mount_export_dependencies(
        &server,
        "integration-1",
        policy,
        vec![parent_item(
            "parent-1",
            "default",
            0,
            json!(["integration-1"]),
        )],
        installed_package("2.0.0"),
        secret_matrix_metadata(),
    )
    .await;

    let error = integration_policy_ops::export(
        &transport_for(&server),
        &["integration-1".into()],
        false,
        ContentFormat::Json,
    )
    .await
    .expect_err("configured secrets");
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(
        error.message,
        "integration policy 'integration-1' is not portable: integration-1:inputs.system-system.streams.system.cpu.vars.stream_secret, integration-1:inputs.system-system.vars.input_secret, integration-1:vars.package_secret"
    );
    for leaked in [
        "package-reference-id",
        "package-secret-value",
        "input-reference-id",
        "input-secret-value",
        "stream-reference-id",
        "stream-secret-value",
    ] {
        assert!(!error.message.contains(leaked), "leaked {leaked}");
    }
    assert_eq!(
        request_count(&server, "/api/fleet/epm/packages/system/2.0.0").await,
        1
    );
}

#[tokio::test]
async fn export_allows_nonsecret_values_and_unconfigured_secret_definitions() {
    let mut nonsecret_values = live_item("integration-1");
    nonsecret_values.insert(
        "vars".into(),
        json!({"package_plain": "visible-package-value"}),
    );
    nonsecret_values.insert(
        "inputs".into(),
        json!({
            "system-system": {
                "vars": {"input_plain": "visible-input-value"},
                "streams": {"system.cpu": {"vars": {"stream_plain": "visible-stream-value"}}}
            }
        }),
    );
    for (case, policy) in [
        ("nonsecret values", nonsecret_values),
        (
            "unconfigured secret definitions",
            live_item("integration-1"),
        ),
    ] {
        let server = verified_server().await;
        mount_export_dependencies(
            &server,
            "integration-1",
            policy,
            vec![parent_item(
                "parent-1",
                "default",
                0,
                json!(["integration-1"]),
            )],
            installed_package("2.0.0"),
            secret_matrix_metadata(),
        )
        .await;
        let result = integration_policy_ops::export(
            &transport_for(&server),
            &["integration-1".into()],
            false,
            ContentFormat::Json,
        )
        .await
        .expect(case);
        assert_eq!(result.exported, 1, "{case}");
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system/2.0.0").await,
            1,
            "{case} must consult exact metadata"
        );
    }
}

#[tokio::test]
async fn export_refuses_every_configured_variable_without_an_exact_definition() {
    let mut package_variable = live_item("integration-1");
    package_variable.insert("vars".into(), json!({"missing": "must-not-leak"}));
    let mut input_variable = live_item("integration-1");
    input_variable.insert(
        "inputs".into(),
        json!({"system-system": {"vars": {"missing": "must-not-leak"}}}),
    );
    let mut stream_variable = live_item("integration-1");
    stream_variable.insert(
        "inputs".into(),
        json!({
            "system-system": {
                "streams": {"system.cpu": {"vars": {"missing": "must-not-leak"}}}
            }
        }),
    );
    for (case, policy, path) in [
        ("package", package_variable, "vars.missing"),
        ("input", input_variable, "inputs.system-system.vars.missing"),
        (
            "stream",
            stream_variable,
            "inputs.system-system.streams.system.cpu.vars.missing",
        ),
    ] {
        let server = verified_server().await;
        mount_export_dependencies(
            &server,
            "integration-1",
            policy,
            vec![parent_item(
                "parent-1",
                "default",
                0,
                json!(["integration-1"]),
            )],
            installed_package("2.0.0"),
            secret_matrix_metadata(),
        )
        .await;
        let error = integration_policy_ops::export(
            &transport_for(&server),
            &["integration-1".into()],
            false,
            ContentFormat::Json,
        )
        .await
        .expect_err(case);
        assert_eq!(
            error.kind,
            ErrorKind::Unsupported,
            "{case}: {}",
            error.message
        );
        assert!(
            error.message.contains(&format!("integration-1:{path}")),
            "{case}: {}",
            error.message
        );
        assert!(!error.message.contains("must-not-leak"), "{case}");
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system/2.0.0").await,
            1,
            "{case} must inspect exact metadata"
        );
    }
}

#[tokio::test]
async fn export_rejects_malformed_exact_package_metadata_before_serializing() {
    let mut cases = Vec::new();
    let mut metadata = secret_matrix_metadata();
    metadata["vars"] = json!({});
    cases.push(("package vars", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["vars"] = Value::Null;
    cases.push(("null package vars", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"] = json!({});
    cases.push(("policy templates", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"] = Value::Null;
    cases.push(("null policy templates", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"] = json!([false]);
    cases.push(("template entry", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["name"] = json!("");
    cases.push(("template name", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["inputs"] = json!({});
    cases.push(("template inputs", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["inputs"] = Value::Null;
    cases.push(("null template inputs", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["inputs"] = json!([false]);
    cases.push(("input entry", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["inputs"][0]["type"] = json!("");
    cases.push(("input type", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["inputs"][0]["vars"] = json!({});
    cases.push(("input vars", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["inputs"][0]["vars"] = Value::Null;
    cases.push(("null input vars", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["inputs"][0]["streams"] = json!({});
    cases.push(("input streams", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["inputs"][0]["streams"] = Value::Null;
    cases.push(("null input streams", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["inputs"][0]["streams"] = json!([false]);
    cases.push(("stream entry", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["inputs"][0]["streams"][0]["data_stream"] = json!(false);
    cases.push(("stream data stream", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["inputs"][0]["streams"][0]["data_stream"]["dataset"] =
        json!("");
    cases.push(("stream dataset", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["inputs"][0]["streams"][0]["vars"] = json!({});
    cases.push(("stream vars", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["inputs"][0]["streams"][0]["vars"] = Value::Null;
    cases.push(("null stream vars", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["vars"] = json!([false]);
    cases.push(("variable entry", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["vars"][0]["name"] = json!("");
    cases.push(("variable name", metadata));
    let mut metadata = secret_matrix_metadata();
    metadata["vars"][0]["secret"] = json!("true");
    cases.push(("variable secret flag", metadata));

    for (case, metadata) in cases {
        let server = verified_server().await;
        mount_export_dependencies(
            &server,
            "integration-1",
            live_item("integration-1"),
            vec![parent_item(
                "parent-1",
                "default",
                0,
                json!(["integration-1"]),
            )],
            installed_package("2.0.0"),
            metadata,
        )
        .await;
        let error = integration_policy_ops::export(
            &transport_for(&server),
            &["integration-1".into()],
            false,
            ContentFormat::Json,
        )
        .await
        .expect_err(case);
        assert_eq!(error.kind, ErrorKind::Http, "{case}: {}", error.message);
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system/2.0.0").await,
            1,
            "{case} must reach exact metadata once"
        );
    }
}

#[tokio::test]
async fn export_rejects_duplicate_composite_stream_metadata_before_secret_classification() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert(
        "inputs".into(),
        json!({
            "system-system": {
                "streams": {"system.cpu": {"vars": {"stream_secret": "must-not-leak"}}}
            }
        }),
    );
    let mut metadata = secret_matrix_metadata();
    metadata["policy_templates"][0]["inputs"][0]["streams"] = json!([
        {
            "data_stream": {"dataset": "system.cpu"},
            "vars": [{"name": "stream_secret", "secret": false}],
        },
        {
            "data_stream": {"dataset": "system.cpu"},
            "vars": [{"name": "stream_secret", "secret": true}],
        },
    ]);
    mount_export_dependencies(
        &server,
        "integration-1",
        policy,
        vec![parent_item(
            "parent-1",
            "default",
            0,
            json!(["integration-1"]),
        )],
        installed_package("2.0.0"),
        metadata,
    )
    .await;

    let error = integration_policy_ops::export(
        &transport_for(&server),
        &["integration-1".into()],
        false,
        ContentFormat::Json,
    )
    .await
    .expect_err("duplicate composite stream key");
    assert_eq!(error.kind, ErrorKind::Http);
    assert!(
        error
            .message
            .contains("duplicate stream key 'system-system:system.cpu'")
    );
    assert!(!error.message.contains("must-not-leak"));
}

#[tokio::test]
async fn export_refuses_an_explicitly_selected_managed_integration() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert("is_managed".into(), json!(true));
    mount_export_dependencies(
        &server,
        "integration-1",
        policy,
        vec![parent_item(
            "parent-1",
            "default",
            0,
            json!(["integration-1"]),
        )],
        installed_package("2.0.0"),
        safe_package_metadata(),
    )
    .await;

    let error = integration_policy_ops::export(
        &transport_for(&server),
        &["integration-1".into()],
        false,
        ContentFormat::Json,
    )
    .await
    .expect_err("managed integration");
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(
        request_count(&server, "/api/fleet/epm/packages/system/2.0.0").await,
        0
    );
}

#[tokio::test]
async fn all_custom_skips_only_managed_and_parent_owned_rows() {
    let server = verified_server().await;
    let mut listed_managed = item("a-listed-managed");
    listed_managed["is_managed"] = json!(true);
    mount_integration_pages(
        &server,
        vec![(
            1,
            vec![
                listed_managed,
                item("b-full-read-managed"),
                item("c-platform-parent"),
                item("d-protected-parent"),
                item("e-safe"),
            ],
            5,
        )],
    )
    .await;

    let mut full_read_managed = live_item("b-full-read-managed");
    full_read_managed.insert("is_managed".into(), json!(true));
    mount_export_dependencies(
        &server,
        "b-full-read-managed",
        full_read_managed,
        vec![parent_item(
            "parent-b",
            "default",
            0,
            json!(["b-full-read-managed"]),
        )],
        installed_package("2.0.0"),
        safe_package_metadata(),
    )
    .await;

    let mut platform_child = live_item("c-platform-parent");
    platform_child.insert("policy_ids".into(), json!(["parent-c"]));
    let mut platform_parent = parent_item("parent-c", "default", 0, json!(["c-platform-parent"]));
    platform_parent["is_default"] = json!(true);
    mount_export_dependencies(
        &server,
        "c-platform-parent",
        platform_child,
        vec![platform_parent],
        installed_package("2.0.0"),
        safe_package_metadata(),
    )
    .await;

    let mut protected_child = live_item("d-protected-parent");
    protected_child.insert("policy_ids".into(), json!(["parent-d"]));
    let mut protected_parent = parent_item("parent-d", "default", 0, json!(["d-protected-parent"]));
    protected_parent["is_protected"] = json!(true);
    mount_export_dependencies(
        &server,
        "d-protected-parent",
        protected_child,
        vec![protected_parent],
        installed_package("2.0.0"),
        safe_package_metadata(),
    )
    .await;

    let mut safe_child = live_item("e-safe");
    safe_child.insert("policy_ids".into(), json!(["parent-e"]));
    mount_export_dependencies(
        &server,
        "e-safe",
        safe_child,
        vec![parent_item("parent-e", "default", 1, json!(["e-safe"]))],
        installed_package("2.0.0"),
        safe_package_metadata(),
    )
    .await;

    let result =
        integration_policy_ops::export(&transport_for(&server), &[], true, ContentFormat::Json)
            .await
            .expect("all-custom skips only owned rows");
    assert_eq!(result.exported, 1);
    let specs: Vec<IntegrationPolicySpec> =
        content_codec::decode_sequence(&result.body, ContentFormat::Json, "integration policy")
            .expect("safe artifact");
    assert_eq!(
        specs
            .iter()
            .map(|spec| spec.id.as_str())
            .collect::<Vec<_>>(),
        ["e-safe"]
    );
    assert_eq!(
        request_count(&server, "/api/fleet/package_policies/a-listed-managed").await,
        0
    );
    assert_eq!(
        request_count(&server, "/api/fleet/agent_policies/parent-b").await,
        0
    );
    assert_eq!(
        request_count(&server, "/api/fleet/epm/packages/system").await,
        1
    );
    assert_eq!(
        request_count(&server, "/api/fleet/epm/packages/system/2.0.0").await,
        1
    );
}

#[tokio::test]
async fn all_custom_refuses_every_other_unsupported_custom_row() {
    let mut unknown = live_item("integration-1");
    unknown.insert("future_field".into(), json!(true));
    let mut foreign_space = live_item("integration-1");
    foreign_space.insert("spaceIds".into(), json!(["default", "foreign-space"]));
    let mut environment_reference = live_item("integration-1");
    environment_reference.insert("output_id".into(), json!("environment-output-id"));
    let mut secret_reference = live_item("integration-1");
    secret_reference.insert("secret_references".into(), json!([{"id": "reference-id"}]));
    let mut declared_secret = live_item("integration-1");
    declared_secret.insert("vars".into(), json!({"package_secret": "plaintext-secret"}));
    for (case, policy, metadata, metadata_expected) in [
        ("unknown field", unknown, safe_package_metadata(), false),
        (
            "foreign space",
            foreign_space,
            safe_package_metadata(),
            false,
        ),
        (
            "environment reference",
            environment_reference,
            safe_package_metadata(),
            false,
        ),
        (
            "secret reference",
            secret_reference,
            safe_package_metadata(),
            false,
        ),
        (
            "declared plaintext secret",
            declared_secret,
            secret_matrix_metadata(),
            true,
        ),
    ] {
        let server = verified_server().await;
        mount_integration_pages(&server, vec![(1, vec![item("integration-1")], 1)]).await;
        mount_export_dependencies(
            &server,
            "integration-1",
            policy,
            vec![parent_item(
                "parent-1",
                "default",
                0,
                json!(["integration-1"]),
            )],
            installed_package("2.0.0"),
            metadata,
        )
        .await;
        let error =
            integration_policy_ops::export(&transport_for(&server), &[], true, ContentFormat::Json)
                .await
                .expect_err(case);
        assert_eq!(
            error.kind,
            ErrorKind::Unsupported,
            "{case}: {}",
            error.message
        );
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system/2.0.0").await > 0,
            metadata_expected,
            "{case} metadata reachability"
        );
    }
}

#[tokio::test]
async fn get_reports_every_direct_safe_blocker_without_serializing_sensitive_content() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.extend(
        json!({
            "enabled": false,
            "is_managed": true,
            "supports_agentless": true,
            "supports_cloud_connector": true,
            "output_id": "output-environment-id",
            "cloud_connector_id": "connector-environment-id",
            "cloud_connector_name": "connector-environment-name",
            "secret_references": [{"id": "secret-reference-id"}],
            "spaceIds": ["default", "foreign-space"],
            "created_by": "audit-user",
            "updated_by": "audit-user",
            "inputs": {
                "system-system": {
                    "vars": {"password": "input-secret-value"},
                    "compiled_input": {"compiled": "must-not-render"}
                }
            },
            "policy_ids": ["parent-platform", "parent-protected"]
        })
        .as_object()
        .expect("blocker object")
        .clone(),
    );
    let mut platform_parent =
        parent_item("parent-platform", "default", 2, json!(["integration-1"]));
    platform_parent["is_preconfigured"] = json!(true);
    let mut protected_parent = parent_item(
        "parent-protected",
        "foreign-parent-space",
        3,
        json!(["integration-1"]),
    );
    protected_parent["is_protected"] = json!(true);
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": policy})))
        .expect(1)
        .mount(&server)
        .await;
    for parent in [platform_parent, protected_parent] {
        let parent_id = parent["id"].as_str().unwrap().to_owned();
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/agent_policies/{parent_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": parent})))
            .expect(1)
            .mount(&server)
            .await;
    }

    let detail = integration_policy_ops::get_op(&transport_for(&server), "integration-1")
        .await
        .expect("safe blocked detail");
    assert_eq!(detail.affected_agents, 5);
    assert_eq!(
        detail.blocked_by,
        vec![
            "cloud_connector_id",
            "cloud_connector_name",
            "enabled",
            "is_managed",
            "namespace",
            "output_id",
            "parent:parent-platform.platform_owned",
            "parent:parent-protected.is_protected",
            "secret_references",
            "spaceIds",
            "supports_agentless",
            "supports_cloud_connector",
        ]
    );
    let rendered = serde_json::to_string(&detail).expect("serialized detail");
    for private in [
        "input-secret-value",
        "secret-reference-id",
        "audit-user",
        "output-environment-id",
        "connector-environment-id",
        "connector-environment-name",
        "must-not-render",
    ] {
        assert!(!rendered.contains(private), "detail leaked {private}");
    }
}
