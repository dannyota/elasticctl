use elasticctl_api::content_codec::{self, ContentFormat};
use elasticctl_api::fleet::agent_policies::PLATFORM_FLAGS;
use elasticctl_api::fleet::integration_policies::{self, IntegrationPolicySpec};
use elasticctl_api::fleet::integration_policy_ops::{self, IntegrationPolicyFilter};
use elasticctl_api::{
    IntegrationPolicyDeletePlan, IntegrationPolicyDeleteReport, IntegrationPolicyImportPlan,
    IntegrationPolicyImportReport,
};
use elasticctl_core::{ErrorKind, Feature, Profile, Transport};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

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
    transport_for_space(server, "default")
}

fn transport_for_space(server: &MockServer, space: &str) -> Transport {
    Transport::new(&Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: space.into(),
        verify: true,
        timeout_secs: 5,
    })
    .expect("transport")
}

#[derive(Clone)]
struct SequenceResponder {
    responses: Arc<Vec<ResponseTemplate>>,
    next: Arc<AtomicUsize>,
}

impl SequenceResponder {
    fn new(responses: Vec<ResponseTemplate>) -> Self {
        Self {
            responses: Arc::new(responses),
            next: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Respond for SequenceResponder {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let index = self.next.fetch_add(1, Ordering::SeqCst);
        self.responses[index.min(self.responses.len() - 1)].clone()
    }
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
fn integration_import_reports_are_reexported_from_the_api_crate() {
    fn accepts_plan(_: Option<IntegrationPolicyImportPlan>) {}
    fn accepts_report(_: Option<IntegrationPolicyImportReport>) {}

    accepts_plan(None);
    accepts_report(None);
}

#[test]
fn integration_delete_reports_are_reexported_from_the_api_crate() {
    fn accepts_plan(_: Option<IntegrationPolicyDeletePlan>) {}
    fn accepts_report(_: Option<IntegrationPolicyDeleteReport>) {}

    accepts_plan(None);
    accepts_report(None);
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

fn modern_package_metadata(policy_templates: Value, data_streams: Value) -> Value {
    json!({
        "name": "system",
        "version": "2.0.0",
        "policy_templates": policy_templates,
        "data_streams": data_streams,
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

fn measured_system_metadata() -> Value {
    modern_package_metadata(
        json!([
            {
                "name": "system",
                "inputs": [
                    {"type": "system", "streams": []}
                ]
            }
        ]),
        json!([
            {
                "dataset": "system.cpu",
                "streams": [
                    {"input": "system", "vars": [{"name": "period"}]}
                ]
            }
        ]),
    )
}

fn expanded_system_inputs() -> Value {
    json!({
        "system-system": {
            "enabled": true,
            "streams": {
                "system.cpu": {
                    "enabled": true,
                    "vars": {"period": "10s"}
                }
            }
        }
    })
}

async fn mount_export_dependencies(
    server: &MockServer,
    id: &str,
    policy: serde_json::Map<String, Value>,
    parents: Vec<Value>,
    package: Value,
    metadata: Value,
) {
    mount_export_dependencies_for_package(
        server,
        id,
        policy,
        parents,
        PackageCoordinate {
            name: "system",
            version: "2.0.0",
        },
        package,
        metadata,
    )
    .await;
}

struct PackageCoordinate<'a> {
    name: &'a str,
    version: &'a str,
}

async fn mount_export_dependencies_for_package(
    server: &MockServer,
    id: &str,
    policy: serde_json::Map<String, Value>,
    parents: Vec<Value>,
    package_coordinate: PackageCoordinate<'_>,
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
        .and(path(format!(
            "/api/fleet/epm/packages/{}",
            package_coordinate.name
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": package})))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/fleet/epm/packages/{}/{}",
            package_coordinate.name, package_coordinate.version
        )))
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

fn write_import_artifact(
    directory: &std::path::Path,
    name: &str,
    specs: &[Value],
) -> std::path::PathBuf {
    let path = directory.join(name);
    std::fs::write(
        &path,
        serde_json::to_string(specs).expect("serialize import artifact"),
    )
    .expect("write import artifact");
    path
}

async fn no_import_mutation_requests(server: &MockServer) -> bool {
    server
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .all(|request| request.method != "POST" && request.method != "PUT")
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
    assert!(
        specs.iter().all(|spec| spec.inputs.is_empty()),
        "offline validation must keep object-shaped empty inputs structurally valid"
    );
}

#[test]
fn prepared_import_artifact_rejects_empty_files_and_redacts_configured_values() {
    let directory = tempfile::tempdir().expect("artifact directory");
    let empty = directory.path().join("empty.json");
    std::fs::write(&empty, "[]").expect("write empty artifact");

    let error = integration_policy_ops::prepare_import(&empty)
        .expect_err("empty import artifacts must fail before transport setup");
    assert_eq!(error.kind, ErrorKind::Error);
    assert!(
        error
            .message
            .contains("integration-policy import needs at least one integration policy")
    );

    let secret = "prepared-artifact-secret-value";
    let mut configured = spec_json("prepared");
    configured["vars"] = json!({"api_token": secret});
    let artifact = write_import_artifact(directory.path(), "configured.json", &[configured]);
    let prepared =
        integration_policy_ops::prepare_import(&artifact).expect("prepare configured artifact");
    let debug = format!("{prepared:?}");

    assert!(debug.contains("policy_count"), "{debug}");
    assert!(!debug.contains(secret), "{debug}");
    assert!(!debug.contains("configured.json"), "{debug}");
}

#[tokio::test]
async fn prepared_import_plans_retained_bytes_after_the_source_is_removed() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let artifact =
        write_import_artifact(directory.path(), "retained.json", &[spec_json("retained")]);
    let prepared = integration_policy_ops::prepare_import(&artifact).expect("prepare artifact");
    std::fs::remove_file(&artifact).expect("remove source after preparation");

    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/retained"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "statusCode": 404,
            "error": "Not Found",
            "message": "missing"
        })))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!([]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .mount(&server)
        .await;

    let plan = integration_policy_ops::plan_prepared_import(
        &transport_for(&server),
        prepared,
        false,
        false,
    )
    .await
    .expect("planning must use the retained artifact, not reopen its source");

    assert_eq!(plan.preview.targets, vec!["retained"]);
    assert_eq!(
        plan.preview.preview_action,
        format!(
            "Import 1 integration policy(ies) from {}",
            artifact.display()
        )
    );
    assert!(no_import_mutation_requests(&server).await);
}

#[tokio::test]
async fn absent_exact_package_is_previewed_without_an_install_request() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let artifact = directory.path().join("integration-policies.json");
    std::fs::write(&artifact, json!([spec_json("integration-1")]).to_string())
        .expect("write artifact");

    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "statusCode": 404,
            "error": "Not Found",
            "message": "missing"
        })))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!([]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": {"name": "system", "status": "not_installed"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .mount(&server)
        .await;

    let plan =
        integration_policy_ops::plan_import(&transport_for(&server), &artifact, false, false)
            .await
            .expect("plan absent exact package");

    assert_eq!(plan.package_installs, vec!["system@2.0.0"]);
    assert!(
        plan.preview
            .preview_details
            .iter()
            .any(|line| line == "package install  system@2.0.0")
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .all(|request| request.method == "GET"),
        "planning must not mutate Fleet"
    );
}

#[tokio::test]
async fn plan_import_rejects_empty_inputs_when_exact_metadata_declares_input_keys() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let default_sentinel = "package-default-must-not-leak";
    let secret_sentinel = "input-secret-default-must-not-leak";
    let configured_sentinel = "configured-value-must-not-leak";
    let mut desired = spec_json("empty-create");
    desired["vars"] = json!({"package_plain": configured_sentinel});
    let artifact = write_import_artifact(directory.path(), "empty-create.json", &[desired]);

    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/empty-create"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "statusCode": 404,
            "error": "Not Found",
            "message": "missing"
        })))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!([]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    let mut metadata = measured_system_metadata();
    metadata["vars"] = json!([
        {"name": "package_plain", "default": default_sentinel}
    ]);
    metadata["policy_templates"][0]["inputs"][0]["vars"] = json!([
        {"name": "input_secret", "secret": true, "default": secret_sentinel}
    ]);
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": metadata})))
        .mount(&server)
        .await;

    let error =
        integration_policy_ops::plan_import(&transport_for(&server), &artifact, false, false)
            .await
            .expect_err("empty simplified inputs must not form a guard-able import plan");

    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(
        error.message,
        "integration policy 'empty-create' has an empty inputs map but package system@2.0.0 declares inputs"
    );
    for sentinel in [default_sentinel, secret_sentinel, configured_sentinel] {
        assert!(!error.message.contains(sentinel), "error leaked {sentinel}");
    }
    assert!(no_import_mutation_requests(&server).await);
}

#[tokio::test]
async fn plan_import_rejects_empty_inputs_for_a_pending_replacement() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let mut desired = spec_json("replace-empty");
    desired["description"] = json!("desired description");
    let artifact = write_import_artifact(directory.path(), "replace-empty.json", &[desired]);

    let mut current = live_item("replace-empty");
    current.insert("description".into(), json!("current description"));
    current.insert("inputs".into(), expanded_system_inputs());
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/replace-empty"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": current})))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, vec![item("replace-empty")], 1)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!(["replace-empty"]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item": measured_system_metadata()})),
        )
        .mount(&server)
        .await;

    let error =
        integration_policy_ops::plan_import(&transport_for(&server), &artifact, true, false)
            .await
            .expect_err("an empty replacement must not form a guard-able import plan");

    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(
        error.message,
        "integration policy 'replace-empty' has an empty inputs map but package system@2.0.0 declares inputs"
    );
    assert!(no_import_mutation_requests(&server).await);
}

#[tokio::test]
async fn plan_import_allows_empty_inputs_when_exact_metadata_declares_no_input_keys() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let artifact = write_import_artifact(
        directory.path(),
        "no-input-keys.json",
        &[spec_json("no-input-keys")],
    );

    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/no-input-keys"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "statusCode": 404,
            "error": "Not Found",
            "message": "missing"
        })))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!([]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item": safe_package_metadata()})),
        )
        .mount(&server)
        .await;

    let plan =
        integration_policy_ops::plan_import(&transport_for(&server), &artifact, false, false)
            .await
            .expect("packages without declared inputs may retain empty inputs");

    assert_eq!(plan.preview.targets, vec!["no-input-keys"]);
    assert!(no_import_mutation_requests(&server).await);
}

#[tokio::test]
async fn plan_import_refuses_an_unchanged_empty_snapshot_when_metadata_declares_inputs() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let artifact = write_import_artifact(
        directory.path(),
        "unchanged-empty.json",
        &[spec_json("unchanged-empty")],
    );

    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/unchanged-empty"))
        .and(query_param("format", "simplified"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item": live_item("unchanged-empty")})),
        )
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, vec![item("unchanged-empty")], 1)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!(["unchanged-empty"]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item": measured_system_metadata()})),
        )
        .mount(&server)
        .await;

    let error =
        integration_policy_ops::plan_import(&transport_for(&server), &artifact, true, false)
            .await
            .expect_err("an unchanged empty input map must not form a guard-able import plan");

    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(
        error.message,
        "integration policy 'unchanged-empty' has an empty inputs map but package system@2.0.0 declares inputs"
    );
    assert!(no_import_mutation_requests(&server).await);
}

#[tokio::test]
async fn expanded_system_inputs_create_exactly_and_plan_as_unchanged_on_overwrite() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let mut desired = spec_json("expanded-system");
    desired["inputs"] = expanded_system_inputs();
    let artifact = write_import_artifact(
        directory.path(),
        "expanded-system.json",
        std::slice::from_ref(&desired),
    );
    let mut stored = live_item("expanded-system");
    stored.insert("inputs".into(), desired["inputs"].clone());

    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/expanded-system"))
        .and(query_param("format", "simplified"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404).set_body_json(json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing"
            })),
            ResponseTemplate::new(404).set_body_json(json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing"
            })),
            ResponseTemplate::new(200).set_body_json(json!({"item": stored.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": stored.clone()})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({
                "items": [], "total": 0, "page": 1, "perPage": 1000
            })),
            ResponseTemplate::new(200).set_body_json(json!({
                "items": [], "total": 0, "page": 1, "perPage": 1000
            })),
            ResponseTemplate::new(200).set_body_json(json!({
                "items": [item("expanded-system")], "total": 1, "page": 1, "perPage": 1000
            })),
        ]))
        .mount(&server)
        .await;
    let before = parent_item("parent-1", "default", 0, json!([]));
    let after = parent_item("parent-1", "default", 0, json!(["expanded-system"]));
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": before.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": before})),
            ResponseTemplate::new(200).set_body_json(json!({"item": after})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item": measured_system_metadata()})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/package_policies"))
        .and(body_json(desired.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": stored})))
        .expect(1)
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let create_plan = integration_policy_ops::plan_import(&transport, &artifact, false, false)
        .await
        .expect("expanded inputs plan for create");
    let report = integration_policy_ops::apply_import(&transport, &create_plan)
        .await
        .expect("expanded inputs create");
    assert_eq!(
        report.succeeded,
        vec![json!({"id": "expanded-system", "action": "created"})]
    );
    assert!(report.failed.is_empty(), "{:?}", report.failed);

    let overwrite_plan = integration_policy_ops::plan_import(&transport, &artifact, true, false)
        .await
        .expect("stored expanded inputs are unchanged on overwrite planning");
    assert_eq!(overwrite_plan.preview.targets, vec!["expanded-system"]);
    assert!(
        overwrite_plan.preview.preview_details[0].starts_with("expanded-system  unchanged"),
        "{:?}",
        overwrite_plan.preview.preview_details
    );
}

#[tokio::test]
async fn skip_existing_still_refuses_an_artifact_name_owned_by_another_id() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let artifact = directory.path().join("integration-policies.json");
    std::fs::write(&artifact, json!([spec_json("integration-1")]).to_string())
        .expect("write artifact");

    let mut existing = live_item("integration-1");
    existing.insert("is_managed".into(), json!(true));
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": existing})))
        .mount(&server)
        .await;
    let mut other = item("other-id");
    other["name"] = json!("Integration integration-1");
    mount_integration_pages(&server, vec![(1, vec![item("integration-1"), other], 2)]).await;

    let error =
        integration_policy_ops::plan_import(&transport_for(&server), &artifact, false, true)
            .await
            .expect_err("foreign name owner must conflict even when the id is skipped");
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert!(error.message.contains("other-id"));
    assert_eq!(
        request_count(&server, "/api/fleet/agent_policies/parent-1").await,
        0,
        "skipped rows must not normalize or preflight parents"
    );
    assert_eq!(
        request_count(&server, "/api/fleet/epm/packages/system").await,
        0,
        "skipped rows must not preflight packages"
    );
}

#[tokio::test]
async fn apply_rejects_a_plan_for_a_different_active_space_before_requests() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let artifact = directory.path().join("integration-policies.json");
    std::fs::write(&artifact, json!([spec_json("integration-1")]).to_string())
        .expect("write artifact");

    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": live_item("integration-1")
        })))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, vec![item("integration-1")], 1)]).await;
    let plan = integration_policy_ops::plan_import(&transport_for(&server), &artifact, false, true)
        .await
        .expect("skip plan");
    let before_apply = server.received_requests().await.expect("requests").len();

    let error = integration_policy_ops::apply_import(&transport_for_space(&server, "other"), &plan)
        .await
        .expect_err("a different active space invalidates the plan");
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(
        server.received_requests().await.expect("requests").len(),
        before_apply,
        "target mismatch must stop before any request"
    );
}

#[tokio::test]
async fn apply_rejects_a_new_second_owner_of_a_relevant_name() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let artifact = directory.path().join("integration-policies.json");
    std::fs::write(&artifact, json!([spec_json("integration-1")]).to_string())
        .expect("write artifact");

    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": live_item("integration-1")
        })))
        .mount(&server)
        .await;
    let mut second_owner = item("z-other-owner");
    second_owner["name"] = json!("Integration integration-1");
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({
                "items": [item("integration-1")],
                "total": 1,
                "page": 1,
                "perPage": 1000
            })),
            ResponseTemplate::new(200).set_body_json(json!({
                "items": [item("integration-1"), second_owner],
                "total": 2,
                "page": 1,
                "perPage": 1000
            })),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!(["integration-1"]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let plan = integration_policy_ops::plan_import(&transport, &artifact, true, false)
        .await
        .expect("plan existing unchanged integration");
    let report = integration_policy_ops::apply_import(&transport, &plan)
        .await
        .expect("apply returns a row failure");
    assert!(report.unchanged.is_empty());
    assert_eq!(report.failed.len(), 1);
    assert!(
        report.failed[0]["error"]
            .as_str()
            .expect("failure error")
            .contains("name ownership changed")
    );
}

#[tokio::test]
async fn plan_import_matrix_classifies_conflicts_skips_and_overwrite_rows() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let mut changed = spec_json("changed");
    changed["description"] = json!("desired");
    let artifact = write_import_artifact(
        directory.path(),
        "integration-policies.json",
        &[spec_json("fresh"), spec_json("same"), changed],
    );

    let mut changed_live = live_item("changed");
    changed_live.insert("description".into(), json!("current"));
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/changed"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": changed_live})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/fresh"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "statusCode": 404,
            "error": "Not Found",
            "message": "missing"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/same"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": live_item("same")
        })))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, vec![item("changed"), item("same")], 2)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 3, json!(["changed", "same"]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let error = integration_policy_ops::plan_import(&transport, &artifact, false, false)
        .await
        .expect_err("existing ids conflict by default");
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(
        error.message,
        "integration policies already exist: changed, same"
    );
    assert_eq!(
        request_count(&server, "/api/fleet/agent_policies/parent-1").await,
        0,
        "default conflict must not normalize or read parents"
    );
    assert_eq!(
        request_count(&server, "/api/fleet/epm/packages/system").await,
        0,
        "default conflict must not read package state"
    );

    let skipped = integration_policy_ops::plan_import(&transport, &artifact, false, true)
        .await
        .expect("skip existing plan");
    assert_eq!(
        skipped.skipped,
        vec![
            json!({"id": "changed", "reason": "exists"}),
            json!({"id": "same", "reason": "exists"}),
        ]
    );
    assert_eq!(skipped.preview.targets, vec!["fresh"]);
    assert_eq!(skipped.total, 3);
    assert!(skipped.package_installs.is_empty());

    let overwrite = integration_policy_ops::plan_import(&transport, &artifact, true, false)
        .await
        .expect("overwrite plan");
    assert_eq!(overwrite.preview.targets, vec!["changed", "fresh", "same"]);
    assert_eq!(
        overwrite.preview.preview_details,
        vec![
            "changed  replace  Integration changed  parents parent-1 (Parent parent-1)  agents 3",
            "fresh  create  Integration fresh  parents parent-1 (Parent parent-1)  agents 3",
            "same  unchanged  Integration same  parents parent-1 (Parent parent-1)  agents 3",
            "warning  Fleet can change after the final recheck and before the write",
        ]
    );
    assert!(overwrite.package_installs.is_empty());
    assert!(no_import_mutation_requests(&server).await);
}

#[tokio::test]
async fn plan_import_rejects_existing_package_coordinate_changes_before_dependencies() {
    for (label, package) in [
        ("name", json!({"name": "other", "version": "2.0.0"})),
        ("version", json!({"name": "system", "version": "3.0.0"})),
    ] {
        let server = verified_server().await;
        let directory = tempfile::tempdir().expect("artifact directory");
        let mut desired = spec_json("existing");
        desired["package"] = package;
        let artifact =
            write_import_artifact(directory.path(), &format!("{label}.json"), &[desired]);
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/existing"))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": live_item("existing")
            })))
            .mount(&server)
            .await;

        let error =
            integration_policy_ops::plan_import(&transport_for(&server), &artifact, true, false)
                .await
                .expect_err("same-id package coordinate changes are unsupported");
        assert_eq!(error.kind, ErrorKind::Unsupported, "{label}");
        assert_eq!(
            request_count(&server, "/api/fleet/package_policies").await,
            0,
            "{label}: name and package preflight must not begin"
        );
        assert_eq!(
            request_count(&server, "/api/fleet/agent_policies/parent-1").await,
            0,
            "{label}: parent reads must not begin"
        );
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system").await,
            0,
            "{label}: package status must not begin"
        );
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system/2.0.0").await,
            0,
            "{label}: package metadata must not begin"
        );
        assert!(no_import_mutation_requests(&server).await);
    }
}

#[tokio::test]
async fn plan_import_rejects_multiple_requested_versions_before_transport_io() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let mut second = spec_json("second");
    second["package"]["version"] = json!("3.0.0");
    let artifact = write_import_artifact(
        directory.path(),
        "different-versions.json",
        &[spec_json("first"), second],
    );

    let error =
        integration_policy_ops::plan_import(&transport_for(&server), &artifact, false, false)
            .await
            .expect_err("one package cannot request two versions");
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert!(error.message.contains("more than one version"));
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty(),
        "version contradiction is entirely local"
    );
}

#[tokio::test]
async fn plan_import_ignores_unrelated_duplicate_live_names() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let artifact = write_import_artifact(directory.path(), "fresh.json", &[spec_json("fresh")]);
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/fresh"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "statusCode": 404,
            "error": "Not Found",
            "message": "missing"
        })))
        .mount(&server)
        .await;
    let mut duplicate_a = item("unrelated-a");
    duplicate_a["name"] = json!("Unrelated duplicate");
    let mut duplicate_b = item("unrelated-b");
    duplicate_b["name"] = json!("Unrelated duplicate");
    mount_integration_pages(&server, vec![(1, vec![duplicate_a, duplicate_b], 2)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!([]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .mount(&server)
        .await;

    let plan =
        integration_policy_ops::plan_import(&transport_for(&server), &artifact, false, false)
            .await
            .expect("unrelated duplicate names must not affect a selected name");
    assert_eq!(plan.preview.targets, vec!["fresh"]);
}

#[tokio::test]
async fn plan_import_package_state_matrix_is_strict_and_stops_before_metadata() {
    let cases = vec![
        (
            "installed-exact",
            installed_package("2.0.0"),
            None,
            Vec::<String>::new(),
            1,
        ),
        (
            "not-installed",
            json!({"name": "system", "status": "not_installed"}),
            None,
            vec!["system@2.0.0".into()],
            1,
        ),
        (
            "installed-different-version",
            installed_package("3.0.0"),
            Some(ErrorKind::Conflict),
            Vec::new(),
            0,
        ),
        (
            "unknown-status",
            json!({"name": "system", "status": "installing"}),
            Some(ErrorKind::Http),
            Vec::new(),
            0,
        ),
        (
            "not-installed-with-version",
            json!({
                "name": "system",
                "status": "not_installed",
                "installationInfo": {"version": "2.0.0"}
            }),
            Some(ErrorKind::Http),
            Vec::new(),
            0,
        ),
    ];

    for (label, status, expected_error, expected_installs, metadata_requests) in cases {
        let server = verified_server().await;
        let directory = tempfile::tempdir().expect("artifact directory");
        let artifact = write_import_artifact(
            directory.path(),
            &format!("{label}.json"),
            &[spec_json("fresh")],
        );
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/fresh"))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing"
            })))
            .mount(&server)
            .await;
        mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": parent_item("parent-1", "default", 0, json!([]))
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": status})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": safe_package_metadata()
            })))
            .mount(&server)
            .await;

        let result =
            integration_policy_ops::plan_import(&transport_for(&server), &artifact, false, false)
                .await;
        match expected_error {
            Some(kind) => assert_eq!(result.expect_err(label).kind, kind, "{label}"),
            None => assert_eq!(
                result.expect(label).package_installs,
                expected_installs,
                "{label}"
            ),
        }
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system/2.0.0").await,
            metadata_requests,
            "{label}: unsafe status must stop metadata preflight"
        );
        assert!(no_import_mutation_requests(&server).await, "{label}");
    }
}

#[tokio::test]
async fn plan_import_parent_matrix_refuses_missing_incompatible_and_unsafe_parents() {
    for (label, expected_kind) in [
        ("missing", ErrorKind::NotFound),
        ("namespace", ErrorKind::Conflict),
        ("unsafe", ErrorKind::Unsupported),
    ] {
        let server = verified_server().await;
        let directory = tempfile::tempdir().expect("artifact directory");
        let mut desired = spec_json("fresh");
        if label == "namespace" {
            desired
                .as_object_mut()
                .expect("artifact object")
                .remove("namespace");
            desired["policy_ids"] = json!(["parent-a", "parent-b"]);
        }
        let artifact =
            write_import_artifact(directory.path(), &format!("{label}.json"), &[desired]);
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/fresh"))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing"
            })))
            .mount(&server)
            .await;
        mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
        match label {
            "missing" => {
                Mock::given(method("GET"))
                    .and(path("/api/fleet/agent_policies/parent-1"))
                    .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                        "statusCode": 404,
                        "error": "Not Found",
                        "message": "missing"
                    })))
                    .mount(&server)
                    .await;
            }
            "namespace" => {
                for (id, namespace) in [("parent-a", "default"), ("parent-b", "other")] {
                    Mock::given(method("GET"))
                        .and(path(format!("/api/fleet/agent_policies/{id}")))
                        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                            "item": parent_item(id, namespace, 0, json!([]))
                        })))
                        .mount(&server)
                        .await;
                }
            }
            "unsafe" => {
                let mut parent = parent_item("parent-1", "default", 0, json!([]));
                parent["is_default"] = json!(true);
                Mock::given(method("GET"))
                    .and(path("/api/fleet/agent_policies/parent-1"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": parent})))
                    .mount(&server)
                    .await;
            }
            _ => unreachable!("matrix label"),
        }

        let error =
            integration_policy_ops::plan_import(&transport_for(&server), &artifact, false, false)
                .await
                .expect_err("parent preflight must fail");
        assert_eq!(error.kind, expected_kind, "{label}");
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system").await,
            0,
            "{label}: parent failure must stop package preflight"
        );
        assert!(no_import_mutation_requests(&server).await, "{label}");
    }
}

#[tokio::test]
async fn plan_import_refuses_configured_secrets_without_leaking_values() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let secret = "integration-import-secret-value";
    let mut desired = spec_json("fresh");
    desired["vars"] = json!({"package_secret": secret});
    desired["inputs"] = json!({"system-system": {}});
    let artifact = write_import_artifact(directory.path(), "secret.json", &[desired]);
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/fresh"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "statusCode": 404,
            "error": "Not Found",
            "message": "missing"
        })))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!([]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": secret_matrix_metadata()
        })))
        .mount(&server)
        .await;

    let error =
        integration_policy_ops::plan_import(&transport_for(&server), &artifact, false, false)
            .await
            .expect_err("configured secrets are not portable");
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert!(!error.message.contains(secret));
    assert!(error.message.contains("vars.package_secret"));
}

#[tokio::test]
async fn plan_import_refuses_current_plaintext_secrets_omitted_from_overwrite() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let mut desired = spec_json("existing");
    desired["description"] = json!("new description");
    desired["inputs"] = json!({"system-system": {}});
    let artifact = write_import_artifact(directory.path(), "current-secrets.json", &[desired]);

    let mut current = live_item("existing");
    current.insert("description".into(), json!("old description"));
    current.insert(
        "vars".into(),
        json!({"package_secret": "current-package-secret"}),
    );
    current.insert(
        "inputs".into(),
        json!({
            "system-system": {
                "vars": {"input_secret": "current-input-secret"},
                "streams": {
                    "system.cpu": {
                        "vars": {"stream_secret": "current-stream-secret"}
                    }
                }
            }
        }),
    );
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/existing"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": current})))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, vec![item("existing")], 1)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!(["existing"]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": secret_matrix_metadata()
        })))
        .mount(&server)
        .await;

    let error =
        integration_policy_ops::plan_import(&transport_for(&server), &artifact, true, false)
            .await
            .expect_err("current secret values cannot be removed through overwrite");
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(
        error.message,
        "integration policy import contains configured secrets: existing:inputs.system-system.streams.system.cpu.vars.stream_secret, existing:inputs.system-system.vars.input_secret, existing:vars.package_secret"
    );
    for value in [
        "current-package-secret",
        "current-input-secret",
        "current-stream-secret",
    ] {
        assert!(!error.message.contains(value));
    }
    assert!(no_import_mutation_requests(&server).await);
}

#[tokio::test]
async fn plan_import_refuses_current_variables_without_exact_metadata_definitions() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let artifact = write_import_artifact(
        directory.path(),
        "current-unknown.json",
        &[spec_json("existing")],
    );

    let mut current = live_item("existing");
    current.insert(
        "vars".into(),
        json!({"unknown_live_var": "current-unknown-value"}),
    );
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/existing"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": current})))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, vec![item("existing")], 1)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!(["existing"]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .mount(&server)
        .await;

    let error =
        integration_policy_ops::plan_import(&transport_for(&server), &artifact, true, false)
            .await
            .expect_err("current values without an exact definition are unsafe");
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert!(error.message.contains("existing:vars.unknown_live_var"));
    assert!(!error.message.contains("current-unknown-value"));
    assert!(no_import_mutation_requests(&server).await);
}

#[tokio::test]
async fn integration_import_plan_debug_exposes_only_public_summary_data() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let mut desired = spec_json("existing");
    desired["description"] = json!("canonical-value-must-not-leak");
    desired["inputs"] = json!({"system-system": {}});
    let artifact = write_import_artifact(directory.path(), "debug.json", &[desired]);

    let mut current = live_item("existing");
    current.insert(
        "description".into(),
        json!("raw-current-value-must-not-leak"),
    );
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/existing"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": current})))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, vec![item("existing")], 1)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!(["existing"]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    let mut metadata = secret_matrix_metadata();
    metadata["raw_metadata_value"] = json!("metadata-value-must-not-leak");
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": metadata})))
        .mount(&server)
        .await;

    let mut plan =
        integration_policy_ops::plan_import(&transport_for(&server), &artifact, true, false)
            .await
            .expect("safe plan");
    plan.preview.preview_action = "public-preview-value-must-not-leak".into();
    plan.skipped = vec![json!({"value": "public-skipped-value-must-not-leak"})];
    plan.package_installs = vec!["public-package-value-must-not-leak".into()];
    let debug = format!("{plan:?}");
    assert!(debug.contains("IntegrationPolicyImportPlan"));
    assert!(debug.contains("total: 1"));
    for value in [
        "canonical-value-must-not-leak",
        "raw-current-value-must-not-leak",
        "metadata-value-must-not-leak",
        "public-preview-value-must-not-leak",
        "public-skipped-value-must-not-leak",
        "public-package-value-must-not-leak",
    ] {
        assert!(!debug.contains(value), "Debug leaked {value}");
    }
}

#[tokio::test]
async fn plan_import_sanitizes_remote_route_error_bodies() {
    for (label, body, forbidden) in [
        (
            "string",
            json!("route-string-token"),
            vec!["route-string-token"],
        ),
        ("number", json!(918273), vec!["918273"]),
        ("boolean", json!(true), vec!["true"]),
        (
            "object",
            json!({"credential": "route-object-token", "environment": "route-environment-token"}),
            vec!["route-object-token", "route-environment-token"],
        ),
    ] {
        let server = verified_server().await;
        let directory = tempfile::tempdir().expect("artifact directory");
        let artifact = write_import_artifact(
            directory.path(),
            &format!("{label}.json"),
            &[spec_json("fresh")],
        );
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/fresh"))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(500).set_body_json(body))
            .mount(&server)
            .await;

        let error =
            integration_policy_ops::plan_import(&transport_for(&server), &artifact, false, false)
                .await
                .expect_err("server error must not escape its body");
        assert_eq!(error.kind, ErrorKind::Http, "{label}");
        assert_eq!(error.http_status, Some(500), "{label}");
        assert_eq!(
            error.message, "integration-policy import planning read failed",
            "{label}"
        );
        for value in forbidden {
            assert!(!error.message.contains(value), "{label} leaked {value}");
        }
    }
}

#[tokio::test]
async fn plan_import_skips_or_conflicts_before_normalizing_an_unsupported_existing_policy() {
    for (label, skip_existing) in [("default-conflict", false), ("skip", true)] {
        let server = verified_server().await;
        let directory = tempfile::tempdir().expect("artifact directory");
        let artifact = write_import_artifact(
            directory.path(),
            &format!("{label}.json"),
            &[spec_json("existing")],
        );
        let mut existing = live_item("existing");
        existing.insert("is_managed".into(), json!(true));
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/existing"))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": existing})))
            .mount(&server)
            .await;
        if skip_existing {
            mount_integration_pages(&server, vec![(1, vec![item("existing")], 1)]).await;
        }

        let result = integration_policy_ops::plan_import(
            &transport_for(&server),
            &artifact,
            false,
            skip_existing,
        )
        .await;
        if skip_existing {
            let plan = result.expect("skip path must retain the unsupported row raw");
            assert_eq!(
                plan.skipped,
                vec![json!({"id": "existing", "reason": "exists"})]
            );
        } else {
            assert_eq!(
                result
                    .expect_err("default conflict is decided before normalization")
                    .kind,
                ErrorKind::Conflict
            );
        }
        assert_eq!(
            request_count(&server, "/api/fleet/agent_policies/parent-1").await,
            0,
            "{label} must not inspect parents"
        );
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system").await,
            0,
            "{label} must not inspect packages"
        );
        assert!(no_import_mutation_requests(&server).await, "{label}");
    }
}

#[tokio::test]
async fn apply_import_uses_the_artifact_retained_by_planning_after_the_file_changes() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let original = spec_json("fresh");
    let artifact = write_import_artifact(
        directory.path(),
        "retained.json",
        std::slice::from_ref(&original),
    );
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/fresh"))
        .and(query_param("format", "simplified"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404).set_body_json(json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing"
            })),
            ResponseTemplate::new(404).set_body_json(json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing"
            })),
            ResponseTemplate::new(200).set_body_json(json!({"item": live_item("fresh")})),
        ]))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!([]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/package_policies"))
        .and(body_json(original))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": live_item("fresh")})))
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let plan = integration_policy_ops::plan_import(&transport, &artifact, false, false)
        .await
        .expect("plan import");
    std::fs::write(&artifact, "not an integration-policy artifact").expect("replace artifact");
    let report = integration_policy_ops::apply_import(&transport, &plan)
        .await
        .expect("apply must use the retained artifact");

    assert_eq!(
        report.succeeded,
        vec![json!({"id": "fresh", "action": "created"})]
    );
    assert!(report.failed.is_empty());
}

#[tokio::test]
async fn apply_import_sanitizes_create_route_error_bodies_in_reports() {
    for (label, body, forbidden) in [
        (
            "string",
            json!("apply-string-token"),
            vec!["apply-string-token"],
        ),
        ("number", json!(817263), vec!["817263"]),
        ("boolean", json!(true), vec!["true"]),
        (
            "object",
            json!({"credential": "apply-object-token", "environment": "apply-environment-token"}),
            vec!["apply-object-token", "apply-environment-token"],
        ),
    ] {
        let server = verified_server().await;
        let directory = tempfile::tempdir().expect("artifact directory");
        let artifact = write_import_artifact(
            directory.path(),
            &format!("{label}.json"),
            &[spec_json("fresh")],
        );
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/fresh"))
            .and(query_param("format", "simplified"))
            .respond_with(SequenceResponder::new(vec![
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
            ]))
            .mount(&server)
            .await;
        mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": parent_item("parent-1", "default", 0, json!([]))
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": {"name": "system", "status": "not_installed"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": safe_package_metadata()
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .respond_with(ResponseTemplate::new(500).set_body_json(body))
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let plan = integration_policy_ops::plan_import(&transport, &artifact, false, false)
            .await
            .expect("plan failed-create import");
        let report = integration_policy_ops::apply_import(&transport, &plan)
            .await
            .expect("route failures become safe report rows");
        assert_eq!(
            report.failed,
            vec![json!({
                "id": "fresh",
                "applied": false,
                "error": "integration-policy import create request failed"
            })],
            "{label}"
        );
        let message = report.failed[0]["error"].as_str().expect("safe error");
        for value in forbidden {
            assert!(!message.contains(value), "{label} leaked {value}");
        }
    }
}

#[tokio::test]
async fn apply_import_creates_replaces_and_leaves_unchanged_in_stable_id_order() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let mut changed = spec_json("changed");
    changed["description"] = json!("desired");
    let artifact = write_import_artifact(
        directory.path(),
        "apply.json",
        &[spec_json("same"), spec_json("fresh"), changed.clone()],
    );

    let mut changed_current = live_item("changed");
    changed_current.insert("description".into(), json!("current"));
    let mut changed_stored = changed_current.clone();
    changed_stored.insert("description".into(), json!("desired"));
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/changed"))
        .and(query_param("format", "simplified"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": changed_current.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": changed_current.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": changed_stored.clone()})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/fresh"))
        .and(query_param("format", "simplified"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404).set_body_json(json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing"
            })),
            ResponseTemplate::new(404).set_body_json(json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing"
            })),
            ResponseTemplate::new(200).set_body_json(json!({"item": live_item("fresh")})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/same"))
        .and(query_param("format", "simplified"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": live_item("same")})),
            ResponseTemplate::new(200).set_body_json(json!({"item": live_item("same")})),
        ]))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, vec![item("changed"), item("same")], 2)]).await;
    let before_fresh = parent_item("parent-1", "default", 7, json!(["changed", "same"]));
    let after_fresh = parent_item(
        "parent-1",
        "default",
        7,
        json!(["changed", "fresh", "same"]),
    );
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": before_fresh.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": before_fresh.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": before_fresh.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": before_fresh.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": before_fresh})),
            ResponseTemplate::new(200).set_body_json(json!({"item": after_fresh})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .mount(&server)
        .await;
    let update_body = json!({
        "name": "Integration changed",
        "description": "desired",
        "namespace": "default",
        "policy_ids": ["parent-1"],
        "package": {"name": "system", "version": "2.0.0"},
        "inputs": {}
    });
    Mock::given(method("PUT"))
        .and(path("/api/fleet/package_policies/changed"))
        .and(body_json(update_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": changed_stored
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/package_policies"))
        .and(body_json(spec_json("fresh")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": live_item("fresh")})))
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let plan = integration_policy_ops::plan_import(&transport, &artifact, true, false)
        .await
        .expect("plan mixed apply");
    let report = integration_policy_ops::apply_import(&transport, &plan)
        .await
        .expect("apply mixed rows");
    assert_eq!(
        report.succeeded,
        vec![
            json!({"id": "changed", "action": "replaced"}),
            json!({"id": "fresh", "action": "created"}),
        ]
    );
    assert_eq!(report.unchanged, vec![json!({"id": "same"})]);
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    assert_eq!(report.affected_agents, 7);
    assert!(report.package_installs.is_empty());
    let writes = server
        .received_requests()
        .await
        .expect("recorded requests")
        .into_iter()
        .filter(|request| request.method == "POST" || request.method == "PUT")
        .map(|request| (request.method.to_string(), request.url.path().to_owned()))
        .collect::<Vec<_>>();
    assert_eq!(
        writes,
        vec![
            ("PUT".into(), "/api/fleet/package_policies/changed".into()),
            ("POST".into(), "/api/fleet/package_policies".into()),
        ]
    );
}

#[tokio::test]
async fn apply_import_create_race_matrix_stops_before_writes() {
    for (label, expected_error) in [
        ("appeared", "integration policy appeared since preview"),
        (
            "name",
            "integration policy name ownership changed since preview",
        ),
        ("parent", "integration policy parent changed since preview"),
        ("package", "package changed since preview"),
    ] {
        let server = verified_server().await;
        let directory = tempfile::tempdir().expect("artifact directory");
        let artifact = write_import_artifact(
            directory.path(),
            &format!("{label}.json"),
            &[spec_json("fresh")],
        );
        let at_apply = if label == "appeared" {
            ResponseTemplate::new(200).set_body_json(json!({"item": live_item("fresh")}))
        } else {
            ResponseTemplate::new(404).set_body_json(json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing"
            }))
        };
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/fresh"))
            .and(query_param("format", "simplified"))
            .respond_with(SequenceResponder::new(vec![
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
                at_apply,
            ]))
            .mount(&server)
            .await;
        let mut claimant = item("other");
        claimant["name"] = json!("Integration fresh");
        let at_apply_names = if label == "name" {
            vec![claimant]
        } else {
            Vec::new()
        };
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies"))
            .respond_with(SequenceResponder::new(vec![
                ResponseTemplate::new(200).set_body_json(json!({
                    "items": [], "total": 0, "page": 1, "perPage": 1000
                })),
                ResponseTemplate::new(200).set_body_json(json!({
                    "items": at_apply_names,
                    "total": if label == "name" { 1 } else { 0 },
                    "page": 1,
                    "perPage": 1000
                })),
            ]))
            .mount(&server)
            .await;
        let at_apply_parent = if label == "parent" {
            parent_item("parent-1", "default", 1, json!([]))
        } else {
            parent_item("parent-1", "default", 0, json!([]))
        };
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(SequenceResponder::new(vec![
                ResponseTemplate::new(200).set_body_json(json!({
                    "item": parent_item("parent-1", "default", 0, json!([]))
                })),
                ResponseTemplate::new(200).set_body_json(json!({"item": at_apply_parent})),
            ]))
            .mount(&server)
            .await;
        let at_apply_package = if label == "package" {
            installed_package("3.0.0")
        } else {
            installed_package("2.0.0")
        };
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(SequenceResponder::new(vec![
                ResponseTemplate::new(200)
                    .set_body_json(json!({"item": installed_package("2.0.0")})),
                ResponseTemplate::new(200).set_body_json(json!({"item": at_apply_package})),
            ]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": safe_package_metadata()
            })))
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let plan = integration_policy_ops::plan_import(&transport, &artifact, false, false)
            .await
            .expect("plan race target");
        let report = integration_policy_ops::apply_import(&transport, &plan)
            .await
            .expect("races return row failures");
        assert_eq!(
            report.failed,
            vec![json!({"id": "fresh", "applied": false, "error": expected_error})],
            "{label}"
        );
        assert!(report.succeeded.is_empty(), "{label}");
        assert!(no_import_mutation_requests(&server).await, "{label}");
    }
}

#[tokio::test]
async fn apply_import_existing_race_matrix_stops_before_writes() {
    for (label, at_apply, expected_error) in [
        (
            "disappeared",
            ResponseTemplate::new(404).set_body_json(json!({
                "statusCode": 404,
                "error": "Not Found",
                "message": "missing"
            })),
            "integration policy disappeared since preview",
        ),
        (
            "changed",
            ResponseTemplate::new(200).set_body_json(json!({
                "item": {
                    "id": "existing",
                    "name": "Integration existing",
                    "description": "raced",
                    "namespace": "default",
                    "policy_ids": ["parent-1"],
                    "package": {"name": "system", "version": "2.0.0"},
                    "inputs": {},
                    "enabled": true
                }
            })),
            "integration policy changed since preview",
        ),
    ] {
        let server = verified_server().await;
        let directory = tempfile::tempdir().expect("artifact directory");
        let mut desired = spec_json("existing");
        desired["description"] = json!("desired");
        let artifact =
            write_import_artifact(directory.path(), &format!("{label}.json"), &[desired]);
        let mut current = live_item("existing");
        current.insert("description".into(), json!("current"));
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/existing"))
            .and(query_param("format", "simplified"))
            .respond_with(SequenceResponder::new(vec![
                ResponseTemplate::new(200).set_body_json(json!({"item": current})),
                at_apply,
            ]))
            .mount(&server)
            .await;
        mount_integration_pages(&server, vec![(1, vec![item("existing")], 1)]).await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": parent_item("parent-1", "default", 0, json!(["existing"]))
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": installed_package("2.0.0")
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": safe_package_metadata()
            })))
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let plan = integration_policy_ops::plan_import(&transport, &artifact, true, false)
            .await
            .expect("plan existing race target");
        let report = integration_policy_ops::apply_import(&transport, &plan)
            .await
            .expect("races return row failures");
        assert_eq!(
            report.failed,
            vec![json!({"id": "existing", "applied": false, "error": expected_error})],
            "{label}"
        );
        assert!(no_import_mutation_requests(&server).await, "{label}");
    }
}

#[tokio::test]
async fn apply_import_observes_a_failed_create_install_and_continues_dependents() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let artifact = write_import_artifact(
        directory.path(),
        "missing-package.json",
        &[spec_json("b-succeeds"), spec_json("a-fails")],
    );
    for id in ["a-fails", "b-succeeds"] {
        let responses = if id == "a-fails" {
            vec![
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
            ]
        } else {
            vec![
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
                ResponseTemplate::new(200).set_body_json(json!({"item": live_item(id)})),
            ]
        };
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/package_policies/{id}")))
            .and(query_param("format", "simplified"))
            .respond_with(SequenceResponder::new(responses))
            .mount(&server)
            .await;
    }
    mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 4, json!([]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({
                "item": {"name": "system", "status": "not_installed"}
            })),
            ResponseTemplate::new(200).set_body_json(json!({
                "item": {"name": "system", "status": "not_installed"}
            })),
            ResponseTemplate::new(200).set_body_json(json!({"item": installed_package("2.0.0")})),
            ResponseTemplate::new(200).set_body_json(json!({"item": installed_package("2.0.0")})),
            ResponseTemplate::new(200).set_body_json(json!({"item": installed_package("2.0.0")})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/package_policies"))
        .and(body_json(spec_json("a-fails")))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "statusCode": 500,
            "error": "Internal Server Error",
            "message": "Fleet rejected a-fails"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/package_policies"))
        .and(body_json(spec_json("b-succeeds")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item": live_item("b-succeeds")})),
        )
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let plan = integration_policy_ops::plan_import(&transport, &artifact, false, false)
        .await
        .expect("plan missing package creates");
    assert_eq!(plan.package_installs, vec!["system@2.0.0"]);
    let report = integration_policy_ops::apply_import(&transport, &plan)
        .await
        .expect("failed create is a row result");
    assert_eq!(
        report.succeeded,
        vec![json!({"id": "b-succeeds", "action": "created"})]
    );
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0]["id"], "a-fails");
    assert_eq!(report.failed[0]["applied"], false);
    assert_eq!(
        report.failed[0]["error"],
        "integration-policy import create request failed"
    );
    assert_eq!(report.package_installs, vec!["system@2.0.0"]);
    assert_eq!(report.affected_agents, 4);
}

#[tokio::test]
async fn apply_import_blocks_only_the_package_group_that_changed() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let mut other = spec_json("c-other");
    other["package"] = json!({"name": "other", "version": "1.0.0"});
    let artifact = write_import_artifact(
        directory.path(),
        "groups.json",
        &[other.clone(), spec_json("b-system"), spec_json("a-system")],
    );
    for id in ["a-system", "b-system", "c-other"] {
        let responses = if id == "c-other" {
            let mut stored = live_item(id);
            stored.insert(
                "package".into(),
                json!({"name": "other", "version": "1.0.0"}),
            );
            vec![
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
                ResponseTemplate::new(200).set_body_json(json!({"item": stored})),
            ]
        } else {
            vec![
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
            ]
        };
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/package_policies/{id}")))
            .and(query_param("format", "simplified"))
            .respond_with(SequenceResponder::new(responses))
            .mount(&server)
            .await;
    }
    mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 2, json!([]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": installed_package("2.0.0")})),
            ResponseTemplate::new(200).set_body_json(json!({"item": installed_package("3.0.0")})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/other"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": {
                "name": "other",
                "status": "installed",
                "installationInfo": {"version": "1.0.0"}
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/other/1.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": {
                "name": "other",
                "version": "1.0.0",
                "vars": [],
                "policy_templates": []
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/package_policies"))
        .and(body_json(other))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": {
                "id": "c-other",
                "name": "Integration c-other",
                "namespace": "default",
                "policy_ids": ["parent-1"],
                "package": {"name": "other", "version": "1.0.0"},
                "inputs": {},
                "enabled": true
            }
        })))
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let plan = integration_policy_ops::plan_import(&transport, &artifact, false, false)
        .await
        .expect("plan independent package groups");
    let report = integration_policy_ops::apply_import(&transport, &plan)
        .await
        .expect("package failures are row results");
    assert_eq!(
        report.succeeded,
        vec![json!({"id": "c-other", "action": "created"})]
    );
    assert_eq!(
        report.failed,
        vec![
            json!({
                "id": "a-system",
                "applied": false,
                "error": "package changed since preview"
            }),
            json!({
                "id": "b-system",
                "applied": false,
                "error": "package dependency is unavailable: package changed since preview"
            }),
        ]
    );
    assert_eq!(report.affected_agents, 2);
    assert_eq!(
        request_count(&server, "/api/fleet/package_policies/b-system").await,
        1,
        "blocked dependent must not recheck or write"
    );
}

#[tokio::test]
async fn apply_import_invalid_package_state_matrix_blocks_dependents_before_writes() {
    let cases = vec![
        (
            "installing-without-version",
            json!({"name": "system", "status": "installing"}),
        ),
        (
            "installing-with-version",
            json!({
                "name": "system",
                "status": "installing",
                "installationInfo": {"version": "2.0.0"}
            }),
        ),
        (
            "not-installed-with-version",
            json!({
                "name": "system",
                "status": "not_installed",
                "installationInfo": {"version": "2.0.0"}
            }),
        ),
        (
            "failed-without-version",
            json!({"name": "system", "status": "failed"}),
        ),
        (
            "failed-with-version",
            json!({
                "name": "system",
                "status": "failed",
                "installationInfo": {"version": "2.0.0"}
            }),
        ),
        (
            "unknown-without-version",
            json!({"name": "system", "status": "future"}),
        ),
        (
            "unknown-with-version",
            json!({
                "name": "system",
                "status": "future",
                "installationInfo": {"version": "2.0.0"}
            }),
        ),
        (
            "installed-without-version",
            json!({"name": "system", "status": "installed"}),
        ),
    ];
    for (label, invalid_state) in cases {
        let server = verified_server().await;
        let directory = tempfile::tempdir().expect("artifact directory");
        let artifact = write_import_artifact(
            directory.path(),
            &format!("{label}.json"),
            &[spec_json("b-dependent"), spec_json("a-first")],
        );
        for id in ["a-first", "b-dependent"] {
            let responses = if id == "a-first" {
                vec![
                    ResponseTemplate::new(404).set_body_json(json!({
                        "statusCode": 404,
                        "error": "Not Found",
                        "message": "missing"
                    })),
                    ResponseTemplate::new(404).set_body_json(json!({
                        "statusCode": 404,
                        "error": "Not Found",
                        "message": "missing"
                    })),
                ]
            } else {
                vec![ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                }))]
            };
            Mock::given(method("GET"))
                .and(path(format!("/api/fleet/package_policies/{id}")))
                .and(query_param("format", "simplified"))
                .respond_with(SequenceResponder::new(responses))
                .mount(&server)
                .await;
        }
        mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": parent_item("parent-1", "default", 0, json!([]))
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(SequenceResponder::new(vec![
                ResponseTemplate::new(200).set_body_json(json!({
                    "item": {"name": "system", "status": "not_installed"}
                })),
                ResponseTemplate::new(200).set_body_json(json!({"item": invalid_state})),
            ]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": safe_package_metadata()
            })))
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let plan = integration_policy_ops::plan_import(&transport, &artifact, false, false)
            .await
            .expect("plan strict package state");
        let report = integration_policy_ops::apply_import(&transport, &plan)
            .await
            .expect("invalid package state is a row failure");
        assert_eq!(report.failed.len(), 2, "{label}");
        assert_eq!(report.failed[0]["id"], "a-first", "{label}");
        assert_eq!(report.failed[0]["applied"], false, "{label}");
        assert_eq!(report.failed[1]["id"], "b-dependent", "{label}");
        assert!(
            report.failed[1]["error"]
                .as_str()
                .expect("dependency error")
                .starts_with("package dependency is unavailable:")
        );
        assert!(no_import_mutation_requests(&server).await, "{label}");
    }
}

#[tokio::test]
async fn apply_import_marks_post_write_storage_and_package_failures_as_applied() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let artifact = write_import_artifact(
        directory.path(),
        "post-write.json",
        &[spec_json("b-package"), spec_json("a-stored")],
    );
    for id in ["a-stored", "b-package"] {
        let responses = if id == "a-stored" {
            let mut wrong = live_item(id);
            wrong.insert("description".into(), json!("server drift"));
            vec![
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
                ResponseTemplate::new(200).set_body_json(json!({"item": wrong})),
            ]
        } else {
            vec![
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
                ResponseTemplate::new(200).set_body_json(json!({"item": live_item(id)})),
            ]
        };
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/package_policies/{id}")))
            .and(query_param("format", "simplified"))
            .respond_with(SequenceResponder::new(responses))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(body_json(spec_json(id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": live_item(id)})))
            .mount(&server)
            .await;
    }
    mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
    let before = parent_item("parent-1", "default", 5, json!([]));
    let after_first = parent_item("parent-1", "default", 5, json!(["a-stored"]));
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": before.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": before.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": before})),
            ResponseTemplate::new(200).set_body_json(json!({"item": after_first})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": installed_package("2.0.0")})),
            ResponseTemplate::new(200).set_body_json(json!({"item": installed_package("2.0.0")})),
            ResponseTemplate::new(200).set_body_json(json!({"item": installed_package("2.0.0")})),
            ResponseTemplate::new(200).set_body_json(json!({"item": installed_package("2.0.0")})),
            ResponseTemplate::new(200).set_body_json(json!({"item": installed_package("3.0.0")})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let plan = integration_policy_ops::plan_import(&transport, &artifact, false, false)
        .await
        .expect("plan post-write rows");
    let report = integration_policy_ops::apply_import(&transport, &plan)
        .await
        .expect("post-write checks return failures");
    assert_eq!(
        report.failed,
        vec![
            json!({
                "id": "a-stored",
                "applied": true,
                "error": "server stored a different integration-policy spec"
            }),
            json!({
                "id": "b-package",
                "applied": true,
                "error": "package system installed a different version"
            }),
        ]
    );
    assert_eq!(report.affected_agents, 5, "parent union counts once");
    assert!(report.succeeded.is_empty());
}

#[tokio::test]
async fn apply_import_rejects_public_tampering_and_host_mismatch_before_requests() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let artifact = write_import_artifact(directory.path(), "tamper.json", &[spec_json("fresh")]);
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/fresh"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "statusCode": 404,
            "error": "Not Found",
            "message": "missing"
        })))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!([]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": {"name": "system", "status": "not_installed"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let plan = integration_policy_ops::plan_import(&transport, &artifact, false, false)
        .await
        .expect("plan for tamper checks");
    let before = server.received_requests().await.expect("requests").len();
    let mut tampered_preview = plan.clone();
    tampered_preview.preview.preview_action = "tampered".into();
    let mut tampered_skipped = plan.clone();
    tampered_skipped.skipped = vec![json!({"id": "fresh", "reason": "exists"})];
    let mut tampered_installs = plan.clone();
    tampered_installs.package_installs.clear();
    let mut tampered_total = plan.clone();
    tampered_total.total = 99;
    for tampered in [
        tampered_preview,
        tampered_skipped,
        tampered_installs,
        tampered_total,
    ] {
        let error = integration_policy_ops::apply_import(&transport, &tampered)
            .await
            .expect_err("tampered public plan must be rejected locally");
        assert_eq!(error.kind, ErrorKind::Error);
    }

    let other = verified_server().await;
    let other_transport = transport_for(&other);
    let error = integration_policy_ops::apply_import(&other_transport, &plan)
        .await
        .expect_err("a plan cannot move to another Kibana host");
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(
        server.received_requests().await.expect("requests").len(),
        before,
        "invalid plans and a host mismatch must issue no source requests"
    );
    assert!(
        other
            .received_requests()
            .await
            .expect("other requests")
            .is_empty(),
        "host mismatch must stop before target requests"
    );
}

#[tokio::test]
async fn apply_import_parent_race_matrix_stops_before_dependency_or_write() {
    for label in [
        "agents",
        "attachment",
        "platform",
        "protection",
        "namespace",
    ] {
        let server = verified_server().await;
        let directory = tempfile::tempdir().expect("artifact directory");
        let artifact = write_import_artifact(
            directory.path(),
            &format!("parent-{label}.json"),
            &[spec_json("fresh")],
        );
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/fresh"))
            .and(query_param("format", "simplified"))
            .respond_with(SequenceResponder::new(vec![
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "missing"
                })),
            ]))
            .mount(&server)
            .await;
        mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;
        let mut raced = parent_item("parent-1", "default", 0, json!([]));
        match label {
            "agents" => raced["agents"] = json!(1),
            "attachment" => raced["package_policies"] = json!(["other-integration"]),
            "platform" => raced["is_default"] = json!(true),
            "protection" => raced["is_protected"] = json!(true),
            "namespace" => raced["namespace"] = json!("other"),
            _ => unreachable!("parent race label"),
        }
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(SequenceResponder::new(vec![
                ResponseTemplate::new(200).set_body_json(json!({
                    "item": parent_item("parent-1", "default", 0, json!([]))
                })),
                ResponseTemplate::new(200).set_body_json(json!({"item": raced})),
            ]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": installed_package("2.0.0")
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": safe_package_metadata()
            })))
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let plan = integration_policy_ops::plan_import(&transport, &artifact, false, false)
            .await
            .expect("plan parent race target");
        let report = integration_policy_ops::apply_import(&transport, &plan)
            .await
            .expect("parent race is a row failure");
        assert_eq!(
            report.failed,
            vec![json!({
                "id": "fresh",
                "applied": false,
                "error": "integration policy parent changed since preview"
            })],
            "{label}"
        );
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system").await,
            1,
            "{label}: only planning may read the package"
        );
        assert!(no_import_mutation_requests(&server).await, "{label}");
    }
}

#[tokio::test]
async fn plan_import_rejects_a_wrong_returned_id_before_parent_or_package_preflight() {
    let server = verified_server().await;
    let directory = tempfile::tempdir().expect("artifact directory");
    let artifact = write_import_artifact(directory.path(), "wrong-id.json", &[spec_json("wanted")]);
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/wanted"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": live_item("returned-other")
        })))
        .mount(&server)
        .await;

    let error =
        integration_policy_ops::plan_import(&transport_for(&server), &artifact, true, false)
            .await
            .expect_err("a single-item response must echo its requested id");
    assert_eq!(error.kind, ErrorKind::Http);
    assert_eq!(
        request_count(&server, "/api/fleet/package_policies").await,
        0,
        "wrong-id response must stop before list ownership reads"
    );
    assert_eq!(
        request_count(&server, "/api/fleet/agent_policies/parent-1").await,
        0,
        "wrong-id response must stop before parent reads"
    );
    assert_eq!(
        request_count(&server, "/api/fleet/epm/packages/system").await,
        0,
        "wrong-id response must stop before package reads"
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
        "inputs": {}
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
                {"name": "system", "inputs": [{"type": "system-password", "vars": [{"name": "password", "secret": false}]}]},
                {"name": "system-system", "inputs": [{"type": "password", "vars": [{"name": "password", "secret": true}]}]}
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
            .contains("duplicate input key 'system-system-password'")
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
async fn export_accepts_measured_system_top_level_streams() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert(
        "inputs".into(),
        json!({
            "system-system": {
                "streams": {"system.cpu": {"vars": {"period": "10s"}}}
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
        measured_system_metadata(),
    )
    .await;

    let result = integration_policy_ops::export(
        &transport_for(&server),
        &["integration-1".into()],
        false,
        ContentFormat::Json,
    )
    .await
    .expect("modern system stream definition is known and nonsecret");
    assert_eq!(result.exported, 1);
}

#[tokio::test]
async fn export_rejects_modern_stream_secrets_without_leaking_values() {
    let server = verified_server().await;
    let secret = "modern-stream-secret-value";
    let mut policy = live_item("integration-1");
    policy.insert(
        "inputs".into(),
        json!({
            "system-system": {
                "streams": {"system.cpu": {"vars": {"period": secret}}}
            }
        }),
    );
    let mut metadata = measured_system_metadata();
    metadata["data_streams"][0]["streams"][0]["vars"][0]["secret"] = json!(true);
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
    .expect_err("modern secret definitions are not portable");
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert!(
        error
            .message
            .contains("integration-1:inputs.system-system.streams.system.cpu.vars.period")
    );
    assert!(!error.message.contains(secret));
}

#[tokio::test]
async fn export_joins_short_selectors_with_the_package_name() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert(
        "package".into(),
        json!({"name": "azure", "version": "1.40.0"}),
    );
    policy.insert(
        "inputs".into(),
        json!({
            "logs-a": {"streams": {"azure.activitylogs": {"vars": {"period": "10s"}}}},
            "metrics-a": {"streams": {"azure.metrics": {"vars": {"period": "10s"}}}},
        }),
    );
    let metadata = json!({
        "name": "azure",
        "version": "1.40.0",
        "policy_templates": [
            {
                "name": "logs",
                "data_streams": ["activitylogs"],
                "inputs": [{"type": "a"}]
            },
            {
                "name": "metrics",
                "data_streams": ["metrics"],
                "inputs": [{"type": "a"}]
            }
        ],
        "data_streams": [
            {
                "dataset": "azure.activitylogs",
                "streams": [{"input": "a", "vars": [{"name": "period"}]}]
            },
            {
                "dataset": "azure.metrics",
                "streams": [{"input": "a", "vars": [{"name": "period"}]}]
            }
        ]
    });
    mount_export_dependencies_for_package(
        &server,
        "integration-1",
        policy,
        vec![parent_item(
            "parent-1",
            "default",
            0,
            json!(["integration-1"]),
        )],
        PackageCoordinate {
            name: "azure",
            version: "1.40.0",
        },
        json!({
            "name": "azure",
            "status": "installed",
            "installationInfo": {"version": "1.40.0"}
        }),
        metadata,
    )
    .await;

    let result = integration_policy_ops::export(
        &transport_for(&server),
        &["integration-1".into()],
        false,
        ContentFormat::Json,
    )
    .await
    .expect("short selectors disambiguate repeated input types");
    assert_eq!(result.exported, 1);
}

#[tokio::test]
async fn modern_template_selector_absence_selects_all_and_empty_selects_none() {
    for (label, selectors, expected) in [
        ("absent", None, None),
        ("empty", Some(json!([])), Some(ErrorKind::Http)),
    ] {
        let server = verified_server().await;
        let mut policy = live_item("integration-1");
        policy.insert(
            "inputs".into(),
            json!({
                "system-system": {
                    "streams": {"system.cpu": {"vars": {"period": "10s"}}}
                }
            }),
        );
        let mut metadata = measured_system_metadata();
        if let Some(selectors) = selectors {
            metadata["policy_templates"][0]["data_streams"] = selectors;
        }
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

        let result = integration_policy_ops::export(
            &transport_for(&server),
            &["integration-1".into()],
            false,
            ContentFormat::Json,
        )
        .await;
        match expected {
            None => assert_eq!(result.expect(label).exported, 1),
            Some(kind) => assert_eq!(result.expect_err(label).kind, kind),
        }
    }
}

#[tokio::test]
async fn export_accepts_legacy_only_and_identical_dual_stream_definitions() {
    let templates = json!([
        {
            "name": "system",
            "inputs": [
                {
                    "type": "system",
                    "streams": [
                        {
                            "data_stream": {"dataset": "system.cpu"},
                            "vars": [{"name": "period"}]
                        }
                    ]
                }
            ]
        }
    ]);
    let dual = modern_package_metadata(
        templates.clone(),
        json!([
            {
                "dataset": "system.cpu",
                "streams": [{"input": "system", "vars": [{"name": "period"}]}]
            }
        ]),
    );
    for (label, metadata) in [
        ("legacy", package_metadata(json!([]), templates)),
        ("identical dual", dual),
    ] {
        let server = verified_server().await;
        let mut policy = live_item("integration-1");
        policy.insert(
            "inputs".into(),
            json!({
                "system-system": {
                    "streams": {"system.cpu": {"vars": {"period": "10s"}}}
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
            metadata,
        )
        .await;
        assert_eq!(
            integration_policy_ops::export(
                &transport_for(&server),
                &["integration-1".into()],
                false,
                ContentFormat::Json,
            )
            .await
            .expect(label)
            .exported,
            1
        );
    }
}

#[tokio::test]
async fn export_refuses_conflicting_modern_and_legacy_stream_definitions() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert(
        "inputs".into(),
        json!({
            "system-system": {
                "streams": {"system.cpu": {"vars": {"period": "10s"}}}
            }
        }),
    );
    let metadata = modern_package_metadata(
        json!([
            {
                "name": "system",
                "inputs": [{
                    "type": "system",
                    "streams": [{
                        "data_stream": {"dataset": "system.cpu"},
                        "vars": [{"name": "period", "secret": true}]
                    }]
                }]
            }
        ]),
        json!([
            {
                "dataset": "system.cpu",
                "streams": [{"input": "system", "vars": [{"name": "period"}]}]
            }
        ]),
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
    .expect_err("dual definitions must agree");
    assert_eq!(error.kind, ErrorKind::Http);
    assert!(
        error
            .message
            .contains("conflicting modern and legacy stream definition")
    );
}

#[tokio::test]
async fn export_rejects_ambiguous_modern_dataset_and_template_joins() {
    let mut cases = Vec::new();

    let mut duplicate_selector = measured_system_metadata();
    duplicate_selector["policy_templates"][0]["data_streams"] = json!(["cpu", "cpu"]);
    cases.push((
        "duplicate selector",
        duplicate_selector,
        "duplicate data_streams selector",
    ));

    let mut duplicate_resolved_selector = measured_system_metadata();
    duplicate_resolved_selector["policy_templates"][0]["data_streams"] =
        json!(["cpu", "system.cpu"]);
    cases.push((
        "duplicate resolved selector",
        duplicate_resolved_selector,
        "duplicate data_streams dataset",
    ));

    let mut unresolved_selector = measured_system_metadata();
    unresolved_selector["policy_templates"][0]["data_streams"] = json!(["missing"]);
    cases.push((
        "unresolved selector",
        unresolved_selector,
        "does not match a dataset",
    ));

    let mut ambiguous_selector = measured_system_metadata();
    ambiguous_selector["policy_templates"][0]["data_streams"] = json!(["cpu"]);
    ambiguous_selector["data_streams"] = json!([
        {"dataset": "cpu", "streams": [{"input": "system", "vars": []}]},
        {"dataset": "system.cpu", "streams": [{"input": "system", "vars": []}]},
    ]);
    cases.push((
        "ambiguous selector",
        ambiguous_selector,
        "matches multiple datasets",
    ));

    let mut duplicate_dataset = measured_system_metadata();
    duplicate_dataset["data_streams"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "dataset": "system.cpu", "streams": []
        }));
    cases.push((
        "duplicate dataset",
        duplicate_dataset,
        "duplicate data stream dataset",
    ));

    let mut duplicate_stream_input = measured_system_metadata();
    duplicate_stream_input["data_streams"][0]["streams"]
        .as_array_mut()
        .unwrap()
        .push(json!({"input": "system", "vars": []}));
    cases.push((
        "duplicate stream input",
        duplicate_stream_input,
        "duplicate stream input",
    ));

    let mut zero_candidate = measured_system_metadata();
    zero_candidate["data_streams"][0]["streams"][0]["input"] = json!("missing");
    cases.push((
        "zero candidate",
        zero_candidate,
        "no matching template input",
    ));

    let multiple_candidate = modern_package_metadata(
        json!([
            {"name": "one", "data_streams": ["cpu"], "inputs": [{"type": "system"}]},
            {"name": "two", "data_streams": ["cpu"], "inputs": [{"type": "system"}]},
        ]),
        json!([
            {
                "dataset": "system.cpu",
                "streams": [{"input": "system", "vars": []}]
            }
        ]),
    );
    cases.push((
        "multiple candidates",
        multiple_candidate,
        "multiple matching template inputs",
    ));

    let duplicate_composite_input = modern_package_metadata(
        json!([
            {"name": "one-two", "data_streams": ["cpu"], "inputs": [{"type": "three"}]},
            {"name": "one", "data_streams": ["cpu"], "inputs": [{"type": "two-three"}]},
        ]),
        json!([{"dataset": "system.cpu", "streams": []}]),
    );
    cases.push((
        "duplicate composite input",
        duplicate_composite_input,
        "duplicate input key",
    ));

    let duplicate_template_name = modern_package_metadata(
        json!([
            {"name": "system", "data_streams": ["cpu"], "inputs": [{"type": "one"}]},
            {"name": "system", "data_streams": ["cpu"], "inputs": [{"type": "two"}]},
        ]),
        json!([{"dataset": "system.cpu", "streams": []}]),
    );
    cases.push((
        "duplicate template name",
        duplicate_template_name,
        "duplicate template name",
    ));

    for (label, metadata, expected) in cases {
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
        .expect_err(label);
        assert_eq!(error.kind, ErrorKind::Http, "{label}: {}", error.message);
        assert!(
            error.message.contains(expected),
            "{label}: {}",
            error.message
        );
    }
}

#[tokio::test]
async fn export_rejects_malformed_modern_package_metadata() {
    let mut cases = Vec::new();

    let mut metadata = measured_system_metadata();
    metadata["data_streams"] = json!({});
    cases.push(("data streams", metadata));
    let mut metadata = measured_system_metadata();
    metadata["data_streams"] = json!([false]);
    cases.push(("data stream entry", metadata));
    let mut metadata = measured_system_metadata();
    metadata["data_streams"][0]["dataset"] = json!("");
    cases.push(("dataset", metadata));
    let mut metadata = measured_system_metadata();
    metadata["data_streams"][0]["streams"] = json!({});
    cases.push(("streams", metadata));
    let mut metadata = measured_system_metadata();
    metadata["data_streams"][0]["streams"] = json!([false]);
    cases.push(("stream entry", metadata));
    let mut metadata = measured_system_metadata();
    metadata["data_streams"][0]["streams"][0]["input"] = json!("");
    cases.push(("stream input", metadata));
    let mut metadata = measured_system_metadata();
    metadata["data_streams"][0]["streams"][0]["vars"] = json!({});
    cases.push(("stream vars", metadata));
    let mut metadata = measured_system_metadata();
    metadata["data_streams"][0]["streams"][0]["vars"] = json!([false]);
    cases.push(("variable entry", metadata));
    let mut metadata = measured_system_metadata();
    metadata["data_streams"][0]["streams"][0]["vars"][0]["name"] = json!("");
    cases.push(("variable name", metadata));
    let mut metadata = measured_system_metadata();
    metadata["data_streams"][0]["streams"][0]["vars"] =
        json!([{"name": "period"}, {"name": "period"}]);
    cases.push(("duplicate variable", metadata));
    let mut metadata = measured_system_metadata();
    metadata["data_streams"][0]["streams"][0]["vars"][0]["secret"] = json!("true");
    cases.push(("secret flag", metadata));

    for (label, metadata) in cases {
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
        .expect_err(label);
        assert_eq!(error.kind, ErrorKind::Http, "{label}: {}", error.message);
    }
}

#[tokio::test]
async fn export_fails_closed_for_unknown_modern_configuration_without_leaking_values() {
    let value = "unknown-modern-value";
    let mut package = live_item("integration-1");
    package.insert("vars".into(), json!({"unknown": value}));
    let mut input = live_item("integration-1");
    input.insert(
        "inputs".into(),
        json!({"unknown-input": {"vars": {"period": value}}}),
    );
    let mut dataset = live_item("integration-1");
    dataset.insert(
        "inputs".into(),
        json!({
            "system-system": {
                "streams": {"system.unknown": {"vars": {"period": value}}}
            }
        }),
    );
    let mut variable = live_item("integration-1");
    variable.insert(
        "inputs".into(),
        json!({
            "system-system": {
                "streams": {"system.cpu": {"vars": {"unknown": value}}}
            }
        }),
    );

    for (label, policy, path) in [
        ("package", package, "vars.unknown"),
        ("input", input, "inputs.unknown-input"),
        (
            "dataset",
            dataset,
            "inputs.system-system.streams.system.unknown",
        ),
        (
            "variable",
            variable,
            "inputs.system-system.streams.system.cpu.vars.unknown",
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
            measured_system_metadata(),
        )
        .await;
        let error = integration_policy_ops::export(
            &transport_for(&server),
            &["integration-1".into()],
            false,
            ContentFormat::Json,
        )
        .await
        .expect_err(label);
        assert_eq!(
            error.kind,
            ErrorKind::Unsupported,
            "{label}: {}",
            error.message
        );
        assert!(error.message.contains(path), "{label}: {}", error.message);
        assert!(!error.message.contains(value), "{label}: {}", error.message);
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
async fn all_custom_skips_only_managed_and_parent_platform_owned_rows() {
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
                item("e-safe"),
            ],
            4,
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
async fn all_custom_refuses_a_custom_integration_with_a_protected_parent() {
    let server = verified_server().await;
    mount_integration_pages(&server, vec![(1, vec![item("integration-1")], 1)]).await;
    let mut protected_parent = parent_item("parent-1", "default", 0, json!(["integration-1"]));
    protected_parent["is_protected"] = json!(true);
    mount_export_dependencies(
        &server,
        "integration-1",
        live_item("integration-1"),
        vec![protected_parent],
        installed_package("2.0.0"),
        safe_package_metadata(),
    )
    .await;

    let error =
        integration_policy_ops::export(&transport_for(&server), &[], true, ContentFormat::Json)
            .await
            .expect_err("protected custom parent must refuse all-custom export");

    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(
        error.message,
        "integration policy 'integration-1' is not portable: parent parent-1 is_protected"
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

#[tokio::test]
async fn delete_preview_names_every_parent() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert("policy_ids".into(), json!(["parent-a", "parent-b"]));
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": policy})))
        .expect(1)
        .mount(&server)
        .await;
    for (id, agents) in [("parent-a", 2), ("parent-b", 3)] {
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/agent_policies/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": parent_item(id, "default", agents, json!(["integration-1"]))
            })))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .expect(1)
        .mount(&server)
        .await;

    let plan =
        integration_policy_ops::plan_delete(&transport_for(&server), &["integration-1".into()])
            .await
            .expect("safe delete plan");

    assert_eq!(
        plan.preview.preview_action,
        "Delete 1 integration policy(ies)"
    );
    assert_eq!(
        plan.preview.preview_details,
        [
            "integration-1  Integration integration-1  parents parent-a (Parent parent-a) agents 2, parent-b (Parent parent-b) agents 3  agents 5",
            "affected agents 5",
            "warning  Fleet can change after the final recheck and before the write",
        ]
    );
    assert_eq!(plan.preview.targets, ["integration-1"]);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded requests")
            .iter()
            .all(|request| request.method != "DELETE"),
        "planning must not delete"
    );
}

#[tokio::test]
async fn delete_rejects_empty_selectors_without_transport_io() {
    let server = verified_server().await;
    let error = integration_policy_ops::plan_delete(&transport_for(&server), &[])
        .await
        .expect_err("an empty delete selection is invalid");
    assert_eq!(error.kind, ErrorKind::Error);
    assert_eq!(
        error.message,
        "integration-policy delete needs at least one selector"
    );
    let error = integration_policy_ops::plan_delete(&transport_for(&server), &[" ".into()])
        .await
        .expect_err("a blank selector is invalid");
    assert_eq!(error.kind, ErrorKind::Error);
    assert_eq!(
        error.message,
        "integration-policy delete selectors must not be empty"
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded requests")
            .is_empty(),
        "empty local validation must precede the feature probe"
    );
}

#[tokio::test]
async fn delete_resolves_id_and_exact_name_deduplicates_and_sorts_targets() {
    let server = verified_server().await;
    let mut first = live_item("a-id");
    first.insert("policy_ids".into(), json!(["parent-a"]));
    let mut second = live_item("z-id");
    second.insert("name".into(), json!("Named integration"));
    second.insert("policy_ids".into(), json!(["parent-z"]));

    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/a-id"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": first})))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/Named%20integration"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "statusCode": 404, "message": "missing"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/z-id"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": second})))
        .expect(1)
        .mount(&server)
        .await;
    let mut named_summary = item("z-id");
    named_summary["name"] = json!("Named integration");
    named_summary["policy_ids"] = json!(["parent-z"]);
    mount_integration_pages(&server, vec![(1, vec![item("a-id"), named_summary], 2)]).await;
    for (id, policy) in [("parent-a", "a-id"), ("parent-z", "z-id")] {
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/agent_policies/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": parent_item(id, "default", 0, json!([policy]))
            })))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .expect(2)
        .mount(&server)
        .await;

    let plan = integration_policy_ops::plan_delete(
        &transport_for(&server),
        &["Named integration".into(), "a-id".into(), "a-id".into()],
    )
    .await
    .expect("both selectors resolve");
    assert_eq!(plan.total, 2);
    assert_eq!(plan.preview.targets, ["a-id", "z-id"]);
}

#[tokio::test]
async fn delete_keeps_missing_selector_classification() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/missing"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "statusCode": 404, "message": "must not escape"
        })))
        .mount(&server)
        .await;
    mount_integration_pages(&server, vec![(1, Vec::new(), 0)]).await;

    let error = integration_policy_ops::plan_delete(&transport_for(&server), &["missing".into()])
        .await
        .expect_err("missing selector");
    assert_eq!(error.kind, ErrorKind::NotFound);
    assert_eq!(
        error.message,
        "no integration policy with id or name 'missing'"
    );
    assert!(!error.message.contains("must not escape"));
}

#[tokio::test]
async fn delete_rejects_a_one_object_response_with_the_wrong_selected_id() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/selected"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": live_item("other")})))
        .mount(&server)
        .await;

    let error = integration_policy_ops::plan_delete(&transport_for(&server), &["selected".into()])
        .await
        .expect_err("a mutation must not retarget a selector");
    assert_eq!(error.kind, ErrorKind::Http);
    assert_eq!(
        error.message,
        "decoding integration policy delete planning read: response id did not match the selector"
    );
    assert_eq!(
        request_count(&server, "/api/fleet/agent_policies/parent-1").await,
        0
    );
}

#[tokio::test]
async fn delete_sanitizes_a_conflicting_id_selection_response() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "message": "id-selection-conflict-secret",
            "config": "id-selection-conflict-config"
        })))
        .mount(&server)
        .await;

    let error =
        integration_policy_ops::plan_delete(&transport_for(&server), &["integration-1".into()])
            .await
            .expect_err("a route conflict must not expose its response body");
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(error.http_status, Some(409));
    assert_eq!(
        error.message,
        "integration-policy delete planning integration read failed"
    );
    assert!(!error.message.contains("id-selection-conflict-secret"));
    assert!(!error.message.contains("id-selection-conflict-config"));
}

#[tokio::test]
async fn delete_sanitizes_a_conflicting_name_list_response() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/Named%20integration"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "message": "id-miss-secret"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "message": "name-list-conflict-secret",
            "config": "name-list-conflict-config"
        })))
        .mount(&server)
        .await;

    let error =
        integration_policy_ops::plan_delete(&transport_for(&server), &["Named integration".into()])
            .await
            .expect_err("a list conflict must not expose its response body");
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(error.http_status, Some(409));
    assert_eq!(
        error.message,
        "integration-policy delete planning integration list read failed"
    );
    assert!(!error.message.contains("name-list-conflict-secret"));
    assert!(!error.message.contains("name-list-conflict-config"));
}

#[tokio::test]
async fn delete_sanitizes_a_name_resolved_disappearance_response() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/Named%20integration"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "message": "id-miss-secret"
        })))
        .mount(&server)
        .await;
    let mut named = item("selected-id");
    named["name"] = json!("Named integration");
    mount_integration_pages(&server, vec![(1, vec![named], 1)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/selected-id"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "message": "name-disappearance-secret",
            "config": "name-disappearance-config"
        })))
        .mount(&server)
        .await;

    let error =
        integration_policy_ops::plan_delete(&transport_for(&server), &["Named integration".into()])
            .await
            .expect_err("a name-resolved disappearance must not expose its response body");
    assert_eq!(error.kind, ErrorKind::NotFound);
    assert_eq!(error.http_status, Some(404));
    assert_eq!(
        error.message,
        "integration-policy delete planning name read failed"
    );
    assert!(!error.message.contains("name-disappearance-secret"));
    assert!(!error.message.contains("name-disappearance-config"));
}

#[tokio::test]
async fn delete_refuses_unsafe_direct_state_before_parent_or_package_reads() {
    for (field, value, expected) in [
        ("enabled", json!(false), ErrorKind::Unsupported),
        ("is_managed", json!(true), ErrorKind::Unsupported),
        ("supports_agentless", json!(true), ErrorKind::Unsupported),
        (
            "supports_cloud_connector",
            json!(true),
            ErrorKind::Unsupported,
        ),
        (
            "output_id",
            json!("environment-output-id"),
            ErrorKind::Unsupported,
        ),
        (
            "cloud_connector_id",
            json!("environment-connector-id"),
            ErrorKind::Unsupported,
        ),
        (
            "cloud_connector_name",
            json!("environment-name"),
            ErrorKind::Unsupported,
        ),
        (
            "spaceIds",
            json!(["default", "other-space"]),
            ErrorKind::Unsupported,
        ),
        (
            "secret_references",
            json!([{"id": "secret-reference-id"}]),
            ErrorKind::Unsupported,
        ),
        ("is_managed", json!("true"), ErrorKind::Http),
        ("future_field", json!(true), ErrorKind::Unsupported),
    ] {
        let server = verified_server().await;
        let mut policy = live_item("integration-1");
        policy.insert(field.into(), value);
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/integration-1"))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": policy})))
            .mount(&server)
            .await;

        let error =
            integration_policy_ops::plan_delete(&transport_for(&server), &["integration-1".into()])
                .await
                .expect_err(field);
        assert_eq!(error.kind, expected, "{field}: {}", error.message);
        assert_eq!(
            request_count(&server, "/api/fleet/agent_policies/parent-1").await,
            0,
            "{field} must not read parents"
        );
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system").await,
            0,
            "{field} must not read packages"
        );
        assert!(
            server
                .received_requests()
                .await
                .expect("recorded requests")
                .iter()
                .all(|request| request.method != "DELETE"),
            "{field} must not delete"
        );
    }
}

#[tokio::test]
async fn delete_refuses_unsafe_parent_state_before_package_reads() {
    for (label, parent, expected) in [
        (
            "platform owned",
            {
                let mut parent = parent_item("parent-1", "default", 0, json!(["integration-1"]));
                parent["is_default"] = json!(true);
                parent
            },
            ErrorKind::Unsupported,
        ),
        (
            "protected",
            {
                let mut parent = parent_item("parent-1", "default", 0, json!(["integration-1"]));
                parent["is_protected"] = json!(true);
                parent
            },
            ErrorKind::Unsupported,
        ),
        (
            "other namespace",
            parent_item("parent-1", "other-space", 0, json!(["integration-1"])),
            ErrorKind::Unsupported,
        ),
        (
            "attachment inconsistency",
            parent_item("parent-1", "default", 0, json!([])),
            ErrorKind::Http,
        ),
    ] {
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
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": parent})))
            .mount(&server)
            .await;

        let error =
            integration_policy_ops::plan_delete(&transport_for(&server), &["integration-1".into()])
                .await
                .expect_err(label);
        assert_eq!(error.kind, expected, "{label}: {}", error.message);
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system").await,
            0,
            "{label} must stop before package reads"
        );
    }
}

#[tokio::test]
async fn delete_refuses_secret_references_and_plaintext_or_unknown_variables_without_leaks() {
    let reference_server = verified_server().await;
    let mut referenced = live_item("integration-1");
    referenced.insert(
        "secret_references".into(),
        json!([{"id": "secret-reference-id-must-not-leak"}]),
    );
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": referenced})))
        .mount(&reference_server)
        .await;
    let error = integration_policy_ops::plan_delete(
        &transport_for(&reference_server),
        &["integration-1".into()],
    )
    .await
    .expect_err("secret reference blocks deletion");
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert!(!error.message.contains("secret-reference-id-must-not-leak"));

    for (label, policy, metadata, expected_path, forbidden) in [
        (
            "declared package input and stream secrets",
            {
                let mut policy = live_item("integration-1");
                policy.insert(
                    "vars".into(),
                    json!({"package_secret": "package-secret-value"}),
                );
                policy.insert(
                    "inputs".into(),
                    json!({
                        "system-system": {
                            "vars": {"input_secret": "input-secret-value"},
                            "streams": {
                                "system.cpu": {"vars": {"stream_secret": "stream-secret-value"}}
                            }
                        }
                    }),
                );
                policy
            },
            secret_matrix_metadata(),
            "inputs.system-system.streams.system.cpu.vars.stream_secret",
            vec![
                "package-secret-value",
                "input-secret-value",
                "stream-secret-value",
            ],
        ),
        (
            "unknown configured variable",
            {
                let mut policy = live_item("integration-1");
                policy.insert("vars".into(), json!({"unknown": "unknown-variable-value"}));
                policy
            },
            safe_package_metadata(),
            "vars.unknown",
            vec!["unknown-variable-value"],
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
            metadata,
        )
        .await;
        let error =
            integration_policy_ops::plan_delete(&transport_for(&server), &["integration-1".into()])
                .await
                .expect_err(label);
        assert_eq!(
            error.kind,
            ErrorKind::Unsupported,
            "{label}: {}",
            error.message
        );
        assert!(
            error.message.contains(expected_path),
            "{label}: {}",
            error.message
        );
        for value in forbidden {
            assert!(!error.message.contains(value), "{label} leaked {value}");
        }
    }
}

#[tokio::test]
async fn delete_requires_an_exact_installed_package_dependency() {
    for (label, package, expected) in [
        (
            "absent package",
            json!({"name": "system", "status": "not_installed"}),
            ErrorKind::Conflict,
        ),
        (
            "different version",
            installed_package("1.0.0"),
            ErrorKind::Conflict,
        ),
        (
            "installed without version",
            json!({"name": "system", "status": "installed"}),
            ErrorKind::Http,
        ),
        (
            "not installed with version",
            json!({
                "name": "system", "status": "not_installed",
                "installationInfo": {"version": "2.0.0"}
            }),
            ErrorKind::Http,
        ),
        (
            "unknown status",
            json!({"name": "system", "status": "installing"}),
            ErrorKind::Http,
        ),
    ] {
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
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": parent_item("parent-1", "default", 0, json!(["integration-1"]))
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": package})))
            .mount(&server)
            .await;

        let error =
            integration_policy_ops::plan_delete(&transport_for(&server), &["integration-1".into()])
                .await
                .expect_err(label);
        assert_eq!(error.kind, expected, "{label}: {}", error.message);
        assert_eq!(
            request_count(&server, "/api/fleet/epm/packages/system/2.0.0").await,
            0,
            "{label} must not read metadata after an invalid dependency"
        );
    }
}

#[tokio::test]
async fn delete_aggregates_package_conflicts_in_stable_id_order() {
    let server = verified_server().await;
    for (id, parent_id) in [("a", "parent-a"), ("b", "parent-b")] {
        let mut policy = live_item(id);
        policy.insert("policy_ids".into(), json!([parent_id]));
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/package_policies/{id}")))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": policy})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/agent_policies/{parent_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": parent_item(parent_id, "default", 0, json!([id]))
            })))
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": {"name": "system", "status": "not_installed"}
        })))
        .expect(2)
        .mount(&server)
        .await;

    let error =
        integration_policy_ops::plan_delete(&transport_for(&server), &["b".into(), "a".into()])
            .await
            .expect_err("both absent package dependencies are conflicts");
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(
        error.message,
        "integration policy 'a' package system is not installed; integration policy 'b' package system is not installed"
    );
}

#[tokio::test]
async fn delete_plan_debug_does_not_expose_private_fleet_values() {
    let server = verified_server().await;
    let mut policy = live_item("integration-1");
    policy.insert(
        "description".into(),
        json!("integration-delete-raw-description-must-not-leak"),
    );
    let mut metadata = safe_package_metadata();
    metadata["metadata-private-value"] = json!("metadata-value-must-not-leak");
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

    let mut plan =
        integration_policy_ops::plan_delete(&transport_for(&server), &["integration-1".into()])
            .await
            .expect("safe plan");
    plan.preview.preview_action = "public-preview-value-must-not-leak".into();
    let debug = format!("{plan:?}");
    assert!(debug.contains("IntegrationPolicyDeletePlan"));
    for value in [
        "integration-delete-raw-description-must-not-leak",
        "metadata-value-must-not-leak",
        "public-preview-value-must-not-leak",
    ] {
        assert!(!debug.contains(value), "Debug leaked {value}");
    }
}

#[tokio::test]
async fn delete_apply_fails_a_disappeared_target_without_deleting() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": live_item("integration-1")})),
            ResponseTemplate::new(404).set_body_json(json!({
                "statusCode": 404, "message": "sensitive disappearance body"
            })),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 4, json!(["integration-1"]))
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .expect(1)
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let plan = integration_policy_ops::plan_delete(&transport, &["integration-1".into()])
        .await
        .expect("plan");
    let report = integration_policy_ops::apply_delete(&transport, &plan)
        .await
        .expect("disappearance is a row failure");
    assert!(report.deleted.is_empty());
    assert_eq!(
        report.failed,
        vec![json!({
            "id": "integration-1", "applied": false,
            "error": "integration policy disappeared since preview"
        })]
    );
    assert_eq!(report.affected_agents, 0);
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded requests")
            .iter()
            .all(|request| request.method != "DELETE")
    );
}

#[tokio::test]
async fn delete_apply_rechecks_integration_parent_and_package_snapshots() {
    for (label, integration_change, parent_change, package_change, expected_error) in [
        (
            "integration",
            true,
            None,
            None,
            "integration policy changed since preview",
        ),
        (
            "parent agent count",
            false,
            Some(parent_item(
                "parent-1",
                "default",
                2,
                json!(["integration-1"]),
            )),
            None,
            "integration policy parent changed since preview",
        ),
        (
            "parent attachment",
            false,
            Some(parent_item("parent-1", "default", 0, json!([]))),
            None,
            "integration policy parent changed since preview",
        ),
        (
            "package",
            false,
            None,
            Some(installed_package("1.0.0")),
            "integration policy package changed since preview",
        ),
    ] {
        let server = verified_server().await;
        let mut changed_policy = live_item("integration-1");
        changed_policy.insert("description".into(), json!("changed-but-safe"));
        let policy_responses = if integration_change {
            vec![
                ResponseTemplate::new(200)
                    .set_body_json(json!({"item": live_item("integration-1")})),
                ResponseTemplate::new(200).set_body_json(json!({"item": changed_policy})),
            ]
        } else {
            vec![
                ResponseTemplate::new(200)
                    .set_body_json(json!({"item": live_item("integration-1")})),
                ResponseTemplate::new(200)
                    .set_body_json(json!({"item": live_item("integration-1")})),
            ]
        };
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/integration-1"))
            .and(query_param("format", "simplified"))
            .respond_with(SequenceResponder::new(policy_responses))
            .mount(&server)
            .await;
        let parent = parent_item("parent-1", "default", 0, json!(["integration-1"]));
        let parent_responses = match parent_change {
            Some(changed) => vec![
                ResponseTemplate::new(200).set_body_json(json!({"item": parent})),
                ResponseTemplate::new(200).set_body_json(json!({"item": changed})),
            ],
            None => vec![
                ResponseTemplate::new(200).set_body_json(json!({"item": parent.clone()})),
                ResponseTemplate::new(200).set_body_json(json!({"item": parent})),
            ],
        };
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/parent-1"))
            .respond_with(SequenceResponder::new(parent_responses))
            .mount(&server)
            .await;
        let package_responses = match package_change {
            Some(changed) => vec![
                ResponseTemplate::new(200)
                    .set_body_json(json!({"item": installed_package("2.0.0")})),
                ResponseTemplate::new(200).set_body_json(json!({"item": changed})),
            ],
            None => vec![
                ResponseTemplate::new(200)
                    .set_body_json(json!({"item": installed_package("2.0.0")})),
            ],
        };
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(SequenceResponder::new(package_responses))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "item": safe_package_metadata()
            })))
            .mount(&server)
            .await;

        let transport = transport_for(&server);
        let plan = integration_policy_ops::plan_delete(&transport, &["integration-1".into()])
            .await
            .expect(label);
        let report = integration_policy_ops::apply_delete(&transport, &plan)
            .await
            .expect("snapshot changes are row failures");
        assert!(report.deleted.is_empty(), "{label}");
        assert_eq!(report.failed.len(), 1, "{label}");
        assert_eq!(report.failed[0]["applied"], false, "{label}");
        assert_eq!(report.failed[0]["error"], expected_error, "{label}");
        assert!(
            server
                .received_requests()
                .await
                .expect("recorded requests")
                .iter()
                .all(|request| request.method != "DELETE"),
            "{label} must not delete after a race"
        );
    }
}

#[tokio::test]
async fn delete_apply_rereads_metadata_for_each_target_and_continues_after_change() {
    let server = verified_server().await;
    let mut a = live_item("a");
    a.insert("policy_ids".into(), json!(["parent-a"]));
    let mut b = live_item("b");
    b.insert("policy_ids".into(), json!(["parent-b"]));
    for (id, policy, parent_id) in [("a", a, "parent-a"), ("b", b, "parent-b")] {
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/package_policies/{id}")))
            .and(query_param("format", "simplified"))
            .respond_with(SequenceResponder::new(vec![
                ResponseTemplate::new(200).set_body_json(json!({"item": policy.clone()})),
                ResponseTemplate::new(200).set_body_json(json!({"item": policy})),
            ]))
            .expect(2)
            .mount(&server)
            .await;
        let parent = parent_item(parent_id, "default", 1, json!([id]));
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/agent_policies/{parent_id}")))
            .respond_with(SequenceResponder::new(vec![
                ResponseTemplate::new(200).set_body_json(json!({"item": parent.clone()})),
                ResponseTemplate::new(200).set_body_json(json!({"item": parent})),
            ]))
            .expect(2)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .expect(4)
        .mount(&server)
        .await;
    let safe_metadata = safe_package_metadata();
    let mut changed_metadata = safe_metadata.clone();
    changed_metadata["registry-value-must-not-leak"] =
        json!("changed-metadata-value-must-not-leak");
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": safe_metadata.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": safe_metadata.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": changed_metadata})),
            ResponseTemplate::new(200).set_body_json(json!({"item": safe_metadata})),
        ]))
        .expect(4)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/fleet/package_policies/b"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "b"})))
        .expect(1)
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let plan = integration_policy_ops::plan_delete(&transport, &["b".into(), "a".into()])
        .await
        .expect("plan");
    let report = integration_policy_ops::apply_delete(&transport, &plan)
        .await
        .expect("metadata change is a row failure");
    assert_eq!(report.deleted, vec![json!({"id": "b"})]);
    assert_eq!(report.affected_agents, 1);
    assert_eq!(
        report.failed,
        vec![json!({
            "id": "a",
            "applied": false,
            "error": "integration policy package metadata changed since preview"
        })]
    );
    assert!(
        !report.failed[0]["error"]
            .as_str()
            .expect("error string")
            .contains("changed-metadata-value-must-not-leak")
    );
    assert_eq!(
        request_count(&server, "/api/fleet/epm/packages/system/2.0.0").await,
        4,
        "each target must read exact metadata during planning and immediately before deletion"
    );
    let delete_paths = server
        .received_requests()
        .await
        .expect("recorded requests")
        .into_iter()
        .filter(|request| request.method == "DELETE")
        .map(|request| request.url.path().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(delete_paths, ["/api/fleet/package_policies/b"]);
}

async fn assert_delete_apply_metadata_read_failure(
    label: &str,
    status: u16,
    body: Value,
    forbidden: &[&str],
    metadata_requests: u64,
) {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": live_item("integration-1")})),
            ResponseTemplate::new(200).set_body_json(json!({"item": live_item("integration-1")})),
        ]))
        .expect(2)
        .mount(&server)
        .await;
    let parent = parent_item("parent-1", "default", 4, json!(["integration-1"]));
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": parent.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": parent})),
        ]))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": safe_package_metadata()})),
            ResponseTemplate::new(status).set_body_json(body),
        ]))
        .expect(metadata_requests)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "integration-1"})))
        .expect(0)
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let plan = integration_policy_ops::plan_delete(&transport, &["integration-1".into()])
        .await
        .expect(label);
    let report = integration_policy_ops::apply_delete(&transport, &plan)
        .await
        .expect("metadata recheck failure is a row failure");
    assert!(report.deleted.is_empty(), "{label}");
    assert_eq!(report.affected_agents, 0, "{label}");
    assert_eq!(
        report.failed,
        vec![json!({
            "id": "integration-1",
            "applied": false,
            "error": "integration-policy delete apply package metadata read failed"
        })],
        "{label}"
    );
    for value in forbidden {
        assert!(
            !report.failed[0]["error"]
                .as_str()
                .expect("error string")
                .contains(value),
            "{label} leaked {value}"
        );
    }
    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/api/fleet/epm/packages/system/2.0.0")
            .count(),
        metadata_requests as usize,
        "{label} must re-read exact metadata"
    );
    assert!(
        requests.iter().all(|request| request.method != "DELETE"),
        "{label} must not delete"
    );
}

#[tokio::test]
async fn delete_apply_fails_malformed_metadata_reads_without_leaks() {
    assert_delete_apply_metadata_read_failure(
        "malformed metadata",
        200,
        json!({
            "item": {
                "name": "system",
                "version": "2.0.0",
                "vars": "malformed-metadata-value-must-not-leak",
                "policy_templates": []
            }
        }),
        &["malformed-metadata-value-must-not-leak"],
        2,
    )
    .await;
}

#[tokio::test]
async fn delete_apply_fails_metadata_route_reads_without_leaks() {
    assert_delete_apply_metadata_read_failure(
        "metadata route failure",
        500,
        json!({
            "message": "metadata-route-value-must-not-leak",
            "config": "metadata-route-config-must-not-leak"
        }),
        &[
            "metadata-route-value-must-not-leak",
            "metadata-route-config-must-not-leak",
        ],
        4,
    )
    .await;
}

#[tokio::test]
async fn delete_applies_exact_single_id_routes_advances_shared_parents_and_unions_agents() {
    let server = verified_server().await;
    let mut first = live_item("a");
    first.insert("policy_ids".into(), json!(["parent-shared"]));
    let mut second = live_item("b");
    second.insert("policy_ids".into(), json!(["parent-b", "parent-shared"]));
    for (id, policy) in [("a", first), ("b", second)] {
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/package_policies/{id}")))
            .and(query_param("format", "simplified"))
            .respond_with(SequenceResponder::new(vec![
                ResponseTemplate::new(200).set_body_json(json!({"item": policy.clone()})),
                ResponseTemplate::new(200).set_body_json(json!({"item": policy})),
            ]))
            .mount(&server)
            .await;
    }
    let shared_before = parent_item("parent-shared", "default", 5, json!(["a", "b"]));
    let shared_after_a = parent_item("parent-shared", "default", 5, json!(["b"]));
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-shared"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": shared_before.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": shared_before.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": shared_before})),
            ResponseTemplate::new(200).set_body_json(json!({"item": shared_after_a})),
        ]))
        .mount(&server)
        .await;
    let parent_b = parent_item("parent-b", "default", 3, json!(["b"]));
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-b"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": parent_b.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": parent_b})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .expect(4)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .expect(4)
        .mount(&server)
        .await;
    for id in ["a", "b"] {
        Mock::given(method("DELETE"))
            .and(path(format!("/api/fleet/package_policies/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": id})))
            .expect(1)
            .mount(&server)
            .await;
    }

    let transport = transport_for(&server);
    let plan = integration_policy_ops::plan_delete(&transport, &["b".into(), "a".into()])
        .await
        .expect("plan");
    let report = integration_policy_ops::apply_delete(&transport, &plan)
        .await
        .expect("apply");
    assert_eq!(report.deleted, vec![json!({"id": "a"}), json!({"id": "b"})]);
    assert!(report.failed.is_empty());
    assert_eq!(report.affected_agents, 8);
    let delete_requests = server
        .received_requests()
        .await
        .expect("recorded requests")
        .into_iter()
        .filter(|request| request.method == "DELETE")
        .collect::<Vec<_>>();
    assert_eq!(delete_requests.len(), 2);
    for request in delete_requests {
        assert!(request.url.query().is_none(), "delete must not send force");
        assert!(request.body.is_empty(), "delete must not send a body");
    }
}

#[tokio::test]
async fn delete_reports_applied_true_for_a_wrong_success_id_without_echoing_it() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": live_item("integration-1")})),
            ResponseTemplate::new(200).set_body_json(json!({"item": live_item("integration-1")})),
        ]))
        .mount(&server)
        .await;
    let parent = parent_item("parent-1", "default", 7, json!(["integration-1"]));
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": parent.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": parent})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "wrong-id-must-not-leak"})),
        )
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let plan = integration_policy_ops::plan_delete(&transport, &["integration-1".into()])
        .await
        .expect("plan");
    let report = integration_policy_ops::apply_delete(&transport, &plan)
        .await
        .expect("wrong echo is a row failure");
    assert!(report.deleted.is_empty());
    assert_eq!(report.affected_agents, 0);
    assert_eq!(
        report.failed,
        vec![json!({
            "id": "integration-1", "applied": true,
            "error": "integration-policy delete response did not confirm the requested id"
        })]
    );
    assert!(
        !report.failed[0]["error"]
            .as_str()
            .expect("error string")
            .contains("wrong-id-must-not-leak")
    );
}

#[tokio::test]
async fn delete_continues_after_an_independent_target_fails() {
    let server = verified_server().await;
    let mut a = live_item("a");
    a.insert("policy_ids".into(), json!(["parent-a"]));
    let mut b = live_item("b");
    b.insert("policy_ids".into(), json!(["parent-b"]));
    for (id, planned, reapplied) in [("a", a, None), ("b", b.clone(), Some(b))] {
        let responses = match reapplied {
            Some(reapplied) => vec![
                ResponseTemplate::new(200).set_body_json(json!({"item": planned})),
                ResponseTemplate::new(200).set_body_json(json!({"item": reapplied})),
            ],
            None => vec![
                ResponseTemplate::new(200).set_body_json(json!({"item": planned})),
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404, "message": "body-must-not-leak"
                })),
            ],
        };
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/package_policies/{id}")))
            .and(query_param("format", "simplified"))
            .respond_with(SequenceResponder::new(responses))
            .mount(&server)
            .await;
    }
    let parent_a = parent_item("parent-a", "default", 2, json!(["a"]));
    let parent_b = parent_item("parent-b", "default", 3, json!(["b"]));
    for (id, parent, expected) in [("parent-a", parent_a, 1), ("parent-b", parent_b, 2)] {
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/agent_policies/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": parent})))
            .expect(expected)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .expect(3)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .expect(3)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/fleet/package_policies/b"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "b"})))
        .expect(1)
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let plan = integration_policy_ops::plan_delete(&transport, &["b".into(), "a".into()])
        .await
        .expect("plan");
    let report = integration_policy_ops::apply_delete(&transport, &plan)
        .await
        .expect("independent rows continue");
    assert_eq!(report.deleted, vec![json!({"id": "b"})]);
    assert_eq!(report.affected_agents, 3);
    assert_eq!(
        report.failed,
        vec![json!({
            "id": "a", "applied": false,
            "error": "integration policy disappeared since preview"
        })]
    );
}

#[tokio::test]
async fn delete_sanitizes_planning_and_route_error_bodies() {
    for (label, body, forbidden) in [
        (
            "string",
            json!("planning-secret-token"),
            vec!["planning-secret-token"],
        ),
        (
            "object",
            json!({"message": "planning-message-token", "config": "planning-config-token"}),
            vec!["planning-message-token", "planning-config-token"],
        ),
    ] {
        let server = verified_server().await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies/integration-1"))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(500).set_body_json(body))
            .mount(&server)
            .await;
        let error =
            integration_policy_ops::plan_delete(&transport_for(&server), &["integration-1".into()])
                .await
                .expect_err(label);
        assert_eq!(error.kind, ErrorKind::Http, "{label}");
        assert_eq!(error.http_status, Some(500), "{label}");
        assert_eq!(
            error.message, "integration-policy delete planning integration read failed",
            "{label}"
        );
        for value in forbidden {
            assert!(!error.message.contains(value), "{label} leaked {value}");
        }
    }

    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .and(query_param("format", "simplified"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item": live_item("integration-1")})),
        )
        .expect(2)
        .mount(&server)
        .await;
    let parent = parent_item("parent-1", "default", 0, json!(["integration-1"]));
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/parent-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": parent})))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/fleet/package_policies/integration-1"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "message": "route-secret-token", "config": "route-config-token"
        })))
        .mount(&server)
        .await;

    let transport = transport_for(&server);
    let plan = integration_policy_ops::plan_delete(&transport, &["integration-1".into()])
        .await
        .expect("plan");
    let report = integration_policy_ops::apply_delete(&transport, &plan)
        .await
        .expect("route failure is a row failure");
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0]["applied"], false);
    assert_eq!(
        report.failed[0]["error"],
        "integration-policy delete request failed"
    );
    let error = report.failed[0]["error"].as_str().expect("error string");
    assert!(!error.contains("route-secret-token"));
    assert!(!error.contains("route-config-token"));
}

#[tokio::test]
async fn delete_binds_host_and_space_before_any_apply_request() {
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
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": parent_item("parent-1", "default", 0, json!(["integration-1"]))
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": installed_package("2.0.0")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/system/2.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item": safe_package_metadata()
        })))
        .mount(&server)
        .await;
    let plan =
        integration_policy_ops::plan_delete(&transport_for(&server), &["integration-1".into()])
            .await
            .expect("plan");
    let requests_before = server
        .received_requests()
        .await
        .expect("recorded requests")
        .len();
    let error = integration_policy_ops::apply_delete(&transport_for_space(&server, "other"), &plan)
        .await
        .expect_err("space changed");
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(
        error.message,
        "integration delete target changed since preview"
    );
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("recorded requests")
            .len(),
        requests_before,
        "target binding must reject before a recheck request"
    );

    let other = verified_server().await;
    let error = integration_policy_ops::apply_delete(&transport_for(&other), &plan)
        .await
        .expect_err("host changed");
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(
        error.message,
        "integration delete target changed since preview"
    );
    assert!(
        other
            .received_requests()
            .await
            .expect("recorded requests")
            .is_empty(),
        "host binding must reject before a feature probe or recheck"
    );
}
