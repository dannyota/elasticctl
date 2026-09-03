use elasticctl_api::content_codec::{self, ContentFormat};
use elasticctl_api::fleet::integration_policies::{self, IntegrationPolicySpec};
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
