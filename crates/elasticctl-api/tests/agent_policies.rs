use elasticctl_api::content_codec::{self, ContentFormat};
use elasticctl_api::fleet::agent_policies::{
    self, AgentPolicySpec, DEFAULT_INACTIVITY_TIMEOUT, PackageStatus,
};
use elasticctl_core::{ErrorKind, Profile, Transport};
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

fn spec(id: &str) -> AgentPolicySpec {
    AgentPolicySpec::try_from(json!({
        "id": id,
        "name": format!("Policy {id}"),
        "namespace": "default",
        "description": "sample",
        "inactivity_timeout": 1209600,
        "monitoring_enabled": ["logs"],
        "agent_features": [],
        "global_data_tags": [{"name": "environment", "value": "production"}]
    }))
    .expect("spec")
}

fn item(id: &str) -> Value {
    json!({
        "id": id,
        "name": format!("Policy {id}"),
        "namespace": "default",
        "description": "sample",
        "inactivity_timeout": 1209600,
        "monitoring_enabled": ["logs"],
        "agent_features": [],
        "global_data_tags": [{"name": "environment", "value": "production"}],
        "is_managed": false,
        "is_protected": false,
        "has_fleet_server": null,
        "status": "active",
        "revision": 3,
        "schema_version": "1.1.1",
        "version": "WzEsMV0=",
        "updated_at": "2026-09-03T00:00:00.000Z",
        "updated_by": "system",
        "agents": 0,
        "unprivileged_agents": 0,
        "package_policies": [],
        "space_ids": ["default"]
    })
}

#[test]
fn json_and_yaml_carry_the_same_agent_policy_specs() {
    let specs = vec![spec("b"), spec("a")];
    for format in [ContentFormat::Json, ContentFormat::Yaml] {
        let body = content_codec::encode_sequence(&specs, format).expect("encode");
        let decoded: Vec<AgentPolicySpec> =
            content_codec::decode_sequence(&body, format, "agent policy").expect("decode");
        assert_eq!(decoded, specs);
    }
}

#[test]
fn sparse_specs_fill_the_default_table_and_serialize_it() {
    let sparse = AgentPolicySpec::try_from(json!({
        "id": "ap", "name": "Sparse", "namespace": "default"
    }))
    .expect("sparse spec");
    assert_eq!(sparse.inactivity_timeout, DEFAULT_INACTIVITY_TIMEOUT);
    assert!(sparse.monitoring_enabled.is_empty());
    let value = serde_json::to_value(&sparse).expect("value");
    assert_eq!(value["inactivity_timeout"], 1209600);
    assert_eq!(value["monitoring_enabled"], json!([]));
    assert_eq!(value["agent_features"], json!([]));
    assert_eq!(value["global_data_tags"], json!([]));
    assert!(value.get("description").is_none());
    assert!(value.get("unenroll_timeout").is_none());
}

#[test]
fn specs_reject_unknown_fields_empty_identity_and_bad_nested_values() {
    for (value, needle) in [
        (
            json!({"id": "ap", "name": "x", "namespace": "default", "nmae": "typo"}),
            "unknown field",
        ),
        (
            json!({"id": "", "name": "x", "namespace": "default"}),
            "id must not be empty",
        ),
        (
            json!({"id": "ap", "name": " ", "namespace": "default"}),
            "name must not be empty",
        ),
        (
            json!({"id": "ap", "name": "x", "namespace": ""}),
            "namespace must not be empty",
        ),
        (
            json!({"id": "ap", "name": "x", "namespace": "default", "monitoring_enabled": ["cpu"]}),
            "monitoring_enabled",
        ),
        (
            json!({"id": "ap", "name": "x", "namespace": "default", "global_data_tags": ["bad"]}),
            "global_data_tags",
        ),
        (
            json!({"id": "ap", "name": "x", "namespace": "default", "agent_features": [{"name": "feature"}]}),
            "agent_features[0].enabled",
        ),
        (
            json!({"id": "ap", "name": "x", "namespace": "default", "agent_features": [{"name": "feature", "enabled": "yes"}]}),
            "agent_features[0].enabled",
        ),
        (
            json!({"id": "ap", "name": "x", "namespace": "default", "global_data_tags": [{"name": "bad tag", "value": "x"}]}),
            "must not contain whitespace",
        ),
        (
            json!({"id": "ap", "name": "x", "namespace": "default", "global_data_tags": [{"name": "env", "value": true}]}),
            "global_data_tags[0].value",
        ),
        (
            json!({"id": "ap", "name": "x", "namespace": "default", "global_data_tags": [{"name": "env", "value": "a"}, {"name": "env", "value": "b"}]}),
            "duplicate global_data_tags name 'env'",
        ),
        (
            json!({"id": "ap", "name": "x", "namespace": "default", "is_managed": true}),
            "unknown field",
        ),
    ] {
        let error = AgentPolicySpec::try_from(value).expect_err("must reject");
        assert!(error.message.contains(needle), "{}", error.message);
    }
}

#[tokio::test]
async fn list_page_pins_the_measured_query_and_strict_envelope() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies"))
        .and(query_param("page", "2"))
        .and(query_param("perPage", "1000"))
        .and(query_param("sortField", "created_at"))
        .and(query_param("sortOrder", "asc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [item("ap-1")], "total": 1, "page": 2, "perPage": 1000
        })))
        .mount(&server)
        .await;
    let transport = transport_for(&server);
    let page = agent_policies::list_page(&transport, 2)
        .await
        .expect("page");
    assert_eq!((page.total, page.page, page.per_page), (1, 2, 1000));
    assert_eq!(page.items[0]["id"], "ap-1");
}

#[tokio::test]
async fn list_page_rejects_an_envelope_with_extra_or_missing_keys() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [], "total": 0, "page": 1
        })))
        .mount(&server)
        .await;
    let error = agent_policies::list_page(&transport_for(&server), 1)
        .await
        .expect_err("missing perPage");
    assert_eq!(error.kind, ErrorKind::Http);
}

#[tokio::test]
async fn create_sends_sys_monitoring_false_with_the_explicit_id() {
    let server = verified_server().await;
    let expected = serde_json::to_value(spec("ap-1")).unwrap();
    Mock::given(method("POST"))
        .and(path("/api/fleet/agent_policies"))
        .and(query_param("sys_monitoring", "false"))
        .and(body_json(expected))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("ap-1")})))
        .mount(&server)
        .await;
    let created = agent_policies::create(&transport_for(&server), &spec("ap-1"))
        .await
        .expect("create");
    assert_eq!(created.item["id"], "ap-1");
}

#[tokio::test]
async fn update_puts_the_supplied_body_and_decodes_the_item_envelope() {
    let server = verified_server().await;
    let body = json!({"name": "Policy ap-1", "namespace": "default", "overrides": null});
    Mock::given(method("PUT"))
        .and(path("/api/fleet/agent_policies/ap-1"))
        .and(body_json(body.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("ap-1")})))
        .mount(&server)
        .await;
    agent_policies::update(&transport_for(&server), "ap-1", &body)
        .await
        .expect("update");
}

#[tokio::test]
async fn delete_posts_the_id_without_force_and_requires_the_echoed_id() {
    let server = verified_server().await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/agent_policies/delete"))
        .and(body_json(json!({"agentPolicyId": "ap-1"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "ap-1", "name": "Policy ap-1"})),
        )
        .mount(&server)
        .await;
    agent_policies::delete(&transport_for(&server), "ap-1")
        .await
        .expect("delete");

    let other = verified_server().await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/agent_policies/delete"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "other", "name": "Other"})),
        )
        .mount(&other)
        .await;
    let error = agent_policies::delete(&transport_for(&other), "ap-1")
        .await
        .expect_err("wrong id");
    assert_eq!(error.kind, ErrorKind::Http);
}

#[tokio::test]
async fn package_status_reads_only_the_installation_facts() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/elastic_agent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "elastic_agent", "version": "2.5.0", "status": "not_installed",
            "latestVersion": "2.5.0", "title": "Elastic Agent", "assets": {}, "policy_templates": []
        }})))
        .mount(&server)
        .await;
    let status = agent_policies::package_status(&transport_for(&server), "elastic_agent")
        .await
        .expect("status");
    assert_eq!(
        status,
        PackageStatus {
            name: "elastic_agent".into(),
            status: "not_installed".into(),
            installed_version: None,
        }
    );
}

#[tokio::test]
async fn package_status_rejects_a_wrong_name_or_installed_state_without_a_version() {
    for item in [
        json!({"name": "other", "status": "not_installed"}),
        json!({"name": "elastic_agent", "status": "installed"}),
    ] {
        let server = verified_server().await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/elastic_agent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item})))
            .mount(&server)
            .await;
        let error = agent_policies::package_status(&transport_for(&server), "elastic_agent")
            .await
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Http);
    }
}

#[tokio::test]
async fn every_route_requires_the_fleet_feature_floor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.4.0", "build_flavor": "traditional"}
        })))
        .mount(&server)
        .await;
    let error = agent_policies::get(&transport_for(&server), "ap-1")
        .await
        .expect_err("below floor");
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert!(
        error.message.contains("fleet policies"),
        "{}",
        error.message
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
