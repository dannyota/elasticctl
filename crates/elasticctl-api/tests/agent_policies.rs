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

use elasticctl_api::fleet::agent_policy_ops::{self, AgentPolicyFilter};

fn platform_item(id: &str) -> Value {
    let mut value = item(id);
    value["is_managed"] = json!(true);
    value["is_preconfigured"] = json!(true);
    value["data_output_id"] = json!("es-default");
    value
}

async fn mount_pages(server: &MockServer, pages: Vec<(u64, Vec<Value>, u64)>) {
    for (page, items, total) in pages {
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies"))
            .and(query_param("page", page.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": items, "total": total, "page": page, "perPage": 1000
            })))
            .mount(server)
            .await;
    }
}

#[tokio::test]
async fn collect_walks_every_page_and_sorts_by_id() {
    let server = verified_server().await;
    let first: Vec<Value> = (0..1000).map(|n| item(&format!("ap-{n:04}"))).collect();
    mount_pages(
        &server,
        vec![(1, first, 1001), (2, vec![item("ap-0000-last")], 1001)],
    )
    .await;
    let items = agent_policy_ops::collect(&transport_for(&server))
        .await
        .expect("collect");
    assert_eq!(items.len(), 1001);
    assert_eq!(items[0]["id"], "ap-0000");
    assert_eq!(items[1]["id"], "ap-0000-last");
}

#[tokio::test]
async fn collect_fails_closed_on_paging_contradictions() {
    let duplicate = verified_server().await;
    mount_pages(&duplicate, vec![(1, vec![item("ap-1"), item("ap-1")], 2)]).await;
    let error = agent_policy_ops::collect(&transport_for(&duplicate))
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Http);
    assert!(
        error.message.contains("duplicate agent policy id 'ap-1'"),
        "{}",
        error.message
    );

    let short = verified_server().await;
    mount_pages(&short, vec![(1, vec![item("ap-1")], 5)]).await;
    let error = agent_policy_ops::collect(&transport_for(&short))
        .await
        .unwrap_err();
    assert!(
        error.message.contains("page was short before total"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn list_filters_locally_sorts_and_truncates() {
    let server = verified_server().await;
    mount_pages(
        &server,
        vec![(1, vec![item("zeta"), item("alpha"), item("beta")], 3)],
    )
    .await;
    let transport = transport_for(&server);
    let list = agent_policy_ops::list_op(
        &transport,
        &AgentPolicyFilter {
            search: Some("POLICY".into()),
            limit: Some(2),
        },
    )
    .await
    .expect("list");
    assert_eq!(list.total, 3);
    assert!(list.truncated);
    let ids: Vec<_> = list
        .agent_policies
        .iter()
        .map(|row| row.id.as_str())
        .collect();
    assert_eq!(ids, ["alpha", "beta"]);
}

#[tokio::test]
async fn resolve_prefers_the_id_route_then_exact_names() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/ap-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("ap-1")})))
        .mount(&server)
        .await;
    // Names without spaces: wiremock's `path` matcher compares the encoded path.
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/policy-two"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/Twin"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
        )
        .mount(&server)
        .await;
    let mut two = item("ap-2");
    two["name"] = json!("policy-two");
    let mut twin_a = item("twin-a");
    twin_a["name"] = json!("Twin");
    let mut twin_b = item("twin-b");
    twin_b["name"] = json!("Twin");
    mount_pages(
        &server,
        vec![(1, vec![item("ap-1"), two, twin_a, twin_b], 4)],
    )
    .await;
    let transport = transport_for(&server);

    assert_eq!(
        agent_policy_ops::resolve(&transport, "ap-1")
            .await
            .unwrap()
            .id,
        "ap-1"
    );
    assert_eq!(
        agent_policy_ops::resolve(&transport, "policy-two")
            .await
            .unwrap()
            .id,
        "ap-2"
    );
    let ambiguous = agent_policy_ops::resolve(&transport, "Twin")
        .await
        .unwrap_err();
    assert_eq!(ambiguous.kind, ErrorKind::Conflict);
    assert!(
        ambiguous.message.contains("twin-a, twin-b"),
        "{}",
        ambiguous.message
    );
}

#[tokio::test]
async fn get_returns_sanitized_detail_without_raw_audit_or_integration_data() {
    let server = verified_server().await;
    let mut live = platform_item("hosted");
    live["agents"] = json!(2);
    live["package_policies"] = json!([{"id": "system-1", "inputs": {"secret": "must-not-leak"}}]);
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/hosted"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": live})))
        .mount(&server)
        .await;
    let detail = agent_policy_ops::get_op(&transport_for(&server), "hosted")
        .await
        .unwrap();
    let value = serde_json::to_value(detail).unwrap();
    assert_eq!(value["agents"], 2);
    assert_eq!(value["attached_integrations"], json!(["system-1"]));
    assert_eq!(
        value["blocked_by"],
        json!(["data_output_id", "is_managed", "is_preconfigured"])
    );
    assert!(value.get("updated_by").is_none());
    assert!(!value.to_string().contains("must-not-leak"));
}

#[tokio::test]
async fn get_classifies_missing_agent_and_attachment_facts() {
    // Kibana populates `agents` only for a caller with Fleet agents read, so
    // its absence is a privilege gap; a missing `package_policies` is malformed.
    for (missing, kind) in [
        ("agents", ErrorKind::Permission),
        ("package_policies", ErrorKind::Http),
    ] {
        let server = verified_server().await;
        let mut live = item("broken");
        live.as_object_mut().unwrap().remove(missing);
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies/broken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": live})))
            .mount(&server)
            .await;
        let error = agent_policy_ops::get_op(&transport_for(&server), "broken")
            .await
            .unwrap_err();
        assert_eq!(error.kind, kind, "{missing}: {}", error.message);
        if missing == "agents" {
            assert!(
                error.message.contains("Fleet agents read"),
                "{}",
                error.message
            );
        }
    }
}

#[test]
fn normalize_drops_server_fields_fills_defaults_and_equates_null_with_absent() {
    let mut live = item("ap-1");
    live.as_object_mut().unwrap().remove("inactivity_timeout");
    live["overrides"] = Value::Null;
    live["is_verifier"] = Value::Null;
    let spec =
        agent_policy_ops::normalize(live.as_object().unwrap(), "default").expect("normalize");
    assert_eq!(spec.inactivity_timeout, 1209600);
    assert_eq!(spec.overrides, None);
    let value = serde_json::to_value(&spec).unwrap();
    for gone in [
        "status",
        "revision",
        "version",
        "updated_at",
        "agents",
        "package_policies",
        "space_ids",
        "is_managed",
    ] {
        assert!(value.get(gone).is_none(), "{gone} must be normalized away");
    }
}

#[test]
fn normalize_refuses_platform_environment_and_cross_space_state() {
    let error = agent_policy_ops::normalize(platform_item("ap-1").as_object().unwrap(), "default")
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(
        error.message,
        "agent policy 'ap-1' is not portable: data_output_id, is_managed, is_preconfigured"
    );

    let mut shared = item("ap-2");
    shared["space_ids"] = json!(["default", "soc"]);
    let error = agent_policy_ops::normalize(shared.as_object().unwrap(), "default").unwrap_err();
    assert!(error.message.ends_with("space_ids"), "{}", error.message);

    let mut upgrade = item("ap-3");
    upgrade["required_versions"] = json!([]);
    let error = agent_policy_ops::normalize(upgrade.as_object().unwrap(), "default").unwrap_err();
    assert!(
        error.message.ends_with("required_versions"),
        "{}",
        error.message
    );

    let mut agentless = item("ap-4");
    agentless["agentless"] = json!({"cloudShellUrl": "https://example.invalid"});
    let error = agent_policy_ops::normalize(agentless.as_object().unwrap(), "default").unwrap_err();
    assert!(error.message.ends_with("agentless"), "{}", error.message);
}

#[test]
fn normalize_rejects_malformed_server_owned_fields_as_http() {
    for (field, value) in [
        ("is_managed", json!("false")),
        ("agentless", json!(false)),
        ("required_versions", json!({})),
        ("data_output_id", json!(7)),
        ("space_ids", json!(["default", 7])),
    ] {
        let mut live = item("bad");
        live[field] = value;
        let error = agent_policy_ops::normalize(live.as_object().unwrap(), "default").unwrap_err();
        assert_eq!(error.kind, ErrorKind::Http, "{field}: {}", error.message);
    }
}

#[test]
fn validate_rejects_duplicate_ids_and_names_then_sorts() {
    let dir = tempfile::tempdir().unwrap();
    let dup = dir.path().join("dup.json");
    std::fs::write(&dup, r#"[{"id":"b","name":"B","namespace":"default"},{"id":"b","name":"B2","namespace":"default"}]"#).unwrap();
    let error = agent_policy_ops::validate(&dup).unwrap_err();
    assert!(
        error.message.contains("duplicate agent policy ids: b"),
        "{}",
        error.message
    );

    let duplicate_name = dir.path().join("duplicate-name.json");
    std::fs::write(&duplicate_name, r#"[{"id":"a","name":"Same","namespace":"default"},{"id":"b","name":"Same","namespace":"default"}]"#).unwrap();
    let error = agent_policy_ops::validate(&duplicate_name).unwrap_err();
    assert!(
        error.message.contains("duplicate agent policy names: Same"),
        "{}",
        error.message
    );

    let ok = dir.path().join("ok.yaml");
    std::fs::write(
        &ok,
        "- id: b\n  name: B\n  namespace: default\n- id: a\n  name: A\n  namespace: default\n",
    )
    .unwrap();
    let specs = agent_policy_ops::validate(&ok).unwrap();
    assert_eq!(
        specs.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
        ["a", "b"]
    );
}

#[tokio::test]
async fn export_requires_a_selection_and_refuses_platform_policies() {
    let server = verified_server().await;
    let transport = transport_for(&server);
    let bare = agent_policy_ops::export(&transport, &[], false, ContentFormat::Json)
        .await
        .unwrap_err();
    assert_eq!(bare.kind, ErrorKind::Error);
    assert!(
        bare.message.contains("selectors or --all-custom"),
        "{}",
        bare.message
    );
    assert!(server.received_requests().await.unwrap().is_empty());

    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/platform"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item": platform_item("platform")})),
        )
        .mount(&server)
        .await;
    let explicit =
        agent_policy_ops::export(&transport, &["platform".into()], false, ContentFormat::Json)
            .await
            .unwrap_err();
    assert_eq!(explicit.kind, ErrorKind::Unsupported);
}

#[tokio::test]
async fn all_custom_export_skips_platform_policies_and_sorts_by_id() {
    let server = verified_server().await;
    mount_pages(
        &server,
        vec![(
            1,
            vec![item("zeta"), platform_item("platform"), item("alpha")],
            3,
        )],
    )
    .await;
    for id in ["zeta", "alpha"] {
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/agent_policies/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item(id)})))
            .mount(&server)
            .await;
    }
    let outcome = agent_policy_ops::export(&transport_for(&server), &[], true, ContentFormat::Json)
        .await
        .expect("export");
    assert_eq!(outcome.exported, 2);
    let specs: Vec<AgentPolicySpec> = serde_json::from_str(&outcome.body).unwrap();
    assert_eq!(
        specs.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
        ["alpha", "zeta"]
    );
    assert_eq!(specs[0].inactivity_timeout, 1209600);
}
