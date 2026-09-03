use elasticctl_api::AgentPolicyImportPlan;
use elasticctl_api::content_codec::{self, ContentFormat};
use elasticctl_api::fleet::agent_policies::{
    self, AgentPolicySpec, DEFAULT_INACTIVITY_TIMEOUT, PackageStatus,
};
use elasticctl_core::{ErrorKind, Profile, Transport};
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
fn normalize_refuses_an_unknown_live_top_level_field() {
    let mut live = item("x");
    live["future_field"] = json!(1);
    let error = agent_policy_ops::normalize(live.as_object().unwrap(), "default").unwrap_err();
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(
        error.message,
        "agent policy 'x' carries unknown field 'future_field'"
    );
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

#[test]
fn replace_body_strips_id_nulls_clearable_fields_and_refuses_other_removals() {
    let mut current = spec("ap-1");
    current.overrides = Some(serde_json::Map::new());
    current.keep_monitoring_alive = Some(true);
    current.unenroll_timeout = Some(3600);
    let mut desired = spec("ap-1");
    desired.unenroll_timeout = Some(3600);
    let body = agent_policy_ops::build_replace_body(&current, &desired).expect("body");
    assert!(body.get("id").is_none());
    assert_eq!(body["overrides"], Value::Null);
    assert_eq!(body["keep_monitoring_alive"], Value::Null);
    assert_eq!(body["name"], "Policy ap-1");

    let mut dropped = spec("ap-1");
    dropped.unenroll_timeout = None;
    let error = agent_policy_ops::build_replace_body(&current, &dropped).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(
        error.message,
        "removing unenroll_timeout is not supported by the agent-policy update API"
    );

    let mut nested_current = spec("ap-1");
    nested_current.advanced_settings = Some(
        json!({"agent_limits_go_max_procs": 2, "agent_logging_level": "info"})
            .as_object()
            .unwrap()
            .clone(),
    );
    let mut nested_desired = spec("ap-1");
    nested_desired.advanced_settings = Some(
        json!({"agent_limits_go_max_procs": 4})
            .as_object()
            .unwrap()
            .clone(),
    );
    // Kibana maps these objects `flattened` and replaces them whole, so a
    // shrunken nested object is sent as-is rather than refused.
    let body =
        agent_policy_ops::build_replace_body(&nested_current, &nested_desired).expect("body");
    assert_eq!(
        body["advanced_settings"],
        json!({"agent_limits_go_max_procs": 4})
    );
}

fn write_artifact(
    dir: &std::path::Path,
    name: &str,
    specs: &[AgentPolicySpec],
) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_string(specs).unwrap()).unwrap();
    path
}

#[tokio::test]
async fn plan_import_classifies_conflicts_skips_and_replacements() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/existing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("existing")})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/fresh"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/elastic_agent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "elastic_agent", "version": "2.5.0", "status": "not_installed"
        }})))
        .mount(&server)
        .await;
    mount_pages(&server, vec![(1, vec![item("existing")], 1)]).await;
    let transport = transport_for(&server);
    let dir = tempfile::tempdir().unwrap();
    let mut changed = spec("existing");
    changed.description = Some("changed".into());
    let path = write_artifact(
        dir.path(),
        "policies.json",
        &[changed.clone(), spec("fresh")],
    );

    let refused = agent_policy_ops::plan_import(&transport, &path, false, false)
        .await
        .unwrap_err();
    assert_eq!(refused.kind, ErrorKind::Conflict);
    assert_eq!(refused.message, "agent policies already exist: existing");

    let skipped = agent_policy_ops::plan_import(&transport, &path, false, true)
        .await
        .unwrap();
    assert_eq!(
        skipped.skipped,
        vec![json!({"id": "existing", "reason": "exists"})]
    );
    assert_eq!(skipped.preview.targets, ["fresh"]);
    assert_eq!(skipped.total, 2);

    let overwrite = agent_policy_ops::plan_import(&transport, &path, true, false)
        .await
        .unwrap();
    assert_eq!(
        overwrite.preview.preview_details,
        [
            "existing  replace  Policy existing  agents 0",
            "fresh  create  Policy fresh",
            "package install  elastic_agent@server-selected",
        ]
    );
    assert_eq!(
        overwrite.package_installs,
        ["elastic_agent@server-selected"]
    );
}

#[tokio::test]
async fn plan_import_does_not_normalize_an_existing_policy_it_will_skip_or_refuse_as_conflict() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/existing"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"item": platform_item("existing")})),
        )
        .mount(&server)
        .await;
    mount_pages(&server, vec![(1, vec![platform_item("existing")], 1)]).await;
    let transport = transport_for(&server);
    let dir = tempfile::tempdir().unwrap();
    let path = write_artifact(dir.path(), "policies.json", &[spec("existing")]);

    let skipped = agent_policy_ops::plan_import(&transport, &path, false, true)
        .await
        .expect("skip-existing must not normalize the existing platform-owned policy");
    assert_eq!(
        skipped.skipped,
        vec![json!({"id": "existing", "reason": "exists"})]
    );
    assert_eq!(skipped.total, 1);

    let conflict = agent_policy_ops::plan_import(&transport, &path, false, false)
        .await
        .expect_err("default mode must not normalize the existing platform-owned policy");
    assert_eq!(conflict.kind, ErrorKind::Conflict);
    assert_eq!(conflict.message, "agent policies already exist: existing");

    let overwrite = agent_policy_ops::plan_import(&transport, &path, true, false)
        .await
        .expect_err("overwrite still cannot replace a platform-owned policy");
    assert_eq!(overwrite.kind, ErrorKind::Unsupported);
}

#[tokio::test]
async fn plan_import_refuses_a_name_owned_by_another_id() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/new-id"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
        )
        .mount(&server)
        .await;
    let mut taken = item("other-id");
    taken["name"] = json!("Policy new-id");
    mount_pages(&server, vec![(1, vec![taken], 1)]).await;
    let dir = tempfile::tempdir().unwrap();
    let path = write_artifact(dir.path(), "policies.json", &[spec("new-id")]);
    let error = agent_policy_ops::plan_import(&transport_for(&server), &path, true, false)
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(
        error.message,
        "agent policy names already exist: Policy new-id (other-id)"
    );
}

#[tokio::test]
async fn plan_import_does_not_preflight_a_package_for_nonempty_to_nonempty_monitoring() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/existing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("existing")})))
        .mount(&server)
        .await;
    mount_pages(&server, vec![(1, vec![item("existing")], 1)]).await;
    let mut desired = spec("existing");
    desired.description = Some("changed".into());
    let dir = tempfile::tempdir().unwrap();
    let path = write_artifact(dir.path(), "policies.json", &[desired]);
    let plan = agent_policy_ops::plan_import(&transport_for(&server), &path, true, false)
        .await
        .expect("plan without a package-status route");
    assert!(plan.package_installs.is_empty());
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

#[tokio::test]
async fn apply_import_creates_replaces_and_reports_unchanged_rows() {
    let server = verified_server().await;
    // fresh: 404 at plan and recheck, then the created object after POST
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/fresh"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(200).set_body_json(json!({"item": item("fresh")})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/agent_policies"))
        .and(query_param("sys_monitoring", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("fresh")})))
        .mount(&server)
        .await;
    // same: identical at plan and recheck -> unchanged, no write
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/same"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("same")})))
        .mount(&server)
        .await;
    // changed: description differs; PUT then the stored object equals desired
    let mut changed_live = item("changed");
    changed_live["agents"] = json!(7);
    let mut changed_after = changed_live.clone();
    changed_after["description"] = json!("new");
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/changed"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": changed_live})),
            ResponseTemplate::new(200).set_body_json(json!({"item": changed_live})),
            ResponseTemplate::new(200).set_body_json(json!({"item": changed_after})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/fleet/agent_policies/changed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": changed_after})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/elastic_agent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "elastic_agent", "version": "2.5.0", "status": "installed",
            "installationInfo": {"version": "2.5.0"}
        }})))
        .mount(&server)
        .await;
    mount_pages(
        &server,
        vec![(1, vec![item("same"), changed_live.clone()], 2)],
    )
    .await;
    let transport = transport_for(&server);
    let dir = tempfile::tempdir().unwrap();
    let mut changed = spec("changed");
    changed.description = Some("new".into());
    let path = write_artifact(
        dir.path(),
        "p.json",
        &[spec("fresh"), spec("same"), changed],
    );

    let plan = agent_policy_ops::plan_import(&transport, &path, true, false)
        .await
        .unwrap();
    let report = agent_policy_ops::apply_import(&transport, &plan)
        .await
        .unwrap();
    assert!(report.applied);
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
    assert_eq!(report.total, 3);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.iter().filter(|r| r.method == "PUT").count(), 1);
    assert_eq!(requests.iter().filter(|r| r.method == "POST").count(), 1);
}

#[tokio::test]
async fn apply_import_refuses_races_and_reports_stored_mismatches_as_applied() {
    let server = verified_server().await;
    // appeared: planned create, exists at recheck -> no POST
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/appeared"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(200).set_body_json(json!({"item": item("appeared")})),
        ]))
        .mount(&server)
        .await;
    // drift: create succeeds but the stored object differs
    let mut drift_stored = item("drift");
    drift_stored["description"] = json!("server changed it");
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/drift"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(200).set_body_json(json!({"item": drift_stored})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/agent_policies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("drift")})))
        .mount(&server)
        .await;
    // Both specs enable monitoring, so planning reads the package status.
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/elastic_agent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "elastic_agent", "version": "2.5.0", "status": "installed",
            "installationInfo": {"version": "2.5.0"}
        }})))
        .mount(&server)
        .await;
    mount_pages(&server, vec![(1, vec![], 0)]).await;
    let transport = transport_for(&server);
    let dir = tempfile::tempdir().unwrap();
    let path = write_artifact(dir.path(), "p.json", &[spec("appeared"), spec("drift")]);

    let plan = agent_policy_ops::plan_import(&transport, &path, false, false)
        .await
        .unwrap();
    let report = agent_policy_ops::apply_import(&transport, &plan)
        .await
        .unwrap();
    assert_eq!(
        report.failed,
        vec![
            json!({"id": "appeared", "applied": false, "error": "agent policy appeared since preview"}),
            json!({"id": "drift", "applied": true, "error": "server stored a different agent-policy spec"}),
        ]
    );
    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST")
            .count(),
        1
    );
}

#[tokio::test]
async fn apply_import_rechecks_agent_counts_from_the_full_snapshot() {
    let server = verified_server().await;
    let first = item("agents-race");
    let mut second = first.clone();
    second["agents"] = json!(1);
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/agents-race"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": first.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": second})),
        ]))
        .mount(&server)
        .await;
    mount_pages(&server, vec![(1, vec![first], 1)]).await;
    let dir = tempfile::tempdir().unwrap();
    // A description change makes this a planned replace row, not unchanged,
    // so the recheck below must stop it before issuing the PUT.
    let mut changed = spec("agents-race");
    changed.description = Some("changed".into());
    let path = write_artifact(dir.path(), "p.json", &[changed]);
    let transport = transport_for(&server);
    let plan = agent_policy_ops::plan_import(&transport, &path, true, false)
        .await
        .unwrap();
    let report = agent_policy_ops::apply_import(&transport, &plan)
        .await
        .unwrap();
    assert_eq!(
        report.failed,
        vec![json!({
            "id": "agents-race", "applied": false,
            "error": "agent policy changed since preview"
        })]
    );
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.method == "PUT"),
        "no replace request must be issued once the recheck sees a changed agent count"
    );
}

#[tokio::test]
async fn apply_import_rechecks_attachment_ids_from_the_full_snapshot() {
    let server = verified_server().await;
    let first = item("attachment-race");
    let mut second = first.clone();
    second["package_policies"] = json!([{"id": "integration-1"}]);
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/attachment-race"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": first.clone()})),
            ResponseTemplate::new(200).set_body_json(json!({"item": second})),
        ]))
        .mount(&server)
        .await;
    mount_pages(&server, vec![(1, vec![first], 1)]).await;
    let dir = tempfile::tempdir().unwrap();
    // A description change makes this a planned replace row, not unchanged,
    // so the recheck below must stop it before issuing the PUT.
    let mut changed = spec("attachment-race");
    changed.description = Some("changed".into());
    let path = write_artifact(dir.path(), "p.json", &[changed]);
    let transport = transport_for(&server);
    let plan = agent_policy_ops::plan_import(&transport, &path, true, false)
        .await
        .unwrap();
    let report = agent_policy_ops::apply_import(&transport, &plan)
        .await
        .unwrap();
    assert_eq!(
        report.failed[0]["error"],
        "agent policy changed since preview"
    );
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.method == "PUT"),
        "no replace request must be issued once the recheck sees a changed attachment set"
    );
}

#[tokio::test]
async fn apply_import_rechecks_the_monitoring_package_before_a_write() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/fresh"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
        )
        .mount(&server)
        .await;
    mount_pages(&server, vec![(1, vec![], 0)]).await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/elastic_agent"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": {
                "name": "elastic_agent", "status": "not_installed"
            }})),
            ResponseTemplate::new(200).set_body_json(json!({"item": {
                "name": "elastic_agent", "status": "installed",
                "installationInfo": {"version": "2.5.0"}
            }})),
        ]))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let path = write_artifact(dir.path(), "p.json", &[spec("fresh")]);
    let transport = transport_for(&server);
    let plan = agent_policy_ops::plan_import(&transport, &path, false, false)
        .await
        .unwrap();
    let report = agent_policy_ops::apply_import(&transport, &plan)
        .await
        .unwrap();
    assert_eq!(
        report.failed[0]["error"],
        "elastic_agent package changed since preview"
    );
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.method == "POST")
    );
}

#[tokio::test]
async fn apply_import_succeeds_with_no_package_installs_when_the_post_write_read_still_reports_not_installed()
 {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/fresh"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(200).set_body_json(json!({"item": item("fresh")})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/agent_policies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("fresh")})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/elastic_agent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "elastic_agent", "status": "not_installed"
        }})))
        .mount(&server)
        .await;
    mount_pages(&server, vec![(1, vec![], 0)]).await;
    let dir = tempfile::tempdir().unwrap();
    let path = write_artifact(dir.path(), "p.json", &[spec("fresh")]);
    let transport = transport_for(&server);
    let plan = agent_policy_ops::plan_import(&transport, &path, false, false)
        .await
        .unwrap();
    let report = agent_policy_ops::apply_import(&transport, &plan)
        .await
        .unwrap();
    assert_eq!(
        report.succeeded,
        vec![json!({"id": "fresh", "action": "created"})]
    );
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    assert!(report.package_installs.is_empty());
}

#[tokio::test]
async fn apply_import_reports_a_failed_row_when_the_post_write_package_read_errors() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/fresh"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(200).set_body_json(json!({"item": item("fresh")})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/agent_policies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("fresh")})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/elastic_agent"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": {
                "name": "elastic_agent", "status": "not_installed"
            }})),
            ResponseTemplate::new(200).set_body_json(json!({"item": {
                "name": "elastic_agent", "status": "not_installed"
            }})),
            ResponseTemplate::new(500).set_body_json(json!({"statusCode": 500, "message": "boom"})),
        ]))
        .mount(&server)
        .await;
    mount_pages(&server, vec![(1, vec![], 0)]).await;
    let dir = tempfile::tempdir().unwrap();
    let path = write_artifact(dir.path(), "p.json", &[spec("fresh")]);
    let transport = transport_for(&server);
    let plan = agent_policy_ops::plan_import(&transport, &path, false, false)
        .await
        .unwrap();
    let report = agent_policy_ops::apply_import(&transport, &plan)
        .await
        .unwrap();
    assert!(report.succeeded.is_empty(), "{:?}", report.succeeded);
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0]["id"], "fresh");
    assert_eq!(report.failed[0]["applied"], true);
}

#[tokio::test]
async fn apply_import_reports_the_installed_version_when_the_post_write_read_reports_installed() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/fresh"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
            ResponseTemplate::new(200).set_body_json(json!({"item": item("fresh")})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/agent_policies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("fresh")})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/elastic_agent"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": {
                "name": "elastic_agent", "status": "not_installed"
            }})),
            ResponseTemplate::new(200).set_body_json(json!({"item": {
                "name": "elastic_agent", "status": "not_installed"
            }})),
            ResponseTemplate::new(200).set_body_json(json!({"item": {
                "name": "elastic_agent", "status": "installed",
                "installationInfo": {"version": "2.5.0"}
            }})),
        ]))
        .mount(&server)
        .await;
    mount_pages(&server, vec![(1, vec![], 0)]).await;
    let dir = tempfile::tempdir().unwrap();
    let path = write_artifact(dir.path(), "p.json", &[spec("fresh")]);
    let transport = transport_for(&server);
    let plan = agent_policy_ops::plan_import(&transport, &path, false, false)
        .await
        .unwrap();
    let report = agent_policy_ops::apply_import(&transport, &plan)
        .await
        .unwrap();
    assert_eq!(
        report.succeeded,
        vec![json!({"id": "fresh", "action": "created"})]
    );
    assert_eq!(
        report.package_installs,
        vec!["elastic_agent@2.5.0".to_string()]
    );
}

#[tokio::test]
async fn apply_import_rejects_a_tampered_plan_before_any_request() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/fresh"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/elastic_agent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "elastic_agent", "status": "not_installed"
        }})))
        .mount(&server)
        .await;
    mount_pages(&server, vec![(1, vec![], 0)]).await;
    let dir = tempfile::tempdir().unwrap();
    let path = write_artifact(dir.path(), "p.json", &[spec("fresh")]);
    let transport = transport_for(&server);
    let plan: AgentPolicyImportPlan =
        agent_policy_ops::plan_import(&transport, &path, false, false)
            .await
            .unwrap();
    let before_requests = server.received_requests().await.unwrap().len();

    let mut tampered_preview = plan.clone();
    tampered_preview.preview.preview_action = "tampered".into();
    let error = agent_policy_ops::apply_import(&transport, &tampered_preview)
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Error);

    let mut tampered_skipped = plan.clone();
    tampered_skipped.skipped = vec![json!({"id": "fresh", "reason": "exists"})];
    let error = agent_policy_ops::apply_import(&transport, &tampered_skipped)
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Error);

    let mut tampered_installs = plan.clone();
    tampered_installs.package_installs = Vec::new();
    let error = agent_policy_ops::apply_import(&transport, &tampered_installs)
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Error);

    let mut tampered_total = plan.clone();
    tampered_total.total = 99;
    let error = agent_policy_ops::apply_import(&transport, &tampered_total)
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Error);

    assert_eq!(
        server.received_requests().await.unwrap().len(),
        before_requests
    );
}

#[tokio::test]
async fn apply_import_refuses_a_planned_create_whose_name_appeared_since_preview() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/new"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/epm/packages/elastic_agent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
            "name": "elastic_agent", "status": "not_installed"
        }})))
        .mount(&server)
        .await;
    let mut taken = item("other");
    taken["name"] = json!("Policy new");
    // Empty at plan time; another client claims the name by apply time.
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies"))
        .and(query_param("page", "1"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({
                "items": [], "total": 0, "page": 1, "perPage": 1000
            })),
            ResponseTemplate::new(200).set_body_json(json!({
                "items": [taken], "total": 1, "page": 1, "perPage": 1000
            })),
        ]))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let path = write_artifact(dir.path(), "p.json", &[spec("new")]);
    let transport = transport_for(&server);
    let plan = agent_policy_ops::plan_import(&transport, &path, false, false)
        .await
        .unwrap();
    let report = agent_policy_ops::apply_import(&transport, &plan)
        .await
        .unwrap();
    assert_eq!(
        report.failed,
        vec![json!({
            "id": "new",
            "applied": false,
            "error": "agent policy name appeared since preview: Policy new (other)"
        })]
    );
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.method == "POST"),
        "no create request must be issued once the name conflict is detected"
    );
}

#[tokio::test]
async fn plan_delete_refuses_agents_and_attached_integrations_in_one_conflict() {
    let server = verified_server().await;
    let mut busy = item("busy");
    busy["agents"] = json!(3);
    busy["package_policies"] = json!([{"id": "int-1"}, {"id": "int-0"}]);
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/busy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": busy})))
        .mount(&server)
        .await;
    let error = agent_policy_ops::plan_delete(&transport_for(&server), &["busy".into()])
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(
        error.message,
        "agent policy 'busy' has 3 assigned agents; agent policy 'busy' has attached integrations: int-0, int-1"
    );
}

#[tokio::test]
async fn delete_previews_then_posts_without_force_and_fails_a_vanished_target() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/idle"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("idle")})))
        .mount(&server)
        .await;
    // gone: resolve and the plan read see it; the apply recheck does not.
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/gone"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": item("gone")})),
            ResponseTemplate::new(200).set_body_json(json!({"item": item("gone")})),
            ResponseTemplate::new(404)
                .set_body_json(json!({"statusCode": 404, "message": "missing"})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/agent_policies/delete"))
        .and(body_json(json!({"agentPolicyId": "idle"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "idle", "name": "Policy idle"})),
        )
        .mount(&server)
        .await;
    let transport = transport_for(&server);
    let plan =
        agent_policy_ops::plan_delete(&transport, &["idle".into(), "gone".into(), "idle".into()])
            .await
            .unwrap();
    assert_eq!(plan.preview.preview_action, "Delete 2 agent policy(ies)");
    assert_eq!(
        plan.preview.preview_details,
        [
            "gone  Policy gone  agents 0  integrations 0",
            "idle  Policy idle  agents 0  integrations 0"
        ]
    );
    let report = agent_policy_ops::apply_delete(&transport, &plan)
        .await
        .unwrap();
    assert_eq!(report.deleted, vec![json!({"id": "idle"})]);
    assert_eq!(
        report.failed,
        vec![json!({
            "id": "gone", "applied": false,
            "error": "agent policy disappeared since preview"
        })]
    );
    assert_eq!(report.total, 2);
    assert_eq!(report.affected_agents, 0);
}

#[tokio::test]
async fn apply_delete_fails_a_target_that_changed_since_preview() {
    let server = verified_server().await;
    // idle: resolve and the plan read see it clean, the apply recheck sees agents acquired.
    let mut acquired = item("idle");
    acquired["agents"] = json!(2);
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/idle"))
        .respond_with(SequenceResponder::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"item": item("idle")})),
            ResponseTemplate::new(200).set_body_json(json!({"item": item("idle")})),
            ResponseTemplate::new(200).set_body_json(json!({"item": acquired})),
        ]))
        .mount(&server)
        .await;
    // Mounted so a wrongly issued delete would show up as a request, not a 404.
    Mock::given(method("POST"))
        .and(path("/api/fleet/agent_policies/delete"))
        .and(body_json(json!({"agentPolicyId": "idle"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "idle", "name": "Policy idle"})),
        )
        .mount(&server)
        .await;
    let transport = transport_for(&server);
    let plan = agent_policy_ops::plan_delete(&transport, &["idle".into()])
        .await
        .unwrap();
    let report = agent_policy_ops::apply_delete(&transport, &plan)
        .await
        .unwrap();
    assert!(report.deleted.is_empty());
    assert_eq!(
        report.failed,
        vec![json!({
            "id": "idle", "applied": false,
            "error": "agent policy changed since preview"
        })]
    );
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.method == "POST"),
        "no delete request must be issued once the recheck sees a change"
    );
}

#[tokio::test]
async fn apply_delete_reports_applied_true_when_the_route_echoes_a_different_id() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/idle"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("idle")})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/fleet/agent_policies/delete"))
        .and(body_json(json!({"agentPolicyId": "idle"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "other", "name": "Other"})),
        )
        .mount(&server)
        .await;
    let transport = transport_for(&server);
    let plan = agent_policy_ops::plan_delete(&transport, &["idle".into()])
        .await
        .unwrap();
    let report = agent_policy_ops::apply_delete(&transport, &plan)
        .await
        .unwrap();
    assert!(report.deleted.is_empty());
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0]["id"], "idle");
    assert_eq!(report.failed[0]["applied"], true);
    assert!(
        report.failed[0]["error"]
            .as_str()
            .unwrap()
            .contains("expected id 'idle', got 'other'"),
        "{:?}",
        report.failed[0]
    );
}

#[tokio::test]
async fn apply_delete_rejects_tampered_plan_targets() {
    let server = verified_server().await;
    Mock::given(method("GET"))
        .and(path("/api/fleet/agent_policies/idle"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": item("idle")})))
        .mount(&server)
        .await;
    let transport = transport_for(&server);
    let mut plan = agent_policy_ops::plan_delete(&transport, &["idle".into()])
        .await
        .unwrap();
    plan.targets.push(plan.targets[0].clone());
    let requests_before = server.received_requests().await.unwrap().len();
    let error = agent_policy_ops::apply_delete(&transport, &plan)
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Error);
    assert_eq!(error.message, "invalid agent-policy delete plan");
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        requests_before,
        "a tampered plan must be rejected before any request"
    );
}
