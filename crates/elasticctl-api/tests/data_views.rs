use elasticctl_api::content_codec::{self, ContentFormat};
use elasticctl_api::data_views::{self, DataViewSpec, DataViewUpdate};
use elasticctl_api::data_views_ops::{self, DataViewFilter};
use elasticctl_core::{Profile, Transport};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn spec(id: &str) -> DataViewSpec {
    serde_json::from_value(json!({
        "id": id,
        "title": "logs-security-*",
        "name": "Security events",
        "timeFieldName": "@timestamp",
        "allowNoIndex": true,
        "allowHidden": false,
        "sourceFilters": [],
        "fieldFormats": {},
        "runtimeFieldMap": {},
        "fieldAttrs": {}
    }))
    .expect("spec")
}

#[test]
fn json_and_yaml_carry_the_same_data_view_specs() {
    let specs = vec![spec("b"), spec("a")];
    for format in [ContentFormat::Json, ContentFormat::Yaml] {
        let body = content_codec::encode_sequence(&specs, format).expect("encode");
        let decoded: Vec<DataViewSpec> =
            content_codec::decode_sequence(&body, format, "data view").expect("decode");
        assert_eq!(decoded, specs);
    }
}

#[test]
fn data_view_spec_rejects_unknown_fields_and_empty_identity() {
    let unknown = json!({"id": "dv", "title": "logs-*", "titel": "typo"});
    assert!(serde_json::from_value::<DataViewSpec>(unknown).is_err());
    assert!(DataViewSpec::try_from(json!({"id": "", "title": "logs-*"})).is_err());
    assert!(DataViewSpec::try_from(json!({"id": "dv", "title": ""})).is_err());
}

#[test]
fn direct_deserialization_validates_portable_data_views() {
    for (value, path) in [
        (json!({"id": "", "title": "logs-*"}), "id"),
        (
            json!({"id": "dv", "title": "logs-*", "typeMeta": "rollup"}),
            "typeMeta",
        ),
        (
            json!({"id": "dv", "title": "logs-*", "fieldAttrs": {"host.name": "bad"}}),
            "fieldAttrs.host.name",
        ),
        (
            json!({"id": "dv", "title": "logs-*", "fields": {"host.name": {"scripted": false}}}),
            "fields.host.name",
        ),
    ] {
        let err =
            serde_json::from_value::<DataViewSpec>(value).expect_err("must reject invalid spec");
        assert!(err.to_string().contains(path), "{err}");
    }
}

#[test]
fn empty_type_meta_is_canonicalized_to_absence() {
    let spec: DataViewSpec = serde_json::from_value(json!({
        "id": "dv", "title": "logs-*", "typeMeta": {}
    }))
    .expect("decode");
    assert_eq!(spec.type_meta, None);
    assert!(
        serde_json::to_value(spec)
            .expect("encode")
            .get("typeMeta")
            .is_none()
    );
}

#[test]
fn sequence_decode_names_the_invalid_json_or_yaml_element() {
    let json_body = r#"[
        {"id":"first","title":"logs-*"},
        {"id":"second","title":"logs-*","fields":{"host.name":{"scripted":false}}}
    ]"#;
    let yaml_body = r#"
- id: first
  title: logs-*
- id: second
  title: logs-*
  fields:
    host.name:
      scripted: false
"#;
    for (body, format) in [
        (json_body, ContentFormat::Json),
        (yaml_body, ContentFormat::Yaml),
    ] {
        let err = content_codec::decode_sequence::<DataViewSpec>(body, format, "data view")
            .expect_err("must reject second item");
        assert!(
            err.message.contains("data view at index 1"),
            "{}",
            err.message
        );
        assert!(err.message.contains("fields.host.name"), "{}", err.message);
    }
}

#[test]
fn data_view_spec_names_invalid_nested_field_paths() {
    for (value, path) in [
        (
            json!({"id": "dv", "title": "logs-*", "typeMeta": "rollup"}),
            "typeMeta",
        ),
        (
            json!({"id": "dv", "title": "logs-*", "fieldAttrs": {"host.name": "bad"}}),
            "fieldAttrs.host.name",
        ),
        (
            json!({"id": "dv", "title": "logs-*", "fields": {"host.name": {"scripted": false}}}),
            "fields.host.name",
        ),
    ] {
        let err = DataViewSpec::try_from(value).expect_err("must reject invalid portable value");
        assert!(err.message.contains(path), "{}", err.message);
    }
}

#[test]
fn format_uses_yaml_extensions_and_json_otherwise() {
    assert_eq!(
        ContentFormat::from_path(std::path::Path::new("views.yaml")),
        ContentFormat::Yaml
    );
    assert_eq!(
        ContentFormat::from_path(std::path::Path::new("views.yml")),
        ContentFormat::Yaml
    );
    assert_eq!(
        ContentFormat::from_path(std::path::Path::new("views.json")),
        ContentFormat::Json
    );
}

#[test]
fn resolution_prefers_an_exact_id_over_duplicate_names() {
    let views = vec![
        data_views::DataViewSummary {
            id: "x".into(),
            title: "id-title".into(),
            name: Some("other".into()),
            time_field_name: None,
        },
        data_views::DataViewSummary {
            id: "a".into(),
            title: "first-name-match".into(),
            name: Some("x".into()),
            time_field_name: None,
        },
        data_views::DataViewSummary {
            id: "b".into(),
            title: "second-name-match".into(),
            name: Some("x".into()),
            time_field_name: None,
        },
    ];

    assert_eq!(
        data_views_ops::resolve_from_summaries(&views, "x")
            .expect("id must win")
            .title,
        "id-title"
    );
}

#[test]
fn resolution_reports_exact_name_ambiguity() {
    let views = vec![
        data_views::DataViewSummary {
            id: "a".into(),
            title: "logs-a-*".into(),
            name: Some("duplicate".into()),
            time_field_name: None,
        },
        data_views::DataViewSummary {
            id: "b".into(),
            title: "logs-b-*".into(),
            name: Some("duplicate".into()),
            time_field_name: None,
        },
    ];
    let error = data_views_ops::resolve_from_summaries(&views, "duplicate")
        .expect_err("duplicate name must refuse");
    assert_eq!(error.message, "data view 'duplicate' is ambiguous");
}

#[test]
fn normalization_keeps_only_scripted_fields() {
    let body = json!({"data_view": {
        "id": "dv", "title": "logs-*", "version": "opaque", "namespaces": ["default"],
        "fields": {
            "host.name": {"name": "host.name", "scripted": false},
            "legacy": {"name": "legacy", "scripted": true, "script": "return 1"}
        }
    }});
    let spec = data_views_ops::normalize(&body["data_view"]).expect("normalize");
    assert_eq!(spec.id, "dv");
    assert!(!spec.allow_no_index);
    assert!(!spec.allow_hidden);
    assert_eq!(spec.type_meta, None);
    assert_eq!(spec.fields.keys().collect::<Vec<_>>(), vec!["legacy"]);
    let value = serde_json::to_value(spec).expect("value");
    assert!(value.get("version").is_none());
    assert!(value.get("namespaces").is_none());
}

#[tokio::test]
async fn list_searches_case_insensitively_and_sorts_by_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view": [
                {"id": "b", "name": "Unrelated", "title": "Logs-VIEW-b"},
                {"id": "a", "name": "view alpha", "title": "logs-a-*"},
                {"id": "c", "name": "other", "title": "logs-c-*"}
            ]})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let listed = data_views_ops::list_op(
        &transport(&server),
        &DataViewFilter {
            search: Some("vIeW".into()),
        },
    )
    .await
    .expect("list");

    assert_eq!(listed.total, 2);
    assert_eq!(
        listed
            .data_views
            .iter()
            .map(|view| view.id.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );
}

#[test]
fn validate_sorts_specs_and_reports_every_duplicate_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let valid_path = dir.path().join("views.json");
    std::fs::write(
        &valid_path,
        r#"[{"id":"b","title":"logs-b-*"},{"id":"a","title":"logs-a-*"}]"#,
    )
    .expect("write valid artifact");
    let specs = data_views_ops::validate(&valid_path).expect("valid artifact");
    assert_eq!(
        specs
            .iter()
            .map(|spec| spec.id.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );

    let duplicate_path = dir.path().join("duplicates.yaml");
    std::fs::write(
        &duplicate_path,
        "- id: c\n  title: logs-c-*\n- id: a\n  title: logs-a-*\n- id: c\n  title: logs-c-2-*\n- id: a\n  title: logs-a-2-*\n",
    )
    .expect("write duplicate artifact");
    let error = data_views_ops::validate(&duplicate_path).expect_err("duplicates must refuse");
    assert_eq!(error.message, "duplicate data view ids: a, c");
}

fn transport(server: &MockServer) -> Transport {
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

fn response(spec: DataViewSpec) -> serde_json::Value {
    json!({"data_view": spec})
}

#[tokio::test]
async fn routes_use_the_documented_paths_and_bodies() {
    let server = MockServer::start().await;
    let current = spec("dv");
    Mock::given(method("GET"))
        .and(path("/api/data_views"))
        .and(header("elastic-api-version", "2023-10-31"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view": [current]})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(spec("dv"))))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view"))
        .and(body_json(
            json!({"data_view": spec("dv"), "override": false}),
        ))
        .and(header("elastic-api-version", "2023-10-31"))
        .and(header("kbn-xsrf", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(spec("dv"))))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view/dv"))
        .and(body_json(json!({
            "data_view": {"sourceFilters": [], "title": "logs-new-*"},
            "refresh_fields": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(spec("dv"))))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view/dv/fields"))
        .and(body_json(
            json!({"fields": {"host.name": {"count": 2, "customLabel": null}}}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view_id": "dv"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/default"))
        .and(body_json(json!({"data_view_id": "dv", "force": true})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/default"))
        .and(body_json(json!({"data_view_id": null, "force": true})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/swap_references/_preview"))
        .and(body_json(json!({"fromId": "old", "toId": "new"})))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"result": [{"id": "dash", "type": "dashboard"}]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/swap_references"))
        .and(body_json(
            json!({"delete": true, "fromId": "old", "toId": "new"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [{"id": "dash", "type": "dashboard"}],
            "deleteStatus": {"deletePerformed": true, "remainingRefs": 0}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let transport = transport(&server);
    assert_eq!(data_views::list(&transport).await.expect("list").len(), 1);
    assert_eq!(
        data_views::get(&transport, "dv")
            .await
            .expect("get")
            .data_view["id"],
        json!("dv")
    );
    data_views::create(&transport, &spec("dv"))
        .await
        .expect("create");
    data_views::update(
        &transport,
        "dv",
        &DataViewUpdate {
            source_filters: Some(vec![]),
            title: Some("logs-new-*".into()),
            ..Default::default()
        },
    )
    .await
    .expect("update");
    data_views::update_fields_metadata(
        &transport,
        "dv",
        &json!({"host.name": {"count": 2, "customLabel": null}})
            .as_object()
            .expect("object")
            .clone(),
    )
    .await
    .expect("metadata");
    data_views::delete(&transport, "dv").await.expect("delete");
    assert_eq!(
        data_views::get_default(&transport).await.expect("default"),
        Some("dv".into())
    );
    data_views::set_default(&transport, Some("dv"))
        .await
        .expect("set default");
    data_views::set_default(&transport, None)
        .await
        .expect("unset default");
    assert_eq!(
        data_views::preview_swap(&transport, "old", "new")
            .await
            .expect("preview")[0]
            .id,
        "dash"
    );
    assert!(
        data_views::swap(&transport, "old", "new")
            .await
            .expect("swap")
            .delete_status
            .delete_performed
    );
}

#[tokio::test]
async fn detail_routes_keep_server_owned_and_generated_fields() {
    let server = MockServer::start().await;
    let body = json!({"data_view": {
        "id": "dv", "title": "logs-*", "version": "WzEsMV0=",
        "namespaces": ["default"],
        "fields": {"host.name": {"scripted": false, "type": "string"}}
    }});
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let view = data_views::get(&transport(&server), "dv")
        .await
        .expect("get");
    assert_eq!(view.data_view["version"], json!("WzEsMV0="));
    assert_eq!(view.data_view["namespaces"], json!(["default"]));
    assert_eq!(view.data_view["fields"]["host.name"]["scripted"], false);
}

#[tokio::test]
async fn detail_path_encodes_reserved_id_characters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv%2Fwith%20space"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(spec("dv/with space"))))
        .expect(1)
        .mount(&server)
        .await;

    data_views::get(&transport(&server), "dv/with space")
        .await
        .expect("encoded path");
}

#[tokio::test]
async fn fixed_route_envelopes_reject_malformed_responses() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view": [], "extra": true})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data_view": spec("dv"), "extra": true})),
        )
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": false})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data_view_id": 1})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/swap_references/_preview"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"result": [{"id": "dash", "type": true}]})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/swap_references"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [{"id": "dash", "type": "dashboard"}],
            "deleteStatus": {"deletePerformed": true, "remainingRefs": "zero"}
        })))
        .mount(&server)
        .await;

    let transport = transport(&server);
    assert!(data_views::list(&transport).await.is_err());
    assert!(data_views::get(&transport, "dv").await.is_err());
    assert!(data_views::delete(&transport, "dv").await.is_err());
    assert!(data_views::get_default(&transport).await.is_err());
    assert!(
        data_views::preview_swap(&transport, "old", "new")
            .await
            .is_err()
    );
    assert!(data_views::swap(&transport, "old", "new").await.is_err());
}

#[tokio::test]
async fn default_envelope_requires_data_view_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/default"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    assert!(data_views::get_default(&transport(&server)).await.is_err());
}

#[test]
fn update_serializes_only_the_documented_partial_fields() {
    let body = serde_json::to_value(DataViewUpdate {
        source_filters: Some(vec![]),
        title: Some("logs-new-*".into()),
        ..Default::default()
    })
    .expect("serialize");
    assert_eq!(body, json!({"sourceFilters": [], "title": "logs-new-*"}));
    for forbidden in ["id", "allowHidden", "fieldAttrs"] {
        assert!(
            body.get(forbidden).is_none(),
            "{forbidden} must not reach the update route"
        );
    }
}

#[tokio::test]
async fn export_resolves_every_selector_before_fetching_details() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view": [
                {"id": "present", "title": "logs-present-*"}
            ]})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let error = data_views_ops::export(
        &transport(&server),
        &["present".into(), "missing".into()],
        ContentFormat::Json,
    )
    .await
    .expect_err("missing selector must refuse");
    assert_eq!(error.message, "no data view with id or name 'missing'");
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(
        requests.len(),
        1,
        "no detail request may precede resolution"
    );
    assert_eq!(requests[0].url.path(), "/api/data_views");
}

#[tokio::test]
async fn export_sorts_normalized_details_by_stable_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view": [
                {"id": "b", "title": "logs-b-*"},
                {"id": "a", "title": "logs-a-*"}
            ]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    for (id, title) in [("a", "logs-a-*"), ("b", "logs-b-*")] {
        Mock::given(method("GET"))
            .and(path(format!("/api/data_views/data_view/{id}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"data_view": {
                    "id": id,
                    "title": title,
                    "version": "opaque",
                    "fields": {"host.name": {"scripted": false}}
                }})),
            )
            .expect(1)
            .mount(&server)
            .await;
    }

    let exported = data_views_ops::export(
        &transport(&server),
        &["b".into(), "a".into()],
        ContentFormat::Json,
    )
    .await
    .expect("export");
    let specs: Vec<DataViewSpec> = serde_json::from_str(&exported.body).expect("portable JSON");
    assert_eq!(exported.exported, 2);
    assert_eq!(
        specs
            .iter()
            .map(|spec| spec.id.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );
    assert!(specs.iter().all(|spec| spec.fields.is_empty()));
}
