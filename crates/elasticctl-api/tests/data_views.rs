use elasticctl_api::content_codec::{self, ContentFormat};
use elasticctl_api::data_views::{self, DataViewSpec, DataViewUpdate};
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
