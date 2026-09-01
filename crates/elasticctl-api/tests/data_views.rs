use elasticctl_api::content_codec::{self, ContentFormat};
use elasticctl_api::data_views::{self, DataViewSpec, DataViewUpdate};
use elasticctl_api::data_views_ops::{self, DataViewFilter};
use elasticctl_api::{DataViewImportPlan, DataViewPatch, MutationPlan};
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::{Value, json};
use std::collections::BTreeMap;
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

#[test]
fn normalization_classifies_malformed_live_data_as_http() {
    let error = data_views_ops::normalize(&json!({"id": "dv", "title": 42}))
        .expect_err("live response must be strict");
    assert_eq!(error.kind, ErrorKind::Http);
    assert!(error.message.starts_with("decoding data view:"));
}

#[tokio::test]
async fn list_searches_case_insensitively_and_sorts_by_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view": [
                {"id": "b", "name": "Unrelated", "title": "Logs-VIEW-b"},
                {"id": "a", "name": "view alpha", "title": "logs-a-*", "managed": true, "namespaces": ["default"]},
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

#[test]
fn validate_reports_read_failures_as_local_errors() {
    let path = tempfile::tempdir()
        .expect("tempdir")
        .path()
        .join("missing.json");
    let error = data_views_ops::validate(&path).expect_err("missing artifact");
    assert_eq!(error.kind, ErrorKind::Error);
    assert!(error.message.starts_with("reading "));
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

fn artifact(specs: &[DataViewSpec]) -> tempfile::TempPath {
    let file = tempfile::NamedTempFile::new().expect("artifact");
    serde_json::to_writer(&file, specs).expect("write artifact");
    file.into_temp_path()
}

fn import_plan(
    specs: Vec<DataViewSpec>,
    before: BTreeMap<String, Option<DataViewSpec>>,
    patches: BTreeMap<String, DataViewPatch>,
) -> DataViewImportPlan {
    let preview_details = specs
        .iter()
        .map(|spec| match before.get(&spec.id).and_then(Option::as_ref) {
            None => format!("{}  create  {}", spec.id, spec.title),
            Some(current) if current == spec => format!("{}  no-op  {}", spec.id, spec.title),
            Some(current) => format!("{}  replace  {} -> {}", spec.id, current.title, spec.title),
        })
        .collect();
    DataViewImportPlan {
        preview: MutationPlan {
            preview_action: format!("Import {} data view(s) from test", specs.len()),
            preview_details,
            targets: specs.iter().map(|spec| spec.id.clone()).collect(),
        },
        total: specs.len(),
        specs,
        before,
        patches,
        skipped: Vec::new(),
        overwrite: true,
    }
}

#[tokio::test]
async fn plan_import_rejects_empty_artifacts_before_transport_reads() {
    let server = MockServer::start().await;
    for extension in ["json", "yaml"] {
        let file = tempfile::NamedTempFile::with_suffix(format!(".{extension}")).expect("file");
        std::fs::write(file.path(), if extension == "json" { "[]" } else { "[]\n" })
            .expect("write");
        let error =
            data_views_ops::plan_import(Some(&transport(&server)), file.path(), false, false)
                .await
                .expect_err("empty import must refuse");
        assert_eq!(error.kind, ErrorKind::Error);
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn plan_import_rejects_a_wrong_embedded_detail_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(spec("other"))))
        .expect(1)
        .mount(&server)
        .await;
    let path = artifact(&[spec("dv")]);

    let error = data_views_ops::plan_import(Some(&transport(&server)), &path, true, false)
        .await
        .expect_err("wrong detail id must refuse");

    assert_eq!(error.kind, ErrorKind::Http);
}

#[test]
fn build_patch_rejects_unequal_data_view_ids() {
    let error = data_views_ops::build_patch(&spec("old"), &spec("new"))
        .expect_err("id changes are not a patch");
    assert_eq!(error.kind, ErrorKind::Unsupported);
}

#[test]
fn build_patch_covers_every_documented_update_field_and_metadata_union() {
    let current = DataViewSpec {
        field_attrs: json!({
            "a": {"changed": 1, "removed": true, "same": "yes"},
            "z": {"removed": "old"}
        })
        .as_object()
        .expect("object")
        .clone(),
        fields: json!({"old": {"scripted": true, "script": "1"}})
            .as_object()
            .expect("object")
            .clone(),
        view_type: Some("rollup".into()),
        type_meta: Some(json!({"old": true}).as_object().expect("object").clone()),
        ..spec("dv")
    };
    let desired = DataViewSpec {
        title: "logs-new-*".into(),
        name: Some("New name".into()),
        time_field_name: Some("event.created".into()),
        allow_no_index: false,
        source_filters: vec![json!({"value": "secret"})],
        field_formats: json!({"bytes": {"id": "bytes"}})
            .as_object()
            .expect("object")
            .clone(),
        runtime_field_map: json!({"runtime": {"type": "keyword"}})
            .as_object()
            .expect("object")
            .clone(),
        fields: json!({"new": {"scripted": true, "script": "2"}})
            .as_object()
            .expect("object")
            .clone(),
        field_attrs: json!({
            "a": {"added": 2, "changed": 3, "same": "yes"},
            "m": {"new": true}
        })
        .as_object()
        .expect("object")
        .clone(),
        view_type: Some("standard".into()),
        type_meta: Some(json!({"new": true}).as_object().expect("object").clone()),
        ..spec("dv")
    };

    let patch = data_views_ops::build_patch(&current, &desired).expect("patch");
    let base = serde_json::to_value(patch.base.expect("base")).expect("serialize");
    assert_eq!(
        base,
        json!({
            "allowNoIndex": false,
            "fieldFormats": {"bytes": {"id": "bytes"}},
            "fields": {"new": {"scripted": true, "script": "2"}},
            "name": "New name",
            "runtimeFieldMap": {"runtime": {"type": "keyword"}},
            "sourceFilters": [{"value": "secret"}],
            "timeFieldName": "event.created",
            "title": "logs-new-*",
            "type": "standard",
            "typeMeta": {"new": true}
        })
    );
    for forbidden in ["id", "allowHidden", "fieldAttrs"] {
        assert!(base.get(forbidden).is_none());
    }
    assert_eq!(
        patch.field_metadata,
        json!({
            "a": {"added": 2, "changed": 3, "removed": null},
            "m": {"new": true},
            "z": {"removed": null}
        })
        .as_object()
        .expect("object")
        .clone()
    );
    assert_eq!(
        patch.field_metadata.keys().collect::<Vec<_>>(),
        vec!["a", "m", "z"]
    );
    assert_eq!(
        patch.field_metadata["a"]
            .as_object()
            .expect("object")
            .keys()
            .collect::<Vec<_>>(),
        vec!["added", "changed", "removed"]
    );
}

#[tokio::test]
async fn apply_import_rejects_public_plan_tampering_before_any_http() {
    let server = MockServer::start().await;
    let desired = spec("dv");
    let cases = [
        {
            let mut plan = import_plan(
                vec![desired.clone()],
                BTreeMap::from([("dv".into(), None)]),
                BTreeMap::new(),
            );
            plan.preview.targets = vec!["shown".into()];
            plan
        },
        {
            let mut plan = import_plan(
                vec![desired.clone()],
                BTreeMap::from([("dv".into(), None)]),
                BTreeMap::new(),
            );
            plan.preview.preview_details = vec!["shown  create  logs-*".into()];
            plan
        },
        {
            let before = DataViewSpec {
                title: "logs-old-*".into(),
                ..desired.clone()
            };
            let patch = data_views_ops::build_patch(&before, &desired).expect("patch");
            let mut plan = import_plan(
                vec![desired.clone()],
                BTreeMap::from([("dv".into(), Some(before))]),
                BTreeMap::from([("dv".into(), patch)]),
            );
            plan.overwrite = false;
            plan
        },
        {
            let before = DataViewSpec {
                title: "logs-old-*".into(),
                ..desired.clone()
            };
            let mut plan = import_plan(
                vec![desired.clone()],
                BTreeMap::from([("dv".into(), Some(before))]),
                BTreeMap::from([("dv".into(), DataViewPatch::default())]),
            );
            plan.patches.get_mut("dv").expect("patch").base = Some(DataViewUpdate::default());
            plan
        },
        {
            let mut plan = import_plan(
                vec![desired.clone()],
                BTreeMap::from([("dv".into(), None)]),
                BTreeMap::new(),
            );
            plan.specs.push(desired.clone());
            plan
        },
        {
            let first = spec("a");
            let second = spec("b");
            let mut plan = import_plan(
                vec![first, second],
                BTreeMap::from([("a".into(), None), ("b".into(), None)]),
                BTreeMap::new(),
            );
            plan.before.remove("b");
            plan
        },
        {
            let mut plan = import_plan(
                vec![spec("b"), spec("a")],
                BTreeMap::from([("a".into(), None), ("b".into(), None)]),
                BTreeMap::new(),
            );
            plan.preview.targets = vec!["b".into(), "a".into()];
            plan
        },
        {
            let before = DataViewSpec {
                title: "logs-old-*".into(),
                ..desired.clone()
            };
            import_plan(
                vec![desired.clone()],
                BTreeMap::from([("dv".into(), Some(before))]),
                BTreeMap::new(),
            )
        },
        {
            let mut plan = import_plan(
                vec![desired.clone()],
                BTreeMap::from([("dv".into(), None)]),
                BTreeMap::new(),
            );
            plan.patches.insert("dv".into(), DataViewPatch::default());
            plan
        },
        {
            let mut plan = import_plan(
                vec![desired.clone()],
                BTreeMap::from([("dv".into(), None)]),
                BTreeMap::new(),
            );
            plan.total = 2;
            plan.skipped = vec![json!({"id": "other", "reason": "wrong"})];
            plan
        },
        {
            let noncanonical = DataViewSpec {
                type_meta: Some(serde_json::Map::new()),
                ..desired.clone()
            };
            import_plan(
                vec![noncanonical],
                BTreeMap::from([("dv".into(), None)]),
                BTreeMap::new(),
            )
        },
    ];

    for plan in cases {
        assert!(
            data_views_ops::apply_import(&transport(&server), &plan)
                .await
                .is_err()
        );
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn apply_import_rejects_a_wrong_embedded_detail_id_without_writing() {
    let server = MockServer::start().await;
    let desired = spec("dv");
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(spec("other"))))
        .expect(1)
        .mount(&server)
        .await;
    let plan = import_plan(
        vec![desired.clone()],
        BTreeMap::from([("dv".into(), Some(desired))]),
        BTreeMap::from([("dv".into(), DataViewPatch::default())]),
    );

    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("partial report");

    assert_eq!(report.failed[0]["applied"], false);
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
}

#[tokio::test]
async fn apply_import_refuses_disappeared_replacements_and_changed_no_ops_without_writes() {
    for (before, desired, patch) in [
        {
            let before = DataViewSpec {
                title: "logs-old-*".into(),
                ..spec("replace")
            };
            let desired = DataViewSpec {
                title: "logs-new-*".into(),
                ..spec("replace")
            };
            let patch = data_views_ops::build_patch(&before, &desired).expect("patch");
            (before, desired, patch)
        },
        {
            let before = spec("no-op");
            (before.clone(), before, DataViewPatch::default())
        },
    ] {
        let server = MockServer::start().await;
        let current = if desired.id == "replace" {
            None
        } else {
            Some(DataViewSpec {
                title: "logs-raced-*".into(),
                ..desired.clone()
            })
        };
        Mock::given(method("GET"))
            .and(path(format!("/api/data_views/data_view/{}", desired.id)))
            .respond_with(match current {
                Some(current) => ResponseTemplate::new(200).set_body_json(response(current)),
                None => ResponseTemplate::new(404).set_body_json(json!({"message": "missing"})),
            })
            .expect(1)
            .mount(&server)
            .await;
        let id = desired.id.clone();
        let plan = import_plan(
            vec![desired],
            BTreeMap::from([(id.clone(), Some(before))]),
            BTreeMap::from([(id, patch)]),
        );

        let report = data_views_ops::apply_import(&transport(&server), &plan)
            .await
            .expect("report");
        assert_eq!(report.failed[0]["applied"], false);
        assert_eq!(server.received_requests().await.expect("requests").len(), 1);
    }
}

#[tokio::test]
async fn apply_import_reports_lossy_replacement_and_metadata_only_failure() {
    let before = DataViewSpec {
        title: "logs-old-*".into(),
        ..spec("lossy")
    };
    let desired = DataViewSpec {
        title: "logs-new-*".into(),
        ..spec("lossy")
    };
    let patch = data_views_ops::build_patch(&before, &desired).expect("patch");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/lossy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(before.clone())))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view/lossy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(desired.clone())))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/lossy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(before.clone())))
        .mount(&server)
        .await;
    let plan = import_plan(
        vec![desired],
        BTreeMap::from([("lossy".into(), Some(before))]),
        BTreeMap::from([("lossy".into(), patch)]),
    );
    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("report");
    assert_eq!(
        report.failed[0],
        json!({"id":"lossy","applied":true,"error":"server stored a different data-view spec"})
    );

    let before = DataViewSpec {
        field_attrs: json!({"host.name": {"customLabel": "Old"}})
            .as_object()
            .expect("object")
            .clone(),
        ..spec("metadata")
    };
    let desired = DataViewSpec {
        field_attrs: json!({"host.name": {"customLabel": "New"}})
            .as_object()
            .expect("object")
            .clone(),
        ..spec("metadata")
    };
    let patch = data_views_ops::build_patch(&before, &desired).expect("patch");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(before.clone())))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view/metadata/fields"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"message": "failed"})))
        .mount(&server)
        .await;
    let plan = import_plan(
        vec![desired],
        BTreeMap::from([("metadata".into(), Some(before))]),
        BTreeMap::from([("metadata".into(), patch)]),
    );
    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("report");
    assert_eq!(
        report.failed[0],
        json!({"id":"metadata","applied":false,"error":"field metadata failed: failed"})
    );
}

#[tokio::test]
async fn apply_import_keeps_applied_false_for_malformed_success_responses() {
    let desired = spec("create");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/create"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "missing"})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let plan = import_plan(
        vec![desired],
        BTreeMap::from([("create".into(), None)]),
        BTreeMap::new(),
    );
    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("report");
    assert_eq!(report.failed[0]["applied"], false);

    let before = DataViewSpec {
        title: "logs-old-*".into(),
        ..spec("base")
    };
    let desired = DataViewSpec {
        title: "logs-new-*".into(),
        ..spec("base")
    };
    let patch = data_views_ops::build_patch(&before, &desired).expect("patch");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/base"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(before.clone())))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view/base"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let plan = import_plan(
        vec![desired],
        BTreeMap::from([("base".into(), Some(before))]),
        BTreeMap::from([("base".into(), patch)]),
    );
    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("report");
    assert_eq!(report.failed[0]["applied"], false);

    let before = DataViewSpec {
        field_attrs: json!({"host.name": {"customLabel": "Old"}})
            .as_object()
            .expect("object")
            .clone(),
        ..spec("metadata")
    };
    let desired = DataViewSpec {
        field_attrs: json!({"host.name": {"customLabel": "New"}})
            .as_object()
            .expect("object")
            .clone(),
        ..spec("metadata")
    };
    let patch = data_views_ops::build_patch(&before, &desired).expect("patch");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(before.clone())))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view/metadata/fields"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": false})))
        .mount(&server)
        .await;
    let plan = import_plan(
        vec![desired],
        BTreeMap::from([("metadata".into(), Some(before))]),
        BTreeMap::from([("metadata".into(), patch)]),
    );
    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("report");
    assert_eq!(report.failed[0]["applied"], false);
}

#[test]
fn import_report_preserves_per_row_key_order() {
    let report = elasticctl_api::DataViewImportReport {
        applied: true,
        succeeded: vec![json!({"id": "dv", "action": "created"})],
        skipped: vec![json!({"id": "old", "reason": "exists"})],
        failed: vec![json!({"id": "bad", "applied": false, "error": "nope"})],
        total: 3,
    };
    assert_eq!(
        serde_json::to_string(&report).expect("serialize"),
        "{\"applied\":true,\"succeeded\":[{\"id\":\"dv\",\"action\":\"created\"}],\"skipped\":[{\"id\":\"old\",\"reason\":\"exists\"}],\"failed\":[{\"id\":\"bad\",\"applied\":false,\"error\":\"nope\"}],\"total\":3}"
    );
}

#[tokio::test]
async fn apply_import_accepts_an_all_skipped_plan_without_http() {
    let server = MockServer::start().await;
    let plan = DataViewImportPlan {
        preview: MutationPlan {
            preview_action: "Import 0 data view(s) from test".into(),
            preview_details: Vec::new(),
            targets: Vec::new(),
        },
        specs: Vec::new(),
        before: BTreeMap::new(),
        patches: BTreeMap::new(),
        skipped: vec![json!({"id": "dv", "reason": "exists"})],
        total: 1,
        overwrite: false,
    };

    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("all skipped report");

    assert_eq!(report.skipped, plan.skipped);
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn apply_import_rejects_noncanonical_or_overwrite_skipped_rows_before_http() {
    let server = MockServer::start().await;
    let valid = || DataViewImportPlan {
        preview: MutationPlan {
            preview_action: "Import 0 data view(s) from test".into(),
            preview_details: Vec::new(),
            targets: Vec::new(),
        },
        specs: Vec::new(),
        before: BTreeMap::new(),
        patches: BTreeMap::new(),
        skipped: vec![
            json!({"id": "a", "reason": "exists"}),
            json!({"id": "z", "reason": "exists"}),
        ],
        total: 2,
        overwrite: false,
    };
    let mut reversed_rows = valid();
    reversed_rows.skipped.reverse();
    let mut reversed_keys = valid();
    reversed_keys.skipped = vec![json!({"reason": "exists", "id": "a"})];
    reversed_keys.total = 1;
    let mut overwrite = valid();
    overwrite.overwrite = true;

    for plan in [reversed_rows, reversed_keys, overwrite] {
        assert!(
            data_views_ops::apply_import(&transport(&server), &plan)
                .await
                .is_err()
        );
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}

#[tokio::test]
async fn plan_skip_existing_all_then_apply_retains_canonical_zero_target_plan() {
    let server = MockServer::start().await;
    for id in ["a", "b"] {
        Mock::given(method("GET"))
            .and(path(format!("/api/data_views/data_view/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(response(spec(id))))
            .expect(1)
            .mount(&server)
            .await;
    }
    let path = artifact(&[spec("b"), spec("a")]);

    let plan = data_views_ops::plan_import(Some(&transport(&server)), &path, false, true)
        .await
        .expect("all skipped plan");

    assert_eq!(plan.total, 2);
    assert!(plan.specs.is_empty());
    assert_eq!(plan.preview.targets, Vec::<String>::new());
    assert!(plan.preview.preview_details.is_empty());
    assert_eq!(
        plan.skipped,
        vec![
            json!({"id": "a", "reason": "exists"}),
            json!({"id": "b", "reason": "exists"}),
        ]
    );
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("plan requests")
            .len(),
        2
    );

    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("all skipped apply");

    assert_eq!(report.total, 2);
    assert_eq!(report.skipped, plan.skipped);
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("all requests")
            .len(),
        2
    );
}

#[tokio::test]
async fn plan_import_is_local_without_conflict_flags() {
    let path = artifact(&[spec("dv-new")]);

    let plan = data_views_ops::plan_import(None, &path, false, false)
        .await
        .expect("local plan");

    assert_eq!(plan.total, 1);
    assert_eq!(plan.specs, vec![spec("dv-new")]);
    assert_eq!(
        plan.preview.preview_details,
        vec!["dv-new  create  logs-security-*"]
    );
    assert_eq!(plan.before.get("dv-new"), Some(&None));
    assert!(plan.patches.is_empty());
}

#[tokio::test]
async fn plan_import_refuses_every_default_conflict() {
    let server = MockServer::start().await;
    for id in ["dv-a", "dv-b"] {
        Mock::given(method("GET"))
            .and(path(format!("/api/data_views/data_view/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(response(spec(id))))
            .expect(1)
            .mount(&server)
            .await;
    }
    let path = artifact(&[spec("dv-b"), spec("dv-a")]);

    let error = data_views_ops::plan_import(Some(&transport(&server)), &path, false, false)
        .await
        .expect_err("existing views must conflict");

    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(error.message, "data views already exist: dv-a, dv-b");
}

#[tokio::test]
async fn plan_import_skips_existing_views() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv-old"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(spec("dv-old"))))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv-new"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "missing"})))
        .expect(1)
        .mount(&server)
        .await;
    let path = artifact(&[spec("dv-old"), spec("dv-new")]);

    let plan = data_views_ops::plan_import(Some(&transport(&server)), &path, false, true)
        .await
        .expect("skip plan");

    assert_eq!(plan.specs, vec![spec("dv-new")]);
    assert_eq!(
        plan.skipped,
        vec![json!({"id": "dv-old", "reason": "exists"})]
    );
    assert_eq!(
        plan.preview.preview_details,
        vec!["dv-new  create  logs-security-*"]
    );
}

#[tokio::test]
async fn plan_import_overwrite_classifies_create_replace_and_no_op() {
    let server = MockServer::start().await;
    let same = DataViewSpec {
        title: "logs-same-*".into(),
        ..spec("dv-same")
    };
    let old = DataViewSpec {
        title: "logs-old-*".into(),
        ..spec("dv-old")
    };
    for (id, detail) in [
        ("dv-same", Some(same)),
        ("dv-old", Some(old)),
        ("dv-new", None),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/api/data_views/data_view/{id}")))
            .respond_with(match detail {
                Some(spec) => ResponseTemplate::new(200).set_body_json(response(spec)),
                None => ResponseTemplate::new(404).set_body_json(json!({"message": "missing"})),
            })
            .expect(1)
            .mount(&server)
            .await;
    }
    let desired_same = DataViewSpec {
        title: "logs-same-*".into(),
        ..spec("dv-same")
    };
    let desired_old = DataViewSpec {
        title: "logs-new-*".into(),
        ..spec("dv-old")
    };
    let desired_new = DataViewSpec {
        title: "logs-new-*".into(),
        ..spec("dv-new")
    };
    let path = artifact(&[
        desired_old.clone(),
        desired_new.clone(),
        desired_same.clone(),
    ]);

    let plan = data_views_ops::plan_import(Some(&transport(&server)), &path, true, false)
        .await
        .expect("overwrite plan");

    assert_eq!(plan.specs, vec![desired_new, desired_old, desired_same]);
    assert_eq!(
        plan.preview.preview_details,
        vec![
            "dv-new  create  logs-new-*",
            "dv-old  replace  logs-old-* -> logs-new-*",
            "dv-same  no-op  logs-same-*",
        ]
    );
}

#[test]
fn build_patch_rejects_unsupported_data_view_deltas() {
    let current = spec("dv");
    let same_hidden = DataViewSpec {
        allow_hidden: false,
        ..current.clone()
    };
    assert!(data_views_ops::build_patch(&current, &same_hidden).is_ok());

    let typed = DataViewSpec {
        view_type: Some("rollup".into()),
        ..current.clone()
    };
    let type_meta = DataViewSpec {
        type_meta: Some(json!({"x": 1}).as_object().expect("object").clone()),
        ..current.clone()
    };
    for (before, desired) in [
        (
            current.clone(),
            DataViewSpec {
                allow_hidden: true,
                ..current.clone()
            },
        ),
        (
            current.clone(),
            DataViewSpec {
                name: None,
                ..current.clone()
            },
        ),
        (
            current.clone(),
            DataViewSpec {
                time_field_name: None,
                ..current.clone()
            },
        ),
        (
            typed.clone(),
            DataViewSpec {
                view_type: None,
                ..typed
            },
        ),
        (
            type_meta.clone(),
            DataViewSpec {
                type_meta: None,
                ..type_meta
            },
        ),
    ] {
        let error = data_views_ops::build_patch(&before, &desired).expect_err("unsupported delta");
        assert_eq!(error.kind, ErrorKind::Unsupported);
    }
}

#[tokio::test]
async fn apply_import_refuses_a_create_that_appeared_after_planning() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(spec("dv"))))
        .expect(1)
        .mount(&server)
        .await;
    let plan = import_plan(
        vec![spec("dv")],
        BTreeMap::from([("dv".into(), None)]),
        BTreeMap::new(),
    );

    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("partial report");

    assert_eq!(
        report.failed,
        vec![json!({"id": "dv", "applied": false, "error": "data view appeared since preview"})]
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1, "a raced create must not post");
}

#[tokio::test]
async fn apply_import_refuses_a_replacement_that_changed_after_planning() {
    let server = MockServer::start().await;
    let old = DataViewSpec {
        title: "logs-old-*".into(),
        ..spec("dv")
    };
    let changed = DataViewSpec {
        title: "logs-raced-*".into(),
        ..spec("dv")
    };
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(changed)))
        .expect(1)
        .mount(&server)
        .await;
    let desired = DataViewSpec {
        title: "logs-new-*".into(),
        ..spec("dv")
    };
    let patch = data_views_ops::build_patch(&old, &desired).expect("patch");
    let plan = import_plan(
        vec![desired],
        BTreeMap::from([("dv".into(), Some(old))]),
        BTreeMap::from([("dv".into(), patch)]),
    );

    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("partial report");

    assert_eq!(
        report.failed,
        vec![json!({"id": "dv", "applied": false, "error": "data view changed since preview"})]
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
}

#[tokio::test]
async fn apply_import_creates_then_reads_and_checks_the_stored_spec() {
    let server = MockServer::start().await;
    let desired = DataViewSpec {
        title: "logs-new-*".into(),
        ..spec("dv")
    };
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "missing"})))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view"))
        .and(body_json(json!({"data_view": desired, "override": false})))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(desired.clone())))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(desired.clone())))
        .expect(1)
        .mount(&server)
        .await;
    let plan = import_plan(
        vec![desired],
        BTreeMap::from([("dv".into(), None)]),
        BTreeMap::new(),
    );

    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("report");

    assert_eq!(
        report.succeeded,
        vec![json!({"id": "dv", "action": "created"})]
    );
}

#[tokio::test]
async fn apply_import_updates_base_then_metadata_then_reads() {
    let server = MockServer::start().await;
    let before = DataViewSpec {
        title: "logs-old-*".into(),
        ..spec("dv")
    };
    let desired = DataViewSpec {
        title: "logs-new-*".into(),
        field_attrs: json!({"host.name": {"customLabel": "Host"}})
            .as_object()
            .expect("object")
            .clone(),
        ..spec("dv")
    };
    let patch = data_views_ops::build_patch(&before, &desired).expect("patch");
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(before.clone())))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view/dv"))
        .and(body_json(
            json!({"data_view": {"title": "logs-new-*"}, "refresh_fields": true}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(desired.clone())))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view/dv/fields"))
        .and(body_json(
            json!({"fields": {"host.name": {"customLabel": "Host"}}}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(desired.clone())))
        .expect(1)
        .mount(&server)
        .await;
    let plan = import_plan(
        vec![desired],
        BTreeMap::from([("dv".into(), Some(before))]),
        BTreeMap::from([("dv".into(), patch)]),
    );

    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("report");

    assert_eq!(
        report.succeeded,
        vec![json!({"id": "dv", "action": "replaced"})]
    );
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.url.path())
            .collect::<Vec<_>>(),
        vec![
            "/api/data_views/data_view/dv",
            "/api/data_views/data_view/dv",
            "/api/data_views/data_view/dv/fields",
            "/api/data_views/data_view/dv",
        ]
    );
}

#[tokio::test]
async fn apply_import_deletes_field_metadata_with_null() {
    let server = MockServer::start().await;
    let before = DataViewSpec {
        field_attrs: json!({"host.name": {"customLabel": "Host"}})
            .as_object()
            .expect("object")
            .clone(),
        ..spec("dv")
    };
    let desired = spec("dv");
    let patch = data_views_ops::build_patch(&before, &desired).expect("patch");
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(before.clone())))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view/dv/fields"))
        .and(body_json(
            json!({"fields":{"host.name":{"customLabel":null}}}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(desired.clone())))
        .expect(1)
        .mount(&server)
        .await;
    let plan = import_plan(
        vec![desired],
        BTreeMap::from([("dv".into(), Some(before))]),
        BTreeMap::from([("dv".into(), patch)]),
    );

    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("report");

    assert_eq!(
        report.succeeded,
        vec![json!({"id": "dv", "action": "replaced"})]
    );
}

#[tokio::test]
async fn apply_import_leaves_a_no_op_unchanged() {
    let server = MockServer::start().await;
    let desired = spec("dv");
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(desired.clone())))
        .expect(1)
        .mount(&server)
        .await;
    let plan = import_plan(
        vec![desired.clone()],
        BTreeMap::from([("dv".into(), Some(desired))]),
        BTreeMap::from([("dv".into(), DataViewPatch::default())]),
    );

    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("report");

    assert_eq!(
        report.succeeded,
        vec![json!({"id": "dv", "action": "unchanged"})]
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
}

#[tokio::test]
async fn apply_import_reports_a_metadata_failure_after_a_base_write() {
    let server = MockServer::start().await;
    let before = DataViewSpec {
        title: "logs-old-*".into(),
        ..spec("dv")
    };
    let desired = DataViewSpec {
        title: "logs-new-*".into(),
        field_attrs: json!({"host.name": {"customLabel": "Host"}})
            .as_object()
            .expect("object")
            .clone(),
        ..spec("dv")
    };
    let patch = data_views_ops::build_patch(&before, &desired).expect("patch");
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(before.clone())))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(desired.clone())))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view/dv/fields"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({"message": "request timed out"})),
        )
        .mount(&server)
        .await;
    let plan = import_plan(
        vec![desired],
        BTreeMap::from([("dv".into(), Some(before))]),
        BTreeMap::from([("dv".into(), patch)]),
    );

    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("report");

    assert_eq!(
        report.failed,
        vec![
            json!({"id":"dv","applied":true,"error":"base updated; field metadata failed: request timed out"})
        ]
    );
}

#[tokio::test]
async fn apply_import_reports_a_lossy_create_and_continues() {
    let server = MockServer::start().await;
    let desired_a = DataViewSpec {
        title: "logs-a-*".into(),
        ..spec("dv-a")
    };
    let desired_b = DataViewSpec {
        title: "logs-b-*".into(),
        ..spec("dv-b")
    };
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv-a"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message":"missing"})))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view"))
        .and(body_json(
            json!({"data_view": desired_a, "override": false}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(desired_a.clone())))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv-a"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(spec("dv-a"))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv-b"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message":"missing"})))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/data_views/data_view"))
        .and(body_json(
            json!({"data_view": desired_b, "override": false}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(desired_b.clone())))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv-b"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response(desired_b.clone())))
        .mount(&server)
        .await;
    let plan = import_plan(
        vec![desired_a, desired_b],
        BTreeMap::from([("dv-a".into(), None), ("dv-b".into(), None)]),
        BTreeMap::new(),
    );

    let report = data_views_ops::apply_import(&transport(&server), &plan)
        .await
        .expect("report");

    assert_eq!(
        report.failed,
        vec![
            json!({"id":"dv-a","applied":true,"error":"server stored a different data-view spec"})
        ]
    );
    assert_eq!(
        report.succeeded,
        vec![json!({"id":"dv-b","action":"created"})]
    );
}

#[test]
fn apply_import_report_preserves_serialized_field_order() {
    let report = elasticctl_api::DataViewImportReport {
        applied: true,
        succeeded: Vec::new(),
        skipped: Vec::new(),
        failed: Vec::new(),
        total: 0,
    };
    assert_eq!(
        serde_json::to_string(&report).expect("serialize"),
        "{\"applied\":true,\"succeeded\":[],\"skipped\":[],\"failed\":[],\"total\":0}"
    );
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

async fn export_one_detail(format: ContentFormat, detail: Value) -> String {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view": [
                {"id": "dv", "title": "logs-*"}
            ]})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail))
        .mount(&server)
        .await;
    data_views_ops::export(&transport(&server), &["dv".into()], format)
        .await
        .expect("export")
        .body
}

#[tokio::test]
async fn export_canonicalizes_nested_objects_for_json_and_yaml() {
    let first = json!({"data_view": {
        "id": "dv", "title": "logs-*",
        "sourceFilters": [{"z": 3, "a": {"z": 2, "a": 1}}],
        "fieldFormats": {"z": {"z": 2, "a": 1}, "a": {"z": 4, "a": 3}},
        "runtimeFieldMap": {"z": {"z": 2, "a": 1}, "a": {"z": 4, "a": 3}},
        "fieldAttrs": {"z": {"z": 2, "a": 1}, "a": {"z": 4, "a": 3}},
        "fields": {"legacy": {"z": 2, "scripted": true, "a": 1}},
        "typeMeta": {"z": {"z": 2, "a": 1}, "a": {"z": 4, "a": 3}}
    }});
    let second = json!({"data_view": {
        "id": "dv", "title": "logs-*",
        "sourceFilters": [{"a": {"a": 1, "z": 2}, "z": 3}],
        "fieldFormats": {"a": {"a": 3, "z": 4}, "z": {"a": 1, "z": 2}},
        "runtimeFieldMap": {"a": {"a": 3, "z": 4}, "z": {"a": 1, "z": 2}},
        "fieldAttrs": {"a": {"a": 3, "z": 4}, "z": {"a": 1, "z": 2}},
        "fields": {"legacy": {"a": 1, "scripted": true, "z": 2}},
        "typeMeta": {"a": {"a": 3, "z": 4}, "z": {"a": 1, "z": 2}}
    }});

    for format in [ContentFormat::Json, ContentFormat::Yaml] {
        assert_eq!(
            export_one_detail(format, first.clone()).await,
            export_one_detail(format, second.clone()).await,
            "{format:?} export must not depend on server member order"
        );
    }
}

#[tokio::test]
async fn export_without_selectors_reads_every_data_view() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view": [
                {"id": "b", "title": "logs-b-*"}, {"id": "a", "title": "logs-a-*"}
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
                    "id": id, "title": title
                }})),
            )
            .expect(1)
            .mount(&server)
            .await;
    }

    let exported = data_views_ops::export(&transport(&server), &[], ContentFormat::Json)
        .await
        .expect("all data views");
    let specs: Vec<DataViewSpec> = serde_json::from_str(&exported.body).expect("portable JSON");
    assert_eq!(exported.exported, 2);
    assert_eq!(
        specs
            .iter()
            .map(|spec| spec.id.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );
}

#[tokio::test]
async fn export_deduplicates_selectors_by_stable_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/data_views"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view": [
                {"id": "dv", "name": "View", "title": "logs-*"}
            ]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/data_views/data_view/dv"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data_view": {
                "id": "dv", "title": "logs-*"
            }})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let exported = data_views_ops::export(
        &transport(&server),
        &["dv".into(), "View".into(), "dv".into()],
        ContentFormat::Json,
    )
    .await
    .expect("deduplicated export");
    assert_eq!(exported.exported, 1);
}

#[tokio::test]
async fn export_rejects_malformed_or_mismatched_live_details_as_http() {
    for detail in [
        json!({"data_view": {"id": "dv", "title": 7}}),
        json!({"data_view": {"id": "other", "title": "logs-*"}}),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/data_views"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"data_view": [
                    {"id": "dv", "title": "logs-*"}
                ]})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/data_view/dv"))
            .respond_with(ResponseTemplate::new(200).set_body_json(detail))
            .mount(&server)
            .await;

        let error =
            data_views_ops::export(&transport(&server), &["dv".into()], ContentFormat::Json)
                .await
                .expect_err("invalid live detail");
        assert_eq!(error.kind, ErrorKind::Http);
    }
}
