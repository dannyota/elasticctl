use super::*;

#[test]
fn common_identity_preserves_markers_and_redacts_only_whole_tokens() {
    let mut evidence = Evidence::default();
    evidence.private(ABSENT.into());
    evidence.private("unique-recorder-nonce".into());
    let prose = "user elastic cannot import elasticctl-live-vl-absent";
    evidence.exchange(
        "common_identity",
        json!({"nested": [prose, "(elastic)", "tag-unique-recorder-nonce-end"]}),
        json!({
            "created_by": "elastic", "updated_by": "elastic",
            "id": "elasticctl-live-vl-record", "message": prose,
            "boundaries": ["elastic", "elastic elastic", "éelasticé", "(elastic)",
                "xelastic elasticx 1elastic elastic1 _elastic elastic_ -elastic elastic-"],
            "_version": "elastic"
        }),
    );
    let document = &evidence.fixtures[0].document;
    assert!(!document.to_string().contains("REDACTEDctl"), "{document}");
    assert_eq!(
        document["response"]["id"],
        "elasticctl-fixture-value-list-id-3"
    );
    assert_eq!(
        document["response"]["message"],
        "user REDACTED cannot import REDACTED"
    );
    assert_eq!(
        document["request"]["nested"],
        json!([
            "user REDACTED cannot import REDACTED",
            "(REDACTED)",
            "tag-REDACTED-end"
        ])
    );
    assert_eq!(
        document["response"]["boundaries"],
        json!([
            "REDACTED",
            "REDACTED REDACTED",
            "éREDACTEDé",
            "(REDACTED)",
            "xelastic elasticx 1elastic elastic1 _elastic elastic_ -elastic elastic-"
        ])
    );
    assert_eq!(document["response"]["_version"], "elastic");
}

async fn recording_for_user(user: &'static str) -> std::collections::BTreeMap<String, Vec<u8>> {
    let (server, _) = stack(Stack {
        created_by: Some(user),
        ..Stack::default()
    })
    .await;
    let t = transport(&server);
    let mut session = Session::new(
        &t,
        Timing {
            budget: Duration::from_secs(1),
            ..fast()
        },
    );
    let recording = run(&mut session, Some("ech".into()), std::future::pending::<()>)
        .await
        .unwrap();
    let dir = std::env::temp_dir().join(format!(
        "value-list-common-user-{}",
        server.address().port()
    ));
    write_recording(Recording {
        dir: dir.clone(),
        ..recording
    })
    .unwrap();
    let files = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_str().unwrap().to_string(),
                std::fs::read(path).unwrap(),
            )
        })
        .collect();
    std::fs::remove_dir_all(dir).unwrap();
    files
}

#[tokio::test]
async fn common_identity_recording_preserves_markers_text_and_versions() {
    let ordinary = recording_for_user("private-operator").await;
    let common = recording_for_user("elastic").await;
    for (name, bytes) in &common {
        let text = std::str::from_utf8(bytes).unwrap();
        assert!(!text.contains("REDACTEDctl"), "{name}: {text}");
    }
    let create: serde_json::Value =
        serde_json::from_slice(&common["container_create.json"]).unwrap();
    for root in ["request", "response"] {
        assert_eq!(create[root]["id"], "elasticctl-fixture-value-list-id-3");
        assert_eq!(create[root]["description"], "elasticctl-live-marker");
        assert_eq!(create[root]["meta"]["recorder_nonce"], "REDACTED");
    }
    // Comparing written bytes covers import/export text and every opaque version.
    assert_eq!(common, ordinary);
}

#[test]
fn user_field_values_are_private_in_same_and_later_prose() {
    for field in [
        "created_by",
        "updated_by",
        "username",
        "full_name",
        "email",
        "closed_by",
        "pushed_by",
        "realm_name",
        "kibana.alert.rule.CREATED_BY",
    ] {
        let mut evidence = Evidence::default();
        evidence.response(
            "create",
            json!({
                field: {"identity": ["private-operator", "private-profile"]},
                "message": "created by private-operator (private-profile)"
            }),
        );
        evidence.http_response(
            "refused",
            409,
            json!({
                "message": "private-operator (private-profile) cannot import"
            }),
        );
        for fixture in &evidence.fixtures {
            assert!(
                !fixture.document.to_string().contains("private-"),
                "{field}: {}",
                fixture.document
            );
        }
    }
}

async fn written_refusal(user_in_item: bool) {
    let (server, state) = stack(Stack::default()).await;
    Mock::given(method("POST"))
        .and(path(if user_in_item {
            "/api/lists/items"
        } else {
            "/api/lists"
        }))
        .respond_with(move |r: &Request| {
            let mut body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
            body["_version"] = json!("v1");
            body["created_by"] = json!("private-operator");
            if user_in_item {
                let value = body["value"].as_str().unwrap();
                if !value.contains('/') && !value.contains('-') {
                    body["value"] = json!(format!("{value}-{value}"));
                }
                let mut stored = body.clone();
                stored.as_object_mut().unwrap().remove("created_by");
                state
                    .lock()
                    .unwrap()
                    .values
                    .entry(body["list_id"].as_str().unwrap().into())
                    .or_default()
                    .push(stored);
            } else {
                state
                    .lock()
                    .unwrap()
                    .lists
                    .insert(body["id"].as_str().unwrap().into(), body.clone());
            }
            response(200, body)
        })
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_import"))
        .and(wiremock::matchers::query_param(
            "list_id",
            "elasticctl-live-vl-absent",
        ))
        .respond_with(response(
            409,
            json!({
                "status_code": 409,
                "message": "User private-operator cannot import into elasticctl-live-vl-absent"
            }),
        ))
        .with_priority(1)
        .mount(&server)
        .await;
    let t = transport(&server);
    let mut session = Session::new(
        &t,
        Timing {
            budget: Duration::from_secs(1),
            ..fast()
        },
    );
    let recording = run(&mut session, Some("ech".into()), std::future::pending::<()>)
        .await
        .unwrap();
    let dir = std::env::temp_dir().join(format!("value-list-prose-{}", server.address().port()));
    write_recording(Recording {
        dir: dir.clone(),
        ..recording
    })
    .unwrap();
    let body = std::fs::read_to_string(dir.join("import_absent_list.json")).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    let leaked: Vec<_> = ["private-operator", "elasticctl-live-vl-absent"]
        .into_iter()
        .filter(|value| body.contains(value))
        .collect();
    assert!(leaked.is_empty(), "leaked {leaked:?}: {body}");
    assert!(body.contains("cannot import into"));
}

#[tokio::test]
async fn written_refusal_scrubs_prior_user_and_absent_list_id() {
    written_refusal(false).await;
}

#[tokio::test]
async fn written_refusal_scrubs_user_from_unrecorded_item_create() {
    written_refusal(true).await;
}
