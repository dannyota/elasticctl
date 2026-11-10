use elasticctl_api::{Observed, Preconditions, health::credential_identity, require_rule_identity};
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn fixture(set: &str, name: &str) -> Value {
    let file = format!(
        "{}/../../tests/fixtures/{set}/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str::<Value>(&std::fs::read_to_string(file).unwrap()).unwrap()["response"]
        .clone()
}

fn transport(uri: &str) -> Transport {
    Transport::new(&Profile {
        kibana_url: uri.into(),
        es_url: Some(uri.into()),
        api_key: Some("test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .unwrap()
}

async fn identity(body: Value) -> elasticctl_core::Result<elasticctl_api::CredentialIdentity> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_security/_authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    credential_identity(&transport(&server.uri())).await
}

#[test]
fn preconditions_sorted_orders_by_object_then_id() {
    let entry = |object, id: &str, state| Observed {
        object,
        id: id.into(),
        state,
    };
    let seen = Preconditions(vec![
        entry("rule", "z", Some(json!({ "rule_id": "z" }))),
        entry("alert", "b", None),
        entry("rule", "a", None),
        entry("alert", "a", Some(json!({}))),
    ])
    .sorted();
    assert_eq!(
        seen.0
            .iter()
            .map(|s| (s.object, s.id.as_str()))
            .collect::<Vec<_>>(),
        vec![("alert", "a"), ("alert", "b"), ("rule", "a"), ("rule", "z")]
    );
}

#[test]
fn require_rule_identity_checks_present_rules_and_ignores_other_entries() {
    let entry = |object, id: &str, state| Observed {
        object,
        id: id.into(),
        state,
    };
    let seen = Preconditions(vec![
        entry("rule", "z", Some(json!({ "rule_id": "z" }))),
        entry("rule", "a", None),
        entry("alert", "a", Some(json!({}))),
    ]);
    require_rule_identity(&seen).unwrap();
    for state in [
        json!({ "rule_id": "b" }),
        json!({}),
        json!({ "rule_id": 4 }),
        json!(null),
    ] {
        let bad = Preconditions(vec![entry("rule", "a", Some(state))]);
        let e = require_rule_identity(&bad).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Conflict);
        assert_eq!(e.message, "a rule read returned a different rule_id");
    }
}

#[tokio::test]
async fn credential_identity_decodes_recorded_responses() {
    for set in ["ech-9.5.2", "serverless-9.7.0", "traditional-9.5.1"] {
        let body = fixture(set, "authenticate");
        let got = identity(body.clone()).await.unwrap();
        assert_eq!(got.username, body["username"].as_str().unwrap());
        assert_eq!(
            got.realm_type,
            body["authentication_realm"]["type"].as_str().unwrap()
        );
        assert_eq!(
            got.api_key_id.as_deref(),
            body.pointer("/api_key/id").and_then(Value::as_str)
        );
    }
}

#[tokio::test]
async fn credential_identity_without_api_key_has_no_key_id() {
    let mut base = fixture("traditional-9.5.1", "authenticate");
    base.as_object_mut().unwrap().remove("api_key");
    for key in [None, Some(json!(null)), Some(json!({}))] {
        let mut body = base.clone();
        if let Some(key) = key {
            body["api_key"] = key;
        }
        assert_eq!(identity(body).await.unwrap().api_key_id, None);
    }
}

#[tokio::test]
async fn credential_identity_rejects_invalid_api_key() {
    let base = fixture("traditional-9.5.1", "authenticate");
    for key in [
        json!(false),
        json!([]),
        json!({ "id": null }),
        json!({ "id": 3 }),
        json!({ "id": "" }),
    ] {
        let mut body = base.clone();
        body["api_key"] = key;
        assert_eq!(identity(body).await.unwrap_err().kind, ErrorKind::Http);
    }
}

#[tokio::test]
async fn credential_identity_rejects_missing_username_or_realm_type() {
    let base = fixture("traditional-9.5.1", "authenticate");
    let mut missing_username = base.clone();
    missing_username.as_object_mut().unwrap().remove("username");
    let mut missing_realm_type = base.clone();
    missing_realm_type["authentication_realm"]
        .as_object_mut()
        .unwrap()
        .remove("type");
    for body in [missing_username, missing_realm_type] {
        assert_eq!(identity(body).await.unwrap_err().kind, ErrorKind::Http);
    }
}
