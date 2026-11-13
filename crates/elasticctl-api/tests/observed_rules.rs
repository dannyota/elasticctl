use elasticctl_api::{
    Rule, VOLATILE_FIELDS, normalize,
    observe::{self, Observed, Preconditions},
    rules_ops::{self, RuleCreateOutcome, RuleCreatePlan},
};
use elasticctl_api_test_support::MockStack;
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

const RULES: &str = "/api/detection_engine/rules";

fn fixture(source: &str) -> Value {
    let text = match source {
        "ech" => include_str!("../../../tests/fixtures/ech-9.5.2/rules_get.json"),
        "serverless" => include_str!("../../../tests/fixtures/serverless-9.7.0/rules_get.json"),
        "traditional" => include_str!("../../../tests/fixtures/traditional-9.5.1/rules_get.json"),
        _ => panic!("unknown fixture"),
    };
    serde_json::from_str::<Value>(text).unwrap()["response"].clone()
}

fn error_fixture() -> Value {
    serde_json::from_str::<Value>(include_str!(
        "../../../tests/fixtures/ech-9.5.2/case_conflict.json"
    ))
    .unwrap()["error"]
        .clone()
}

fn create_rule() -> Rule {
    let mut value = fixture("ech");
    let map = value.as_object_mut().unwrap();
    for key in VOLATILE_FIELDS {
        map.remove(key);
    }
    for key in ["exceptions_list", "actions", "response_actions"] {
        map.insert(key.into(), json!([]));
    }
    Rule::from_value(value).unwrap()
}

fn transport(server: &MockServer) -> Transport {
    Transport::new(&Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .unwrap()
}

async fn serve(server: &MockServer, verb: &str, status: u16, body: Value) {
    Mock::given(method(verb))
        .and(path(RULES))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(server)
        .await;
}

async fn observed(value: Value) -> Preconditions {
    let id = value["rule_id"].as_str().unwrap().to_owned();
    let stack = MockStack::with_rules(vec![value]).await;
    let state = rules_ops::observe_rules(stack.transport(), &[id])
        .await
        .unwrap();
    assert_eq!(stack.requests().await.len(), 1);
    state
}

async fn assert_refused(rule: Rule, kind: ErrorKind) {
    let stack = MockStack::with_rules(vec![]).await;
    let err = rules_ops::plan_create(stack.transport(), rule)
        .await
        .unwrap_err();
    assert_eq!(err.kind, kind);
    assert!(stack.requests().await.is_empty());
}

async fn plan(rule: Rule) -> (RuleCreatePlan, Preconditions) {
    let stack = MockStack::with_rules(vec![]).await;
    let result = rules_ops::plan_create(stack.transport(), rule)
        .await
        .unwrap();
    let requests = stack.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    result
}

#[tokio::test]
async fn existing_rules_return_canonical_state_for_each_fixture() {
    for flavor in ["ech", "serverless", "traditional"] {
        let value = fixture(flavor);
        let id = value["rule_id"].as_str().unwrap().to_owned();
        let expected = normalize::canonical(&Rule::from_value(value.clone()).unwrap()).into_value();
        let seen = observed(value).await;
        assert_eq!(
            seen,
            Preconditions(vec![Observed {
                object: "rule",
                id,
                state: Some(expected)
            }])
        );
    }
}

#[tokio::test]
async fn missing_rule_returns_absent_state() {
    let stack = MockStack::with_rules(vec![]).await;
    let seen = rules_ops::observe_rules(stack.transport(), &["missing".into()])
        .await
        .unwrap();
    assert_eq!(
        seen,
        Preconditions(vec![Observed {
            object: "rule",
            id: "missing".into(),
            state: None
        }])
    );
    let requests = stack.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
}

#[tokio::test]
async fn server_error_is_returned_with_status() {
    let server = MockServer::start().await;
    serve(&server, "GET", 500, error_fixture()).await;
    let err = rules_ops::observe_rules(&transport(&server), &["id".into()])
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Http);
    assert_eq!(err.http_status, Some(500));
    let requests = server.received_requests().await.unwrap();
    assert!(!requests.is_empty());
    assert!(
        requests
            .iter()
            .all(|r| r.method.as_str() == "GET" && r.url.path() == RULES)
    );
}

#[tokio::test]
async fn unchanged_rules_produce_equal_observations() {
    let value = fixture("ech");
    let id = value["rule_id"].as_str().unwrap().to_owned();
    let stack = MockStack::with_rules(vec![value]).await;
    let first = rules_ops::observe_rules(stack.transport(), std::slice::from_ref(&id))
        .await
        .unwrap();
    let second = rules_ops::observe_rules(stack.transport(), &[id])
        .await
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(stack.requests().await.len(), 2);
}

#[tokio::test]
async fn meaningful_rule_changes_change_observed_state() {
    let base = fixture("ech");
    let initial = observed(base.clone()).await;
    for (key, value) in [
        ("enabled", json!(true)),
        ("query", json!("changed query")),
        ("name", json!("changed name")),
    ] {
        let mut changed = base.clone();
        changed[key] = value;
        assert_ne!(initial, observed(changed).await, "{key}");
    }
}

#[tokio::test]
async fn volatile_rule_changes_leave_observed_state_equal() {
    let base = fixture("ech");
    let initial = observed(base.clone()).await;
    for (key, value) in [
        ("updated_at", json!("different")),
        ("revision", json!(12345)),
        ("execution_summary", json!({"status":"changed"})),
    ] {
        let mut changed = base.clone();
        changed[key] = value;
        assert_eq!(initial, observed(changed).await, "{key}");
    }
}

#[tokio::test]
async fn observation_matches_enabled_planner_by_id_and_name() {
    let value = fixture("ech");
    let id = value["rule_id"].as_str().unwrap().to_owned();
    let name = value["name"].as_str().unwrap().to_owned();
    let stack = MockStack::with_rules(vec![value]).await;
    let seen = rules_ops::observe_rules(stack.transport(), std::slice::from_ref(&id))
        .await
        .unwrap();
    for selector in [id, name] {
        let (_, planned) =
            rules_ops::plan_set_enabled_observed(stack.transport(), &[selector], true)
                .await
                .unwrap();
        assert_eq!(seen, planned);
    }
    let requests = stack.requests().await;
    assert_eq!(requests.len(), 5);
    assert!(requests.iter().all(|r| r.method == "GET"));
}

#[tokio::test]
async fn escape_alias_is_rejected_on_recheck_and_resolved_by_planner() {
    let mut value = fixture("ech");
    value["rule_id"] = json!("r\n");
    let server = MockServer::start().await;
    for id in ["r\\n", "r\n"] {
        Mock::given(method("GET"))
            .and(path(RULES))
            .and(query_param("rule_id", id))
            .respond_with(ResponseTemplate::new(200).set_body_json(value.clone()))
            .mount(&server)
            .await;
    }
    let t = transport(&server);
    let seen = rules_ops::observe_rules(&t, &["r\\n".into()])
        .await
        .unwrap();
    assert_eq!(seen.0.len(), 1);
    assert_eq!(seen.0[0].id, "r\\n");
    assert_eq!(seen.0[0].state.as_ref().unwrap()["rule_id"], "r\n");
    assert_eq!(
        observe::require_rule_identity(&seen).unwrap_err().kind,
        ErrorKind::Conflict
    );
    let (_, planned) = rules_ops::plan_set_enabled_observed(&t, &["r\\n".into()], false)
        .await
        .unwrap();
    assert_eq!(planned.0[0].id, "r\n");
    observe::require_rule_identity(&planned).unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|r| r.method.as_str() == "GET"));
}

#[tokio::test]
async fn invalid_rule_id_is_refused_without_request() {
    for value in [None, Some(json!(42))] {
        let mut input = create_rule().into_value();
        match value {
            Some(v) => input["rule_id"] = v,
            None => {
                input.as_object_mut().unwrap().remove("rule_id");
            }
        }
        let rule: Rule = serde_json::from_value(input).unwrap();
        assert_refused(rule, ErrorKind::Error).await;
    }
}

#[tokio::test]
async fn invalid_name_or_type_is_refused_without_request() {
    for key in ["name", "type"] {
        for value in [None, Some(json!(42))] {
            let mut rule = create_rule();
            match value {
                Some(v) => {
                    rule.as_map_mut().insert(key.into(), v);
                }
                None => {
                    rule.as_map_mut().remove(key);
                }
            }
            assert_refused(rule, ErrorKind::Error).await;
        }
    }
}

#[tokio::test]
async fn each_volatile_field_is_refused_without_request() {
    for key in VOLATILE_FIELDS {
        let mut rule = create_rule();
        rule.as_map_mut().insert(key.into(), Value::Null);
        assert_refused(rule, ErrorKind::Error).await;
    }
}

#[tokio::test]
async fn non_false_enabled_is_refused_without_request() {
    for value in [json!(true), json!("false"), Value::Null, json!(0)] {
        let mut rule = create_rule();
        rule.as_map_mut().insert("enabled".into(), value);
        assert_refused(rule, ErrorKind::Error).await;
    }
}

#[tokio::test]
async fn nonempty_dependencies_are_unsupported_and_empty_arrays_are_accepted() {
    for key in ["exceptions_list", "actions", "response_actions"] {
        for value in [json!(["item"]), Value::Null, json!({})] {
            let mut rule = create_rule();
            rule.as_map_mut().insert(key.into(), value);
            assert_refused(rule, ErrorKind::Unsupported).await;
        }
    }
    let (result, _) = plan(create_rule()).await;
    for key in ["exceptions_list", "actions", "response_actions"] {
        assert_eq!(result.rule.as_map()[key], json!([]));
    }
}

#[tokio::test]
async fn absent_and_false_enabled_are_stored_as_false() {
    for absent in [true, false] {
        let mut rule = create_rule();
        if absent {
            rule.as_map_mut().remove("enabled");
        } else {
            rule.as_map_mut().insert("enabled".into(), json!(false));
        }
        let (result, _) = plan(rule).await;
        assert_eq!(result.rule.as_map()["enabled"], false);
    }
}

#[tokio::test]
async fn existing_id_and_escape_alias_conflict_after_one_get() {
    for alias in [false, true] {
        let mut rule = create_rule();
        let mut value = fixture("ech");
        rule.as_map_mut().insert("rule_id".into(), json!("r\\n"));
        value["rule_id"] = if alias { json!("r\n") } else { json!("r\\n") };
        let server = MockServer::start().await;
        serve(&server, "GET", 200, value).await;
        let err = rules_ops::plan_create(&transport(&server), rule)
            .await
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Conflict);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method.as_str(), "GET");
        assert_eq!(
            requests[0]
                .url
                .query_pairs()
                .find(|(k, _)| k == "rule_id")
                .unwrap()
                .1,
            "r\\n"
        );
    }
}

#[tokio::test]
async fn create_precondition_is_exactly_one_absent_rule() {
    let rule = create_rule();
    let id = rule.rule_id().unwrap().to_owned();
    let (_, seen) = plan(rule).await;
    assert_eq!(
        seen,
        Preconditions(vec![Observed {
            object: "rule",
            id,
            state: None
        }])
    );
}

#[tokio::test]
async fn preview_has_action_target_and_one_line_per_field() {
    let rule = create_rule();
    let id = rule.rule_id().unwrap().to_owned();
    let (result, _) = plan(rule).await;
    assert_eq!(result.preview.preview_action, "Create 1 rule (disabled)");
    assert_eq!(result.preview.targets, vec![id]);
    assert_eq!(
        result.preview.preview_details.len(),
        result.rule.as_map().len()
    );
}

#[tokio::test]
async fn preview_sorts_keys_and_compact_nested_json() {
    let mut rule = create_rule();
    rule.as_map_mut()
        .insert("unknown".into(), json!({"z": 1, "a": {"z": 2, "a": 1}}));
    let (result, _) = plan(rule).await;
    let lines = &result.preview.preview_details;
    let keys: Vec<_> = lines
        .iter()
        .map(|line| line.split_once(": ").unwrap().0)
        .collect();
    assert!(
        keys.windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
    );
    assert!(
        lines
            .iter()
            .any(|line| line == "unknown: {\"a\":{\"a\":1,\"z\":2},\"z\":1}")
    );
    for line in lines {
        let (_, text) = line.split_once(": ").unwrap();
        let value: Value = serde_json::from_str(text).unwrap();
        assert_eq!(text, serde_json::to_string(&value).unwrap());
    }
}

#[tokio::test]
async fn preview_includes_full_known_and_unknown_fields() {
    let mut rule = create_rule();
    let fields = [
        ("threat_query", json!("threat query")),
        ("threat_mapping", json!(["mapping"])),
        ("filters", json!(["filter"])),
        ("threshold", json!(["threshold"])),
        ("new_terms_fields", json!(["field"])),
        ("unknown_field", json!(["unknown"])),
    ];
    for (key, value) in &fields {
        rule.as_map_mut().insert((*key).into(), value.clone());
    }
    let (result, _) = plan(rule).await;
    for (key, value) in fields {
        let expected = format!("{key}: {}", serde_json::to_string(&value).unwrap());
        assert!(
            result.preview.preview_details.contains(&expected),
            "{expected}"
        );
    }
    assert!(
        result
            .preview
            .preview_details
            .iter()
            .all(|line| !line.contains("other fields"))
    );
}

#[tokio::test]
async fn preview_escapes_query_control_characters() {
    let mut rule = create_rule();
    rule.as_map_mut()
        .insert("query".into(), json!("quoted \"value\"\nnext\ttab"));
    let (result, _) = plan(rule).await;
    assert!(
        result
            .preview
            .preview_details
            .iter()
            .any(|line| line == "query: \"quoted \\\"value\\\"\\nnext\\ttab\"")
    );
    assert!(
        result
            .preview
            .preview_details
            .iter()
            .all(|line| !line.contains(['\n', '\t']))
    );
}

#[tokio::test]
async fn preview_accepts_large_rules() {
    let mut rule = create_rule();
    rule.as_map_mut()
        .insert("large".into(), json!("x".repeat(60_000)));
    let (result, _) = plan(rule).await;
    assert!(
        result
            .preview
            .preview_details
            .iter()
            .any(|line| line == &format!("large: \"{}\"", "x".repeat(60_000)))
    );
}

#[tokio::test]
async fn apply_success_posts_disabled_rule_without_volatile_fields() {
    let rule = create_rule();
    let id = rule.rule_id().unwrap().to_owned();
    let (plan, _) = plan(rule).await;
    let mut response = fixture("ech");
    response["rule_id"] = json!(id);
    response["enabled"] = json!(false);
    let server = MockServer::start().await;
    serve(&server, "POST", 200, response).await;
    let outcome = rules_ops::apply_create(&transport(&server), &plan)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        RuleCreateOutcome {
            applied: true,
            rule_id: id,
            enabled: false
        }
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method.as_str(), "POST");
    assert_eq!(requests[0].url.path(), RULES);
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["enabled"], false);
    for key in VOLATILE_FIELDS {
        assert!(body.get(key).is_none(), "{key}");
    }
}

#[tokio::test]
async fn apply_rejects_mismatched_response_identity_or_enabled() {
    let (plan, _) = plan(create_rule()).await;
    for identity_mismatch in [true, false] {
        let mut response = fixture("ech");
        if identity_mismatch {
            response["rule_id"] = json!("other");
        } else {
            response["enabled"] = json!(true);
        }
        let server = MockServer::start().await;
        serve(&server, "POST", 200, response).await;
        let err = rules_ops::apply_create(&transport(&server), &plan)
            .await
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Http);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method.as_str(), "POST");
    }
}

#[tokio::test]
async fn apply_preserves_recorded_conflict_status() {
    let (plan, _) = plan(create_rule()).await;
    let server = MockServer::start().await;
    serve(&server, "POST", 409, error_fixture()).await;
    let err = rules_ops::apply_create(&transport(&server), &plan)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);
    assert_eq!(err.http_status, Some(409));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method.as_str(), "POST");
}

#[tokio::test]
async fn apply_refuses_non_false_enabled_before_request() {
    let (mut plan, _) = plan(create_rule()).await;
    let server = MockServer::start().await;
    for value in [
        Some(json!(true)),
        Some(json!("false")),
        Some(Value::Null),
        Some(json!(0)),
        None,
    ] {
        match value {
            Some(value) => {
                plan.rule.as_map_mut().insert("enabled".into(), value);
            }
            None => {
                plan.rule.as_map_mut().remove("enabled");
            }
        }
        let err = rules_ops::apply_create(&transport(&server), &plan)
            .await
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Error);
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn empty_and_duplicate_observations_preserve_requested_order() {
    let value = fixture("ech");
    let id = value["rule_id"].as_str().unwrap().to_owned();
    let stack = MockStack::with_rules(vec![value]).await;
    assert_eq!(
        rules_ops::observe_rules(stack.transport(), &[])
            .await
            .unwrap(),
        Preconditions::default()
    );
    assert!(stack.requests().await.is_empty());
    let seen = rules_ops::observe_rules(
        stack.transport(),
        &[id.clone(), "missing".into(), id.clone()],
    )
    .await
    .unwrap();
    assert_eq!(
        seen.0
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>(),
        vec![id.as_str(), "missing", id.as_str()]
    );
    assert_eq!(seen.0[0].state, seen.0[2].state);
    let requests = stack.requests().await;
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|r| r.method == "GET"));
}

async fn assert_mutated_plan_refused(key: &str, value: Option<Value>, kind: ErrorKind) {
    let (mut plan, _) = plan(create_rule()).await;
    match value {
        Some(value) => {
            plan.rule.as_map_mut().insert(key.into(), value);
        }
        None => {
            plan.rule.as_map_mut().remove(key);
        }
    }
    let server = MockServer::start().await;
    let err = rules_ops::apply_create(&transport(&server), &plan)
        .await
        .unwrap_err();
    assert_eq!(err.kind, kind);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn apply_refuses_mutated_actions() {
    assert_mutated_plan_refused("actions", Some(json!([{}])), ErrorKind::Unsupported).await;
}

#[tokio::test]
async fn apply_refuses_mutated_response_actions() {
    assert_mutated_plan_refused(
        "response_actions",
        Some(json!([{}])),
        ErrorKind::Unsupported,
    )
    .await;
}

#[tokio::test]
async fn apply_refuses_mutated_exceptions_list() {
    assert_mutated_plan_refused("exceptions_list", Some(json!([{}])), ErrorKind::Unsupported).await;
}

#[tokio::test]
async fn apply_refuses_mutated_volatile_field() {
    assert_mutated_plan_refused(VOLATILE_FIELDS[0], Some(Value::Null), ErrorKind::Error).await;
}

#[tokio::test]
async fn apply_refuses_removed_enabled() {
    assert_mutated_plan_refused("enabled", None, ErrorKind::Error).await;
}

#[tokio::test]
async fn preview_escapes_keys_and_sorts_original_bytes() {
    let mut rule = create_rule();
    for key in ["extra\nfield", "extra field", "q\"uote"] {
        rule.as_map_mut().insert(key.into(), json!(42));
    }
    let (result, _) = plan(rule).await;
    let lines = &result.preview.preview_details;
    assert_eq!(lines.len(), result.rule.as_map().len());
    assert!(lines.iter().all(|line| !line.contains('\n')));
    let newline = lines
        .iter()
        .position(|line| line == "extra\\nfield: 42")
        .unwrap();
    let space = lines
        .iter()
        .position(|line| line == "extra field: 42")
        .unwrap();
    assert!(newline < space);
    assert!(lines.iter().any(|line| line == "q\\\"uote: 42"));
}
