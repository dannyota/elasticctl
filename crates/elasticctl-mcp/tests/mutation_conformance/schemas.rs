use super::*;

const TOOLS: [&str; 11] = [
    "rules_set_enabled_plan",
    "rules_create_plan",
    "alerts_set_status_plan",
    "alerts_set_tags_plan",
    "cases_create_plan",
    "cases_comment_plan",
    "cases_set_status_plan",
    "plan_list",
    "plan_get",
    "plan_discard",
    "plan_apply",
];
fn validate(catalog: &Value, name: &str, r: &Value, error: bool) {
    assert_eq!(r["result"]["isError"], error, "{name}: {r}");
    let tool = catalog["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == name)
        .unwrap();
    let schema = &tool["outputSchema"];
    assert_eq!(schema["type"], "object", "{name}: {schema}");
    for branch in ["ToolSuccess", "ToolFailure"] {
        let required = schema["$defs"][branch]["required"]
            .as_array()
            .unwrap_or_else(|| panic!("{name}: {branch} has no required fields"));
        assert!(
            !required.is_empty(),
            "{name}: {branch} has no required fields"
        );
    }
    assert!(
        schema["$defs"]["ToolSuccess"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("data"))
    );
    let validator = jsonschema::validator_for(schema).unwrap();
    assert!(
        !validator.is_valid(&json!({})),
        "{name}: accepts empty object"
    );
    let c = content(r);
    let errors: Vec<_> = validator.iter_errors(c).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "{name}: {errors:?}: {r}");
    let mut broken = c.clone();
    if error {
        broken["error"]["code"] = json!(123);
    } else {
        assert!(broken.as_object_mut().unwrap().remove("data").is_some());
    }
    assert!(
        !validator.is_valid(&broken),
        "{name}: accepts malformed payload: {broken}"
    );
    let permissive = jsonschema::validator_for(&json!({})).unwrap();
    assert!(permissive.is_valid(&json!({})) && permissive.is_valid(&broken));
    let text: Value =
        serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(&text, c);
}
#[tokio::test]
async fn all_eleven_mutation_output_schemas_success_and_error() {
    let (s, mut h) = setup().await;
    for (verb, route, body) in [
        (
            "GET",
            "/api/cases/elasticctl-fixture-case",
            fixture("case_get"),
        ),
        (
            "POST",
            "/api/detection_engine/signals/search",
            fixture("signals_search"),
        ),
    ] {
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&s)
            .await;
    }
    write_mock(&s, 1, 200).await;
    h.send_json(json!({"jsonrpc":"2.0","id":99,"method":"tools/list","params":{"_meta":meta()}}))
        .await;
    let catalog = receive(&mut h).await;
    let actual: Vec<_> = catalog["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .filter(|n| n.ends_with("_plan") || n.starts_with("plan_"))
        .collect();
    assert_eq!(actual.len(), TOOLS.len());
    assert!(TOOLS.iter().all(|name| actual.contains(name)));
    let alert = fixture("signals_search")["hits"]["hits"][0]["_id"].clone();
    for (name, args) in [
        (
            "rules_set_enabled_plan",
            json!({"selectors":["r"],"enabled":false}),
        ),
        (
            "rules_create_plan",
            json!({"rule":{"rule_id":"new-rule","name":"New rule","type":"query","query":"event.kind: event"}}),
        ),
        (
            "alerts_set_status_plan",
            json!({"alert_ids":[alert],"status":"closed"}),
        ),
        (
            "alerts_set_tags_plan",
            json!({"alert_ids":[alert],"add":["tag"]}),
        ),
        ("cases_create_plan", json!({"title":"case"})),
        (
            "cases_comment_plan",
            json!({"id":"elasticctl-fixture-case","message":"comment"}),
        ),
        (
            "cases_set_status_plan",
            json!({"ids":["elasticctl-fixture-case"],"status":"closed"}),
        ),
    ] {
        let r = call(&mut h, name, args).await;
        validate(&catalog, name, &r, false);
    }
    let r = call(&mut h, "plan_list", json!({})).await;
    validate(&catalog, "plan_list", &r, false);
    let p = plan(&mut h).await;
    for name in ["plan_get", "plan_discard"] {
        let r = call(&mut h, name, json!({"plan_id":p["plan_id"]})).await;
        validate(&catalog, name, &r, false);
    }
    let p = plan(&mut h).await;
    let q = question(&mut h, &p["plan_id"]).await;
    send(&mut h, 2, answer(&p["plan_id"], &q, accept())).await;
    let r = receive(&mut h).await;
    validate(&catalog, "plan_apply", &r, false);
    for name in TOOLS {
        let r = call(&mut h, name, json!({"unexpected":true})).await;
        validate(&catalog, name, &r, true);
        assert_eq!(code(&r), "invalid_argument", "{name}: {r}");
    }
    finish(h).await;
}
#[tokio::test]
async fn input_required_matches_documented_protocol_shape() {
    let (_s, mut h) = setup().await;
    let p = plan(&mut h).await;
    let q = question(&mut h, &p["plan_id"]).await;
    let schema = json!({"type":"object","additionalProperties":false,
        "required":["resultType","inputRequests","requestState"],"properties":{
            "resultType":{"const":"input_required"},
            "requestState":{"type":"string","pattern":"^cfm_[0-9a-f]{32}$"},
            "inputRequests":{"type":"object","required":["confirm"],"additionalProperties":false,
                "properties":{"confirm":{"type":"object","additionalProperties":false,"required":["method","params"],
                    "properties":{"method":{"const":"elicitation/create"},"params":{"type":"object",
                        "required":["mode","message","requestedSchema"],"additionalProperties":false,
                        "properties":{"mode":{"const":"form"},"message":{"type":"string","minLength":1},
                            "requestedSchema":{"type":"object","required":["type","properties","required"]}}}}}}}}});
    assert!(
        jsonschema::validator_for(&schema).unwrap().is_valid(&q),
        "{q}"
    );
    assert_eq!(
        q["inputRequests"]["confirm"]["params"]["requestedSchema"],
        json!({"type":"object",
        "properties":{"apply":{"type":"boolean","title":"Apply this change",
            "description":"True applies the change shown above. False keeps the dry run.","default":false}},"required":["apply"]})
    );
    finish(h).await;
}
