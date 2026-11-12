use super::*;

#[test]
fn extended_plan_checks_every_target_and_the_operation() {
    let owner = "elasticctl-live-test";
    let mut s = Session {
        child: tests::FakeChild::default(),
        path: McpProtocolPath::Current,
        form: true,
        next: 10,
        owned: [owner.into()].into(),
        plans: Default::default(),
        checks: Default::default(),
    };
    let op = json!({"alert_ids":[owner],"status":"closed","reason":null});
    let view = json!({"data":{"plan":{"targets":[owner],"operation":op}}});
    assert!(s.check_change(&view, &[owner.into()], &op).is_ok());
    assert!(
        s.check_change(&view, &["unregistered".into()], &op)
            .is_err()
    );
    let mut wrong = view.clone();
    wrong["data"]["plan"]["targets"] = json!([owner, "unrelated"]);
    assert!(s.check_change(&wrong, &[owner.into()], &op).is_err());
    wrong = view;
    wrong["data"]["plan"]["operation"]["status"] = json!("open");
    assert!(s.check_change(&wrong, &[owner.into()], &op).is_err());
    s.owned.clear();
    assert!(s.check_change(&wrong, &[owner.into()], &op).is_err());
}

fn reply(id: u64, content: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":{"resultType":"complete","content":[{"type":"text","text":content.to_string()}],"structuredContent":content}})
}
fn session(replies: Vec<Value>) -> Session<tests::FakeChild> {
    Session {
        child: tests::FakeChild {
            replies: replies.into(),
            ..Default::default()
        },
        path: McpProtocolPath::Current,
        form: true,
        next: 10,
        owned: ["elasticctl-live-test".into()].into(),
        plans: Default::default(),
        checks: Default::default(),
    }
}
#[test]
fn every_new_step_plans_gets_and_confirms_exact_operations() {
    let id = "elasticctl-live-test";
    let mut steps = vec![
        (
            "cases_create_plan",
            json!({"title":id,"description":LIVE_TAG,"tags":[LIVE_TAG,id],"severity":"low"}),
            vec![],
            json!({"title":id,"description":LIVE_TAG,"tags":[LIVE_TAG,id],"severity":"low","sync_alerts":false}),
        ),
        (
            "cases_comment_plan",
            json!({"id":id,"message":LIVE_TAG}),
            vec![id.to_string()],
            json!({"case_id":id,"message":LIVE_TAG}),
        ),
        (
            "rules_create_plan",
            json!({"rule":{"rule_id":id,"enabled":false,"tags":[LIVE_TAG,id]}}),
            vec![id.to_string()],
            json!({"rule":{"rule_id":id,"enabled":false,"tags":[LIVE_TAG,id]}}),
        ),
    ];
    for (add, remove) in [(vec![LIVE_TAG], vec![]), (vec![], vec![LIVE_TAG])] {
        let args = json!({"alert_ids":[id],"add":add,"remove":remove});
        steps.push(("alerts_set_tags_plan", args.clone(), vec![id.into()], args));
    }
    for status in ["acknowledged", "open", "closed"] {
        steps.push((
            "alerts_set_status_plan",
            json!({"alert_ids":[id],"status":status}),
            vec![id.into()],
            json!({"alert_ids":[id],"status":status,"reason":null}),
        ));
    }
    for status in ["closed", "open"] {
        steps.push((
            "cases_set_status_plan",
            json!({"ids":[id],"status":status}),
            vec![id.into()],
            json!({"status":status,"updates":[{"id":id,"version":"v"}],"resolved":1}),
        ));
    }
    for (tool, args, targets, op) in steps {
        let content =
            json!({"data":{"plan":{"plan_id":"pln_fake","targets":targets,"operation":op}}});
        let question = json!({"jsonrpc":"2.0","id":12,"result":{"resultType":"input_required","inputRequests":{"confirm":{"method":"elicitation/create","params":{"mode":"form","message":"static","requestedSchema":frames::schema()}}},"requestState":"cfm_fake"}});
        let applied = json!({"data":{"plan":{"state":"applied"},"replayed":false,"outcome":{"complete":true,"failed":0}}});
        let mut s = session(vec![
            reply(10, content.clone()),
            reply(11, content),
            question,
            reply(13, applied),
        ]);
        s.change(tool, args.clone(), id, targets, op).unwrap();
        assert_eq!(s.child.sent[0]["params"]["name"], tool);
        assert_eq!(s.child.sent[0]["params"]["arguments"], args);
        assert_eq!(s.child.sent[1]["params"]["name"], "plan_get");
        assert_eq!(
            s.child.sent[3]["params"]["inputResponses"]["confirm"]["content"]["apply"],
            true
        );
    }
}
#[test]
fn changed_target_on_plan_get_stops_before_apply() {
    let id = "elasticctl-live-test";
    let op = json!({"case_id":id,"message":LIVE_TAG});
    let content = json!({"data":{"plan":{"plan_id":"pln_fake","targets":[id],"operation":op}}});
    let mut changed = content.clone();
    changed["data"]["plan"]["operation"]["case_id"] = json!("unrelated");
    let mut s = session(vec![reply(10, content), reply(11, changed)]);
    assert!(
        s.change(
            "cases_comment_plan",
            json!({"id":id,"message":LIVE_TAG}),
            id,
            vec![id.into()],
            op
        )
        .is_err()
    );
    assert_eq!(s.child.sent.len(), 2);
}

fn fixture(name: &str) -> Value {
    let file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/traditional-9.5.1")
        .join(format!("{name}.json"));
    serde_json::from_slice::<Value>(&std::fs::read(file).unwrap()).unwrap()["response"].clone()
}
#[test]
fn sync_case_refusal_reads_both_objects_and_cleanup_deletes_exact_case() {
    for missing_marker in [false, true] {
        let rt = runtime().unwrap();
        let server = rt.block_on(MockServer::start());
        let stored = std::sync::Arc::new(std::sync::Mutex::new(Value::Null));
        let state = stored.clone();
        rt.block_on(Mock::given(wiremock::matchers::any()).respond_with(move |r: &wiremock::Request| {
            let mut c = state.lock().unwrap();
            let path = r.url.path();
            if path == "/api/cases" && r.method == "POST" {
                *c = fixture("case_get");
                let body = r.body_json::<Value>().unwrap();
                c["id"] = json!("case-created"); c["title"] = body["title"].clone();
                c["tags"] = if missing_marker { json!([]) } else { body["tags"].clone() };
                c["settings"] = body["settings"].clone(); c["totalAlerts"] = json!(0);
            }
            if path.ends_with("/comments") { c["totalAlerts"] = json!(1); }
            if path.ends_with("/signals/search") {
                return ResponseTemplate::new(200).set_body_json(json!({"hits":{"total":{"value":1},"hits":[{"_id":"alert-owned","_index":".alerts-offline","_source":{"kibana.alert.rule.rule_id":"elasticctl-live-test","kibana.alert.rule.tags":[LIVE_TAG,"elasticctl-live-test"],"kibana.alert.workflow_status":"open","kibana.alert.rule.uuid":"offline-rule-uuid","kibana.alert.rule.name":"marker rule"}}]}}));
            }
            if path == "/api/detection_engine/rules" {
                let mut rule = fixture("rules_get"); rule["rule_id"] = json!("elasticctl-live-test"); rule["tags"] = json!([LIVE_TAG,"elasticctl-live-test"]);
                return ResponseTemplate::new(200).set_body_json(rule);
            }
            ResponseTemplate::new(200).set_body_json(c.clone())
        }).mount(&server));
        let profile: Profile = serde_json::from_value(
            json!({"kibana_url":server.uri(),"es_url":server.uri(),"api_key":"offline"}),
        )
        .unwrap();
        let t = cleanup_transport(&profile).unwrap();
        let mut registry = Registry::default();
        registry.rules.insert("elasticctl-live-test".into());
        registry
            .alerts
            .insert("alert-owned".into(), "elasticctl-live-test".into());
        let mut s = session(vec![reply(
            10,
            json!({"error":{"code":"case_sync_alerts"}}),
        )]);
        let result = extension::refusal(&mut s, &rt, &t, &mut registry, "alert-owned");
        if missing_marker {
            assert!(result.is_err());
            assert!(registry.cases.is_empty());
            assert!(s.child.sent.is_empty());
        } else {
            result.unwrap();
            assert_eq!(s.child.sent.len(), 1);
            assert_eq!(s.child.sent[0]["params"]["name"], "cases_set_status_plan");
            registry.rules.clear();
            registry.alerts.clear();
            rt.block_on(clean(&t, &registry)).unwrap();
        }
        let requests = rt.block_on(server.received_requests()).unwrap();
        let writes: Vec<_> = requests
            .iter()
            .filter(|r| r.method != "GET" && !r.url.path().ends_with("/signals/search"))
            .collect();
        assert_eq!(writes.len(), if missing_marker { 1 } else { 3 });
        if !missing_marker {
            assert_eq!(writes[1].url.path(), "/api/cases/case-created/comments");
            assert_eq!(writes[2].method, "DELETE");
            assert_eq!(
                writes[2]
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == "ids")
                    .unwrap()
                    .1,
                "[\"case-created\"]"
            );
            assert!(
                requests
                    .iter()
                    .filter(|r| r.url.path().ends_with("/signals/search"))
                    .count()
                    >= 3
            );
        }
    }
}
