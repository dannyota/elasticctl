use super::*;
#[test]
fn requests_declare_form_only_on_current_path() {
    let current = frames::request(
        McpProtocolPath::Current,
        7,
        "plan_apply",
        json!({"plan_id":"p"}),
        true,
    );
    assert_eq!(
        current
            .pointer("/params/_meta/io.modelcontextprotocol~1clientCapabilities/elicitation/form"),
        Some(&json!({}))
    );
    let legacy = frames::request(
        McpProtocolPath::Legacy,
        8,
        "plan_apply",
        json!({"plan_id":"p"}),
        true,
    );
    assert!(legacy["params"].get("_meta").is_none());
}
#[test]
fn current_answer_carries_response_and_opaque_state() {
    let q = json!({"result":{"resultType":"input_required","inputRequests":{"confirm":{"method":"elicitation/create","params":{"mode":"form","message":"static","requestedSchema":frames::schema()}}},"requestState":"cfm_test"}});
    let answer = frames::answer(&q, true).unwrap();
    assert_eq!(answer["requestState"], "cfm_test");
    assert_eq!(
        answer["inputResponses"]["confirm"]["content"]["apply"],
        true
    );
    assert_eq!(
        frames::legacy_answer(json!(4), false)["result"]["action"],
        "decline"
    );
}
#[test]
fn no_step_names_an_unmarked_object() {
    assert!(marker("prebuilt").is_err());
    assert!(marker(&unique_name("mutation")).is_ok());
}

#[derive(Default)]
pub(super) struct FakeChild {
    pub(super) sent: Vec<Value>,
    pub(super) replies: std::collections::VecDeque<Value>,
}
impl Child for FakeChild {
    fn send(&mut self, frame: Value) -> TestResult {
        self.sent.push(frame);
        Ok(())
    }
    fn receive(&mut self) -> TestResult<Value> {
        self.replies.pop_front().ok_or("fake exhausted".into())
    }
}
fn complete(path: McpProtocolPath, id: u64) -> Value {
    let content = json!({"data":{"plan":{"state":"applied"},"replayed":false}});
    let mut frame = json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":content.to_string()}],"structuredContent":content}});
    if matches!(path, McpProtocolPath::Current) {
        frame["result"]["resultType"] = json!("complete");
    }
    frame
}
#[test]
fn fake_current_child_receives_retry_outside_arguments() {
    let question = json!({"jsonrpc":"2.0","id":11,"result":{"resultType":"input_required","inputRequests":{"confirm":{"method":"elicitation/create","params":{"mode":"form","message":"static","requestedSchema":frames::schema()}}},"requestState":"cfm_test"}});
    let fake = FakeChild {
        replies: [
            view(McpProtocolPath::Current),
            question,
            complete(McpProtocolPath::Current, 12),
        ]
        .into(),
        ..Default::default()
    };
    let mut s = Session {
        child: fake,
        path: McpProtocolPath::Current,
        form: true,
        next: 10,
        owned: ["elasticctl-live-test".into()].into(),
        checks: Default::default(),
        plans: [("pln_test".into(), "elasticctl-live-test".into())].into(),
    };
    frames::applied(&s.apply("pln_test", true).unwrap(), false).unwrap();
    let sent = &s.child.sent;
    assert_eq!(sent.len(), 3);
    assert_eq!(
        sent[2]["params"]["arguments"],
        json!({"plan_id":"pln_test"})
    );
    assert_eq!(sent[2]["params"]["requestState"], "cfm_test");
    assert_eq!(
        sent[2]["params"]["inputResponses"]["confirm"]["action"],
        "accept"
    );
}
#[test]
fn fake_legacy_child_receives_elicitation_response() {
    let question = json!({"jsonrpc":"2.0","id":"server-request","method":"elicitation/create","params":{"mode":"form","message":"static","requestedSchema":frames::schema()}});
    let fake = FakeChild {
        replies: [
            view(McpProtocolPath::Legacy),
            question,
            complete(McpProtocolPath::Legacy, 11),
        ]
        .into(),
        ..Default::default()
    };
    let mut s = Session {
        child: fake,
        path: McpProtocolPath::Legacy,
        form: true,
        next: 10,
        owned: ["elasticctl-live-test".into()].into(),
        checks: Default::default(),
        plans: [("pln_test".into(), "elasticctl-live-test".into())].into(),
    };
    s.apply("pln_test", false).unwrap();
    assert_eq!(
        s.child.sent[2],
        frames::legacy_answer(json!("server-request"), false)
    );
}
#[test]
fn missing_marker_stops_before_a_child_call() {
    let mut s = Session {
        child: FakeChild::default(),
        path: McpProtocolPath::Current,
        form: true,
        next: 10,
        owned: ["elasticctl-live-test".into()].into(),
        checks: Default::default(),
        plans: [("pln_test".into(), "elasticctl-live-test".into())].into(),
    };
    assert!(s.plan("unmarked", true).is_err());
    assert!(s.child.sent.is_empty());
    assert!(rule_body(&unique_name("rule"), "unmarked-index").is_err());
}
#[test]
fn malformed_questions_are_refused() {
    assert!(frames::answer(&json!({"result":{"resultType":"complete"}}), true).is_err());
    assert!(frames::form(&json!({"mode":"form","message":"text","requestedSchema":{}})).is_err());
}

fn view(path: McpProtocolPath) -> Value {
    let mut f = complete(path, 10);
    let c = json!({"data":{"plan":{"targets":["elasticctl-live-test"],"operation":{"rule_ids":["elasticctl-live-test"]}}}});
    f["result"]["structuredContent"] = c.clone();
    f["result"]["content"][0]["text"] = json!(c.to_string());
    f
}
#[test]
fn rule_state_ignores_a_run_and_keeps_a_real_change() {
    let id = format!("{LIVE_PREFIX}rule-state");
    let rule = |enabled: bool, run: &str| {
        elasticctl_api::model::Rule::from_value(json!({
            "rule_id": id,
            "name": "marker",
            "enabled": enabled,
            "tags": [LIVE_TAG, id],
            "execution_summary": {"last_execution": {"date": run, "status": "succeeded"}},
        }))
        .unwrap()
    };
    let before = rule(true, "2026-11-11T02:20:00.000Z");
    assert_eq!(
        rule_state(&before),
        rule_state(&rule(true, "2026-11-11T02:21:00.000Z")),
        "a rule run alone is not a change"
    );
    assert_ne!(
        rule_state(&before),
        rule_state(&rule(false, "2026-11-11T02:20:00.000Z")),
        "a toggle is a change"
    );
    assert!(rule_state(&before).enabled());
}

#[test]
fn shipped_classes_cover_every_mutation_class() {
    assert_eq!(
        SHIPPED_CLASSES,
        ["rules-toggle", "alerts-triage", "cases", "rules-create"]
    );
}
