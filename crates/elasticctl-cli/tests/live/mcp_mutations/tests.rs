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
fn dirty_baseline_prevents_body_and_cleanup() {
    guarded_run(
        || Err("dirty".into()),
        || panic!("body"),
        || panic!("cleanup"),
        || panic!("audit"),
    )
    .unwrap_err();
}
#[test]
fn failed_cleanup_prevents_audit() {
    guarded_run(
        || Ok(()),
        || Ok(()),
        || Err("cleanup".into()),
        || panic!("audit"),
    )
    .unwrap_err();
}
#[test]
fn no_step_names_an_unmarked_object() {
    assert!(marker("prebuilt").is_err());
    assert!(marker(&unique_name("mutation")).is_ok());
}

#[derive(Default)]
struct FakeChild {
    sent: Vec<Value>,
    replies: std::collections::VecDeque<Value>,
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
    let question = json!({"jsonrpc":"2.0","id":10,"result":{"resultType":"input_required","inputRequests":{"confirm":{"method":"elicitation/create","params":{"mode":"form","message":"static","requestedSchema":frames::schema()}}},"requestState":"cfm_test"}});
    let fake = FakeChild {
        replies: [question, complete(McpProtocolPath::Current, 11)].into(),
        ..Default::default()
    };
    let mut s = Session {
        child: fake,
        path: McpProtocolPath::Current,
        form: true,
        next: 10,
    };
    frames::applied(&s.apply("pln_test", true).unwrap(), false).unwrap();
    let sent = &s.child.sent;
    assert_eq!(sent.len(), 2);
    assert_eq!(
        sent[1]["params"]["arguments"],
        json!({"plan_id":"pln_test"})
    );
    assert_eq!(sent[1]["params"]["requestState"], "cfm_test");
    assert_eq!(
        sent[1]["params"]["inputResponses"]["confirm"]["action"],
        "accept"
    );
}
#[test]
fn fake_legacy_child_receives_elicitation_response() {
    let question = json!({"jsonrpc":"2.0","id":"server-request","method":"elicitation/create","params":{"mode":"form","message":"static","requestedSchema":frames::schema()}});
    let fake = FakeChild {
        replies: [question, complete(McpProtocolPath::Legacy, 10)].into(),
        ..Default::default()
    };
    let mut s = Session {
        child: fake,
        path: McpProtocolPath::Legacy,
        form: true,
        next: 10,
    };
    s.apply("pln_test", false).unwrap();
    assert_eq!(
        s.child.sent[1],
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
