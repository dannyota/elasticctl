use super::*;
use crate::mcp_compose::objects::{ComposeIds, Provisioned};
use std::collections::VecDeque;

const URI: &str = "elasticctl://stack/rules/rule";
const SENTINEL: &str = "private-response-sentinel";

#[derive(Default)]
struct Recording {
    replies: VecDeque<Value>,
    calls: Vec<(&'static str, Value)>,
}

impl ResourceRequests for Recording {
    fn request_raw(&mut self, method: &'static str, params: Value) -> TestResult<Value> {
        self.calls.push((method, params));
        self.replies.pop_front().ok_or("Unexpected request.".into())
    }

    fn protocol_path(&self) -> McpProtocolPath {
        McpProtocolPath::Current
    }
}

fn resource(uri: &str, text: &str) -> Value {
    json!({"result":{"contents":[{"uri":uri,"mimeType":"application/json","text":text}],"ttlMs":0,"cacheScope":"private"}})
}

fn tool(text: &str) -> Value {
    json!({"result":{"content":[{"type":"text","text":text}],"structuredContent":serde_json::from_str::<Value>(text).unwrap(),"isError":false}})
}

fn pair_calls() -> Vec<(&'static str, Value)> {
    vec![
        ("resources/read", json!({"uri":URI})),
        (
            "tools/call",
            json!({"name":"rules_get","arguments":{"selector":"rule"}}),
        ),
    ]
}

fn run_pair(fake: &mut Recording) -> TestResult {
    read_pair(
        fake,
        URI,
        "elasticctl://stack/rules/{rule_id}",
        "rules_get",
        json!({"selector":"rule"}),
    )
}

#[test]
fn unequal_then_equal_retries_both_requests_once() {
    let mut fake = Recording {
        replies: [
            resource(URI, "{}"),
            tool("[]"),
            resource(URI, "[]"),
            tool("[]"),
        ]
        .into(),
        ..Default::default()
    };
    run_pair(&mut fake).unwrap();
    assert_eq!(fake.calls, [pair_calls(), pair_calls()].concat());
    assert!(fake.replies.is_empty());
}

#[test]
fn two_mismatches_fail_without_response_text() {
    let text = serde_json::to_string(SENTINEL).unwrap();
    let mut fake = Recording {
        replies: [
            resource(URI, &text),
            tool("{}"),
            resource(URI, &text),
            tool("[]"),
        ]
        .into(),
        ..Default::default()
    };
    let error = run_pair(&mut fake).unwrap_err();
    assert_eq!(fake.calls, [pair_calls(), pair_calls()].concat());
    assert!(!error.contains(SENTINEL));
    assert_eq!(
        error,
        "MCP resource and tool text differed for elasticctl://stack/rules/{rule_id}."
    );
}

#[test]
fn malformed_frames_fail_without_response_text() {
    for bad in [
        json!({"error":{"message":SENTINEL}}),
        json!({"unexpected":SENTINEL}),
        json!({"result":{"contents":[],"private":SENTINEL}}),
        resource(URI, SENTINEL),
        resource("wrong", &serde_json::to_string(SENTINEL).unwrap()),
    ] {
        let mut fake = Recording {
            replies: [bad].into(),
            ..Default::default()
        };
        let error = run_pair(&mut fake).unwrap_err();
        assert!(!error.contains(SENTINEL));
        assert_eq!(fake.calls, pair_calls()[..1]);
    }
    for bad in [
        json!({"error":{"message":SENTINEL}}),
        json!({"unexpected":SENTINEL}),
        json!({"result":{"content":[{"text":42}],"private":SENTINEL}}),
        json!({"result":{"content":[{"text":SENTINEL}],"isError":true}}),
    ] {
        let mut fake = Recording {
            replies: [resource(URI, "{}"), bad].into(),
            ..Default::default()
        };
        let error = run_pair(&mut fake).unwrap_err();
        assert!(!error.contains(SENTINEL));
        assert_eq!(fake.calls, pair_calls());
    }
}

#[test]
fn resource_text_size_boundary_is_inclusive() {
    for (size, passes) in [(262_144, true), (262_145, false)] {
        let text = format!("\"{}\"", "x".repeat(size - 2));
        assert_eq!(text.len(), size);
        let mut fake = Recording {
            replies: [resource(URI, &text), tool(&text)].into(),
            ..Default::default()
        };
        assert_eq!(run_pair(&mut fake).is_ok(), passes);
        assert_eq!(fake.calls.len(), if passes { 2 } else { 1 });
    }
}

#[test]
fn current_checks_send_all_nine_exact_pairs_in_order() {
    let mut ids = ComposeIds::new();
    ids.work_rule = "rule/%".into();
    ids.work_lists[0].list_id = "list/%".into();
    let provisioned = Provisioned {
        flavor: elasticctl_core::Flavor::SelfManaged,
        work_alert: "alert/%".into(),
        degraded_alert: String::new(),
        cases: vec![("case/%".into(), String::new())],
        prebuilt_total: 0,
    };
    let e = Expected {
        ids: &ids,
        provisioned: &provisioned,
        fill: None,
    };
    let mut fake = Recording::default();
    fake.replies.extend([
        json!({"result":{"capabilities":{"prompts":{},"resources":{},"tools":{}}}}),
        json!({"result":{"resources":expected_resource_entries(false),"ttlMs":0,"cacheScope":"private"}}),
        json!({"result":{"resourceTemplates":expected_resource_entries(true),"ttlMs":0,"cacheScope":"private"}}),
        json!({"result":{"prompts":expected_prompts(),"ttlMs":0,"cacheScope":"private"}}),
    ]);
    let mut expected = vec![
        ("server/discover", json!({})),
        ("resources/list", json!({})),
        ("resources/templates/list", json!({})),
        ("prompts/list", json!({})),
    ];
    for (uri, name, arguments) in [
        (
            "elasticctl://stack/coverage/tactic",
            "detection_coverage",
            json!({"group_by":"tactic","limit":200}),
        ),
        (
            "elasticctl://stack/coverage/technique",
            "detection_coverage",
            json!({"group_by":"technique","limit":200}),
        ),
        ("elasticctl://stack/doctor", "stack_doctor", json!({})),
        ("elasticctl://stack/info", "stack_info", json!({})),
        (
            "elasticctl://stack/prebuilt-rules/status",
            "rules_prebuilt_status",
            json!({}),
        ),
        (
            "elasticctl://stack/alerts/alert%2F%25",
            "alerts_get",
            json!({"alert_id":"alert/%"}),
        ),
        (
            "elasticctl://stack/cases/case%2F%25",
            "cases_get",
            json!({"id":"case/%"}),
        ),
        (
            "elasticctl://stack/exception-lists/single/list%2F%25",
            "exceptions_get",
            json!({"list_id":"list/%","namespace":"single","limit":50}),
        ),
        (
            "elasticctl://stack/rules/rule%2F%25",
            "rules_get",
            json!({"selector":"rule/%"}),
        ),
    ] {
        expected.push(("resources/read", json!({"uri":uri})));
        expected.push(("tools/call", json!({"name":name,"arguments":arguments})));
        fake.replies.extend([resource(uri, "{}"), tool("{}")]);
    }
    for (index, arguments, replacement) in [
        (0, json!({"rule":"rule/%"}), r#"{"selector":"rule/%"}"#),
        (1, json!({}), r#"{"group_by":"technique","limit":200}"#),
        (
            2,
            json!({"rule":"rule/%"}),
            r#"{"selector":"rule/%","since":"24h"}"#,
        ),
        (
            3,
            json!({"alert_id":"alert/%"}),
            r#"{"alert_id":"alert/%","since":"24h"}"#,
        ),
    ] {
        let catalog = expected_prompts();
        let definition = &catalog[index];
        expected.push((
            "prompts/get",
            json!({"name":definition["name"],"arguments":arguments}),
        ));
        fake.replies.push_back(json!({"result":{"description":definition["description"],"messages":[{"role":"user","content":{"type":"text","text":PROMPT_TEXTS[index].replace("<args>",replacement)}}]}}));
    }
    fake.replies
        .extend((0..2).map(|_| json!({"error":{"code":-32602,"message":"Resource not found"}})));
    current_checks(&mut fake, &e).unwrap();
    assert_eq!(&fake.calls[..expected.len()], expected);
    assert_eq!(fake.calls.len(), expected.len() + 2);
    assert_eq!(
        fake.calls.last().unwrap(),
        &("resources/read", json!({"uri":"elasticctl://plans/x"}))
    );
    assert!(fake.replies.is_empty());
}
