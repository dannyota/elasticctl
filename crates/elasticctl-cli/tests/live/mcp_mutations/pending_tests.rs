use super::*;
use std::sync::{Arc, Mutex};

const TOKEN: &str = "elasticctl-live-pending-create";
#[derive(Clone, Copy)]
enum Fault {
    Lost,
    Malformed,
    Readback,
    Unknown,
    Unmarked,
    Unavailable,
}
#[derive(Default)]
struct State {
    object: Option<Value>,
    fail_read: bool,
    creates: usize,
}
struct Creator {
    inner: tests::FakeChild,
    state: Arc<Mutex<State>>,
    object: Value,
    fault: Fault,
    reads: usize,
}
impl Child for Creator {
    fn send(&mut self, frame: Value) -> TestResult {
        self.inner.send(frame)
    }
    fn receive(&mut self) -> TestResult<Value> {
        self.reads += 1;
        if self.reads == 4 {
            self.state.lock().unwrap().object = Some(self.object.clone());
            if matches!(self.fault, Fault::Lost) {
                return Err("contract".into());
            }
        }
        self.inner.receive()
    }
}
fn fixture(name: &str) -> Value {
    conformance::fixture(name)
}
fn exercise(kind: &'static str, fault: Fault) {
    let rt = runtime().unwrap();
    let server = rt.block_on(MockServer::start());
    let state = Arc::new(Mutex::new(State {
        fail_read: matches!(fault, Fault::Readback),
        ..Default::default()
    }));
    let mut object = fixture(if kind == "rule" {
        "rules_get"
    } else {
        "case_get"
    });
    object["id"] = json!("case-owned");
    object["title"] = json!(TOKEN);
    object["rule_id"] = json!(TOKEN);
    object["enabled"] = json!(false);
    object["tags"] = if matches!(fault, Fault::Unmarked) {
        json!([TOKEN])
    } else {
        json!([LIVE_TAG, TOKEN])
    };
    let stored = state.clone();
    let created = object.clone();
    rt.block_on(
        Mock::given(wiremock::matchers::any())
            .respond_with(move |r: &wiremock::Request| {
                let mut s = stored.lock().unwrap();
                let p = r.url.path();
                if p == "/api/cases" && r.method == "POST" {
                    s.creates += 1;
                    let mut c = created.clone();
                    let body = r.body_json::<Value>().unwrap();
                    c["title"] = body["title"].clone();
                    c["tags"] = body["tags"].clone();
                    s.object = Some(c);
                    return match fault {
                        Fault::Lost => ResponseTemplate::new(200)
                            .set_body_json(s.object.clone().unwrap())
                            .set_delay(Duration::from_secs(2)),
                        Fault::Malformed => {
                            ResponseTemplate::new(200).set_body_json(json!({"id":null}))
                        }
                        Fault::Unavailable => ResponseTemplate::new(503),
                        _ => ResponseTemplate::new(200).set_body_json(s.object.clone().unwrap()),
                    };
                }
                if p == "/api/cases/_find" {
                    assert!(r.url.query_pairs().any(|(k, v)| k == "tags" && v == TOKEN));
                    let cases: Vec<_> = s.object.iter().cloned().collect();
                    return ResponseTemplate::new(200)
                        .set_body_json(json!({"total":cases.len(),"cases":cases}));
                }
                if p.ends_with("/signals/search") {
                    return ResponseTemplate::new(200)
                        .set_body_json(json!({"hits":{"total":{"value":0},"hits":[]}}));
                }
                if p.ends_with("/_bulk_action") {
                    return ResponseTemplate::new(200).set_body_json(fixture("rules_bulk_disable"));
                }
                if r.method == "DELETE" {
                    if kind == "rule" {
                        assert!(
                            r.url
                                .query_pairs()
                                .any(|(k, v)| k == "rule_id" && v == TOKEN)
                        );
                    } else {
                        assert!(
                            r.url
                                .query_pairs()
                                .any(|(k, v)| k == "ids" && v == "[\"case-owned\"]")
                        );
                    }
                    let deleted = s.object.take().unwrap();
                    return ResponseTemplate::new(200).set_body_json(deleted);
                }
                if s.fail_read {
                    s.fail_read = false;
                    return ResponseTemplate::new(503);
                }
                match &s.object {
                    Some(v) => ResponseTemplate::new(200).set_body_json(v),
                    None => ResponseTemplate::new(404),
                }
            })
            .mount(&server),
    );
    let profile: Profile = serde_json::from_value(
        json!({"kibana_url":server.uri(),"es_url":server.uri(),"api_key":"offline","timeout_secs":1}),
    )
    .unwrap();
    let t = cleanup_transport(&profile).unwrap();
    let mut registry = Registry::default();
    let create_transport = if matches!(fault, Fault::Unavailable) {
        Transport::new(&profile).unwrap()
    } else {
        cleanup_transport(&profile).unwrap()
    };
    let result = if kind == "refusal" {
        rt.block_on(extension::create_refusal_case(
            &create_transport,
            &mut registry,
            TOKEN,
        ))
        .map(|_| ())
    } else {
        let args = if kind == "rule" {
            json!({"rule":rule_body(TOKEN, "elasticctl-live-index").unwrap()})
        } else {
            json!({"title":TOKEN,"description":LIVE_TAG,"tags":[LIVE_TAG,TOKEN],"severity":"low"})
        };
        let tool = if kind == "rule" {
            "rules_create_plan"
        } else {
            "cases_create_plan"
        };
        let (targets, op) = extension::change_view(tool, &args, None);
        let view = json!({"data":{"plan":{"plan_id":"pln_fake","targets":targets,"operation":op}}});
        let reply = |id, v: Value| json!({"jsonrpc":"2.0","id":id,"result":{"resultType":"complete","content":[{"type":"text","text":v.to_string()}],"structuredContent":v}});
        let outcome = match fault {
            Fault::Malformed => json!({}),
            Fault::Unknown => json!({"data":{"plan":{"state":"unknown"}}}),
            _ => {
                json!({"data":{"plan":{"state":"applied"},"replayed":false,"outcome":{"complete":true,"failed":0,"created":{"case_id":"case-owned","rule_id":TOKEN}}}})
            }
        };
        let child = Creator { inner: tests::FakeChild { replies: vec![reply(10,view.clone()),reply(11,view),json!({"jsonrpc":"2.0","id":12,"result":{"resultType":"input_required","inputRequests":{"confirm":{"method":"elicitation/create","params":{"mode":"form","message":"static","requestedSchema":frames::schema()}}},"requestState":"cfm_fake"}}),reply(13,outcome)].into(), ..Default::default() }, state: state.clone(), object, fault, reads: 0 };
        let mut session = Session {
            child,
            path: McpProtocolPath::Current,
            form: true,
            next: 10,
            owned: [TOKEN.into()].into(),
            plans: Default::default(),
            checks: Default::default(),
        };
        if kind == "rule" {
            extension::create_mcp_rule(
                &mut session,
                &rt,
                &t,
                &mut registry,
                TOKEN,
                &rule_body(TOKEN, "elasticctl-live-index").unwrap(),
            )
            .map(|_| ())
        } else {
            extension::create_mcp_case(&mut session, &rt, &t, &mut registry, TOKEN).map(|_| ())
        }
    };
    assert!(result.is_err());
    assert!(state.lock().unwrap().object.is_some());
    let cleanup = rt.block_on(clean(&t, &registry));
    if matches!(fault, Fault::Unmarked) {
        assert!(cleanup.is_err());
        assert!(state.lock().unwrap().object.is_some());
        assert!(
            !rt.block_on(server.received_requests())
                .unwrap()
                .iter()
                .any(|r| r.method == "DELETE")
        );
    } else {
        cleanup.unwrap();
        assert!(state.lock().unwrap().object.is_none(), "residue");
    }
    if kind == "refusal" {
        assert_eq!(state.lock().unwrap().creates, 1);
    }
}
#[test]
fn mcp_case_uncertain_create_is_cleaned() {
    for f in [
        Fault::Lost,
        Fault::Malformed,
        Fault::Readback,
        Fault::Unknown,
    ] {
        exercise("case", f);
    }
}
#[test]
fn mcp_rule_uncertain_create_is_cleaned() {
    for f in [
        Fault::Lost,
        Fault::Malformed,
        Fault::Readback,
        Fault::Unknown,
    ] {
        exercise("rule", f);
    }
}
#[test]
fn refusal_uncertain_create_is_cleaned() {
    for f in [Fault::Lost, Fault::Malformed, Fault::Readback] {
        exercise("refusal", f);
    }
}
#[test]
fn pending_unmarked_candidate_is_never_deleted() {
    exercise("case", Fault::Unmarked);
}
#[test]
fn refusal_persisted_503_is_sent_once_and_cleaned() {
    exercise("refusal", Fault::Unavailable);
}
