use super::*;
use std::sync::{Arc, Mutex};

const ID: &str = "elasticctl-live-owned-token";
const INDEX: &str = "elasticctl-live-index-token";
fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/traditional-9.5.1")
        .join(format!("{name}.json"));
    serde_json::from_slice::<Value>(&std::fs::read(path).unwrap()).unwrap()["response"].clone()
}
#[derive(Clone, Copy)]
enum Fault {
    Dirty,
    MissingTag,
    WrongCreate,
    Panic,
    Cleanup,
    CancelAlerts,
    LateAlerts,
}
struct Stack {
    fault: Fault,
    created: bool,
    deleted: bool,
}
struct Responder(Arc<Mutex<Stack>>);
impl wiremock::Respond for Responder {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let mut s = self.0.lock().unwrap();
        let path = request.url.path();
        if path.ends_with("/_find") {
            return ResponseTemplate::new(200).set_body_json(
                json!({"total":if matches!(s.fault, Fault::Dirty) {1} else {0},"data":[]}),
            );
        }
        if path.ends_with("/signals/search") {
            let body = request.body_json::<Value>().unwrap();
            let ids = body.pointer("/query/ids/values").and_then(Value::as_array);
            let hits: Vec<_> = if matches!(s.fault, Fault::CancelAlerts | Fault::LateAlerts) {
                (0..12).filter(|n| ids.is_none_or(|ids| ids.contains(&json!(format!("alert-{n}"))))).map(|n| json!({"_id":format!("alert-{n}"),"_source":{"kibana.alert.rule.rule_id":ID,"kibana.alert.rule.tags":[LIVE_TAG,ID]}})).collect()
            } else {
                vec![]
            };
            return ResponseTemplate::new(200)
                .set_body_json(json!({"hits":{"total":{"value":hits.len()},"hits":hits}}));
        }
        if path.ends_with("/signals/status") {
            return ResponseTemplate::new(200).set_body_json(
                json!({"total":1,"updated":1,"version_conflicts":0,"noops":0,"failures":[]}),
            );
        }
        let mut rule = fixture("rules_get");
        rule["rule_id"] = json!(ID);
        rule["tags"] = if matches!(s.fault, Fault::MissingTag) {
            json!([ID])
        } else {
            json!([LIVE_TAG, ID])
        };
        rule["enabled"] = json!(false);
        if request.method == "POST" && path == "/api/detection_engine/rules" {
            s.created = true;
            if matches!(s.fault, Fault::WrongCreate) {
                rule["rule_id"] = json!("unrelated");
            }
            return ResponseTemplate::new(200).set_body_json(rule);
        }
        if request.method == "GET" && (!s.created || s.deleted) {
            return ResponseTemplate::new(404)
                .set_body_json(json!({"message":"not found","status_code":404}));
        }
        if request.method == "DELETE" {
            s.deleted = true;
            return ResponseTemplate::new(200).set_body_json(rule);
        }
        if request.method == "POST" && path.ends_with("/_bulk_action") {
            if matches!(s.fault, Fault::Cleanup) {
                return ResponseTemplate::new(403)
                    .set_body_json(json!({"message":"refused","status_code":403}));
            }
            return ResponseTemplate::new(200).set_body_json(fixture("rules_bulk_disable"));
        }
        ResponseTemplate::new(200).set_body_json(rule)
    }
}
fn exercise(fault: Fault) -> (String, Vec<(String, String, Value)>, Registry) {
    let rt = runtime().unwrap();
    let server = rt.block_on(MockServer::start());
    let state = Arc::new(Mutex::new(Stack {
        fault,
        created: false,
        deleted: false,
    }));
    rt.block_on(
        Mock::given(wiremock::matchers::any())
            .respond_with(Responder(state))
            .mount(&server),
    );
    let profile: Profile = serde_json::from_value(
        json!({"kibana_url":server.uri(),"es_url":server.uri(),"api_key":"offline"}),
    )
    .unwrap();
    let t = Transport::new(&profile).unwrap();
    let mut registry = Registry::default();
    let result = orchestrate(
        &rt,
        &t,
        &mut registry,
        || Ok(()),
        |r| {
            rt.block_on(create_rule(&t, r, ID, INDEX))?;
            if matches!(fault, Fault::CancelAlerts | Fault::LateAlerts) {
                if matches!(fault, Fault::LateAlerts) {
                    for n in 0..10 {
                        r.alerts.insert(format!("alert-{n}"), ID.into());
                    }
                }
                CANCELLATION.with(|f| {
                    *f.borrow_mut() = Some(Arc::new(std::sync::atomic::AtomicBool::new(true)))
                });
                check_cancelled()?;
            }
            panic!("body fault")
        },
    );
    let trace = rt
        .block_on(server.received_requests())
        .unwrap()
        .into_iter()
        .filter(|r| r.method != "GET" && !r.url.path().ends_with("/signals/search"))
        .map(|r| {
            (
                r.method.to_string(),
                format!(
                    "{}{}",
                    r.url.path(),
                    r.url.query().map(|q| format!("?{q}")).unwrap_or_default()
                ),
                r.body_json().unwrap_or(Value::Null),
            )
        })
        .collect();
    (result.unwrap_err(), trace, registry)
}
fn create_trace() -> (String, String, Value) {
    (
        "POST".into(),
        "/api/detection_engine/rules".into(),
        rule_body(ID, INDEX).unwrap().into_value(),
    )
}
#[test]
fn dirty_baseline_real_orchestration_has_no_writes() {
    let (class, trace, registry) = exercise(Fault::Dirty);
    assert_eq!(class, "baseline_failed");
    assert!(trace.is_empty());
    assert!(registry.rules.is_empty());
}
#[test]
fn missing_tag_readback_never_registers_or_writes_again() {
    let (class, trace, registry) = exercise(Fault::MissingTag);
    assert_eq!(class, "contract");
    assert_eq!(trace, vec![create_trace()]);
    assert!(registry.rules.is_empty());
}
#[test]
fn unrelated_create_identity_is_never_registered_or_deleted() {
    let (class, trace, registry) = exercise(Fault::WrongCreate);
    assert_eq!(class, "contract");
    assert_eq!(trace, vec![create_trace()]);
    assert!(registry.rules.is_empty());
}
#[test]
fn panic_after_real_create_runs_exact_cleanup() {
    let (class, trace, _) = exercise(Fault::Panic);
    assert_eq!(class, "contract");
    assert_eq!(
        trace,
        vec![
            create_trace(),
            (
                "POST".into(),
                "/api/detection_engine/rules/_bulk_action".into(),
                json!({"action":"disable","query":format!("alert.attributes.params.ruleId: \"{ID}\"")})
            ),
            (
                "DELETE".into(),
                format!("/api/detection_engine/rules?rule_id={ID}"),
                Value::Null
            )
        ]
    );
}
#[test]
fn first_cleanup_failure_stops_complete_write_trace() {
    let (class, trace, _) = exercise(Fault::Cleanup);
    assert_eq!(class, "cleanup_failed");
    assert_eq!(
        trace,
        vec![
            create_trace(),
            (
                "POST".into(),
                "/api/detection_engine/rules/_bulk_action".into(),
                json!({"action":"disable","query":format!("alert.attributes.params.ruleId: \"{ID}\"")})
            )
        ]
    );
}
#[test]
fn loopback_kibana_with_remote_es_is_not_lab() {
    let mut p: Profile = serde_json::from_value(
        json!({"kibana_url":"http://127.0.0.1:5601", "es_url":"https://example.test"}),
    )
    .unwrap();
    assert!(!measure::lab::lab_target(true, &p));
    p.es_url = Some("http://[::1]:9200".into());
    assert!(!measure::lab::lab_target(false, &p));
    assert!(measure::lab::lab_target(true, &p));
}

#[test]
fn unrelated_case_response_never_enters_cleanup_trace() {
    let rt = runtime().unwrap();
    let server = rt.block_on(MockServer::start());
    rt.block_on(async {
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/_find"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"total":0})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/cases"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":"unrelated"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/cases/unrelated"))
            .respond_with(ResponseTemplate::new(200).set_body_json(fixture("case_get")))
            .mount(&server)
            .await;
    });
    let profile: Profile =
        serde_json::from_value(json!({"kibana_url":server.uri(),"api_key":"offline"})).unwrap();
    let t = Transport::new(&profile).unwrap();
    let mut registry = Registry::default();
    let result = orchestrate(
        &rt,
        &t,
        &mut registry,
        || Ok(()),
        |r| rt.block_on(create_case(&t, r, ID)).map(|_| ()),
    );
    assert_eq!(result.unwrap_err(), "contract");
    assert!(registry.cases.is_empty());
    let writes: Vec<_> = rt
        .block_on(server.received_requests())
        .unwrap()
        .into_iter()
        .filter(|r| r.method != "GET" && !r.url.path().ends_with("/signals/search"))
        .map(|r| (r.method.to_string(), r.url.path().to_owned()))
        .collect();
    assert_eq!(writes, vec![("POST".into(), "/api/cases".into())]);
}

#[test]
fn alert_readback_requires_both_rule_marker_and_token() {
    assert!(
        verify_alert(
            &json!({"kibana.alert.rule.rule_id":ID,"kibana.alert.rule.tags":[LIVE_TAG, ID]}),
            ID
        )
        .is_ok()
    );
    assert!(
        verify_alert(
            &json!({"kibana.alert.rule.rule_id":ID,"kibana.alert.rule.tags":[LIVE_TAG]}),
            ID
        )
        .is_err()
    );
    assert!(verify_alert(&json!({"kibana.alert.rule.rule_id":"unrelated","kibana.alert.rule.tags":[LIVE_TAG, ID]}), ID).is_err());
}

#[test]
fn mcp_mutations_cleanup_discovers_alerts_on_early_cancellation_and_after_ten_hits() {
    for fault in [Fault::CancelAlerts, Fault::LateAlerts] {
        let (class, trace, _) = exercise(fault);
        assert_eq!(class, "contract");
        let closed: Vec<_> = trace
            .iter()
            .filter(|(_, p, _)| p.ends_with("/signals/status"))
            .collect();
        assert_eq!(closed.len(), 12);
        for n in 0..12 {
            assert!(
                closed
                    .iter()
                    .any(|(_, _, b)| b["signal_ids"] == json!([format!("alert-{n}")]))
            );
        }
        let disable = trace
            .iter()
            .position(|(_, p, _)| p.ends_with("/_bulk_action"))
            .unwrap();
        let close = trace
            .iter()
            .position(|(_, p, _)| p.ends_with("/signals/status"))
            .unwrap();
        let delete = trace.iter().position(|(m, _, _)| m == "DELETE").unwrap();
        assert!(disable < close && close < delete);
    }
}
