use super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct State {
    user: Option<String>,
    metadata: Value,
    key_metadata: Value,
    invalidated: bool,
    fail_invalidation: bool,
    wrong_key: bool,
    wrong_owner: bool,
    foreign: u8,
    lost_user: bool,
    lost_key: bool,
    read_failures: usize,
    rules: BTreeMap<String, Value>,
    owners: BTreeMap<String, String>,
}
#[derive(Clone)]
struct Stack(Arc<Mutex<State>>);
fn fixture(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/traditional-9.5.1")
        .join(format!("{name}.json"));
    serde_json::from_slice::<Value>(&std::fs::read(p).unwrap()).unwrap()["response"].clone()
}
impl wiremock::Respond for Stack {
    fn respond(&self, r: &wiremock::Request) -> ResponseTemplate {
        let mut s = self.0.lock().unwrap();
        let p = r.url.path();
        let method = r.method.as_str();
        let body = r.body_json::<Value>().unwrap_or(Value::Null);
        let auth = r
            .headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let admin = auth == "Basic ZWxhc3RpYzpvZmZsaW5l";
        let owner = if admin {
            "elastic".into()
        } else {
            s.user.clone().unwrap_or_default()
        };
        if p == "/" || p == "/api/console/proxy" {
            let v = json!({"cluster_name":if s.foreign == 2 {"foreign"} else {"docker-cluster"},"cluster_uuid":if s.foreign == 5 && p != "/" {"other"} else {"local"}});
            let mut response = ResponseTemplate::new(200).set_body_json(v);
            if s.foreign == 1 && p == "/" {
                response = response.insert_header("x-found-handling-cluster", "foreign");
            }
            return response;
        }
        if p == "/_nodes/_local/settings" {
            return ResponseTemplate::new(200).set_body_json(json!({"cluster_name":"docker-cluster","nodes":{"local":{"settings":{"discovery":{"type":if s.foreign == 3 {"multi-node"} else {"single-node"}}}}}}));
        }
        if p == "/api/status" {
            let mut response = ResponseTemplate::new(200).set_body_json(fixture("status"));
            if s.foreign == 4 {
                response = response.insert_header("x-found-handling-cluster", "foreign");
            }
            return response;
        }
        if p == "/_security/_authenticate" {
            let mut v = fixture("authenticate");
            v["username"] = json!(owner);
            if auth.starts_with("ApiKey ") {
                v["api_key"]["id"] = json!("owned-key");
            } else {
                v.as_object_mut().unwrap().remove("api_key");
                v["authentication_realm"]["type"] = json!("native");
            }
            return ResponseTemplate::new(200).set_body_json(v);
        }
        if p == "/_security/user" {
            let users = s
                .user
                .as_ref()
                .map(|u| json!({u:{"metadata":s.metadata}}))
                .unwrap_or(json!({}));
            return ResponseTemplate::new(200).set_body_json(users);
        }
        if let Some(user) = p.strip_prefix("/_security/user/") {
            if method == "PUT" {
                s.user = Some(user.into());
                s.metadata = body["metadata"].clone();
                if s.lost_user {
                    return ResponseTemplate::new(200).set_body_string("lost response");
                }
                return ResponseTemplate::new(200).set_body_json(json!({"created":true}));
            }
            if s.user.as_deref() != Some(user) {
                return ResponseTemplate::new(404).set_body_json(json!({"status":404}));
            }
            if method == "DELETE" {
                s.user = None;
                return ResponseTemplate::new(200).set_body_json(json!({"found":true}));
            }
            if s.read_failures > 0 {
                s.read_failures -= 1;
                return ResponseTemplate::new(503);
            }
            return ResponseTemplate::new(200).set_body_json(json!({user:{"username":user,"metadata":s.metadata,"roles":["superuser"],"enabled":true}}));
        }
        if p == "/_security/api_key" {
            if method == "POST" {
                s.key_metadata = s.metadata.clone();
                if s.lost_key {
                    return ResponseTemplate::new(200).set_body_string("lost response");
                }
                return ResponseTemplate::new(200)
                    .set_body_json(json!({"id":"owned-key","encoded":"b2ZmbGluZQ=="}));
            }
            if method == "DELETE" {
                if s.fail_invalidation {
                    return ResponseTemplate::new(403).set_body_json(json!({"status":403}));
                }
                s.invalidated = true;
                return ResponseTemplate::new(200)
                    .set_body_json(json!({"error_count":0,"invalidated_api_keys":["owned-key"]}));
            }
            let keys = s.user.as_ref().map(|u| json!([{"id":"owned-key","name":u,"username":if s.wrong_key {"unrelated"} else {u},"metadata":s.key_metadata,"invalidated":s.invalidated}])).unwrap_or(json!([]));
            return ResponseTemplate::new(200).set_body_json(json!({"api_keys":keys}));
        }
        if p.ends_with("/signals/search") {
            return ResponseTemplate::new(200)
                .set_body_json(json!({"hits":{"hits":[],"total":{"value":0}}}));
        }
        if p.ends_with("/_find") {
            return ResponseTemplate::new(200).set_body_json(json!({"total":0}));
        }
        if p == "/api/detection_engine/rules" {
            if method == "POST" {
                let id = body["rule_id"].as_str().unwrap().to_owned();
                let mut rule = fixture("rules_get");
                for (k, v) in body.as_object().unwrap() {
                    rule[k] = v.clone();
                }
                rule["id"] = json!(id);
                s.rules.insert(id.clone(), rule.clone());
                s.owners.insert(id, owner);
                return ResponseTemplate::new(200).set_body_json(rule);
            }
            let id = r
                .url
                .query_pairs()
                .find(|(k, _)| k == "rule_id")
                .unwrap()
                .1
                .into_owned();
            if let Some(rule) = s.rules.get(&id).cloned() {
                if method == "DELETE" {
                    s.rules.remove(&id);
                }
                return ResponseTemplate::new(200).set_body_json(rule);
            }
            return ResponseTemplate::new(404)
                .set_body_json(json!({"status_code":404,"message":"absent"}));
        }
        if let Some(id) = p.strip_prefix("/api/alerting/rule/") {
            return ResponseTemplate::new(200).set_body_json(
                json!({"api_key_owner":if s.wrong_owner {"elastic"} else {s.owners[id].as_str()}}),
            );
        }
        if p.ends_with("/_bulk_action") {
            let enabled = body["action"] == "enable";
            let query = body["query"].as_str().unwrap();
            let id = s
                .rules
                .keys()
                .find(|id| query.contains(id.as_str()))
                .unwrap()
                .clone();
            s.rules.get_mut(&id).unwrap()["enabled"] = json!(enabled);
            s.owners.insert(id, owner);
            return ResponseTemplate::new(200).set_body_json(fixture("rules_bulk_disable"));
        }
        ResponseTemplate::new(404)
    }
}
fn setup(rt: &tokio::runtime::Runtime) -> (MockServer, Stack, Profile, Transport) {
    let server = rt.block_on(MockServer::start());
    let stack = Stack(Arc::new(Mutex::new(State::default())));
    rt.block_on(
        Mock::given(wiremock::matchers::any())
            .respond_with(stack.clone())
            .mount(&server),
    );
    let profile: Profile = serde_json::from_value(json!({"kibana_url":server.uri(),"es_url":server.uri(),"username":"elastic","password":"offline"})).unwrap();
    let t = cleanup_transport(&profile).unwrap();
    (server, stack, profile, t)
}
fn writes(rt: &tokio::runtime::Runtime, server: &MockServer) -> Vec<(String, String)> {
    // Never include request bodies or headers: they contain generated credentials.
    rt.block_on(server.received_requests())
        .unwrap()
        .into_iter()
        .filter(|r| {
            r.method != "GET"
                && r.url.path() != "/api/console/proxy"
                && r.url.path() != "/api/detection_engine/signals/search"
        })
        .map(|r| (r.method.to_string(), r.url.path().into()))
        .collect()
}
#[test]
fn mcp_mutations_lab_measures_distinct_owners_then_cleans_key_before_user() {
    let rt = runtime().unwrap();
    let (server, stack, profile, t) = setup(&rt);
    let mut registry = Registry::default();
    rt.block_on(measure::lab::measure_with_basic(
        &t,
        &profile,
        "elasticctl-live-index",
        &mut registry,
        true,
    ))
    .unwrap();
    let user = stack.0.lock().unwrap().user.clone().unwrap();
    let requests = rt.block_on(server.received_requests()).unwrap();
    let first_toggle = requests
        .iter()
        .position(|r| r.url.path().ends_with("/_bulk_action"))
        .unwrap();
    assert_eq!(
        requests[..first_toggle]
            .iter()
            .filter(|r| r.url.path().starts_with("/api/alerting/rule/"))
            .count(),
        2
    );
    let trace = writes(&rt, &server);
    assert_eq!(
        trace
            .iter()
            .filter(|(_, p)| p.ends_with("/_bulk_action"))
            .count(),
        2
    );
    assert!(stack.0.lock().unwrap().owners.values().all(|o| o == &user));
    rt.block_on(clean(&t, &registry)).unwrap();
    let trace = writes(&rt, &server);
    assert_eq!(
        &trace[trace.len() - 2..],
        &[
            ("DELETE".into(), "/_security/api_key".into()),
            ("DELETE".into(), format!("/_security/user/{user}"))
        ]
    );
    assert!(stack.0.lock().unwrap().user.is_none());
    assert!(stack.0.lock().unwrap().invalidated);
}
#[test]
fn mcp_mutations_lab_cleanup_failure_never_deletes_user() {
    let rt = runtime().unwrap();
    let (server, stack, profile, t) = setup(&rt);
    let mut registry = Registry::default();
    rt.block_on(lab_identity::provision(&profile, true, &mut registry))
        .unwrap();
    stack.0.lock().unwrap().fail_invalidation = true;
    let error = orchestrate(
        &rt,
        &t,
        &cleanup_transport(&profile).unwrap(),
        &mut registry,
        || Ok(()),
        |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(error, "cleanup_failed");
    let trace = writes(&rt, &server);
    assert_eq!(trace.len(), 3);
    assert_eq!(trace[2], ("DELETE".into(), "/_security/api_key".into()));
    assert!(stack.0.lock().unwrap().user.is_some());
}
#[test]
fn mcp_mutations_lab_unrelated_key_is_not_invalidated_and_user_is_retained() {
    let rt = runtime().unwrap();
    let (server, stack, profile, t) = setup(&rt);
    let mut registry = Registry::default();
    stack.0.lock().unwrap().wrong_key = true;
    assert!(
        rt.block_on(lab_identity::provision(&profile, true, &mut registry))
            .is_err()
    );
    let error = orchestrate(
        &rt,
        &t,
        &cleanup_transport(&profile).unwrap(),
        &mut registry,
        || Ok(()),
        |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(error, "cleanup_failed");
    assert_eq!(writes(&rt, &server).len(), 2);
}
#[test]
fn mcp_mutations_lab_requires_opt_in_and_rejects_dirty_security_baseline() {
    let rt = runtime().unwrap();
    let (server, stack, profile, t) = setup(&rt);
    let mut registry = Registry::default();
    assert!(
        rt.block_on(lab_identity::provision(&profile, false, &mut registry))
            .is_err()
    );
    assert!(writes(&rt, &server).is_empty());
    stack.0.lock().unwrap().user = Some("elasticctl-live-m13-leftover".into());
    assert!(
        rt.block_on(lab_identity::baseline(&t, &profile, true))
            .is_err()
    );
    assert!(writes(&rt, &server).is_empty());
}

#[test]
fn mcp_mutations_lab_unverified_rule_owners_prevent_measurement_toggles() {
    let rt = runtime().unwrap();
    let (server, stack, profile, t) = setup(&rt);
    let mut registry = Registry::default();
    stack.0.lock().unwrap().wrong_owner = true;
    rt.block_on(measure::lab::measure_with_basic(
        &t,
        &profile,
        "elasticctl-live-index",
        &mut registry,
        true,
    ))
    .unwrap();
    assert!(
        writes(&rt, &server)
            .iter()
            .all(|(_, p)| !p.ends_with("/_bulk_action"))
    );
    rt.block_on(clean(&t, &registry)).unwrap();
}

#[test]
fn mcp_mutations_lab_foreign_loopback_fingerprints_skip_without_writes() {
    for foreign in 1..=5 {
        let rt = runtime().unwrap();
        let (server, stack, profile, t) = setup(&rt);
        stack.0.lock().unwrap().foreign = foreign;
        let mut registry = Registry::default();
        rt.block_on(measure::lab::measure_with_basic(
            &t,
            &profile,
            "elasticctl-live-index",
            &mut registry,
            true,
        ))
        .unwrap();
        assert!(writes(&rt, &server).is_empty());
        assert!(registry.lab.is_none());
    }
}
#[test]
fn mcp_mutations_lab_lost_create_responses_are_recovered() {
    for lost_user in [true, false] {
        let rt = runtime().unwrap();
        let (server, stack, profile, t) = setup(&rt);
        {
            let mut s = stack.0.lock().unwrap();
            s.lost_user = lost_user;
            s.lost_key = !lost_user;
        }
        let mut registry = Registry::default();
        assert!(
            rt.block_on(lab_identity::provision(&profile, true, &mut registry))
                .is_err()
        );
        assert!(registry.lab.is_some());
        rt.block_on(clean(&t, &registry)).unwrap();
        assert!(stack.0.lock().unwrap().user.is_none());
        if !lost_user {
            assert!(stack.0.lock().unwrap().invalidated);
        }
        assert!(
            writes(&rt, &server)
                .last()
                .unwrap()
                .1
                .starts_with("/_security/user/")
        );
    }
}
#[test]
fn mcp_mutations_lab_cleanup_retries_readback_but_retains_foreign_user() {
    for foreign in [false, true] {
        let rt = runtime().unwrap();
        let (server, stack, profile, t) = setup(&rt);
        let mut registry = Registry::default();
        rt.block_on(lab_identity::provision(&profile, true, &mut registry))
            .unwrap();
        {
            let mut s = stack.0.lock().unwrap();
            s.read_failures = 2;
            if foreign {
                s.metadata = json!({"token":"foreign"});
            }
        }
        let result = rt.block_on(clean(&t, &registry));
        assert_eq!(result.is_err(), foreign);
        assert_eq!(stack.0.lock().unwrap().user.is_some(), foreign);
        if foreign {
            assert!(
                !writes(&rt, &server)
                    .iter()
                    .any(|(m, p)| m == "DELETE" && p.starts_with("/_security/user/"))
            );
        }
    }
}
