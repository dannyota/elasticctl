#[allow(dead_code)]
mod support;
use serde_json::{Value, json};
use support::Harness;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const SETS: [&str; 3] = ["traditional-9.5.1", "ech-9.5.2", "serverless-9.7.0"];
static LEGACY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const ID: &str = "elasticctl-fixture-case";
fn recorded(set: &str, name: &str) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    serde_json::from_slice(&std::fs::read(root.join(set).join(format!("{name}.json"))).unwrap())
        .unwrap()
}
fn fixture(set: &str, name: &str) -> Value {
    recorded(set, name)["response"].clone()
}
async fn mount(s: &MockServer, verb: &str, route: &str, body: Value) {
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .with_priority(1)
        .mount(s)
        .await;
}
async fn setup(set: &str, legacy: bool) -> (MockServer, Harness) {
    let s = MockServer::start().await;
    for (route, name) in [
        ("/_security/_authenticate".to_owned(), "authenticate"),
        (format!("/api/cases/{ID}"), "case_get"),
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(fixture(set, name)))
            .mount(&s)
            .await;
    }
    let mut target = support::target();
    target.profile.kibana_url = s.uri();
    target.profile.es_url = Some(s.uri());
    target.profile.timeout_secs = 1;
    target.profile.api_key = Some("test-key".into());
    let mut options = support::options();
    options.allow_mutations = elasticctl_mcp::MutationClasses::parse(["cases"]).unwrap();
    let mut h = Harness::start(target, options);
    if legacy {
        let mut init = support::legacy_initialize(1000);
        init["params"]["capabilities"] = json!({"elicitation":{"form":{}}});
        h.send_json(init).await;
        assert!(h.receive_json().await.get("result").is_some());
    }
    (s, h)
}
async fn call(h: &mut Harness, legacy: bool, name: &str, args: Value, extra: Value) -> Value {
    let mut params = json!({"name":name,"arguments":args});
    if !legacy {
        params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}});
    }
    for (k, v) in extra.as_object().unwrap() {
        params[k] = v.clone();
    }
    h.send_json(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":params}))
        .await;
    tokio::time::timeout(std::time::Duration::from_secs(8), h.receive_json())
        .await
        .unwrap()
}
fn data(r: &Value) -> &Value {
    &r["result"]["structuredContent"]["data"]
}
fn code(r: &Value) -> &Value {
    &r["result"]["structuredContent"]["error"]["code"]
}
async fn plan(h: &mut Harness, legacy: bool, tool: &str, args: Value) -> String {
    let r = call(h, legacy, tool, args, json!({})).await;
    data(&r)["plan"]["plan_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{r}"))
        .into()
}
async fn question(h: &mut Harness, legacy: bool, id: &str) -> Value {
    if legacy {
        h.send_json(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"plan_apply","arguments":{"plan_id":id}}})).await;
        let q = h.receive_json().await;
        assert_eq!(q["method"], "elicitation/create", "{q}");
        q
    } else {
        let q = call(h, false, "plan_apply", json!({"plan_id":id}), json!({})).await;
        assert_eq!(q["result"]["resultType"], "input_required", "{q}");
        q
    }
}
fn text(q: &Value, legacy: bool) -> &str {
    (if legacy {
        &q["params"]["message"]
    } else {
        &q["result"]["inputRequests"]["confirm"]["params"]["message"]
    })
    .as_str()
    .unwrap()
}
async fn accept(h: &mut Harness, legacy: bool, id: &str, q: &Value) -> Value {
    if legacy {
        h.send_json(json!({"jsonrpc":"2.0","id":q["id"],"result":{"action":"accept","content":{"apply":true}}})).await;
        h.receive_json().await
    } else {
        call(h, false, "plan_apply", json!({"plan_id":id}), json!({"requestState":q["result"]["requestState"],"inputResponses":{"confirm":{"action":"accept","content":{"apply":true}}}})).await
    }
}
async fn finish(mut h: Harness) {
    h.close_input();
    h.join().await.unwrap();
}
async fn no_writes(s: &MockServer) {
    assert!(
        s.received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
}

#[tokio::test]
async fn invalid_inputs_send_zero_requests() {
    for legacy in [false, true] {
        let (s, mut h) = setup(SETS[0], legacy).await;
        let mut inputs = vec![
            ("cases_create_plan", json!({"title":"a\nb"})),
            ("cases_create_plan", json!({"title":"x".repeat(161)})),
            ("cases_create_plan", json!({"title":"é".repeat(81)})),
            ("cases_create_plan", json!({"title":"  "})),
            (
                "cases_create_plan",
                json!({"title":"x","description":"x".repeat(4097)}),
            ),
            (
                "cases_create_plan",
                json!({"title":"x","tags":(0..11).map(|i|i.to_string()).collect::<Vec<_>>()}),
            ),
            (
                "cases_create_plan",
                json!({"title":"x","severity":"urgent"}),
            ),
            ("cases_create_plan", json!({"title":"x","assignees":[]})),
            (
                "cases_create_plan",
                json!({"title":"x","settings":{"syncAlerts":false}}),
            ),
            ("cases_create_plan", json!({"title":"x","syncAlerts":false})),
            (
                "cases_comment_plan",
                json!({"id":ID,"message":"x".repeat(4097)}),
            ),
            ("cases_set_status_plan", json!({"ids":[],"status":"closed"})),
            (
                "cases_set_status_plan",
                json!({"ids":(0..21).map(|i|i.to_string()).collect::<Vec<_>>(),"status":"closed"}),
            ),
            (
                "cases_set_status_plan",
                json!({"ids":[ID],"status":"in-progress"}),
            ),
            (
                "cases_set_status_plan",
                json!({"ids":[ID,ID],"status":"closed"}),
            ),
        ];
        for ch in ['\t', '\u{7f}', '\u{85}', '\u{2028}', '\u{202e}'] {
            for field in ["title", "description", "tags", "message"] {
                let value = format!("a{ch}b");
                let (tool, mut args) = if field == "message" {
                    ("cases_comment_plan", json!({"id":ID}))
                } else {
                    ("cases_create_plan", json!({"title":"x"}))
                };
                args[field] = if field == "tags" {
                    json!([value])
                } else {
                    json!(value)
                };
                inputs.push((tool, args));
            }
        }
        for (tool, args) in inputs {
            let r = call(&mut h, legacy, tool, args.clone(), json!({})).await;
            assert_eq!(code(&r), "invalid_argument", "{tool} {args}: {r}");
            assert!(s.received_requests().await.unwrap().is_empty());
        }
        finish(h).await;
    }
}

#[tokio::test]
async fn recorded_flows_and_consent() {
    let _legacy = LEGACY.lock().await;
    for set in SETS {
        for legacy in [false, true] {
            for (tool, args, verb, route, fixture_name) in [
                (
                    "cases_create_plan",
                    json!({"title":"new title","description":"first\nsecond","tags":["tag", "second tag"],"severity":"high"}),
                    "POST",
                    "/api/cases".to_owned(),
                    "case_create",
                ),
                (
                    "cases_comment_plan",
                    json!({"id":ID,"message":"first\nsecond"}),
                    "POST",
                    format!("/api/cases/{ID}/comments"),
                    "case_comment",
                ),
                (
                    "cases_set_status_plan",
                    json!({"ids":[ID,"other"],"status":"closed"}),
                    "PATCH",
                    "/api/cases".to_owned(),
                    "case_update_status",
                ),
            ] {
                let (s, mut h) = setup(set, legacy).await;
                let mut response = fixture(set, fixture_name);
                if tool == "cases_set_status_plan" {
                    let mut other = response[0].clone();
                    other["id"] = json!("other");
                    response.as_array_mut().unwrap().push(other);
                }
                mount(&s, verb, &route, response).await;
                let case = fixture(set, "case_get");
                if tool == "cases_set_status_plan" {
                    let mut other = case.clone();
                    other["id"] = json!("other");
                    other["version"] = json!("other-version");
                    mount(&s, "GET", "/api/cases/other", other).await;
                }
                let id = plan(&mut h, legacy, tool, args).await;
                let r = call(&mut h, legacy, "plan_get", json!({"plan_id":id}), json!({})).await;
                let operation = &data(&r)["plan"]["operation"];
                match tool {
                    "cases_create_plan" => assert_eq!(
                        operation,
                        &json!({"title":"new title","description":"first\nsecond",
                            "tags":["tag","second tag"],"severity":"high","sync_alerts":false})
                    ),
                    "cases_comment_plan" => {
                        assert_eq!(operation, &json!({"case_id":ID,"message":"first\nsecond"}))
                    }
                    _ => assert_eq!(
                        operation,
                        &json!({"status":"closed","resolved":2,"updates":[
                            {"id":ID,"version":case["version"]},
                            {"id":"other","version":"other-version"}
                        ]})
                    ),
                }
                let q = question(&mut h, legacy, &id).await;
                let consent = text(&q, legacy);
                match tool {
                    "cases_create_plan" => {
                        assert_eq!(
                            consent.lines().next().unwrap(),
                            "elasticctl asks to apply: Create case 'new title'"
                        );
                        assert!(consent.lines().any(|l| l == "  tags: tag, second tag"));
                        assert!(consent.lines().any(|l| l == "  severity: high"));
                        assert!(consent.contains("\n  description: first\n  | second\n"));
                        assert!(consent.contains("\n  syncAlerts: false\n"));
                    }
                    "cases_comment_plan" => {
                        assert_eq!(consent.lines().nth(2).unwrap(), format!("  case_id: {ID}"));
                        assert!(consent.contains("\n  first\n  | second\n"));
                    }
                    _ => {
                        assert_eq!(
                            consent.lines().next().unwrap(),
                            "elasticctl asks to apply: Close 2 cases"
                        );
                        for case_id in [ID, "other"] {
                            assert!(consent.lines().any(|l| l
                                == format!(
                                    "  {case_id}  {}  {} -> closed",
                                    case["title"].as_str().unwrap(),
                                    case["status"].as_str().unwrap()
                                )));
                        }
                        assert!(consent.contains(
                            "attached alerts: not changed (syncAlerts is off for every case listed)"
                        ));
                    }
                }
                let r = accept(&mut h, legacy, &id, &q).await;
                assert_eq!(data(&r)["plan"]["state"], "applied", "{r}");
                if tool == "cases_create_plan" {
                    assert_eq!(
                        data(&r)["outcome"]["created"]["case_id"],
                        fixture(set, "case_create")["id"]
                    );
                }
                let requests = s.received_requests().await.unwrap();
                assert_eq!(requests[0].url.path(), "/_security/_authenticate");
                let writes: Vec<_> = requests.iter().filter(|r| r.method != "GET").collect();
                assert_eq!(writes.len(), 1);
                assert_eq!(writes[0].method, verb);
                assert_eq!(writes[0].url.path(), route);
                let body: Value = writes[0].body_json().unwrap();
                match tool {
                    "cases_create_plan" => {
                        assert_eq!(body["title"], "new title");
                        assert_eq!(body["description"], "first\nsecond");
                        assert_eq!(body["tags"], json!(["tag", "second tag"]));
                        assert_eq!(body["severity"], "high");
                        assert_eq!(body["assignees"], json!([]));
                        assert_eq!(body["settings"]["syncAlerts"], false);
                    }
                    "cases_comment_plan" => {
                        assert_eq!(body["type"], "user");
                        assert_eq!(body["comment"], "first\nsecond");
                    }
                    _ => assert_eq!(
                        body["cases"],
                        json!([
                            {"id":ID,"version":case["version"],"status":"closed"},
                            {"id":"other","version":"other-version","status":"closed"}
                        ])
                    ),
                }
                assert!(
                    requests
                        .iter()
                        .all(|r| r.url.path() == "/_security/_authenticate"
                            || r.url.path().starts_with("/api/cases"))
                );
                finish(h).await;
            }
        }
    }
}

#[tokio::test]
async fn sync_alerts_refused_before_plan_storage() {
    let _legacy = LEGACY.lock().await;
    for legacy in [false, true] {
        for status in ["open", "closed"] {
            for variant in 0..4 {
                let (s, mut h) = setup(SETS[0], legacy).await;
                let ids = if variant == 3 {
                    vec!["first", "second", ID]
                } else {
                    vec![ID]
                };
                for id in &ids {
                    let mut body = fixture(SETS[0], "case_get");
                    body["id"] = json!(id);
                    if *id == ID {
                        match variant {
                            1 => {
                                body.as_object_mut().unwrap().remove("settings");
                            }
                            2 => body["settings"]["syncAlerts"] = json!("false"),
                            _ => {
                                body["settings"]["syncAlerts"] = json!(true);
                                body["totalAlerts"] = json!(2);
                            }
                        }
                    }
                    mount(&s, "GET", &format!("/api/cases/{id}"), body).await;
                }
                let r = call(
                    &mut h,
                    legacy,
                    "cases_set_status_plan",
                    json!({"ids":ids,"status":status}),
                    json!({}),
                )
                .await;
                assert_eq!(code(&r), "case_sync_alerts", "{r}");
                assert!(
                    r["result"]["structuredContent"]["error"]["message"]
                        .as_str()
                        .unwrap()
                        .contains("syncAlerts")
                );
                let r = call(&mut h, legacy, "plan_list", json!({}), json!({})).await;
                assert_eq!(data(&r)["plans"], json!([]));
                assert!(h.audit.lock().unwrap().is_empty());
                no_writes(&s).await;
                finish(h).await;
            }
        }
    }
}

#[tokio::test]
async fn drift_checks_and_comment_version_exclusion() {
    let _legacy = LEGACY.lock().await;
    for legacy in [false, true] {
        for second in [false, true] {
            for change in [
                "sync",
                "title",
                "status",
                "status_version",
                "comment_version",
            ] {
                let (s, mut h) = setup(SETS[0], legacy).await;
                let status_plan = change == "sync" || change == "status_version";
                let (tool, args) = if status_plan {
                    (
                        "cases_set_status_plan",
                        json!({"ids":[ID],"status":"closed"}),
                    )
                } else {
                    ("cases_comment_plan", json!({"id":ID,"message":"comment"}))
                };
                let id = plan(&mut h, legacy, tool, args).await;
                let q = if second {
                    Some(question(&mut h, legacy, &id).await)
                } else {
                    None
                };
                let mut body = fixture(SETS[0], "case_get");
                match change {
                    "sync" => body["settings"]["syncAlerts"] = json!(true),
                    "title" => body["title"] = json!("changed"),
                    "status" => body["status"] = json!("closed"),
                    _ => body["version"] = json!("changed"),
                }
                mount(&s, "GET", &format!("/api/cases/{ID}"), body).await;
                if change == "comment_version" {
                    mount(
                        &s,
                        "POST",
                        &format!("/api/cases/{ID}/comments"),
                        fixture(SETS[0], "case_comment"),
                    )
                    .await;
                }
                let r = if let Some(q) = q {
                    accept(&mut h, legacy, &id, &q).await
                } else if change == "comment_version" {
                    let q = question(&mut h, legacy, &id).await;
                    accept(&mut h, legacy, &id, &q).await
                } else {
                    call(
                        &mut h,
                        legacy,
                        "plan_apply",
                        json!({"plan_id":id}),
                        json!({}),
                    )
                    .await
                };
                if change == "comment_version" {
                    assert_eq!(data(&r)["plan"]["state"], "applied", "{r}");
                } else {
                    assert_eq!(
                        code(&r),
                        if change == "sync" {
                            "case_sync_alerts"
                        } else {
                            "plan_stale"
                        },
                        "{r}"
                    );
                    let r =
                        call(&mut h, legacy, "plan_get", json!({"plan_id":id}), json!({})).await;
                    assert_eq!(data(&r)["plan"]["state"], "stale");
                    no_writes(&s).await;
                    if !second {
                        assert!(
                            !h.audit
                                .lock()
                                .unwrap()
                                .iter()
                                .any(|l| l.contains("confirmation_requested"))
                        );
                    }
                }
                finish(h).await;
            }
        }
    }
}

#[tokio::test]
async fn conflict_and_server_error_classification() {
    let _legacy = LEGACY.lock().await;
    for set in SETS {
        for legacy in [false, true] {
            for status in [409, 500] {
                let (s, mut h) = setup(set, legacy).await;
                Mock::given(method("PATCH"))
                    .and(path("/api/cases"))
                    .respond_with(
                        ResponseTemplate::new(status)
                            .set_body_json(recorded(set, "case_conflict")["error"].clone()),
                    )
                    .mount(&s)
                    .await;
                let id = plan(
                    &mut h,
                    legacy,
                    "cases_set_status_plan",
                    json!({"ids":[ID],"status":"closed"}),
                )
                .await;
                let q = question(&mut h, legacy, &id).await;
                let r = accept(&mut h, legacy, &id, &q).await;
                assert_eq!(
                    code(&r),
                    if status == 409 {
                        "plan_stale"
                    } else {
                        "apply_outcome_unknown"
                    },
                    "{r}"
                );
                let r = call(&mut h, legacy, "plan_get", json!({"plan_id":id}), json!({})).await;
                let state = if status == 409 { "stale" } else { "unknown" };
                assert_eq!(data(&r)["plan"]["state"], state);
                let audits: Vec<Value> = h
                    .audit
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|l| serde_json::from_str(l).unwrap())
                    .collect();
                let started = audits
                    .iter()
                    .position(|l| l["audit"]["event"] == "apply_started")
                    .unwrap();
                let ended = audits
                    .iter()
                    .position(|l| l["audit"]["event"] == "apply_finished")
                    .unwrap();
                assert!(started < ended);
                assert_eq!(audits[ended]["audit"]["state"], state);
                assert_eq!(audits[ended]["audit"]["http_status"], status);
                let closed: Vec<usize> = (0..audits.len())
                    .filter(|&i| audits[i]["audit"]["event"] == "plan_closed")
                    .collect();
                if status == 409 {
                    assert_eq!(closed.len(), 1, "{audits:?}");
                    assert!(closed[0] > ended, "{audits:?}");
                    assert_eq!(audits[closed[0]]["audit"]["state"], "stale");
                } else {
                    assert!(closed.is_empty(), "{audits:?}");
                }
                assert_eq!(
                    s.received_requests()
                        .await
                        .unwrap()
                        .iter()
                        .filter(|r| r.method == "PATCH")
                        .count(),
                    1
                );
                finish(h).await;
            }
        }
    }
}

#[tokio::test]
async fn timeout_create_replays_without_second_post() {
    let _legacy = LEGACY.lock().await;
    for legacy in [false, true] {
        let (s, mut h) = setup(SETS[0], legacy).await;
        Mock::given(method("POST"))
            .and(path("/api/cases"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(fixture(SETS[0], "case_create"))
                    .set_delay(std::time::Duration::from_secs(2)),
            )
            .mount(&s)
            .await;
        let id = plan(&mut h, legacy, "cases_create_plan", json!({"title":"new"})).await;
        let q = question(&mut h, legacy, &id).await;
        let r = accept(&mut h, legacy, &id, &q).await;
        assert_eq!(code(&r), "apply_outcome_unknown", "{r}");
        let r = call(
            &mut h,
            legacy,
            "plan_apply",
            json!({"plan_id":id}),
            json!({}),
        )
        .await;
        assert_eq!(data(&r)["plan"]["state"], "unknown");
        assert_eq!(data(&r)["replayed"], true);
        assert_eq!(
            s.received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.method == "POST")
                .count(),
            1
        );
        finish(h).await;
    }
}

#[tokio::test]
async fn stack_titles_are_sanitized_and_identity_is_line_three() {
    let _legacy = LEGACY.lock().await;
    for legacy in [false, true] {
        for ch in ['\n', '\t', '\u{7f}', '\u{85}', '\u{2028}', '\u{202e}'] {
            let (s, mut h) = setup(SETS[0], legacy).await;
            let mut texts = Vec::new();
            for id in [ID, "other"] {
                let mut body = fixture(SETS[0], "case_get");
                body["id"] = json!(id);
                body["title"] = json!(format!("same{ch}forged"));
                mount(&s, "GET", &format!("/api/cases/{id}"), body).await;
                let plan_id = plan(
                    &mut h,
                    legacy,
                    "cases_comment_plan",
                    json!({"id":id,"message":"full\nmessage"}),
                )
                .await;
                let q = question(&mut h, legacy, &plan_id).await;
                let consent = text(&q, legacy).to_owned();
                assert_eq!(
                    consent.lines().next().unwrap(),
                    "elasticctl asks to apply: Comment on case 'same�forged'"
                );
                assert_eq!(consent.lines().nth(2).unwrap(), format!("  case_id: {id}"));
                assert!(!consent.lines().any(|l| l == "forged"));
                texts.push(consent);
                if legacy {
                    h.send_json(json!({"jsonrpc":"2.0","id":q["id"],"result":{"action":"cancel"}}))
                        .await;
                    h.receive_json().await;
                }
            }
            assert_ne!(texts[0].lines().nth(2), texts[1].lines().nth(2));
            no_writes(&s).await;
            finish(h).await;
        }
    }
}

#[tokio::test]
async fn mixed_session_rejects_each_case_tool_without_requests() {
    let (s, mut h) = setup(SETS[0], true).await;
    for (tool, args) in [
        ("cases_create_plan", json!({"title":"new"})),
        ("cases_comment_plan", json!({"id":ID,"message":"comment"})),
        (
            "cases_set_status_plan",
            json!({"ids":[ID],"status":"closed"}),
        ),
    ] {
        let r = call(
            &mut h,
            true,
            tool,
            args,
            json!({"_meta":support::current_metadata()}),
        )
        .await;
        assert_eq!(r["error"]["code"], -32600, "{r}");
        assert!(s.received_requests().await.unwrap().is_empty());
        assert!(h.audit.lock().unwrap().is_empty());
    }
    finish(h).await;
}

#[tokio::test]
async fn status_names_all_cases_including_already_in_state() {
    for target in ["open", "closed"] {
        let (s, mut h) = setup(SETS[0], false).await;
        for id in ["one", "two", "three"] {
            let mut body = fixture(SETS[0], "case_get");
            body["id"] = json!(id);
            body["status"] = json!(target);
            mount(&s, "GET", &format!("/api/cases/{id}"), body).await;
        }
        let id = plan(
            &mut h,
            false,
            "cases_set_status_plan",
            json!({"ids":["one","two","three"],"status":target}),
        )
        .await;
        let q = question(&mut h, false, &id).await;
        for id in ["one", "two", "three"] {
            assert!(text(&q, false).contains(&format!("  {id}  ")));
        }
        let r = accept(&mut h, false, &id, &q).await;
        assert_eq!(data(&r)["plan"]["state"], "applied");
        assert_eq!(data(&r)["outcome"]["unchanged"], 3);
        no_writes(&s).await;
        finish(h).await;
    }
}

#[tokio::test]
async fn organization_key_refuses_case_create() {
    organization_key_refused("cases_create_plan", json!({"title":"new"})).await;
}

#[tokio::test]
async fn organization_key_refuses_case_comment() {
    organization_key_refused("cases_comment_plan", json!({"id":ID,"message":"comment"})).await;
}

#[tokio::test]
async fn organization_key_refuses_case_status() {
    organization_key_refused(
        "cases_set_status_plan",
        json!({"ids":[ID],"status":"closed"}),
    )
    .await;
}

async fn organization_key_refused(tool: &str, args: Value) {
    for legacy in [false, true] {
        let (s, mut h) = setup(SETS[0], legacy).await;
        let mut auth = fixture(SETS[0], "authenticate");
        auth["authentication_realm"]["type"] = json!("_cloud_api_key");
        mount(&s, "GET", "/_security/_authenticate", auth).await;
        let r = call(&mut h, legacy, tool, args.clone(), json!({})).await;
        assert_eq!(code(&r), "credential_unsuitable", "{tool}: {r}");
        let r = call(&mut h, legacy, "plan_list", json!({}), json!({})).await;
        assert_eq!(data(&r)["plans"], json!([]));
        assert!(h.audit.lock().unwrap().iter().all(|line| {
            let line: Value = serde_json::from_str(line).unwrap();
            line["audit"]["event"] != "plan_created"
        }));
        let requests = s.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "{tool}: {requests:?}");
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].url.path(), "/_security/_authenticate");
        finish(h).await;
    }
}

#[tokio::test]
async fn credential_failure_stores_no_plan_and_reads_no_cases() {
    for tool in [
        "cases_create_plan",
        "cases_comment_plan",
        "cases_set_status_plan",
    ] {
        let (s, mut h) = setup(SETS[0], false).await;
        Mock::given(path("/_security/_authenticate"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message":"forbidden"})))
            .with_priority(1)
            .mount(&s)
            .await;
        let args = match tool {
            "cases_create_plan" => json!({"title":"new"}),
            "cases_comment_plan" => json!({"id":ID,"message":"comment"}),
            _ => json!({"ids":[ID],"status":"closed"}),
        };
        let r = call(&mut h, false, tool, args, json!({})).await;
        assert_eq!(code(&r), "elastic_permission", "{r}");
        let requests = s.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url.path(), "/_security/_authenticate");
        let r = call(&mut h, false, "plan_list", json!({}), json!({})).await;
        assert_eq!(data(&r)["plans"], json!([]));
        assert!(h.audit.lock().unwrap().is_empty());
        finish(h).await;
    }
}
