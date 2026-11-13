use super::*;

const SET: &str = "traditional-9.5.1";
const RULE: &str = "elasticctl-live-conformance";

pub(super) fn fixture(name: &str) -> Value {
    let file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(SET)
        .join(format!("{name}.json"));
    serde_json::from_slice::<Value>(&std::fs::read(file).unwrap()).unwrap()["response"].clone()
}

pub(super) struct Observed {
    pub(super) child: McpChild,
    frames: Vec<Value>,
}
impl Child for Observed {
    fn send(&mut self, frame: Value) -> TestResult {
        self.frames.push(frame.clone());
        Child::send(&mut self.child, frame)
    }
    fn receive(&mut self) -> TestResult<Value> {
        let frame = Child::receive(&mut self.child)?;
        self.frames.push(frame.clone());
        Ok(frame)
    }
}
pub(super) fn checked<T>(result: TestResult<T>, session: &Session<Observed>) -> T {
    result.unwrap_or_else(|error| panic!("{error}; frames: {:?}", session.child.frames))
}

pub(super) async fn setup() -> (MockServer, tempfile::TempDir, PathBuf) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_security/_authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture("authenticate")))
        .mount(&server)
        .await;
    let mut rule = fixture("rules_get");
    rule["rule_id"] = json!(RULE);
    rule["enabled"] = json!(true);
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", RULE))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule))
        .mount(&server)
        .await;
    let mut bulk = fixture("rules_bulk_disable");
    bulk["attributes"]["results"]["updated"][0]["rule_id"] = json!(RULE);
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_bulk_action"))
        .and(body_json(json!({"action":"disable","query":format!("alert.attributes.params.ruleId: \"{RULE}\"")})))
        .respond_with(ResponseTemplate::new(200).set_body_json(bulk))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = mcp_smoke::mcp_subprocess_config(dir.path(), &server.uri());
    assert_eq!(
        mcp_smoke::offline_child_command(&config, false).get_program(),
        std::ffi::OsStr::new(env!("CARGO_BIN_EXE_elasticctl"))
    );
    (server, dir, config)
}
pub(super) fn spawn(
    config: &Path,
    path: McpProtocolPath,
    form: bool,
    mutations: bool,
) -> Session<Observed> {
    let s = Session::spawn(config, path, form, mutations, None).unwrap();
    Session {
        child: Observed {
            child: s.child,
            frames: vec![],
        },
        path: s.path,
        form: s.form,
        next: s.next,
        owned: [RULE.into()].into(),
        checks: Default::default(),
        plans: Default::default(),
    }
}
async fn writes(server: &MockServer, expected: usize) {
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests.iter().filter(|r| r.method != "GET").count(),
        expected,
        "{requests:?}"
    );
}

async fn confirmation(path: McpProtocolPath, accept: bool) {
    let (server, _dir, config) = setup().await;
    let mut s = spawn(&config, path, true, true);
    let result = s.plan(RULE, false);
    let plan = checked(result, &s);
    writes(&server, 0).await;
    let result = s.apply(&plan, accept);
    let content = checked(result, &s);
    if accept {
        checked(frames::applied(&content, false), &s);
        let result = s.call("plan_apply", json!({"plan_id":plan}));
        let replay = checked(result, &s);
        let replay = checked(frames::content(replay, path), &s);
        checked(frames::applied(&replay, true), &s);
        assert_eq!(content["data"]["outcome"], replay["data"]["outcome"]);
        assert_eq!(
            content["data"]["outcome"],
            json!({"requested":1,"updated":1,"unchanged":0,"failed":0,"complete":true,"created":null})
        );
    } else {
        checked(frames::code(&content, "plan_declined"), &s);
    }
    s.child.child.shutdown().unwrap();
    writes(&server, usize::from(accept)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_accept_and_replay() {
    confirmation(McpProtocolPath::Current, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_decline() {
    confirmation(McpProtocolPath::Current, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_accept_and_replay() {
    confirmation(McpProtocolPath::Legacy, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_decline() {
    confirmation(McpProtocolPath::Legacy, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_form_refuses_without_write() {
    let (server, _dir, config) = setup().await;
    for path in [McpProtocolPath::Current, McpProtocolPath::Legacy] {
        let mut s = spawn(&config, path, false, true);
        let result = s.plan(RULE, false);
        let plan = checked(result, &s);
        let before = server.received_requests().await.unwrap().len();
        let result = s.call("plan_apply", json!({"plan_id":plan}));
        let frame = checked(result, &s);
        let content = checked(frames::content(frame, path), &s);
        checked(frames::code(&content, "confirmation_unavailable"), &s);
        assert_eq!(server.received_requests().await.unwrap().len(), before);
        s.child.child.shutdown().unwrap();
    }
    writes(&server, 0).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_class_child_rejects_every_mutation_tool() {
    let (server, _dir, config) = setup().await;
    for path in [McpProtocolPath::Current, McpProtocolPath::Legacy] {
        let mut s = spawn(&config, path, false, false);
        for tool in MUTATION_TOOLS {
            let result = s.call(tool, json!({}));
            let frame = checked(result, &s);
            assert_eq!(
                frame.pointer("/error/code"),
                Some(&json!(-32601)),
                "{frame}"
            );
            assert!(frame.get("result").is_none(), "{frame}");
        }
        s.child.child.shutdown().unwrap();
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_plan_refuses_without_write() {
    let (server, _dir, config) = setup().await;
    let mut s = spawn(&config, McpProtocolPath::Current, true, true);
    let result = s.plan(RULE, false);
    let plan = checked(result, &s);
    let mut changed = fixture("rules_get");
    changed["rule_id"] = json!(RULE);
    changed["description"] = json!("changed after planning");
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(changed))
        .with_priority(1)
        .mount(&server)
        .await;
    let result = s.call("plan_apply", json!({"plan_id":plan}));
    let frame = checked(result, &s);
    let content = checked(frames::content(frame, s.path), &s);
    checked(frames::code(&content, "plan_stale"), &s);
    s.child.child.shutdown().unwrap();
    writes(&server, 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirected_resolved_target_never_reaches_confirmation_or_write() {
    let (server, _dir, config) = setup().await;
    let mut unrelated = fixture("rules_get");
    unrelated["rule_id"] = json!("another-users-rule");
    unrelated["name"] = json!(RULE);
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", RULE))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"message":"absent","status_code":404})),
        )
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "another-users-rule"))
        .respond_with(ResponseTemplate::new(200).set_body_json(unrelated.clone()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"total":1,"page":1,"perPage":100,"data":[unrelated]})),
        )
        .mount(&server)
        .await;
    let mut s = spawn(&config, McpProtocolPath::Current, true, true);
    assert!(s.plan(RULE, false).is_err());
    assert!(s.plans.is_empty());
    assert!(
        s.child
            .frames
            .iter()
            .any(|f| f.pointer("/result/structuredContent/data/plan/targets")
                == Some(&json!(["another-users-rule"]))),
        "{:?}",
        s.child.frames
    );
    assert!(
        s.child
            .frames
            .iter()
            .all(|f| f.pointer("/params/name") != Some(&json!("plan_apply")))
    );
    s.child.child.shutdown().unwrap();
    writes(&server, 0).await;
}
