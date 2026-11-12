//! `detection_coverage` through the MCP router.
//!
//! Rule rows are the recorded marker rules of `rules_find_sorted_page.json`,
//! cloned with only `rule_id`, `threat`, or `index` changed. Every `_find`
//! body copies the recorded page shape; the status and rule bodies are the
//! recorded responses, with only the version number changed where a case
//! needs an older stack.

#[allow(dead_code)]
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::pin::Pin;
use std::sync::{
    Arc, LazyLock,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

use elasticctl_core::{Profile, Resolved, Source};
use serde_json::{Value, json};
use support::{Harness, current_metadata, options};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::time::{sleep, timeout};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{method, path},
};

const NAME: &str = "detection_coverage";
const FIND: &str = "/api/detection_engine/rules/_find";
const RULE: &str = "/api/detection_engine/rules";
const STATUS_PATH: &str = "/api/status";
const DESCRIPTION: &str = "Detection coverage across Elastic Security rules, grouped by MITRE ATT&CK technique, tactic, index pattern, or integration package. Each row counts enabled and disabled rules. Use rules_list with technique or tactic to see the rules behind a row. Reads at most 4,000 rules; near that size a call can need a longer server --timeout. Read-only.";
const TAG_DESCRIPTION: &str = "Exact rule-tag filter. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.";
const STRUCTURED_CAP: usize = 262_144;

fn recorded(text: &str) -> Value {
    serde_json::from_str::<Value>(text).expect("fixture is JSON")["response"].clone()
}

static SORTED_PAGE: LazyLock<Value> = LazyLock::new(|| {
    recorded(include_str!(
        "../../../tests/fixtures/serverless-9.7.0/rules_find_sorted_page.json"
    ))
});
static RULE_GET: LazyLock<Value> = LazyLock::new(|| {
    recorded(include_str!(
        "../../../tests/fixtures/serverless-9.7.0/rule_get_executed.json"
    ))
});
static STATUS: LazyLock<Value> = LazyLock::new(|| {
    recorded(include_str!(
        "../../../tests/fixtures/traditional-9.5.1/status.json"
    ))
});

/// The recorded marker rule with a technique, a tactic, an index pattern,
/// and the `system` package.
fn marker() -> Value {
    SORTED_PAGE["data"][0].clone()
}

fn target_for(server: &MockServer) -> Resolved {
    Resolved {
        name: "test".to_string(),
        source: Source::Profile,
        profile: Profile {
            kibana_url: server.uri(),
            es_url: Some(server.uri()),
            api_key: Some("fake-auth-marker".to_string()),
            username: None,
            password: None,
            space: "default".to_string(),
            verify: true,
            timeout_secs: 30,
        },
    }
}

/// Serves `_find` pages of a fixed corpus by the `page` and `per_page`
/// query, optionally delaying one page.
struct Corpus {
    rules: Vec<Value>,
    delayed: Option<(usize, Duration)>,
}

impl Respond for Corpus {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let query: BTreeMap<String, String> = request.url.query_pairs().into_owned().collect();
        let number = |key: &str| query.get(key).and_then(|v| v.parse::<usize>().ok());
        let (Some(page), Some(per_page)) = (number("page"), number("per_page")) else {
            return ResponseTemplate::new(400).set_body_json(json!({"message": "unpaged"}));
        };
        let start = (page.saturating_sub(1) * per_page).min(self.rules.len());
        let end = (page * per_page).min(self.rules.len());
        let mut body = SORTED_PAGE.clone();
        body["page"] = json!(page);
        body["perPage"] = json!(per_page);
        body["total"] = json!(self.rules.len());
        body["data"] = Value::Array(self.rules[start..end].to_vec());
        let response = ResponseTemplate::new(200).set_body_json(body);
        match self.delayed {
            Some((delayed, delay)) if delayed == page => response.set_delay(delay),
            _ => response,
        }
    }
}

async fn corpus_server(rules: Vec<Value>, delayed: Option<(usize, Duration)>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(FIND))
        .respond_with(Corpus { rules, delayed })
        .mount(&server)
        .await;
    server
}

async fn mount_status(server: &MockServer, version: &str) {
    let mut status = STATUS.clone();
    status["version"]["number"] = json!(version);
    Mock::given(method("GET"))
        .and(path(STATUS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(status))
        .mount(server)
        .await;
}

/// The recorded rule, served through the explicit gate.
async fn mount_held_rule(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(RULE))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*RULE_GET))
        .mount(server)
        .await;
}

trait Session {
    async fn send_json(&mut self, value: Value);
    async fn receive_json(&mut self) -> Value;
}

impl Session for Harness {
    async fn send_json(&mut self, value: Value) {
        self.send_json(value).await;
    }

    async fn receive_json(&mut self) -> Value {
        self.receive_json().await
    }
}

/// Capture the isolated MCP runtime without changing the shared harness.
struct RuntimeInput {
    input: tokio::io::DuplexStream,
    runtime: Option<tokio::sync::oneshot::Sender<tokio::runtime::Handle>>,
}

impl AsyncRead for RuntimeInput {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(runtime) = self.runtime.take() {
            runtime.send(tokio::runtime::Handle::current()).unwrap();
        }
        Pin::new(&mut self.input).poll_read(cx, buf)
    }
}

struct ClockHarness {
    input: Option<tokio::io::DuplexStream>,
    output: tokio::io::BufReader<tokio::io::DuplexStream>,
    task: tokio::task::JoinHandle<elasticctl_core::Result<()>>,
    runtime: Option<tokio::sync::oneshot::Receiver<tokio::runtime::Handle>>,
}

impl ClockHarness {
    fn start(target: Resolved, options: elasticctl_mcp::ServerOptions) -> Self {
        let (input, server_input) = tokio::io::duplex(1_048_576);
        let (server_output, output) = tokio::io::duplex(1_048_576);
        let (runtime, captured) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(elasticctl_mcp::server::serve_io(
            target,
            options,
            RuntimeInput {
                input: server_input,
                runtime: Some(runtime),
            },
            server_output,
        ));
        Self {
            input: Some(input),
            output: tokio::io::BufReader::new(output),
            task,
            runtime: Some(captured),
        }
    }

    async fn pause_clock(&mut self) -> Clock {
        let runtime = timeout(Duration::from_secs(30), self.runtime.take().unwrap())
            .await
            .expect("MCP runtime did not start")
            .unwrap();
        let blocker = timeout(
            Duration::from_secs(30),
            runtime.spawn(async {
                let (blocker, waiting) = std::sync::mpsc::channel::<()>();
                // Tokio inhibits paused-clock auto-advance while this task is outstanding.
                tokio::task::spawn_blocking(move || {
                    let _ = waiting.recv();
                });
                tokio::time::pause();
                blocker
            }),
        )
        .await
        .expect("MCP clock did not pause")
        .unwrap();
        Clock {
            runtime,
            blocker: Some(blocker),
        }
    }

    fn close_input(&mut self) {
        self.input.take();
    }

    async fn assert_no_reply(&mut self) {
        let mut trailing = Vec::new();
        timeout(
            Duration::from_secs(30),
            self.output.read_to_end(&mut trailing),
        )
        .await
        .expect("MCP output did not close")
        .unwrap();
        assert!(trailing.is_empty(), "the cancelled call emitted a response");
    }

    async fn join(self) -> elasticctl_core::Result<()> {
        timeout(Duration::from_secs(30), self.task)
            .await
            .expect("MCP session did not stop")
            .expect("server task must not panic")
    }
}

impl Session for ClockHarness {
    async fn send_json(&mut self, value: Value) {
        let mut frame = serde_json::to_vec(&value).unwrap();
        frame.push(b'\n');
        self.input
            .as_mut()
            .expect("input remains open")
            .write_all(&frame)
            .await
            .unwrap();
    }

    async fn receive_json(&mut self) -> Value {
        let mut line = Vec::new();
        timeout(
            Duration::from_secs(30),
            self.output.read_until(b'\n', &mut line),
        )
        .await
        .expect("MCP reply did not arrive")
        .unwrap();
        serde_json::from_slice(&line).expect("server returns JSON")
    }
}

struct Clock {
    runtime: tokio::runtime::Handle,
    blocker: Option<std::sync::mpsc::Sender<()>>,
}

impl Clock {
    async fn now(&self) -> tokio::time::Instant {
        timeout(
            Duration::from_secs(30),
            self.runtime.spawn(async { tokio::time::Instant::now() }),
        )
        .await
        .expect("MCP clock did not answer")
        .unwrap()
    }

    async fn advance(&self, duration: Duration) {
        timeout(
            Duration::from_secs(30),
            self.runtime.spawn(async move {
                tokio::time::advance(duration).await;
            }),
        )
        .await
        .expect("MCP clock did not advance")
        .unwrap();
    }
}

impl Drop for Clock {
    fn drop(&mut self) {
        let blocker = self.blocker.take();
        self.runtime.spawn(async move {
            tokio::time::resume();
            drop(blocker);
        });
    }
}

/// Forward requests to wiremock, holding rule replies until explicitly released.
struct Gate {
    target: Resolved,
    arrivals: Arc<AtomicUsize>,
    departures: Arc<AtomicUsize>,
    release: Arc<tokio::sync::Semaphore>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Gate {
    async fn start(server: &MockServer) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut target = target_for(server);
        target.profile.kibana_url = format!("http://{}", listener.local_addr().unwrap());
        target.profile.es_url = Some(target.profile.kibana_url.clone());
        let upstream = *server.address();
        let arrivals = Arc::new(AtomicUsize::new(0));
        let departures = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let (a, d, r) = (arrivals.clone(), departures.clone(), release.clone());
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    socket = listener.accept() => {
                        let (socket, _) = socket.unwrap();
                        let (a, d, r) = (a.clone(), d.clone(), r.clone());
                        connections.spawn(async move {
                            let mut socket = tokio::io::BufReader::new(socket);
                            let mut header = String::new();
                            let mut length = 0;
                            loop {
                                let mut line = String::new();
                                if socket.read_line(&mut line).await.unwrap() == 0 { return; }
                                if let Some(n) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                                    length = n.trim().parse::<usize>().unwrap();
                                }
                                if line == "\r\n" { break; }
                                if !line.to_ascii_lowercase().starts_with("connection:") { header.push_str(&line); }
                            }
                            header.push_str("Connection: close\r\n\r\n");
                            let mut body = vec![0; length];
                            socket.read_exact(&mut body).await.unwrap();
                            let mut remote = tokio::net::TcpStream::connect(upstream).await.unwrap();
                            remote.write_all(header.as_bytes()).await.unwrap();
                            remote.write_all(&body).await.unwrap();
                            if header.starts_with(&format!("GET {RULE}?")) {
                                a.fetch_add(1, Ordering::SeqCst);
                                r.acquire().await.unwrap().forget();
                                d.fetch_add(1, Ordering::SeqCst);
                            }
                            // A deadline can close the client before the gate opens.
                            let _ = tokio::io::copy(&mut remote, socket.get_mut()).await;
                        });
                    }
                    Some(result) = connections.join_next(), if !connections.is_empty() => { result.unwrap(); }
                }
            }
        });
        Self {
            target,
            arrivals,
            departures,
            release,
            task,
        }
    }

    async fn wait_for(&self, expected: usize) {
        Self::wait_count(&self.arrivals, expected).await;
    }

    async fn open(&self, count: usize, expected: usize) {
        self.release.add_permits(count);
        Self::wait_count(&self.departures, expected).await;
    }

    async fn wait_count(count: &AtomicUsize, expected: usize) {
        timeout(Duration::from_secs(30), async {
            while count.load(Ordering::SeqCst) < expected {
                sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("held rule requests did not reach the gate condition");
    }
}

/// The marker rule as `coverage-<n>` with one technique, `T<n>`.
fn technique_rule(n: usize) -> Value {
    let mut rule = marker();
    rule["rule_id"] = json!(format!("coverage-{n:04}"));
    let technique = &mut rule["threat"][0]["technique"][0];
    technique["id"] = json!(format!("T{n:04}"));
    technique["subtechnique"][0]["id"] = json!(format!("T{n:04}.001"));
    rule
}

/// The marker rule as `coverage-<n>` with the given index patterns.
fn index_rule(n: usize, patterns: &[String]) -> Value {
    let mut rule = marker();
    rule["rule_id"] = json!(format!("coverage-{n:04}"));
    rule["index"] = json!(patterns);
    rule
}

async fn send_call(harness: &mut impl Session, id: u64, name: &str, arguments: Value) {
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"_meta": current_metadata(), "name": name, "arguments": arguments},
        }))
        .await;
}

async fn call(harness: &mut impl Session, id: u64, arguments: Value) -> Value {
    send_call(harness, id, NAME, arguments).await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], id);
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .expect("one text item");
    assert_eq!(
        serde_json::from_str::<Value>(text).expect("text is JSON"),
        reply["result"]["structuredContent"],
        "text equals structured content"
    );
    reply
}

async fn tool_definition(harness: &mut impl Session) -> Value {
    harness
        .send_json(json!({
            "jsonrpc": "2.0", "id": 900, "method": "tools/list",
            "params": {"_meta": current_metadata()},
        }))
        .await;
    let reply = harness.receive_json().await;
    assert_eq!(reply["id"], 900);
    reply["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .find(|tool| tool["name"] == NAME)
        .expect("detection_coverage is listed")
        .clone()
}

fn assert_schema(schema: &Value, instance: &Value) {
    let validator = jsonschema::validator_for(schema).expect("output schema compiles");
    let errors = validator.iter_errors(instance).collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema rejected {instance}: {errors:?}");
}

fn resolve<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    let mut resolved = schema;
    while let Some(reference) = resolved.get("$ref").and_then(Value::as_str) {
        resolved = root
            .pointer(reference.strip_prefix('#').expect("local reference"))
            .expect("reference resolves");
    }
    resolved
}

fn allows_type(root: &Value, schema: &Value, expected: &str) -> bool {
    let schema = resolve(root, schema);
    match &schema["type"] {
        Value::String(value) if value == expected => true,
        Value::Array(values) if values.iter().any(|value| value == expected) => true,
        _ => schema["anyOf"]
            .as_array()
            .is_some_and(|branches| branches.iter().any(|b| allows_type(root, b, expected))),
    }
}

fn find_count(requests: &[wiremock::Request]) -> usize {
    requests.iter().filter(|r| r.url.path() == FIND).count()
}

async fn requests(server: &MockServer) -> Vec<wiremock::Request> {
    let requests = server.received_requests().await.expect("request log");
    assert!(requests.iter().all(|r| r.method.as_str() == "GET"));
    requests
}

fn queries(requests: &[wiremock::Request]) -> Vec<BTreeMap<String, String>> {
    requests
        .iter()
        .filter(|r| r.url.path() == FIND)
        .map(|r| r.url.query_pairs().into_owned().collect())
        .collect()
}

#[tokio::test]
async fn the_definition_declares_the_description_inputs_and_defaults() {
    let server = MockServer::start().await;
    let mut harness = Harness::start(target_for(&server), options());
    let tool = tool_definition(&mut harness).await;
    assert_eq!(tool["description"], DESCRIPTION);
    let input = &tool["inputSchema"];
    assert_eq!(input["type"], "object");
    assert_eq!(input["additionalProperties"], false);
    let properties = input["properties"].as_object().expect("properties");
    assert_eq!(
        properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["enabled", "group_by", "limit", "source", "tag"])
    );
    assert!(
        input["required"]
            .as_array()
            .is_none_or(|required| required.is_empty()),
        "every input is optional"
    );
    let group_by = &properties["group_by"];
    assert_eq!(group_by["default"], "technique");
    assert_eq!(
        resolve(input, group_by)["enum"],
        json!(["technique", "tactic", "index_pattern", "integration"])
    );
    let source = &properties["source"];
    assert_eq!(source["default"], "all");
    assert_eq!(
        resolve(input, source)["enum"],
        json!(["custom", "customized", "prebuilt", "all"])
    );
    let limit = &properties["limit"];
    assert_eq!(
        (&limit["default"], &limit["minimum"], &limit["maximum"]),
        (&json!(50), &json!(1), &json!(200))
    );
    assert!(allows_type(input, limit, "integer"));
    let tag = &properties["tag"];
    assert_eq!(tag["description"], TAG_DESCRIPTION);
    assert_eq!(
        (&tag["minLength"], &tag["maxLength"]),
        (&json!(1), &json!(1024))
    );
    assert!(allows_type(input, tag, "string") && allows_type(input, tag, "null"));
    let enabled = &properties["enabled"];
    assert!(allows_type(input, enabled, "boolean") && allows_type(input, enabled, "null"));
    assert_eq!(tool["outputSchema"]["type"], "object");
    assert!(server.received_requests().await.unwrap().is_empty());
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

/// No arguments: the whole corpus, every source, grouped by technique, at
/// most 50 rows, read in one page with no filter and no capability probe.
#[tokio::test]
async fn defaults_are_technique_all_sources_and_limit_50() {
    let rules = SORTED_PAGE["data"].as_array().unwrap().clone();
    let server = corpus_server(rules, None).await;
    let mut harness = Harness::start(target_for(&server), options());
    let schema = tool_definition(&mut harness).await["outputSchema"].clone();
    let reply = call(&mut harness, 1, json!({})).await;
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(
        structured["data"],
        json!({
            "group_by": "technique",
            "summary": {"rules": 2, "enabled_rules": 2, "disabled_rules": 0, "unmapped_rules": 1, "groups": 1},
            "rows": [{
                "key": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactics": ["TA0002"],
                "enabled_rules": 1,
                "disabled_rules": 0,
            }],
        })
    );
    assert_eq!(
        structured["page"],
        json!({"limit": 50, "returned": 1, "total": 1, "has_more": false, "truncated": false})
    );
    assert_schema(&schema, structured);
    let requests = requests(&server).await;
    assert_eq!(requests.len(), 1, "one page, no probe");
    let query = &queries(&requests)[0];
    assert_eq!(
        query,
        &BTreeMap::from([
            ("page".to_string(), "1".to_string()),
            ("per_page".to_string(), "500".to_string()),
            ("sort_field".to_string(), "created_at".to_string()),
            ("sort_order".to_string(), "asc".to_string()),
        ])
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn each_grouping_projects_its_rows_and_only_techniques_carry_tactics() {
    let rules = SORTED_PAGE["data"].as_array().unwrap().clone();
    let server = corpus_server(rules, None).await;
    let mut harness = Harness::start(target_for(&server), options());
    let schema = tool_definition(&mut harness).await["outputSchema"].clone();
    for (id, group_by, rows, unmapped) in [
        (
            1,
            "tactic",
            json!([{"key": "TA0002", "name": "Execution", "enabled_rules": 1, "disabled_rules": 0}]),
            1,
        ),
        (
            2,
            "index_pattern",
            json!([
                {"key": "elasticctl-sample-alert-events", "enabled_rules": 1, "disabled_rules": 0},
                {"key": "elasticctl-sample-compose-missing", "enabled_rules": 1, "disabled_rules": 0},
            ]),
            0,
        ),
        (
            3,
            "integration",
            json!([{"key": "system", "enabled_rules": 1, "disabled_rules": 0}]),
            1,
        ),
    ] {
        let reply = call(&mut harness, id, json!({"group_by": group_by})).await;
        let structured = &reply["result"]["structuredContent"];
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        assert_eq!(structured["data"]["group_by"], group_by);
        assert_eq!(structured["data"]["rows"], rows, "{group_by}");
        assert_eq!(structured["data"]["summary"]["unmapped_rules"], unmapped);
        let groups = rows.as_array().unwrap().len();
        assert_eq!(structured["data"]["summary"]["groups"], groups);
        assert_eq!(structured["page"]["total"], groups);
        for row in structured["data"]["rows"].as_array().unwrap() {
            assert!(row.get("tactics").is_none(), "{group_by}: {row}");
        }
        assert_schema(&schema, structured);
    }
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn enabled_source_and_tag_reach_every_page_request() {
    let rules = (0..501).map(technique_rule).collect();
    let server = corpus_server(rules, None).await;
    mount_status(&server, "9.5.1").await;
    let mut harness = Harness::start(target_for(&server), options());
    let tag = "\u{e9}".repeat(512);
    for (id, arguments, expected) in [
        (
            1,
            json!({"enabled": false, "source": "custom", "tag": "prod", "group_by": "integration", "limit": 7}),
            "alert.attributes.params.immutable: false AND alert.attributes.enabled: false AND alert.attributes.tags: \"prod\"".to_string(),
        ),
        (
            2,
            json!({"source": "prebuilt", "enabled": true}),
            "alert.attributes.params.immutable: true AND alert.attributes.enabled: true".to_string(),
        ),
        (
            3,
            json!({"source": "customized", "tag": tag}),
            format!("alert.attributes.params.ruleSource.isCustomized: true AND alert.attributes.tags: \"{tag}\""),
        ),
    ] {
        let before = find_count(&requests(&server).await);
        let reply = call(&mut harness, id, arguments.clone()).await;
        assert_eq!(reply["result"]["isError"], false, "{arguments}: {reply}");
        let page = &reply["result"]["structuredContent"]["page"];
        assert_eq!(page["limit"], arguments["limit"].as_u64().unwrap_or(50));
        let requests = requests(&server).await;
        let new = &queries(&requests)[before..];
        assert_eq!(new.len(), 2, "{arguments}: two pages");
        for (number, query) in new.iter().enumerate() {
            assert_eq!(query["page"], (number + 1).to_string());
            assert_eq!(query["filter"], expected, "{arguments}");
        }
    }
    let probes = requests(&server)
        .await
        .iter()
        .filter(|r| r.url.path() == STATUS_PATH)
        .count();
    assert_eq!(probes, 1, "one cached capability probe");
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn invalid_inputs_fail_before_any_request() {
    let server = corpus_server(vec![marker()], None).await;
    mount_status(&server, "9.5.1").await;
    let mut harness = Harness::start(target_for(&server), options());
    let schema = tool_definition(&mut harness).await["outputSchema"].clone();
    let long = "a".repeat(1025);
    let invalid = [
        json!({"group_by": "rule"}),
        json!({"group_by": "Technique"}),
        json!({"group_by": "index-pattern"}),
        json!({"group_by": ""}),
        json!({"group_by": 1}),
        json!({"group_by": null}),
        json!({"source": "any"}),
        json!({"source": "ALL"}),
        json!({"source": null}),
        json!({"limit": 0}),
        json!({"limit": 201}),
        json!({"limit": -1}),
        json!({"limit": "50"}),
        json!({"limit": 1.5}),
        json!({"limit": null}),
        json!({"tag": ""}),
        json!({"tag": " "}),
        json!({"tag": "\n\t"}),
        json!({"tag": long}),
        json!({"tag": 7}),
        json!({"tag": ["prod"]}),
        json!({"enabled": "true"}),
        json!({"enabled": 1}),
        json!({"technique": "T1059"}),
        json!({"filter": "alert.attributes.enabled: true"}),
        json!({"index": "logs-*"}),
    ];
    for (id, arguments) in invalid.into_iter().enumerate() {
        let reply = call(&mut harness, id as u64 + 1, arguments.clone()).await;
        let structured = &reply["result"]["structuredContent"];
        assert_eq!(reply["result"]["isError"], true, "{arguments}");
        assert_eq!(
            structured["error"]["code"], "invalid_argument",
            "{arguments}"
        );
        assert!(structured.get("data").is_none());
        assert_schema(&schema, structured);
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "an invalid input reached the server"
    );
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn a_source_other_than_all_below_9_5_1_is_elastic_unsupported() {
    let server = corpus_server(vec![marker()], None).await;
    mount_status(&server, "9.5.0").await;
    let mut harness = Harness::start(target_for(&server), options());
    let schema = tool_definition(&mut harness).await["outputSchema"].clone();
    for (id, source) in [(1, "custom"), (2, "customized"), (3, "prebuilt")] {
        let reply = call(&mut harness, id, json!({"source": source})).await;
        let structured = &reply["result"]["structuredContent"];
        assert_eq!(reply["result"]["isError"], true, "{source}");
        assert_eq!(structured["error"]["kind"], "unsupported");
        assert_eq!(structured["error"]["code"], "elastic_unsupported");
        assert!(structured.get("data").is_none());
        assert_schema(&schema, structured);
    }
    assert_eq!(
        requests(&server)
            .await
            .iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>(),
        vec![STATUS_PATH],
        "only the cached capability probe"
    );
    let reply = call(&mut harness, 4, json!({"source": "all"})).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(find_count(&requests(&server).await), 1);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn page_total_is_the_group_count_and_201_groups_at_limit_200_are_truncated() {
    let rules = (0..201).map(technique_rule).collect();
    let server = corpus_server(rules, None).await;
    let mut harness = Harness::start(target_for(&server), options());
    let schema = tool_definition(&mut harness).await["outputSchema"].clone();
    for (id, arguments, page) in [
        (
            1,
            json!({"limit": 200}),
            json!({"limit": 200, "returned": 200, "total": 201, "has_more": true, "truncated": true}),
        ),
        (
            2,
            json!({}),
            json!({"limit": 50, "returned": 50, "total": 201, "has_more": true, "truncated": true}),
        ),
        (
            3,
            json!({"limit": 200, "group_by": "tactic"}),
            json!({"limit": 200, "returned": 1, "total": 1, "has_more": false, "truncated": false}),
        ),
    ] {
        let reply = call(&mut harness, id, arguments.clone()).await;
        let structured = &reply["result"]["structuredContent"];
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        assert_eq!(structured["page"], page, "{arguments}");
        assert_eq!(
            structured["page"]["total"],
            structured["data"]["summary"]["groups"]
        );
        assert_eq!(
            structured["data"]["rows"].as_array().unwrap().len(),
            page["returned"].as_u64().unwrap() as usize
        );
        assert_eq!(structured["data"]["summary"]["rules"], 201);
        assert_schema(&schema, structured);
    }
    let reply = call(&mut harness, 4, json!({"limit": 200})).await;
    let rows = reply["result"]["structuredContent"]["data"]["rows"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(rows[0]["key"], "T0000");
    assert_eq!(rows[199]["key"], "T0199", "ties sort by key");
    assert_eq!(find_count(&requests(&server).await), 4, "one page per call");
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

/// Rows that do not fit the structured cap are dropped whole from the end;
/// `summary` still describes the whole corpus.
#[tokio::test]
async fn byte_cap_trimming_drops_whole_trailing_rows() {
    let patterns: Vec<String> = ["a", "b", "c", "d"]
        .iter()
        .map(|prefix| format!("{prefix}{}", "x".repeat(99_999)))
        .collect();
    let rules = patterns
        .iter()
        .enumerate()
        .map(|(n, pattern)| index_rule(n, std::slice::from_ref(pattern)))
        .collect();
    let server = corpus_server(rules, None).await;
    let mut harness = Harness::start(target_for(&server), options());
    let schema = tool_definition(&mut harness).await["outputSchema"].clone();
    let reply = call(&mut harness, 1, json!({"group_by": "index_pattern"})).await;
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(reply["result"]["isError"], false, "trimmed, not failed");
    assert_eq!(
        structured["page"],
        json!({"limit": 50, "returned": 2, "total": 4, "has_more": true, "truncated": true})
    );
    assert_eq!(
        structured["data"]["summary"],
        json!({"rules": 4, "enabled_rules": 4, "disabled_rules": 0, "unmapped_rules": 0, "groups": 4})
    );
    assert_eq!(
        structured["data"]["rows"],
        json!([
            {"key": patterns[0], "enabled_rules": 1, "disabled_rules": 0},
            {"key": patterns[1], "enabled_rules": 1, "disabled_rules": 0},
        ])
    );
    assert!(serde_json::to_string(structured).unwrap().len() <= STRUCTURED_CAP);
    assert_schema(&schema, structured);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

async fn wait_for(server: &MockServer, route: &str, expected: usize) {
    timeout(Duration::from_secs(30), async {
        loop {
            let requests = server.received_requests().await.expect("requests");
            if requests.iter().filter(|r| r.url.path() == route).count() >= expected {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{expected} requests to {route} did not arrive"));
}

/// With three `rules_get` calls held, a fourth call is still admitted: the
/// call that ended released its permit. The admitted call fails validation
/// before any request. Returns the replies of the three held calls.
async fn assert_a_permit_is_free(
    harness: &mut ClockHarness,
    gate: &Gate,
    expire_held: bool,
) -> Vec<Value> {
    let (replies, attempts) = permit_check(harness, gate, expire_held, 0).await;
    if !expire_held {
        assert_eq!(
            attempts, 1,
            "a caller without a short deadline must pass on its first attempt"
        );
    }
    replies
}

/// `expire_attempts` advances the clock before probing to exercise void attempts.
async fn permit_check(
    harness: &mut ClockHarness,
    gate: &Gate,
    expire_held: bool,
    expire_attempts: usize,
) -> (Vec<Value>, usize) {
    // A gate cannot prevent a one-second holder from reaching its deadline.
    // Freeze that clock so only the call that ended can have freed a permit.
    let clock = harness.pause_clock().await;
    let baseline = gate.arrivals.load(Ordering::SeqCst);
    for attempt in 1..=6 {
        let started = clock.now().await;
        let base = 10 * attempt as u64;
        let held = [base + 1, base + 2, base + 3];
        let probe = base + 4;
        for id in held {
            send_call(
                harness,
                id,
                "rules_get",
                json!({"selector": "elasticctl-sample-alert-probe"}),
            )
            .await;
        }
        let arrivals = baseline + attempt * held.len();
        gate.wait_for(arrivals).await;
        if attempt <= expire_attempts {
            clock.advance(Duration::from_secs(2)).await;
        }
        send_call(harness, probe, NAME, json!({"limit": 0})).await;
        let mut replies = Vec::new();
        let admitted = loop {
            let reply = harness.receive_json().await;
            if reply["id"] == probe {
                break reply;
            }
            assert!(held.contains(&reply["id"].as_u64().unwrap()), "{reply}");
            assert_eq!(
                reply["result"]["structuredContent"]["error"]["code"], "deadline_exceeded",
                "a gated call cannot finish before release"
            );
            replies.push(reply);
        };
        assert_eq!(
            admitted["result"]["structuredContent"]["error"]["code"], "invalid_argument",
            "admitted, not busy"
        );
        // Arrival counts alone do not prove holders stayed inside their permits.
        // Unchanged server time and closed gates rule out both ways they can finish.
        let void = !replies.is_empty() || clock.now().await != started;
        if !void && expire_held {
            clock.advance(Duration::from_secs(2)).await;
        } else {
            gate.open(held.len(), arrivals).await;
        }
        while replies.len() < held.len() {
            replies.push(harness.receive_json().await);
        }
        let mut ids: Vec<u64> = replies.iter().map(|r| r["id"].as_u64().unwrap()).collect();
        ids.sort_unstable();
        assert_eq!(ids, held);
        if void {
            assert!(
                attempt < 6,
                "held calls expired before the probe after 5 retries (6 attempts)"
            );
            continue;
        }
        if expire_held {
            gate.open(held.len(), arrivals).await;
        } else {
            assert!(
                replies
                    .iter()
                    .all(|reply| reply["result"]["isError"] == false),
                "every holder must answer from the released gate: {replies:?}"
            );
        }
        return (replies, attempt);
    }
    unreachable!("the sixth void attempt fails")
}

#[tokio::test]
async fn expired_holders_void_the_probe_and_the_next_attempt_proves_admission() {
    let server = MockServer::start().await;
    mount_held_rule(&server).await;
    let gate = Gate::start(&server).await;
    let mut short = options();
    short.call_timeout = Duration::from_secs(1);
    let mut harness = ClockHarness::start(gate.target.clone(), short);
    let (replies, attempts) = permit_check(&mut harness, &gate, true, 1).await;
    assert_eq!(attempts, 2, "the expired attempt must not count as a pass");
    for reply in replies {
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"],
            "deadline_exceeded"
        );
    }
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
#[should_panic(expected = "held calls expired before the probe after 5 retries (6 attempts)")]
async fn expired_holders_fail_after_five_retries() {
    let server = MockServer::start().await;
    mount_held_rule(&server).await;
    let gate = Gate::start(&server).await;
    let mut short = options();
    short.call_timeout = Duration::from_secs(1);
    let mut harness = ClockHarness::start(gate.target.clone(), short);
    permit_check(&mut harness, &gate, true, 6).await;
}

#[tokio::test]
async fn the_permit_probe_is_busy_while_four_gated_calls_hold_every_permit() {
    let server = MockServer::start().await;
    mount_held_rule(&server).await;
    let gate = Gate::start(&server).await;
    let mut harness = ClockHarness::start(gate.target.clone(), options());
    let _clock = harness.pause_clock().await;
    let held = [10_u64, 11, 12, 13];
    for id in held {
        send_call(
            &mut harness,
            id,
            "rules_get",
            json!({"selector": "elasticctl-sample-alert-probe"}),
        )
        .await;
    }
    gate.wait_for(held.len()).await;
    let reply = call(&mut harness, 14, json!({"limit": 0})).await;
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["code"], "busy",
        "without a freed permit, the admission assertion must fail"
    );
    gate.release.add_permits(held.len());
    let mut ids = Vec::new();
    for _ in held {
        let reply = harness.receive_json().await;
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        ids.push(reply["id"].as_u64().unwrap());
    }
    ids.sort_unstable();
    assert_eq!(ids, held);
    harness.close_input();
    harness.join().await.expect("clean EOF");
}

/// 1,200 rules read in three pages; page 2 answers after `delay`.
async fn three_page_server(delay: Duration) -> MockServer {
    let rules = (0..1_200).map(technique_rule).collect();
    let server = corpus_server(rules, Some((2, delay))).await;
    mount_held_rule(&server).await;
    server
}

#[tokio::test]
async fn cancelling_during_page_2_of_3_sends_no_page_3_and_frees_the_permit() {
    let server = three_page_server(Duration::from_secs(1)).await;
    let gate = Gate::start(&server).await;
    let mut harness = ClockHarness::start(gate.target.clone(), options());
    send_call(&mut harness, 1, NAME, json!({})).await;
    wait_for(&server, FIND, 2).await;
    harness
        .send_json(json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 1, "reason": "test", "_meta": current_metadata()},
        }))
        .await;
    // Past the delayed page 2: a live call would have requested page 3.
    sleep(Duration::from_millis(1_000)).await;
    assert_eq!(find_count(&requests(&server).await), 2, "no page 3");
    for reply in assert_a_permit_is_free(&mut harness, &gate, false).await {
        assert_eq!(reply["result"]["isError"], false, "{reply}");
    }
    let requests = requests(&server).await;
    assert_eq!(find_count(&requests), 2, "no page 3");
    let pages: Vec<String> = queries(&requests)
        .into_iter()
        .map(|q| q["page"].clone())
        .collect();
    assert_eq!(pages, ["1", "2"]);
    harness.close_input();
    harness.assert_no_reply().await;
    harness.join().await.expect("clean EOF");
}

#[tokio::test]
async fn a_one_second_deadline_during_page_2_of_3_sends_no_page_3_and_frees_the_permit() {
    let server = three_page_server(Duration::from_secs(2)).await;
    let gate = Gate::start(&server).await;
    let mut one_second = options();
    one_second.call_timeout = Duration::from_secs(1);
    let mut harness = ClockHarness::start(gate.target.clone(), one_second);
    let schema = tool_definition(&mut harness).await["outputSchema"].clone();
    let started = tokio::time::Instant::now();
    let reply = call(&mut harness, 1, json!({})).await;
    assert!(started.elapsed() < Duration::from_millis(1_900));
    let structured = &reply["result"]["structuredContent"];
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    assert_eq!(structured["error"]["code"], "deadline_exceeded");
    assert!(structured.get("data").is_none(), "no partial data");
    assert!(structured.get("page").is_none(), "no partial page");
    assert_schema(&schema, structured);
    assert_eq!(find_count(&requests(&server).await), 2);
    // Past the delayed page 2: a live call would have requested page 3.
    sleep(Duration::from_millis(1_500)).await;
    assert_eq!(find_count(&requests(&server).await), 2, "no page 3");
    for reply in assert_a_permit_is_free(&mut harness, &gate, true).await {
        assert_eq!(
            reply["result"]["structuredContent"]["error"]["code"],
            "deadline_exceeded"
        );
    }
    assert_eq!(find_count(&requests(&server).await), 2, "no page 3");
    harness.close_input();
    harness.join().await.expect("clean EOF");
}
