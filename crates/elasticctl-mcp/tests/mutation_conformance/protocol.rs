use super::*;
use rmcp::{
    ClientHandler, ClientLifecycleMode, ClientServiceExt, RoleClient,
    model::{CallToolRequestParams, ProtocolVersion},
    transport::async_rw::AsyncRwTransport,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

struct Scripted {
    content: Value,
    calls: Arc<AtomicUsize>,
}
fn client_info() -> rmcp::model::ClientConfig {
    serde_json::from_value(json!({"protocolVersion":"2026-07-28",
        "capabilities":{"elicitation":{"form":{}}},"clientInfo":{"name":"conformance","version":"0"}})).unwrap()
}
impl ClientHandler for Scripted {
    fn get_info(&self) -> rmcp::model::ClientConfig {
        client_info()
    }
    async fn create_elicitation(
        &self,
        request: rmcp::model::ElicitRequestParams,
        _: rmcp::service::RequestContext<RoleClient>,
    ) -> Result<rmcp::model::ElicitResult, rmcp::ErrorData> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(serde_json::to_value(request).unwrap()["mode"], "form");
        Ok(serde_json::from_value(json!({"action":"accept","content":self.content})).unwrap())
    }
}
struct DefaultHandler;
impl ClientHandler for DefaultHandler {
    fn get_info(&self) -> rmcp::model::ClientConfig {
        client_info()
    }
}
struct Tee<R> {
    reader: R,
    bytes: Arc<std::sync::Mutex<Vec<u8>>>,
}
impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Tee<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let start = buf.filled().len();
        let result = std::pin::Pin::new(&mut this.reader).poll_read(cx, buf);
        this.bytes
            .lock()
            .unwrap()
            .extend_from_slice(&buf.filled()[start..]);
        result
    }
}
fn frames(bytes: &std::sync::Mutex<Vec<u8>>) -> Vec<Value> {
    String::from_utf8(bytes.lock().unwrap().clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
async fn sdk<H: ClientHandler>(handler: H, expected: &str, writes: usize, response: Value) {
    let s = stack().await;
    write_mock(&s, writes as u64, 200).await;
    let (cw, sr) = tokio::io::duplex(1048576);
    let (sw, cr) = tokio::io::duplex(1048576);
    let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
    let received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sr = Tee {
        reader: sr,
        bytes: sent.clone(),
    };
    let cr = Tee {
        reader: cr,
        bytes: received.clone(),
    };
    let server = tokio::spawn(elasticctl_mcp::serve_io(target(&s), options(), sr, sw));
    let client = handler
        .serve_with_lifecycle(
            AsyncRwTransport::<RoleClient, _, _>::new_client(cr, cw),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .unwrap();
    let planned = client
        .call_tool(
            CallToolRequestParams::new("rules_set_enabled_plan").with_arguments(
                json!({"selectors":["r"],"enabled":false})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .unwrap();
    let id = planned.structured_content.unwrap()["data"]["plan"]["plan_id"].clone();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.call_tool(
            CallToolRequestParams::new("plan_apply")
                .with_arguments(json!({"plan_id":id}).as_object().unwrap().clone()),
        ),
    )
    .await
    .unwrap()
    .unwrap()
    .structured_content
    .unwrap();
    if writes == 1 {
        assert_eq!(result["data"]["plan"]["state"], expected, "{result}");
    } else {
        assert_eq!(result["error"]["code"], expected, "{result}");
    }
    assert_writes(&s, writes).await;
    client.cancel().await.unwrap();
    server.await.unwrap().unwrap();
    let sent = frames(&sent);
    let received = frames(&received);
    assert!(received.iter().all(|f| f["method"] != "elicitation/create"));
    let rounds: Vec<_> = sent
        .iter()
        .filter(|f| f["method"] == "tools/call" && f["params"]["name"] == "plan_apply")
        .collect();
    assert_eq!(rounds.len(), 2, "{sent:?}");
    let first = received
        .iter()
        .find(|f| f["id"] == rounds[0]["id"] && f.get("result").is_some())
        .unwrap();
    assert_eq!(first["result"]["resultType"], "input_required");
    let state = first["result"]["requestState"].as_str().unwrap();
    assert!(!state.is_empty());
    assert!(rounds[0]["params"].get("inputResponses").is_none());
    assert_eq!(rounds[1]["params"]["requestState"], state);
    assert_eq!(
        rounds[1]["params"]["inputResponses"],
        json!({"confirm":response})
    );
}
#[tokio::test]
async fn sdk_call_tool_accepts_both_rounds() {
    let calls = Arc::new(AtomicUsize::new(0));
    sdk(
        Scripted {
            content: json!({"apply":true}),
            calls: calls.clone(),
        },
        "applied",
        1,
        accept(),
    )
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn sdk_default_handler_declines() {
    sdk(
        DefaultHandler,
        "plan_declined",
        0,
        json!({"action":"decline"}),
    )
    .await;
}
#[tokio::test]
async fn sdk_blind_accept_never_writes() {
    for content in [json!({}), json!({"apply":"true"}), json!({"apply":1})] {
        let calls = Arc::new(AtomicUsize::new(0));
        sdk(
            Scripted {
                content: content.clone(),
                calls: calls.clone(),
            },
            "not_confirmed",
            0,
            json!({"action":"accept","content":content}),
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
#[tokio::test]
async fn same_change_hash_matches_across_paths() {
    let s = stack().await;
    let mut current = Harness::start(target(&s), options());
    let a = plan(&mut current).await;
    let mut legacy = Harness::start(target(&s), options());
    let mut init = support::legacy_initialize(100);
    init["params"]["capabilities"] = json!({"elicitation":{"form":{}}});
    legacy.send_json(init).await;
    receive(&mut legacy).await;
    send(
        &mut legacy,
        1,
        json!({"name":"rules_set_enabled_plan","arguments":{"selectors":["r"],"enabled":false}}),
    )
    .await;
    let b = receive(&mut legacy).await;
    for hash in [&a["hash"], &data(&b)["plan"]["hash"]] {
        let hash = hash.as_str().expect("hash must be a string");
        assert_eq!(hash.len(), 64);
        assert!(
            hash.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );
    }
    assert_eq!(a["hash"], data(&b)["plan"]["hash"]);
    assert_ne!(a["plan_id"], data(&b)["plan"]["plan_id"]);
    assert_writes(&s, 0).await;
    finish(current).await;
    finish(legacy).await;
}
#[tokio::test]
async fn sequential_valid_answers_write_once() {
    let s = stack().await;
    let gate = Gate::start(&s).await;
    let mut h = Harness::start(gate.target.clone(), options());
    write_mock(&s, 1, 200).await;
    let p = plan(&mut h).await;
    let id = &p["plan_id"];
    let first = question(&mut h, id).await;
    gate.hold.store(1, Ordering::SeqCst);
    send(&mut h, 10, answer(id, &first, accept())).await;
    wait_count(&gate.arrivals, 1).await;
    let second = question(&mut h, id).await;
    assert_ne!(first["requestState"], second["requestState"]);
    send(&mut h, 11, answer(id, &second, accept())).await;
    let a = receive(&mut h).await;
    gate.release.add_permits(1);
    let b = receive(&mut h).await;
    for r in [&a, &b] {
        assert_eq!(data(r)["plan"]["state"], "applied", "{r}");
    }
    assert!([&a, &b].iter().any(|r| data(r)["replayed"] == true));
    assert_writes(&s, 1).await;
    finish(h).await;
}
#[tokio::test]
async fn oversized_apply_closes_without_applying() {
    for legacy in [false, true] {
        let s = stack().await;
        write_mock(&s, 0, 200).await;
        let (mut cw, sr) = tokio::io::duplex(1048576);
        let (sw, cr) = tokio::io::duplex(1048576);
        let audit = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let captured = audit.clone();
        let server = tokio::spawn(elasticctl_mcp::server::serve_io_with_audit(
            target(&s),
            options(),
            sr,
            sw,
            move |line: &str| captured.lock().unwrap().push(line.into()),
        ));
        let mut output = tokio::io::BufReader::new(cr);
        if legacy {
            cw.write_all(format!("{}\n", support::legacy_initialize(100)).as_bytes())
                .await
                .unwrap();
            let mut line = String::new();
            tokio::time::timeout(Duration::from_secs(30), output.read_line(&mut line))
                .await
                .expect("server response timed out")
                .unwrap();
        }
        let mut ids = Vec::new();
        for n in 0..3 {
            let mut p = params(
                "rules_set_enabled_plan",
                json!({"selectors":["r"],"enabled":false}),
            );
            if legacy {
                p.as_object_mut().unwrap().remove("_meta");
            }
            cw.write_all(
                format!(
                    "{}\n",
                    json!({"jsonrpc":"2.0","id":n,"method":"tools/call","params":p})
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            let mut line = String::new();
            tokio::time::timeout(Duration::from_secs(30), output.read_line(&mut line))
                .await
                .expect("server response timed out")
                .unwrap();
            let r: Value = serde_json::from_str(&line).unwrap();
            ids.push(data(&r)["plan"]["plan_id"].clone());
        }
        assert!(ids.iter().all(Value::is_string));
        let mut p = params("plan_apply", json!({"plan_id":ids[0]}));
        if legacy {
            p.as_object_mut().unwrap().remove("_meta");
        }
        let mut frame =
            json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":p}).to_string();
        frame.push_str(&" ".repeat(262145 - frame.len()));
        assert_eq!(frame.len(), 262145);
        frame.push('\n');
        if let Err(e) = cw.write_all(frame.as_bytes()).await {
            assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe);
        }
        tokio::time::timeout(Duration::from_secs(30), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut line = String::new();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(30), output.read_line(&mut line))
                .await
                .expect("server response timed out")
                .unwrap(),
            0
        );
        assert_writes(&s, 0).await;
        let events: Vec<_> = audit
            .lock()
            .unwrap()
            .iter()
            .map(|line| serde_json::from_str::<Value>(line).unwrap()["audit"]["event"].clone())
            .collect();
        assert_eq!(events, vec![json!("plan_created"); ids.len()]);
    }
}

async fn wait_count(count: &AtomicUsize, n: usize) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while count.load(Ordering::SeqCst) < n {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
}
fn limits() -> (usize, usize) {
    let server = include_str!("../../src/server.rs");
    assert!(
        server.contains("Semaphore::new(4)"),
        "design 8 requires four active calls"
    );
    let plan = include_str!("../../src/plan/mod.rs");
    assert!(
        plan.contains("MAX_OPEN_PLANS: usize = 8;"),
        "design 5.4 requires eight open plans"
    );
    (4, 8)
}
#[tokio::test]
async fn planners_and_applies_share_admission_and_store_limits() {
    let (permits, limit) = limits();
    let s = stack().await;
    let gate = Gate::start(&s).await;
    let mut h = Harness::start(gate.target.clone(), options());
    let mut plans = Vec::new();
    for n in 0..permits {
        let rule_id = format!("r{n}");
        Mock::given(method("POST"))
            .and(path("/api/detection_engine/rules/_bulk_action"))
            .and(wiremock::matchers::body_json(json!({"action":"disable",
                "query":format!("alert.attributes.params.ruleId: \"{rule_id}\"")})))
            .respond_with(ResponseTemplate::new(200).set_body_json(fixture("rules_bulk_disable")))
            .expect(1)
            .mount(&s)
            .await;
        let r = call(
            &mut h,
            "rules_set_enabled_plan",
            json!({"selectors":[rule_id],"enabled":false}),
        )
        .await;
        let p = data(&r)["plan"].clone();
        assert_eq!(p["state"], "open", "{r}");
        let q = question(&mut h, &p["plan_id"]).await;
        plans.push((p, q));
    }
    gate.hold.store(permits, Ordering::SeqCst);
    for (n, (p, q)) in plans.iter().enumerate() {
        send(&mut h, 10 + n as u64, answer(&p["plan_id"], q, accept())).await;
    }
    wait_count(&gate.arrivals, permits).await;
    for n in 0..limit {
        send(
            &mut h,
            100 + n as u64,
            params(
                "rules_set_enabled_plan",
                json!({"selectors":["r"],"enabled":false}),
            ),
        )
        .await;
    }
    for _ in 0..limit {
        let r = receive(&mut h).await;
        assert!(
            r["id"].as_u64().unwrap() >= 100,
            "apply escaped delayed window: {r}"
        );
        assert_eq!(code(&r), "busy", "{r}");
    }
    gate.release.add_permits(permits);
    for _ in 0..permits {
        let r = receive(&mut h).await;
        assert_eq!(data(&r)["plan"]["state"], "applied", "{r}");
    }
    for wave in 0..(limit / permits) {
        for n in 0..permits {
            send(
                &mut h,
                200 + (wave * permits + n) as u64,
                params(
                    "rules_set_enabled_plan",
                    json!({"selectors":["r"],"enabled":false}),
                ),
            )
            .await;
        }
        for _ in 0..permits {
            let r = receive(&mut h).await;
            assert_eq!(data(&r)["plan"]["state"], "open", "{r}");
        }
    }
    let over = call(
        &mut h,
        "rules_set_enabled_plan",
        json!({"selectors":["r"],"enabled":false}),
    )
    .await;
    assert_eq!(code(&over), "too_many_plans");
    let listed = call(&mut h, "plan_list", json!({})).await;
    assert_eq!(
        data(&listed)["plans"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["state"] == "open")
            .count(),
        limit
    );
    assert_eq!(
        s.received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST")
            .count(),
        permits
    );
    s.verify().await;
    let audit = h
        .audit
        .lock()
        .unwrap()
        .iter()
        .map(|s| serde_json::from_str::<Value>(s).unwrap())
        .collect::<Vec<_>>();
    for (p, _) in plans {
        assert_eq!(
            audit
                .iter()
                .filter(|v| v["audit"]["plan_id"] == p["plan_id"]
                    && v["audit"]["event"] == "apply_started")
                .count(),
            1
        );
        let replay = call(&mut h, "plan_apply", json!({"plan_id":p["plan_id"]})).await;
        assert_eq!(data(&replay)["replayed"], true);
    }
    assert_eq!(
        s.received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST")
            .count(),
        permits
    );
    s.verify().await;
    finish(h).await;
}

struct Gate {
    target: elasticctl_core::Resolved,
    hold: Arc<AtomicUsize>,
    arrivals: Arc<AtomicUsize>,
    release: Arc<tokio::sync::Semaphore>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Gate {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Gate {
    async fn start(s: &MockServer) -> Self {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut target = target(s);
        target.profile.kibana_url = format!("http://{}", listener.local_addr().unwrap());
        target.profile.es_url = Some(target.profile.kibana_url.clone());
        let upstream = *s.address();
        let hold = Arc::new(AtomicUsize::new(0));
        let arrivals = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let (h, a, r) = (hold.clone(), arrivals.clone(), release.clone());
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    socket = listener.accept() => {
                        let (socket, _) = socket.unwrap();
                        let (h, a, r) = (h.clone(), a.clone(), r.clone());
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
                            if header.starts_with("GET /_security/_authenticate ") &&
                                h.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
                                a.fetch_add(1, Ordering::SeqCst);
                                r.acquire().await.unwrap().forget();
                            }
                            tokio::io::copy(&mut remote, socket.get_mut()).await.unwrap();
                        });
                    }
                    Some(result) = connections.join_next(), if !connections.is_empty() => { result.unwrap(); }
                }
            }
        });
        Self {
            target,
            hold,
            arrivals,
            release,
            task,
        }
    }
}
