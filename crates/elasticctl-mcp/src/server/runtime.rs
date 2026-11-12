use std::{
    panic::{self, AssertUnwindSafe},
    sync::Arc,
    thread,
};

use elasticctl_core::{Error, ErrorKind, Resolved, Result};
use rmcp::{ServiceExt, transport::Transport as McpTransport};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::oneshot,
};
use tokio_util::sync::CancellationToken;

use super::{
    ServerOptions, ServerState,
    handler::McpServer,
    lifecycle::{
        CurrentLifecycleService, FirstPath, LegacyInitializationGate, ReplayTransport, first_path,
    },
    validate_target,
};
use crate::bounded_io::BoundedIo;

/// Serve MCP over process stdin and stdout.
pub async fn serve_stdio(target: Resolved, options: ServerOptions) -> Result<()> {
    let root = CancellationToken::new();
    let signal_root = root.clone();
    let signal = tokio::spawn(await_stdio_shutdown(signal_root));
    let result = serve_io_with_root(
        target,
        options,
        tokio::io::stdin(),
        tokio::io::stdout(),
        root,
        None,
    )
    .await;
    signal.abort();
    let _ = signal.await;
    result
}

#[cfg(unix)]
async fn await_stdio_shutdown(root: CancellationToken) {
    let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        root.cancelled().await;
        return;
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => root.cancel(),
        _ = terminate.recv() => root.cancel(),
        _ = root.cancelled() => {},
    }
}

#[cfg(not(unix))]
async fn await_stdio_shutdown(root: CancellationToken) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => root.cancel(),
        _ = root.cancelled() => {},
    }
}

/// Serve MCP over bounded newline-delimited JSON streams.
pub async fn serve_io<R, W>(
    target: Resolved,
    options: ServerOptions,
    input: R,
    output: W,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    serve_io_with_root(
        target,
        options,
        input,
        output,
        CancellationToken::new(),
        None,
    )
    .await
}

/// Options available only through the integration test entry point.
#[doc(hidden)]
pub struct TestOptions {
    pub audit_writer: Box<dyn Fn(&str) + Send + Sync>,
    pub legacy_wait: Option<std::time::Duration>,
    /// Test-only plan life override; `None` keeps the production life.
    pub plan_life: Option<std::time::Duration>,
}
impl<F: Fn(&str) + Send + Sync + 'static> From<F> for TestOptions {
    fn from(writer: F) -> Self {
        Self {
            audit_writer: Box::new(writer),
            legacy_wait: None,
            plan_life: None,
        }
    }
}
impl Default for TestOptions {
    fn default() -> Self {
        Self::from(|_: &str| {})
    }
}
impl TestOptions {
    fn configure(self, state: &mut ServerState) {
        state.audit = crate::plan::audit::AuditSink::production(self.audit_writer);
        if let Some(wait) = self.legacy_wait {
            state.legacy_wait = wait;
        }
        if let Some(life) = self.plan_life {
            state.plan_life = life;
        }
    }
}

/// Serve a routed session with integration test options.
#[doc(hidden)]
pub async fn serve_io_with_audit<R, W>(
    target: Resolved,
    options: ServerOptions,
    input: R,
    output: W,
    options_for_test: impl Into<TestOptions>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let test = options_for_test.into();
    serve_io_with_root(
        target,
        options,
        input,
        output,
        CancellationToken::new(),
        Some(test),
    )
    .await
}

async fn serve_io_with_root<R, W>(
    target: Resolved,
    options: ServerOptions,
    input: R,
    output: W,
    root: CancellationToken,
    test: Option<TestOptions>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let context = validate_target(&target, &options)?;
    let mut state = ServerState::new(
        context,
        target,
        options.call_timeout,
        options.allow_query_tools,
    );
    state.allow_mutations = options.allow_mutations;
    if let Some(test) = test {
        test.configure(&mut state);
    }
    let state = Arc::new(state);
    let mut cancel_on_drop = CancelSessionOnDrop::new(root.clone());
    let (complete, waiting) = oneshot::channel();
    thread::Builder::new()
        .name("elasticctl-mcp".to_string())
        .spawn(move || {
            let result = panic::catch_unwind(AssertUnwindSafe(|| {
                tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::new(), || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_io()
                        .enable_time()
                        .build()
                        .map_err(|_| mcp_runtime_error("MCP session runtime could not start"))?;
                    let result = runtime.block_on(serve_with_writes(state, input, output, root));
                    runtime.shutdown_background();
                    result
                })
            }));
            let result = match result {
                Ok(result) => result,
                Err(_) => Err(mcp_runtime_error("MCP session thread failed")),
            };
            let _ = complete.send(result);
        })
        .map_err(|_| mcp_runtime_error("MCP session thread could not start"))?;
    let result = waiting
        .await
        .map_err(|_| mcp_runtime_error("MCP session completion channel closed"))?;
    cancel_on_drop.disarm();
    result
}

struct CancelSessionOnDrop {
    root: CancellationToken,
    armed: bool,
}

impl CancelSessionOnDrop {
    fn new(root: CancellationToken) -> Self {
        Self { root, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelSessionOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.root.cancel();
        }
    }
}

fn mcp_runtime_error(message: &'static str) -> Error {
    Error::new(ErrorKind::Error, message)
}

async fn serve_session<R, W>(
    state: Arc<ServerState>,
    input: R,
    output: W,
    root: CancellationToken,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut transport = BoundedIo::with_cancellation(input, output, root.clone());
    let Some(first) = transport.receive().await else {
        return Ok(());
    };
    let replay = ReplayTransport::new(first.clone(), transport, root.clone());
    match first_path(&first) {
        FirstPath::Current => {
            let running = rmcp::service::serve_directly_with_ct(
                CurrentLifecycleService::new(McpServer::new(state)),
                replay,
                None,
                root,
            );
            running
                .waiting()
                .await
                .map_err(|_| Error::new(ErrorKind::Error, "MCP server task failed"))?;
        }
        FirstPath::LegacyGate => {
            let running = LegacyInitializationGate::new(McpServer::new(state))
                .serve_with_ct(replay, root)
                .await
                .map_err(|_| Error::new(ErrorKind::Error, "MCP protocol startup failed"))?;
            running
                .waiting()
                .await
                .map_err(|_| Error::new(ErrorKind::Error, "MCP server task failed"))?;
        }
        FirstPath::SdkStartup => {
            let running = McpServer::new(state)
                .serve_with_ct(replay, root)
                .await
                .map_err(|_| Error::new(ErrorKind::Error, "MCP protocol startup failed"))?;
            running
                .waiting()
                .await
                .map_err(|_| Error::new(ErrorKind::Error, "MCP server task failed"))?;
        }
    }
    Ok(())
}

// The mutation design section 8.1 bounds pending writes at shutdown.
const APPLY_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
async fn serve_with_writes<R, W>(
    state: Arc<ServerState>,
    input: R,
    output: W,
    root: CancellationToken,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let session = serve_session(state.clone(), input, output, root.clone());
    tokio::pin!(session);
    let (result, deadline) = tokio::select! { biased;
        _ = root.cancelled() => {
            let deadline = tokio::time::Instant::now() + APPLY_SHUTDOWN_GRACE;
            let result = session.await;
            (result, deadline)
        }
        result = &mut session => (result, tokio::time::Instant::now() + APPLY_SHUTDOWN_GRACE),
    };
    let mut tasks = std::mem::take(
        &mut state
            .pending_writes
            .lock()
            .expect("pending writes lock")
            .tasks,
    );
    let _ = tokio::time::timeout_at(deadline, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    let pending = state.pending_writes.lock().expect("pending writes lock");
    let mut plans = state.plans.lock().expect("plan store lock");
    for (id, protocol) in &pending.protocols {
        if let Ok(plan) = plans.get(id, tokio::time::Instant::now())
            && plan.state == crate::plan::store::PlanState::Applying
        {
            state.audit.emit(&crate::plan::audit::line(
                crate::plan::audit::unix_seconds(),
                plan,
                protocol,
                crate::plan::audit::Event::ApplyInterrupted,
            ));
        }
        for p in plans.take_closed() {
            state.audit.emit(&crate::plan::audit::closed_line(
                crate::plan::audit::unix_seconds(),
                &p,
                protocol,
            ));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn plan_life_defaults_are_unset() {
        assert_eq!(super::TestOptions::default().plan_life, None);
        assert_eq!(super::TestOptions::from(|_: &str| {}).plan_life, None);
    }

    #[test]
    fn server_plan_life_reaches_expiry_and_text() {
        use crate::plan::store::{Plan, PlanState, PlanStore};
        let target = elasticctl_core::Resolved {
            name: "test".into(),
            source: elasticctl_core::Source::Profile,
            profile: elasticctl_core::Profile {
                kibana_url: "http://127.0.0.1:9200".into(),
                es_url: Some("http://127.0.0.1:9200".into()),
                api_key: Some("test-key".into()),
                username: None,
                password: None,
                space: "default".into(),
                verify: true,
                timeout_secs: 30,
            },
        };
        let options = super::ServerOptions::default();
        let context = super::validate_target(&target, &options).unwrap();
        let mut state = super::ServerState::new(context, target, options.call_timeout, false);
        assert_eq!(state.plan_life, Duration::from_secs(900));
        let now = tokio::time::Instant::now();
        for (test, seconds, minutes) in [
            (super::TestOptions::default(), 900, 15),
            (
                super::TestOptions {
                    plan_life: Some(Duration::from_secs(61)),
                    ..Default::default()
                },
                61,
                2,
            ),
            (
                super::TestOptions {
                    plan_life: Some(Duration::from_secs(960)),
                    ..Default::default()
                },
                960,
                16,
            ),
        ] {
            test.configure(&mut state);
            assert_eq!(state.plan_life, Duration::from_secs(seconds));
            let content = crate::plan::store::tests::sample(now).content;
            let plan = Plan::with_life(content, now, state.plan_life).unwrap();
            assert_eq!(plan.expires_in_secs(now), seconds);
            assert_eq!(
                crate::plan::view::view(&plan, true, false, now)["plan"]["expires_in_secs"],
                seconds
            );
            assert_eq!(
                crate::plan::view::list_row(&plan, now)["expires_in_secs"],
                seconds
            );
            assert!(
                plan.consent_text(now)
                    .contains(&format!("Expires in {minutes} min."))
            );
            let id = plan.id.clone();
            let mut store = PlanStore::default();
            store.insert(plan, now).unwrap();
            let before = now + Duration::from_secs(seconds - 1);
            let plan = store.get(&id, before).unwrap();
            assert_eq!(plan.state, PlanState::Open);
            assert_eq!(plan.expires_in_secs(before), 1);
            assert!(plan.consent_text(before).contains("Expires in 1 min."));
            assert_eq!(
                store
                    .get(&id, now + Duration::from_secs(seconds))
                    .unwrap()
                    .state,
                PlanState::Expired
            );
        }
    }

    #[test]
    fn audit_writer_options_leave_legacy_wait_unset() {
        let options = super::TestOptions::from(|_: &str| {});
        assert_eq!(options.legacy_wait, None);
    }

    use serde_json::{Value, json};
    use std::{sync::Arc, time::Duration};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    fn fixture(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/traditional-9.5.1")
            .join(format!("{name}.json"));
        serde_json::from_slice::<Value>(&std::fs::read(path).unwrap()).unwrap()["response"].clone()
    }

    async fn send(writer: &mut tokio::io::DuplexStream, frame: Value) {
        writer
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
    }

    async fn receive(reader: &mut BufReader<tokio::io::DuplexStream>) -> Value {
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
            let frame: Value = serde_json::from_str(&line).unwrap();
            if frame["method"] != "notifications/cancelled" {
                return frame;
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn legacy_confirmation_waits_production_240_seconds() {
        let _serial = crate::plan::confirm::tests::LEGACY_SESSION.lock().await;
        // Keep paused time from auto-advancing while TCP I/O is pending.
        let clock_guard = tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let upstream = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                connections.spawn(async move {
                    let mut headers = Vec::new();
                    while !headers.ends_with(b"\r\n\r\n") {
                        headers.push(stream.read_u8().await.unwrap());
                    }
                    let headers = String::from_utf8(headers).unwrap();
                    let request = headers.lines().next().unwrap();
                    let body = if request == "GET /_security/_authenticate HTTP/1.1" {
                        fixture("authenticate")
                    } else {
                        assert!(request.starts_with("GET /api/detection_engine/rules?"), "{request}");
                        fixture("rules_get")
                    }.to_string();
                    stream.write_all(format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len()
                    ).as_bytes()).await.unwrap();
                });
            }
        });
        let target = elasticctl_core::Resolved {
            name: "test".into(),
            source: elasticctl_core::Source::Profile,
            profile: elasticctl_core::Profile {
                kibana_url: url.clone(),
                es_url: Some(url),
                api_key: Some("test-key".into()),
                username: None,
                password: None,
                space: "default".into(),
                verify: true,
                timeout_secs: 30,
            },
        };
        let options = super::ServerOptions {
            allow_mutations: crate::MutationClasses::parse(["rules-toggle"]).unwrap(),
            ..Default::default()
        };
        let context = super::validate_target(&target, &options).unwrap();
        let mut state = super::ServerState::new(context, target, options.call_timeout, false);
        state.allow_mutations = options.allow_mutations;
        let (mut input, server_input) = tokio::io::duplex(1_048_576);
        let (server_output, output) = tokio::io::duplex(1_048_576);
        let mut output = BufReader::new(output);
        let server = tokio::spawn(super::serve_with_writes(
            Arc::new(state),
            server_input,
            server_output,
            tokio_util::sync::CancellationToken::new(),
        ));
        send(
            &mut input,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-11-25","capabilities":{"elicitation":{"form":{}}},
                "clientInfo":{"name":"test","version":"0"}
            }}),
        )
        .await;
        let initialized = receive(&mut output).await;
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
        send(
            &mut input,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await;
        let rule_id = fixture("rules_get")["rule_id"].clone();
        send(
            &mut input,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
                "name":"rules_set_enabled_plan","arguments":{"selectors":[rule_id],"enabled":false}
            }}),
        )
        .await;
        let planned = receive(&mut output).await;
        let id = planned["result"]["structuredContent"]["data"]["plan"]["plan_id"]
            .as_str()
            .expect("plan created");
        send(
            &mut input,
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
                "name":"plan_apply","arguments":{"plan_id":id}
            }}),
        )
        .await;
        let question = receive(&mut output).await;
        assert_eq!(question["method"], "elicitation/create", "{question}");
        assert_eq!(question["params"]["mode"], "form");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(240);
        let last_pending = deadline - Duration::from_millis(1);
        tokio::time::advance(last_pending - tokio::time::Instant::now()).await;
        // A read round trip lets the server process expired timers before checking pending output.
        send(
            &mut input,
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{
                "name":"plan_get","arguments":{"plan_id":id}
            }}),
        )
        .await;
        let pending = receive(&mut output).await;
        assert_eq!(
            pending["id"], 4,
            "plan_apply must still be pending at 239.999 s: {pending}"
        );
        assert_eq!(
            pending["result"]["structuredContent"]["data"]["plan"]["state"],
            "open"
        );
        // Poll without a timer so the pending assertion cannot advance paused time.
        let mut next = Box::pin(receive(&mut output));
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(next.as_mut().poll(cx).is_pending()))
                .await
        );
        assert_eq!(tokio::time::Instant::now(), last_pending);
        tokio::time::advance(Duration::from_millis(1)).await;
        let mut timed_out = None;
        for _ in 0..1024 {
            if let Some(frame) = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(match next.as_mut().poll(cx) {
                    std::task::Poll::Ready(frame) => Some(frame),
                    std::task::Poll::Pending => None,
                })
            })
            .await
            {
                timed_out = Some(frame);
                break;
            }
            tokio::task::yield_now().await;
        }
        drop(next);
        let timed_out = timed_out.expect(
            "plan_apply must return confirmation_timeout at 240 s within 1024 scheduler yields",
        );
        assert_eq!(tokio::time::Instant::now(), deadline);
        assert_eq!(timed_out["id"], 3);
        assert_eq!(
            timed_out["result"]["structuredContent"]["error"]["code"],
            "confirmation_timeout"
        );
        send(
            &mut input,
            json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{
                "name":"plan_get","arguments":{"plan_id":id}
            }}),
        )
        .await;
        let reopened = receive(&mut output).await;
        assert_eq!(reopened["id"], 5);
        assert_eq!(
            reopened["result"]["structuredContent"]["data"]["plan"]["state"],
            "open"
        );
        drop(input);
        server.await.unwrap().unwrap();
        upstream.abort();
        clock_guard.abort();
    }
    #[tokio::test(start_paused = true)]
    async fn legacy_answer_deadline_includes_admission_and_second_check() {
        let _serial = crate::plan::confirm::tests::LEGACY_SESSION.lock().await;
        // Keep paused time from auto-advancing while TCP I/O is pending.
        let clock_guard = tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let delayed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let delay = delayed.clone();
        let arrived = Arc::new(tokio::sync::Notify::new());
        let arrival = arrived.clone();
        let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen_writes = writes.clone();
        let upstream = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let delay = delay.clone();
                let arrival = arrival.clone();
                let writes = seen_writes.clone();
                connections.spawn(async move {
                    let mut headers = Vec::new();
                    while !headers.ends_with(b"\r\n\r\n") {
                        headers.push(stream.read_u8().await.unwrap());
                    }
                    let headers = String::from_utf8(headers).unwrap();
                    let request = headers.lines().next().unwrap();
                    if request.starts_with("POST ") {
                        writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    if delay.load(std::sync::atomic::Ordering::SeqCst) {
                        arrival.notify_one();
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                    let body = if request == "GET /_security/_authenticate HTTP/1.1" {
                        fixture("authenticate")
                    } else if request.starts_with("POST ") {
                        fixture("rules_bulk_disable")
                    } else {
                        assert!(request.starts_with("GET /api/detection_engine/rules?"), "{request}");
                        fixture("rules_get")
                    }.to_string();
                    stream.write_all(format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len()
                    ).as_bytes()).await.unwrap();
                });
            }
        });
        let target = elasticctl_core::Resolved {
            name: "test".into(),
            source: elasticctl_core::Source::Profile,
            profile: elasticctl_core::Profile {
                kibana_url: url.clone(),
                es_url: Some(url),
                api_key: Some("test-key".into()),
                username: None,
                password: None,
                space: "default".into(),
                verify: true,
                timeout_secs: 30,
            },
        };
        let options = super::ServerOptions {
            allow_mutations: crate::MutationClasses::parse(["rules-toggle"]).unwrap(),
            ..Default::default()
        };
        let context = super::validate_target(&target, &options).unwrap();
        let mut state = super::ServerState::new(context, target, options.call_timeout, false);
        state.allow_mutations = options.allow_mutations;
        let answered = Arc::new(tokio::sync::Notify::new());
        let answer_notice = answered.clone();
        state.audit = crate::plan::audit::AuditSink::production(move |line| {
            let v: Value = serde_json::from_str(line).unwrap();
            if v["audit"]["event"] == "confirmation_answered" {
                answer_notice.notify_one();
            }
        });
        let state = Arc::new(state);
        let (mut input, server_input) = tokio::io::duplex(1_048_576);
        let (server_output, output) = tokio::io::duplex(1_048_576);
        let mut output = BufReader::new(output);
        let server = tokio::spawn(super::serve_with_writes(
            state.clone(),
            server_input,
            server_output,
            tokio_util::sync::CancellationToken::new(),
        ));
        send(
            &mut input,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-11-25","capabilities":{"elicitation":{"form":{}}},
                "clientInfo":{"name":"test","version":"0"}
            }}),
        )
        .await;
        let initialized = receive(&mut output).await;
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
        send(
            &mut input,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await;
        let rule_id = fixture("rules_get")["rule_id"].clone();
        send(
            &mut input,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
                "name":"rules_set_enabled_plan","arguments":{"selectors":[rule_id],"enabled":false}
            }}),
        )
        .await;
        let planned = receive(&mut output).await;
        let id = planned["result"]["structuredContent"]["data"]["plan"]["plan_id"]
            .as_str()
            .expect("plan created");
        for fields in [
            json!({"requestState":"bogus"}),
            json!({"inputResponses":{}}),
        ] {
            let mut params = json!({"name":"plan_apply","arguments":{"plan_id":id}});
            params
                .as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            send(
                &mut input,
                json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":params}),
            )
            .await;
            let rejected = receive(&mut output).await;
            assert_eq!(rejected["error"]["code"], -32600);
            let mut plans = state.plans.lock().unwrap();
            let plan = plans.get(id, tokio::time::Instant::now()).unwrap();
            assert_eq!(plan.state, crate::plan::store::PlanState::Open);
            assert_eq!(plan.prompt_count(), 0);
        }
        send(
            &mut input,
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
                "name":"plan_apply","arguments":{"plan_id":id}
            }}),
        )
        .await;
        let question = receive(&mut output).await;
        assert_eq!(question["method"], "elicitation/create", "{question}");
        assert_eq!(question["params"]["mode"], "form");
        let mut holders: Vec<_> = (0..4).map(|_| state.try_admit().unwrap()).collect();
        send(&mut input, json!({"jsonrpc":"2.0","id":question["id"],"result":{"action":"accept","content":{"apply":true}}})).await;
        answered.notified().await;
        tokio::time::advance(Duration::from_secs(29)).await;
        delayed.store(true, std::sync::atomic::Ordering::SeqCst);
        holders.pop();
        arrived.notified().await;
        delayed.store(false, std::sync::atomic::Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(2)).await;
        let response = receive(&mut output).await;
        assert_eq!(
            response["result"]["structuredContent"]["error"]["code"], "deadline_exceeded",
            "{response}"
        );
        assert_eq!(writes.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            state
                .plans
                .lock()
                .unwrap()
                .get(id, tokio::time::Instant::now())
                .unwrap()
                .state,
            crate::plan::store::PlanState::Open
        );
        drop(holders);
        drop(input);
        server.await.unwrap().unwrap();
        upstream.abort();
        clock_guard.abort();
    }
}
