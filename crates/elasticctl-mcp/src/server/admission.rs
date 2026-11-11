use std::{future::Future, sync::Arc};

use tokio::time;
use tokio_util::sync::CancellationToken;

use super::ServerState;

pub(super) enum Admitted<T> {
    Done(T),
    Busy,
    DeadlineExceeded,
    Cancelled,
}

pub(super) async fn run_admitted<T, F>(
    state: &Arc<ServerState>,
    cancellation: CancellationToken,
    operation: F,
) -> Admitted<T>
where
    F: Future<Output = T>,
{
    let Some(permit) = state.try_admit() else {
        return Admitted::Busy;
    };
    let deadline = time::Instant::now() + state.call_timeout;
    let operation = async move {
        let _permit = permit;
        operation.await
    };
    tokio::pin!(operation);
    tokio::select! {
        _ = cancellation.cancelled() => Admitted::Cancelled,
        outcome = time::timeout_at(deadline, &mut operation) => {
            if time::Instant::now() >= deadline {
                Admitted::DeadlineExceeded
            } else {
                match outcome {
                    Ok(result) => Admitted::Done(result),
                    Err(_) => Admitted::DeadlineExceeded,
                }
            }
        }
    }
}

pub(crate) fn acquire(state: &Arc<ServerState>) -> Option<tokio::sync::OwnedSemaphorePermit> {
    state.try_admit()
}
pub(crate) async fn reacquire(
    state: &Arc<ServerState>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    time::timeout(state.call_timeout, state.permits.clone().acquire_owned())
        .await
        .ok()?
        .ok()
}
pub(crate) fn timeout(state: &ServerState) -> std::time::Duration {
    state.call_timeout
}

#[cfg(test)]
mod tests {
    use super::{Admitted, run_admitted};
    use crate::{TargetContext, server::ServerState};
    use elasticctl_core::{Profile, Resolved, Source};
    use std::{
        future::pending,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use tokio_util::sync::CancellationToken;

    fn state() -> Arc<ServerState> {
        Arc::new(ServerState::new(
            TargetContext {
                profile: "test".into(),
                host: "example.test".into(),
                space: "default".into(),
            },
            Resolved {
                name: "test".into(),
                source: Source::Profile,
                profile: Profile {
                    kibana_url: "https://example.test".into(),
                    es_url: None,
                    api_key: None,
                    username: None,
                    password: None,
                    space: "default".into(),
                    verify: true,
                    timeout_secs: 30,
                },
            },
            Duration::from_secs(1),
            false,
        ))
    }

    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn fifth_operation_is_busy_and_is_not_polled() {
        let state = state();
        let release = CancellationToken::new();
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let state = state.clone();
            let release = release.clone();
            tasks.push(tokio::spawn(async move {
                run_admitted(&state, CancellationToken::new(), release.cancelled()).await
            }));
        }
        tokio::time::timeout(Duration::from_millis(500), async {
            while state.permits.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("four operations admitted");
        assert!(matches!(
            run_admitted(&state, CancellationToken::new(), async {
                panic!("busy operation ran")
            })
            .await,
            Admitted::Busy
        ));
        release.cancel();
        for task in tasks {
            assert!(matches!(task.await.unwrap(), Admitted::Done(())));
        }
        assert_eq!(state.permits.available_permits(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_drops_operation_and_releases_permit() {
        let state = state();
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(dropped.clone());
        let outcome = run_admitted(&state, CancellationToken::new(), async move {
            let _guard = guard;
            pending::<()>().await;
        })
        .await;
        assert!(matches!(outcome, Admitted::DeadlineExceeded));
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(state.permits.available_permits(), 4);
    }

    #[tokio::test]
    async fn cancellation_drops_operation_and_releases_permit() {
        let state = state();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(dropped.clone());
        let outcome = run_admitted(&state, cancellation, async move {
            let _guard = guard;
            pending::<()>().await;
        })
        .await;
        assert!(matches!(outcome, Admitted::Cancelled));
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(state.permits.available_permits(), 4);
    }

    #[tokio::test]
    async fn late_completion_is_deadline_exceeded() {
        let mut state = state();
        Arc::get_mut(&mut state).unwrap().call_timeout = Duration::from_millis(1);
        let outcome = run_admitted(&state, CancellationToken::new(), async {
            std::thread::sleep(Duration::from_millis(5));
        })
        .await;
        assert!(matches!(outcome, Admitted::DeadlineExceeded));
        assert_eq!(state.permits.available_permits(), 4);
    }
    #[tokio::test]
    async fn legacy_confirmed_reacquisition_is_busy_and_cancellation_recovers_permits() {
        let _serial = crate::plan::confirm::tests::LEGACY_SESSION.lock().await;
        use rmcp::ServiceExt;
        use serde_json::{Value, json};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        async fn send(w: &mut tokio::io::DuplexStream, v: Value) {
            w.write_all(format!("{v}\n").as_bytes()).await.unwrap();
        }
        async fn receive(r: &mut tokio::io::BufReader<tokio::io::DuplexStream>) -> Value {
            let mut line = String::new();
            tokio::time::timeout(Duration::from_secs(5), r.read_line(&mut line))
                .await
                .unwrap()
                .unwrap();
            serde_json::from_str(&line).unwrap()
        }
        let upstream = wiremock::MockServer::start().await;
        for (path, fixture) in [
            ("/_security/_authenticate", "authenticate"),
            ("/api/detection_engine/rules", "rules_get"),
        ] {
            let path_to_fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                "../../tests/fixtures/traditional-9.5.1/{fixture}.json"
            ));
            let mut body: Value =
                serde_json::from_slice::<Value>(&std::fs::read(path_to_fixture).unwrap()).unwrap()
                    ["response"]
                    .clone();
            if fixture == "rules_get" {
                body["rule_id"] = json!("r");
            }
            wiremock::Mock::given(wiremock::matchers::path(path))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(body))
                .mount(&upstream)
                .await;
        }
        let weak_state = Arc::new(std::sync::Mutex::new(None::<std::sync::Weak<ServerState>>));
        let holders = Arc::new(std::sync::Mutex::new(Vec::new()));
        let on_answer_state = weak_state.clone();
        let on_answer_holders = holders.clone();
        let mut state = state();
        let mutable = Arc::get_mut(&mut state).unwrap();
        mutable.audit = crate::plan::audit::AuditSink::production(move |line| {
            let line: Value = serde_json::from_str(line).unwrap();
            if line["audit"]["event"] == "confirmation_answered"
                && line["audit"]["result"] == "confirmed"
            {
                let state = on_answer_state
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .upgrade()
                    .unwrap();
                let mut holders = on_answer_holders.lock().unwrap();
                for _ in 0..4 {
                    holders.push(state.try_admit().expect("confirmation released its permit"));
                }
            }
        });
        mutable.resolved.profile.kibana_url = upstream.uri();
        mutable.resolved.profile.es_url = Some(upstream.uri());
        mutable.resolved.profile.api_key = Some("test-key".into());
        mutable.allow_mutations = crate::MutationClasses::parse(["rules-toggle"]).unwrap();
        *weak_state.lock().unwrap() = Some(Arc::downgrade(&state));
        let (mut input, sr) = tokio::io::duplex(1048576);
        let (sw, output) = tokio::io::duplex(1048576);
        let mut output = tokio::io::BufReader::new(output);
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            super::super::handler::McpServer::new(server_state)
                .serve((sr, sw))
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        send(&mut input, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"elicitation":{"form":{}}},"clientInfo":{"name":"test","version":"0"}}})).await;
        receive(&mut output).await;
        send(
            &mut input,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await;
        send(&mut input, json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"rules_set_enabled_plan","arguments":{"selectors":["r"],"enabled":false}}})).await;
        let plan =
            receive(&mut output).await["result"]["structuredContent"]["data"]["plan"]["plan_id"]
                .clone();
        assert!(plan.is_string());
        send(&mut input, json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"plan_apply","arguments":{"plan_id":plan}}})).await;
        let question = receive(&mut output).await;
        assert_eq!(question["method"], "elicitation/create");
        let cancellation = CancellationToken::new();
        let release = cancellation.clone();
        let held = holders.clone();
        let holder = tokio::spawn(async move {
            release.cancelled().await;
            held.lock().unwrap().clear();
        });
        let answered_at = tokio::time::Instant::now();
        send(&mut input, json!({"jsonrpc":"2.0","id":question["id"],"result":{"action":"accept","content":{"apply":true}}})).await;
        let r = receive(&mut output).await;
        assert_eq!(r["id"], 3);
        assert!(answered_at.elapsed() >= state.call_timeout);
        assert_eq!(
            r["result"]["structuredContent"]["error"]["code"], "busy",
            "{r}"
        );
        assert_eq!(
            state
                .plans
                .lock()
                .unwrap()
                .get(plan.as_str().unwrap(), tokio::time::Instant::now())
                .unwrap()
                .state,
            crate::plan::store::PlanState::Open
        );
        assert!(
            upstream
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method == "GET")
        );
        assert_eq!(state.permits.available_permits(), 0);
        cancellation.cancel();
        holder.await.unwrap();
        assert_eq!(state.permits.available_permits(), 4);
        send(&mut input, json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"plan_get","arguments":{"plan_id":plan}}})).await;
        let r = receive(&mut output).await;
        assert_eq!(
            r["result"]["structuredContent"]["data"]["plan"]["state"],
            "open"
        );
        drop(input);
        server.await.unwrap();
    }
}
