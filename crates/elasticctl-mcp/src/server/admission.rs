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
}
