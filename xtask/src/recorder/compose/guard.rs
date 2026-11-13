//! Run work so that a panic, an interrupt, or a time bound still returns
//! control to the caller.
//!
//! The conformance matrix spawns its lab leg and races the join handle
//! against Ctrl-C. The compose step borrows its session, so it cannot move
//! into a spawned task. It is polled in place instead: each poll catches a
//! panic, and `tokio::select!` races the work against the interrupt and the
//! bound. The work future is dropped before this returns, so the caller
//! reads the ownership flags exactly as they stood.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// How a piece of guarded work ended.
#[derive(Debug)]
pub(in crate::recorder) enum Ended<T> {
    Finished(T),
    Panicked,
    Interrupted,
    TimedOut,
}

/// Polls the inner future and turns a panic into `None`.
struct CatchUnwind<F> {
    inner: Pin<Box<F>>,
}

impl<F: Future> Future for CatchUnwind<F> {
    type Output = Option<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = &mut self.get_mut().inner;
        match catch_unwind(AssertUnwindSafe(|| inner.as_mut().poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(output)) => Poll::Ready(Some(output)),
            Err(_) => Poll::Ready(None),
        }
    }
}

/// Run `work` until it finishes, panics, the interrupt fires, or `limit`
/// passes. An interrupt wins over work that becomes ready at the same poll.
pub(in crate::recorder) async fn guarded<T>(
    work: impl Future<Output = T>,
    limit: Option<Duration>,
    interrupt: impl Future<Output = ()>,
) -> Ended<T> {
    let caught = CatchUnwind {
        inner: Box::pin(work),
    };
    let deadline = async {
        match limit {
            Some(limit) => tokio::time::sleep(limit).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        biased;
        () = interrupt => Ended::Interrupted,
        () = deadline => Ended::TimedOut,
        output = caught => output.map_or(Ended::Panicked, Ended::Finished),
    }
}

/// The process interrupt. When the listener cannot be installed it never
/// fires, and the default disposition still ends the process on Ctrl-C.
pub(in crate::recorder) async fn ctrl_c() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn finished_work_returns_its_output() {
        let ended = guarded(async { 7 }, None, std::future::pending()).await;
        assert!(matches!(ended, Ended::Finished(7)));
    }

    #[tokio::test]
    async fn a_panic_is_caught_and_reported() {
        let mut flag = false;
        let ended = guarded(
            async {
                flag = true;
                tokio::task::yield_now().await;
                if flag {
                    panic!("injected panic");
                }
            },
            None,
            std::future::pending(),
        )
        .await;
        assert!(matches!(ended, Ended::Panicked));
        assert!(flag, "state written before the panic is still readable");
    }

    #[tokio::test]
    async fn an_interrupt_drops_the_work_before_returning() {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(Arc::clone(&dropped));
        let ended = guarded(
            async move {
                let _guard = guard;
                std::future::pending::<()>().await;
            },
            None,
            async {},
        )
        .await;
        assert!(matches!(ended, Ended::Interrupted));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn the_bound_stops_work_that_never_finishes() {
        let ended = guarded(
            std::future::pending::<()>(),
            Some(Duration::from_millis(20)),
            std::future::pending(),
        )
        .await;
        assert!(matches!(ended, Ended::TimedOut));
    }
}
