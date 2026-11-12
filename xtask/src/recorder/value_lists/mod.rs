//! Separate value-list recording with exact marker ownership and baseline restoration.

mod cleanup;
mod evidence;
mod inventory;
mod steps;
#[cfg(test)]
mod tests;

use crate::diagnostics::{recording_error, safe_recording_error_summary};
use crate::environment::transport_from_env;
use crate::fixtures::{Recording, write_recording};
use crate::recorder::compose::guard::{self, Ended, guarded};
use elasticctl_core::{Result, Transport};
use evidence::Evidence;
use std::path::PathBuf;
use std::time::Duration;

const PREFIX: &str = "elasticctl-live-vl-";
const LIST: &str = "elasticctl-live-vl-record";
const RANGES: &str = "elasticctl-live-vl-spellings";
const EXCEPTION: &str = "elasticctl-live-vl-exception";
const ITEM: &str = "elasticctl-live-vl-exception-item";
const ABSENT: &str = "elasticctl-live-vl-absent";
const MARKER: &str = "elasticctl-live-marker";

#[derive(Clone, Copy)]
struct Timing {
    budget: Duration,
    interval: Duration,
}

impl Timing {
    const LIVE: Self = Self {
        budget: Duration::from_secs(60),
        interval: Duration::from_secs(1),
    };
}

struct Session<'a> {
    t: &'a Transport,
    evidence: Evidence,
    lists: Vec<&'static str>,
    items: Vec<String>,
    exception: bool,
    exception_item: bool,
    before_absent: bool,
    baseline_checked: bool,
    init_attempted: bool,
    timing: Timing,
    nonce: String,
    pending_creates: std::collections::BTreeSet<String>,
    pending_imports: std::collections::BTreeSet<String>,
    attempted_deletes: std::collections::BTreeSet<String>,
}

impl<'a> Session<'a> {
    fn new(t: &'a Transport, timing: Timing) -> Self {
        let nonce = crate::recorder::markers::integration_recording_nonce();
        let mut evidence = Evidence::new(crate::scrub::hosts::recording_hosts());
        evidence.private(nonce.clone());
        Self {
            t,
            evidence,
            lists: Vec::new(),
            items: Vec::new(),
            exception: false,
            exception_item: false,
            before_absent: false,
            baseline_checked: false,
            init_attempted: false,
            timing,
            nonce,
            pending_creates: std::collections::BTreeSet::new(),
            pending_imports: std::collections::BTreeSet::new(),
            attempted_deletes: std::collections::BTreeSet::new(),
        }
    }

    fn recording(&mut self) -> Result<Recording> {
        let flavor = &self.evidence.flavor;
        let version = &self.evidence.version;
        // The directory comes from status and an environment override, never a remote path.
        if [flavor, version].iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
                || part.contains("..")
        }) {
            return Err(recording_error("invalid fixture flavor or version"));
        }
        Ok(Recording {
            dir: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/fixtures")
                .join(format!("{flavor}-{version}"))
                .join("value_lists"),
            fixtures: std::mem::take(&mut self.evidence.fixtures),
        })
    }
}

/// Record only after both the pass and its cleanup have succeeded.
pub(crate) async fn record_value_lists() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("record-value-lists: operation panicked")
    }));
    let t = transport_from_env(60);
    let mut session = Session::new(&t, Timing::LIVE);
    let flavor = std::env::var("ELASTICCTL_FIXTURE_FLAVOR").ok();
    let result = run(&mut session, flavor, guard::ctrl_c).await;
    match result.and_then(write_recording) {
        Ok(()) => println!("recorded value-list fixtures"),
        Err(error) => {
            eprintln!(
                "record-value-lists: {} ({})",
                error.message,
                safe_recording_error_summary(&error)
            );
            std::process::exit(1);
        }
    }
}

async fn run<I, F>(
    session: &mut Session<'_>,
    flavor: Option<String>,
    mut interrupt: I,
) -> Result<Recording>
where
    I: FnMut() -> F,
    F: std::future::Future<Output = ()>,
{
    let work = guarded(steps::record(session, flavor), None, interrupt()).await;
    let already_interrupted = matches!(work, Ended::Interrupted);
    let mut cleanup_interrupted = false;
    let cleanup = guarded(
        cleanup::finish(session),
        Some(Duration::from_secs(300)),
        async {
            if !already_interrupted {
                interrupt().await;
                cleanup_interrupted = true;
            }
            interrupt().await;
        },
    )
    .await;
    let step = ended(work, "recording").and_then(|()| {
        if cleanup_interrupted {
            Err(recording_error("recording interrupted during cleanup"))
        } else {
            Ok(())
        }
    });
    let clean = ended(cleanup, "cleanup").map_err(|error| {
        let mut ids = session
            .lists
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>();
        ids.extend(session.items.iter().cloned());
        if session.exception {
            ids.push(EXCEPTION.into());
        }
        if session.exception_item {
            ids.push(ITEM.into());
        }
        ids.extend(session.pending_imports.iter().cloned());
        ids.sort();
        ids.dedup();
        recording_error(format!(
            "{}; survivors or unresolved ids: {}",
            error.message,
            ids.join(", ")
        ))
    });
    match (step, clean) {
        (Ok(()), Ok(())) => session.recording(),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(step), Err(clean)) => Err(recording_error(format!(
            "{}; cleanup failed: {}",
            step.message, clean.message
        ))),
    }
}

fn ended(value: Ended<Result<()>>, phase: &str) -> Result<()> {
    match value {
        Ended::Finished(result) => result.map_err(|error| {
            if error.kind == elasticctl_core::ErrorKind::Error {
                error
            } else {
                crate::diagnostics::safe_recording_transport_error(
                    "value-list endpoint failed",
                    error,
                )
            }
        }),
        Ended::Interrupted => Err(recording_error(format!("{phase} interrupted"))),
        Ended::Panicked => Err(recording_error(format!("{phase} panicked"))),
        Ended::TimedOut => Err(recording_error(format!("{phase} timed out"))),
    }
}
