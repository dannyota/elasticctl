use super::*;
use elasticctl_api::value_lists as api;
use elasticctl_core::urlencode;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[path = "value_lists/cleanup.rs"]
mod cleanup;
#[path = "value_lists/setup.rs"]
mod setup;
#[path = "value_lists/tests.rs"]
mod tests;

const PREFIX: &str = "elasticctl-live-vl-";

type StepResult<T = ()> = Result<T, StepError>;

#[derive(Debug, PartialEq, Eq)]
enum StepError {
    NotWired(u8),
    Failed,
    Interrupted,
}

fn checked_step<T>(result: elasticctl_core::Result<T>) -> StepResult<T> {
    result.map_err(|_| StepError::Failed)
}

fn require(value: bool) -> StepResult {
    if value {
        Ok(())
    } else {
        Err(StepError::Failed)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Failure {
    Contract,
    Cleanup,
    InitialBaseline,
    FinalBaseline,
}
impl Failure {
    fn class(&self) -> ConformanceFailureClass {
        match self {
            Self::Contract => ConformanceFailureClass::Contract,
            Self::Cleanup | Self::FinalBaseline => ConformanceFailureClass::Cleanup,
            Self::InitialBaseline => ConformanceFailureClass::Harness,
        }
    }
}

fn classify(
    initial: Result<(), ()>,
    body: StepResult,
    cleanup: Result<(), ()>,
    baseline: Result<(), ()>,
) -> Result<(), Failure> {
    initial.map_err(|_| Failure::InitialBaseline)?;
    cleanup.map_err(|_| Failure::Cleanup)?;
    baseline.map_err(|_| Failure::FinalBaseline)?;
    body.map_err(|_| Failure::Contract)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Rule,
    Item,
    Exception,
    List,
}
impl Kind {
    fn key(self) -> &'static str {
        match self {
            Self::Rule => "rule_id",
            Self::Item => "item_id",
            Self::Exception => "list_id",
            Self::List => "id",
        }
    }
    fn endpoint(self) -> &'static str {
        match self {
            Self::Rule => "/api/detection_engine/rules",
            Self::Item => "/api/exception_lists/items",
            Self::Exception => "/api/exception_lists",
            Self::List => "/api/lists",
        }
    }
}

struct Object {
    kind: Kind,
    id: String,
    pending: bool,
    delete_sent: bool,
    import: Option<(api::ValueListType, Vec<String>)>,
}
impl Object {
    fn new(kind: Kind, id: String) -> Self {
        Self {
            kind,
            id,
            pending: false,
            delete_sent: false,
            import: None,
        }
    }
    fn path(&self) -> String {
        let mut path = format!(
            "{}?{}={}",
            self.kind.endpoint(),
            self.kind.key(),
            urlencode(&self.id)
        );
        if matches!(self.kind, Kind::Item | Kind::Exception) {
            path.push_str("&namespace_type=single");
        }
        path
    }
    fn owns(&self, body: &Value, nonce: &str) -> bool {
        let identity = body[self.kind.key()] == self.id;
        let marker = if self.kind == Kind::List {
            body["meta"]["marker"] == LIVE_TAG && body["meta"]["recorder_nonce"] == nonce
        } else {
            body["tags"]
                .as_array()
                .is_some_and(|tags| tags.contains(&json!(LIVE_TAG)) && tags.contains(&json!(nonce)))
        };
        identity
            && marker
            && (self.kind != Kind::Rule || body["enabled"] == false)
            && (!matches!(self.kind, Kind::Item | Kind::Exception)
                || body["namespace_type"] == "single")
    }
}

struct Index {
    id: String,
    pending: bool,
    delete_sent: bool,
    pending_event: Option<(String, Value)>,
}

struct Lease {
    nonce: String,
    objects: Vec<Object>,
    index: Option<Index>,
    before: Option<api::BootstrapState>,
    restore_streams: bool,
    init_pending: bool,
    stream_delete_sent: bool,
    budget: Duration,
    interval: Duration,
    cancelled: Arc<AtomicBool>,
}
impl Lease {
    fn new(nonce: String) -> Self {
        Self {
            nonce,
            objects: Vec::new(),
            index: None,
            before: None,
            restore_streams: false,
            init_pending: false,
            stream_delete_sent: false,
            budget: Duration::from_secs(15),
            interval: Duration::from_millis(100),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
    fn check_interrupt(&self) -> StepResult {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(StepError::Interrupted)
        } else {
            Ok(())
        }
    }
}

fn state_pull() -> StepResult {
    Err(StepError::NotWired(3))
}
fn state_push() -> StepResult {
    Err(StepError::NotWired(4))
}
fn preview() -> StepResult {
    Err(StepError::NotWired(5))
}
fn refusals() -> StepResult {
    Err(StepError::NotWired(6))
}

async fn referenced_delete(t: &Transport, lease: &Lease) -> StepResult {
    lease.check_interrupt()?;
    let list = lease
        .objects
        .iter()
        .find(|o| o.kind == Kind::List)
        .ok_or(StepError::Failed)?;
    let plan = checked_step(api::plan_delete(t, std::slice::from_ref(&list.id)).await)?;
    let outcomes = api::apply_delete(t, &plan).await;
    let outcome = outcomes.first().ok_or(StepError::Failed)?;
    require(
        outcome.result.outcome == api::Outcome::Failed
            && outcome
                .result
                .error
                .as_ref()
                .is_some_and(|e| e.status == Some(409))
            && !outcome.references.is_empty()
            && outcome.result.error.as_ref().is_some_and(|error| {
                outcome.references.iter().all(|reference| {
                    error.message.contains(&reference.container.list_id)
                        && error.message.contains(&reference.item_id)
                })
            })
            && outcome.references.iter().all(|r| {
                lease
                    .objects
                    .iter()
                    .any(|o| o.kind == Kind::Item && o.id == r.item_id)
                    && lease
                        .objects
                        .iter()
                        .any(|o| o.kind == Kind::Exception && o.id == r.container.list_id)
            }),
    )
}

async fn body(t: &Transport, lease: &mut Lease) -> StepResult {
    setup::initialize(t, lease).await?;
    setup::objects(t, lease).await?;
    state_pull()?;
    state_push()?;
    preview()?;
    refusals()?;
    referenced_delete(t, lease).await
}

fn signals(
    rt: &tokio::runtime::Runtime,
    cancelled: Arc<AtomicBool>,
) -> TestResult<tokio::task::JoinHandle<()>> {
    let _enter = rt.enter();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| "signal handler failed")?;
        let mut terminate = signal(SignalKind::terminate()).map_err(|_| "signal handler failed")?;
        Ok(tokio::spawn(async move {
            tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
            cancelled.store(true, Ordering::SeqCst);
        }))
    }
    #[cfg(not(unix))]
    Ok(tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        cancelled.store(true, Ordering::SeqCst);
    }))
}

fn execute() -> Result<(), Failure> {
    let _serial = serialize_live();
    let dir = tempfile::tempdir().map_err(|_| Failure::InitialBaseline)?;
    let config = write_live_config(dir.path());
    let profile = live_profile();
    let rt = tokio::runtime::Runtime::new().map_err(|_| Failure::InitialBaseline)?;
    let t = Transport::with_options(
        &profile,
        elasticctl_core::TransportOptions {
            disable_retries: true,
            disable_redirects: true,
            ..Default::default()
        },
    )
    .map_err(|_| Failure::InitialBaseline)?;
    let mut lease = Lease::new(unique_name("vl-run"));
    let signal = signals(&rt, lease.cancelled.clone()).map_err(|_| Failure::InitialBaseline)?;
    let mut baseline = None;
    let mut audit = LiveCleanup::new(config.clone(), profile.clone());
    audit.finished = true;
    let initial = (|| {
        let captured = capture_baseline(&config, &profile)?;
        assert_clean_baseline(&config, &audit, captured.clone())?;
        rt.block_on(setup::baseline(&t, &mut lease))
            .map_err(|_| "value-list baseline failed")?;
        baseline = Some(captured);
        Ok::<_, String>(())
    })();
    let result = if initial.is_ok() {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(body(&t, &mut lease))
        }))
        .unwrap_or(Err(StepError::Failed))
    } else {
        Err(StepError::Failed)
    };
    let cleaned = rt.block_on(cleanup::finish(&t, &mut lease)).map_err(|_| ());
    let final_baseline = baseline.map_or(Ok(()), |b| {
        assert_clean_baseline(&config, &audit, b).map_err(|_| ())?;
        rt.block_on(setup::audit_lists(&t, &lease)).map_err(|_| ())
    });
    signal.abort();
    if let Err(StepError::NotWired(step)) = &result {
        eprintln!("value-list step {step}: not wired");
    }
    classify(initial.map_err(|_| ()), result, cleaned, final_baseline)
}

pub(super) fn run_contract() {
    if skip_unless_live() {
        return;
    }
    run_classified(execute);
}

fn run_classified(run: impl FnOnce() -> Result<(), Failure>) {
    if let Err(failure) = run() {
        panic_conformance(failure.class(), format!("{failure:?}"));
    }
}
