use super::plan::container_mismatches;
use super::{
    Action, Container, Evidence, ReadOf, StoredValues, ValueSet, decode_export, read_container,
};
use elasticctl_core::{Error, ErrorKind, Result, Transport, urlencode};
use std::{
    future::Future,
    pin::Pin,
    time::{Duration, Instant},
};

pub trait Clock {
    fn now(&self) -> Duration;
    fn pause(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

pub struct SystemClock {
    start: Instant,
}
impl Default for SystemClock {
    fn default() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}
impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.start.elapsed()
    }
    fn pause(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration))
    }
}

const BUDGET: Duration = Duration::from_secs(120);
const INTERVAL: Duration = Duration::from_secs(1);

pub(super) enum Expected<'a> {
    Values(&'a ValueSet),
    Container,
}
pub(super) struct ReadBack {
    pub evidence: Evidence,
    pub stored: Option<StoredValues>,
    pub verified: bool,
}

pub(super) async fn settle<C: Clock>(
    t: &Transport,
    container: &Container,
    expected: Expected<'_>,
    clock: &C,
    last_export_end: &mut Option<Duration>,
) -> ReadBack {
    let mut evidence = Evidence::new(Action::ReadBack, &container.id, &container.name);
    evidence.of = Some(match expected {
        Expected::Values(_) => ReadOf::Values,
        Expected::Container => ReadOf::Container,
    });
    evidence.sent = None;
    evidence.values = None;
    evidence.observed = Some(false);
    let deadline = clock.now() + BUDGET;
    let mut last_end: Option<Duration> = if matches!(expected, Expected::Values(_)) {
        *last_export_end
    } else {
        None
    };
    loop {
        if let Some(end) = last_end {
            let wait = (end + INTERVAL).saturating_sub(clock.now());
            if clock.now() + wait >= deadline {
                break;
            }
            if !wait.is_zero() {
                clock.pause(wait).await;
            }
        }
        let left = deadline.saturating_sub(clock.now());
        if left.is_zero() {
            break;
        }
        let read = tokio::time::timeout(left, observe(t, container, &expected)).await;
        last_end = Some(clock.now());
        if matches!(expected, Expected::Values(_)) {
            *last_export_end = last_end;
        }
        match read {
            Ok(Ok(observed)) => {
                evidence.observed = Some(true);
                evidence.read_error = None;
                let (matches, stored) = match observed {
                    Observation::Values(stored) => {
                        let Expected::Values(expected) = &expected else {
                            unreachable!()
                        };
                        let set = stored.set();
                        evidence.missing = Some(expected.difference(&set).count());
                        evidence.extra = Some(set.difference(expected).count());
                        (set == **expected, Some(stored))
                    }
                    Observation::Container(fields) => {
                        let matches = fields.is_empty();
                        evidence.mismatched = Some(fields);
                        (matches, None)
                    }
                };
                if matches && clock.now() <= deadline {
                    return ReadBack {
                        evidence,
                        stored,
                        verified: true,
                    };
                }
            }
            Ok(Err(error)) => evidence.read_error = Some(error.into()),
            Err(_) => {
                evidence.read_error = Some(
                    Error::new(ErrorKind::Timeout, "value-list read-back budget exhausted").into(),
                );
                break;
            }
        }
        if clock.now() >= deadline {
            break;
        }
    }
    ReadBack {
        evidence,
        stored: None,
        verified: false,
    }
}

enum Observation {
    Values(StoredValues),
    Container(Vec<String>),
}
async fn observe(
    t: &Transport,
    container: &Container,
    expected: &Expected<'_>,
) -> Result<Observation> {
    match expected {
        Expected::Values(_) => {
            let text = t
                .post_text_once(
                    &format!(
                        "/api/lists/items/_export?list_id={}",
                        urlencode(&container.id)
                    ),
                    None,
                )
                .await?;
            Ok(Observation::Values(decode_export(
                &container.list_type,
                &text,
            )?))
        }
        Expected::Container => Ok(Observation::Container(
            match read_container(t, &container.id).await? {
                Some(observed) => container_mismatches(container, &observed.container),
                None => vec!["id".into()],
            },
        )),
    }
}
