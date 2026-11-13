use crate::recorder::markers::ALERT_POLL_INTERVAL;
use std::time::{Duration, Instant};

pub(super) const SETTLE_WINDOW: Duration = Duration::from_secs(30);

pub(super) const SETTLE_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug)]
pub(super) struct Timing {
    pub(super) poll: Duration,
    pub(super) settle_window: Duration,
    pub(super) settle_interval: Duration,
}

impl Timing {
    pub(super) const LIVE: Self = Self {
        poll: ALERT_POLL_INTERVAL,
        settle_window: SETTLE_WINDOW,
        settle_interval: SETTLE_INTERVAL,
    };

    #[cfg(test)]
    pub(super) const INSTANT: Self = Self {
        poll: Duration::ZERO,
        settle_window: Duration::ZERO,
        settle_interval: Duration::ZERO,
    };
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct Unresolved {
    pub(super) case: bool,
    pub(super) alert_rule: bool,
    pub(super) compose_rule: bool,
    pub(super) compose_item: bool,
    pub(super) item: bool,
    pub(super) list: bool,
    pub(super) alert_index: bool,
    pub(super) index_recreation: bool,
}

pub(super) struct Watch {
    window: Duration,
    absent_since: Option<Instant>,
}

impl Watch {
    pub(super) fn new(window: Duration) -> Self {
        Self {
            window,
            absent_since: None,
        }
    }

    pub(super) fn observe(&mut self, now: Instant, removed: bool) -> bool {
        if removed {
            self.absent_since = Some(now);
        }
        let since = *self.absent_since.get_or_insert(now);
        now.duration_since(since) >= self.window
    }

    pub(super) fn reset(&mut self) {
        self.absent_since = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_object_that_never_appears_settles_only_after_the_full_window() {
        let start = Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let mut watch = Watch::new(SETTLE_WINDOW);

        assert!(!watch.observe(at(0), false));
        assert!(!watch.observe(at(2), false));
        assert!(!watch.observe(at(29), false));
        assert!(watch.observe(at(30), false));
    }

    #[test]
    fn a_removal_restarts_the_window() {
        let start = Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let mut watch = Watch::new(SETTLE_WINDOW);

        assert!(!watch.observe(at(0), false));
        assert!(!watch.observe(at(20), true));
        assert!(!watch.observe(at(31), false));
        assert!(!watch.observe(at(49), false));
        assert!(watch.observe(at(50), false));
    }

    #[test]
    fn a_reset_starts_the_window_at_the_next_absent_read() {
        let start = Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let mut watch = Watch::new(Duration::from_secs(10));

        assert!(!watch.observe(at(0), false));
        watch.reset();
        assert!(!watch.observe(at(12), false));
        assert!(watch.observe(at(22), false));
    }

    #[test]
    fn a_zero_window_settles_on_the_first_read() {
        let mut watch = Watch::new(Duration::ZERO);
        assert!(watch.observe(Instant::now(), true));
    }
}
