//! Creates whose answer was lost, and the window cleanup watches them for.
//!
//! A create answered with a timeout, a connection error, a 5xx, or any
//! other failure that is not a definite "already exists", or one cut off by
//! an interrupt or a panic, may still be applied by the server after cleanup
//! has read the identity once. The request future is dropped with the step,
//! so it cannot be drained; cleanup instead re-reads the identity for a
//! fixed window and clears the claim only once the object has stayed absent
//! for all of it.

use crate::recorder::markers::ALERT_POLL_INTERVAL;
use std::time::{Duration, Instant};

/// How long an object must stay absent before cleanup accepts that a lost
/// create will not land.
pub(super) const SETTLE_WINDOW: Duration = Duration::from_secs(30);

/// The pause between reads while an object settles.
pub(super) const SETTLE_INTERVAL: Duration = Duration::from_secs(2);

/// The waits of one run. Tests pass short or zero values.
#[derive(Clone, Copy, Debug)]
pub(super) struct Timing {
    /// Between the step's polls, and after each alert close request.
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

/// Claims whose create answer was neither a definite success nor a
/// definite "already exists". Each is set before its create, with the
/// matching ownership flag, and cleared only by such an answer or by the
/// settle window.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct Unresolved {
    pub(super) case: bool,
    pub(super) alert_rule: bool,
    pub(super) compose_rule: bool,
    pub(super) compose_item: bool,
    pub(super) item: bool,
    pub(super) list: bool,
    pub(super) alert_index: bool,
}

/// How long a watched object has been seen absent.
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

    /// Record a read taken at `now` that found the object absent, or found
    /// it and proved it removed. True once it has stayed absent for the
    /// whole window since the last removal.
    pub(super) fn observe(&mut self, now: Instant, removed: bool) -> bool {
        if removed {
            self.absent_since = Some(now);
        }
        let since = *self.absent_since.get_or_insert(now);
        now.duration_since(since) >= self.window
    }

    /// The object was seen again, so the window starts over at the next
    /// absent read.
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
