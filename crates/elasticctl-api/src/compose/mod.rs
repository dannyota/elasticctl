//! Bounded shared reads for cross-vertical reports.
use elasticctl_core::{Error, ErrorKind, Result};
mod alert_activity;
pub mod alert_context;
pub mod coverage;
mod exception_coverage;
pub mod readiness;
pub mod rule_health;
mod rule_snapshot;
pub use alert_activity::*;
pub use exception_coverage::*;
pub use rule_snapshot::*;
pub const MAX_EXCEPTION_LISTS: usize = 5;
pub const MAX_RELATED_CASES: usize = 5;
pub const RECENT_ALERTS: usize = 5;
pub const MAX_PATTERNS: usize = 16;
pub const MAX_PACKAGES: usize = 8;
pub const MESSAGE_BYTES: usize = 2_048;
#[derive(Debug)]
pub enum Part<T> {
    Ok(T),
    Unavailable(Error),
    Skipped(SkipReason),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    NotApplicable,
    DependencyUnavailable,
    NotConfigured,
}
pub fn is_fatal(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::Auth | ErrorKind::Connection | ErrorKind::Timeout
    )
}
pub fn degrade<T>(result: Result<T>) -> Result<Part<T>> {
    match result {
        Ok(v) => Ok(Part::Ok(v)),
        Err(e) if is_fatal(e.kind) => Err(e),
        Err(e) => Ok(Part::Unavailable(e)),
    }
}
pub fn is_path_segment(value: &str) -> bool {
    !matches!(value, "" | "." | "..")
}
