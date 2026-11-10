//! Alert state re-checks.

use super::*;
use crate::Preconditions;

/// The alert state needed for a re-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertFacet {
    /// Compare workflow status.
    Status,
    /// Compare presence only.
    Presence,
}

/// Read alert states by ID, returning absent state for missing alerts.
pub async fn observe_alerts(
    _t: &Transport,
    _ids: &[String],
    _facet: AlertFacet,
) -> Result<Preconditions> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "observe_alerts is not available in this build",
    ))
}
