//! Case state re-checks.

use super::*;
use crate::Preconditions;

/// Read case states by ID, returning absent state for missing cases.
pub async fn observe_cases(
    _t: &Transport,
    _ids: &[String],
    _with_version: bool,
) -> Result<Preconditions> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "observe_cases is not available in this build",
    ))
}
