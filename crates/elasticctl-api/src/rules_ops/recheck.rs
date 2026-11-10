//! Rule state re-checks.

use super::*;
use crate::Preconditions;

/// Read each rule by ID, returning absent state for missing rules.
pub async fn observe_rules(_t: &Transport, _rule_ids: &[String]) -> Result<Preconditions> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "observe_rules is not available in this build",
    ))
}
