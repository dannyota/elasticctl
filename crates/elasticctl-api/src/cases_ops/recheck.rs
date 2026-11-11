//! Case state re-checks.

use super::*;
use crate::observe::{Observed, Preconditions};

/// Read case states by ID, returning absent state for missing cases.
pub async fn observe_cases(
    t: &Transport,
    ids: &[String],
    with_version: bool,
) -> Result<Preconditions> {
    let mut seen = Vec::with_capacity(ids.len());
    for id in ids {
        let state = match cases::get(t, id).await {
            Ok(case) => Some(super::observed::case_state(&case, with_version)),
            Err(e) if e.kind == ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        seen.push(Observed {
            object: "case",
            id: id.clone(),
            state,
        });
    }
    Ok(Preconditions(seen))
}
