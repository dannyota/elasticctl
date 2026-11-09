//! Integration recording modules.

pub(crate) mod cleanup;
pub(crate) mod fixtures;
pub(crate) mod inputs;
pub(crate) mod inventory;
pub(crate) mod metadata;
pub(crate) mod proofs;

mod exercise;
mod lifecycle;
mod preparation;
mod teardown;

pub(super) use lifecycle::record_integration_policies;
