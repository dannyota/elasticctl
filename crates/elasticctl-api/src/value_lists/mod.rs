//! Local value-list models, codecs, and safety checks.

mod address;
mod codec;
mod model;
mod stems;
mod validation;

pub use address::canonical_value;
pub use codec::{decode_container, decode_values, encode_container, encode_values, read_pair};
pub use model::{Container, LocalPair, StoredValues, ValueListType, ValueSet};
pub use stems::{file_stem, plan_stems, stem_collisions};
pub use validation::{
    Findings, LocalValidation, PhaseOrder, ProjectedStates, ReferenceUse, Warning, WarningKind,
    project_states, size_warning, stored_warnings, validate_additions, validate_local_pair,
    validate_projected,
};

fn invalid(message: impl Into<String>) -> elasticctl_core::Error {
    elasticctl_core::Error::new(elasticctl_core::ErrorKind::Error, message)
}

#[cfg(test)]
mod tests;
