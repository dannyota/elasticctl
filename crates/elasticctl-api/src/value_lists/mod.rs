mod address;
mod apply;
mod codec;
mod evidence;
pub(crate) mod legacy;
mod lifecycle;
mod model;
mod plan;
mod read_back;
mod reads;
mod scan;
mod stems;
mod validation;

pub use address::canonical_value;
pub use apply::apply_plans;
pub use codec::{decode_container, decode_values, encode_container, encode_values, read_pair};
pub use evidence::{Action, Evidence, Failure, ListOutcome, Outcome, ReadOf, Sent};
pub use lifecycle::{
    DeleteOutcome, DeletePlan, DeleteReference, InitOutcome, apply_delete, apply_init, plan_delete,
};
pub use model::{Container, LocalPair, StoredValues, ValueListType, ValueSet};
pub use plan::{ContainerAction, ListPlan, pack_imports, plan_import, plan_list};
pub use read_back::{Clock, SystemClock};
pub use reads::{
    BootstrapState, RemoteContainer, RemoteList, bootstrap_state, decode_export,
    decode_remote_container, export_values, find_containers, read_container, read_list,
    require_bootstrapped,
};
pub use scan::{InstalledReference, ReferenceOperator, item_references, scan_references};
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
