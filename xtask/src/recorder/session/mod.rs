mod cleanup;

use crate::recorder::integration::proofs::MarkerIntegrationInputs;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingDefaultRestorePhase {
    CreateMayImplicitlySetSource,
    ExplicitDefaultMutationMayHaveChanged,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PendingDefaultRestore {
    pub(crate) raw: Value,
    pub(crate) canonical: Option<String>,
    pub(crate) phase: PendingDefaultRestorePhase,
}

#[derive(Clone, Debug, Default)]
pub(crate) enum IntegrationMarkerInputs {
    #[default]
    Empty,
    BootstrapObject,
    Exact(Map<String, Value>),
}

impl IntegrationMarkerInputs {
    pub(crate) fn expectation(&self) -> MarkerIntegrationInputs<'_> {
        match self {
            Self::Empty => MarkerIntegrationInputs::Empty,
            Self::BootstrapObject => MarkerIntegrationInputs::BootstrapObject,
            Self::Exact(inputs) => MarkerIntegrationInputs::Exact(inputs),
        }
    }
}

#[derive(Default)]
pub(crate) struct CleanupOwnership {
    pub(crate) rule: bool,
    pub(crate) item: bool,
    pub(crate) list: bool,
    pub(crate) scratch_index: bool,
    pub(crate) search_index: bool,
    pub(crate) alert_rule: bool,
    pub(crate) alert_index: bool,
    pub(crate) alert_rule_claimed: bool,
    pub(crate) alert_index_claimed: bool,
    pub(crate) case: bool,
    pub(crate) pending_data_view_default_restore: Option<PendingDefaultRestore>,
    pub(crate) data_view_source: bool,
    pub(crate) data_view_replacement: bool,
    pub(crate) data_view_index: bool,
    pub(crate) agent_policy: bool,
    pub(crate) agent_policy_dup: bool,
    pub(crate) integration_policy: bool,
    pub(crate) integration_policy_dup: bool,
    pub(crate) integration_policy_parent: bool,
    pub(crate) integration_recording_nonce: Option<String>,
    pub(crate) integration_system_package_version: Option<String>,
    pub(crate) integration_policy_inputs: IntegrationMarkerInputs,
    pub(crate) integration_package_inventory: Option<BTreeSet<(String, String)>>,
    pub(crate) dashboard: bool,
    pub(crate) dashboard_loss: bool,
    pub(crate) dashboard_data_view: bool,
    pub(crate) esql_async_ids: Vec<String>,
    pub(crate) compose_rule: bool,
    pub(crate) compose_item: bool,
}

#[derive(Default)]
pub(crate) struct CleanupResponses {
    pub(crate) rule: Option<Value>,
}

pub(crate) struct RecordingSession<'a> {
    pub(crate) transport: &'a elasticctl_core::Transport,
    pub(crate) ownership: CleanupOwnership,
}
