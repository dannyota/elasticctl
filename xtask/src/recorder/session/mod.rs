//! Session ownership and pending restoration.

pub(crate) mod cleanup;

use crate::recorder::integration::proofs::MarkerIntegrationInputs;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// Record what a preview actually wrote.
///
/// `rules/preview` returns a `previewId` but no hit count, so read the count from
/// the preview alerts index. This records the index name, preview-ID field,
/// project-key access, and the first attempt that can see the alerts.
///
/// Return `Err` rather than panicking and return the exchange for the caller to
/// write after deleting the scratch index and probe rule. No hits are an error,
/// not a fixture claiming a field matched.
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

/// The bootstrap marker may carry any object-shaped input map only until the
/// production export has classified and captured it. Later marker reads and
/// cleanup must require the exact captured map.
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
    /// Set once, when `record_alerts` is about to create the marker rule or
    /// index, and never cleared back to `false` even after a successful
    /// delete (unlike `alert_rule`/`alert_index` above, which toggle off
    /// once deleted and gate whether `cleanup` attempts one). Gates
    /// `cleanup`'s final re-verification that the object is actually gone —
    /// the only in-session proof of that for a lab session that gets torn
    /// down right after.
    pub(crate) alert_rule_claimed: bool,
    pub(crate) alert_index_claimed: bool,
    /// Set before `record_cases` issues the case-create write, cleared once
    /// `record_cases` has verified its own delete. A case has no fixed,
    /// caller-chosen id to re-check the way `rule`/`list`/`item` do, so
    /// `cleanup`'s sweep for this flag identifies it by title+tag instead
    /// (`sweep_delete_marker_cases`).
    pub(crate) case: bool,
    /// The sole authority to restore a data-view default. It is claimed
    /// before source create because that route may implicitly set the source
    /// default, and it clears only after an acknowledged exact raw restore.
    pub(crate) pending_data_view_default_restore: Option<PendingDefaultRestore>,
    pub(crate) data_view_source: bool,
    pub(crate) data_view_replacement: bool,
    pub(crate) data_view_index: bool,
    /// Set before `record_agent_policies` creates the marker agent policy,
    /// cleared once `cleanup` has verified its own delete (or found it
    /// already absent).
    pub(crate) agent_policy: bool,
    /// Set only around the duplicate-name conflict probe. A successful
    /// duplicate create is never expected — `record_agent_policies` clears
    /// this right after proving the duplicate does not exist — but a
    /// duplicate that somehow survives is still cleaned up and fails the
    /// recording.
    pub(crate) agent_policy_dup: bool,
    /// Claimed after a create response or an exact-id ambiguity recovery
    /// passes the strict nonce, integration, and package-version proof. It
    /// clears only after its exact-id delete is observed as absent. This must
    /// run before parent cleanup because Fleet can reject a parent with an
    /// attachment.
    pub(crate) integration_policy: bool,
    /// Claimed only when a duplicate create response or exact-id ambiguity
    /// recovery passes the strict nonce proof. A conflicting response alone
    /// never claims it. A proven surviving object remains owned until exact-id
    /// cleanup proves it is gone.
    pub(crate) integration_policy_dup: bool,
    /// Claimed after a parent create response or exact-id ambiguity recovery
    /// passes the strict nonce and empty-attachment proof. It clears after
    /// exact-id deletion is observed as absent.
    pub(crate) integration_policy_parent: bool,
    /// The session-only nonce embedded in every live integration marker
    /// description. Cleanup retains it so an object from another recording
    /// session can never be claimed or deleted by these fixed ids.
    pub(crate) integration_recording_nonce: Option<String>,
    /// The exact `system` version proven present before marker writes. This
    /// is kept independently of the audit inventory so every cleanup GET can
    /// prove the integration still points at the package version this session
    /// was authorized to use.
    pub(crate) integration_system_package_version: Option<String>,
    /// Memory-only input proof for the currently owned integration marker.
    /// It never supplies a public fixture by itself.
    pub(crate) integration_policy_inputs: IntegrationMarkerInputs,
    /// The strict, normalized inventory captured before an integration create.
    /// It is memory-only evidence: the recorder requires the exact `system`
    /// package to pre-exist and every package-policy create attempt must leave
    /// this inventory unchanged. Inventory bodies never become public fixtures.
    pub(crate) integration_package_inventory: Option<BTreeSet<(String, String)>>,
    /// Claimed before the dashboard data-view POST so cleanup can always
    /// remove the dependent dashboard before that data view.
    pub(crate) dashboard: bool,
    pub(crate) dashboard_loss: bool,
    pub(crate) dashboard_data_view: bool,
}

#[derive(Default)]
pub(crate) struct CleanupResponses {
    pub(crate) rule: Option<Value>,
}

pub(crate) struct RecordingSession<'a> {
    pub(crate) transport: &'a elasticctl_core::Transport,
    pub(crate) ownership: CleanupOwnership,
}
