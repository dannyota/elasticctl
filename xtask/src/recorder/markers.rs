#[cfg(not(test))]
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const RULE_ID: &str = "elasticctl-fixture-probe";

pub(crate) const LIST_ID: &str = "elasticctl-sample-exceptions";

pub(crate) const ITEM_ID: &str = "elasticctl-sample-exception-item";

pub(crate) const NAMESPACE_TYPE: &str = "single";

pub(crate) const MARKER_TAGS: [&str; 2] = ["elasticctl", "fixture"];

pub(crate) const SCRATCH_DOC_ID: &str = "elasticctl-sample-fixture";

pub(crate) const SCRATCH_MARKER: &str = "elasticctl_fixture_marker";

pub(crate) const ALERT_RULE_ID: &str = "elasticctl-sample-alert-probe";

pub(crate) const ALERT_RULE_NAME: &str = "elasticctl sample alert probe";

pub(crate) const ALERT_PROBE_INDEX: &str = "elasticctl-sample-alert-events";

pub(crate) const ALERT_MARKER_TAG: &str = "elasticctl-sample";

pub(crate) const ALERT_FIXTURE_TIMESTAMP: &str = "2026-01-01T00:00:00.000Z";

pub(crate) const ALERT_POLL_ATTEMPTS: u32 = 30;

pub(crate) const ALERT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

pub(crate) const CASE_TITLE: &str = "elasticctl sample case";

pub(crate) const CASE_TAG: &str = "elasticctl-sample";

pub(crate) const CASE_COMMENT: &str = "elasticctl sample comment";

pub(crate) const DATA_VIEW_INDEX: &str = "elasticctl-sample-data-view-events";

pub(crate) const DATA_VIEW_SOURCE_ID: &str = "elasticctl-sample-data-view-source";

pub(crate) const DATA_VIEW_REPLACEMENT_ID: &str = "elasticctl-sample-data-view-replacement";

pub(crate) const DATA_VIEW_DOC_ID: &str = "elasticctl-sample-data-view-document";

pub(crate) const DATA_VIEW_DEFAULT_PLACEHOLDER: &str = "elasticctl-fixture-original-default";

pub(crate) const DATA_VIEW_METADATA_DESCRIPTION: &str = "elasticctl sample metadata";

pub(crate) const DASHBOARD_ID: &str = "elasticctl-sample-dashboard";

pub(crate) const DASHBOARD_LOSS_ID: &str = "elasticctl-sample-dashboard-loss";

pub(crate) const DASHBOARD_DATA_VIEW_ID: &str = "elasticctl-sample-data-view";

pub(crate) const DASHBOARD_TITLE: &str = "elasticctl sample dashboard";

pub(crate) const DASHBOARD_DATA_VIEW_TITLE: &str = "elasticctl-sample-dashboard-data-view-*";

pub(crate) const DASHBOARD_DATA_VIEW_NAME: &str = "elasticctl sample dashboard data view";

pub(crate) const DASHBOARD_MARKER: &str = "elasticctl-sample";

pub(crate) const DASHBOARD_UPDATED_DESCRIPTION: &str = "elasticctl-sample updated";

pub(crate) const DASHBOARD_PANEL_ID_PLACEHOLDER_PREFIX: &str =
    "elasticctl-fixture-dashboard-panel-";

pub(crate) const DASHBOARD_VOLATILE_FIELDS: &[&str] = &[
    "createdAt",
    "updatedAt",
    "created_at",
    "updated_at",
    "version",
    "migrationVersion",
    "coreMigrationVersion",
    "originId",
    "namespaces",
    "space",
];

pub(crate) const AGENT_POLICY_ID: &str = "elasticctl-sample-agent-policy";

pub(crate) const AGENT_POLICY_DUP_ID: &str = "elasticctl-sample-agent-policy-dup";

pub(crate) const AGENT_POLICY_NAME: &str = "elasticctl-sample-agent-policy";

pub(crate) const INTEGRATION_POLICY_PARENT_ID: &str = "elasticctl-sample-integration-policy-parent";

pub(crate) const INTEGRATION_POLICY_PARENT_NAME: &str =
    "elasticctl-sample-integration-policy-parent";

pub(crate) const INTEGRATION_POLICY_ID: &str = "elasticctl-sample-integration-policy";

pub(crate) const INTEGRATION_POLICY_DUP_ID: &str = "elasticctl-sample-integration-policy-dup";

pub(crate) const INTEGRATION_POLICY_NAME: &str = "elasticctl-sample-integration-policy";

pub(crate) const INTEGRATION_POLICY_PACKAGE: &str = "system";

pub(crate) const INTEGRATION_POLICY_NAMESPACE: &str = "default";

pub(crate) const INTEGRATION_POLICY_DESCRIPTION: &str = "elasticctl sample integration policy";

pub(crate) const INTEGRATION_POLICY_UPDATED_DESCRIPTION: &str =
    "elasticctl sample integration policy updated";

pub(crate) const INTEGRATION_POLICY_PARENT_DESCRIPTION: &str =
    "elasticctl sample integration policy parent";

pub(crate) const INTEGRATION_POLICY_PARENT_INACTIVITY_TIMEOUT: u64 = 1_209_600;

pub(crate) const INSTALLED_PACKAGE_INVENTORY_PATH: &str =
    "/api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc";

const INTEGRATION_RECORDING_NONCE_PREFIX: &str = " [elasticctl-recorder-nonce=";

const INTEGRATION_RECORDING_NONCE_SUFFIX: &str = "]";

#[cfg(test)]
pub(crate) const TEST_INTEGRATION_RECORDING_NONCE: &str = "test-integration-recording-nonce";

#[cfg(not(test))]
static INTEGRATION_RECORDING_NONCE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(not(test))]
pub(crate) fn integration_recording_nonce() -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let sequence = INTEGRATION_RECORDING_NONCE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{timestamp:x}-{:x}-{sequence:x}", std::process::id())
}

#[cfg(test)]
pub(crate) fn integration_recording_nonce() -> String {
    TEST_INTEGRATION_RECORDING_NONCE.to_string()
}

pub(crate) fn nonce_bearing_integration_description(description: &str, nonce: &str) -> String {
    format!(
        "{description}{INTEGRATION_RECORDING_NONCE_PREFIX}{nonce}{INTEGRATION_RECORDING_NONCE_SUFFIX}"
    )
}

pub(crate) fn marker_integration_description(nonce: &str) -> String {
    nonce_bearing_integration_description(INTEGRATION_POLICY_DESCRIPTION, nonce)
}

pub(crate) fn marker_integration_updated_description(nonce: &str) -> String {
    nonce_bearing_integration_description(INTEGRATION_POLICY_UPDATED_DESCRIPTION, nonce)
}

pub(crate) fn marker_integration_parent_description(nonce: &str) -> String {
    nonce_bearing_integration_description(INTEGRATION_POLICY_PARENT_DESCRIPTION, nonce)
}

pub(crate) const AGENT_POLICY_FIXTURE_TIMESTAMP: &str = "2026-01-01T00:00:00.000Z";

pub(crate) const CASE_VERSION_PLACEHOLDER: &str = "WzAsMV0=";

pub(crate) const CASE_ID_PLACEHOLDER: &str = "elasticctl-fixture-case";

pub(crate) const CASE_RULE_UUID_PLACEHOLDER: &str = "elasticctl-fixture-case-rule-uuid";

pub(crate) const CASE_DURATION_VOLATILE_FIELDS: &[&str] = &[
    "duration",
    "time_to_acknowledge",
    "time_to_investigate",
    "time_to_resolve",
];

pub(crate) const TRIAGE_ENVELOPE_VOLATILE_FIELDS: &[&str] = &["took", "timed_out", "_shards"];

pub(crate) const CLOSE_BY_QUERY_RUNTIME_FIELDS: &[&str] = &[
    "took",
    "timed_out",
    "_shards",
    "batches",
    "deleted",
    "requests_per_second",
    "retries",
    "throttled_millis",
    "throttled_until_millis",
];

pub(crate) const ALERT_SEARCH_VOLATILE_FIELDS: &[&str] = &[
    "took",
    "timed_out",
    "_shards",
    "_score",
    "max_score",
    "kibana.alert.rule.execution.uuid",
    "sort",
];
