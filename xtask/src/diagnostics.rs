pub(crate) fn recording_error(message: impl Into<String>) -> elasticctl_core::Error {
    elasticctl_core::Error::new(elasticctl_core::ErrorKind::Error, message)
}

const RECORD_TRACE_LABELS: &[&str] = &[
    "bootstrap",
    "prebuilt",
    "prebuilt-status-before",
    "prebuilt-status-before-check",
    "prebuilt-install",
    "prebuilt-install-check",
    "prebuilt-status-after",
    "prebuilt-status-compare",
    "exceptions-rules",
    "search",
    "data-views",
    "alerts",
    "alerts-preflight-rule",
    "alerts-preflight-index",
    "alerts-preflight-open",
    "alerts-index-write",
    "alerts-index-proof",
    "alerts-index-refresh",
    "alerts-rule-create",
    "alerts-poll",
    "alerts-page",
    "alerts-source",
    "alerts-status",
    "alerts-tags-add",
    "alerts-tags-remove",
    "alerts-users",
    "alerts-assignees-add",
    "alerts-assignees-remove",
    "alerts-profile-suggest",
    "alerts-rule-disable",
    "cases",
    "alerts-close",
    "data-views-preflight-source",
    "data-views-preflight-replacement",
    "data-views-preflight-index",
    "data-views-default-snapshot",
    "data-views-source-not-found",
    "data-views-index-create",
    "data-views-index-check",
    "data-views-index-proof-check",
    "data-views-default-before-create",
    "data-views-default-before-create-check",
    "data-views-source-create",
    "data-views-default-after-create",
    "data-views-default-after-create-check",
    "data-views-source-get",
    "data-views-scripted-check",
    "data-views-create-check",
    "data-views-list",
    "data-views-list-check",
    "data-views-update",
    "data-views-update-check",
    "data-views-fields",
    "data-views-fields-check",
    "data-views-fields-get",
    "data-views-fields-get-check",
    "data-views-hidden-update",
    "data-views-hidden-get",
    "data-views-hidden-check",
    "data-views-default-before",
    "data-views-default-before-check",
    "data-views-default-claim",
    "data-views-default-set",
    "data-views-default-set-check",
    "data-views-default-unset",
    "data-views-default-unset-check",
    "data-views-default-before-swap",
    "data-views-default-before-swap-check",
    "data-views-preview",
    "data-views-preview-request",
    "data-views-preview-check",
    "data-views-replacement-build",
    "data-views-replacement-create",
    "data-views-replacement-check",
    "data-views-swap",
    "data-views-swap-check",
    "data-views-source-after-swap",
    "data-views-default-after-swap",
    "data-views-default-after-swap-check",
    "data-views-default-restore",
    "data-views-default-restore-check",
    "data-views-default-restored-get",
    "data-views-default-raw-snapshot",
    "data-views-default-restored-check",
    "data-views-replacement-delete",
    "data-views-replacement-delete-check",
    "data-views-replacement-gone-check",
    "data-views-index-delete",
    "data-views-index-delete-check",
    "dashboards",
    "dashboards-preflight",
    "dashboards-data-view-create",
    "dashboards-data-view-check",
    "dashboards-loss-create",
    "dashboards-loss-check",
    "dashboards-loss-delete",
    "dashboards-loss-gone-check",
    "dashboards-create",
    "dashboards-create-check",
    "dashboards-get",
    "dashboards-get-check",
    "dashboards-search",
    "dashboards-search-check",
    "dashboards-update",
    "dashboards-update-check",
    "dashboards-export",
    "dashboards-export-check",
    "dashboards-delete",
    "dashboards-delete-check",
    "dashboards-data-view-delete",
    "dashboards-data-view-delete-check",
    "dashboards-import",
    "dashboards-import-check",
    "dashboards-import-conflict",
    "dashboards-import-conflict-check",
    "dashboards-final-delete",
    "dashboards-final-delete-check",
    "dashboards-final-data-view-delete",
    "dashboards-final-data-view-delete-check",
    "dashboards-not-found",
    "dashboards-data-view-not-found",
    "agent-policies",
    "fleet-setup",
    "fleet-agent-policy-preflight",
    "fleet-package-status",
    "fleet-agent-policy-create",
    "fleet-agent-policy-create-check",
    "fleet-agent-policy-get",
    "fleet-agent-policy-list",
    "fleet-agent-policy-list-check",
    "fleet-agent-policy-name-conflict",
    "fleet-agent-policy-name-conflict-check",
    "fleet-agent-policy-update",
    "fleet-agent-policy-update-check",
    "fleet-agent-policy-update-omitted",
    "fleet-agent-policy-get-after-omit",
    "fleet-agent-policy-delete",
    "fleet-agent-policy-delete-check",
    "integration-policies",
    "fleet-integration-policy-inventory-before",
    "fleet-integration-policy-status",
    "fleet-integration-policy-preflight",
    "fleet-integration-policy-parent-create",
    "fleet-integration-policy-metadata",
    "fleet-integration-policy-bootstrap-preflight",
    "fleet-integration-policy-bootstrap-create",
    "fleet-integration-policy-inventory-after-bootstrap-create",
    "fleet-integration-policy-bootstrap-get",
    "fleet-integration-policy-bootstrap-export",
    "fleet-integration-policy-bootstrap-delete",
    "fleet-integration-policy-create-preflight",
    "fleet-integration-policy-create",
    "fleet-integration-policy-inventory-after-create",
    "fleet-integration-policy-inventory-after-duplicate-create",
    "fleet-integration-policy-get",
    "fleet-integration-policy-list",
    "fleet-integration-policy-name-conflict-preflight",
    "fleet-integration-policy-name-conflict",
    "fleet-integration-policy-name-conflict-check",
    "fleet-integration-policy-parent-get",
    "fleet-integration-policy-update",
    "fleet-integration-policy-round-trip",
    "fleet-integration-policy-delete",
    "fleet-integration-policy-delete-check",
    "fleet-integration-policy-parent-delete",
    "fleet-integration-policy-parent-delete-check",
    "fleet-integration-policy-cleanup",
];

fn record_trace_label_is_safe(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
}

pub(crate) fn record_trace(label: &'static str) {
    debug_assert!(RECORD_TRACE_LABELS.contains(&label));
    debug_assert!(record_trace_label_is_safe(label));
    if std::env::var("ELASTICCTL_RECORD_TRACE").ok().as_deref() == Some("1") {
        eprintln!("record step: {label}");
    }
}

pub(crate) fn safe_recording_transport_error(
    context: &'static str,
    error: elasticctl_core::Error,
) -> elasticctl_core::Error {
    match error.http_status {
        Some(status) => elasticctl_core::Error::with_status(error.kind, status, context),
        None => elasticctl_core::Error::new(error.kind, context),
    }
}

pub(crate) fn safe_recording_error_summary(error: &elasticctl_core::Error) -> String {
    let status = error
        .http_status
        .map_or_else(|| "none".to_string(), |status| status.to_string());
    format!("class={} status={status}", error.kind.as_str())
}

pub(crate) fn dashboard_transport<T>(
    context: &'static str,
    result: elasticctl_core::Result<T>,
) -> elasticctl_core::Result<T> {
    result.map_err(|error| safe_recording_transport_error(context, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorder_error_summary_omits_server_messages() {
        let error = elasticctl_core::Error::with_status(
            elasticctl_core::ErrorKind::Conflict,
            409,
            "private object and index ids",
        );

        let summary = safe_recording_error_summary(&error);

        assert_eq!(summary, "class=conflict status=409");
        assert!(!summary.contains("private"));
    }

    #[test]
    fn record_trace_labels_are_static_safe_words() {
        assert!(RECORD_TRACE_LABELS.contains(&"alerts-close"));
        assert!(
            !RECORD_TRACE_LABELS.contains(&"fleet-integration-policy-parent-delete-refused"),
            "the recorder must never trace an attached-parent delete attempt"
        );
        for label in [
            "prebuilt-status-before",
            "prebuilt-status-before-check",
            "prebuilt-install",
            "prebuilt-install-check",
            "prebuilt-status-after",
            "prebuilt-status-compare",
        ] {
            assert!(RECORD_TRACE_LABELS.contains(&label));
        }
        assert!(RECORD_TRACE_LABELS.iter().all(|label| {
            record_trace_label_is_safe(label)
                && !label.contains("http")
                && !label.contains("url")
                && !label.contains("body")
        }));
        for unsafe_label in [
            "data views",
            "data-views: private",
            "data_views",
            "data-views\n",
        ] {
            assert!(!record_trace_label_is_safe(unsafe_label));
        }
    }
}
