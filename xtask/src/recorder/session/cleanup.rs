use crate::diagnostics::{recording_error, safe_recording_error_summary};
use crate::recorder::alerts::cleanup::sweep_close_marker_alerts;
use crate::recorder::cases::sweep_delete_marker_cases;
use crate::recorder::dashboards::fixtures::{owns_dashboard, owns_recorded_data_view};
use crate::recorder::data_views::defaults::restore_pending_data_view_default;
use crate::recorder::data_views::fixtures::{owns_data_view_index, verify_data_view_index_deleted};
use crate::recorder::integration::cleanup::{
    cleanup_marker_integration_parent, cleanup_marker_integration_with_inputs,
};
use crate::recorder::integration::inventory::{
    read_installed_package_inventory, require_absent_integration_markers,
    require_matching_inventory,
};
use crate::recorder::markers::{
    AGENT_POLICY_DUP_ID, AGENT_POLICY_ID, AGENT_POLICY_NAME, ALERT_PROBE_INDEX, ALERT_RULE_ID,
    DASHBOARD_DATA_VIEW_ID, DASHBOARD_ID, DASHBOARD_LOSS_ID, DATA_VIEW_DOC_ID, DATA_VIEW_INDEX,
    DATA_VIEW_REPLACEMENT_ID, DATA_VIEW_SOURCE_ID, INTEGRATION_POLICY_DUP_ID,
    INTEGRATION_POLICY_ID, INTEGRATION_POLICY_PARENT_ID, ITEM_ID, LIST_ID, NAMESPACE_TYPE, RULE_ID,
    SCRATCH_DOC_ID,
};
use crate::recorder::ownership::{
    owns_alert_index, owns_alert_rule, owns_item, owns_list, owns_rule, owns_scratch_index,
    owns_search_index, require_absent_alert_index, require_absent_alert_rule,
};
use crate::recorder::preview::{PREVIEW_PROBE_INDEX, SEARCH_PROBE_INDEX};
use crate::recorder::session::{CleanupResponses, IntegrationMarkerInputs, RecordingSession};
use elasticctl_core::urlencode;
use serde_json::{Value, json};

impl RecordingSession<'_> {
    pub(crate) async fn cleanup_integration_resources(&mut self) -> elasticctl_core::Result<()> {
        let mut errors = Vec::new();
        let expected_system_version = self.ownership.integration_system_package_version.clone();
        let session_nonce = self.ownership.integration_recording_nonce.clone();
        let expected_inputs = self.ownership.integration_policy_inputs.clone();

        if self.ownership.integration_policy {
            match (expected_system_version.as_deref(), session_nonce.as_deref()) {
                (Some(version), Some(nonce)) => match cleanup_marker_integration_with_inputs(
                    self.transport,
                    INTEGRATION_POLICY_ID,
                    version,
                    nonce,
                    expected_inputs.expectation(),
                )
                .await
                {
                    Ok(()) => self.ownership.integration_policy = false,
                    Err(error) => errors.push(format!(
                        "cleaning integration policy {INTEGRATION_POLICY_ID}: {}",
                        error.message
                    )),
                },
                _ => errors.push(format!(
                    "refusing to delete integration policy {INTEGRATION_POLICY_ID}: session cleanup ownership is incomplete"
                )),
            }
        }
        if self.ownership.integration_policy_dup {
            match (expected_system_version.as_deref(), session_nonce.as_deref()) {
                (Some(version), Some(nonce)) => match cleanup_marker_integration_with_inputs(
                    self.transport,
                    INTEGRATION_POLICY_DUP_ID,
                    version,
                    nonce,
                    expected_inputs.expectation(),
                )
                .await
                {
                    Ok(()) => self.ownership.integration_policy_dup = false,
                    Err(error) => errors.push(format!(
                        "cleaning integration policy {INTEGRATION_POLICY_DUP_ID}: {}",
                        error.message
                    )),
                },
                _ => errors.push(format!(
                    "refusing to delete integration policy {INTEGRATION_POLICY_DUP_ID}: session cleanup ownership is incomplete"
                )),
            }
        }

        if !self.ownership.integration_policy
            && !self.ownership.integration_policy_dup
            && self.ownership.integration_policy_parent
        {
            match session_nonce.as_deref() {
                Some(nonce) => match cleanup_marker_integration_parent(self.transport, nonce, &[]).await {
                    Ok(()) => self.ownership.integration_policy_parent = false,
                    Err(error) => errors.push(format!(
                        "cleaning integration policy parent {INTEGRATION_POLICY_PARENT_ID}: {}",
                        error.message
                    )),
                },
                None => errors.push(format!(
                    "refusing to delete integration policy parent {INTEGRATION_POLICY_PARENT_ID}: session cleanup ownership is incomplete"
                )),
            }
        }

        if !self.ownership.integration_policy
            && !self.ownership.integration_policy_dup
            && !self.ownership.integration_policy_parent
            && let Some(baseline) = self.ownership.integration_package_inventory.clone()
        {
            match read_installed_package_inventory(self.transport).await {
                Ok(current) => match require_matching_inventory(&baseline, &current) {
                    Ok(()) => match require_absent_integration_markers(self.transport).await {
                        Ok(()) => {
                            self.ownership.integration_package_inventory = None;
                            self.ownership.integration_system_package_version = None;
                            self.ownership.integration_recording_nonce = None;
                            self.ownership.integration_policy_inputs =
                                IntegrationMarkerInputs::Empty;
                        }
                        Err(error) => errors.push(format!(
                            "verifying integration marker cleanup: {}",
                            error.message
                        )),
                    },
                    Err(error) => errors.push(format!(
                        "verifying installed package inventory restoration: {}",
                        error.message
                    )),
                },
                Err(error) => errors.push(format!(
                    "reading installed package inventory after cleanup: {}",
                    safe_recording_error_summary(&error)
                )),
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(recording_error(errors.join("; ")))
        }
    }

    pub(crate) async fn cleanup(&mut self) -> elasticctl_core::Result<CleanupResponses> {
        let mut errors = Vec::new();
        let mut responses = CleanupResponses::default();

        if let Err(error) = self.cleanup_integration_resources().await {
            errors.push(format!(
                "cleaning integration marker resources: {}",
                error.message
            ));
        }

        let mut data_view_cleanup_safe = true;
        if self.ownership.pending_data_view_default_restore.is_some()
            && let Err(error) = restore_pending_data_view_default(self).await
        {
            data_view_cleanup_safe = false;
            errors.push(format!(
                "restoring original data-view default: {}",
                error.message
            ));
        }

        for (id, owned) in [
            (AGENT_POLICY_ID, &mut self.ownership.agent_policy),
            (AGENT_POLICY_DUP_ID, &mut self.ownership.agent_policy_dup),
        ] {
            if !*owned {
                continue;
            }
            match self
                .transport
                .get(&format!("/api/fleet/agent_policies/{}", urlencode(id)))
                .await
            {
                Ok(policy) if policy["item"]["name"].as_str() == Some(AGENT_POLICY_NAME) => {
                    match self
                        .transport
                        .post(
                            "/api/fleet/agent_policies/delete",
                            Some(&json!({"agentPolicyId": id})),
                        )
                        .await
                    {
                        Ok(_) => match self
                            .transport
                            .get(&format!("/api/fleet/agent_policies/{}", urlencode(id)))
                            .await
                        {
                            Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                                *owned = false
                            }
                            Ok(_) => {
                                errors.push(format!("agent policy {id} still exists after delete"))
                            }
                            Err(error) => errors.push(format!(
                                "verifying agent policy {id} deletion: {}",
                                safe_recording_error_summary(&error)
                            )),
                        },
                        Err(error) => errors.push(format!(
                            "deleting agent policy {id}: {}",
                            safe_recording_error_summary(&error)
                        )),
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete agent policy {id}: its name no longer matches the marker"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => *owned = false,
                Err(error) => errors.push(format!(
                    "checking agent policy {id}: {}",
                    safe_recording_error_summary(&error)
                )),
            }
        }

        for (id, owned) in [
            (DASHBOARD_ID, &mut self.ownership.dashboard),
            (DASHBOARD_LOSS_ID, &mut self.ownership.dashboard_loss),
        ] {
            if !*owned {
                continue;
            }
            match self
                .transport
                .get(&format!("/api/dashboards/{}", urlencode(id)))
                .await
            {
                Ok(dashboard) if owns_dashboard(&dashboard, id) => {
                    match self
                        .transport
                        .delete(&format!("/api/dashboards/{}", urlencode(id)))
                        .await
                    {
                        Ok(Value::Null) => {
                            match self
                                .transport
                                .get(&format!("/api/dashboards/{}", urlencode(id)))
                                .await
                            {
                                Err(error)
                                    if error.kind == elasticctl_core::ErrorKind::NotFound =>
                                {
                                    *owned = false
                                }
                                Ok(_) => {
                                    errors.push(format!("dashboard {id} still exists after delete"))
                                }
                                Err(error) => errors.push(format!(
                                    "verifying dashboard {id} deletion: {}",
                                    safe_recording_error_summary(&error)
                                )),
                            }
                        }
                        Ok(_) => errors.push(format!(
                            "deleting dashboard {id}: expected an empty response body"
                        )),
                        Err(error) => errors.push(format!(
                            "deleting dashboard {id}: {}",
                            safe_recording_error_summary(&error)
                        )),
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete dashboard {id}: its marker identity no longer matches"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => *owned = false,
                Err(error) => errors.push(format!(
                    "checking dashboard {id}: {}",
                    safe_recording_error_summary(&error)
                )),
            }
        }

        data_view_cleanup_safe &= !self.ownership.dashboard && !self.ownership.dashboard_loss;

        if data_view_cleanup_safe {
            for (id, owned) in [
                (DATA_VIEW_SOURCE_ID, &mut self.ownership.data_view_source),
                (
                    DATA_VIEW_REPLACEMENT_ID,
                    &mut self.ownership.data_view_replacement,
                ),
                (
                    DASHBOARD_DATA_VIEW_ID,
                    &mut self.ownership.dashboard_data_view,
                ),
            ] {
                if !*owned {
                    continue;
                }
                match elasticctl_api::data_views::get(self.transport, id).await {
                    Ok(view) if owns_recorded_data_view(&view.data_view, id) => {
                        match elasticctl_api::data_views::delete(self.transport, id).await {
                            Ok(()) => {
                                match elasticctl_api::data_views::get(self.transport, id).await {
                                    Err(error)
                                        if error.kind == elasticctl_core::ErrorKind::NotFound =>
                                    {
                                        *owned = false
                                    }
                                    Ok(_) => errors
                                        .push(format!("data view {id} still exists after delete")),
                                    Err(error) => errors.push(format!(
                                        "verifying data view {id} deletion: {}",
                                        safe_recording_error_summary(&error)
                                    )),
                                }
                            }
                            Err(error) => errors.push(format!(
                                "deleting data view {id}: {}",
                                safe_recording_error_summary(&error)
                            )),
                        }
                    }
                    Ok(_) => errors.push(format!(
                        "refusing to delete data view {id}: its marker identity no longer matches"
                    )),
                    Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                        *owned = false
                    }
                    Err(error) => errors.push(format!(
                        "checking data view {id}: {}",
                        safe_recording_error_summary(&error)
                    )),
                }
            }

            let data_view_index_cleanup_safe = !self.ownership.data_view_source
                && !self.ownership.data_view_replacement
                && !self.ownership.dashboard_data_view;
            if data_view_index_cleanup_safe && self.ownership.data_view_index {
                match self
                    .transport
                    .get_absolute_es(&format!("/{DATA_VIEW_INDEX}/_doc/{DATA_VIEW_DOC_ID}"))
                    .await
                {
                    Ok(document) if owns_data_view_index(&document) => {
                        match self
                            .transport
                            .delete_absolute_es(&format!("/{DATA_VIEW_INDEX}"))
                            .await
                        {
                            Ok(_) => match verify_data_view_index_deleted(self.transport).await {
                                Ok(()) => self.ownership.data_view_index = false,
                                Err(error) => errors.push(format!(
                                    "verifying data-view index {DATA_VIEW_INDEX} deletion: {}",
                                    error.message
                                )),
                            },
                            Err(error) => errors.push(format!(
                                "deleting data-view index {DATA_VIEW_INDEX}: {}",
                                error.message
                            )),
                        }
                    }
                    Ok(_) => errors.push(format!(
                        "refusing to delete data-view index {DATA_VIEW_INDEX}: its marker fields no longer match"
                    )),
                    Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                        match verify_data_view_index_deleted(self.transport).await {
                            Ok(()) => self.ownership.data_view_index = false,
                            Err(error) => errors.push(format!(
                                "verifying markerless data-view index {DATA_VIEW_INDEX}: {}",
                                error.message
                            )),
                        }
                    }
                    Err(error) => errors.push(format!(
                        "checking data-view index {DATA_VIEW_INDEX}: {}",
                        error.message
                    )),
                }
            }
        }

        if self.ownership.rule {
            match self
                .transport
                .get(&format!("/api/detection_engine/rules?rule_id={RULE_ID}"))
                .await
            {
                Ok(rule) if owns_rule(&rule) => {
                    match self
                        .transport
                        .delete(&format!("/api/detection_engine/rules?rule_id={RULE_ID}"))
                        .await
                    {
                        Ok(deleted) => {
                            self.ownership.rule = false;
                            responses.rule = Some(deleted);
                        }
                        Err(error) => {
                            errors.push(format!("deleting rule {RULE_ID}: {}", error.message))
                        }
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete rule {RULE_ID}: its marker fields no longer match"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                    self.ownership.rule = false;
                }
                Err(error) => errors.push(format!("checking rule {RULE_ID}: {}", error.message)),
            }
        }

        if self.ownership.item {
            match self
                .transport
                .get(&format!(
                    "/api/exception_lists/items?item_id={}&namespace_type={NAMESPACE_TYPE}",
                    urlencode(ITEM_ID)
                ))
                .await
            {
                Ok(item) if owns_item(&item) => {
                    match self
                        .transport
                        .delete(&format!(
                            "/api/exception_lists/items?item_id={}&namespace_type={NAMESPACE_TYPE}",
                            urlencode(ITEM_ID)
                        ))
                        .await
                    {
                        Ok(_) => self.ownership.item = false,
                        Err(error) => {
                            errors.push(format!("deleting item {ITEM_ID}: {}", error.message))
                        }
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete item {ITEM_ID}: its marker fields no longer match"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                    self.ownership.item = false;
                }
                Err(error) => errors.push(format!("checking item {ITEM_ID}: {}", error.message)),
            }
        }

        if self.ownership.list {
            match self
                .transport
                .get(&format!(
                    "/api/exception_lists?list_id={}&namespace_type={NAMESPACE_TYPE}",
                    urlencode(LIST_ID)
                ))
                .await
            {
                Ok(list) if owns_list(&list) => {
                    match self
                        .transport
                        .delete(&format!(
                            "/api/exception_lists?list_id={}&namespace_type={NAMESPACE_TYPE}",
                            urlencode(LIST_ID)
                        ))
                        .await
                    {
                        Ok(_) => self.ownership.list = false,
                        Err(error) => {
                            errors.push(format!("deleting list {LIST_ID}: {}", error.message))
                        }
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete list {LIST_ID}: its marker fields no longer match"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                    self.ownership.list = false;
                }
                Err(error) => errors.push(format!("checking list {LIST_ID}: {}", error.message)),
            }
        }

        if self.ownership.scratch_index {
            match self
                .transport
                .get_absolute_es(&format!("/{PREVIEW_PROBE_INDEX}/_doc/{SCRATCH_DOC_ID}"))
                .await
            {
                Ok(document) if owns_scratch_index(&document) => {
                    match self
                        .transport
                        .delete_absolute_es(&format!("/{PREVIEW_PROBE_INDEX}"))
                        .await
                    {
                        Ok(_) => self.ownership.scratch_index = false,
                        Err(error) => errors.push(format!(
                            "deleting scratch index {PREVIEW_PROBE_INDEX}: {}",
                            error.message
                        )),
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete scratch index {PREVIEW_PROBE_INDEX}: its marker field no longer matches"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                    self.ownership.scratch_index = false;
                }
                Err(error) => errors.push(format!(
                    "checking scratch index {PREVIEW_PROBE_INDEX}: {}",
                    error.message
                )),
            }
        }

        self.cleanup_esql_async(&mut errors).await;

        if self.ownership.search_index {
            match self
                .transport
                .get_absolute_es(&format!("/{SEARCH_PROBE_INDEX}/_doc/1"))
                .await
            {
                Ok(document) if owns_search_index(&document) => {
                    match self
                        .transport
                        .delete_absolute_es(&format!("/{SEARCH_PROBE_INDEX}"))
                        .await
                    {
                        Ok(_) => self.ownership.search_index = false,
                        Err(error) => errors.push(format!(
                            "deleting scratch index {SEARCH_PROBE_INDEX}: {}",
                            error.message
                        )),
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete scratch index {SEARCH_PROBE_INDEX}: its marker field no longer matches"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                    self.ownership.search_index = false;
                }
                Err(error) => errors.push(format!(
                    "checking scratch index {SEARCH_PROBE_INDEX}: {}",
                    error.message
                )),
            }
        }

        if self.ownership.alert_rule {
            match self
                .transport
                .get(&format!(
                    "/api/detection_engine/rules?rule_id={ALERT_RULE_ID}"
                ))
                .await
            {
                Ok(rule) if owns_alert_rule(&rule) => {
                    match self
                        .transport
                        .delete(&format!(
                            "/api/detection_engine/rules?rule_id={ALERT_RULE_ID}"
                        ))
                        .await
                    {
                        Ok(_) => self.ownership.alert_rule = false,
                        Err(error) => {
                            errors.push(format!("deleting rule {ALERT_RULE_ID}: {}", error.message))
                        }
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete rule {ALERT_RULE_ID}: its marker fields no longer match"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                    self.ownership.alert_rule = false;
                }
                Err(error) => {
                    errors.push(format!("checking rule {ALERT_RULE_ID}: {}", error.message))
                }
            }
        }

        if self.ownership.alert_index {
            match self
                .transport
                .get_absolute_es(&format!("/{ALERT_PROBE_INDEX}/_doc/1"))
                .await
            {
                Ok(document) if owns_alert_index(&document) => {
                    match self
                        .transport
                        .delete_absolute_es(&format!("/{ALERT_PROBE_INDEX}"))
                        .await
                    {
                        Ok(_) => self.ownership.alert_index = false,
                        Err(error) => errors.push(format!(
                            "deleting alert index {ALERT_PROBE_INDEX}: {}",
                            error.message
                        )),
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete alert index {ALERT_PROBE_INDEX}: its marker field no longer matches"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                    self.ownership.alert_index = false;
                }
                Err(error) => errors.push(format!(
                    "checking alert index {ALERT_PROBE_INDEX}: {}",
                    error.message
                )),
            }
        }

        if self.ownership.case
            && let Err(error) = sweep_delete_marker_cases(self.transport).await
        {
            errors.push(format!("verifying case probe baseline: {}", error.message));
        }

        if self.ownership.alert_rule_claimed
            && let Err(error) = require_absent_alert_rule(self.transport).await
        {
            errors.push(format!(
                "verifying the alert probe rule is gone: {}",
                error.message
            ));
        }
        if self.ownership.alert_index_claimed
            && let Err(error) = require_absent_alert_index(self.transport).await
        {
            errors.push(format!(
                "verifying the alert probe index is gone: {}",
                error.message
            ));
        }

        if let Err(error) = sweep_close_marker_alerts(self.transport).await {
            errors.push(format!(
                "verifying alert probe baseline: {}. Manual remediation: POST {} with \
                 body {{\"query\":{{\"term\":{{\"kibana.alert.rule.rule_id\":\"{ALERT_RULE_ID}\"}}}},\
                 \"status\":\"closed\",\"conflicts\":\"abort\"}}",
                error.message,
                elasticctl_api::alerts::STATUS_PATH,
            ));
        }

        if errors.is_empty() {
            Ok(responses)
        } else {
            Err(recording_error(format!(
                "cleanup failed: {}",
                errors.join("; ")
            )))
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::recorder::alerts::cleanup::sweep_close_marker_alerts;

    use crate::recorder::markers::{
        DASHBOARD_DATA_VIEW_ID, DASHBOARD_ID, DATA_VIEW_DOC_ID, DATA_VIEW_INDEX,
        DATA_VIEW_REPLACEMENT_ID, DATA_VIEW_SOURCE_ID, INTEGRATION_POLICY_DESCRIPTION,
        INTEGRATION_POLICY_ID, INTEGRATION_POLICY_NAME, INTEGRATION_POLICY_PARENT_ID,
        INTEGRATION_POLICY_PARENT_NAME, INTEGRATION_POLICY_UPDATED_DESCRIPTION,
        TEST_INTEGRATION_RECORDING_NONCE,
    };

    use crate::recorder::session::{
        CleanupOwnership, PendingDefaultRestore, PendingDefaultRestorePhase, RecordingSession,
    };
    use crate::recorder::test_support::{
        OTHER_INTEGRATION_RECORDING_NONCE, installed_system_inventory,
        integration_cleanup_ownership, marker_integration_parent_response,
        marker_integration_parent_response_with_nonce, marker_integration_response,
        marker_integration_response_with_nonce, merge_marker_item_fields, mock_transport,
    };

    use crate::recorder::test_support::{
        unsafe_marker_integration_fields, unsafe_marker_parent_fields,
    };
    use serde_json::json;

    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn alert_sweep_failure_keeps_private_server_ids_out_of_both_call_paths() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(elasticctl_api::alerts::SEARCH_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hits": {"total": {"value": 1}}
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(elasticctl_api::alerts::STATUS_PATH))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "message": "private alert and index ids"
            })))
            .expect(2)
            .mount(&server)
            .await;
        let transport = mock_transport(&server);

        let error = sweep_close_marker_alerts(&transport)
            .await
            .expect_err("helper failure");
        assert_eq!(error.kind, elasticctl_core::ErrorKind::Conflict);
        assert_eq!(error.http_status, Some(409));
        assert_eq!(error.message, "close-by-query sweep retry failed");
        assert!(!error.message.contains("private"));

        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let cleanup = match session.cleanup().await {
            Ok(_) => panic!("cleanup must fail"),
            Err(error) => error,
        };
        assert!(!cleanup.message.contains("private"));
    }

    #[tokio::test]
    async fn cleanup_keeps_index_ownership_when_marker_document_is_missing_but_root_remains() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/{DATA_VIEW_INDEX}/_doc/{DATA_VIEW_DOC_ID}")))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/{DATA_VIEW_INDEX}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"settings": {}})))
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                data_view_index: true,
                ..Default::default()
            },
        };

        assert!(
            session.cleanup().await.is_err(),
            "markerless root must fail"
        );

        assert!(session.ownership.data_view_index);
        assert!(
            server
                .received_requests()
                .await
                .expect("requests")
                .iter()
                .all(|request| !(request.method.as_str() == "DELETE"
                    && request.url.path() == format!("/{DATA_VIEW_INDEX}")))
        );
    }

    #[tokio::test]
    async fn source_create_response_loss_cleanup_restores_before_data_view_deletes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/data_views/default"))
            .respond_with(
                ResponseTemplate::new(500).set_body_json(json!({"message": "restore failed"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/default"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data_view_id": DATA_VIEW_SOURCE_ID})),
            )
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                pending_data_view_default_restore: Some(PendingDefaultRestore {
                    raw: json!({"data_view_id": null}),
                    canonical: None,
                    phase: PendingDefaultRestorePhase::CreateMayImplicitlySetSource,
                }),
                data_view_source: true,
                data_view_replacement: true,
                data_view_index: true,
                ..Default::default()
            },
        };

        assert!(
            session.cleanup().await.is_err(),
            "restore failure after source-create response loss must stop deletes"
        );

        assert!(
            session
                .ownership
                .pending_data_view_default_restore
                .is_some()
        );
        assert!(session.ownership.data_view_source);
        assert!(session.ownership.data_view_replacement);
        assert!(session.ownership.data_view_index);
        let requests = server.received_requests().await.expect("requests");
        let deletes: Vec<_> = requests
            .iter()
            .filter(|request| request.method.as_str() == "DELETE")
            .map(|request| request.url.path())
            .collect();
        assert!(
            deletes.iter().all(|path| {
                *path != format!("/api/data_views/data_view/{DATA_VIEW_SOURCE_ID}")
                    && *path != format!("/api/data_views/data_view/{DATA_VIEW_REPLACEMENT_ID}")
                    && *path != format!("/{DATA_VIEW_INDEX}")
            }),
            "data-view cleanup deleted after failed restore: {deletes:?}"
        );
    }

    #[tokio::test]
    async fn explicit_default_response_loss_cleanup_retains_the_lease_and_skips_deletes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/default"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data_view_id": DATA_VIEW_SOURCE_ID})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/data_views/default"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "lost"})))
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                pending_data_view_default_restore: Some(PendingDefaultRestore {
                    raw: json!({"data_view_id": null}),
                    canonical: None,
                    phase: PendingDefaultRestorePhase::ExplicitDefaultMutationMayHaveChanged,
                }),
                data_view_source: true,
                data_view_replacement: true,
                data_view_index: true,
                ..Default::default()
            },
        };

        assert!(session.cleanup().await.is_err());
        assert!(
            session
                .ownership
                .pending_data_view_default_restore
                .is_some()
        );
        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().all(|request| {
            !(request.method.as_str() == "DELETE"
                && matches!(
                    request.url.path(),
                    "/api/data_views/data_view/elasticctl-sample-data-view-source"
                        | "/api/data_views/data_view/elasticctl-sample-data-view-replacement"
                        | "/.kibana-elasticctl-sample-data-views"
                ))
        }));
    }

    #[tokio::test]
    async fn cleanup_default_errors_do_not_leak_server_envelopes_or_delete_data_views() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/data_views/default"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "message": "private-cleanup-post-id",
                "opaque": {"raw": "private-cleanup-post-envelope"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/default"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "message": "private-cleanup-get-id",
                "opaque": {"raw": "private-cleanup-get-envelope"}
            })))
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                pending_data_view_default_restore: Some(PendingDefaultRestore {
                    raw: json!({"data_view_id": "private-original-default"}),
                    canonical: Some("private-original-default".to_string()),
                    phase: PendingDefaultRestorePhase::ExplicitDefaultMutationMayHaveChanged,
                }),
                data_view_source: true,
                data_view_replacement: true,
                data_view_index: true,
                ..Default::default()
            },
        };

        let error = match session.cleanup().await {
            Ok(_) => panic!("default errors must fail cleanup"),
            Err(error) => error,
        };

        assert!(
            session
                .ownership
                .pending_data_view_default_restore
                .is_some()
        );
        assert!(session.ownership.data_view_source);
        assert!(session.ownership.data_view_replacement);
        assert!(session.ownership.data_view_index);
        for private in [
            "private-original-default",
            "private-cleanup-post-id",
            "private-cleanup-post-envelope",
            "private-cleanup-get-id",
            "private-cleanup-get-envelope",
            "data_view_id",
            "opaque",
        ] {
            assert!(
                !error.message.contains(private),
                "cleanup error leaked {private}: {}",
                error.message
            );
        }
        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().all(|request| {
            !(request.method.as_str() == "DELETE"
                && matches!(
                    request.url.path(),
                    "/api/data_views/data_view/elasticctl-sample-data-view-source"
                        | "/api/data_views/data_view/elasticctl-sample-data-view-replacement"
                        | "/.kibana-elasticctl-sample-data-views"
                ))
        }));
    }

    #[tokio::test]
    async fn cleanup_raw_default_mismatch_keeps_ownership_without_leaking_defaults() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/data_views/default"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/default"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data_view_id": DATA_VIEW_SOURCE_ID})),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/default"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data_view_id": "private-actual-default"
            })))
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                pending_data_view_default_restore: Some(PendingDefaultRestore {
                    raw: json!({"data_view_id": "private-expected-default"}),
                    canonical: Some("private-expected-default".to_string()),
                    phase: PendingDefaultRestorePhase::ExplicitDefaultMutationMayHaveChanged,
                }),
                data_view_source: true,
                data_view_replacement: true,
                data_view_index: true,
                ..Default::default()
            },
        };

        let error = match session.cleanup().await {
            Ok(_) => panic!("raw default mismatch must fail cleanup"),
            Err(error) => error,
        };

        assert!(
            session
                .ownership
                .pending_data_view_default_restore
                .is_some()
        );
        assert!(session.ownership.data_view_source);
        assert!(session.ownership.data_view_replacement);
        assert!(session.ownership.data_view_index);
        assert!(
            !error.message.contains("private-expected-default")
                && !error.message.contains("private-actual-default")
                && !error.message.contains("data_view_id"),
            "cleanup diagnostic leaked raw default evidence: {}",
            error.message
        );

        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().any(|request| {
            request.method.as_str() == "POST" && request.url.path() == "/api/data_views/default"
        }));
        assert!(requests.iter().any(|request| {
            request.method.as_str() == "GET" && request.url.path() == "/api/data_views/default"
        }));
        assert!(requests.iter().all(|request| {
            !(request.method.as_str() == "DELETE"
                && matches!(
                    request.url.path(),
                    "/api/data_views/data_view/elasticctl-sample-data-view-source"
                        | "/api/data_views/data_view/elasticctl-sample-data-view-replacement"
                        | "/.kibana-elasticctl-sample-data-views"
                ))
        }));
    }

    #[tokio::test]
    async fn cleanup_unexpected_nonmarker_default_sends_no_restore_or_delete() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/data_views/default"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"data_view_id": "private-other"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                pending_data_view_default_restore: Some(PendingDefaultRestore {
                    raw: json!({"data_view_id": "private-original"}),
                    canonical: Some("private-original".to_string()),
                    phase: PendingDefaultRestorePhase::ExplicitDefaultMutationMayHaveChanged,
                }),
                data_view_source: true,
                data_view_replacement: true,
                data_view_index: true,
                ..Default::default()
            },
        };

        let error = match session.cleanup().await {
            Ok(_) => panic!("unexpected default must refuse"),
            Err(error) => error,
        };
        assert!(
            session
                .ownership
                .pending_data_view_default_restore
                .is_some()
        );
        assert!(!error.message.contains("private-original"));
        assert!(!error.message.contains("private-other"));
        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().all(|request| {
            !(request.method.as_str() == "POST" && request.url.path() == "/api/data_views/default")
        }));
        assert!(requests.iter().all(|request| {
            !(request.method.as_str() == "DELETE"
                && matches!(
                    request.url.path(),
                    "/api/data_views/data_view/elasticctl-sample-data-view-source"
                        | "/api/data_views/data_view/elasticctl-sample-data-view-replacement"
                        | "/.kibana-elasticctl-sample-data-views"
                ))
        }));
    }

    #[tokio::test]
    async fn cleanup_keeps_each_data_view_owned_until_post_delete_get_is_not_found() {
        for id in [DATA_VIEW_SOURCE_ID, DATA_VIEW_REPLACEMENT_ID] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(format!("/api/data_views/data_view/{id}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"data_view": {"id": id, "title": "logs-*"}})),
                )
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(format!("/api/data_views/data_view/{id}")))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;
            let transport = mock_transport(&server);
            let mut session = RecordingSession {
                transport: &transport,
                ownership: CleanupOwnership {
                    data_view_source: id == DATA_VIEW_SOURCE_ID,
                    data_view_replacement: id == DATA_VIEW_REPLACEMENT_ID,
                    ..Default::default()
                },
            };

            assert!(
                session.cleanup().await.is_err(),
                "post-delete view still exists"
            );

            assert_eq!(
                session.ownership.data_view_source,
                id == DATA_VIEW_SOURCE_ID,
                "{id} source ownership"
            );
            assert_eq!(
                session.ownership.data_view_replacement,
                id == DATA_VIEW_REPLACEMENT_ID,
                "{id} replacement ownership"
            );
        }
    }

    #[tokio::test]
    async fn dashboard_cleanup_transport_error_omits_server_message() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/api/dashboards/{DASHBOARD_ID}")))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "message": "private dashboard cleanup identity"
            })))
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                dashboard: true,
                ..Default::default()
            },
        };

        let error = match session.cleanup().await {
            Err(error) => error,
            Ok(_) => panic!("dashboard cleanup must report its failed check"),
        };

        assert!(error.message.contains("class=http status=500"));
        assert!(!error.message.contains("private"));
    }

    #[tokio::test]
    async fn dashboard_cleanup_failure_retains_data_views_and_their_index() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/api/dashboards/{DASHBOARD_ID}")))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "message": "private dashboard cleanup identity"
            })))
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                dashboard: true,
                dashboard_data_view: true,
                data_view_index: true,
                ..Default::default()
            },
        };

        assert!(session.cleanup().await.is_err());
        assert!(session.ownership.dashboard);
        assert!(session.ownership.dashboard_data_view);
        assert!(session.ownership.data_view_index);
        let requests = server.received_requests().await.expect("requests");
        assert!(
            requests
                .iter()
                .any(|request| { request.url.path() == format!("/api/dashboards/{DASHBOARD_ID}") })
        );
        assert!(requests.iter().all(|request| {
            !request.url.path().starts_with("/api/data_views/data_view/")
                && !request
                    .url
                    .path()
                    .starts_with(&format!("/{DATA_VIEW_INDEX}"))
        }));
    }

    #[tokio::test]
    async fn data_view_cleanup_failure_retains_its_index() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/data_views/data_view/{DATA_VIEW_SOURCE_ID}"
            )))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "message": "private data-view cleanup identity"
            })))
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                data_view_source: true,
                data_view_index: true,
                ..Default::default()
            },
        };

        assert!(session.cleanup().await.is_err());
        assert!(session.ownership.data_view_source);
        assert!(session.ownership.data_view_index);
        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().any(|request| {
            request.url.path() == format!("/api/data_views/data_view/{DATA_VIEW_SOURCE_ID}")
        }));
        assert!(requests.iter().all(|request| {
            !request
                .url
                .path()
                .starts_with(&format!("/{DATA_VIEW_INDEX}"))
        }));
    }

    #[tokio::test]
    async fn cleanup_refuses_a_same_id_dashboard_data_view_with_mismatched_marker_content() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/data_views/data_view/{DASHBOARD_DATA_VIEW_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data_view": {
                    "id": DASHBOARD_DATA_VIEW_ID,
                    "title": "replacement-without-marker",
                    "name": "replacement-without-marker"
                }
            })))
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                dashboard_data_view: true,
                ..Default::default()
            },
        };

        let error = match session.cleanup().await {
            Err(error) => error,
            Ok(_) => panic!("a same-id replacement must retain ownership for investigation"),
        };
        let requests = server.received_requests().await.expect("requests");

        assert!(error.message.contains("marker identity no longer matches"));
        assert!(session.ownership.dashboard_data_view);
        assert!(
            requests
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );
    }

    #[tokio::test]
    async fn transient_integration_cleanup_delete_is_one_shot_before_a_replacement_is_refused() {
        let server = MockServer::start().await;
        let integration_path = format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}");
        let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reads_for_response = reads.clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                if reads_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(200).set_body_json(marker_integration_response(
                        INTEGRATION_POLICY_UPDATED_DESCRIPTION,
                    ))
                } else {
                    ResponseTemplate::new(200).set_body_json(
                        marker_integration_response_with_nonce(
                            INTEGRATION_POLICY_UPDATED_DESCRIPTION,
                            OTHER_INTEGRATION_RECORDING_NONCE,
                        ),
                    )
                }
            })
            .mount(&server)
            .await;
        let deletes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let deletes_for_response = deletes.clone();
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                if deletes_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(500).set_body_json(json!({"statusCode": 500}))
                } else {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "id": INTEGRATION_POLICY_ID,
                    }))
                }
            })
            .mount(&server)
            .await;

        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                integration_policy: true,
                ..integration_cleanup_ownership()
            },
        };

        session
            .cleanup_integration_resources()
            .await
            .expect_err("the transient cleanup delete is ambiguous");
        let cleanup_error = session
            .cleanup_integration_resources()
            .await
            .expect_err("the next cleanup must refuse the replacement nonce");
        assert!(
            cleanup_error
                .message
                .contains("marker identity no longer matches")
        );

        let requests = server.received_requests().await.expect("requests");
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.method.as_str() == "DELETE" && request.url.path() == integration_path
                })
                .count(),
            1,
            "cleanup must not replay DELETE against a replacement integration"
        );
        let delete = requests
            .iter()
            .position(|request| request.method.as_str() == "DELETE")
            .expect("cleanup delete");
        assert!(
            requests.iter().enumerate().any(|(index, request)| {
                index > delete
                    && request.method.as_str() == "GET"
                    && request.url.path() == integration_path
            }),
            "the next cleanup must fresh-GET before deciding whether it owns the replacement"
        );
    }

    #[tokio::test]
    async fn transient_parent_cleanup_delete_is_one_shot_before_a_replacement_is_refused() {
        let server = MockServer::start().await;
        let parent_path = format!("/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}");
        let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reads_for_response = reads.clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                if reads_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    let mut parent = marker_integration_parent_response();
                    parent["item"]["package_policies"] = json!([]);
                    ResponseTemplate::new(200).set_body_json(parent)
                } else {
                    let mut parent = marker_integration_parent_response_with_nonce(
                        OTHER_INTEGRATION_RECORDING_NONCE,
                    );
                    parent["item"]["package_policies"] = json!([]);
                    ResponseTemplate::new(200).set_body_json(parent)
                }
            })
            .mount(&server)
            .await;
        let deletes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let deletes_for_response = deletes.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies/delete"))
            .and(body_json(
                json!({"agentPolicyId": INTEGRATION_POLICY_PARENT_ID}),
            ))
            .respond_with(move |_: &wiremock::Request| {
                if deletes_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(500).set_body_json(json!({"statusCode": 500}))
                } else {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "id": INTEGRATION_POLICY_PARENT_ID,
                    }))
                }
            })
            .mount(&server)
            .await;

        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                integration_policy_parent: true,
                integration_recording_nonce: Some(TEST_INTEGRATION_RECORDING_NONCE.to_string()),
                ..Default::default()
            },
        };

        session
            .cleanup_integration_resources()
            .await
            .expect_err("the transient parent cleanup delete is ambiguous");
        let cleanup_error = session
            .cleanup_integration_resources()
            .await
            .expect_err("the next cleanup must refuse the replacement nonce");
        assert!(
            cleanup_error
                .message
                .contains("marker identity no longer matches")
        );

        let requests = server.received_requests().await.expect("requests");
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.method.as_str() == "POST"
                        && request.url.path() == "/api/fleet/agent_policies/delete"
                })
                .count(),
            1,
            "cleanup must not replay the parent delete against a replacement"
        );
        let delete = requests
            .iter()
            .position(|request| {
                request.method.as_str() == "POST"
                    && request.url.path() == "/api/fleet/agent_policies/delete"
            })
            .expect("cleanup parent delete");
        assert!(
            requests.iter().enumerate().any(|(index, request)| {
                index > delete
                    && request.method.as_str() == "GET"
                    && request.url.path() == parent_path
            }),
            "the next cleanup must fresh-GET before deciding whether it owns the replacement"
        );
    }

    #[tokio::test]
    async fn integration_cleanup_deletes_integration_then_parent_without_touching_packages() {
        let server = MockServer::start().await;
        let integration_gets = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let integration_gets_for_response = integration_gets.clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                if integration_gets_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    == 0
                {
                    ResponseTemplate::new(200)
                        .set_body_json(marker_integration_response(INTEGRATION_POLICY_DESCRIPTION))
                } else {
                    ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}))
                }
            })
            .mount(&server)
            .await;
        let parent_gets = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let parent_gets_for_response = parent_gets.clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                if parent_gets_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    let mut parent = marker_integration_parent_response();
                    parent["item"]["package_policies"] = json!([]);
                    ResponseTemplate::new(200).set_body_json(parent)
                } else {
                    ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}))
                }
            })
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"id": INTEGRATION_POLICY_ID})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies/delete"))
            .and(body_json(
                json!({"agentPolicyId": INTEGRATION_POLICY_PARENT_ID}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"id": INTEGRATION_POLICY_PARENT_ID})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortOrder", "asc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_inventory()))
            .expect(1)
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                integration_policy: true,
                integration_policy_parent: true,
                ..integration_cleanup_ownership()
            },
        };

        session
            .cleanup_integration_resources()
            .await
            .expect("owned marker resources must clean up");

        assert!(!session.ownership.integration_policy);
        assert!(!session.ownership.integration_policy_parent);
        let requests = server.received_requests().await.expect("requests");
        let delete_paths: Vec<_> = requests
            .iter()
            .filter(|request| matches!(request.method.as_str(), "DELETE" | "POST"))
            .map(|request| (request.method.as_str(), request.url.path().to_string()))
            .collect();
        assert_eq!(
            delete_paths,
            vec![
                (
                    "DELETE",
                    format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}")
                ),
                ("POST", "/api/fleet/agent_policies/delete".to_string()),
            ]
        );
        assert!(requests.iter().all(|request| {
            !request.url.query_pairs().any(|(key, _)| key == "force")
                && !String::from_utf8_lossy(&request.body).contains("force")
        }));
        assert!(
            requests
                .iter()
                .all(|request| { request.url.path() != "/api/fleet/epm/packages/system/2.0.0" })
        );
    }

    #[tokio::test]
    async fn integration_cleanup_refuses_a_changed_package_version_without_delete() {
        let server = MockServer::start().await;
        let mut changed = marker_integration_response(INTEGRATION_POLICY_DESCRIPTION);
        changed["item"]["package"]["version"] = json!("2.0.1");
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(changed))
            .expect(1)
            .mount(&server)
            .await;

        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                integration_policy: true,
                ..integration_cleanup_ownership()
            },
        };

        assert!(
            session.cleanup_integration_resources().await.is_err(),
            "a changed package version must remain for investigation"
        );
        assert!(session.ownership.integration_policy);
        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().all(|request| {
            !(request.method.as_str() == "DELETE"
                && request.url.path()
                    == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"))
        }));
    }

    #[tokio::test]
    async fn integration_cleanup_refuses_a_swapped_integration_without_delete() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
                "id": INTEGRATION_POLICY_ID,
                "name": INTEGRATION_POLICY_NAME,
                "namespace": "default",
                "description": "swapped integration policy",
                "policy_ids": [INTEGRATION_POLICY_PARENT_ID],
                "package": {"name": "system", "version": "2.0.0"},
                "inputs": {"untrusted": true}
            }})))
            .expect(1)
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                integration_policy: true,
                ..integration_cleanup_ownership()
            },
        };

        let error = session
            .cleanup_integration_resources()
            .await
            .expect_err("a swapped resource must remain owned for investigation");

        assert!(error.message.contains("marker identity no longer matches"));
        assert!(session.ownership.integration_policy);
        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().all(|request| {
            !(request.method.as_str() == "DELETE"
                && request.url.path()
                    == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"))
        }));
    }

    #[tokio::test]
    async fn integration_cleanup_refuses_a_swapped_parent_without_parent_delete() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
                "id": INTEGRATION_POLICY_PARENT_ID,
                "name": INTEGRATION_POLICY_PARENT_NAME,
                "namespace": "default",
                "description": "swapped integration policy parent",
                "monitoring_enabled": ["logs"],
                "inactivity_timeout": 60
            }})))
            .expect(1)
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership {
                integration_policy_parent: true,
                integration_recording_nonce: Some(TEST_INTEGRATION_RECORDING_NONCE.to_string()),
                ..Default::default()
            },
        };

        let error = session
            .cleanup_integration_resources()
            .await
            .expect_err("a swapped parent must remain owned for investigation");

        assert!(error.message.contains("marker identity no longer matches"));
        assert!(session.ownership.integration_policy_parent);
        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().all(|request| {
            !(request.method.as_str() == "POST"
                && request.url.path() == "/api/fleet/agent_policies/delete")
        }));
    }

    #[tokio::test]
    async fn integration_cleanup_rejects_nonportable_marker_state_without_delete() {
        for (label, fields) in unsafe_marker_integration_fields() {
            let server = MockServer::start().await;
            let mut response = marker_integration_response(INTEGRATION_POLICY_DESCRIPTION);
            merge_marker_item_fields(&mut response, &fields);
            Mock::given(method("GET"))
                .and(path(format!(
                    "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
                )))
                .and(query_param("format", "simplified"))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&server)
                .await;
            let transport = mock_transport(&server);
            let mut session = RecordingSession {
                transport: &transport,
                ownership: CleanupOwnership {
                    integration_policy: true,
                    ..integration_cleanup_ownership()
                },
            };

            let error = session
                .cleanup_integration_resources()
                .await
                .expect_err("a changed integration must remain for investigation");
            assert!(
                !error.message.contains("foreign"),
                "{label} cleanup error leaked injected state"
            );
            assert!(
                session.ownership.integration_policy,
                "{label} retained ownership"
            );
            let requests = server.received_requests().await.expect("requests");
            assert!(
                requests.iter().all(|request| {
                    !(request.method.as_str() == "DELETE"
                        && request.url.path()
                            == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"))
                }),
                "{label} must not be deleted during cleanup"
            );
        }
    }

    #[tokio::test]
    async fn parent_cleanup_rejects_nonportable_marker_state_without_delete() {
        for (label, fields) in unsafe_marker_parent_fields() {
            let server = MockServer::start().await;
            let mut response = marker_integration_parent_response();
            response["item"]["package_policies"] = json!([]);
            merge_marker_item_fields(&mut response, &fields);
            Mock::given(method("GET"))
                .and(path(format!(
                    "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&server)
                .await;
            let transport = mock_transport(&server);
            let mut session = RecordingSession {
                transport: &transport,
                ownership: CleanupOwnership {
                    integration_policy_parent: true,
                    integration_recording_nonce: Some(TEST_INTEGRATION_RECORDING_NONCE.to_string()),
                    ..Default::default()
                },
            };

            let error = session
                .cleanup_integration_resources()
                .await
                .expect_err("a changed parent must remain for investigation");
            assert!(
                !error.message.contains("foreign"),
                "{label} cleanup error leaked injected state"
            );
            assert!(
                session.ownership.integration_policy_parent,
                "{label} retained ownership"
            );
            let requests = server.received_requests().await.expect("requests");
            assert!(
                requests.iter().all(|request| {
                    !(request.method.as_str() == "POST"
                        && request.url.path() == "/api/fleet/agent_policies/delete")
                }),
                "{label} must not be deleted during cleanup"
            );
        }
    }

    #[tokio::test]
    async fn cleanup_rejects_root_item_envelopes_without_mutation() {
        let integration_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                marker_integration_response(INTEGRATION_POLICY_DESCRIPTION)["item"].clone(),
            ))
            .expect(1)
            .mount(&integration_server)
            .await;
        let integration_transport = mock_transport(&integration_server);
        let mut integration_session = RecordingSession {
            transport: &integration_transport,
            ownership: CleanupOwnership {
                integration_policy: true,
                ..integration_cleanup_ownership()
            },
        };

        integration_session
            .cleanup_integration_resources()
            .await
            .expect_err("a root integration response cannot authorize cleanup");
        let integration_requests = integration_server
            .received_requests()
            .await
            .expect("integration requests");
        assert!(integration_requests.iter().all(|request| {
            !(request.method.as_str() == "DELETE"
                && request.url.path()
                    == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"))
        }));

        let parent_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(marker_integration_parent_response()["item"].clone()),
            )
            .expect(1)
            .mount(&parent_server)
            .await;
        let parent_transport = mock_transport(&parent_server);
        let mut parent_session = RecordingSession {
            transport: &parent_transport,
            ownership: CleanupOwnership {
                integration_policy_parent: true,
                integration_recording_nonce: Some(TEST_INTEGRATION_RECORDING_NONCE.to_string()),
                ..Default::default()
            },
        };

        parent_session
            .cleanup_integration_resources()
            .await
            .expect_err("a root parent response cannot authorize cleanup");
        let parent_requests = parent_server
            .received_requests()
            .await
            .expect("parent requests");
        assert!(parent_requests.iter().all(|request| {
            !(request.method.as_str() == "POST"
                && request.url.path() == "/api/fleet/agent_policies/delete")
        }));
    }
}
