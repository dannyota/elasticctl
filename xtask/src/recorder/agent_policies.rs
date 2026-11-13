use crate::diagnostics::{record_trace, recording_error};
use crate::fixtures::{
    RecordedFixture, Recording, error_fixture, exchange_fixture, response_fixture,
};
use crate::recorder::markers::{
    AGENT_POLICY_DUP_ID, AGENT_POLICY_FIXTURE_TIMESTAMP, AGENT_POLICY_ID, AGENT_POLICY_NAME,
};
use crate::recorder::session::RecordingSession;
use crate::scrub::redact;
use elasticctl_core::urlencode;
use serde_json::{Value, json};

fn scrub_agent_policy(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("version");
            if let Some(Value::Array(spaces)) = map.get_mut("space_ids") {
                spaces.retain(|space| space.as_str() == Some("default"));
            }
            for key in ["created_by", "updated_by"] {
                if let Some(identity) = map.get_mut(key) {
                    redact(identity);
                }
            }
            for key in ["created_at", "updated_at"] {
                if let Some(timestamp) = map.get_mut(key)
                    && timestamp.is_string()
                {
                    *timestamp = json!(AGENT_POLICY_FIXTURE_TIMESTAMP);
                }
            }
            for v in map.values_mut() {
                scrub_agent_policy(v);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(scrub_agent_policy),
        _ => {}
    }
}

fn agent_policy_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    mut body: Value,
) -> RecordedFixture {
    scrub_agent_policy(&mut body);
    response_fixture(name, flavor, version, body, None)
}

fn agent_policy_exchange_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    mut request: Value,
    mut body: Value,
) -> RecordedFixture {
    scrub_agent_policy(&mut request);
    scrub_agent_policy(&mut body);
    exchange_fixture(name, flavor, version, request, body)
}

pub(super) fn reduce_package_status_item(body: &Value) -> Option<Value> {
    let item = body.get("item")?.as_object()?;
    let installed_version = item
        .get("installationInfo")
        .and_then(Value::as_object)
        .and_then(|info| info.get("version"))
        .cloned();
    let mut reduced = serde_json::Map::new();
    for key in ["name", "version", "status", "latestVersion"] {
        if let Some(value) = item.get(key) {
            reduced.insert(key.to_string(), value.clone());
        }
    }
    if let Some(version) = installed_version {
        reduced.insert("installationInfo".to_string(), json!({"version": version}));
    }
    Some(Value::Object(reduced))
}

fn scope_agent_policy_list_to_marker(body: &mut Value, marker_id: &str) -> usize {
    let Some(items) = body.get_mut("items").and_then(Value::as_array_mut) else {
        return 0;
    };
    items.retain(|item| item["id"].as_str() == Some(marker_id));
    let kept = items.len();
    if let Some(map) = body.as_object_mut() {
        map.insert("total".to_string(), json!(kept));
    }
    kept
}

pub(super) async fn record_agent_policies(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    flavor: &str,
    version: &str,
) -> elasticctl_core::Result<()> {
    let t = session.transport;

    record_trace("fleet-setup");
    let mut setup = t.post("/api/fleet/setup", Some(&json!({}))).await?;
    if setup["isInitialized"].as_bool() != Some(true) {
        return Err(recording_error(
            "fleet setup did not report isInitialized: true",
        ));
    }
    if let Some(errors) = setup
        .get_mut("nonFatalErrors")
        .and_then(Value::as_array_mut)
    {
        for entry in errors.iter_mut() {
            if let Some(message) = entry.get_mut("message") {
                *message = json!("redacted");
            }
        }
    }
    recording.fixtures.push(response_fixture(
        "fleet_setup",
        flavor,
        version,
        setup,
        None,
    ));

    record_trace("fleet-agent-policy-preflight");
    match t
        .get(&format!(
            "/api/fleet/agent_policies/{}",
            urlencode(AGENT_POLICY_ID)
        ))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
            recording.fixtures.push(error_fixture(
                "agent_policy_not_found",
                flavor,
                version,
                error,
            ));
        }
        Ok(_) => {
            return Err(recording_error(format!(
                "refusing to record: agent policy {AGENT_POLICY_ID} already exists and is not cleanup-owned"
            )));
        }
        Err(error) => return Err(error),
    }

    record_trace("fleet-package-status");
    let package = t.get("/api/fleet/epm/packages/elastic_agent").await?;
    let reduced_package = reduce_package_status_item(&package).ok_or_else(|| {
        recording_error(
            "refusing to record: package status for elastic_agent did not carry a reducible item",
        )
    })?;
    recording.fixtures.push(response_fixture(
        "package_elastic_agent",
        flavor,
        version,
        json!({"item": reduced_package}),
        None,
    ));

    session.ownership.agent_policy = true;
    let create_body = json!({
        "id": AGENT_POLICY_ID,
        "name": AGENT_POLICY_NAME,
        "namespace": "default",
        "description": "elasticctl sample agent policy",
        "monitoring_enabled": [],
        "inactivity_timeout": 1_209_600
    });
    record_trace("fleet-agent-policy-create");
    let created = t
        .post(
            "/api/fleet/agent_policies?sys_monitoring=false",
            Some(&create_body),
        )
        .await?;
    record_trace("fleet-agent-policy-create-check");
    if created["item"]["id"].as_str() != Some(AGENT_POLICY_ID) {
        return Err(recording_error(
            "agent policy create did not preserve the marker id",
        ));
    }
    let mut dup_body = create_body.clone();
    dup_body["id"] = json!(AGENT_POLICY_DUP_ID);
    recording.fixtures.push(agent_policy_exchange_fixture(
        "agent_policy_create",
        flavor,
        version,
        create_body,
        created,
    ));

    record_trace("fleet-agent-policy-get");
    let got = t
        .get(&format!(
            "/api/fleet/agent_policies/{}",
            urlencode(AGENT_POLICY_ID)
        ))
        .await?;
    if got["item"]["agents"].as_u64().is_none() || !got["item"]["package_policies"].is_array() {
        return Err(recording_error(
            "agent policy get did not return an agents count and a package_policies array",
        ));
    }
    recording.fixtures.push(agent_policy_fixture(
        "agent_policy_get",
        flavor,
        version,
        got,
    ));

    record_trace("fleet-agent-policy-list");
    let mut listed = t
        .get("/api/fleet/agent_policies?page=1&perPage=1000&sortField=created_at&sortOrder=asc")
        .await?;
    record_trace("fleet-agent-policy-list-check");
    if scope_agent_policy_list_to_marker(&mut listed, AGENT_POLICY_ID) != 1 {
        return Err(recording_error(
            "agent policy list never contained the marker item",
        ));
    }
    recording.fixtures.push(agent_policy_fixture(
        "agent_policies_list",
        flavor,
        version,
        listed,
    ));

    session.ownership.agent_policy_dup = true;
    record_trace("fleet-agent-policy-name-conflict");
    match t
        .post(
            "/api/fleet/agent_policies?sys_monitoring=false",
            Some(&dup_body),
        )
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::Conflict => {
            recording.fixtures.push(error_fixture(
                "agent_policy_name_conflict",
                flavor,
                version,
                error,
            ));
        }
        Ok(_) => {
            return Err(recording_error(
                "duplicate agent-policy name did not conflict",
            ));
        }
        Err(error) => return Err(error),
    }
    record_trace("fleet-agent-policy-name-conflict-check");
    match t
        .get(&format!(
            "/api/fleet/agent_policies/{}",
            urlencode(AGENT_POLICY_DUP_ID)
        ))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
            session.ownership.agent_policy_dup = false;
        }
        Ok(_) => {
            return Err(recording_error(format!(
                "agent policy {AGENT_POLICY_DUP_ID} exists after a conflicting create; cleanup will remove it and recording fails"
            )));
        }
        Err(error) => return Err(error),
    }

    let update_body = json!({
        "name": AGENT_POLICY_NAME,
        "namespace": "default",
        "description": "elasticctl sample agent policy updated",
        "monitoring_enabled": [],
        "inactivity_timeout": 1_209_600,
        "unenroll_timeout": 3600
    });
    record_trace("fleet-agent-policy-update");
    let updated = t
        .put(
            &format!("/api/fleet/agent_policies/{}", urlencode(AGENT_POLICY_ID)),
            &update_body,
        )
        .await?;
    record_trace("fleet-agent-policy-update-check");
    if updated["item"]["unenroll_timeout"].as_u64() != Some(3600) {
        return Err(recording_error(
            "agent policy update did not persist unenroll_timeout",
        ));
    }
    recording.fixtures.push(agent_policy_exchange_fixture(
        "agent_policy_update",
        flavor,
        version,
        update_body,
        updated,
    ));

    let update_omitted_body = json!({
        "name": AGENT_POLICY_NAME,
        "namespace": "default",
        "description": "elasticctl sample agent policy omitted",
        "monitoring_enabled": [],
        "inactivity_timeout": 1_209_600
    });
    record_trace("fleet-agent-policy-update-omitted");
    let updated_omitted = t
        .put(
            &format!("/api/fleet/agent_policies/{}", urlencode(AGENT_POLICY_ID)),
            &update_omitted_body,
        )
        .await?;
    recording.fixtures.push(agent_policy_exchange_fixture(
        "agent_policy_update_omitted",
        flavor,
        version,
        update_omitted_body,
        updated_omitted,
    ));

    record_trace("fleet-agent-policy-get-after-omit");
    let got_after_omit = t
        .get(&format!(
            "/api/fleet/agent_policies/{}",
            urlencode(AGENT_POLICY_ID)
        ))
        .await?;
    recording.fixtures.push(agent_policy_fixture(
        "agent_policy_get_after_omit",
        flavor,
        version,
        got_after_omit,
    ));

    let delete_body = json!({"agentPolicyId": AGENT_POLICY_ID});
    record_trace("fleet-agent-policy-delete");
    let deleted = t
        .post("/api/fleet/agent_policies/delete", Some(&delete_body))
        .await?;
    if deleted["id"].as_str() != Some(AGENT_POLICY_ID) {
        return Err(recording_error(
            "agent policy delete did not report the marker id",
        ));
    }
    recording.fixtures.push(agent_policy_fixture(
        "agent_policy_delete",
        flavor,
        version,
        deleted,
    ));

    record_trace("fleet-agent-policy-delete-check");
    match t
        .get(&format!(
            "/api/fleet/agent_policies/{}",
            urlencode(AGENT_POLICY_ID)
        ))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
            recording.fixtures.push(error_fixture(
                "agent_policy_delete_not_found",
                flavor,
                version,
                error,
            ));
            session.ownership.agent_policy = false;
        }
        Ok(_) => {
            return Err(recording_error(format!(
                "agent policy {AGENT_POLICY_ID} still exists after delete"
            )));
        }
        Err(error) => return Err(error),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::markers::{
        AGENT_POLICY_FIXTURE_TIMESTAMP, AGENT_POLICY_ID, AGENT_POLICY_NAME,
    };
    use serde_json::json;

    #[test]
    fn scrub_agent_policy_replaces_identity_and_timestamps_and_drops_opaque_fields() {
        let mut value = json!({
            "item": {
                "id": AGENT_POLICY_ID,
                "name": AGENT_POLICY_NAME,
                "namespace": "default",
                "description": "elasticctl sample agent policy",
                "monitoring_enabled": [],
                "inactivity_timeout": 1_209_600,
                "version": "opaque-version-token",
                "created_at": "2026-09-01T00:00:00.000Z",
                "updated_at": "2026-09-01T00:01:00.000Z",
                "created_by": "elastic",
                "updated_by": "elastic",
                "space_ids": ["default", "other-space"]
            }
        });

        scrub_agent_policy(&mut value);

        assert_eq!(
            value,
            json!({
                "item": {
                    "id": AGENT_POLICY_ID,
                    "name": AGENT_POLICY_NAME,
                    "namespace": "default",
                    "description": "elasticctl sample agent policy",
                    "monitoring_enabled": [],
                    "inactivity_timeout": 1_209_600,
                    "created_at": AGENT_POLICY_FIXTURE_TIMESTAMP,
                    "updated_at": AGENT_POLICY_FIXTURE_TIMESTAMP,
                    "created_by": "REDACTED",
                    "updated_by": "REDACTED",
                    "space_ids": ["default"]
                }
            })
        );
    }

    #[test]
    fn scope_agent_policy_list_to_marker_keeps_only_the_marker_item_and_rewrites_total() {
        let mut value = json!({
            "items": [
                {"id": "some-other-policy", "name": "prod"},
                {"id": AGENT_POLICY_ID, "name": AGENT_POLICY_NAME},
                {"id": "yet-another-policy", "name": "staging"}
            ],
            "total": 2066,
            "page": 1,
            "perPage": 1000
        });

        let kept = scope_agent_policy_list_to_marker(&mut value, AGENT_POLICY_ID);

        assert_eq!(kept, 1);
        assert_eq!(
            value,
            json!({
                "items": [{"id": AGENT_POLICY_ID, "name": AGENT_POLICY_NAME}],
                "total": 1,
                "page": 1,
                "perPage": 1000
            })
        );
    }

    #[test]
    fn scope_agent_policy_list_to_marker_returns_zero_when_the_marker_was_never_present() {
        let mut value = json!({
            "items": [{"id": "some-other-policy", "name": "prod"}],
            "total": 1
        });

        let kept = scope_agent_policy_list_to_marker(&mut value, AGENT_POLICY_ID);

        assert_eq!(kept, 0);
        assert_eq!(value["total"], 0);
        assert_eq!(value["items"], json!([]));
    }

    #[test]
    fn reduce_package_status_item_keeps_only_the_allowlisted_fields() {
        let body = json!({
            "item": {
                "name": "elastic_agent",
                "version": "9.5.1",
                "status": "installed",
                "latestVersion": "9.5.2",
                "readme": "/package/elastic_agent/9.5.1/docs/README.md",
                "assets": [{"id": "elastic_agent-9.5.1", "type": "epm-packages"}],
                "data_streams": [{"type": "logs", "dataset": "elastic_agent"}],
                "owner": {"github": "elastic/fleet"},
                "conditions": {"kibana": {"version": "^9.5.1"}},
                "installationInfo": {
                    "version": "9.5.1",
                    "installed_kibana": [{"id": "logs-elastic_agent", "type": "index-template"}],
                    "installed_es": [{"id": "logs-elastic_agent", "type": "ingest_pipeline"}],
                    "installed_kibana_space_id": "default",
                    "created_at": "2026-09-01T00:00:00.000Z",
                    "updated_at": "2026-09-01T00:01:00.000Z",
                    "verification_key_id": "opaque-key-id"
                }
            },
            "metadata": {"has_policies": true}
        });

        let reduced = reduce_package_status_item(&body).expect("item is present and reducible");

        assert_eq!(
            reduced,
            json!({
                "name": "elastic_agent",
                "version": "9.5.1",
                "status": "installed",
                "latestVersion": "9.5.2",
                "installationInfo": {"version": "9.5.1"}
            })
        );
    }

    #[test]
    fn reduce_package_status_item_refuses_a_body_without_a_reducible_item() {
        assert!(reduce_package_status_item(&json!({"metadata": {"has_policies": true}})).is_none());
        assert!(reduce_package_status_item(&json!({"item": "not-an-object"})).is_none());
        assert!(reduce_package_status_item(&json!({})).is_none());
    }

    #[test]
    fn reduce_package_status_item_recorded_envelope_carries_only_item() {
        let body = json!({
            "item": {"name": "elastic_agent", "status": "not_installed"},
            "metadata": {"has_policies": false, "keepPoliciesUpToDate": true}
        });

        let reduced = reduce_package_status_item(&body).expect("item is present and reducible");
        let recorded = json!({"item": reduced});

        assert_eq!(
            recorded,
            json!({"item": {"name": "elastic_agent", "status": "not_installed"}})
        );
        assert_eq!(
            recorded.as_object().unwrap().keys().collect::<Vec<_>>(),
            vec!["item"]
        );
    }
}
