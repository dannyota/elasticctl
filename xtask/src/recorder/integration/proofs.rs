use crate::diagnostics::{recording_error, safe_recording_transport_error};
#[cfg(test)]
use crate::recorder::markers::TEST_INTEGRATION_RECORDING_NONCE;
use crate::recorder::markers::{
    INTEGRATION_POLICY_ID, INTEGRATION_POLICY_NAME, INTEGRATION_POLICY_NAMESPACE,
    INTEGRATION_POLICY_PACKAGE, INTEGRATION_POLICY_PARENT_ID,
    INTEGRATION_POLICY_PARENT_INACTIVITY_TIMEOUT, INTEGRATION_POLICY_PARENT_NAME,
};
use crate::recorder::markers::{
    marker_integration_description, marker_integration_parent_description,
    marker_integration_updated_description,
};
use elasticctl_core::urlencode;
use serde_json::{Map, Value};

fn integration_response_item(
    value: &Value,
) -> elasticctl_core::Result<&serde_json::Map<String, Value>> {
    value
        .get("item")
        .and_then(Value::as_object)
        .ok_or_else(|| recording_error("integration policy response must contain an item object"))
}

fn is_optional_false(item: &serde_json::Map<String, Value>, fields: &[&str]) -> bool {
    fields.iter().all(|field| {
        matches!(
            item.get(*field),
            None | Some(Value::Null) | Some(Value::Bool(false))
        )
    })
}

fn is_optional_null(item: &serde_json::Map<String, Value>, fields: &[&str]) -> bool {
    fields
        .iter()
        .all(|field| matches!(item.get(*field), None | Some(Value::Null)))
}

fn is_optional_empty_object(item: &serde_json::Map<String, Value>, fields: &[&str]) -> bool {
    fields.iter().all(|field| match item.get(*field) {
        None | Some(Value::Null) => true,
        Some(Value::Object(values)) => values.is_empty(),
        Some(_) => false,
    })
}

fn is_optional_empty_array(item: &serde_json::Map<String, Value>, fields: &[&str]) -> bool {
    fields.iter().all(|field| match item.get(*field) {
        None | Some(Value::Null) => true,
        Some(Value::Array(values)) => values.is_empty(),
        Some(_) => false,
    })
}

fn is_optional_empty_string(item: &serde_json::Map<String, Value>, field: &str) -> bool {
    match item.get(field) {
        None | Some(Value::Null) => true,
        Some(Value::String(value)) => value.is_empty(),
        Some(_) => false,
    }
}

fn normalized_active_space(active_space: &str) -> &str {
    if active_space.is_empty() {
        "default"
    } else {
        active_space
    }
}

fn has_only_active_spaces(
    item: &serde_json::Map<String, Value>,
    fields: &[&str],
    active_space: &str,
) -> bool {
    let active_space = normalized_active_space(active_space);
    fields.iter().all(|field| match item.get(*field) {
        None | Some(Value::Null) => true,
        Some(Value::Array(spaces)) => spaces
            .iter()
            .all(|space| space.as_str() == Some(active_space)),
        Some(_) => false,
    })
}

fn marker_integration_package_matches(
    item: &serde_json::Map<String, Value>,
    expected_version: &str,
) -> bool {
    !expected_version.trim().is_empty()
        && item
            .get("package")
            .and_then(Value::as_object)
            .is_some_and(|package| {
                package.get("name").and_then(Value::as_str) == Some(INTEGRATION_POLICY_PACKAGE)
                    && package.get("version").and_then(Value::as_str) == Some(expected_version)
            })
}

#[derive(Clone, Copy)]
pub(crate) enum MarkerIntegrationInputs<'a> {
    Empty,
    Exact(&'a Map<String, Value>),
    BootstrapObject,
}

#[derive(Clone, Copy)]
pub(crate) struct MarkerResponseExpectation<'a> {
    pub(crate) description: Option<&'a str>,
    pub(crate) inputs: MarkerIntegrationInputs<'a>,
}

#[derive(Clone, Copy)]
pub(crate) struct IntegrationFixtureContext<'a> {
    pub(crate) active_space: &'a str,
    pub(crate) nonce: &'a str,
    pub(crate) expected_inputs: &'a Map<String, Value>,
}

fn marker_integration_inputs_match(
    item: &Map<String, Value>,
    expected: MarkerIntegrationInputs<'_>,
) -> bool {
    let Some(inputs) = item.get("inputs").and_then(Value::as_object) else {
        return false;
    };
    match expected {
        MarkerIntegrationInputs::Empty => inputs.is_empty(),
        MarkerIntegrationInputs::Exact(expected) => inputs == expected,
        MarkerIntegrationInputs::BootstrapObject => true,
    }
}

pub(crate) fn validate_marker_integration_item_with_nonce_and_inputs(
    item: &Map<String, Value>,
    id: &str,
    expected_version: &str,
    active_space: &str,
    nonce: &str,
    expected_description: Option<&str>,
    expected_inputs: MarkerIntegrationInputs<'_>,
) -> elasticctl_core::Result<()> {
    let created_description = marker_integration_description(nonce);
    let updated_description = marker_integration_updated_description(nonce);
    let description_matches = match expected_description {
        Some(expected) => {
            (expected == created_description.as_str() || expected == updated_description.as_str())
                && item.get("description").and_then(Value::as_str) == Some(expected)
        }
        None => matches!(
            item.get("description").and_then(Value::as_str),
            Some(description)
                if description == created_description || description == updated_description
        ),
    };
    let identity_matches = item.get("id").and_then(Value::as_str) == Some(id)
        && item.get("name").and_then(Value::as_str) == Some(INTEGRATION_POLICY_NAME)
        && item.get("namespace").and_then(Value::as_str) == Some(INTEGRATION_POLICY_NAMESPACE)
        && !nonce.trim().is_empty()
        && description_matches
        && item
            .get("policy_ids")
            .and_then(Value::as_array)
            .is_some_and(|ids| {
                ids.len() == 1 && ids[0].as_str() == Some(INTEGRATION_POLICY_PARENT_ID)
            })
        && match item.get("policy_id") {
            None | Some(Value::Null) => true,
            Some(Value::String(id)) => id == INTEGRATION_POLICY_PARENT_ID,
            Some(_) => false,
        }
        && marker_integration_package_matches(item, expected_version)
        && marker_integration_inputs_match(item, expected_inputs)
        && item.get("enabled").and_then(Value::as_bool) == Some(true)
        && is_optional_false(
            item,
            &[
                "is_managed",
                "supports_agentless",
                "supports_cloud_connector",
            ],
        )
        && is_optional_false(
            item,
            &["output_id", "cloud_connector_id", "cloud_connector_name"],
        )
        && is_optional_empty_array(item, &["secret_references"])
        && has_only_active_spaces(item, &["spaceIds", "space_ids"], active_space)
        && is_optional_empty_object(item, &["vars", "var_group_selections"])
        && is_optional_empty_string(item, "condition")
        && is_optional_empty_array(
            item,
            &["additional_datastreams_permissions", "global_data_tags"],
        );
    if identity_matches {
        Ok(())
    } else {
        Err(recording_error(
            "integration policy response did not preserve the marker identity",
        ))
    }
}

pub(crate) fn validate_marker_integration_with_nonce_and_inputs<'a>(
    value: &'a Value,
    id: &str,
    expected_version: &str,
    active_space: &str,
    nonce: &str,
    expected_description: Option<&str>,
    expected_inputs: MarkerIntegrationInputs<'_>,
) -> elasticctl_core::Result<&'a Map<String, Value>> {
    let item = integration_response_item(value)?;
    validate_marker_integration_item_with_nonce_and_inputs(
        item,
        id,
        expected_version,
        active_space,
        nonce,
        expected_description,
        expected_inputs,
    )?;
    Ok(item)
}

pub(crate) fn validate_marker_integration_parent_identity_with_nonce<'a>(
    value: &'a Value,
    active_space: &str,
    nonce: &str,
) -> elasticctl_core::Result<&'a serde_json::Map<String, Value>> {
    let item = integration_response_item(value).map_err(|_| {
        recording_error("integration policy parent response must contain an item object")
    })?;
    let identity_matches = item.get("id").and_then(Value::as_str)
        == Some(INTEGRATION_POLICY_PARENT_ID)
        && item.get("name").and_then(Value::as_str) == Some(INTEGRATION_POLICY_PARENT_NAME)
        && item.get("namespace").and_then(Value::as_str) == Some(INTEGRATION_POLICY_NAMESPACE)
        && item.get("description").and_then(Value::as_str)
            == Some(marker_integration_parent_description(nonce).as_str())
        && !nonce.trim().is_empty()
        && item
            .get("monitoring_enabled")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        && item.get("inactivity_timeout").and_then(Value::as_u64)
            == Some(INTEGRATION_POLICY_PARENT_INACTIVITY_TIMEOUT)
        && is_optional_false(
            item,
            &[
                "is_default",
                "is_default_fleet_server",
                "has_fleet_server",
                "is_managed",
                "is_preconfigured",
                "supports_agentless",
                "is_verifier",
                "is_protected",
            ],
        )
        && is_optional_null(item, &["agentless"])
        && is_optional_null(
            item,
            &[
                "data_output_id",
                "monitoring_output_id",
                "download_source_id",
                "fleet_server_host_id",
                "required_versions",
            ],
        )
        && has_only_active_spaces(item, &["space_ids", "spaceIds"], active_space)
        && is_optional_empty_array(item, &["agent_features", "global_data_tags"])
        && is_optional_empty_object(
            item,
            &[
                "advanced_settings",
                "overrides",
                "monitoring_http",
                "monitoring_diagnostics",
            ],
        )
        && is_optional_false(item, &["keep_monitoring_alive", "monitoring_pprof_enabled"])
        && is_optional_null(item, &["unenroll_timeout"]);
    if identity_matches {
        Ok(item)
    } else {
        Err(recording_error(
            "integration policy parent did not preserve the marker identity",
        ))
    }
}

pub(crate) fn validate_marker_integration_parent_for_delete_with_nonce<'a>(
    value: &'a Value,
    active_space: &str,
    nonce: &str,
) -> elasticctl_core::Result<&'a serde_json::Map<String, Value>> {
    let item = validate_marker_integration_parent_identity_with_nonce(value, active_space, nonce)?;
    if item.get("agents").and_then(Value::as_u64) == Some(0) {
        Ok(item)
    } else {
        Err(recording_error(
            "integration policy parent did not preserve the marker identity",
        ))
    }
}

#[cfg(test)]
fn require_marker_integration_response_with_nonce(
    body: &Value,
    expected_version: &str,
    active_space: &str,
    nonce: &str,
    expected_description: Option<&str>,
    context: &str,
) -> elasticctl_core::Result<()> {
    require_marker_integration_response_with_nonce_and_inputs(
        body,
        expected_version,
        active_space,
        nonce,
        expected_description,
        MarkerIntegrationInputs::Empty,
        context,
    )
}

pub(crate) fn require_marker_integration_response_with_nonce_and_inputs(
    body: &Value,
    expected_version: &str,
    active_space: &str,
    nonce: &str,
    expected_description: Option<&str>,
    expected_inputs: MarkerIntegrationInputs<'_>,
    context: &str,
) -> elasticctl_core::Result<()> {
    require_marker_integration_response_for_id_with_nonce_and_inputs(
        body,
        INTEGRATION_POLICY_ID,
        expected_version,
        active_space,
        nonce,
        MarkerResponseExpectation {
            description: expected_description,
            inputs: expected_inputs,
        },
        context,
    )
}

pub(crate) fn require_marker_integration_response_for_id_with_nonce_and_inputs(
    body: &Value,
    expected_id: &str,
    expected_version: &str,
    active_space: &str,
    nonce: &str,
    expectation: MarkerResponseExpectation<'_>,
    context: &str,
) -> elasticctl_core::Result<()> {
    let MarkerResponseExpectation {
        description: expected_description,
        inputs: expected_inputs,
    } = expectation;
    if validate_marker_integration_with_nonce_and_inputs(
        body,
        expected_id,
        expected_version,
        active_space,
        nonce,
        expected_description,
        expected_inputs,
    )
    .is_err()
    {
        return Err(recording_error(format!(
            "{context}: integration response did not preserve the marker identity"
        )));
    }
    Ok(())
}

pub(crate) fn require_parent_attachments_with_nonce(
    body: &Value,
    expected: &[&str],
    active_space: &str,
    nonce: &str,
    context: &'static str,
) -> elasticctl_core::Result<()> {
    let item =
        match validate_marker_integration_parent_for_delete_with_nonce(body, active_space, nonce) {
            Ok(item) => item,
            Err(_) => {
                return Err(recording_error(format!(
                    "{context}: integration parent did not preserve the marker identity"
                )));
            }
        };
    let attachments = match item.get("package_policies").and_then(Value::as_array) {
        Some(attachments) => attachments,
        None => {
            return Err(recording_error(format!(
                "{context}: integration parent did not contain package_policies"
            )));
        }
    };
    let mut ids = Vec::with_capacity(attachments.len());
    for attachment in attachments {
        let id = attachment
            .as_str()
            .or_else(|| attachment.get("id").and_then(Value::as_str))
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| {
                recording_error(format!(
                    "{context}: integration parent contained a malformed package policy attachment"
                ))
            })?;
        ids.push(id);
    }
    let mut expected = expected.to_vec();
    ids.sort_unstable();
    expected.sort_unstable();
    if ids != expected {
        return Err(recording_error(format!(
            "{context}: integration parent did not contain the expected marker attachments"
        )));
    }
    Ok(())
}

pub(crate) fn require_parent_attachment_with_nonce(
    body: &Value,
    active_space: &str,
    nonce: &str,
) -> elasticctl_core::Result<()> {
    require_parent_attachments_with_nonce(
        body,
        &[INTEGRATION_POLICY_ID],
        active_space,
        nonce,
        "integration parent get",
    )
}

pub(crate) async fn reread_marker_integration_before_mutation_with_nonce_and_inputs(
    t: &elasticctl_core::Transport,
    expected_version: &str,
    nonce: &str,
    expected_inputs: MarkerIntegrationInputs<'_>,
    context: &'static str,
) -> elasticctl_core::Result<()> {
    let body = t
        .get(&format!(
            "/api/fleet/package_policies/{}?format=simplified",
            urlencode(INTEGRATION_POLICY_ID)
        ))
        .await
        .map_err(|error| safe_recording_transport_error(context, error))?;
    require_marker_integration_response_with_nonce_and_inputs(
        &body,
        expected_version,
        t.space(),
        nonce,
        None,
        expected_inputs,
        context,
    )
}

pub(crate) async fn reread_marker_parent_before_mutation_with_nonce(
    t: &elasticctl_core::Transport,
    expected_attachments: &[&str],
    nonce: &str,
    context: &'static str,
) -> elasticctl_core::Result<()> {
    let body = t
        .get(&format!(
            "/api/fleet/agent_policies/{}",
            urlencode(INTEGRATION_POLICY_PARENT_ID)
        ))
        .await
        .map_err(|error| safe_recording_transport_error(context, error))?;
    require_parent_attachments_with_nonce(&body, expected_attachments, t.space(), nonce, context)
}

#[cfg(test)]
fn require_marker_integration_response(
    body: &Value,
    expected_version: &str,
    active_space: &str,
    context: &str,
) -> elasticctl_core::Result<()> {
    require_marker_integration_response_with_nonce(
        body,
        expected_version,
        active_space,
        TEST_INTEGRATION_RECORDING_NONCE,
        None,
        context,
    )
}

#[cfg(test)]
fn require_parent_attachments(
    body: &Value,
    expected: &[&str],
    active_space: &str,
    context: &'static str,
) -> elasticctl_core::Result<()> {
    require_parent_attachments_with_nonce(
        body,
        expected,
        active_space,
        TEST_INTEGRATION_RECORDING_NONCE,
        context,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::integration::fixtures::integration_policy_fixture;
    use crate::recorder::markers::{INTEGRATION_POLICY_DESCRIPTION, INTEGRATION_POLICY_PARENT_ID};
    use crate::recorder::test_support::{
        marker_integration_parent_response, marker_integration_response, merge_marker_item_fields,
        unsafe_marker_integration_fields, unsafe_marker_parent_fields,
    };
    use serde_json::{Value, json};

    #[test]
    fn integration_marker_proofs_reject_every_nonportable_live_shape() {
        for (label, fields) in unsafe_marker_integration_fields() {
            let mut response = marker_integration_response(INTEGRATION_POLICY_DESCRIPTION);
            merge_marker_item_fields(&mut response, &fields);
            assert!(
                require_marker_integration_response(
                    &response,
                    "2.0.0",
                    "default",
                    "integration strict-proof regression",
                )
                .is_err(),
                "{label} must not pass an integration ownership proof"
            );
            assert!(
                integration_policy_fixture("integration_policy_get", "test", "9.6.0", response)
                    .is_err(),
                "{label} must not become a public fixture"
            );
        }
    }

    #[test]
    fn parent_marker_delete_proofs_reject_every_nonportable_live_shape() {
        for (label, fields) in unsafe_marker_parent_fields() {
            let mut response = marker_integration_parent_response();
            response["item"]["package_policies"] = json!([]);
            merge_marker_item_fields(&mut response, &fields);
            assert!(
                require_parent_attachments(
                    &response,
                    &[],
                    "default",
                    "parent strict-proof regression",
                )
                .is_err(),
                "{label} must not pass a parent delete proof"
            );
        }
    }

    #[test]
    fn strict_marker_proofs_accept_documented_empty_simplified_shapes() {
        let mut integration = marker_integration_response(INTEGRATION_POLICY_DESCRIPTION);
        merge_marker_item_fields(
            &mut integration,
            &json!({
                "is_managed": false,
                "supports_agentless": false,
                "supports_cloud_connector": false,
                "output_id": false,
                "cloud_connector_id": false,
                "cloud_connector_name": false,
                "policy_id": INTEGRATION_POLICY_PARENT_ID,
                "secret_references": [],
                "spaceIds": ["default"],
                "space_ids": null,
                "vars": {},
                "var_group_selections": {},
                "condition": "",
                "additional_datastreams_permissions": [],
                "global_data_tags": []
            }),
        );
        require_marker_integration_response(
            &integration,
            "2.0.0",
            "default",
            "integration simplified compatibility",
        )
        .expect("documented empty integration fields are safe");
        integration["item"]["output_id"] = Value::Null;
        integration["item"]["cloud_connector_id"] = Value::Null;
        integration["item"]["cloud_connector_name"] = Value::Null;
        require_marker_integration_response(
            &integration,
            "2.0.0",
            "default",
            "integration nullable simplified compatibility",
        )
        .expect("documented nullable integration fields are safe");

        let mut parent = marker_integration_parent_response();
        parent["item"]["package_policies"] = json!([]);
        merge_marker_item_fields(
            &mut parent,
            &json!({
                "is_default": false,
                "is_default_fleet_server": false,
                "has_fleet_server": false,
                "is_managed": false,
                "is_preconfigured": false,
                "supports_agentless": false,
                "is_verifier": false,
                "is_protected": false,
                "agentless": null,
                "data_output_id": null,
                "monitoring_output_id": null,
                "download_source_id": null,
                "fleet_server_host_id": null,
                "required_versions": null,
                "space_ids": ["default"],
                "global_data_tags": [],
                "agent_features": [],
                "advanced_settings": {},
                "overrides": null,
                "keep_monitoring_alive": false,
                "monitoring_pprof_enabled": false,
                "monitoring_http": {},
                "monitoring_diagnostics": null,
                "unenroll_timeout": null
            }),
        );
        require_parent_attachments(&parent, &[], "default", "parent simplified compatibility")
            .expect("documented empty parent fields are safe");
    }

    #[test]
    fn marker_space_proofs_normalize_an_empty_active_space_to_default() {
        let mut integration = marker_integration_response(INTEGRATION_POLICY_DESCRIPTION);
        integration["item"]["spaceIds"] = json!(["default"]);
        require_marker_integration_response(
            &integration,
            "2.0.0",
            "",
            "default-space integration compatibility",
        )
        .expect("an empty configured space resolves to Kibana's default space");

        let mut parent = marker_integration_parent_response();
        parent["item"]["package_policies"] = json!([]);
        parent["item"]["space_ids"] = json!(["default"]);
        require_parent_attachments(&parent, &[], "", "default-space parent compatibility")
            .expect("an empty configured space resolves to Kibana's default space");
    }

    #[test]
    fn marker_space_proofs_use_the_active_kibana_space() {
        let mut integration = marker_integration_response(INTEGRATION_POLICY_DESCRIPTION);
        integration["item"]["spaceIds"] = json!(["security"]);
        require_marker_integration_response(
            &integration,
            "2.0.0",
            "security",
            "non-default integration space",
        )
        .expect("the active non-default space is safe");
        assert!(
            require_marker_integration_response(
                &integration,
                "2.0.0",
                "default",
                "wrong integration space",
            )
            .is_err(),
            "a non-default live space is not the default space"
        );

        let mut parent = marker_integration_parent_response();
        parent["item"]["package_policies"] = json!([]);
        parent["item"]["space_ids"] = json!(["security"]);
        require_parent_attachments(&parent, &[], "security", "non-default parent space")
            .expect("the active non-default parent space is safe");
        assert!(
            require_parent_attachments(&parent, &[], "default", "wrong parent space").is_err(),
            "a non-default parent space is not the default space"
        );
    }
}
