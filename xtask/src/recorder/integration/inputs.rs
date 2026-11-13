use crate::diagnostics::recording_error;
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
use serde_json::{Map, Value, json};

pub(crate) fn marker_integration_parent_create_body_with_nonce(nonce: &str) -> Value {
    json!({
        "id": INTEGRATION_POLICY_PARENT_ID,
        "name": INTEGRATION_POLICY_PARENT_NAME,
        "namespace": INTEGRATION_POLICY_NAMESPACE,
        "description": marker_integration_parent_description(nonce),
        "monitoring_enabled": [],
        "inactivity_timeout": INTEGRATION_POLICY_PARENT_INACTIVITY_TIMEOUT,
    })
}

pub(crate) fn marker_integration_create_body_with_nonce(version: &str, nonce: &str) -> Value {
    marker_integration_create_body_with_nonce_and_inputs(version, nonce, &Map::new())
}

pub(crate) fn marker_integration_create_body_with_nonce_and_inputs(
    version: &str,
    nonce: &str,
    inputs: &Map<String, Value>,
) -> Value {
    json!({
        "id": INTEGRATION_POLICY_ID,
        "name": INTEGRATION_POLICY_NAME,
        "description": marker_integration_description(nonce),
        "namespace": INTEGRATION_POLICY_NAMESPACE,
        "policy_ids": [INTEGRATION_POLICY_PARENT_ID],
        "package": {"name": INTEGRATION_POLICY_PACKAGE, "version": version},
        "inputs": inputs,
    })
}

#[cfg(test)]
pub(crate) fn marker_integration_update_body_with_nonce(version: &str, nonce: &str) -> Value {
    marker_integration_update_body_with_nonce_and_inputs(version, nonce, &Map::new())
}

pub(crate) fn marker_integration_update_body_with_nonce_and_inputs(
    version: &str,
    nonce: &str,
    inputs: &Map<String, Value>,
) -> Value {
    let mut body = marker_integration_create_body_with_nonce_and_inputs(version, nonce, inputs);
    let object = body
        .as_object_mut()
        .expect("marker integration body is an object");
    object.remove("id");
    object.insert(
        "description".to_string(),
        json!(marker_integration_updated_description(nonce)),
    );
    body
}

fn sensitive_marker_input_field(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "secret",
        "password",
        "passphrase",
        "token",
        "credential",
        "api_key",
        "apikey",
        "private_key",
        "access_key",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

fn marker_inputs_have_sensitive_field_names(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(name, value)| {
            sensitive_marker_input_field(name) || marker_inputs_have_sensitive_field_names(value)
        }),
        Value::Array(values) => values.iter().any(marker_inputs_have_sensitive_field_names),
        _ => false,
    }
}

fn exported_marker_optional_fields_are_empty(
    spec: &elasticctl_api::fleet::integration_policies::IntegrationPolicySpec,
) -> bool {
    spec.vars.as_ref().is_none_or(Map::is_empty)
        && spec.var_group_selections.as_ref().is_none_or(Map::is_empty)
        && spec.condition.as_deref().is_none_or(str::is_empty)
        && spec
            .additional_datastreams_permissions
            .as_ref()
            .is_none_or(Vec::is_empty)
}

fn capture_exported_bootstrap_inputs(
    spec: elasticctl_api::fleet::integration_policies::IntegrationPolicySpec,
    expected_version: &str,
    nonce: &str,
    bootstrap_item: &Map<String, Value>,
    active_space: &str,
) -> elasticctl_core::Result<Map<String, Value>> {
    let expected_description = marker_integration_description(nonce);
    let identity_matches = spec.id == INTEGRATION_POLICY_ID
        && spec.name == INTEGRATION_POLICY_NAME
        && spec.namespace.as_deref() == Some(INTEGRATION_POLICY_NAMESPACE)
        && spec.policy_ids == [INTEGRATION_POLICY_PARENT_ID]
        && spec.package.name == INTEGRATION_POLICY_PACKAGE
        && spec.package.version == expected_version
        && spec.description.as_deref() == Some(expected_description.as_str())
        && !spec.inputs.is_empty()
        && exported_marker_optional_fields_are_empty(&spec);
    if !identity_matches {
        return Err(recording_error(
            "exported bootstrap integration policy did not preserve the marker identity",
        ));
    }
    if marker_inputs_have_sensitive_field_names(&Value::Object(spec.inputs.clone())) {
        return Err(recording_error(
            "exported bootstrap integration policy contained sensitive-looking input fields",
        ));
    }
    let normalized =
        elasticctl_api::fleet::integration_policy_ops::normalize(bootstrap_item, active_space)
            .map_err(|_| recording_error("normalizing bootstrap integration policy failed"))?;
    if normalized.inputs != spec.inputs {
        return Err(recording_error(
            "exported bootstrap integration policy inputs did not match the marker read",
        ));
    }
    Ok(spec.inputs)
}

pub(crate) async fn export_bootstrap_marker_inputs(
    t: &elasticctl_core::Transport,
    expected_version: &str,
    nonce: &str,
    bootstrap_item: &Map<String, Value>,
) -> elasticctl_core::Result<Map<String, Value>> {
    let selectors = vec![INTEGRATION_POLICY_ID.to_owned()];
    let exported = elasticctl_api::fleet::integration_policy_ops::export(
        t,
        &selectors,
        false,
        elasticctl_api::content_codec::ContentFormat::Json,
    )
    .await
    .map_err(|_| recording_error("exporting bootstrap integration policy failed"))?;
    let spec = decode_exported_bootstrap_marker(exported)?;
    capture_exported_bootstrap_inputs(spec, expected_version, nonce, bootstrap_item, t.space())
}

fn decode_exported_bootstrap_marker(
    exported: elasticctl_api::ops::ExportOutcome,
) -> elasticctl_core::Result<elasticctl_api::fleet::integration_policies::IntegrationPolicySpec> {
    let mut specs = elasticctl_api::content_codec::decode_sequence::<
        elasticctl_api::fleet::integration_policies::IntegrationPolicySpec,
    >(
        &exported.body,
        elasticctl_api::content_codec::ContentFormat::Json,
        "integration policy",
    )
    .map_err(|_| recording_error("decoding exported bootstrap integration policy failed"))?;
    if exported.exported != 1 || !exported.missing.is_empty() || specs.len() != 1 {
        return Err(recording_error(
            "exporting bootstrap integration policy did not return exactly one marker",
        ));
    }
    Ok(specs
        .pop()
        .expect("one exported integration policy was checked"))
}

#[cfg(test)]
pub(crate) fn marker_integration_parent_create_body() -> Value {
    marker_integration_parent_create_body_with_nonce(TEST_INTEGRATION_RECORDING_NONCE)
}

#[cfg(test)]
pub(crate) fn marker_integration_create_body(version: &str) -> Value {
    marker_integration_create_body_with_nonce(version, TEST_INTEGRATION_RECORDING_NONCE)
}

#[cfg(test)]
pub(crate) fn marker_integration_update_body(version: &str) -> Value {
    marker_integration_update_body_with_nonce(version, TEST_INTEGRATION_RECORDING_NONCE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::markers::{
        INTEGRATION_POLICY_ID, INTEGRATION_POLICY_NAME, INTEGRATION_POLICY_PARENT_ID,
        TEST_INTEGRATION_RECORDING_NONCE, marker_integration_description,
        marker_integration_updated_description,
    };
    use crate::recorder::test_support::{
        exported_marker_spec, materialized_bootstrap_item, materialized_marker_inputs,
    };
    use serde_json::{Map, json};

    #[test]
    fn marker_integration_bodies_preserve_one_session_nonce_and_response_only_omission() {
        let nonce = "one-session-nonce";
        let create = marker_integration_create_body_with_nonce("2.0.0", nonce);
        assert_eq!(create["id"], INTEGRATION_POLICY_ID);
        assert_eq!(create["name"], INTEGRATION_POLICY_NAME);
        assert_eq!(create["namespace"], "default");
        assert_eq!(create["policy_ids"], json!([INTEGRATION_POLICY_PARENT_ID]));
        assert_eq!(
            create["package"],
            json!({"name": "system", "version": "2.0.0"})
        );
        assert_eq!(create["inputs"], json!({}));
        assert_eq!(create["description"], marker_integration_description(nonce));
        assert!(create.get("force").is_none());
        assert!(create.get("enabled").is_none());
        assert!(create.get("create_dataset_templates").is_none());

        let update = marker_integration_update_body_with_nonce("2.0.0", nonce);
        assert!(update.get("id").is_none());
        assert!(update.get("enabled").is_none());
        assert_eq!(
            update["description"],
            marker_integration_updated_description(nonce),
            "the update must retain the creation session nonce"
        );
        assert!(update.get("force").is_none());
        assert!(update.get("create_dataset_templates").is_none());
    }

    #[test]
    fn bootstrap_export_capture_rejects_identity_sensitive_and_changed_input_maps_without_values() {
        let inputs = materialized_marker_inputs();
        let bootstrap_item = materialized_bootstrap_item(&inputs);

        let mut wrong_identity = exported_marker_spec(inputs.clone());
        wrong_identity.name = "other marker".to_string();
        let identity_error = capture_exported_bootstrap_inputs(
            wrong_identity,
            "2.0.0",
            TEST_INTEGRATION_RECORDING_NONCE,
            &bootstrap_item,
            "default",
        )
        .expect_err("an exported policy must retain the exact marker identity");
        assert_eq!(
            identity_error.message,
            "exported bootstrap integration policy did not preserve the marker identity"
        );

        let mut unexpected_optional = exported_marker_spec(inputs.clone());
        unexpected_optional.condition = Some("host.name == 'private-default'".to_string());
        let optional_error = capture_exported_bootstrap_inputs(
            unexpected_optional,
            "2.0.0",
            TEST_INTEGRATION_RECORDING_NONCE,
            &bootstrap_item,
            "default",
        )
        .expect_err("the exported bootstrap must not carry configuration outside its map");
        assert_eq!(
            optional_error.message,
            "exported bootstrap integration policy did not preserve the marker identity"
        );
        assert!(!optional_error.message.contains("private-default"));

        let sensitive_inputs = Map::from_iter([(
            "system-log".to_string(),
            json!({"password": "private-bootstrap-value"}),
        )]);
        let sensitive_error = capture_exported_bootstrap_inputs(
            exported_marker_spec(sensitive_inputs.clone()),
            "2.0.0",
            TEST_INTEGRATION_RECORDING_NONCE,
            &materialized_bootstrap_item(&sensitive_inputs),
            "default",
        )
        .expect_err("sensitive-looking input field names must never reach a fixture");
        assert_eq!(
            sensitive_error.message,
            "exported bootstrap integration policy contained sensitive-looking input fields"
        );
        assert!(!sensitive_error.message.contains("password"));
        assert!(!sensitive_error.message.contains("private-bootstrap-value"));

        let changed_inputs =
            Map::from_iter([("system-log".to_string(), json!({"enabled": false}))]);
        let mismatch_error = capture_exported_bootstrap_inputs(
            exported_marker_spec(changed_inputs),
            "2.0.0",
            TEST_INTEGRATION_RECORDING_NONCE,
            &bootstrap_item,
            "default",
        )
        .expect_err("the export and fresh bootstrap read must carry the same input map");
        assert_eq!(
            mismatch_error.message,
            "exported bootstrap integration policy inputs did not match the marker read"
        );
    }

    #[test]
    fn bootstrap_export_decoder_rejects_malformed_or_non_single_output_without_echoing_it() {
        let malformed = elasticctl_api::ops::ExportOutcome {
            body: "private-bootstrap-export-body".to_string(),
            exported: 1,
            missing: Vec::new(),
        };
        let malformed_error = decode_exported_bootstrap_marker(malformed)
            .expect_err("exported output must be a decodable portable sequence");
        assert_eq!(
            malformed_error.message,
            "decoding exported bootstrap integration policy failed"
        );
        assert!(
            !malformed_error
                .message
                .contains("private-bootstrap-export-body")
        );

        let empty = elasticctl_api::ops::ExportOutcome {
            body: "[]".to_string(),
            exported: 0,
            missing: Vec::new(),
        };
        assert_eq!(
            decode_exported_bootstrap_marker(empty)
                .expect_err("one exported marker is required")
                .message,
            "exporting bootstrap integration policy did not return exactly one marker"
        );
    }
}
