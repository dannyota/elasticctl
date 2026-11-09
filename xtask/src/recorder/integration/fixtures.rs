//! Fixtures helpers.

use crate::diagnostics::recording_error;
use crate::fixtures::{RecordedFixture, exchange_fixture, response_fixture};
use crate::recorder::integration::inputs::{
    marker_integration_create_body_with_nonce_and_inputs,
    marker_integration_parent_create_body_with_nonce,
    marker_integration_update_body_with_nonce_and_inputs,
};
use crate::recorder::integration::proofs::{
    IntegrationFixtureContext, MarkerIntegrationInputs, require_parent_attachment_with_nonce,
    validate_marker_integration_item_with_nonce_and_inputs,
    validate_marker_integration_parent_identity_with_nonce,
    validate_marker_integration_with_nonce_and_inputs,
};
#[cfg(test)]
use crate::recorder::markers::TEST_INTEGRATION_RECORDING_NONCE;
use crate::recorder::markers::{
    INTEGRATION_POLICY_DESCRIPTION, INTEGRATION_POLICY_ID, INTEGRATION_POLICY_NAME,
    INTEGRATION_POLICY_NAMESPACE, INTEGRATION_POLICY_PACKAGE,
    INTEGRATION_POLICY_PARENT_DESCRIPTION, INTEGRATION_POLICY_PARENT_ID,
    INTEGRATION_POLICY_PARENT_INACTIVITY_TIMEOUT, INTEGRATION_POLICY_PARENT_NAME,
    INTEGRATION_POLICY_UPDATED_DESCRIPTION,
};
use crate::recorder::markers::{
    marker_integration_description, marker_integration_updated_description,
};
use serde_json::{Map, Value, json};

/// Keep the marker integration only. Package-policy list responses otherwise
/// expose every integration in a shared Fleet space, including user-owned
/// configuration and possible secret references.
#[cfg(test)]
pub(crate) fn scope_integration_policy_list_to_marker_with_nonce(
    body: &mut Value,
    marker_id: &str,
    expected_version: &str,
    active_space: &str,
    nonce: &str,
) -> usize {
    scope_integration_policy_list_to_marker_with_nonce_and_inputs(
        body,
        marker_id,
        expected_version,
        active_space,
        nonce,
        MarkerIntegrationInputs::Empty,
    )
}

pub(crate) fn scope_integration_policy_list_to_marker_with_nonce_and_inputs(
    body: &mut Value,
    marker_id: &str,
    expected_version: &str,
    active_space: &str,
    nonce: &str,
    expected_inputs: MarkerIntegrationInputs<'_>,
) -> usize {
    let Some(items) = body.get_mut("items").and_then(Value::as_array_mut) else {
        return 0;
    };
    items.retain(|item| {
        item.as_object().is_some_and(|item| {
            validate_marker_integration_item_with_nonce_and_inputs(
                item,
                marker_id,
                expected_version,
                active_space,
                nonce,
                None,
                expected_inputs,
            )
            .is_ok()
        })
    });
    let kept = items.len();
    if let Some(map) = body.as_object_mut() {
        map.insert("total".to_string(), json!(kept));
    }
    kept
}

#[cfg(test)]
pub(crate) fn scope_integration_policy_list_to_marker(
    body: &mut Value,
    marker_id: &str,
    expected_version: &str,
    active_space: &str,
) -> usize {
    scope_integration_policy_list_to_marker_with_nonce(
        body,
        marker_id,
        expected_version,
        active_space,
        TEST_INTEGRATION_RECORDING_NONCE,
    )
}

#[cfg(test)]
pub(crate) fn integration_policy_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    body: Value,
) -> elasticctl_core::Result<RecordedFixture> {
    integration_policy_fixture_in_space(
        name,
        flavor,
        version,
        INTEGRATION_POLICY_NAMESPACE,
        TEST_INTEGRATION_RECORDING_NONCE,
        body,
    )
}

pub(crate) fn integration_policy_fixture_in_space(
    name: &'static str,
    flavor: &str,
    version: &str,
    active_space: &str,
    nonce: &str,
    body: Value,
) -> elasticctl_core::Result<RecordedFixture> {
    integration_policy_fixture_in_space_with_inputs(
        name,
        flavor,
        version,
        active_space,
        nonce,
        &Map::new(),
        body,
    )
}

pub(crate) fn integration_policy_fixture_in_space_with_inputs(
    name: &'static str,
    flavor: &str,
    version: &str,
    active_space: &str,
    nonce: &str,
    expected_inputs: &Map<String, Value>,
    body: Value,
) -> elasticctl_core::Result<RecordedFixture> {
    let body = match name {
        "integration_policy_get" => {
            let description = marker_integration_description(nonce);
            reduce_marker_integration_response_with_inputs(
                &body,
                active_space,
                nonce,
                &description,
                expected_inputs,
            )?
        }
        "integration_policy_round_trip" => {
            let description = marker_integration_updated_description(nonce);
            reduce_marker_integration_response_with_inputs(
                &body,
                active_space,
                nonce,
                &description,
                expected_inputs,
            )?
        }
        "integration_policies_list" => {
            reduce_marker_integration_list_with_inputs(&body, active_space, nonce, expected_inputs)?
        }
        "integration_policy_parent_get" => {
            reduce_marker_parent_get_response(&body, active_space, nonce)?
        }
        "integration_policy_delete" => reduce_integration_delete_response(&body)?,
        "integration_policy_parent_delete" => reduce_parent_delete_response(&body)?,
        _ => {
            return Err(recording_error(
                "integration policy fixture has no safe response reducer",
            ));
        }
    };
    Ok(response_fixture(name, flavor, version, body, None))
}

#[cfg(test)]
pub(crate) fn integration_policy_exchange_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    request: Value,
    body: Value,
) -> elasticctl_core::Result<RecordedFixture> {
    integration_policy_exchange_fixture_in_space(
        name,
        flavor,
        version,
        INTEGRATION_POLICY_NAMESPACE,
        TEST_INTEGRATION_RECORDING_NONCE,
        request,
        body,
    )
}

pub(crate) fn integration_policy_exchange_fixture_in_space(
    name: &'static str,
    flavor: &str,
    version: &str,
    active_space: &str,
    nonce: &str,
    request: Value,
    body: Value,
) -> elasticctl_core::Result<RecordedFixture> {
    integration_policy_exchange_fixture_in_space_with_inputs(
        name,
        flavor,
        version,
        IntegrationFixtureContext {
            active_space,
            nonce,
            expected_inputs: &Map::new(),
        },
        request,
        body,
    )
}

pub(crate) fn integration_policy_exchange_fixture_in_space_with_inputs(
    name: &'static str,
    flavor: &str,
    version: &str,
    context: IntegrationFixtureContext<'_>,
    request: Value,
    body: Value,
) -> elasticctl_core::Result<RecordedFixture> {
    let IntegrationFixtureContext {
        active_space,
        nonce,
        expected_inputs,
    } = context;
    let (request, body) = match name {
        "integration_policy_parent_create" => (
            reduce_marker_parent_create_request(&request, nonce)?,
            reduce_marker_parent_create_response(&body, active_space, nonce)?,
        ),
        "integration_policy_create" => (
            reduce_marker_integration_create_request_with_inputs(&request, nonce, expected_inputs)?,
            reduce_marker_integration_response_with_inputs(
                &body,
                active_space,
                nonce,
                &marker_integration_description(nonce),
                expected_inputs,
            )?,
        ),
        "integration_policy_update" => (
            reduce_marker_integration_update_request_with_inputs(&request, nonce, expected_inputs)?,
            reduce_marker_integration_response_with_inputs(
                &body,
                active_space,
                nonce,
                &marker_integration_updated_description(nonce),
                expected_inputs,
            )?,
        ),
        _ => {
            return Err(recording_error(
                "integration policy fixture has no safe exchange reducer",
            ));
        }
    };
    Ok(exchange_fixture(name, flavor, version, request, body))
}

/// Reduce a marker integration response after proving its stable marker
/// identity. The allowlist is intentionally smaller than the public Fleet
/// schema: response-only metadata, active-space references, secrets, and new
/// unknown fields do not prove this recorder's route contract.
pub(crate) fn reduce_marker_integration_response_with_inputs(
    body: &Value,
    active_space: &str,
    nonce: &str,
    expected_description: &str,
    expected_inputs: &Map<String, Value>,
) -> elasticctl_core::Result<Value> {
    let item = body.get("item").and_then(Value::as_object).ok_or_else(|| {
        recording_error("integration policy response must contain an item object")
    })?;
    let package_version = item
        .get("package")
        .and_then(Value::as_object)
        .and_then(|package| package.get("version"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            recording_error("integration policy response package version must be non-empty")
        })?;
    let created_description = marker_integration_description(nonce);
    let updated_description = marker_integration_updated_description(nonce);
    let description = if expected_description == created_description {
        INTEGRATION_POLICY_DESCRIPTION
    } else if expected_description == updated_description {
        INTEGRATION_POLICY_UPDATED_DESCRIPTION
    } else {
        return Err(recording_error(
            "integration policy response did not preserve the marker identity",
        ));
    };
    validate_marker_integration_with_nonce_and_inputs(
        body,
        INTEGRATION_POLICY_ID,
        package_version,
        active_space,
        nonce,
        Some(expected_description),
        MarkerIntegrationInputs::Exact(expected_inputs),
    )?;
    Ok(json!({
        "item": {
            "id": INTEGRATION_POLICY_ID,
            "name": INTEGRATION_POLICY_NAME,
            "namespace": INTEGRATION_POLICY_NAMESPACE,
            "description": description,
            "policy_ids": [INTEGRATION_POLICY_PARENT_ID],
            "package": {
                "name": INTEGRATION_POLICY_PACKAGE,
                "version": package_version,
            },
            "inputs": expected_inputs,
            "enabled": true,
        }
    }))
}

pub(crate) fn marker_integration_request_version<'a>(
    request: &'a Value,
    context: &'static str,
) -> elasticctl_core::Result<&'a str> {
    request
        .pointer("/package/version")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| recording_error(format!("{context} package version must be non-empty")))
}

pub(crate) fn reduce_marker_integration_create_request_with_inputs(
    request: &Value,
    nonce: &str,
    expected_inputs: &Map<String, Value>,
) -> elasticctl_core::Result<Value> {
    let version = marker_integration_request_version(request, "integration policy create request")?;
    let expected =
        marker_integration_create_body_with_nonce_and_inputs(version, nonce, expected_inputs);
    if request != &expected {
        return Err(recording_error(
            "integration policy create request did not preserve the exact marker body",
        ));
    }
    let mut reduced = expected;
    reduced["description"] = json!(INTEGRATION_POLICY_DESCRIPTION);
    Ok(reduced)
}

pub(crate) fn reduce_marker_integration_update_request_with_inputs(
    request: &Value,
    nonce: &str,
    expected_inputs: &Map<String, Value>,
) -> elasticctl_core::Result<Value> {
    let version = marker_integration_request_version(request, "integration policy update request")?;
    let expected =
        marker_integration_update_body_with_nonce_and_inputs(version, nonce, expected_inputs);
    if request != &expected {
        return Err(recording_error(
            "integration policy update request did not preserve the exact marker body",
        ));
    }
    let mut reduced = expected;
    reduced["description"] = json!(INTEGRATION_POLICY_UPDATED_DESCRIPTION);
    Ok(reduced)
}

pub(crate) fn reduce_marker_parent_create_request(
    request: &Value,
    nonce: &str,
) -> elasticctl_core::Result<Value> {
    let expected = marker_integration_parent_create_body_with_nonce(nonce);
    if request != &expected {
        return Err(recording_error(
            "integration policy parent create request did not preserve the exact marker body",
        ));
    }
    let mut reduced = expected;
    reduced["description"] = json!(INTEGRATION_POLICY_PARENT_DESCRIPTION);
    Ok(reduced)
}

pub(crate) fn reduce_marker_parent_create_response(
    body: &Value,
    active_space: &str,
    nonce: &str,
) -> elasticctl_core::Result<Value> {
    validate_marker_integration_parent_identity_with_nonce(body, active_space, nonce).map_err(
        |_| {
            recording_error("integration policy parent create did not preserve the marker identity")
        },
    )?;
    Ok(json!({
        "item": {
            "id": INTEGRATION_POLICY_PARENT_ID,
            "name": INTEGRATION_POLICY_PARENT_NAME,
            "namespace": INTEGRATION_POLICY_NAMESPACE,
            "description": INTEGRATION_POLICY_PARENT_DESCRIPTION,
            "monitoring_enabled": [],
            "inactivity_timeout": INTEGRATION_POLICY_PARENT_INACTIVITY_TIMEOUT,
        }
    }))
}

pub(crate) fn reduce_marker_parent_get_response(
    body: &Value,
    active_space: &str,
    nonce: &str,
) -> elasticctl_core::Result<Value> {
    require_parent_attachment_with_nonce(body, active_space, nonce)?;
    let agents = body
        .pointer("/item/agents")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            recording_error("integration policy parent get agents must be an unsigned integer")
        })?;
    Ok(json!({
        "item": {
            "id": INTEGRATION_POLICY_PARENT_ID,
            "name": INTEGRATION_POLICY_PARENT_NAME,
            "namespace": INTEGRATION_POLICY_NAMESPACE,
            "description": INTEGRATION_POLICY_PARENT_DESCRIPTION,
            "monitoring_enabled": [],
            "inactivity_timeout": INTEGRATION_POLICY_PARENT_INACTIVITY_TIMEOUT,
            "agents": agents,
            "package_policies": [INTEGRATION_POLICY_ID],
        }
    }))
}

pub(crate) fn reduce_marker_integration_list_with_inputs(
    body: &Value,
    active_space: &str,
    nonce: &str,
    expected_inputs: &Map<String, Value>,
) -> elasticctl_core::Result<Value> {
    let items = body
        .get("items")
        .and_then(Value::as_array)
        .filter(|items| items.len() == 1)
        .ok_or_else(|| {
            recording_error("integration policy list must contain exactly one marker item")
        })?;
    let total = body.get("total").and_then(Value::as_u64);
    let page = body.get("page").and_then(Value::as_u64);
    let per_page = body.get("perPage").and_then(Value::as_u64);
    if total != Some(1) || page != Some(1) || per_page != Some(1000) {
        return Err(recording_error(
            "integration policy list did not preserve the exact marker page metadata",
        ));
    }
    let description = marker_integration_description(nonce);
    let reduced = reduce_marker_integration_response_with_inputs(
        &json!({"item": items[0]}),
        active_space,
        nonce,
        &description,
        expected_inputs,
    )?;
    Ok(json!({
        "items": [reduced["item"].clone()],
        "total": 1,
        "page": 1,
        "perPage": 1000,
    }))
}

pub(crate) fn reduce_integration_delete_response(body: &Value) -> elasticctl_core::Result<Value> {
    let item = body
        .as_object()
        .filter(|item| item.len() == 1)
        .filter(|item| item.get("id").and_then(Value::as_str) == Some(INTEGRATION_POLICY_ID))
        .ok_or_else(|| {
            recording_error(
                "integration policy delete response did not contain the exact marker id",
            )
        })?;
    let _ = item;
    Ok(json!({"id": INTEGRATION_POLICY_ID}))
}

pub(crate) fn reduce_parent_delete_response(body: &Value) -> elasticctl_core::Result<Value> {
    let item = body
        .as_object()
        .filter(|item| item.len() == 2)
        .filter(|item| item.get("id").and_then(Value::as_str) == Some(INTEGRATION_POLICY_PARENT_ID))
        .filter(|item| {
            item.get("name").and_then(Value::as_str) == Some(INTEGRATION_POLICY_PARENT_NAME)
        })
        .ok_or_else(|| {
            recording_error(
                "integration policy parent delete response did not contain the exact marker body",
            )
        })?;
    let _ = item;
    Ok(json!({
        "id": INTEGRATION_POLICY_PARENT_ID,
        "name": INTEGRATION_POLICY_PARENT_NAME,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::integration_policy_error_fixture;
    use crate::recorder::integration::inputs::{
        marker_integration_create_body, marker_integration_create_body_with_nonce,
        marker_integration_parent_create_body_with_nonce, marker_integration_update_body,
        marker_integration_update_body_with_nonce,
    };
    use crate::recorder::markers::{
        INTEGRATION_POLICY_DESCRIPTION, INTEGRATION_POLICY_ID, INTEGRATION_POLICY_NAME,
        INTEGRATION_POLICY_NAMESPACE, INTEGRATION_POLICY_PACKAGE,
        INTEGRATION_POLICY_PARENT_DESCRIPTION, INTEGRATION_POLICY_PARENT_ID,
        INTEGRATION_POLICY_PARENT_INACTIVITY_TIMEOUT, INTEGRATION_POLICY_PARENT_NAME,
        INTEGRATION_POLICY_UPDATED_DESCRIPTION, TEST_INTEGRATION_RECORDING_NONCE,
        marker_integration_description,
    };
    use crate::recorder::test_support::{
        marker_integration_parent_response, marker_integration_parent_response_with_nonce,
        marker_integration_response, marker_integration_response_with_nonce,
    };
    use serde_json::{Value, json};

    #[test]
    fn integration_list_scoping_and_scrubbing_keep_only_marker_safe_data() {
        let mut list = json!({
            "items": [
                {"id": "unrelated", "name": "private policy"},
                {
                    "id": INTEGRATION_POLICY_ID,
                    "name": "private policy reusing the marker id",
                    "package": {"name": "private-package", "version": "9.9.9"},
                    "inputs": {"private": {}}
                },
                {
                    "id": INTEGRATION_POLICY_ID,
                    "name": INTEGRATION_POLICY_NAME,
                    "namespace": "default",
                    "description": marker_integration_description(TEST_INTEGRATION_RECORDING_NONCE),
                    "policy_ids": [INTEGRATION_POLICY_PARENT_ID],
                    "package": {"name": "system", "version": "2.0.0"},
                    "inputs": {},
                    "enabled": true,
                    "created_by": "private-user",
                    "created_at": "2026-09-04T00:00:00.000Z",
                    "spaceIds": ["default"],
                    "version": "private-concurrency-token"
                }
            ],
            "total": 2,
            "page": 1,
            "perPage": 1000
        });

        assert_eq!(
            scope_integration_policy_list_to_marker(
                &mut list,
                INTEGRATION_POLICY_ID,
                "2.0.0",
                "default",
            ),
            1
        );
        let fixture =
            integration_policy_fixture("integration_policies_list", "test", "9.6.0", list)
                .expect("marker list is reducible");

        assert_eq!(fixture.document["response"]["total"], 1);
        assert_eq!(
            fixture.document["response"]["items"][0]["id"],
            INTEGRATION_POLICY_ID
        );
        let encoded = fixture.document.to_string();
        for private in [
            "unrelated",
            "private policy reusing the marker id",
            "private-package",
            "private-user",
            "private-concurrency-token",
        ] {
            assert!(!encoded.contains(private), "fixture leaked {private}");
        }
    }

    #[test]
    fn integration_reducer_normalizes_a_session_nonce_without_exposing_it() {
        let mismatch = match integration_policy_fixture_in_space(
            "integration_policy_get",
            "test",
            "9.6.0",
            INTEGRATION_POLICY_NAMESPACE,
            "expected-session-nonce",
            marker_integration_response_with_nonce(
                INTEGRATION_POLICY_DESCRIPTION,
                "other-session-nonce",
            ),
        ) {
            Ok(_) => panic!("a reducer must reject another session's description nonce"),
            Err(error) => error,
        };
        assert!(!mismatch.message.contains("other-session-nonce"));

        let mut documents = Vec::new();
        for nonce in ["same-session-nonce", "later-session-nonce"] {
            let get = integration_policy_fixture_in_space(
                "integration_policy_get",
                "test",
                "9.6.0",
                INTEGRATION_POLICY_NAMESPACE,
                nonce,
                marker_integration_response_with_nonce(INTEGRATION_POLICY_DESCRIPTION, nonce),
            )
            .expect("a same-session nonce-bearing response is safe to reduce");

            assert_eq!(
                get.document["response"]["item"]["description"],
                INTEGRATION_POLICY_DESCRIPTION
            );
            let parent = integration_policy_exchange_fixture_in_space(
                "integration_policy_parent_create",
                "test",
                "9.6.0",
                INTEGRATION_POLICY_NAMESPACE,
                nonce,
                marker_integration_parent_create_body_with_nonce(nonce),
                marker_integration_parent_response_with_nonce(nonce),
            )
            .expect("a same-session nonce-bearing parent exchange is safe to reduce");
            assert_eq!(
                parent.document["request"]["description"],
                INTEGRATION_POLICY_PARENT_DESCRIPTION
            );
            assert_eq!(
                parent.document["response"]["item"]["description"],
                INTEGRATION_POLICY_PARENT_DESCRIPTION
            );
            let create = integration_policy_exchange_fixture_in_space(
                "integration_policy_create",
                "test",
                "9.6.0",
                INTEGRATION_POLICY_NAMESPACE,
                nonce,
                marker_integration_create_body_with_nonce("2.0.0", nonce),
                marker_integration_response_with_nonce(INTEGRATION_POLICY_DESCRIPTION, nonce),
            )
            .expect("a same-session nonce-bearing create exchange is safe to reduce");
            assert_eq!(
                create.document["request"]["description"],
                INTEGRATION_POLICY_DESCRIPTION
            );
            assert_eq!(
                create.document["response"]["item"]["description"],
                INTEGRATION_POLICY_DESCRIPTION
            );
            let update = integration_policy_exchange_fixture_in_space(
                "integration_policy_update",
                "test",
                "9.6.0",
                INTEGRATION_POLICY_NAMESPACE,
                nonce,
                marker_integration_update_body_with_nonce("2.0.0", nonce),
                marker_integration_response_with_nonce(
                    INTEGRATION_POLICY_UPDATED_DESCRIPTION,
                    nonce,
                ),
            )
            .expect("a same-session nonce-bearing update exchange is safe to reduce");
            assert_eq!(
                update.document["request"]["description"],
                INTEGRATION_POLICY_UPDATED_DESCRIPTION
            );
            assert_eq!(
                update.document["response"]["item"]["description"],
                INTEGRATION_POLICY_UPDATED_DESCRIPTION
            );
            let document = Value::Array(vec![
                get.document,
                parent.document,
                create.document,
                update.document,
            ]);
            assert!(
                !document.to_string().contains(nonce),
                "public fixtures must never retain the in-memory ownership nonce"
            );
            documents.push(document);
        }
        assert_eq!(
            documents[0], documents[1],
            "different session nonces must reduce to one deterministic fixture"
        );
    }

    #[test]
    fn integration_policy_error_fixtures_keep_only_classification_and_a_local_message() {
        let fixture = integration_policy_error_fixture(
            "integration_policy_not_found",
            "test",
            "9.6.0",
            elasticctl_core::Error::with_status(
                elasticctl_core::ErrorKind::NotFound,
                404,
                "owner@example.com at https://private.example/opaque-id uses ${secret.ref}",
            ),
        );

        assert_eq!(fixture.document["error"]["kind"], "not_found");
        assert_eq!(fixture.document["error"]["http_status"], 404);
        assert_eq!(
            fixture.document["error"]["message"],
            "Fleet integration-policy recording endpoint returned an error"
        );
        let encoded = fixture.document.to_string();
        for private in [
            "owner@example.com",
            "private.example",
            "opaque-id",
            "secret.ref",
        ] {
            assert!(!encoded.contains(private), "fixture leaked {private}");
        }
    }

    #[test]
    fn integration_policy_response_fixture_rejects_environment_and_secret_references() {
        for (field, value, private) in [
            ("output_id", json!("private-output-id"), "private-output-id"),
            (
                "cloud_connector_id",
                json!("private-connector-id"),
                "private-connector-id",
            ),
            (
                "secret_references",
                json!([{"id": "private-secret-reference"}]),
                "private-secret-reference",
            ),
        ] {
            let mut response = marker_integration_response(INTEGRATION_POLICY_DESCRIPTION);
            response["item"]["enabled"] = json!(true);
            response["item"][field] = value;
            let error = match integration_policy_fixture(
                "integration_policy_get",
                "test",
                "9.6.0",
                response,
            ) {
                Ok(_) => panic!("a nonportable marker response must not become a public fixture"),
                Err(error) => error,
            };
            assert!(!error.message.contains(private), "reducer leaked {private}");
        }
    }

    #[test]
    fn integration_policy_response_fixture_omits_unknown_fields() {
        let mut response = marker_integration_response(INTEGRATION_POLICY_DESCRIPTION);
        response["item"]["enabled"] = json!(true);
        response["item"]["unknown_top_level"] = json!({
            "host": "private.example",
            "nested": {"token": "private-token"}
        });
        response["item"]["package"]["unknown_package_field"] = json!("private-package");

        let fixture =
            integration_policy_fixture("integration_policy_get", "test", "9.6.0", response)
                .expect("marker response is reducible");

        assert_eq!(
            fixture.document["response"],
            json!({
                "item": {
                    "id": INTEGRATION_POLICY_ID,
                    "name": INTEGRATION_POLICY_NAME,
                    "namespace": INTEGRATION_POLICY_NAMESPACE,
                    "description": INTEGRATION_POLICY_DESCRIPTION,
                    "policy_ids": [INTEGRATION_POLICY_PARENT_ID],
                    "package": {"name": INTEGRATION_POLICY_PACKAGE, "version": "2.0.0"},
                    "inputs": {},
                    "enabled": true,
                }
            })
        );
        let encoded = fixture.document.to_string();
        for private in ["private.example", "private-token", "private-package"] {
            assert!(!encoded.contains(private), "fixture leaked {private}");
        }
    }

    #[test]
    fn integration_policy_fixture_reducers_cover_each_public_response_shape() {
        for (name, description, request) in [
            (
                "integration_policy_create",
                INTEGRATION_POLICY_DESCRIPTION,
                Some(marker_integration_create_body("2.0.0")),
            ),
            (
                "integration_policy_get",
                INTEGRATION_POLICY_DESCRIPTION,
                None,
            ),
            (
                "integration_policy_update",
                INTEGRATION_POLICY_UPDATED_DESCRIPTION,
                Some(marker_integration_update_body("2.0.0")),
            ),
            (
                "integration_policy_round_trip",
                INTEGRATION_POLICY_UPDATED_DESCRIPTION,
                None,
            ),
        ] {
            let mut response = marker_integration_response(description);
            response["item"]["enabled"] = json!(true);
            response["item"]["unknown"] = json!({"secret": "private-value"});
            let fixture = match request {
                Some(request) => {
                    integration_policy_exchange_fixture(name, "test", "9.6.0", request, response)
                }
                None => integration_policy_fixture(name, "test", "9.6.0", response),
            }
            .expect("known marker response is reducible");
            assert_eq!(
                fixture.document["response"],
                json!({
                    "item": {
                        "id": INTEGRATION_POLICY_ID,
                        "name": INTEGRATION_POLICY_NAME,
                        "namespace": INTEGRATION_POLICY_NAMESPACE,
                        "description": description,
                        "policy_ids": [INTEGRATION_POLICY_PARENT_ID],
                        "package": {"name": INTEGRATION_POLICY_PACKAGE, "version": "2.0.0"},
                        "inputs": {},
                        "enabled": true,
                    }
                }),
                "{name}"
            );
        }

        let mut parent_get = marker_integration_parent_response();
        parent_get["item"]["agents"] = json!(0);
        parent_get["item"]["package_policies"] = json!([INTEGRATION_POLICY_ID]);
        parent_get["item"]["output_id"] = json!("private-parent-output");
        parent_get["item"]["unknown"] = json!({"host": "private.example"});
        let parent_fixture = integration_policy_fixture(
            "integration_policy_parent_get",
            "test",
            "9.6.0",
            parent_get,
        )
        .expect("marker parent get is reducible");
        assert_eq!(
            parent_fixture.document["response"],
            json!({
                "item": {
                    "id": INTEGRATION_POLICY_PARENT_ID,
                    "name": INTEGRATION_POLICY_PARENT_NAME,
                    "namespace": INTEGRATION_POLICY_NAMESPACE,
                    "description": INTEGRATION_POLICY_PARENT_DESCRIPTION,
                    "monitoring_enabled": [],
                    "inactivity_timeout": INTEGRATION_POLICY_PARENT_INACTIVITY_TIMEOUT,
                    "agents": 0,
                    "package_policies": [INTEGRATION_POLICY_ID],
                }
            })
        );

        let mut list = json!({
            "items": [{
                "id": INTEGRATION_POLICY_ID,
                "name": INTEGRATION_POLICY_NAME,
                "namespace": INTEGRATION_POLICY_NAMESPACE,
                "description": marker_integration_description(TEST_INTEGRATION_RECORDING_NONCE),
                "policy_ids": [INTEGRATION_POLICY_PARENT_ID],
                "package": {"name": INTEGRATION_POLICY_PACKAGE, "version": "2.0.0"},
                "inputs": {},
                "enabled": true,
                "unknown": {"token": "private-token"},
            }],
            "total": 1,
            "page": 1,
            "perPage": 1000,
            "unknown_envelope": {"host": "private.example"},
        });
        assert_eq!(
            scope_integration_policy_list_to_marker(
                &mut list,
                INTEGRATION_POLICY_ID,
                "2.0.0",
                "default",
            ),
            1
        );
        let list_fixture =
            integration_policy_fixture("integration_policies_list", "test", "9.6.0", list)
                .expect("marker list is reducible");
        assert_eq!(
            list_fixture.document["response"],
            json!({
                "items": [{
                    "id": INTEGRATION_POLICY_ID,
                    "name": INTEGRATION_POLICY_NAME,
                    "namespace": INTEGRATION_POLICY_NAMESPACE,
                    "description": INTEGRATION_POLICY_DESCRIPTION,
                    "policy_ids": [INTEGRATION_POLICY_PARENT_ID],
                    "package": {"name": INTEGRATION_POLICY_PACKAGE, "version": "2.0.0"},
                    "inputs": {},
                    "enabled": true,
                }],
                "total": 1,
                "page": 1,
                "perPage": 1000,
            })
        );

        let integration_delete_error = match integration_policy_fixture(
            "integration_policy_delete",
            "test",
            "9.6.0",
            json!({"id": INTEGRATION_POLICY_ID, "private": "private-delete-value"}),
        ) {
            Ok(_) => panic!("an integration delete response must be exact"),
            Err(error) => error,
        };
        assert!(
            !integration_delete_error
                .message
                .contains("private-delete-value")
        );
        let integration_delete = integration_policy_fixture(
            "integration_policy_delete",
            "test",
            "9.6.0",
            json!({"id": INTEGRATION_POLICY_ID}),
        )
        .expect("an exact integration delete response is reducible");
        assert_eq!(
            integration_delete.document["response"],
            json!({"id": INTEGRATION_POLICY_ID})
        );
        let parent_delete_error = match integration_policy_fixture(
            "integration_policy_parent_delete",
            "test",
            "9.6.0",
            json!({
                "id": INTEGRATION_POLICY_PARENT_ID,
                "name": INTEGRATION_POLICY_PARENT_NAME,
                "private": "private-parent-delete-value",
            }),
        ) {
            Ok(_) => panic!("a parent delete response must be exact"),
            Err(error) => error,
        };
        assert!(
            !parent_delete_error
                .message
                .contains("private-parent-delete-value")
        );
        let parent_delete = integration_policy_fixture(
            "integration_policy_parent_delete",
            "test",
            "9.6.0",
            json!({
                "id": INTEGRATION_POLICY_PARENT_ID,
                "name": INTEGRATION_POLICY_PARENT_NAME,
            }),
        )
        .expect("an exact parent delete response is reducible");
        assert_eq!(
            parent_delete.document["response"],
            json!({
                "id": INTEGRATION_POLICY_PARENT_ID,
                "name": INTEGRATION_POLICY_PARENT_NAME,
            })
        );
    }
}
