//! Cleanup helpers.

use crate::diagnostics::{recording_error, safe_recording_transport_error};
use crate::recorder::integration::proofs::{
    MarkerIntegrationInputs, require_parent_attachments_with_nonce,
    reread_marker_integration_before_mutation_with_nonce_and_inputs,
    validate_marker_integration_parent_for_delete_with_nonce,
    validate_marker_integration_with_nonce_and_inputs,
};
use crate::recorder::markers::{
    INTEGRATION_POLICY_ID, INTEGRATION_POLICY_PARENT_ID, marker_integration_description,
};
use elasticctl_core::urlencode;
use serde_json::{Map, Value, json};

pub(crate) fn require_exact_delete_id(
    body: &Value,
    id: &str,
    context: &str,
) -> elasticctl_core::Result<()> {
    if body.get("id").and_then(Value::as_str) == Some(id) {
        Ok(())
    } else {
        Err(recording_error(format!(
            "{context}: delete response did not report the requested marker id"
        )))
    }
}

/// An error or malformed 2xx create response is not proof that Fleet did not
/// commit the write. Re-read only the fixed id and claim it only if its full
/// marker state carries this session's exact creation description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AmbiguousMarkerCreateOwnership {
    Claimed,
    Absent,
    Unclaimed,
}

#[cfg(test)]
async fn claim_ambiguous_marker_integration_create(
    t: &elasticctl_core::Transport,
    id: &str,
    expected_version: &str,
    nonce: &str,
) -> AmbiguousMarkerCreateOwnership {
    claim_ambiguous_marker_integration_create_with_inputs(
        t,
        id,
        expected_version,
        nonce,
        MarkerIntegrationInputs::Empty,
    )
    .await
}

pub(crate) async fn claim_ambiguous_marker_integration_create_with_inputs(
    t: &elasticctl_core::Transport,
    id: &str,
    expected_version: &str,
    nonce: &str,
    expected_inputs: MarkerIntegrationInputs<'_>,
) -> AmbiguousMarkerCreateOwnership {
    let expected_description = marker_integration_description(nonce);
    match t
        .get(&format!(
            "/api/fleet/package_policies/{}?format=simplified",
            urlencode(id)
        ))
        .await
    {
        Ok(current) => {
            if validate_marker_integration_with_nonce_and_inputs(
                &current,
                id,
                expected_version,
                t.space(),
                nonce,
                Some(&expected_description),
                expected_inputs,
            )
            .is_ok()
            {
                AmbiguousMarkerCreateOwnership::Claimed
            } else {
                AmbiguousMarkerCreateOwnership::Unclaimed
            }
        }
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
            AmbiguousMarkerCreateOwnership::Absent
        }
        Err(_) => AmbiguousMarkerCreateOwnership::Unclaimed,
    }
}

/// Parent creation can also commit despite an ambiguous response. A claimed
/// parent must be the same nonce-bearing marker, have no agents, and have no
/// attached integrations before cleanup is allowed to own it.
pub(crate) async fn claim_ambiguous_marker_integration_parent_create(
    t: &elasticctl_core::Transport,
    nonce: &str,
) -> bool {
    match t
        .get(&format!(
            "/api/fleet/agent_policies/{}",
            urlencode(INTEGRATION_POLICY_PARENT_ID)
        ))
        .await
    {
        Ok(current) => {
            validate_marker_integration_parent_for_delete_with_nonce(&current, t.space(), nonce)
                .is_ok()
                && require_parent_attachments_with_nonce(
                    &current,
                    &[],
                    t.space(),
                    nonce,
                    "ambiguous integration policy parent create",
                )
                .is_ok()
        }
        Err(_) => false,
    }
}

#[cfg(test)]
async fn cleanup_marker_integration(
    t: &elasticctl_core::Transport,
    id: &str,
    expected_version: &str,
    nonce: &str,
) -> elasticctl_core::Result<()> {
    cleanup_marker_integration_with_inputs(
        t,
        id,
        expected_version,
        nonce,
        MarkerIntegrationInputs::Empty,
    )
    .await
}

pub(crate) async fn cleanup_marker_integration_with_inputs(
    t: &elasticctl_core::Transport,
    id: &str,
    expected_version: &str,
    nonce: &str,
    expected_inputs: MarkerIntegrationInputs<'_>,
) -> elasticctl_core::Result<()> {
    let path = format!(
        "/api/fleet/package_policies/{}?format=simplified",
        urlencode(id)
    );
    let current = match t.get(&path).await {
        Ok(current) => current,
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(safe_recording_transport_error(
                "checking owned integration policy for cleanup failed",
                error,
            ));
        }
    };
    if validate_marker_integration_with_nonce_and_inputs(
        &current,
        id,
        expected_version,
        t.space(),
        nonce,
        None,
        expected_inputs,
    )
    .is_err()
    {
        return Err(recording_error(
            "refusing to delete integration policy: its marker identity no longer matches",
        ));
    }
    let delete_path = format!("/api/fleet/package_policies/{}", urlencode(id));
    let deleted = t.delete_once(&delete_path).await.map_err(|error| {
        safe_recording_transport_error("deleting owned integration policy failed", error)
    })?;
    require_exact_delete_id(&deleted, id, "integration cleanup")?;
    match t.get(&path).await {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(recording_error(
            "integration policy still exists after cleanup delete",
        )),
        Err(error) => Err(safe_recording_transport_error(
            "verifying integration policy cleanup delete failed",
            error,
        )),
    }
}

pub(crate) async fn cleanup_marker_integration_parent(
    t: &elasticctl_core::Transport,
    nonce: &str,
    expected_attachments: &[&str],
) -> elasticctl_core::Result<()> {
    let path = format!(
        "/api/fleet/agent_policies/{}",
        urlencode(INTEGRATION_POLICY_PARENT_ID)
    );
    let current = match t.get(&path).await {
        Ok(current) => current,
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(safe_recording_transport_error(
                "checking owned integration policy parent for cleanup failed",
                error,
            ));
        }
    };
    if validate_marker_integration_parent_for_delete_with_nonce(&current, t.space(), nonce).is_err()
    {
        return Err(recording_error(
            "refusing to delete integration policy parent: its marker identity no longer matches",
        ));
    }
    require_parent_attachments_with_nonce(
        &current,
        expected_attachments,
        t.space(),
        nonce,
        "integration parent cleanup",
    )?;
    let deleted = t
        .post_once(
            "/api/fleet/agent_policies/delete",
            Some(&json!({"agentPolicyId": INTEGRATION_POLICY_PARENT_ID})),
        )
        .await
        .map_err(|error| {
            safe_recording_transport_error("deleting owned integration policy parent failed", error)
        })?;
    require_exact_delete_id(
        &deleted,
        INTEGRATION_POLICY_PARENT_ID,
        "integration parent cleanup",
    )?;
    match t.get(&path).await {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(recording_error(
            "integration policy parent still exists after cleanup delete",
        )),
        Err(error) => Err(safe_recording_transport_error(
            "verifying integration policy parent cleanup delete failed",
            error,
        )),
    }
}

async fn require_marker_integration_absent(
    t: &elasticctl_core::Transport,
    id: &str,
    context: &'static str,
) -> elasticctl_core::Result<()> {
    match t
        .get(&format!(
            "/api/fleet/package_policies/{}?format=simplified",
            urlencode(id)
        ))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(recording_error(format!(
            "{context}: integration policy still exists after delete"
        ))),
        Err(error) => Err(safe_recording_transport_error(
            "verifying bootstrap integration policy delete failed",
            error,
        )),
    }
}

/// A bootstrap delete has no fixture body to preserve. Its one-shot response
/// can be malformed or lost after Fleet committed, so only a fresh absence
/// proof decides whether the recorder can continue. It never retries here.
pub(crate) async fn delete_bootstrap_marker_integration_once(
    t: &elasticctl_core::Transport,
    expected_version: &str,
    nonce: &str,
    expected_inputs: &Map<String, Value>,
) -> elasticctl_core::Result<()> {
    reread_marker_integration_before_mutation_with_nonce_and_inputs(
        t,
        expected_version,
        nonce,
        MarkerIntegrationInputs::Exact(expected_inputs),
        "rechecking bootstrap integration policy before delete",
    )
    .await?;
    let result = t
        .delete_once(&format!(
            "/api/fleet/package_policies/{}",
            urlencode(INTEGRATION_POLICY_ID)
        ))
        .await;
    let response_is_exact = matches!(
        result.as_ref(),
        Ok(body) if require_exact_delete_id(body, INTEGRATION_POLICY_ID, "bootstrap integration policy delete").is_ok()
    );
    match require_marker_integration_absent(
        t,
        INTEGRATION_POLICY_ID,
        "bootstrap integration policy delete",
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(absence_error) if response_is_exact => Err(absence_error),
        Err(_) => Err(recording_error(
            "bootstrap integration policy delete did not prove marker absence",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::integration::inputs::marker_integration_create_body;
    use crate::recorder::integration::proofs::MarkerIntegrationInputs;
    use crate::recorder::markers::INTEGRATION_POLICY_DESCRIPTION;
    use crate::recorder::markers::INTEGRATION_POLICY_DUP_ID;
    use crate::recorder::markers::INTEGRATION_POLICY_ID;
    use crate::recorder::markers::INTEGRATION_POLICY_PARENT_ID;
    use crate::recorder::markers::TEST_INTEGRATION_RECORDING_NONCE;
    use crate::recorder::test_support::marker_integration_response_with_inputs;
    use crate::recorder::test_support::marker_integration_response_with_nonce;
    use crate::recorder::test_support::materialized_marker_inputs;
    use crate::recorder::test_support::mock_transport;
    use serde_json::json;
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::body_json;
    use wiremock::matchers::method;
    use wiremock::matchers::path;
    use wiremock::matchers::query_param;

    #[tokio::test]
    async fn ambiguous_committed_bootstrap_create_claims_only_the_same_nonce_object_for_cleanup() {
        let server = MockServer::start().await;
        let committed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let committed_for_reads = committed.clone();
        let deleted_for_reads = deleted.clone();
        let inputs = materialized_marker_inputs();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                if committed_for_reads.load(std::sync::atomic::Ordering::SeqCst)
                    && !deleted_for_reads.load(std::sync::atomic::Ordering::SeqCst)
                {
                    ResponseTemplate::new(200).set_body_json(
                        marker_integration_response_with_inputs(
                            INTEGRATION_POLICY_DESCRIPTION,
                            TEST_INTEGRATION_RECORDING_NONCE,
                            &inputs,
                        ),
                    )
                } else {
                    ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}))
                }
            })
            .mount(&server)
            .await;
        let committed_for_create = committed.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(marker_integration_create_body("2.0.0")))
            .respond_with(move |_: &wiremock::Request| {
                committed_for_create.store(true, std::sync::atomic::Ordering::SeqCst);
                ResponseTemplate::new(409).set_body_json(json!({"statusCode": 409}))
            })
            .expect(1)
            .mount(&server)
            .await;
        let deleted_for_delete = deleted.clone();
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                deleted_for_delete.store(true, std::sync::atomic::Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(json!({"id": INTEGRATION_POLICY_ID}))
            })
            .expect(1)
            .mount(&server)
            .await;

        let transport = mock_transport(&server);
        transport
            .post_once(
                "/api/fleet/package_policies?format=simplified",
                Some(&marker_integration_create_body("2.0.0")),
            )
            .await
            .expect_err("an ambiguous committed bootstrap response must remain an error");
        assert_eq!(
            claim_ambiguous_marker_integration_create_with_inputs(
                &transport,
                INTEGRATION_POLICY_ID,
                "2.0.0",
                TEST_INTEGRATION_RECORDING_NONCE,
                MarkerIntegrationInputs::BootstrapObject,
            )
            .await,
            AmbiguousMarkerCreateOwnership::Claimed
        );
        cleanup_marker_integration_with_inputs(
            &transport,
            INTEGRATION_POLICY_ID,
            "2.0.0",
            TEST_INTEGRATION_RECORDING_NONCE,
            MarkerIntegrationInputs::BootstrapObject,
        )
        .await
        .expect("the same-nonce object-shaped bootstrap marker is cleanup-owned");

        let requests = server.received_requests().await.expect("requests");
        let create = requests
            .iter()
            .position(|request| request.method.as_str() == "POST")
            .expect("bootstrap create");
        let claim_get = requests
            .iter()
            .enumerate()
            .find_map(|(index, request)| {
                (index > create
                    && request.method.as_str() == "GET"
                    && request.url.path()
                        == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"))
                .then_some(index)
            })
            .expect("fresh ownership GET");
        let delete = requests
            .iter()
            .position(|request| request.method.as_str() == "DELETE")
            .expect("owned bootstrap delete");
        assert!(create < claim_get && claim_get < delete);
    }

    #[tokio::test]
    async fn same_nonce_duplicate_recovery_requires_an_exact_get_before_cleanup_delete() {
        let server = MockServer::start().await;
        let deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let deleted_for_reads = deleted.clone();
        let mut duplicate = marker_integration_response_with_nonce(
            INTEGRATION_POLICY_DESCRIPTION,
            TEST_INTEGRATION_RECORDING_NONCE,
        );
        duplicate["item"]["id"] = json!(INTEGRATION_POLICY_DUP_ID);
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_DUP_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                if deleted_for_reads.load(std::sync::atomic::Ordering::SeqCst) {
                    ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}))
                } else {
                    ResponseTemplate::new(200).set_body_json(duplicate.clone())
                }
            })
            .mount(&server)
            .await;
        let deleted_for_response = deleted.clone();
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_DUP_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                deleted_for_response.store(true, std::sync::atomic::Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(json!({
                    "id": INTEGRATION_POLICY_DUP_ID,
                }))
            })
            .mount(&server)
            .await;

        let transport = mock_transport(&server);
        assert_eq!(
            claim_ambiguous_marker_integration_create(
                &transport,
                INTEGRATION_POLICY_DUP_ID,
                "2.0.0",
                TEST_INTEGRATION_RECORDING_NONCE,
            )
            .await,
            AmbiguousMarkerCreateOwnership::Claimed
        );
        cleanup_marker_integration(
            &transport,
            INTEGRATION_POLICY_DUP_ID,
            "2.0.0",
            TEST_INTEGRATION_RECORDING_NONCE,
        )
        .await
        .expect("a proven same-nonce duplicate is cleanup-owned");

        let requests = server.received_requests().await.expect("requests");
        let first_get = requests
            .iter()
            .position(|request| request.method.as_str() == "GET")
            .expect("ambiguity recovery GET");
        let delete = requests
            .iter()
            .position(|request| request.method.as_str() == "DELETE")
            .expect("duplicate cleanup delete");
        assert!(first_get < delete);
    }

    #[tokio::test]
    async fn cleanup_after_an_ambiguous_mutation_leaves_an_absent_marker_untouched() {
        let integration_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})))
            .expect(1)
            .mount(&integration_server)
            .await;
        let integration_transport = mock_transport(&integration_server);
        cleanup_marker_integration(
            &integration_transport,
            INTEGRATION_POLICY_ID,
            "2.0.0",
            TEST_INTEGRATION_RECORDING_NONCE,
        )
        .await
        .expect("an absent integration is already clean after an ambiguous mutation");
        assert!(
            integration_server
                .received_requests()
                .await
                .expect("integration requests")
                .iter()
                .all(|request| request.method.as_str() != "DELETE")
        );

        let parent_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
            )))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})))
            .expect(1)
            .mount(&parent_server)
            .await;
        let parent_transport = mock_transport(&parent_server);
        cleanup_marker_integration_parent(&parent_transport, TEST_INTEGRATION_RECORDING_NONCE, &[])
            .await
            .expect("an absent parent is already clean after an ambiguous mutation");
        assert!(
            parent_server
                .received_requests()
                .await
                .expect("parent requests")
                .iter()
                .all(|request| request.method.as_str() != "POST")
        );
    }
}
