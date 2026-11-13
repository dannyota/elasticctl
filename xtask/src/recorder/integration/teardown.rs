use super::lifecycle::{Context, Evidence};
use crate::diagnostics::{record_trace, recording_error, safe_recording_transport_error};
use crate::fixtures::{Recording, integration_policy_error_fixture};
use crate::recorder::integration::cleanup::require_exact_delete_id;
use crate::recorder::integration::fixtures::integration_policy_fixture_in_space;
use crate::recorder::integration::proofs::{
    MarkerIntegrationInputs, reread_marker_integration_before_mutation_with_nonce_and_inputs,
    reread_marker_parent_before_mutation_with_nonce,
};
use crate::recorder::markers::{INTEGRATION_POLICY_ID, INTEGRATION_POLICY_PARENT_ID};
use crate::recorder::session::RecordingSession;
use elasticctl_core::urlencode;
use serde_json::{Value, json};

#[expect(
    clippy::needless_borrow,
    reason = "Preserve the lifecycle slice verbatim with borrowed phase inputs."
)]
pub(super) async fn delete_markers(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    Context {
        flavor,
        version,
        nonce,
    }: Context<'_>,
    Evidence { package_status, .. }: Evidence<'_>,
    stable_inputs: &serde_json::Map<String, Value>,
) -> elasticctl_core::Result<()> {
    let t = session.transport;

    reread_marker_integration_before_mutation_with_nonce_and_inputs(
        t,
        &package_status.version,
        nonce,
        MarkerIntegrationInputs::Exact(&stable_inputs),
        "rechecking integration policy marker before delete",
    )
    .await?;
    record_trace("fleet-integration-policy-delete");
    let deleted = t
        .delete_once(&format!(
            "/api/fleet/package_policies/{}",
            urlencode(INTEGRATION_POLICY_ID)
        ))
        .await
        .map_err(|error| {
            safe_recording_transport_error("deleting integration policy marker failed", error)
        })?;
    require_exact_delete_id(&deleted, INTEGRATION_POLICY_ID, "integration policy delete")?;
    recording.fixtures.push(integration_policy_fixture_in_space(
        "integration_policy_delete",
        flavor,
        version,
        t.space(),
        nonce,
        deleted,
    )?);
    record_trace("fleet-integration-policy-delete-check");
    match t
        .get(&format!(
            "/api/fleet/package_policies/{}?format=simplified",
            urlencode(INTEGRATION_POLICY_ID)
        ))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
            recording.fixtures.push(integration_policy_error_fixture(
                "integration_policy_delete_not_found",
                flavor,
                version,
                error,
            ));
            session.ownership.integration_policy = false;
        }
        Ok(_) => {
            return Err(recording_error(
                "integration policy still exists after marker delete",
            ));
        }
        Err(error) => {
            return Err(safe_recording_transport_error(
                "verifying integration policy marker delete failed",
                error,
            ));
        }
    }

    reread_marker_parent_before_mutation_with_nonce(
        t,
        &[],
        nonce,
        "rechecking integration policy parent before final delete",
    )
    .await?;
    record_trace("fleet-integration-policy-parent-delete");
    let parent_deleted = t
        .post_once(
            "/api/fleet/agent_policies/delete",
            Some(&json!({"agentPolicyId": INTEGRATION_POLICY_PARENT_ID})),
        )
        .await
        .map_err(|error| {
            safe_recording_transport_error("deleting integration policy parent failed", error)
        })?;
    require_exact_delete_id(
        &parent_deleted,
        INTEGRATION_POLICY_PARENT_ID,
        "integration policy parent delete",
    )?;
    recording.fixtures.push(integration_policy_fixture_in_space(
        "integration_policy_parent_delete",
        flavor,
        version,
        t.space(),
        nonce,
        parent_deleted,
    )?);
    record_trace("fleet-integration-policy-parent-delete-check");
    match t
        .get(&format!(
            "/api/fleet/agent_policies/{}",
            urlencode(INTEGRATION_POLICY_PARENT_ID)
        ))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
            recording.fixtures.push(integration_policy_error_fixture(
                "integration_policy_parent_delete_not_found",
                flavor,
                version,
                error,
            ));
            session.ownership.integration_policy_parent = false;
        }
        Ok(_) => {
            return Err(recording_error(
                "integration policy parent still exists after marker delete",
            ));
        }
        Err(error) => {
            return Err(safe_recording_transport_error(
                "verifying integration policy parent marker delete failed",
                error,
            ));
        }
    }

    Ok(())
}
