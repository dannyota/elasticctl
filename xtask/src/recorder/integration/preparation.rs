use super::lifecycle::{Context, Evidence};
use crate::diagnostics::{record_trace, recording_error, safe_recording_transport_error};
use crate::fixtures::{Recording, integration_policy_error_fixture, response_fixture};
use crate::recorder::integration::cleanup::{
    AmbiguousMarkerCreateOwnership, claim_ambiguous_marker_integration_create_with_inputs,
    claim_ambiguous_marker_integration_parent_create, delete_bootstrap_marker_integration_once,
};
use crate::recorder::integration::fixtures::integration_policy_exchange_fixture_in_space;
use crate::recorder::integration::inputs::{
    export_bootstrap_marker_inputs, marker_integration_create_body_with_nonce,
    marker_integration_parent_create_body_with_nonce,
};
use crate::recorder::integration::inventory::{
    combine_package_policy_attempt_and_inventory_errors, decode_system_package_status,
    read_installed_package_inventory, reduce_system_package_status,
    require_installed_integration_package_metadata, require_unchanged_installed_package_inventory,
    reread_system_package_before_integration_policy_create,
};
use crate::recorder::integration::metadata::reduce_integration_package_metadata;
use crate::recorder::integration::proofs::{
    MarkerIntegrationInputs, require_marker_integration_response_with_nonce_and_inputs,
    reread_marker_parent_before_mutation_with_nonce,
    validate_marker_integration_parent_identity_with_nonce,
    validate_marker_integration_with_nonce_and_inputs,
};
use crate::recorder::markers::{
    INTEGRATION_POLICY_DUP_ID, INTEGRATION_POLICY_ID, INTEGRATION_POLICY_PACKAGE,
    INTEGRATION_POLICY_PARENT_ID, marker_integration_description,
};
use crate::recorder::session::{IntegrationMarkerInputs, RecordingSession};
use elasticctl_core::urlencode;
use serde_json::{Value, json};

pub(super) type Bootstrap = (
    Value,
    String,
    Value,
    serde_json::Map<String, Value>,
    serde_json::Map<String, Value>,
);

pub(super) async fn preflight(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    Context {
        flavor, version, ..
    }: Context<'_>,
) -> elasticctl_core::Result<(
    std::collections::BTreeSet<(String, String)>,
    Value,
    crate::recorder::integration::inventory::SystemPackageStatus,
)> {
    let t = session.transport;

    record_trace("integration-policies");
    record_trace("fleet-integration-policy-inventory-before");
    let baseline_inventory = read_installed_package_inventory(t).await.map_err(|error| {
        safe_recording_transport_error("reading installed package inventory failed", error)
    })?;

    record_trace("fleet-integration-policy-status");
    let package_status_body = t
        .get(&format!(
            "/api/fleet/epm/packages/{INTEGRATION_POLICY_PACKAGE}"
        ))
        .await
        .map_err(|error| {
            safe_recording_transport_error("reading system package status failed", error)
        })?;
    let package_status = decode_system_package_status(&package_status_body)?;
    let reduced_status = reduce_system_package_status(&package_status);
    recording.fixtures.push(response_fixture(
        "package_system",
        flavor,
        version,
        json!({"item": reduced_status}),
        None,
    ));
    if !package_status.installed {
        return Err(recording_error(
            "refusing to record: system package must already be installed at the status version",
        ));
    }
    let baseline_has_system = baseline_inventory
        .iter()
        .find(|(name, _)| name == INTEGRATION_POLICY_PACKAGE)
        .map(|(_, version)| version.as_str());
    if baseline_has_system != Some(package_status.version.as_str()) {
        return Err(recording_error(
            "installed system package status disagrees with the package inventory",
        ));
    }

    record_trace("fleet-integration-policy-preflight");
    match t
        .get(&format!(
            "/api/fleet/package_policies/{}?format=simplified",
            urlencode(INTEGRATION_POLICY_ID)
        ))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
            recording.fixtures.push(integration_policy_error_fixture(
                "integration_policy_not_found",
                flavor,
                version,
                error,
            ));
        }
        Ok(_) => {
            return Err(recording_error(format!(
                "refusing to record: integration policy {INTEGRATION_POLICY_ID} already exists and is not cleanup-owned"
            )));
        }
        Err(error) => {
            return Err(safe_recording_transport_error(
                "checking integration policy absence failed",
                error,
            ));
        }
    }
    match t
        .get(&format!(
            "/api/fleet/package_policies/{}?format=simplified",
            urlencode(INTEGRATION_POLICY_DUP_ID)
        ))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(recording_error(format!(
                "refusing to record: integration policy {INTEGRATION_POLICY_DUP_ID} already exists and is not cleanup-owned"
            )));
        }
        Err(error) => {
            return Err(safe_recording_transport_error(
                "checking integration policy duplicate absence failed",
                error,
            ));
        }
    }
    match t
        .get(&format!(
            "/api/fleet/agent_policies/{}",
            urlencode(INTEGRATION_POLICY_PARENT_ID)
        ))
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
            recording.fixtures.push(integration_policy_error_fixture(
                "integration_policy_parent_not_found",
                flavor,
                version,
                error,
            ));
        }
        Ok(_) => {
            return Err(recording_error(format!(
                "refusing to record: integration policy parent {INTEGRATION_POLICY_PARENT_ID} already exists and is not cleanup-owned"
            )));
        }
        Err(error) => {
            return Err(safe_recording_transport_error(
                "checking integration policy parent absence failed",
                error,
            ));
        }
    }

    Ok((baseline_inventory, package_status_body, package_status))
}

pub(super) async fn create_parent(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    Context {
        flavor,
        version,
        nonce,
    }: Context<'_>,
    Evidence {
        baseline_inventory,
        package_status,
    }: Evidence<'_>,
) -> elasticctl_core::Result<Value> {
    let t = session.transport;

    session.ownership.integration_package_inventory = Some(baseline_inventory.clone());
    session.ownership.integration_system_package_version = Some(package_status.version.clone());
    session.ownership.integration_recording_nonce = Some(nonce.to_owned());
    let parent_create_body = marker_integration_parent_create_body_with_nonce(nonce);
    record_trace("fleet-integration-policy-parent-create");
    let parent_created_result = t
        .post_once(
            "/api/fleet/agent_policies?sys_monitoring=false",
            Some(&parent_create_body),
        )
        .await;
    let parent_created = match parent_created_result {
        Ok(parent_created)
            if validate_marker_integration_parent_identity_with_nonce(
                &parent_created,
                t.space(),
                nonce,
            )
            .is_ok() =>
        {
            session.ownership.integration_policy_parent = true;
            parent_created
        }
        Ok(_) => {
            if claim_ambiguous_marker_integration_parent_create(t, nonce).await {
                session.ownership.integration_policy_parent = true;
            }
            return Err(recording_error(
                "integration policy parent create did not preserve the marker identity",
            ));
        }
        Err(error) => {
            if claim_ambiguous_marker_integration_parent_create(t, nonce).await {
                session.ownership.integration_policy_parent = true;
            }
            return Err(safe_recording_transport_error(
                "creating integration policy marker parent failed",
                error,
            ));
        }
    };
    recording
        .fixtures
        .push(integration_policy_exchange_fixture_in_space(
            "integration_policy_parent_create",
            flavor,
            version,
            t.space(),
            nonce,
            parent_create_body,
            parent_created,
        )?);

    record_trace("fleet-integration-policy-metadata");
    let package_metadata = t
        .get(&format!(
            "/api/fleet/epm/packages/{}/{}",
            urlencode(INTEGRATION_POLICY_PACKAGE),
            urlencode(&package_status.version)
        ))
        .await
        .map_err(|error| {
            safe_recording_transport_error("reading system package metadata failed", error)
        })?;
    let reduced_metadata = reduce_integration_package_metadata(
        &package_metadata,
        INTEGRATION_POLICY_PACKAGE,
        &package_status.version,
    )?;
    require_installed_integration_package_metadata(&reduced_metadata)?;
    recording.fixtures.push(response_fixture(
        "package_system_metadata",
        flavor,
        version,
        reduced_metadata,
        None,
    ));

    Ok(package_metadata)
}

#[expect(
    clippy::needless_borrow,
    reason = "Preserve the lifecycle slice verbatim with borrowed phase inputs."
)]
pub(super) async fn bootstrap(
    session: &mut RecordingSession<'_>,
    _recording: &mut Recording,
    Context { nonce, .. }: Context<'_>,
    Evidence {
        baseline_inventory,
        package_status,
    }: Evidence<'_>,
) -> elasticctl_core::Result<Bootstrap> {
    let t = session.transport;

    let bootstrap_body = marker_integration_create_body_with_nonce(&package_status.version, nonce);
    record_trace("fleet-integration-policy-bootstrap-preflight");
    reread_system_package_before_integration_policy_create(
        t,
        &baseline_inventory,
        &package_status.version,
    )
    .await?;
    record_trace("fleet-integration-policy-bootstrap-create");
    let bootstrap_result = t
        .post_once(
            "/api/fleet/package_policies?format=simplified",
            Some(&bootstrap_body),
        )
        .await;
    record_trace("fleet-integration-policy-inventory-after-bootstrap-create");
    let bootstrap_inventory_observation = require_unchanged_installed_package_inventory(
        t,
        &baseline_inventory,
        "reading installed package inventory after bootstrap integration policy create failed",
    )
    .await;
    let created_description = marker_integration_description(nonce);
    match bootstrap_result {
        Ok(created) => {
            if let Err(error) = require_marker_integration_response_with_nonce_and_inputs(
                &created,
                &package_status.version,
                t.space(),
                nonce,
                Some(&created_description),
                MarkerIntegrationInputs::BootstrapObject,
                "bootstrap integration policy create",
            ) {
                if claim_ambiguous_marker_integration_create_with_inputs(
                    t,
                    INTEGRATION_POLICY_ID,
                    &package_status.version,
                    nonce,
                    MarkerIntegrationInputs::BootstrapObject,
                )
                .await
                    == AmbiguousMarkerCreateOwnership::Claimed
                {
                    session.ownership.integration_policy = true;
                    session.ownership.integration_policy_inputs =
                        IntegrationMarkerInputs::BootstrapObject;
                }
                return Err(error);
            }
            session.ownership.integration_policy = true;
            session.ownership.integration_policy_inputs = IntegrationMarkerInputs::BootstrapObject;
            if let Err(observation) = bootstrap_inventory_observation {
                return Err(observation);
            }
        }
        Err(error) => {
            if claim_ambiguous_marker_integration_create_with_inputs(
                t,
                INTEGRATION_POLICY_ID,
                &package_status.version,
                nonce,
                MarkerIntegrationInputs::BootstrapObject,
            )
            .await
                == AmbiguousMarkerCreateOwnership::Claimed
            {
                session.ownership.integration_policy = true;
                session.ownership.integration_policy_inputs =
                    IntegrationMarkerInputs::BootstrapObject;
            }
            return match bootstrap_inventory_observation {
                Ok(()) => Err(safe_recording_transport_error(
                    "creating bootstrap integration policy marker failed",
                    error,
                )),
                Err(observation) => Err(combine_package_policy_attempt_and_inventory_errors(
                    "creating bootstrap integration policy marker failed",
                    &error,
                    &observation,
                )),
            };
        }
    }

    record_trace("fleet-integration-policy-bootstrap-get");
    let bootstrap_read = t
        .get(&format!(
            "/api/fleet/package_policies/{}?format=simplified",
            urlencode(INTEGRATION_POLICY_ID)
        ))
        .await
        .map_err(|error| {
            safe_recording_transport_error(
                "reading bootstrap integration policy marker failed",
                error,
            )
        })?;
    let bootstrap_item = validate_marker_integration_with_nonce_and_inputs(
        &bootstrap_read,
        INTEGRATION_POLICY_ID,
        &package_status.version,
        t.space(),
        nonce,
        Some(&created_description),
        MarkerIntegrationInputs::BootstrapObject,
    )?
    .clone();

    record_trace("fleet-integration-policy-bootstrap-export");
    let stable_inputs =
        export_bootstrap_marker_inputs(t, &package_status.version, nonce, &bootstrap_item).await?;
    session.ownership.integration_policy_inputs =
        IntegrationMarkerInputs::Exact(stable_inputs.clone());

    record_trace("fleet-integration-policy-bootstrap-delete");
    delete_bootstrap_marker_integration_once(t, &package_status.version, nonce, &stable_inputs)
        .await?;
    session.ownership.integration_policy = false;
    reread_marker_parent_before_mutation_with_nonce(
        t,
        &[],
        nonce,
        "rechecking integration policy parent after bootstrap delete",
    )
    .await?;

    Ok((
        bootstrap_body,
        created_description,
        bootstrap_read,
        bootstrap_item,
        stable_inputs,
    ))
}
