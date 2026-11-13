use super::lifecycle::{Context, Evidence};
use crate::diagnostics::{
    record_trace, recording_error, safe_recording_error_summary, safe_recording_transport_error,
};
use crate::fixtures::{Recording, integration_policy_error_fixture};
use crate::recorder::integration::cleanup::{
    AmbiguousMarkerCreateOwnership, claim_ambiguous_marker_integration_create_with_inputs,
};
use crate::recorder::integration::fixtures::{
    integration_policy_exchange_fixture_in_space_with_inputs, integration_policy_fixture_in_space,
    integration_policy_fixture_in_space_with_inputs,
    scope_integration_policy_list_to_marker_with_nonce_and_inputs,
};
use crate::recorder::integration::inputs::{
    marker_integration_create_body_with_nonce_and_inputs,
    marker_integration_update_body_with_nonce_and_inputs,
};
use crate::recorder::integration::inventory::{
    combine_package_policy_attempt_and_inventory_errors,
    require_unchanged_installed_package_inventory,
    reread_system_package_before_integration_policy_create,
};
use crate::recorder::integration::proofs::{
    IntegrationFixtureContext, MarkerIntegrationInputs, MarkerResponseExpectation,
    require_marker_integration_response_for_id_with_nonce_and_inputs,
    require_marker_integration_response_with_nonce_and_inputs,
    require_parent_attachment_with_nonce,
    reread_marker_integration_before_mutation_with_nonce_and_inputs,
};
use crate::recorder::markers::{
    INTEGRATION_POLICY_DUP_ID, INTEGRATION_POLICY_ID, INTEGRATION_POLICY_PARENT_ID,
    marker_integration_description, marker_integration_updated_description,
};
use crate::recorder::session::RecordingSession;
use elasticctl_core::urlencode;
use serde_json::{Value, json};

#[expect(
    clippy::needless_borrow,
    reason = "Preserve the lifecycle slice verbatim with borrowed phase inputs."
)]
pub(super) async fn record_primary(
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
    stable_inputs: &serde_json::Map<String, Value>,
    created_description: &str,
) -> elasticctl_core::Result<()> {
    let t = session.transport;

    let create_body = marker_integration_create_body_with_nonce_and_inputs(
        &package_status.version,
        nonce,
        &stable_inputs,
    );
    record_trace("fleet-integration-policy-create-preflight");
    reread_system_package_before_integration_policy_create(
        t,
        &baseline_inventory,
        &package_status.version,
    )
    .await?;
    record_trace("fleet-integration-policy-create");
    let created_result = t
        .post_once(
            "/api/fleet/package_policies?format=simplified",
            Some(&create_body),
        )
        .await;
    record_trace("fleet-integration-policy-inventory-after-create");
    let inventory_observation = require_unchanged_installed_package_inventory(
        t,
        &baseline_inventory,
        "reading installed package inventory after integration policy create failed",
    )
    .await;
    let created = match created_result {
        Ok(created) => {
            if let Err(error) = require_marker_integration_response_with_nonce_and_inputs(
                &created,
                &package_status.version,
                t.space(),
                nonce,
                Some(&created_description),
                MarkerIntegrationInputs::Exact(&stable_inputs),
                "integration policy create",
            ) {
                if claim_ambiguous_marker_integration_create_with_inputs(
                    t,
                    INTEGRATION_POLICY_ID,
                    &package_status.version,
                    nonce,
                    MarkerIntegrationInputs::Exact(&stable_inputs),
                )
                .await
                    == AmbiguousMarkerCreateOwnership::Claimed
                {
                    session.ownership.integration_policy = true;
                }
                return Err(error);
            }
            session.ownership.integration_policy = true;
            if let Err(observation) = inventory_observation {
                return Err(observation);
            }
            created
        }
        Err(error) => {
            if claim_ambiguous_marker_integration_create_with_inputs(
                t,
                INTEGRATION_POLICY_ID,
                &package_status.version,
                nonce,
                MarkerIntegrationInputs::Exact(&stable_inputs),
            )
            .await
                == AmbiguousMarkerCreateOwnership::Claimed
            {
                session.ownership.integration_policy = true;
            }
            return match inventory_observation {
                Ok(()) => Err(safe_recording_transport_error(
                    "creating integration policy marker failed",
                    error,
                )),
                Err(observation) => Err(combine_package_policy_attempt_and_inventory_errors(
                    "creating integration policy marker failed",
                    &error,
                    &observation,
                )),
            };
        }
    };
    recording
        .fixtures
        .push(integration_policy_exchange_fixture_in_space_with_inputs(
            "integration_policy_create",
            flavor,
            version,
            IntegrationFixtureContext {
                active_space: t.space(),
                nonce,
                expected_inputs: &stable_inputs,
            },
            create_body,
            created,
        )?);

    record_trace("fleet-integration-policy-get");
    let got = t
        .get(&format!(
            "/api/fleet/package_policies/{}?format=simplified",
            urlencode(INTEGRATION_POLICY_ID)
        ))
        .await
        .map_err(|error| {
            safe_recording_transport_error("reading integration policy marker failed", error)
        })?;
    require_marker_integration_response_with_nonce_and_inputs(
        &got,
        &package_status.version,
        t.space(),
        nonce,
        Some(&marker_integration_description(nonce)),
        MarkerIntegrationInputs::Exact(&stable_inputs),
        "integration policy get",
    )?;
    recording
        .fixtures
        .push(integration_policy_fixture_in_space_with_inputs(
            "integration_policy_get",
            flavor,
            version,
            t.space(),
            nonce,
            &stable_inputs,
            got,
        )?);

    record_trace("fleet-integration-policy-list");
    let mut listed = t
        .get(
            "/api/fleet/package_policies?page=1&perPage=1000&sortField=created_at&sortOrder=asc&format=simplified",
        )
        .await
        .map_err(|error| {
            safe_recording_transport_error("listing integration policy marker failed", error)
        })?;
    if scope_integration_policy_list_to_marker_with_nonce_and_inputs(
        &mut listed,
        INTEGRATION_POLICY_ID,
        &package_status.version,
        t.space(),
        nonce,
        MarkerIntegrationInputs::Exact(&stable_inputs),
    ) != 1
    {
        return Err(recording_error(
            "integration policy list never contained the marker item",
        ));
    }
    recording
        .fixtures
        .push(integration_policy_fixture_in_space_with_inputs(
            "integration_policies_list",
            flavor,
            version,
            t.space(),
            nonce,
            &stable_inputs,
            listed,
        )?);

    Ok(())
}

#[expect(
    clippy::needless_borrow,
    reason = "Preserve the lifecycle slice verbatim with borrowed phase inputs."
)]
pub(super) async fn exercise_policy(
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
    stable_inputs: &serde_json::Map<String, Value>,
) -> elasticctl_core::Result<(Value, String)> {
    let t = session.transport;

    let mut duplicate_body = marker_integration_create_body_with_nonce_and_inputs(
        &package_status.version,
        nonce,
        &stable_inputs,
    );
    duplicate_body["id"] = json!(INTEGRATION_POLICY_DUP_ID);
    record_trace("fleet-integration-policy-name-conflict-preflight");
    reread_system_package_before_integration_policy_create(
        t,
        &baseline_inventory,
        &package_status.version,
    )
    .await?;
    record_trace("fleet-integration-policy-name-conflict");
    let duplicate_result = t
        .post_once(
            "/api/fleet/package_policies?format=simplified",
            Some(&duplicate_body),
        )
        .await;
    record_trace("fleet-integration-policy-inventory-after-duplicate-create");
    let duplicate_inventory_observation = require_unchanged_installed_package_inventory(
        t,
        &baseline_inventory,
        "reading installed package inventory after duplicate integration policy create failed",
    )
    .await;
    let duplicate_description = marker_integration_description(nonce);
    match duplicate_result {
        Ok(created) => {
            if let Err(error) = require_marker_integration_response_for_id_with_nonce_and_inputs(
                &created,
                INTEGRATION_POLICY_DUP_ID,
                &package_status.version,
                t.space(),
                nonce,
                MarkerResponseExpectation {
                    description: Some(&duplicate_description),
                    inputs: MarkerIntegrationInputs::Exact(&stable_inputs),
                },
                "duplicate integration policy create",
            ) {
                if claim_ambiguous_marker_integration_create_with_inputs(
                    t,
                    INTEGRATION_POLICY_DUP_ID,
                    &package_status.version,
                    nonce,
                    MarkerIntegrationInputs::Exact(&stable_inputs),
                )
                .await
                    == AmbiguousMarkerCreateOwnership::Claimed
                {
                    session.ownership.integration_policy_dup = true;
                }
                return Err(error);
            }
            session.ownership.integration_policy_dup = true;
            return match duplicate_inventory_observation {
                Ok(()) => Err(recording_error(
                    "duplicate integration-policy name did not conflict",
                )),
                Err(observation) => Err(recording_error(format!(
                    "duplicate integration-policy name did not conflict; installed package inventory observation also failed: {}",
                    safe_recording_error_summary(&observation),
                ))),
            };
        }
        Err(error) => {
            record_trace("fleet-integration-policy-name-conflict-check");
            let ownership = claim_ambiguous_marker_integration_create_with_inputs(
                t,
                INTEGRATION_POLICY_DUP_ID,
                &package_status.version,
                nonce,
                MarkerIntegrationInputs::Exact(&stable_inputs),
            )
            .await;
            if ownership == AmbiguousMarkerCreateOwnership::Claimed {
                session.ownership.integration_policy_dup = true;
            }

            if let Err(observation) = duplicate_inventory_observation {
                return Err(combine_package_policy_attempt_and_inventory_errors(
                    "checking integration policy name conflict failed",
                    &error,
                    &observation,
                ));
            }

            if error.kind == elasticctl_core::ErrorKind::Conflict {
                match ownership {
                    AmbiguousMarkerCreateOwnership::Absent => {
                        recording.fixtures.push(integration_policy_error_fixture(
                            "integration_policy_name_conflict",
                            flavor,
                            version,
                            error,
                        ));
                    }
                    AmbiguousMarkerCreateOwnership::Claimed => {
                        return Err(recording_error(
                            "duplicate integration-policy name did not conflict",
                        ));
                    }
                    AmbiguousMarkerCreateOwnership::Unclaimed => {
                        return Err(recording_error(
                            "duplicate integration-policy id exists after a conflicting create",
                        ));
                    }
                }
            } else {
                return Err(safe_recording_transport_error(
                    "checking integration policy name conflict failed",
                    error,
                ));
            }
        }
    }

    record_trace("fleet-integration-policy-parent-get");
    let parent_attached = t
        .get(&format!(
            "/api/fleet/agent_policies/{}",
            urlencode(INTEGRATION_POLICY_PARENT_ID)
        ))
        .await
        .map_err(|error| {
            safe_recording_transport_error("reading integration policy parent failed", error)
        })?;
    require_parent_attachment_with_nonce(&parent_attached, t.space(), nonce)?;
    recording.fixtures.push(integration_policy_fixture_in_space(
        "integration_policy_parent_get",
        flavor,
        version,
        t.space(),
        nonce,
        parent_attached,
    )?);

    let update_body = marker_integration_update_body_with_nonce_and_inputs(
        &package_status.version,
        nonce,
        &stable_inputs,
    );
    reread_marker_integration_before_mutation_with_nonce_and_inputs(
        t,
        &package_status.version,
        nonce,
        MarkerIntegrationInputs::Exact(&stable_inputs),
        "rechecking integration policy marker before update",
    )
    .await?;
    record_trace("fleet-integration-policy-update");
    let updated = t
        .put_once(
            &format!(
                "/api/fleet/package_policies/{}?format=simplified",
                urlencode(INTEGRATION_POLICY_ID)
            ),
            &update_body,
        )
        .await
        .map_err(|error| {
            safe_recording_transport_error("updating integration policy marker failed", error)
        })?;
    require_marker_integration_response_with_nonce_and_inputs(
        &updated,
        &package_status.version,
        t.space(),
        nonce,
        Some(&marker_integration_updated_description(nonce)),
        MarkerIntegrationInputs::Exact(&stable_inputs),
        "integration policy update",
    )?;
    recording
        .fixtures
        .push(integration_policy_exchange_fixture_in_space_with_inputs(
            "integration_policy_update",
            flavor,
            version,
            IntegrationFixtureContext {
                active_space: t.space(),
                nonce,
                expected_inputs: &stable_inputs,
            },
            update_body,
            updated,
        )?);

    record_trace("fleet-integration-policy-round-trip");
    let round_trip = t
        .get(&format!(
            "/api/fleet/package_policies/{}?format=simplified",
            urlencode(INTEGRATION_POLICY_ID)
        ))
        .await
        .map_err(|error| {
            safe_recording_transport_error("reading integration policy round trip failed", error)
        })?;
    require_marker_integration_response_with_nonce_and_inputs(
        &round_trip,
        &package_status.version,
        t.space(),
        nonce,
        Some(&marker_integration_updated_description(nonce)),
        MarkerIntegrationInputs::Exact(&stable_inputs),
        "integration policy round trip",
    )?;
    if round_trip
        .pointer("/item/description")
        .and_then(Value::as_str)
        != Some(marker_integration_updated_description(nonce).as_str())
    {
        return Err(recording_error(
            "integration policy round trip did not retain the update description",
        ));
    }
    recording
        .fixtures
        .push(integration_policy_fixture_in_space_with_inputs(
            "integration_policy_round_trip",
            flavor,
            version,
            t.space(),
            nonce,
            &stable_inputs,
            round_trip,
        )?);

    Ok((duplicate_body, duplicate_description))
}
