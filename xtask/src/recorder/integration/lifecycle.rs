use super::exercise::{exercise_policy, record_primary};
use super::preparation::{bootstrap, create_parent, preflight};
use super::teardown::delete_markers;
use crate::diagnostics::record_trace;
use crate::fixtures::Recording;
use crate::recorder::markers::integration_recording_nonce;
use crate::recorder::session::RecordingSession;

pub(crate) async fn record_integration_policies(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    flavor: &str,
    version: &str,
) -> elasticctl_core::Result<()> {
    let nonce = integration_recording_nonce();
    record_integration_policies_with_nonce(session, recording, flavor, version, &nonce).await
}

async fn record_integration_policies_with_nonce(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    flavor: &str,
    version: &str,
    nonce: &str,
) -> elasticctl_core::Result<()> {
    let (baseline_inventory, _package_status_body, package_status) = preflight(
        session,
        recording,
        Context {
            flavor,
            version,
            nonce,
        },
    )
    .await?;
    let _package_metadata = create_parent(
        session,
        recording,
        Context {
            flavor,
            version,
            nonce,
        },
        Evidence {
            baseline_inventory: &baseline_inventory,
            package_status: &package_status,
        },
    )
    .await?;
    let (_bootstrap_body, created_description, _bootstrap_read, _bootstrap_item, stable_inputs) =
        bootstrap(
            session,
            recording,
            Context {
                flavor,
                version,
                nonce,
            },
            Evidence {
                baseline_inventory: &baseline_inventory,
                package_status: &package_status,
            },
        )
        .await?;
    record_primary(
        session,
        recording,
        Context {
            flavor,
            version,
            nonce,
        },
        Evidence {
            baseline_inventory: &baseline_inventory,
            package_status: &package_status,
        },
        &stable_inputs,
        &created_description,
    )
    .await?;
    let (_duplicate_body, _duplicate_description) = exercise_policy(
        session,
        recording,
        Context {
            flavor,
            version,
            nonce,
        },
        Evidence {
            baseline_inventory: &baseline_inventory,
            package_status: &package_status,
        },
        &stable_inputs,
    )
    .await?;
    delete_markers(
        session,
        recording,
        Context {
            flavor,
            version,
            nonce,
        },
        Evidence {
            baseline_inventory: &baseline_inventory,
            package_status: &package_status,
        },
        &stable_inputs,
    )
    .await?;

    record_trace("fleet-integration-policy-cleanup");
    session.cleanup_integration_resources().await
}

#[derive(Clone, Copy)]
pub(super) struct Context<'a> {
    pub(super) flavor: &'a str,
    pub(super) version: &'a str,
    pub(super) nonce: &'a str,
}

#[derive(Clone, Copy)]
pub(super) struct Evidence<'a> {
    pub(super) baseline_inventory: &'a std::collections::BTreeSet<(String, String)>,
    pub(super) package_status: &'a crate::recorder::integration::inventory::SystemPackageStatus,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::Recording;
    use crate::recorder::integration::inputs::marker_integration_create_body;
    use crate::recorder::integration::inputs::marker_integration_create_body_with_nonce_and_inputs;
    use crate::recorder::integration::inputs::marker_integration_parent_create_body;
    use crate::recorder::integration::inputs::marker_integration_update_body_with_nonce_and_inputs;
    use crate::recorder::markers::INTEGRATION_POLICY_DESCRIPTION;
    use crate::recorder::markers::INTEGRATION_POLICY_DUP_ID;
    use crate::recorder::markers::INTEGRATION_POLICY_ID;
    use crate::recorder::markers::INTEGRATION_POLICY_PACKAGE;
    use crate::recorder::markers::INTEGRATION_POLICY_PARENT_ID;
    use crate::recorder::markers::INTEGRATION_POLICY_PARENT_NAME;
    use crate::recorder::markers::INTEGRATION_POLICY_UPDATED_DESCRIPTION;
    use crate::recorder::markers::TEST_INTEGRATION_RECORDING_NONCE;

    use crate::recorder::session::CleanupOwnership;
    use crate::recorder::session::IntegrationMarkerInputs;
    use crate::recorder::session::RecordingSession;
    use crate::recorder::test_support::AmbiguousCreateOutcome;
    use crate::recorder::test_support::BootstrapExportFailure;
    use crate::recorder::test_support::IntegrationCreatePreflightDrift;
    use crate::recorder::test_support::IntegrationLifecycleFailure;
    use crate::recorder::test_support::IntegrationLifecycleSwap;
    use crate::recorder::test_support::OTHER_INTEGRATION_RECORDING_NONCE;
    use crate::recorder::test_support::installed_system_inventory;
    use crate::recorder::test_support::installed_system_status;
    use crate::recorder::test_support::marker_integration_parent_response;
    use crate::recorder::test_support::marker_integration_response;
    use crate::recorder::test_support::marker_integration_response_with_inputs;
    use crate::recorder::test_support::materialized_marker_inputs;
    use crate::recorder::test_support::materialized_system_package_metadata;
    use crate::recorder::test_support::mock_transport;
    use crate::recorder::test_support::mount_bootstrap_export_failure_lifecycle;
    use crate::recorder::test_support::mount_integration_lifecycle;
    use crate::recorder::test_support::mount_integration_lifecycle_with_recorded_create;
    use crate::recorder::test_support::mount_integration_lifecycle_with_revalidation_changes;
    use crate::recorder::test_support::mount_integration_lifecycle_with_revalidation_race;
    use crate::recorder::test_support::mount_parent_create_ambiguous_winner;
    use crate::recorder::test_support::mount_primary_create_ambiguous_winner;
    use crate::recorder::test_support::mount_primary_create_with_failed_inventory_observation;

    use crate::recorder::test_support::unsafe_marker_integration_fields;
    use crate::recorder::test_support::unsafe_marker_parent_fields;
    use serde_json::Map;
    use serde_json::Value;
    use serde_json::json;
    use std::path::PathBuf;
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::body_json;
    use wiremock::matchers::method;
    use wiremock::matchers::path;
    use wiremock::matchers::query_param;

    fn request_sequence_and_body_digest(requests: &[wiremock::Request]) -> (Vec<String>, u64) {
        let mut digest = 0xcbf29ce484222325_u64;
        let lines = requests
            .iter()
            .map(|request| {
                let mut line = format!("{} {}", request.method, request.url.path());
                if let Some(query) = request.url.query().filter(|query| !query.is_empty()) {
                    line.push('?');
                    line.push_str(query);
                }
                for byte in line.as_bytes().iter().chain(&request.body) {
                    digest ^= u64::from(*byte);
                    digest = digest.wrapping_mul(0x100000001b3);
                }
                line
            })
            .collect();
        (lines, digest)
    }

    fn buffered_fixture_digest(recording: &Recording) -> u64 {
        let mut digest = 0xcbf29ce484222325_u64;
        for fixture in &recording.fixtures {
            let name = format!("{}.json", fixture.name);
            let encoded = serde_json::to_string_pretty(&fixture.document).expect("fixture JSON");
            for byte in name.as_bytes().iter().chain(encoded.as_bytes()) {
                digest ^= u64::from(*byte);
                digest = digest.wrapping_mul(0x100000001b3);
            }
        }
        digest
    }

    #[tokio::test]
    async fn integration_recorder_bootstraps_materialized_inputs_before_public_recording() {
        let server = MockServer::start().await;
        let inputs = materialized_marker_inputs();
        let policy_state = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let parent_created = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": {"number": "9.6.0", "build_flavor": "serverless"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortOrder", "asc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_inventory()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_status()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(materialized_system_package_metadata()),
            )
            .mount(&server)
            .await;

        let policy_state_for_reads = policy_state.clone();
        let inputs_for_reads = inputs.clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                match policy_state_for_reads.load(std::sync::atomic::Ordering::SeqCst) {
                    1 => ResponseTemplate::new(200).set_body_json(
                        marker_integration_response_with_inputs(
                            INTEGRATION_POLICY_DESCRIPTION,
                            TEST_INTEGRATION_RECORDING_NONCE,
                            &inputs_for_reads,
                        ),
                    ),
                    2 => ResponseTemplate::new(200).set_body_json(
                        marker_integration_response_with_inputs(
                            INTEGRATION_POLICY_DESCRIPTION,
                            TEST_INTEGRATION_RECORDING_NONCE,
                            &inputs_for_reads,
                        ),
                    ),
                    3 => ResponseTemplate::new(200).set_body_json(
                        marker_integration_response_with_inputs(
                            INTEGRATION_POLICY_UPDATED_DESCRIPTION,
                            TEST_INTEGRATION_RECORDING_NONCE,
                            &inputs_for_reads,
                        ),
                    ),
                    _ => ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})),
                }
            })
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_DUP_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})))
            .mount(&server)
            .await;

        let policy_state_for_parent_reads = policy_state.clone();
        let parent_created_for_reads = parent_created.clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                if !parent_created_for_reads.load(std::sync::atomic::Ordering::SeqCst) {
                    return ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}));
                }
                let mut parent = marker_integration_parent_response();
                parent["item"]["package_policies"] =
                    match policy_state_for_parent_reads.load(std::sync::atomic::Ordering::SeqCst) {
                        1..=3 => json!([INTEGRATION_POLICY_ID]),
                        _ => json!([]),
                    };
                ResponseTemplate::new(200).set_body_json(parent)
            })
            .mount(&server)
            .await;
        let parent_created_for_create = parent_created.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies"))
            .and(query_param("sys_monitoring", "false"))
            .and(body_json(marker_integration_parent_create_body()))
            .respond_with(move |_: &wiremock::Request| {
                parent_created_for_create.store(true, std::sync::atomic::Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(marker_integration_parent_response())
            })
            .expect(1)
            .mount(&server)
            .await;

        let bootstrap_body = marker_integration_create_body("2.0.0");
        let policy_state_for_bootstrap = policy_state.clone();
        let inputs_for_bootstrap = inputs.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(bootstrap_body))
            .respond_with(move |_: &wiremock::Request| {
                assert_eq!(
                    policy_state_for_bootstrap.swap(1, std::sync::atomic::Ordering::SeqCst),
                    0,
                    "bootstrap must be the first primary create"
                );
                ResponseTemplate::new(200).set_body_json(marker_integration_response_with_inputs(
                    INTEGRATION_POLICY_DESCRIPTION,
                    TEST_INTEGRATION_RECORDING_NONCE,
                    &inputs_for_bootstrap,
                ))
            })
            .expect(1)
            .mount(&server)
            .await;
        let recorded_body = marker_integration_create_body_with_nonce_and_inputs(
            "2.0.0",
            TEST_INTEGRATION_RECORDING_NONCE,
            &inputs,
        );
        let policy_state_for_recorded = policy_state.clone();
        let inputs_for_recorded = inputs.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(recorded_body.clone()))
            .respond_with(move |_: &wiremock::Request| {
                assert_eq!(
                    policy_state_for_recorded.swap(2, std::sync::atomic::Ordering::SeqCst),
                    0,
                    "recorded create must follow bootstrap deletion"
                );
                ResponseTemplate::new(200).set_body_json(marker_integration_response_with_inputs(
                    INTEGRATION_POLICY_DESCRIPTION,
                    TEST_INTEGRATION_RECORDING_NONCE,
                    &inputs_for_recorded,
                ))
            })
            .expect(1)
            .mount(&server)
            .await;
        let mut duplicate_body = recorded_body;
        duplicate_body["id"] = json!(INTEGRATION_POLICY_DUP_ID);
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(duplicate_body))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({"statusCode": 409})))
            .expect(1)
            .mount(&server)
            .await;
        let policy_state_for_list = policy_state.clone();
        let inputs_for_list = inputs.clone();
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("page", "1"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortField", "created_at"))
            .and(query_param("sortOrder", "asc"))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                assert_eq!(
                    policy_state_for_list.load(std::sync::atomic::Ordering::SeqCst),
                    2,
                    "the recorded list must follow the second create"
                );
                ResponseTemplate::new(200).set_body_json(json!({
                    "items": [marker_integration_response_with_inputs(
                        INTEGRATION_POLICY_DESCRIPTION,
                        TEST_INTEGRATION_RECORDING_NONCE,
                        &inputs_for_list,
                    )["item"].clone()],
                    "total": 1,
                    "page": 1,
                    "perPage": 1000,
                }))
            })
            .expect(1)
            .mount(&server)
            .await;
        let update_body = marker_integration_update_body_with_nonce_and_inputs(
            "2.0.0",
            TEST_INTEGRATION_RECORDING_NONCE,
            &inputs,
        );
        let policy_state_for_update = policy_state.clone();
        let inputs_for_update = inputs.clone();
        Mock::given(method("PUT"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .and(body_json(update_body))
            .respond_with(move |_: &wiremock::Request| {
                assert_eq!(
                    policy_state_for_update.swap(3, std::sync::atomic::Ordering::SeqCst),
                    2,
                    "the update must preserve the recorded input map"
                );
                ResponseTemplate::new(200).set_body_json(marker_integration_response_with_inputs(
                    INTEGRATION_POLICY_UPDATED_DESCRIPTION,
                    TEST_INTEGRATION_RECORDING_NONCE,
                    &inputs_for_update,
                ))
            })
            .expect(1)
            .mount(&server)
            .await;
        let policy_state_for_delete = policy_state.clone();
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                let prior = policy_state_for_delete.load(std::sync::atomic::Ordering::SeqCst);
                match prior {
                    1 => {
                        policy_state_for_delete.store(0, std::sync::atomic::Ordering::SeqCst);
                        ResponseTemplate::new(200)
                            .set_body_json(json!({"id": INTEGRATION_POLICY_ID}))
                    }
                    3 => {
                        policy_state_for_delete.store(4, std::sync::atomic::Ordering::SeqCst);
                        ResponseTemplate::new(200)
                            .set_body_json(json!({"id": INTEGRATION_POLICY_ID}))
                    }
                    _ => ResponseTemplate::new(409).set_body_json(json!({"statusCode": 409})),
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        let parent_created_for_delete = parent_created.clone();
        let policy_state_for_parent_delete = policy_state.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies/delete"))
            .and(body_json(
                json!({"agentPolicyId": INTEGRATION_POLICY_PARENT_ID}),
            ))
            .respond_with(move |_: &wiremock::Request| {
                if policy_state_for_parent_delete.load(std::sync::atomic::Ordering::SeqCst) == 4 {
                    parent_created_for_delete.store(false, std::sync::atomic::Ordering::SeqCst);
                    ResponseTemplate::new(200).set_body_json(json!({
                        "id": INTEGRATION_POLICY_PARENT_ID,
                        "name": INTEGRATION_POLICY_PARENT_NAME,
                    }))
                } else {
                    ResponseTemplate::new(409).set_body_json(json!({"statusCode": 409}))
                }
            })
            .expect(1)
            .mount(&server)
            .await;

        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let mut recording = Recording {
            dir: PathBuf::from("unused-in-test"),
            fixtures: Vec::new(),
        };

        record_integration_policies_with_nonce(
            &mut session,
            &mut recording,
            "test",
            "9.6.0",
            TEST_INTEGRATION_RECORDING_NONCE,
        )
        .await
        .expect("the materialized bootstrap inputs must be exported before recording");

        let expected_inputs = Value::Object(inputs.clone());
        let fixture = |name| {
            recording
                .fixtures
                .iter()
                .find(|fixture| fixture.name == name)
                .expect("recorded fixture")
        };
        assert_eq!(
            fixture("integration_policy_create").document["request"]["inputs"],
            expected_inputs
        );
        assert_eq!(
            fixture("integration_policy_create").document["response"]["item"]["inputs"],
            Value::Object(inputs.clone())
        );
        assert_eq!(
            fixture("integration_policy_get").document["response"]["item"]["inputs"],
            Value::Object(inputs.clone())
        );
        assert_eq!(
            fixture("integration_policies_list").document["response"]["items"][0]["inputs"],
            Value::Object(inputs.clone())
        );
        assert_eq!(
            fixture("integration_policy_update").document["request"]["inputs"],
            Value::Object(inputs.clone())
        );
        assert_eq!(
            fixture("integration_policy_update").document["response"]["item"]["inputs"],
            Value::Object(inputs.clone())
        );
        assert_eq!(
            fixture("integration_policy_round_trip").document["response"]["item"]["inputs"],
            Value::Object(inputs.clone())
        );
        assert!(
            recording
                .fixtures
                .iter()
                .all(|fixture| !fixture.name.contains("bootstrap")),
            "the bootstrap exchange must never become a public fixture"
        );
        let requests = server.received_requests().await.expect("requests");
        let primary_posts: Vec<_> = requests
            .iter()
            .filter_map(|request| {
                (request.method.as_str() == "POST"
                    && request.url.path() == "/api/fleet/package_policies")
                    .then(|| request.body_json::<Value>().ok())
                    .flatten()
                    .filter(|body| body["id"] == INTEGRATION_POLICY_ID)
            })
            .collect();
        assert_eq!(
            primary_posts.len(),
            2,
            "bootstrap and recorded creates are distinct"
        );
        assert_eq!(primary_posts[0]["inputs"], json!({}));
        assert_eq!(primary_posts[1]["inputs"], Value::Object(inputs));

        const MATERIALIZED_INPUTS_LINES: &[&str] = &[
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "GET /api/fleet/epm/packages/system",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy-dup?format=simplified",
            "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            "POST /api/fleet/agent_policies?sys_monitoring=false",
            "GET /api/fleet/epm/packages/system/2.0.0",
            "GET /api/fleet/epm/packages/system",
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "POST /api/fleet/package_policies?format=simplified",
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/status",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            "GET /api/fleet/epm/packages/system",
            "GET /api/fleet/epm/packages/system/2.0.0",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "DELETE /api/fleet/package_policies/elasticctl-sample-integration-policy",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            "GET /api/fleet/epm/packages/system",
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "POST /api/fleet/package_policies?format=simplified",
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/package_policies?page=1&perPage=1000&sortField=created_at&sortOrder=asc&format=simplified",
            "GET /api/fleet/epm/packages/system",
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "POST /api/fleet/package_policies?format=simplified",
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy-dup?format=simplified",
            "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "PUT /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "DELETE /api/fleet/package_policies/elasticctl-sample-integration-policy",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            "POST /api/fleet/agent_policies/delete",
            "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy-dup?format=simplified",
            "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
        ];
        const MATERIALIZED_INPUTS_BODY_DIGEST: u64 = 16607917844578840776;
        const MATERIALIZED_INPUTS_FIXTURE_DIGEST: u64 = 12733467333436562836;
        let (lines, body_digest) = request_sequence_and_body_digest(&requests);
        assert_eq!(
            lines, MATERIALIZED_INPUTS_LINES,
            "complete materialized lifecycle requests"
        );
        assert_eq!(
            body_digest, MATERIALIZED_INPUTS_BODY_DIGEST,
            "materialized lifecycle request bytes"
        );
        assert_eq!(
            buffered_fixture_digest(&recording),
            MATERIALIZED_INPUTS_FIXTURE_DIGEST,
            "materialized lifecycle fixture bytes"
        );
    }

    #[tokio::test]
    async fn bootstrap_export_failures_cleanup_only_the_same_nonce_marker_without_fixture_leaks() {
        for (failure, expected_error, private_fragment) in [
            (
                BootstrapExportFailure::Transport,
                "exporting bootstrap integration policy failed",
                "private bootstrap export transport body",
            ),
            (
                BootstrapExportFailure::Secret,
                "exporting bootstrap integration policy failed",
                "private-bootstrap-secret",
            ),
            (
                BootstrapExportFailure::SensitiveName,
                "exported bootstrap integration policy contained sensitive-looking input fields",
                "private-bootstrap-value",
            ),
            (
                BootstrapExportFailure::ChangedNormalizedInputs,
                "exported bootstrap integration policy inputs did not match the marker read",
                "private-bootstrap-value",
            ),
        ] {
            let server = MockServer::start().await;
            mount_bootstrap_export_failure_lifecycle(&server, failure).await;
            let transport = mock_transport(&server);
            let mut session = RecordingSession {
                transport: &transport,
                ownership: CleanupOwnership::default(),
            };
            let mut recording = Recording {
                dir: PathBuf::from("unused-in-test"),
                fixtures: Vec::new(),
            };

            let error = record_integration_policies_with_nonce(
                &mut session,
                &mut recording,
                "test",
                "9.6.0",
                TEST_INTEGRATION_RECORDING_NONCE,
            )
            .await
            .expect_err("a bootstrap export failure must stop before public recording");
            assert_eq!(error.message, expected_error, "{failure:?}");
            assert!(
                !error.message.contains(private_fragment),
                "{failure:?} error must not echo private transport or input content"
            );
            assert!(
                !error.message.contains(TEST_INTEGRATION_RECORDING_NONCE),
                "{failure:?} error must not echo the nonce"
            );
            assert!(session.ownership.integration_policy, "{failure:?}");
            assert!(matches!(
                session.ownership.integration_policy_inputs,
                IntegrationMarkerInputs::BootstrapObject
            ));
            assert!(
                recording
                    .fixtures
                    .iter()
                    .all(|fixture| !fixture.name.contains("bootstrap")),
                "{failure:?} bootstrap traffic must never become a fixture"
            );
            assert!(
                recording.fixtures.iter().all(|fixture| {
                    !fixture.document.to_string().contains(private_fragment)
                        && !fixture
                            .document
                            .to_string()
                            .contains(TEST_INTEGRATION_RECORDING_NONCE)
                }),
                "{failure:?} public fixture reducers must not retain private values or nonce"
            );

            session
                .cleanup_integration_resources()
                .await
                .expect("a same-nonce bootstrap marker is cleanup-owned after export failure");
            assert!(!session.ownership.integration_policy, "{failure:?}");
            assert!(!session.ownership.integration_policy_parent, "{failure:?}");

            let requests = server.received_requests().await.expect("requests");
            let primary_posts = requests
                .iter()
                .filter(|request| {
                    request.method.as_str() == "POST"
                        && request.url.path() == "/api/fleet/package_policies"
                        && request
                            .body_json::<Value>()
                            .ok()
                            .is_some_and(|body| body["id"] == INTEGRATION_POLICY_ID)
                })
                .count();
            assert_eq!(
                primary_posts, 1,
                "{failure:?} must not retry or record a second create"
            );
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| {
                        request.method.as_str() == "DELETE"
                            && request.url.path()
                                == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}")
                    })
                    .count(),
                1,
                "{failure:?} cleanup deletes exactly the owned bootstrap marker once"
            );

            const BOOTSTRAP_EXPORT_TRANSPORT_LINES: &[&str] = &[
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "GET /api/fleet/epm/packages/system",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy-dup?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "POST /api/fleet/agent_policies?sys_monitoring=false",
                "GET /api/fleet/epm/packages/system/2.0.0",
                "GET /api/fleet/epm/packages/system",
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "POST /api/fleet/package_policies?format=simplified",
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/status",
                "GET /api/status",
                "GET /api/status",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "DELETE /api/fleet/package_policies/elasticctl-sample-integration-policy",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "POST /api/fleet/agent_policies/delete",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy-dup?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            ];
            const BOOTSTRAP_EXPORT_SECRET_LINES: &[&str] = &[
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "GET /api/fleet/epm/packages/system",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy-dup?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "POST /api/fleet/agent_policies?sys_monitoring=false",
                "GET /api/fleet/epm/packages/system/2.0.0",
                "GET /api/fleet/epm/packages/system",
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "POST /api/fleet/package_policies?format=simplified",
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/status",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "GET /api/fleet/epm/packages/system",
                "GET /api/fleet/epm/packages/system/2.0.0",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "DELETE /api/fleet/package_policies/elasticctl-sample-integration-policy",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "POST /api/fleet/agent_policies/delete",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy-dup?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            ];
            const BOOTSTRAP_EXPORT_SENSITIVE_NAME_LINES: &[&str] = &[
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "GET /api/fleet/epm/packages/system",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy-dup?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "POST /api/fleet/agent_policies?sys_monitoring=false",
                "GET /api/fleet/epm/packages/system/2.0.0",
                "GET /api/fleet/epm/packages/system",
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "POST /api/fleet/package_policies?format=simplified",
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/status",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "GET /api/fleet/epm/packages/system",
                "GET /api/fleet/epm/packages/system/2.0.0",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "DELETE /api/fleet/package_policies/elasticctl-sample-integration-policy",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "POST /api/fleet/agent_policies/delete",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy-dup?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            ];
            const BOOTSTRAP_EXPORT_CHANGED_INPUTS_LINES: &[&str] = &[
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "GET /api/fleet/epm/packages/system",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy-dup?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "POST /api/fleet/agent_policies?sys_monitoring=false",
                "GET /api/fleet/epm/packages/system/2.0.0",
                "GET /api/fleet/epm/packages/system",
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "POST /api/fleet/package_policies?format=simplified",
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/status",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "GET /api/fleet/epm/packages/system",
                "GET /api/fleet/epm/packages/system/2.0.0",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "DELETE /api/fleet/package_policies/elasticctl-sample-integration-policy",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "POST /api/fleet/agent_policies/delete",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
                "GET /api/fleet/package_policies/elasticctl-sample-integration-policy-dup?format=simplified",
                "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            ];
            let expected_lines = match failure {
                BootstrapExportFailure::Transport => BOOTSTRAP_EXPORT_TRANSPORT_LINES,
                BootstrapExportFailure::Secret => BOOTSTRAP_EXPORT_SECRET_LINES,
                BootstrapExportFailure::SensitiveName => BOOTSTRAP_EXPORT_SENSITIVE_NAME_LINES,
                BootstrapExportFailure::ChangedNormalizedInputs => {
                    BOOTSTRAP_EXPORT_CHANGED_INPUTS_LINES
                }
            };
            let (lines, _) = request_sequence_and_body_digest(&requests);
            assert_eq!(
                lines, expected_lines,
                "{failure:?} complete bootstrap export failure requests"
            );
        }
    }

    #[tokio::test]
    async fn recorded_create_refuses_a_changed_second_response_and_leaves_it_unowned() {
        let server = MockServer::start().await;
        let inputs = materialized_marker_inputs();
        let changed_inputs =
            Map::from_iter([("system-log".to_string(), json!({"enabled": false}))]);
        let policy_state = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let parent_created = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": {"number": "9.6.0", "build_flavor": "serverless"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortOrder", "asc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_inventory()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_status()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(materialized_system_package_metadata()),
            )
            .mount(&server)
            .await;

        let policy_state_for_reads = policy_state.clone();
        let inputs_for_reads = inputs.clone();
        let changed_inputs_for_reads = changed_inputs.clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                match policy_state_for_reads.load(std::sync::atomic::Ordering::SeqCst) {
                    1 => ResponseTemplate::new(200).set_body_json(
                        marker_integration_response_with_inputs(
                            INTEGRATION_POLICY_DESCRIPTION,
                            TEST_INTEGRATION_RECORDING_NONCE,
                            &inputs_for_reads,
                        ),
                    ),
                    2 => ResponseTemplate::new(200).set_body_json(
                        marker_integration_response_with_inputs(
                            INTEGRATION_POLICY_DESCRIPTION,
                            TEST_INTEGRATION_RECORDING_NONCE,
                            &changed_inputs_for_reads,
                        ),
                    ),
                    _ => ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})),
                }
            })
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_DUP_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})))
            .mount(&server)
            .await;

        let policy_state_for_parent_reads = policy_state.clone();
        let parent_created_for_reads = parent_created.clone();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                if !parent_created_for_reads.load(std::sync::atomic::Ordering::SeqCst) {
                    return ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}));
                }
                let mut parent = marker_integration_parent_response();
                parent["item"]["package_policies"] =
                    match policy_state_for_parent_reads.load(std::sync::atomic::Ordering::SeqCst) {
                        0 => json!([]),
                        _ => json!([INTEGRATION_POLICY_ID]),
                    };
                ResponseTemplate::new(200).set_body_json(parent)
            })
            .mount(&server)
            .await;
        let parent_created_for_create = parent_created.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies"))
            .and(query_param("sys_monitoring", "false"))
            .and(body_json(marker_integration_parent_create_body()))
            .respond_with(move |_: &wiremock::Request| {
                parent_created_for_create.store(true, std::sync::atomic::Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(marker_integration_parent_response())
            })
            .expect(1)
            .mount(&server)
            .await;

        let bootstrap_state = policy_state.clone();
        let inputs_for_bootstrap = inputs.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(marker_integration_create_body("2.0.0")))
            .respond_with(move |_: &wiremock::Request| {
                assert_eq!(
                    bootstrap_state.swap(1, std::sync::atomic::Ordering::SeqCst),
                    0,
                    "bootstrap must create the first primary marker"
                );
                ResponseTemplate::new(200).set_body_json(marker_integration_response_with_inputs(
                    INTEGRATION_POLICY_DESCRIPTION,
                    TEST_INTEGRATION_RECORDING_NONCE,
                    &inputs_for_bootstrap,
                ))
            })
            .expect(1)
            .mount(&server)
            .await;
        let recorded_body = marker_integration_create_body_with_nonce_and_inputs(
            "2.0.0",
            TEST_INTEGRATION_RECORDING_NONCE,
            &inputs,
        );
        let recorded_state = policy_state.clone();
        let changed_inputs_for_recorded = changed_inputs.clone();
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(recorded_body))
            .respond_with(move |_: &wiremock::Request| {
                assert_eq!(
                    recorded_state.swap(2, std::sync::atomic::Ordering::SeqCst),
                    0,
                    "the recorded create must wait for bootstrap absence"
                );
                ResponseTemplate::new(200).set_body_json(marker_integration_response_with_inputs(
                    INTEGRATION_POLICY_DESCRIPTION,
                    TEST_INTEGRATION_RECORDING_NONCE,
                    &changed_inputs_for_recorded,
                ))
            })
            .expect(1)
            .mount(&server)
            .await;
        let bootstrap_delete_state = policy_state.clone();
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                assert_eq!(
                    bootstrap_delete_state.swap(0, std::sync::atomic::Ordering::SeqCst),
                    1,
                    "only the bootstrap marker is deletion-proven before the second create"
                );
                ResponseTemplate::new(200).set_body_json(json!({"id": INTEGRATION_POLICY_ID}))
            })
            .expect(1)
            .mount(&server)
            .await;

        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let mut recording = Recording {
            dir: PathBuf::from("unused-in-test"),
            fixtures: Vec::new(),
        };
        let error = record_integration_policies_with_nonce(
            &mut session,
            &mut recording,
            "test",
            "9.6.0",
            TEST_INTEGRATION_RECORDING_NONCE,
        )
        .await
        .expect_err("a changed second create response cannot be recorded");
        assert_eq!(
            error.message,
            "integration policy create: integration response did not preserve the marker identity"
        );
        assert!(!session.ownership.integration_policy);
        assert!(session.ownership.integration_policy_parent);
        assert!(
            recording
                .fixtures
                .iter()
                .all(|fixture| fixture.name != "integration_policy_create"),
            "the changed second create response must never enter a fixture"
        );

        session
            .cleanup_integration_resources()
            .await
            .expect_err("an unproven changed second marker must block parent cleanup");
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.method.as_str() == "DELETE"
                        && request.url.path()
                            == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}")
                })
                .count(),
            1,
            "cleanup must not delete the changed second marker"
        );
        assert!(requests.iter().all(|request| {
            !(request.method.as_str() == "POST"
                && request.url.path() == "/api/fleet/agent_policies/delete")
        }));
    }

    #[tokio::test]
    async fn integration_recorder_refuses_an_absent_system_package_before_marker_writes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortOrder", "asc"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"items": [], "total": 0})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
                "name": "system", "version": "2.0.0", "status": "not_installed"
            }})))
            .expect(1)
            .mount(&server)
            .await;

        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let mut recording = Recording {
            dir: PathBuf::from("unused-in-test"),
            fixtures: Vec::new(),
        };

        let error = record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
            .await
            .expect_err("an absent package must refuse the recorder locally");

        assert_eq!(
            error.message,
            "refusing to record: system package must already be installed at the status version"
        );
        let requests = server.received_requests().await.expect("requests");
        assert!(
            requests
                .iter()
                .all(|request| { !matches!(request.method.as_str(), "POST" | "PUT" | "DELETE") })
        );

        const ABSENT_SYSTEM_PACKAGE_LINES: &[&str] = &[
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "GET /api/fleet/epm/packages/system",
        ];
        let (lines, _) = request_sequence_and_body_digest(&requests);
        assert_eq!(
            lines, ABSENT_SYSTEM_PACKAGE_LINES,
            "complete absent package preflight requests"
        );
    }

    #[tokio::test]
    async fn integration_recorder_refuses_a_system_version_missing_from_the_baseline() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortOrder", "asc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"name": "system", "status": "installed", "version": "1.9.0"}],
                "total": 1
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
                "name": "system", "version": "2.0.0", "status": "installed",
                "installationInfo": {"version": "2.0.0"}
            }})))
            .expect(1)
            .mount(&server)
            .await;

        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let mut recording = Recording {
            dir: PathBuf::from("unused-in-test"),
            fixtures: Vec::new(),
        };

        let error = record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
            .await
            .expect_err("a status version missing from the baseline must refuse recording");

        assert_eq!(
            error.message,
            "installed system package status disagrees with the package inventory"
        );
        let requests = server.received_requests().await.expect("requests");
        assert!(
            requests
                .iter()
                .all(|request| { !matches!(request.method.as_str(), "POST" | "PUT" | "DELETE") })
        );
    }

    #[tokio::test]
    async fn integration_recorder_refuses_package_state_drift_before_each_create() {
        let cases = [
            (
                IntegrationCreatePreflightDrift::BootstrapMissing,
                "bootstrap package absence",
                "bootstrap",
            ),
            (
                IntegrationCreatePreflightDrift::BootstrapMalformed,
                "malformed bootstrap package status",
                "bootstrap",
            ),
            (
                IntegrationCreatePreflightDrift::BootstrapMetadataNotInstalled,
                "non-installed bootstrap package metadata",
                "bootstrap",
            ),
            (
                IntegrationCreatePreflightDrift::RecordedVersionChanged,
                "recorded package version change",
                "recorded",
            ),
            (
                IntegrationCreatePreflightDrift::DuplicateInventoryChanged,
                "duplicate package inventory change",
                "duplicate",
            ),
            (
                IntegrationCreatePreflightDrift::DuplicateInventoryReadFailure,
                "duplicate package inventory read failure",
                "duplicate",
            ),
        ];

        for (drift, label, blocked_create) in cases {
            let server = MockServer::start().await;
            let _ = mount_integration_lifecycle_with_recorded_create(
                &server,
                IntegrationLifecycleFailure::None,
                None,
                None,
                Some(drift),
            )
            .await;
            let transport = mock_transport(&server);
            let mut session = RecordingSession {
                transport: &transport,
                ownership: CleanupOwnership::default(),
            };
            let mut recording = Recording {
                dir: PathBuf::from("unused-in-test"),
                fixtures: Vec::new(),
            };

            let error = record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
                .await
                .expect_err(label);
            assert!(!error.message.contains("private"), "{label}: {error}");

            let before_cleanup = server.received_requests().await.expect("requests");
            let package_policy_posts: Vec<_> = before_cleanup
                .iter()
                .filter(|request| {
                    request.method.as_str() == "POST"
                        && request.url.path() == "/api/fleet/package_policies"
                })
                .collect();
            match blocked_create {
                "bootstrap" => assert!(
                    package_policy_posts.is_empty(),
                    "{label} must refuse before the bootstrap create"
                ),
                "recorded" => assert!(
                    package_policy_posts.iter().all(|request| {
                        request
                            .body_json::<Value>()
                            .ok()
                            .and_then(|body| body.get("inputs").cloned())
                            == Some(json!({}))
                    }),
                    "{label} must refuse before the recorded create"
                ),
                "duplicate" => assert!(
                    package_policy_posts.iter().all(|request| {
                        request
                            .body_json::<Value>()
                            .ok()
                            .and_then(|body| body.get("id").cloned())
                            != Some(json!(INTEGRATION_POLICY_DUP_ID))
                    }),
                    "{label} must refuse before the duplicate create"
                ),
                _ => unreachable!("test case has a known create stage"),
            }

            match blocked_create {
                "bootstrap" | "recorded" => {
                    assert!(!session.ownership.integration_policy, "{label}");
                    assert!(session.ownership.integration_policy_parent, "{label}");
                }
                "duplicate" => {
                    assert!(session.ownership.integration_policy, "{label}");
                    assert!(session.ownership.integration_policy_parent, "{label}");
                    assert!(!session.ownership.integration_policy_dup, "{label}");
                }
                _ => unreachable!("test case has a known create stage"),
            }
            let cleanup = session.cleanup_integration_resources().await;
            if drift == IntegrationCreatePreflightDrift::DuplicateInventoryReadFailure {
                assert!(
                    cleanup.is_err(),
                    "a permanently unreadable inventory must remain unverified"
                );
                let requests = server.received_requests().await.expect("requests");
                assert!(requests.iter().any(|request| {
                    request.method.as_str() == "DELETE"
                        && request.url.path()
                            == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}")
                }));
                assert!(requests.iter().any(|request| {
                    request.method.as_str() == "POST"
                        && request.url.path() == "/api/fleet/agent_policies/delete"
                }));
            } else {
                cleanup.expect("preflight refusal preserves cleanup ownership");
            }
        }
    }

    #[tokio::test]
    async fn integration_duplicate_conflict_rechecks_the_exact_baseline_inventory() {
        let server = MockServer::start().await;
        mount_integration_lifecycle(&server, IntegrationLifecycleFailure::Update).await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let mut recording = Recording {
            dir: PathBuf::from("unused-in-test"),
            fixtures: Vec::new(),
        };

        record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
            .await
            .expect_err("the injected update failure stops the lifecycle after the conflict");

        let requests = server.received_requests().await.expect("requests");
        let inventory_positions: Vec<_> = requests
            .iter()
            .enumerate()
            .filter(|(_, request)| {
                request.method.as_str() == "GET"
                    && request.url.path() == "/api/fleet/epm/packages/installed"
            })
            .map(|(index, _)| index)
            .collect();
        assert_eq!(
            inventory_positions.len(),
            7,
            "baseline, each create preflight, and each post-create audit read the strict inventory"
        );
        let duplicate_position = requests
            .iter()
            .position(|request| {
                request.method.as_str() == "POST"
                    && request.url.path() == "/api/fleet/package_policies"
                    && request
                        .body_json::<Value>()
                        .ok()
                        .and_then(|body| body.get("id").cloned())
                        == Some(json!(INTEGRATION_POLICY_DUP_ID))
            })
            .expect("duplicate create attempt");
        let duplicate_check_position = requests
            .iter()
            .rposition(|request| {
                request.method.as_str() == "GET"
                    && request.url.path()
                        == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_DUP_ID}")
            })
            .expect("duplicate exact-id check");
        assert!(inventory_positions[5] < duplicate_position);
        assert!(duplicate_position < inventory_positions[6]);
        assert!(inventory_positions[6] < duplicate_check_position);
    }

    #[cfg(any())]
    #[tokio::test]
    async fn integration_duplicate_conflict_does_not_claim_a_concurrent_marker_for_cleanup_legacy()
    {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortOrder", "asc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_inventory()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(installed_system_status()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system/2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(system_package_metadata()))
            .mount(&server)
            .await;

        let primary_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let primary_reads_for_response = primary_reads.clone();
        let primary = marker_integration_response(INTEGRATION_POLICY_DESCRIPTION);
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                match primary_reads_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                    0 => ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})),
                    1 | 2 => ResponseTemplate::new(200).set_body_json(primary.clone()),
                    _ => ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})),
                }
            })
            .mount(&server)
            .await;

        let duplicate_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let duplicate_reads_for_response = duplicate_reads.clone();
        let mut duplicate = marker_integration_response_with_nonce(
            INTEGRATION_POLICY_DESCRIPTION,
            OTHER_INTEGRATION_RECORDING_NONCE,
        );
        duplicate["item"]["id"] = json!(INTEGRATION_POLICY_DUP_ID);
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_DUP_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(move |_: &wiremock::Request| {
                if duplicate_reads_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    == 0
                {
                    ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}))
                } else {
                    ResponseTemplate::new(200).set_body_json(duplicate.clone())
                }
            })
            .mount(&server)
            .await;

        let parent_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let parent_reads_for_response = parent_reads.clone();
        let parent = marker_integration_parent_response();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"
            )))
            .respond_with(move |_: &wiremock::Request| {
                if parent_reads_for_response.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
                {
                    ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}))
                } else {
                    ResponseTemplate::new(200).set_body_json(parent.clone())
                }
            })
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies"))
            .and(query_param("sys_monitoring", "false"))
            .and(body_json(marker_integration_parent_create_body()))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(marker_integration_parent_response()),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(marker_integration_create_body("2.0.0")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(marker_integration_response(INTEGRATION_POLICY_DESCRIPTION)),
            )
            .mount(&server)
            .await;
        let mut duplicate_body = marker_integration_create_body("2.0.0");
        duplicate_body["id"] = json!(INTEGRATION_POLICY_DUP_ID);
        Mock::given(method("POST"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("format", "simplified"))
            .and(body_json(duplicate_body))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({"statusCode": 409})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("page", "1"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortField", "created_at"))
            .and(query_param("sortOrder", "asc"))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [marker_integration_response(INTEGRATION_POLICY_DESCRIPTION)["item"].clone()],
                "total": 1,
                "page": 1,
                "perPage": 1000,
            })))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"id": INTEGRATION_POLICY_ID})),
            )
            .mount(&server)
            .await;

        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let mut recording = Recording {
            dir: PathBuf::from("unused-in-test"),
            fixtures: Vec::new(),
        };

        let error = record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
            .await
            .expect_err("a duplicate marker appearing after preflight must stop recording");
        assert_eq!(
            error.message,
            "duplicate integration-policy id exists after a conflicting create"
        );
        session
            .cleanup_integration_resources()
            .await
            .expect_err("the concurrent duplicate remains for investigation");

        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().all(|request| {
            !(request.method.as_str() == "DELETE"
                && request.url.path()
                    == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_DUP_ID}"))
        }));
    }

    #[tokio::test]
    async fn integration_duplicate_conflict_does_not_claim_a_concurrent_marker_for_cleanup() {
        let server = MockServer::start().await;
        let _ = mount_integration_lifecycle_with_recorded_create(
            &server,
            IntegrationLifecycleFailure::None,
            None,
            Some(OTHER_INTEGRATION_RECORDING_NONCE.to_string()),
            None,
        )
        .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let mut recording = Recording {
            dir: PathBuf::from("unused-in-test"),
            fixtures: Vec::new(),
        };

        let error = record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
            .await
            .expect_err("a duplicate marker from another nonce must stop recording");
        assert_eq!(
            error.message,
            "duplicate integration-policy id exists after a conflicting create"
        );
        assert!(!session.ownership.integration_policy_dup);
        session
            .cleanup_integration_resources()
            .await
            .expect_err("the concurrent duplicate remains for investigation");

        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().all(|request| {
            !(request.method.as_str() == "DELETE"
                && request.url.path()
                    == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_DUP_ID}"))
        }));
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.method.as_str() == "DELETE"
                        && request.url.path()
                            == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}")
                })
                .count(),
            2,
            "bootstrap and proved recorded markers are distinct cleanup deletes"
        );
    }

    #[tokio::test]
    async fn ambiguous_parent_create_never_claims_another_runs_marker_for_cleanup() {
        for outcome in [
            AmbiguousCreateOutcome::Conflict,
            AmbiguousCreateOutcome::ServerError,
            AmbiguousCreateOutcome::RootItem,
        ] {
            let server = MockServer::start().await;
            mount_parent_create_ambiguous_winner(
                &server,
                outcome,
                OTHER_INTEGRATION_RECORDING_NONCE,
            )
            .await;
            let transport = mock_transport(&server);
            let mut session = RecordingSession {
                transport: &transport,
                ownership: CleanupOwnership::default(),
            };
            let mut recording = Recording {
                dir: PathBuf::from("unused-in-test"),
                fixtures: Vec::new(),
            };

            record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
                .await
                .expect_err("an ambiguous parent create must stop recording");
            assert!(
                !session.ownership.integration_policy_parent,
                "{outcome:?} must not claim a parent it cannot prove"
            );
            assert!(
                session.cleanup_integration_resources().await.is_err(),
                "a concurrent marker parent remains for investigation"
            );

            let requests = server.received_requests().await.expect("requests");
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| {
                        request.method.as_str() == "POST"
                            && request.url.path() == "/api/fleet/agent_policies"
                    })
                    .count(),
                1,
                "{outcome:?} must not replay an ambiguous parent create"
            );
            assert!(
                requests.iter().all(|request| {
                    !(request.method.as_str() == "POST"
                        && request.url.path() == "/api/fleet/agent_policies/delete")
                }),
                "{outcome:?} must not let integration cleanup delete the winner parent"
            );
        }
    }

    #[tokio::test]
    async fn ambiguous_primary_create_never_claims_another_runs_marker_for_cleanup() {
        for outcome in [
            AmbiguousCreateOutcome::Conflict,
            AmbiguousCreateOutcome::ServerError,
            AmbiguousCreateOutcome::RootItem,
        ] {
            let server = MockServer::start().await;
            let primary_reads = mount_primary_create_ambiguous_winner(
                &server,
                outcome,
                OTHER_INTEGRATION_RECORDING_NONCE,
            )
            .await;
            let transport = mock_transport(&server);
            let mut session = RecordingSession {
                transport: &transport,
                ownership: CleanupOwnership::default(),
            };
            let mut recording = Recording {
                dir: PathBuf::from("unused-in-test"),
                fixtures: Vec::new(),
            };

            record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
                .await
                .expect_err("an ambiguous integration create must stop recording");
            assert!(
                !session.ownership.integration_policy,
                "{outcome:?} must not claim an integration it cannot prove"
            );
            assert!(
                session.ownership.integration_policy_parent,
                "the independently proven parent remains eligible for safe cleanup checks"
            );
            assert!(
                session.cleanup_integration_resources().await.is_err(),
                "the attached concurrent integration remains for investigation"
            );

            assert_eq!(
                primary_reads.load(std::sync::atomic::Ordering::SeqCst),
                6,
                "{outcome:?} must exact-GET the bootstrap, export target, bootstrap delete, absence, and ambiguous winner before refusing ownership"
            );
            let requests = server.received_requests().await.expect("requests");
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| {
                        request.method.as_str() == "POST"
                            && request.url.path() == "/api/fleet/package_policies"
                    })
                    .count(),
                2,
                "{outcome:?} must create bootstrap and recorded markers once each without replay"
            );
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| {
                        request.method.as_str() == "DELETE"
                            && request.url.path()
                                == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}")
                    })
                    .count(),
                1,
                "{outcome:?} may delete only the bootstrap, never the unowned winner"
            );
        }
    }

    #[tokio::test]
    async fn ambiguous_parent_create_claims_the_same_nonce_then_cleans_after_an_exact_get() {
        for (outcome, expected_error) in [
            (
                AmbiguousCreateOutcome::Conflict,
                "creating integration policy marker parent failed",
            ),
            (
                AmbiguousCreateOutcome::RootItem,
                "integration policy parent create did not preserve the marker identity",
            ),
        ] {
            let server = MockServer::start().await;
            mount_parent_create_ambiguous_winner(
                &server,
                outcome,
                TEST_INTEGRATION_RECORDING_NONCE,
            )
            .await;
            let transport = mock_transport(&server);
            let mut session = RecordingSession {
                transport: &transport,
                ownership: CleanupOwnership::default(),
            };
            let mut recording = Recording {
                dir: PathBuf::from("unused-in-test"),
                fixtures: Vec::new(),
            };

            let error = record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
                .await
                .expect_err("an ambiguous parent create must still return its sanitized error");
            assert_eq!(error.message, expected_error);
            assert!(!error.message.contains(TEST_INTEGRATION_RECORDING_NONCE));
            assert!(
                session.ownership.integration_policy_parent,
                "{outcome:?} must retain the same-nonce parent for cleanup"
            );

            let before_cleanup = server.received_requests().await.expect("requests");
            let parent_create = before_cleanup
                .iter()
                .position(|request| {
                    request.method.as_str() == "POST"
                        && request.url.path() == "/api/fleet/agent_policies"
                })
                .expect("parent create request");
            let recovery_get = before_cleanup
                .iter()
                .enumerate()
                .find_map(|(index, request)| {
                    (index > parent_create
                        && request.method.as_str() == "GET"
                        && request.url.path()
                            == format!("/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}"))
                    .then_some(index)
                })
                .expect("exact parent GET after ambiguous create");

            session
                .cleanup_integration_resources()
                .await
                .expect("same-nonce parent cleanup");
            assert!(!session.ownership.integration_policy_parent);

            let requests = server.received_requests().await.expect("requests");
            let parent_delete = requests
                .iter()
                .position(|request| {
                    request.method.as_str() == "POST"
                        && request.url.path() == "/api/fleet/agent_policies/delete"
                })
                .expect("owned parent cleanup delete");
            assert!(
                parent_create < recovery_get && recovery_get < parent_delete,
                "the exact recovery GET must prove ownership before cleanup delete"
            );
        }
    }

    #[tokio::test]
    async fn ambiguous_primary_create_claims_the_same_nonce_then_cleans_after_an_exact_get() {
        for (outcome, expected_error) in [
            (
                AmbiguousCreateOutcome::Conflict,
                "creating integration policy marker failed",
            ),
            (
                AmbiguousCreateOutcome::RootItem,
                "integration policy create: integration response did not preserve the marker identity",
            ),
        ] {
            let server = MockServer::start().await;
            let primary_reads = mount_primary_create_ambiguous_winner(
                &server,
                outcome,
                TEST_INTEGRATION_RECORDING_NONCE,
            )
            .await;
            let transport = mock_transport(&server);
            let mut session = RecordingSession {
                transport: &transport,
                ownership: CleanupOwnership::default(),
            };
            let mut recording = Recording {
                dir: PathBuf::from("unused-in-test"),
                fixtures: Vec::new(),
            };

            let error = record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
                .await
                .expect_err("an ambiguous primary create must still return its sanitized error");
            assert_eq!(error.message, expected_error);
            assert!(!error.message.contains(TEST_INTEGRATION_RECORDING_NONCE));
            assert!(
                session.ownership.integration_policy,
                "{outcome:?} must retain the same-nonce integration for cleanup"
            );
            assert!(session.ownership.integration_policy_parent);

            let before_cleanup = server.received_requests().await.expect("requests");
            let primary_create = before_cleanup
                .iter()
                .rposition(|request| {
                    request.method.as_str() == "POST"
                        && request.url.path() == "/api/fleet/package_policies"
                })
                .expect("primary create request");
            let recovery_get = before_cleanup
                .iter()
                .enumerate()
                .find_map(|(index, request)| {
                    (index > primary_create
                        && request.method.as_str() == "GET"
                        && request.url.path()
                            == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"))
                    .then_some(index)
                })
                .expect("exact primary GET after ambiguous create");

            session
                .cleanup_integration_resources()
                .await
                .expect("same-nonce integration cleanup");
            assert!(!session.ownership.integration_policy);
            assert!(!session.ownership.integration_policy_parent);

            let requests = server.received_requests().await.expect("requests");
            let integration_delete = requests
                .iter()
                .rposition(|request| {
                    request.method.as_str() == "DELETE"
                        && request.url.path()
                            == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}")
                })
                .expect("owned integration cleanup delete");
            let parent_delete = requests
                .iter()
                .position(|request| {
                    request.method.as_str() == "POST"
                        && request.url.path() == "/api/fleet/agent_policies/delete"
                })
                .expect("owned parent cleanup delete");
            assert!(
                primary_create < recovery_get
                    && recovery_get < integration_delete
                    && integration_delete < parent_delete,
                "the exact recovery GET must prove ownership before ordered cleanup deletes"
            );
            assert!(
                primary_reads.load(std::sync::atomic::Ordering::SeqCst) >= 8,
                "bootstrap and recorded ambiguity recovery must each exact-GET the primary id"
            );
        }
    }

    #[tokio::test]
    async fn proven_primary_create_is_claimed_before_a_failed_inventory_observation() {
        let server = MockServer::start().await;
        mount_primary_create_with_failed_inventory_observation(&server).await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let mut recording = Recording {
            dir: PathBuf::from("unused-in-test"),
            fixtures: Vec::new(),
        };

        record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
            .await
            .expect_err("the failed inventory observation must stop recording");
        assert!(
            session.ownership.integration_policy,
            "a proven create remains cleanup-owned when only its observation failed"
        );
        session
            .cleanup_integration_resources()
            .await
            .expect("integration cleanup removes the proven create");

        let requests = server.received_requests().await.expect("requests");
        let mutations: Vec<_> = requests
            .iter()
            .filter(|request| matches!(request.method.as_str(), "POST" | "PUT" | "DELETE"))
            .map(|request| (request.method.as_str(), request.url.path().to_string()))
            .collect();
        let calls: Vec<_> = requests
            .iter()
            .map(|request| {
                (
                    request.method.as_str(),
                    request.url.path().to_string(),
                    request.url.query().map(str::to_owned),
                )
            })
            .collect();
        assert!(
            mutations.iter().any(|(method, path)| {
                *method == "DELETE"
                    && path == &format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}")
            }),
            "expected integration cleanup DELETE, got mutations={mutations:?} calls={calls:?}"
        );
    }

    #[tokio::test]
    async fn integration_recorder_sanitizes_inventory_get_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "message": "private GET inventory https://private.example/opaque-id"
            })))
            .mount(&server)
            .await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let mut recording = Recording {
            dir: PathBuf::from("unused-in-test"),
            fixtures: Vec::new(),
        };

        let error = record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
            .await
            .expect_err("inventory transport failure");

        assert_eq!(error.message, "reading installed package inventory failed");
        assert!(!error.message.contains("private"));
        assert!(!error.message.contains("opaque-id"));
    }

    #[tokio::test]
    async fn integration_recorder_sanitizes_update_put_errors() {
        let server = MockServer::start().await;
        mount_integration_lifecycle(&server, IntegrationLifecycleFailure::Update).await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let mut recording = Recording {
            dir: PathBuf::from("unused-in-test"),
            fixtures: Vec::new(),
        };

        let error = record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
            .await
            .expect_err("update transport failure");

        assert_eq!(error.message, "updating integration policy marker failed");
        assert!(!error.message.contains("private"));
        assert!(!error.message.contains("identity"));
    }

    #[tokio::test]
    async fn integration_recorder_sanitizes_delete_errors() {
        let server = MockServer::start().await;
        mount_integration_lifecycle(&server, IntegrationLifecycleFailure::Delete).await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let mut recording = Recording {
            dir: PathBuf::from("unused-in-test"),
            fixtures: Vec::new(),
        };

        let error = record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
            .await
            .expect_err("delete transport failure");

        assert_eq!(error.message, "deleting integration policy marker failed");
        assert!(!error.message.contains("private"));
        assert!(!error.message.contains("identity"));
    }

    #[tokio::test]
    async fn transient_duplicate_create_is_one_shot_and_recovers_with_an_exact_get() {
        let server = MockServer::start().await;
        mount_integration_lifecycle(&server, IntegrationLifecycleFailure::DuplicateCreate).await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let mut recording = Recording {
            dir: PathBuf::from("unused-in-test"),
            fixtures: Vec::new(),
        };

        record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
            .await
            .expect_err("a transient duplicate create must stop the lifecycle");

        let requests = server.received_requests().await.expect("requests");
        let duplicate_create = requests
            .iter()
            .enumerate()
            .find_map(|(index, request)| {
                (request.method.as_str() == "POST"
                    && request.url.path() == "/api/fleet/package_policies"
                    && request
                        .body_json::<Value>()
                        .ok()
                        .and_then(|body| body.get("id").cloned())
                        == Some(json!(INTEGRATION_POLICY_DUP_ID)))
                .then_some(index)
            })
            .expect("duplicate create request");
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.method.as_str() == "POST"
                        && request.url.path() == "/api/fleet/package_policies"
                        && request
                            .body_json::<Value>()
                            .ok()
                            .and_then(|body| body.get("id").cloned())
                            == Some(json!(INTEGRATION_POLICY_DUP_ID))
                })
                .count(),
            1,
            "a transient duplicate create must not replay against its fixed id"
        );
        assert!(
            requests.iter().enumerate().any(|(index, request)| {
                index > duplicate_create
                    && request.method.as_str() == "GET"
                    && request.url.path()
                        == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_DUP_ID}")
            }),
            "an ambiguous duplicate create must exact-GET its fixed id before refusing ownership"
        );
        assert!(!session.ownership.integration_policy_dup);
    }

    #[tokio::test]
    async fn transient_lifecycle_mutations_are_one_shot_and_cleanup_refuses_replacement_nonces() {
        let integration_path = format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}");
        let parent_path = format!("/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}");
        let cases = [
            (
                IntegrationLifecycleFailure::Update,
                "PUT",
                integration_path.as_str(),
                integration_path.as_str(),
                1,
            ),
            (
                IntegrationLifecycleFailure::Delete,
                "DELETE",
                integration_path.as_str(),
                integration_path.as_str(),
                2,
            ),
            (
                IntegrationLifecycleFailure::ParentDelete,
                "POST",
                "/api/fleet/agent_policies/delete",
                parent_path.as_str(),
                1,
            ),
        ];

        for (failure, mutation_method, mutation_path, recovery_path, expected_calls) in cases {
            let server = MockServer::start().await;
            mount_integration_lifecycle(&server, failure).await;
            let transport = mock_transport(&server);
            let mut session = RecordingSession {
                transport: &transport,
                ownership: CleanupOwnership::default(),
            };
            let mut recording = Recording {
                dir: PathBuf::from("unused-in-test"),
                fixtures: Vec::new(),
            };

            record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
                .await
                .expect_err("a transient marker mutation must stop the lifecycle");

            let before_cleanup = server.received_requests().await.expect("requests");
            let mutation = before_cleanup
                .iter()
                .enumerate()
                .rev()
                .find_map(|(index, request)| {
                    (request.method.as_str() == mutation_method
                        && request.url.path() == mutation_path)
                        .then_some(index)
                })
                .expect("transient mutation request");
            assert_eq!(
                before_cleanup
                    .iter()
                    .filter(|request| {
                        request.method.as_str() == mutation_method
                            && request.url.path() == mutation_path
                    })
                    .count(),
                expected_calls,
                "{failure:?} must not replay its transient mutation; bootstrap and recorded deletes are distinct"
            );

            let cleanup_error = session
                .cleanup_integration_resources()
                .await
                .expect_err("cleanup must fresh-GET and reject the replacement nonce");
            assert!(
                cleanup_error
                    .message
                    .contains("marker identity no longer matches"),
                "{failure:?}: {}",
                cleanup_error.message
            );

            let requests = server.received_requests().await.expect("requests");
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| {
                        request.method.as_str() == mutation_method
                            && request.url.path() == mutation_path
                    })
                    .count(),
                expected_calls,
                "{failure:?} cleanup must not replay its transient mutation"
            );
            assert!(
                requests.iter().enumerate().any(|(index, request)| {
                    index > mutation
                        && request.method.as_str() == "GET"
                        && request.url.path() == recovery_path
                }),
                "{failure:?} cleanup must fresh-GET the exact id after the transient mutation"
            );
        }
    }

    #[tokio::test]
    async fn integration_lifecycle_rechecks_swapped_resources_before_each_normal_mutation() {
        for swap in [
            IntegrationLifecycleSwap::Update,
            IntegrationLifecycleSwap::IntegrationDelete,
            IntegrationLifecycleSwap::FinalParentDelete,
        ] {
            let server = MockServer::start().await;
            mount_integration_lifecycle_with_revalidation_race(&server, swap).await;
            let transport = mock_transport(&server);
            let mut session = RecordingSession {
                transport: &transport,
                ownership: CleanupOwnership::default(),
            };
            let mut recording = Recording {
                dir: PathBuf::from("unused-in-test"),
                fixtures: Vec::new(),
            };

            let result =
                record_integration_policies(&mut session, &mut recording, "test", "9.6.0").await;
            assert!(result.is_err(), "{swap:?} must stop the lifecycle");

            let requests = server.received_requests().await.expect("requests");
            let integration_put = |request: &wiremock::Request| {
                request.method.as_str() == "PUT"
                    && request.url.path()
                        == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}")
            };
            let integration_delete = |request: &wiremock::Request| {
                request.method.as_str() == "DELETE"
                    && request.url.path()
                        == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}")
            };
            let parent_delete = |request: &wiremock::Request| {
                request.method.as_str() == "POST"
                    && request.url.path() == "/api/fleet/agent_policies/delete"
            };
            match swap {
                IntegrationLifecycleSwap::Update => {
                    assert!(
                        requests.iter().all(|request| !integration_put(request)),
                        "a swapped integration must stop the update before PUT"
                    );
                }
                IntegrationLifecycleSwap::IntegrationDelete => {
                    assert!(
                        requests.iter().all(|request| !integration_delete(request)),
                        "a swapped integration must stop DELETE"
                    );
                }
                IntegrationLifecycleSwap::FinalParentDelete => {
                    assert_eq!(
                        requests
                            .iter()
                            .filter(|request| parent_delete(request))
                            .count(),
                        0,
                        "a swapped final parent must stop before its delete"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn integration_lifecycle_revalidation_blocks_nonportable_state_before_put_and_delete() {
        let mut cases = unsafe_marker_integration_fields();
        cases.push((
            "changed package version",
            json!({
                "package": {"name": INTEGRATION_POLICY_PACKAGE, "version": "2.0.1"}
            }),
        ));

        for (label, fields) in cases {
            for (stage, swap, method_name) in [
                ("update", IntegrationLifecycleSwap::Update, "PUT"),
                (
                    "integration delete",
                    IntegrationLifecycleSwap::IntegrationDelete,
                    "DELETE",
                ),
            ] {
                let server = MockServer::start().await;
                mount_integration_lifecycle_with_revalidation_changes(
                    &server,
                    swap,
                    &fields,
                    &json!({}),
                    None,
                    None,
                )
                .await;
                let transport = mock_transport(&server);
                let mut session = RecordingSession {
                    transport: &transport,
                    ownership: CleanupOwnership::default(),
                };
                let mut recording = Recording {
                    dir: PathBuf::from("unused-in-test"),
                    fixtures: Vec::new(),
                };

                let error =
                    record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
                        .await
                        .expect_err("a changed marker must stop the lifecycle");
                assert!(
                    !error.message.contains("foreign"),
                    "{label} {stage} error leaked injected state"
                );
                let requests = server.received_requests().await.expect("requests");
                assert!(
                    requests.iter().all(|request| {
                        !(request.method.as_str() == method_name
                            && request.url.path()
                                == format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"))
                    }),
                    "{label} must stop before the {stage} {method_name}"
                );
            }
        }
    }

    #[tokio::test]
    async fn parent_lifecycle_revalidation_blocks_nonportable_state_before_delete() {
        for (label, fields) in unsafe_marker_parent_fields() {
            let server = MockServer::start().await;
            mount_integration_lifecycle_with_revalidation_changes(
                &server,
                IntegrationLifecycleSwap::FinalParentDelete,
                &json!({}),
                &fields,
                None,
                None,
            )
            .await;
            let transport = mock_transport(&server);
            let mut session = RecordingSession {
                transport: &transport,
                ownership: CleanupOwnership::default(),
            };
            let mut recording = Recording {
                dir: PathBuf::from("unused-in-test"),
                fixtures: Vec::new(),
            };

            let error = record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
                .await
                .expect_err("a changed parent must stop the lifecycle");
            assert!(
                !error.message.contains("foreign"),
                "{label} error leaked injected parent state"
            );
            let requests = server.received_requests().await.expect("requests");
            assert!(
                requests.iter().all(|request| {
                    !(request.method.as_str() == "POST"
                        && request.url.path() == "/api/fleet/agent_policies/delete")
                }),
                "{label} must stop before the final parent delete"
            );
        }
    }

    #[tokio::test]
    async fn lifecycle_revalidation_rejects_root_item_envelopes_before_mutation() {
        let cases = [
            (
                "integration",
                IntegrationLifecycleSwap::Update,
                Some(marker_integration_response(INTEGRATION_POLICY_DESCRIPTION)["item"].clone()),
                None,
                "PUT",
                format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"),
            ),
            (
                "parent",
                IntegrationLifecycleSwap::FinalParentDelete,
                None,
                Some(marker_integration_parent_response()["item"].clone()),
                "POST",
                "/api/fleet/agent_policies/delete".to_string(),
            ),
        ];

        for (label, swap, integration_override, parent_override, method_name, route) in cases {
            let server = MockServer::start().await;
            mount_integration_lifecycle_with_revalidation_changes(
                &server,
                swap,
                &json!({}),
                &json!({}),
                integration_override,
                parent_override,
            )
            .await;
            let transport = mock_transport(&server);
            let mut session = RecordingSession {
                transport: &transport,
                ownership: CleanupOwnership::default(),
            };
            let mut recording = Recording {
                dir: PathBuf::from("unused-in-test"),
                fixtures: Vec::new(),
            };

            record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
                .await
                .expect_err("a root item must not pass a strict single-response proof");
            let requests = server.received_requests().await.expect("requests");
            assert!(
                requests.iter().all(|request| {
                    !(request.method.as_str() == method_name && request.url.path() == route)
                }),
                "a root {label} response must stop before {method_name} {route}"
            );
        }
    }

    #[tokio::test]
    async fn integration_lifecycle_deletes_the_integration_before_its_parent_and_is_force_free() {
        let server = MockServer::start().await;
        mount_integration_lifecycle(&server, IntegrationLifecycleFailure::None).await;
        let transport = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &transport,
            ownership: CleanupOwnership::default(),
        };
        let mut recording = Recording {
            dir: PathBuf::from("unused-in-test"),
            fixtures: Vec::new(),
        };

        record_integration_policies(&mut session, &mut recording, "test", "9.6.0")
            .await
            .expect("the normal marker lifecycle");

        let requests = server.received_requests().await.expect("requests");
        let mutations: Vec<_> = requests
            .iter()
            .filter(|request| {
                matches!(request.method.as_str(), "POST" | "PUT" | "DELETE")
                    && request.url.path().starts_with("/api/fleet/")
            })
            .collect();
        let mutation_routes: Vec<_> = mutations
            .iter()
            .map(|request| (request.method.as_str(), request.url.path().to_string()))
            .collect();
        assert_eq!(
            mutation_routes,
            vec![
                ("POST", "/api/fleet/agent_policies".to_string()),
                ("POST", "/api/fleet/package_policies".to_string()),
                (
                    "DELETE",
                    format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}")
                ),
                ("POST", "/api/fleet/package_policies".to_string()),
                ("POST", "/api/fleet/package_policies".to_string()),
                (
                    "PUT",
                    format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}")
                ),
                (
                    "DELETE",
                    format!("/api/fleet/package_policies/{INTEGRATION_POLICY_ID}")
                ),
                ("POST", "/api/fleet/agent_policies/delete".to_string()),
            ],
            "the attached parent is never deleted before its integration",
        );
        assert!(mutations.iter().all(|request| {
            !request.url.query_pairs().any(|(key, _)| key == "force")
                && !String::from_utf8_lossy(&request.body).contains("force")
        }));
        assert!(mutations.iter().all(|request| {
            !(request.method.as_str() == "DELETE"
                && request.url.path().starts_with("/api/fleet/epm/packages/"))
        }));

        const INTEGRATION_BEFORE_PARENT_LINES: &[&str] = &[
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "GET /api/fleet/epm/packages/system",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy-dup?format=simplified",
            "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            "POST /api/fleet/agent_policies?sys_monitoring=false",
            "GET /api/fleet/epm/packages/system/2.0.0",
            "GET /api/fleet/epm/packages/system",
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "POST /api/fleet/package_policies?format=simplified",
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/status",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            "GET /api/fleet/epm/packages/system",
            "GET /api/fleet/epm/packages/system/2.0.0",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "DELETE /api/fleet/package_policies/elasticctl-sample-integration-policy",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            "GET /api/fleet/epm/packages/system",
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "POST /api/fleet/package_policies?format=simplified",
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/package_policies?page=1&perPage=1000&sortField=created_at&sortOrder=asc&format=simplified",
            "GET /api/fleet/epm/packages/system",
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "POST /api/fleet/package_policies?format=simplified",
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy-dup?format=simplified",
            "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "PUT /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "DELETE /api/fleet/package_policies/elasticctl-sample-integration-policy",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            "POST /api/fleet/agent_policies/delete",
            "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
            "GET /api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy?format=simplified",
            "GET /api/fleet/package_policies/elasticctl-sample-integration-policy-dup?format=simplified",
            "GET /api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
        ];
        const INTEGRATION_BEFORE_PARENT_BODY_DIGEST: u64 = 16607917844578840776;
        let (lines, body_digest) = request_sequence_and_body_digest(&requests);
        assert_eq!(
            lines, INTEGRATION_BEFORE_PARENT_LINES,
            "complete integration deletion lifecycle requests"
        );
        assert_eq!(
            body_digest, INTEGRATION_BEFORE_PARENT_BODY_DIGEST,
            "integration deletion lifecycle request bytes"
        );
    }
}
