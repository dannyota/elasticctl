mod contracts;
mod report_io;
mod state;
mod timing;

use contracts::{CONTRACTS, Contract, ContractResult, FailureClass, Report, classify_failure};
use elasticctl_core::{Capabilities, Error, Feature, Profile, Transport};
use report_io::{
    output_log, private_audit_failure, private_failure, private_log_path, report_path,
    write_private_log,
};
use state::{TargetState, feature_available, setup_fleet};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlavorLabel {
    Serverless,
    Ech,
    Traditional,
}

impl FlavorLabel {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "serverless" => Ok(Self::Serverless),
            "ech" => Ok(Self::Ech),
            "traditional" => Ok(Self::Traditional),
            _ => Err("invalid --flavor; expected serverless, ech, or traditional".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Serverless => "serverless",
            Self::Ech => "ech",
            Self::Traditional => "traditional",
        }
    }

    fn expected(self) -> elasticctl_core::Flavor {
        match self {
            Self::Serverless => elasticctl_core::Flavor::Serverless,
            Self::Ech => elasticctl_core::Flavor::ElasticCloudHosted,
            Self::Traditional => elasticctl_core::Flavor::SelfManaged,
        }
    }
}

#[derive(Debug)]
struct Args {
    flavor: FlavorLabel,
    report_dir: PathBuf,
}

impl Args {
    fn parse(values: &[String]) -> Result<Self, String> {
        let mut flavor = None;
        let mut report_dir = None;
        let mut index = 0;
        while index < values.len() {
            match values[index].as_str() {
                "--flavor" => {
                    if flavor.is_some() {
                        return Err("duplicate --flavor".to_string());
                    }
                    let value = values
                        .get(index + 1)
                        .ok_or_else(|| "missing value for --flavor".to_string())?;
                    flavor = Some(FlavorLabel::parse(value)?);
                    index += 2;
                }
                "--report-dir" => {
                    if report_dir.is_some() {
                        return Err("duplicate --report-dir".to_string());
                    }
                    let value = values
                        .get(index + 1)
                        .ok_or_else(|| "missing value for --report-dir".to_string())?;
                    report_dir = Some(PathBuf::from(value));
                    index += 2;
                }
                _ => return Err("unknown option".to_string()),
            }
        }
        Ok(Self {
            flavor: flavor.ok_or_else(|| "missing --flavor".to_string())?,
            report_dir: report_dir.ok_or_else(|| "missing --report-dir".to_string())?,
        })
    }
}

#[derive(Debug)]
enum InitializationError {
    Report,
    FleetSetup(Error),
    Baseline(Error),
}

#[derive(Debug)]
struct InitializedRun {
    baseline: TargetState,
    fleet_setup_confirmed: bool,
}

fn clear_previous_report(path: &std::path::Path) -> std::result::Result<(), InitializationError> {
    if path.exists() {
        std::fs::remove_file(path).map_err(|_| InitializationError::Report)?;
    }
    Ok(())
}

async fn initialize_run_before_contracts(
    transport: &Transport,
    capabilities: &Capabilities,
    report_path: &std::path::Path,
) -> std::result::Result<InitializedRun, InitializationError> {
    clear_previous_report(report_path)?;
    let fleet_setup_confirmed = feature_available(capabilities, Feature::FleetPolicies);
    if fleet_setup_confirmed {
        setup_fleet(transport)
            .await
            .map_err(InitializationError::FleetSetup)?;
    }
    let baseline = TargetState::capture(transport, capabilities)
        .await
        .map_err(InitializationError::Baseline)?;
    Ok(InitializedRun {
        baseline,
        fleet_setup_confirmed,
    })
}

fn write_report_if_clean(
    report: &Report,
    baseline: &TargetState,
    final_state: &TargetState,
    path: &std::path::Path,
) -> Result<(), String> {
    final_state.assert_clean_against(baseline)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|_| "conformance report write failed".to_string())?;
    }
    let mut encoded = serde_json::to_string_pretty(&report.to_json())
        .map_err(|_| "conformance report write failed".to_string())?;
    encoded.push('\n');
    std::fs::write(path, encoded).map_err(|_| "conformance report write failed".to_string())
}

fn validate_probe(
    flavor: FlavorLabel,
    capabilities: &elasticctl_core::Capabilities,
) -> Result<(), String> {
    if capabilities.flavor == flavor.expected() {
        Ok(())
    } else {
        Err("conformance target flavor mismatch".to_string())
    }
}

fn test_command(
    workspace: &std::path::Path,
    contract: &Contract,
    fleet_setup_confirmed: bool,
) -> std::process::Command {
    let mut command = std::process::Command::new("cargo");
    command
        .current_dir(workspace)
        .env("ELASTICCTL_LIVE", "1")
        .args([
            "test",
            "--locked",
            "--test",
            "live",
            contract.test,
            "--",
            "--ignored",
            "--exact",
            "--test-threads=1",
        ]);
    if fleet_setup_confirmed
        && contract
            .features
            .iter()
            .any(|required| required.feature == Feature::FleetPolicies)
    {
        command.env("ELASTICCTL_CONFORMANCE_FLEET_SETUP", "1");
    }
    command
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must be inside the workspace")
        .to_path_buf()
}

fn transport_from_environment() -> Result<Transport, String> {
    let kibana_url = std::env::var("ELASTICCTL_KIBANA_URL")
        .map_err(|_| "missing ELASTICCTL_KIBANA_URL".to_string())?;
    let api_key = std::env::var("ELASTICCTL_API_KEY")
        .map_err(|_| "missing ELASTICCTL_API_KEY".to_string())?;
    let timeout_secs = std::env::var("ELASTICCTL_TIMEOUT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(60);
    let mut profile = Profile {
        kibana_url,
        es_url: std::env::var("ELASTICCTL_ES_URL").ok(),
        api_key: Some(api_key),
        username: None,
        password: None,
        space: std::env::var("ELASTICCTL_SPACE").unwrap_or_else(|_| "default".to_string()),
        verify: true,
        timeout_secs,
    };
    profile.strip_userinfo();
    Transport::new(&profile).map_err(|_| "conformance transport setup failed".to_string())
}

async fn capture_state(
    transport: &Transport,
    capabilities: &Capabilities,
    workspace: &std::path::Path,
    flavor: FlavorLabel,
    stage: &str,
) -> Result<TargetState, String> {
    TargetState::capture(transport, capabilities)
        .await
        .map_err(|error| private_failure(workspace, flavor, stage, error.message.as_bytes()))
}

pub async fn run(values: &[String]) -> Result<(), String> {
    let args = Args::parse(values)?;
    let workspace = workspace_root();
    let transport = transport_from_environment()?;
    let capabilities = Capabilities::probe(&transport, transport.kibana_url())
        .await
        .map_err(|error| {
            private_failure(&workspace, args.flavor, "harness", error.message.as_bytes())
        })?;
    validate_probe(args.flavor, &capabilities)?;
    let path = report_path(&args.report_dir, args.flavor, &capabilities.version)?;
    let initialized = initialize_run_before_contracts(&transport, &capabilities, &path)
        .await
        .map_err(|error| match error {
            InitializationError::Report => {
                "conformance could not clear the previous report".to_string()
            }
            InitializationError::FleetSetup(error) => private_failure(
                &workspace,
                args.flavor,
                "fleet-setup",
                error.message.as_bytes(),
            ),
            InitializationError::Baseline(error) => private_failure(
                &workspace,
                args.flavor,
                "baseline",
                error.message.as_bytes(),
            ),
        })?;
    let InitializedRun {
        baseline,
        fleet_setup_confirmed,
    } = initialized;
    baseline.assert_clean_start()?;
    let mut report = Report {
        flavor: args.flavor.as_str().to_string(),
        version: capabilities.version.clone(),
        contracts: Vec::with_capacity(CONTRACTS.len()),
    };

    for contract in &CONTRACTS {
        if let Some(required) = contract
            .features
            .iter()
            .find(|required| capabilities.require_feature(required.feature).is_err())
        {
            report
                .contracts
                .push(ContractResult::skip(contract.name, required.label));
            println!(
                "{} {} {} skip",
                args.flavor.as_str(),
                capabilities.version,
                contract.name
            );
            let state = TargetState::capture(&transport, &capabilities)
                .await
                .map_err(|error| {
                    private_audit_failure(
                        &workspace,
                        args.flavor,
                        contract,
                        error.message.as_bytes(),
                    )
                })?;
            state.assert_clean_against(&baseline).map_err(|safe| {
                let detail = format!("{safe}\nbaseline: {baseline:?}\nafter: {state:?}");
                private_audit_failure(&workspace, args.flavor, contract, detail.as_bytes())
            })?;
            continue;
        }

        let output = test_command(&workspace, contract, fleet_setup_confirmed)
            .output()
            .map_err(|error| {
                private_failure(
                    &workspace,
                    args.flavor,
                    contract.name,
                    error.to_string().as_bytes(),
                )
            })?;
        let private = output_log(&output);
        write_private_log(
            &private_log_path(&workspace, args.flavor, contract.name),
            &private,
        )?;
        let class = (!output.status.success()).then(|| classify_failure(&private));
        let state = TargetState::capture(&transport, &capabilities)
            .await
            .map_err(|error| {
                private_audit_failure(&workspace, args.flavor, contract, error.message.as_bytes())
            })?;
        state.assert_clean_against(&baseline).map_err(|safe| {
            let detail = format!("{safe}\nbaseline: {baseline:?}\nafter: {state:?}");
            private_audit_failure(&workspace, args.flavor, contract, detail.as_bytes())
        })?;

        match class {
            None => {
                report.contracts.push(ContractResult::pass(contract.name));
                println!(
                    "{} {} {} pass",
                    args.flavor.as_str(),
                    capabilities.version,
                    contract.name
                );
                for line in timing::public_timing_lines(&output.stdout) {
                    println!("{} {} {line}", args.flavor.as_str(), capabilities.version);
                }
            }
            Some(FailureClass::Contract) => {
                report.contracts.push(ContractResult::fail(contract.name));
                println!(
                    "{} {} {} fail",
                    args.flavor.as_str(),
                    capabilities.version,
                    contract.name
                );
            }
            Some(FailureClass::Cleanup) => {
                return Err(format!(
                    "conformance cleanup failed; private detail is in {}",
                    private_log_path(&workspace, args.flavor, contract.name)
                        .strip_prefix(&workspace)
                        .unwrap_or_else(|_| std::path::Path::new("target/conformance-private"))
                        .display()
                ));
            }
            Some(FailureClass::Harness) => {
                return Err(format!(
                    "conformance harness failed; private detail is in {}",
                    private_log_path(&workspace, args.flavor, contract.name)
                        .strip_prefix(&workspace)
                        .unwrap_or_else(|_| std::path::Path::new("target/conformance-private"))
                        .display()
                ));
            }
        }
    }

    let final_state = capture_state(
        &transport,
        &capabilities,
        &workspace,
        args.flavor,
        "final-audit",
    )
    .await?;
    write_report_if_clean(&report, &baseline, &final_state, &path)?;
    println!(
        "{} {} conformance report written",
        args.flavor.as_str(),
        capabilities.version
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::contracts::{DASHBOARDS, EXCEPTION_LISTS, FLEET_POLICIES, PREBUILT_RULES};
    use super::report_io::audit_log_path;
    use super::*;
    use elasticctl_api_test_support::fleet::FleetState;
    use std::path::PathBuf;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn mock_transport(server: &MockServer) -> Transport {
        Transport::new(&Profile {
            kibana_url: server.uri(),
            es_url: None,
            api_key: Some("test".to_string()),
            username: None,
            password: None,
            space: "default".to_string(),
            verify: true,
            timeout_secs: 5,
        })
        .unwrap()
    }

    fn temporary_report_path(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("elasticctl-{label}-{nanos}.json"))
    }

    async fn mount_clean_baseline(server: &MockServer) {
        for (endpoint, body) in [
            (
                "/api/status",
                serde_json::json!({"version": {"number": "9.5.1", "build_flavor": "traditional"}}),
            ),
            (
                "/api/detection_engine/rules/_find",
                serde_json::json!({"data": [], "total": 0, "page": 1, "perPage": 1}),
            ),
            (
                "/api/exception_lists/_find",
                serde_json::json!({"data": [], "page": 1, "per_page": 1000, "total": 0}),
            ),
            (
                "/_resolve/index/elasticctl-live-*",
                serde_json::json!({"indices": []}),
            ),
            ("/api/data_views", serde_json::json!({"data_view": []})),
            (
                "/api/dashboards",
                serde_json::json!({"data": [], "meta": {"page": 1, "per_page": 1000, "total": 0}}),
            ),
            (
                "/api/data_views/default",
                serde_json::json!({"data_view_id": null}),
            ),
            (
                "/api/cases/_find",
                serde_json::json!({"cases": [], "total": 0}),
            ),
            (
                "/api/fleet/agent_policies",
                serde_json::json!({"items": [], "page": 1, "perPage": 1000, "total": 0}),
            ),
            (
                "/api/fleet/package_policies",
                serde_json::json!({"items": [], "page": 1, "perPage": 1000, "total": 0}),
            ),
            (
                "/api/fleet/epm/packages/installed",
                serde_json::json!({"items": [], "total": 0}),
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(endpoint))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(server)
                .await;
        }
        Mock::given(method("POST"))
            .and(path(elasticctl_api::alerts::SEARCH_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "hits": {"total": {"value": 0}, "hits": []}
            })))
            .mount(server)
            .await;
    }

    #[test]
    fn parses_the_public_runner_interface() {
        let args = Args::parse(&[
            "--flavor".into(),
            "ech".into(),
            "--report-dir".into(),
            "docs/conformance/v0.2.4".into(),
        ])
        .unwrap();
        assert_eq!(args.flavor, FlavorLabel::Ech);
        assert_eq!(args.report_dir, PathBuf::from("docs/conformance/v0.2.4"));
    }

    #[test]
    fn contract_table_is_the_approved_thirteen_in_order() {
        assert_eq!(
            CONTRACTS
                .iter()
                .map(|contract| contract.name)
                .collect::<Vec<_>>(),
            vec![
                "diagnostics",
                "pull_diff",
                "exception_round_trip",
                "stale_pointer_repair",
                "source_scoping",
                "rule_round_trip",
                "search",
                "triage",
                "content",
                "fleet",
                "mcp_reads_existing_verticals",
                "mcp_answers_across_verticals",
                "mcp_mutations_plan_and_confirm",
            ]
        );
        let mutations = &CONTRACTS[12];
        assert_eq!(mutations.test, mutations.name);
        assert!(mutations.features.is_empty());
        assert_eq!(CONTRACTS[8].features.len(), 1);
        assert_eq!(CONTRACTS[8].features[0].feature, Feature::Dashboards);
        assert_eq!(CONTRACTS[8].features[0].label, "dashboards");
        assert_eq!(CONTRACTS[9].name, "fleet");
        assert_eq!(CONTRACTS[9].features[0].feature, Feature::FleetPolicies);
        let mcp_reads = &CONTRACTS[10];
        assert_eq!(mcp_reads.name, "mcp_reads_existing_verticals");
        assert_eq!(
            mcp_reads
                .features
                .iter()
                .map(|required| required.feature)
                .collect::<Vec<_>>(),
            vec![
                Feature::ExceptionLists,
                Feature::PrebuiltRules,
                Feature::Dashboards,
                Feature::FleetPolicies,
            ]
        );
    }

    #[test]
    fn task_contract_has_the_required_features_and_exact_child_command() {
        let contract = &CONTRACTS[11];
        assert_eq!(contract.name, "mcp_answers_across_verticals");
        assert_eq!(contract.test, contract.name);
        assert_eq!(
            contract
                .features
                .iter()
                .map(|f| f.feature)
                .collect::<Vec<_>>(),
            vec![
                Feature::ExceptionLists,
                Feature::PrebuiltRules,
                Feature::FleetPolicies
            ]
        );
        let command = test_command(std::path::Path::new("/workspace"), contract, true);
        let args = command
            .get_args()
            .map(|a| a.to_str().unwrap())
            .collect::<Vec<_>>();
        assert!(
            args.windows(4)
                .any(|a| a == ["live", contract.test, "--", "--ignored"])
        );
        assert!(args.contains(&"--exact"));
    }

    #[test]
    fn rejects_missing_duplicate_and_unknown_options_without_echoing_values() {
        assert_eq!(Args::parse(&[]).unwrap_err(), "missing --flavor");
        assert_eq!(
            Args::parse(&["--flavor".into()]).unwrap_err(),
            "missing value for --flavor"
        );
        assert_eq!(
            Args::parse(&[
                "--flavor".into(),
                "serverless".into(),
                "--flavor".into(),
                "ech".into(),
                "--report-dir".into(),
                "reports".into(),
            ])
            .unwrap_err(),
            "duplicate --flavor"
        );
        assert_eq!(
            Args::parse(&["--private-value".into(), "secret".into()]).unwrap_err(),
            "unknown option"
        );
        assert_eq!(
            Args::parse(&[
                "--flavor".into(),
                "private-value".into(),
                "--report-dir".into(),
                "reports".into(),
            ])
            .unwrap_err(),
            "invalid --flavor; expected serverless, ech, or traditional"
        );
    }

    #[test]
    fn classifies_only_machine_readable_failure_markers() {
        let private = b"target detail\nelasticctl-conformance-class:contract\nmore detail";
        assert_eq!(classify_failure(private), FailureClass::Contract);
        assert_eq!(
            classify_failure(b"elasticctl-conformance-class:cleanup\ndetail"),
            FailureClass::Cleanup
        );
        assert_eq!(
            classify_failure(b"ordinary cargo failure"),
            FailureClass::Harness
        );
    }

    #[test]
    fn report_json_contains_only_public_fields_and_stable_classes() {
        let report = Report {
            flavor: "ech".to_string(),
            version: "9.5.1".to_string(),
            contracts: vec![
                ContractResult::pass("diagnostics"),
                ContractResult::fail("pull_diff"),
                ContractResult::skip("exception_round_trip", "exception-lists"),
                ContractResult::pass("stale_pointer_repair"),
                ContractResult::pass("source_scoping"),
                ContractResult::pass("rule_round_trip"),
                ContractResult::pass("search"),
                ContractResult::pass("triage"),
                ContractResult::pass("content"),
                ContractResult::pass("fleet"),
                ContractResult::pass("mcp_reads_existing_verticals"),
                ContractResult::pass("mcp_answers_across_verticals"),
                ContractResult::pass("mcp_mutations_plan_and_confirm"),
            ],
        };
        assert_eq!(
            report.to_json(),
            serde_json::json!({
                "flavor": "ech",
                "version": "9.5.1",
                "contracts": [
                    {
                        "contract": "diagnostics",
                        "result": "pass",
                        "error_class": null,
                    },
                    {
                        "contract": "pull_diff",
                        "result": "fail",
                        "error_class": "contract",
                    },
                    {
                        "contract": "exception_round_trip",
                        "result": "skip",
                        "error_class": "unsupported:exception-lists:9.5.1",
                    },
                    {
                        "contract": "stale_pointer_repair",
                        "result": "pass",
                        "error_class": null,
                    },
                    {
                        "contract": "source_scoping",
                        "result": "pass",
                        "error_class": null,
                    },
                    {
                        "contract": "rule_round_trip",
                        "result": "pass",
                        "error_class": null,
                    },
                    {
                        "contract": "search",
                        "result": "pass",
                        "error_class": null,
                    },
                    {
                        "contract": "triage",
                        "result": "pass",
                        "error_class": null,
                    },
                    {
                        "contract": "content",
                        "result": "pass",
                        "error_class": null,
                    },
                    {
                        "contract": "fleet",
                        "result": "pass",
                        "error_class": null,
                    },
                    {
                        "contract": "mcp_reads_existing_verticals",
                        "result": "pass",
                        "error_class": null,
                    },
                    {
                        "contract": "mcp_answers_across_verticals",
                        "result": "pass",
                        "error_class": null,
                    },
                    {
                        "contract": "mcp_mutations_plan_and_confirm",
                        "result": "pass",
                        "error_class": null,
                    },
                ],
            })
        );
    }

    #[test]
    fn private_log_path_uses_only_public_labels() {
        assert_eq!(
            private_log_path(
                std::path::Path::new("/workspace"),
                FlavorLabel::Ech,
                "pull_diff"
            ),
            PathBuf::from("/workspace/target/conformance-private/ech/pull_diff.log")
        );
    }

    #[test]
    fn audit_detail_does_not_replace_the_contract_log() {
        assert_eq!(
            audit_log_path(
                std::path::Path::new("/workspace"),
                FlavorLabel::Ech,
                &CONTRACTS[1]
            ),
            PathBuf::from("/workspace/target/conformance-private/ech/audit-pull_diff.log")
        );
    }

    fn clean_state() -> TargetState {
        TargetState {
            custom: 2,
            prebuilt: 2_066,
            customized: 0,
            marked_rules: 0,
            marked_lists: 0,
            marked_indices: 0,
            marked_data_views: 0,
            marked_dashboards: 0,
            default_data_view: Some("stable-default".to_string()),
            open_marked_alerts: 0,
            marked_cases: 0,
            fleet: Some(FleetState {
                agent_policies: Default::default(),
                integration_policies: Default::default(),
                packages: Default::default(),
            }),
        }
    }

    #[test]
    fn clean_state_matches_baseline() {
        let baseline = clean_state();
        assert_eq!(baseline.assert_clean_start(), Ok(()));
        assert_eq!(baseline.assert_clean_against(&baseline), Ok(()));
    }

    #[test]
    fn feature_gating_defaults_below_the_verified_floor() {
        let below = elasticctl_core::Capabilities {
            flavor: elasticctl_core::Flavor::SelfManaged,
            version: "9.5.0".to_string(),
        };
        assert!(!feature_available(&below, Feature::RuleSourceScoping));
        assert!(!feature_available(&below, Feature::ExceptionLists));
        assert!(!feature_available(&below, Feature::PrebuiltRules));
        assert!(!feature_available(&below, Feature::Dashboards));

        let floor = elasticctl_core::Capabilities {
            flavor: elasticctl_core::Flavor::SelfManaged,
            version: "9.5.1".to_string(),
        };
        assert!(feature_available(&floor, Feature::RuleSourceScoping));
        assert!(feature_available(&floor, Feature::ExceptionLists));
        assert!(feature_available(&floor, Feature::PrebuiltRules));
        assert!(feature_available(&floor, Feature::Dashboards));
    }

    #[tokio::test]
    async fn below_floor_fleet_capture_is_none_without_a_fleet_request() {
        let server = MockServer::start().await;
        mount_clean_baseline(&server).await;
        let capabilities = Capabilities {
            flavor: elasticctl_core::Flavor::SelfManaged,
            version: "9.5.0".to_string(),
        };
        let path = temporary_report_path("below-floor");
        let initialized =
            initialize_run_before_contracts(&mock_transport(&server), &capabilities, &path)
                .await
                .unwrap();
        assert!(!initialized.fleet_setup_confirmed);
        assert_eq!(initialized.baseline.fleet, None);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| !request.url.path().starts_with("/api/fleet/"))
        );
    }

    #[tokio::test]
    async fn setup_precedes_the_first_supported_fleet_read_and_runs_once() {
        let server = MockServer::start().await;
        mount_clean_baseline(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/setup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "isInitialized": true
            })))
            .mount(&server)
            .await;
        let capabilities = Capabilities {
            flavor: elasticctl_core::Flavor::SelfManaged,
            version: "9.5.1".to_string(),
        };
        let transport = mock_transport(&server);
        let path = temporary_report_path("setup-order");
        let initialized = initialize_run_before_contracts(&transport, &capabilities, &path)
            .await
            .unwrap();
        assert!(initialized.fleet_setup_confirmed);
        assert_eq!(initialized.baseline.assert_clean_start(), Ok(()));
        let fleet = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.url.path().starts_with("/api/fleet/"))
            .collect::<Vec<_>>();
        assert_eq!(fleet[0].method.as_str(), "POST");
        assert_eq!(fleet[0].url.path(), "/api/fleet/setup");
        assert_eq!(
            fleet
                .iter()
                .filter(|request| request.url.path() == "/api/fleet/setup")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn a_setup_failure_is_one_shot_and_removes_a_stale_report() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/setup"))
            .respond_with(ResponseTemplate::new(500).set_body_string("retryable"))
            .mount(&server)
            .await;
        let path = temporary_report_path("stale-report");
        std::fs::write(&path, "stale success evidence").unwrap();
        let capabilities = Capabilities {
            flavor: elasticctl_core::Flavor::SelfManaged,
            version: "9.5.1".to_string(),
        };
        let error = initialize_run_before_contracts(&mock_transport(&server), &capabilities, &path)
            .await
            .expect_err("Fleet setup failure must stop before baseline");
        assert!(matches!(error, InitializationError::FleetSetup(_)));
        assert!(!path.exists());
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method.as_str(), "POST");
        assert_eq!(requests[0].url.path(), "/api/fleet/setup");
    }

    #[test]
    fn every_partition_and_marker_drift_fails_the_cleanup_audit() {
        let baseline = clean_state();
        let mut variants = Vec::new();
        let mut state = baseline.clone();
        state.custom += 1;
        variants.push(state);
        let mut state = baseline.clone();
        state.prebuilt += 1;
        variants.push(state);
        let mut state = baseline.clone();
        state.customized += 1;
        variants.push(state);
        let mut state = baseline.clone();
        state.marked_rules = 1;
        variants.push(state);
        let mut state = baseline.clone();
        state.marked_lists = 1;
        variants.push(state);
        let mut state = baseline.clone();
        state.marked_indices = 1;
        variants.push(state);
        let mut state = baseline.clone();
        state.marked_data_views = 1;
        variants.push(state);
        let mut state = baseline.clone();
        state.marked_dashboards = 1;
        variants.push(state);
        let mut state = baseline.clone();
        state.default_data_view = Some("different-default".to_string());
        variants.push(state);
        let mut state = baseline.clone();
        state.open_marked_alerts = 1;
        variants.push(state);
        let mut state = baseline.clone();
        state.marked_cases = 1;
        variants.push(state);
        let mut state = baseline.clone();
        state
            .fleet
            .as_mut()
            .unwrap()
            .agent_policies
            .insert("marker".into());
        variants.push(state);
        let mut state = baseline.clone();
        state
            .fleet
            .as_mut()
            .unwrap()
            .integration_policies
            .insert("marker".into());
        variants.push(state);
        let mut state = baseline.clone();
        state
            .fleet
            .as_mut()
            .unwrap()
            .packages
            .insert("system".into(), "different".into());
        variants.push(state);

        for state in variants {
            assert_eq!(
                state.assert_clean_against(&baseline),
                Err("conformance cleanup audit failed".to_string())
            );
        }
    }

    #[test]
    fn drift_prevents_report_publication() {
        let baseline = clean_state();
        let mut drifted = baseline.clone();
        drifted.marked_rules = 1;
        let dir = std::env::temp_dir().join(format!(
            "elasticctl-conformance-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.json");
        let report = Report {
            flavor: "serverless".to_string(),
            version: "9.6.0".to_string(),
            contracts: Vec::new(),
        };

        assert_eq!(
            write_report_if_clean(&report, &baseline, &drifted, &path),
            Err("conformance cleanup audit failed".to_string())
        );
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fleet_drift_prevents_report_publication() {
        let baseline = clean_state();
        let report = Report {
            flavor: "serverless".to_string(),
            version: "9.6.0".to_string(),
            contracts: Vec::new(),
        };
        let dir = std::env::temp_dir().join(format!(
            "elasticctl-fleet-conformance-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        for drifted in [
            FleetState {
                agent_policies: ["marker".to_string()].into_iter().collect(),
                integration_policies: Default::default(),
                packages: Default::default(),
            },
            FleetState {
                agent_policies: Default::default(),
                integration_policies: ["marker".to_string()].into_iter().collect(),
                packages: Default::default(),
            },
            FleetState {
                agent_policies: Default::default(),
                integration_policies: Default::default(),
                packages: [("system".to_string(), "changed".to_string())]
                    .into_iter()
                    .collect(),
            },
        ] {
            let mut state = baseline.clone();
            state.fleet = Some(drifted);
            let path = dir.join(format!(
                "{}.json",
                state.fleet.as_ref().unwrap().packages.len()
            ));
            assert_eq!(
                write_report_if_clean(&report, &baseline, &state, &path),
                Err("conformance cleanup audit failed".to_string())
            );
            assert!(!path.exists());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn public_flavor_labels_match_the_measured_core_flavors() {
        assert_eq!(
            FlavorLabel::Serverless.expected(),
            elasticctl_core::Flavor::Serverless
        );
        assert_eq!(
            FlavorLabel::Ech.expected(),
            elasticctl_core::Flavor::ElasticCloudHosted
        );
        assert_eq!(
            FlavorLabel::Traditional.expected(),
            elasticctl_core::Flavor::SelfManaged
        );
        let mismatched = elasticctl_core::Capabilities {
            flavor: elasticctl_core::Flavor::SelfManaged,
            version: "9.5.1".to_string(),
        };
        assert_eq!(
            validate_probe(FlavorLabel::Ech, &mismatched),
            Err("conformance target flavor mismatch".to_string())
        );
    }

    #[test]
    fn live_contract_command_is_exact_and_keeps_credentials_out_of_arguments() {
        let command = test_command(std::path::Path::new("/workspace"), &CONTRACTS[1], false);
        assert_eq!(command.get_program(), std::ffi::OsStr::new("cargo"));
        assert_eq!(
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            [
                "test",
                "--locked",
                "--test",
                "live",
                "a_pull_followed_by_a_diff_is_clean",
                "--",
                "--ignored",
                "--exact",
                "--test-threads=1",
            ]
        );
        assert_eq!(
            command.get_current_dir(),
            Some(std::path::Path::new("/workspace"))
        );
        assert!(command.get_envs().any(|(name, value)| {
            name == std::ffi::OsStr::new("ELASTICCTL_LIVE")
                && value == Some(std::ffi::OsStr::new("1"))
        }));
        assert!(
            command
                .get_args()
                .all(|arg| !arg.to_string_lossy().contains("essu_"))
        );

        let mcp_command = test_command(std::path::Path::new("/workspace"), &CONTRACTS[10], true);
        assert!(
            mcp_command
                .get_args()
                .any(|arg| { arg == std::ffi::OsStr::new("mcp_reads_existing_verticals") })
        );
        assert!(mcp_command.get_envs().any(|(name, value)| {
            name == std::ffi::OsStr::new("ELASTICCTL_CONFORMANCE_FLEET_SETUP")
                && value == Some(std::ffi::OsStr::new("1"))
        }));

        // The mutation contract needs no Fleet setup, so a confirmed setup
        // never reaches its child.
        let mutation_command =
            test_command(std::path::Path::new("/workspace"), &CONTRACTS[12], true);
        assert_eq!(
            mutation_command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            [
                "test",
                "--locked",
                "--test",
                "live",
                "mcp_mutations_plan_and_confirm",
                "--",
                "--ignored",
                "--exact",
                "--test-threads=1",
            ]
        );
        assert!(mutation_command.get_envs().any(|(name, value)| {
            name == std::ffi::OsStr::new("ELASTICCTL_LIVE")
                && value == Some(std::ffi::OsStr::new("1"))
        }));
        assert!(!mutation_command.get_envs().any(|(name, _)| {
            name == std::ffi::OsStr::new("ELASTICCTL_CONFORMANCE_FLEET_SETUP")
        }));
    }

    #[test]
    fn validated_fleet_setup_reaches_every_fleet_policy_child() {
        let mcp_reads = Contract {
            name: "mcp_reads_existing_verticals",
            test: "mcp_reads_existing_verticals",
            features: &[EXCEPTION_LISTS, PREBUILT_RULES, DASHBOARDS, FLEET_POLICIES],
        };
        for contract in [&CONTRACTS[9], &mcp_reads, &CONTRACTS[11]] {
            let command = test_command(std::path::Path::new("/workspace"), contract, true);
            assert!(command.get_envs().any(|(name, value)| {
                name == std::ffi::OsStr::new("ELASTICCTL_CONFORMANCE_FLEET_SETUP")
                    && value == Some(std::ffi::OsStr::new("1"))
            }));
            let command = test_command(std::path::Path::new("/workspace"), contract, false);
            assert!(!command.get_envs().any(|(name, _)| {
                name == std::ffi::OsStr::new("ELASTICCTL_CONFORMANCE_FLEET_SETUP")
            }));
        }
    }

    #[test]
    fn report_filename_accepts_a_version_but_rejects_path_syntax() {
        assert_eq!(
            report_path(
                std::path::Path::new("reports"),
                FlavorLabel::Serverless,
                "9.6.0"
            ),
            Ok(PathBuf::from("reports/serverless-9.6.0.json"))
        );
        assert_eq!(
            report_path(
                std::path::Path::new("reports"),
                FlavorLabel::Serverless,
                "../private"
            ),
            Err("conformance target version is not safe for a report filename".to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_logs_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "elasticctl-private-log-test-{}",
            std::process::id()
        ));
        let path = dir.join("private.log");
        write_private_log(&path, b"private target detail").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"private target detail");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
