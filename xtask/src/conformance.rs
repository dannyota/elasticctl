use elasticctl_api::{ListFilter, RuleFilter, RuleSource};
use elasticctl_core::{Capabilities, Error, ErrorKind, Feature, Profile, Transport};
use std::io::Write;
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

#[derive(Clone, Copy)]
struct RequiredFeature {
    feature: Feature,
    label: &'static str,
}

#[derive(Clone, Copy)]
struct Contract {
    name: &'static str,
    test: &'static str,
    features: &'static [RequiredFeature],
}

const RULE_SOURCE: RequiredFeature = RequiredFeature {
    feature: Feature::RuleSourceScoping,
    label: "rule-source-scoping",
};
const EXCEPTION_LISTS: RequiredFeature = RequiredFeature {
    feature: Feature::ExceptionLists,
    label: "exception-lists",
};
const PREBUILT_RULES: RequiredFeature = RequiredFeature {
    feature: Feature::PrebuiltRules,
    label: "prebuilt-rules",
};

const CONTRACTS: [Contract; 8] = [
    Contract {
        name: "diagnostics",
        test: "doctor_reports_no_failed_checks",
        features: &[],
    },
    Contract {
        name: "pull_diff",
        test: "a_pull_followed_by_a_diff_is_clean",
        features: &[RULE_SOURCE],
    },
    Contract {
        name: "exception_round_trip",
        test: "exception_crud_and_bundle_round_trip_preserve_a_marked_list",
        features: &[EXCEPTION_LISTS],
    },
    Contract {
        name: "stale_pointer_repair",
        test: "a_stale_exception_pointer_is_observed_repaired_and_rewritten_on_import",
        features: &[EXCEPTION_LISTS],
    },
    Contract {
        name: "source_scoping",
        test: "source_defaults_keep_custom_rules_and_allow_selected_prebuilt_rules",
        features: &[PREBUILT_RULES, RULE_SOURCE],
    },
    Contract {
        name: "rule_round_trip",
        test: "a_rule_survives_a_create_export_import_round_trip",
        features: &[],
    },
    Contract {
        name: "search",
        test: "search_reads_marked_documents_through_esql_and_dsl",
        features: &[],
    },
    Contract {
        name: "triage",
        test: "triage_transitions_alerts_and_cases_and_leaves_only_closed_residue",
        features: &[],
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureClass {
    Contract,
    Cleanup,
    Harness,
}

fn classify_failure(output: &[u8]) -> FailureClass {
    let text = String::from_utf8_lossy(output);
    if text
        .lines()
        .any(|line| line.trim() == "elasticctl-conformance-class:cleanup")
    {
        FailureClass::Cleanup
    } else if text
        .lines()
        .any(|line| line.trim() == "elasticctl-conformance-class:contract")
    {
        FailureClass::Contract
    } else {
        FailureClass::Harness
    }
}

struct ContractResult {
    contract: String,
    result: &'static str,
    error_class: Option<String>,
}

impl ContractResult {
    fn pass(contract: &str) -> Self {
        Self {
            contract: contract.to_string(),
            result: "pass",
            error_class: None,
        }
    }

    fn fail(contract: &str) -> Self {
        Self {
            contract: contract.to_string(),
            result: "fail",
            error_class: Some("contract".to_string()),
        }
    }

    fn skip(contract: &str, feature: &str) -> Self {
        Self {
            contract: contract.to_string(),
            result: "skip",
            error_class: Some(format!("unsupported:{feature}:9.5.1")),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "contract": self.contract,
            "result": self.result,
            "error_class": self.error_class,
        })
    }
}

struct Report {
    flavor: String,
    version: String,
    contracts: Vec<ContractResult>,
}

impl Report {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "flavor": self.flavor,
            "version": self.version,
            "contracts": self
                .contracts
                .iter()
                .map(ContractResult::to_json)
                .collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TargetState {
    custom: u64,
    prebuilt: u64,
    customized: u64,
    marked_rules: u64,
    marked_lists: usize,
    marked_indices: usize,
    /// Open (non-`closed`) `elasticctl-live-*` marker alerts. Closed marker
    /// alerts are never counted here at all — the capture query below
    /// excludes them, which *is* the triage contract's accepted alert-residue
    /// tolerance (design spec `elasticctl-triage-design.md` section 9): a
    /// closed marker alert is inert and stays out of every baseline count.
    open_marked_alerts: u64,
    /// `elasticctl-live-marker`-tagged cases. Unlike alerts, cases delete
    /// cleanly through a public API, so this carries no such tolerance and
    /// must be zero like every other partition (same spec section).
    marked_cases: u64,
}

/// Whether a feature is available on the measured target.
///
/// This mirrors the per-contract skip gate exactly: both use the same
/// `Capabilities::require_feature` floor. A below-floor target reports every
/// feature as unavailable, so `TargetState::capture` defaults the gated
/// partitions to 0 instead of failing the baseline before the skip
/// classification can run.
///
/// Exception: `open_marked_alerts` and `marked_cases` are *not* gated by this
/// function at all — no `Feature::Alerts`/`Feature::Cases` variant exists,
/// because every supported stack (9.5.1+) serves `signals/search` and
/// `cases/_find` unconditionally. A target that cannot answer those routes
/// cannot be audited for triage residue either, so `capture` fails the whole
/// baseline for it instead of defaulting the two triage partitions to 0 —
/// silently reporting "clean" when the harness could not actually check
/// would be the dishonest outcome, not the fail.
fn feature_available(capabilities: &Capabilities, feature: Feature) -> bool {
    capabilities.require_feature(feature).is_ok()
}

impl TargetState {
    async fn capture(
        transport: &Transport,
        capabilities: &Capabilities,
    ) -> elasticctl_core::Result<Self> {
        async fn rule_total(
            transport: &Transport,
            source: RuleSource,
            tag: Option<&str>,
        ) -> elasticctl_core::Result<u64> {
            let (_, total) = elasticctl_api::rules::find_page(
                transport,
                &RuleFilter {
                    source,
                    tag: tag.map(str::to_string),
                    ..Default::default()
                },
                1,
                1,
            )
            .await?;
            Ok(total)
        }

        let source_scoped = feature_available(capabilities, Feature::RuleSourceScoping);
        let custom = if source_scoped {
            rule_total(transport, RuleSource::Custom, None).await?
        } else {
            0
        };
        let prebuilt = if source_scoped {
            rule_total(transport, RuleSource::Prebuilt, None).await?
        } else {
            0
        };
        let customized = if source_scoped {
            rule_total(transport, RuleSource::Customized, None).await?
        } else {
            0
        };
        let marked_rules =
            rule_total(transport, RuleSource::All, Some("elasticctl-live-marker")).await?;
        let mut marked_lists = 0;
        if feature_available(capabilities, Feature::ExceptionLists) {
            for namespace in ["single", "agnostic"] {
                marked_lists += elasticctl_api::exceptions::find_lists(
                    transport,
                    &ListFilter {
                        tag: Some("elasticctl-live-marker".to_string()),
                        namespace: Some(namespace.to_string()),
                        ..Default::default()
                    },
                )
                .await?
                .len();
            }
        }
        let marked_indices = match transport
            .get_absolute_es("/_resolve/index/elasticctl-live-*")
            .await
        {
            Ok(body) => body
                .get("indices")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::Http,
                        "invalid marked-index response: indices must be an array",
                    )
                })?
                .len(),
            Err(Error {
                kind: ErrorKind::NotFound,
                ..
            }) => 0,
            Err(error) => return Err(error),
        };

        // Same prefix + must_not-closed body live.rs's own baseline counter
        // sends (crates/elasticctl-cli/tests/live.rs::open_marker_alert_count):
        // every `elasticctl-live-`-prefixed marker rule's alerts, excluding
        // `workflow_status: closed`. Un-gated by `Feature`: every supported
        // stack serves `signals/search`.
        let open_marked_alerts = {
            let body = serde_json::json!({
                "query": {"bool": {
                    "filter": [{"prefix": {"kibana.alert.rule.rule_id": "elasticctl-live-"}}],
                    "must_not": [{"term": {"kibana.alert.workflow_status": "closed"}}],
                }},
                "size": 0,
                "track_total_hits": true,
            });
            transport
                .post(elasticctl_api::alerts::SEARCH_PATH, Some(&body))
                .await?
                .pointer("/hits/total/value")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::Http,
                        "invalid alert-count response: hits.total.value must be a number",
                    )
                })?
        };

        // Same tag-filtered find query live.rs's own baseline counter sends
        // (crates/elasticctl-cli/tests/live.rs::marker_case_count).
        let marked_cases = {
            let query = elasticctl_api::cases_ops::find_query(
                &elasticctl_api::cases_ops::CaseFilter {
                    tag: Some("elasticctl-live-marker".to_string()),
                    ..Default::default()
                },
                1,
                1,
            );
            let (_cases, total) = elasticctl_api::cases::find_page(transport, &query).await?;
            total
        };

        Ok(Self {
            custom,
            prebuilt,
            customized,
            marked_rules,
            marked_lists,
            marked_indices,
            open_marked_alerts,
            marked_cases,
        })
    }

    /// `open_marked_alerts` is already the *open* count only — `capture`'s
    /// query excludes `workflow_status: closed`, so a closed marker alert
    /// never reaches this field at all. Requiring it to be zero here still
    /// tolerates closed residue without a separate branch: the exclusion at
    /// capture time *is* the tolerance (triage spec section 9). `marked_cases`
    /// carries no such deviation and is held to zero unconditionally.
    fn markers_are_clean(&self) -> bool {
        self.marked_rules == 0
            && self.marked_lists == 0
            && self.marked_indices == 0
            && self.open_marked_alerts == 0
            && self.marked_cases == 0
    }

    fn assert_clean_start(&self) -> Result<(), String> {
        if self.markers_are_clean() {
            Ok(())
        } else {
            Err("conformance baseline is not marker-clean".to_string())
        }
    }

    fn assert_clean_against(&self, baseline: &Self) -> Result<(), String> {
        if self.markers_are_clean()
            && self.custom == baseline.custom
            && self.prebuilt == baseline.prebuilt
            && self.customized == baseline.customized
        {
            Ok(())
        } else {
            Err("conformance cleanup audit failed".to_string())
        }
    }
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

fn private_log_path(workspace: &std::path::Path, flavor: FlavorLabel, contract: &str) -> PathBuf {
    workspace
        .join("target")
        .join("conformance-private")
        .join(flavor.as_str())
        .join(format!("{contract}.log"))
}

fn audit_log_path(
    workspace: &std::path::Path,
    flavor: FlavorLabel,
    contract: &Contract,
) -> PathBuf {
    private_log_path(workspace, flavor, &format!("audit-{}", contract.name))
}

fn write_private_log(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "conformance private log path is invalid".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|_| "conformance private log write failed".to_string())?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        if path.exists() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| "conformance private log write failed".to_string())?;
        }
    }
    let mut file = options
        .open(path)
        .map_err(|_| "conformance private log write failed".to_string())?;
    file.write_all(bytes)
        .map_err(|_| "conformance private log write failed".to_string())
}

fn report_path(
    report_dir: &std::path::Path,
    flavor: FlavorLabel,
    version: &str,
) -> Result<PathBuf, String> {
    if version.is_empty()
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err("conformance target version is not safe for a report filename".to_string());
    }
    Ok(report_dir.join(format!("{}-{version}.json", flavor.as_str())))
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

fn test_command(workspace: &std::path::Path, contract: &Contract) -> std::process::Command {
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

fn output_log(output: &std::process::Output) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"stdout:\n");
    bytes.extend_from_slice(&output.stdout);
    bytes.extend_from_slice(b"\nstderr:\n");
    bytes.extend_from_slice(&output.stderr);
    bytes
}

fn private_failure(
    workspace: &std::path::Path,
    flavor: FlavorLabel,
    stage: &str,
    detail: impl AsRef<[u8]>,
) -> String {
    let path = private_log_path(workspace, flavor, stage);
    if write_private_log(&path, detail.as_ref()).is_err() {
        return "conformance failed and its private log could not be written".to_string();
    }
    let relative = path.strip_prefix(workspace).unwrap_or(&path);
    format!(
        "conformance {stage} failed; private detail is in {}",
        relative.display()
    )
}

fn private_audit_failure(
    workspace: &std::path::Path,
    flavor: FlavorLabel,
    contract: &Contract,
    detail: impl AsRef<[u8]>,
) -> String {
    let path = audit_log_path(workspace, flavor, contract);
    if write_private_log(&path, detail.as_ref()).is_err() {
        return "conformance failed and its private log could not be written".to_string();
    }
    let relative = path.strip_prefix(workspace).unwrap_or(&path);
    format!(
        "conformance audit-{} failed; private detail is in {}",
        contract.name,
        relative.display()
    )
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
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|_| "conformance could not clear the previous report".to_string())?;
    }

    let baseline = capture_state(
        &transport,
        &capabilities,
        &workspace,
        args.flavor,
        "baseline",
    )
    .await?;
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

        let output = test_command(&workspace, contract)
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
    use super::*;
    use std::path::PathBuf;

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
    fn contract_table_is_the_approved_eight_in_order() {
        assert_eq!(
            CONTRACTS.map(|contract| contract.name),
            [
                "diagnostics",
                "pull_diff",
                "exception_round_trip",
                "stale_pointer_repair",
                "source_scoping",
                "rule_round_trip",
                "search",
                "triage",
            ]
        );
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
            open_marked_alerts: 0,
            marked_cases: 0,
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

        let floor = elasticctl_core::Capabilities {
            flavor: elasticctl_core::Flavor::SelfManaged,
            version: "9.5.1".to_string(),
        };
        assert!(feature_available(&floor, Feature::RuleSourceScoping));
        assert!(feature_available(&floor, Feature::ExceptionLists));
        assert!(feature_available(&floor, Feature::PrebuiltRules));
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
        state.open_marked_alerts = 1;
        variants.push(state);
        let mut state = baseline.clone();
        state.marked_cases = 1;
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
        let command = test_command(std::path::Path::new("/workspace"), &CONTRACTS[1]);
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
