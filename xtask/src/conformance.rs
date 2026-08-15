use elasticctl_core::Feature;
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
#[allow(dead_code)]
struct RequiredFeature {
    feature: Feature,
    label: &'static str,
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
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

const CONTRACTS: [Contract; 6] = [
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

fn private_log_path(workspace: &std::path::Path, flavor: FlavorLabel, contract: &str) -> PathBuf {
    workspace
        .join("target")
        .join("conformance-private")
        .join(flavor.as_str())
        .join(format!("{contract}.log"))
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
            "docs/conformance/v0.2.3".into(),
        ])
        .unwrap();
        assert_eq!(args.flavor, FlavorLabel::Ech);
        assert_eq!(args.report_dir, PathBuf::from("docs/conformance/v0.2.3"));
    }

    #[test]
    fn contract_table_is_the_approved_six_in_order() {
        assert_eq!(
            CONTRACTS.map(|contract| contract.name),
            [
                "diagnostics",
                "pull_diff",
                "exception_round_trip",
                "stale_pointer_repair",
                "source_scoping",
                "rule_round_trip",
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
}
