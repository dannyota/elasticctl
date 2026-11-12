use elasticctl_core::Feature;

#[derive(Clone, Copy)]
pub(super) struct RequiredFeature {
    pub(super) feature: Feature,
    pub(super) label: &'static str,
}

#[derive(Clone, Copy)]
pub(super) struct Contract {
    pub(super) name: &'static str,
    pub(super) test: &'static str,
    pub(super) features: &'static [RequiredFeature],
}

const RULE_SOURCE: RequiredFeature = RequiredFeature {
    feature: Feature::RuleSourceScoping,
    label: "rule-source-scoping",
};
pub(super) const EXCEPTION_LISTS: RequiredFeature = RequiredFeature {
    feature: Feature::ExceptionLists,
    label: "exception-lists",
};
pub(super) const PREBUILT_RULES: RequiredFeature = RequiredFeature {
    feature: Feature::PrebuiltRules,
    label: "prebuilt-rules",
};
pub(super) const DASHBOARDS: RequiredFeature = RequiredFeature {
    feature: Feature::Dashboards,
    label: "dashboards",
};
pub(super) const FLEET_POLICIES: RequiredFeature = RequiredFeature {
    feature: Feature::FleetPolicies,
    label: "fleet-policies",
};

pub(super) const CONTRACTS: [Contract; 13] = [
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
    Contract {
        name: "content",
        test: "content_transfers_data_views_and_dashboards_without_residue",
        features: &[DASHBOARDS],
    },
    Contract {
        name: "fleet",
        test: "fleet_transfers_agent_and_integration_policies_without_residue",
        features: &[FLEET_POLICIES],
    },
    Contract {
        name: "mcp_reads_existing_verticals",
        test: "mcp_reads_existing_verticals",
        features: &[EXCEPTION_LISTS, PREBUILT_RULES, DASHBOARDS, FLEET_POLICIES],
    },
    Contract {
        name: "mcp_answers_across_verticals",
        test: "mcp_answers_across_verticals",
        features: &[EXCEPTION_LISTS, PREBUILT_RULES, FLEET_POLICIES],
    },
    Contract {
        name: "mcp_mutations_plan_and_confirm",
        test: "mcp_mutations_plan_and_confirm",
        features: &[],
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FailureClass {
    Contract,
    Cleanup,
    Harness,
}

pub(super) fn classify_failure(output: &[u8]) -> FailureClass {
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

pub(super) struct ContractResult {
    contract: String,
    result: &'static str,
    error_class: Option<String>,
}

impl ContractResult {
    pub(super) fn pass(contract: &str) -> Self {
        Self {
            contract: contract.to_string(),
            result: "pass",
            error_class: None,
        }
    }

    pub(super) fn fail(contract: &str) -> Self {
        Self {
            contract: contract.to_string(),
            result: "fail",
            error_class: Some("contract".to_string()),
        }
    }

    pub(super) fn skip(contract: &str, feature: &str) -> Self {
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

pub(super) struct Report {
    pub(super) flavor: String,
    pub(super) version: String,
    pub(super) contracts: Vec<ContractResult>,
}

impl Report {
    pub(super) fn to_json(&self) -> serde_json::Value {
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
