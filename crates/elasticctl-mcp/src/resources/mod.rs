pub(crate) mod uri;

use crate::catalog::ToolId;
use rmcp::model::{JsonObject, Resource, ResourceTemplate};
use serde_json::json;
use uri::ResourceRef;

pub(crate) struct ResourceCall {
    pub tool: ToolId,
    pub arguments: JsonObject,
    pub expect_rule_id: Option<String>,
}

pub(crate) fn call_for(reference: &ResourceRef) -> ResourceCall {
    let (tool, arguments) = match reference {
        ResourceRef::CoverageTactic => (
            ToolId::DetectionCoverage,
            json!({"group_by":"tactic","limit":200}),
        ),
        ResourceRef::CoverageTechnique => (
            ToolId::DetectionCoverage,
            json!({"group_by":"technique","limit":200}),
        ),
        ResourceRef::Doctor => (ToolId::StackDoctor, json!({})),
        ResourceRef::Info => (ToolId::StackInfo, json!({})),
        ResourceRef::PrebuiltRulesStatus => (ToolId::RulesPrebuiltStatus, json!({})),
        ResourceRef::Alert { alert_id } => (ToolId::AlertsGet, json!({"alert_id":alert_id})),
        ResourceRef::Case { case_id } => (ToolId::CasesGet, json!({"id":case_id})),
        ResourceRef::ExceptionList {
            namespace_type,
            list_id,
        } => (
            ToolId::ExceptionsGet,
            json!({"list_id":list_id,"namespace":namespace_type,"limit":50}),
        ),
        ResourceRef::Rule { rule_id } => (ToolId::RulesGet, json!({"selector":rule_id})),
    };
    let serde_json::Value::Object(arguments) = arguments else {
        unreachable!()
    };
    ResourceCall {
        tool,
        arguments,
        expect_rule_id: match reference {
            ResourceRef::Rule { rule_id } => Some(rule_id.clone()),
            _ => None,
        },
    }
}

const LISTED: [(&str, &str, &str, ToolId); 5] = [
    (
        "elasticctl://stack/coverage/tactic",
        "coverage-tactic",
        "Detection coverage by ATT&CK tactic",
        ToolId::DetectionCoverage,
    ),
    (
        "elasticctl://stack/coverage/technique",
        "coverage-technique",
        "Detection coverage by ATT&CK technique",
        ToolId::DetectionCoverage,
    ),
    (
        "elasticctl://stack/doctor",
        "doctor",
        "Stack diagnostics",
        ToolId::StackDoctor,
    ),
    (
        "elasticctl://stack/info",
        "info",
        "Stack version and flavor",
        ToolId::StackInfo,
    ),
    (
        "elasticctl://stack/prebuilt-rules/status",
        "prebuilt-rules-status",
        "Prebuilt rule status",
        ToolId::RulesPrebuiltStatus,
    ),
];

const TEMPLATES: [(&str, &str, &str, ToolId); 4] = [
    (
        "elasticctl://stack/alerts/{alert_id}",
        "alert",
        "Alert by id",
        ToolId::AlertsGet,
    ),
    (
        "elasticctl://stack/cases/{case_id}",
        "case",
        "Case by id",
        ToolId::CasesGet,
    ),
    (
        "elasticctl://stack/exception-lists/{namespace_type}/{list_id}",
        "exception-list",
        "Exception list by namespace and id",
        ToolId::ExceptionsGet,
    ),
    (
        "elasticctl://stack/rules/{rule_id}",
        "rule",
        "Rule by rule_id",
        ToolId::RulesGet,
    ),
];

fn description(tool: ToolId) -> String {
    crate::catalog::definitions()
        .into_iter()
        .find(|entry| entry.name == tool.name())
        .expect("resource tool is registered")
        .description
        .expect("resource tool has a description")
        .into_owned()
}

pub(crate) fn list() -> Vec<Resource> {
    LISTED
        .into_iter()
        .map(|(uri, name, title, tool)| {
            Resource::new(uri, name)
                .with_title(title)
                .with_description(description(tool))
                .with_mime_type("application/json")
        })
        .collect()
}

const RULE_TEMPLATE_DESCRIPTION: &str = "Inspect one rule by its exact rule_id.";

pub(crate) fn templates() -> Vec<ResourceTemplate> {
    TEMPLATES
        .into_iter()
        .map(|(uri, name, title, tool)| {
            let description = match tool {
                ToolId::RulesGet => RULE_TEMPLATE_DESCRIPTION.to_owned(),
                _ => description(tool),
            };
            ResourceTemplate::new(uri, name)
                .with_title(title)
                .with_description(description)
                .with_mime_type("application/json")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn description(tool: &str) -> String {
        crate::catalog::definitions()
            .into_iter()
            .find(|entry| entry.name == tool)
            .unwrap()
            .description
            .unwrap()
            .into_owned()
    }

    #[test]
    fn listed_resources_match_the_public_table() {
        let expected = json!([
            {"uri":"elasticctl://stack/coverage/tactic","name":"coverage-tactic","title":"Detection coverage by ATT&CK tactic","mimeType":"application/json","description":"Detection coverage across Elastic Security rules, grouped by MITRE ATT&CK technique, tactic, index pattern, or integration package. Each row counts enabled and disabled rules. Use rules_list with technique or tactic to see the rules behind a row. Reads at most 4,000 rules; near that size a call can need a longer server --timeout. Read-only."},
            {"uri":"elasticctl://stack/coverage/technique","name":"coverage-technique","title":"Detection coverage by ATT&CK technique","mimeType":"application/json","description":"Detection coverage across Elastic Security rules, grouped by MITRE ATT&CK technique, tactic, index pattern, or integration package. Each row counts enabled and disabled rules. Use rules_list with technique or tactic to see the rules behind a row. Reads at most 4,000 rules; near that size a call can need a longer server --timeout. Read-only."},
            {"uri":"elasticctl://stack/doctor","name":"doctor","title":"Stack diagnostics","mimeType":"application/json","description":"Run read-only health checks against the selected Elastic stack."},
            {"uri":"elasticctl://stack/info","name":"info","title":"Stack version and flavor","mimeType":"application/json","description":"Inspect the selected Elastic stack version, flavor, license tier, and spaces."},
            {"uri":"elasticctl://stack/prebuilt-rules/status","name":"prebuilt-rules-status","title":"Prebuilt rule status","mimeType":"application/json","description":"Inspect the installed, missing, outdated, and customized prebuilt-rule counts."}
        ]);
        let resources = list();
        assert_eq!(serde_json::to_value(&resources).unwrap(), expected);
        for (resource, tool) in resources.iter().zip([
            "detection_coverage",
            "detection_coverage",
            "stack_doctor",
            "stack_info",
            "rules_prebuilt_status",
        ]) {
            assert_eq!(
                resource.description.as_deref(),
                Some(description(tool).as_str())
            );
        }
    }

    #[test]
    fn templates_match_the_public_table() {
        let expected = json!([
            {"uriTemplate":"elasticctl://stack/alerts/{alert_id}","name":"alert","title":"Alert by id","mimeType":"application/json","description":"Inspect one alert by its exact document id."},
            {"uriTemplate":"elasticctl://stack/cases/{case_id}","name":"case","title":"Case by id","mimeType":"application/json","description":"Inspect one case by its exact id."},
            {"uriTemplate":"elasticctl://stack/exception-lists/{namespace_type}/{list_id}","name":"exception-list","title":"Exception list by namespace and id","mimeType":"application/json","description":"Inspect one exception-list container and its bounded items."},
            {"uriTemplate":"elasticctl://stack/rules/{rule_id}","name":"rule","title":"Rule by rule_id","mimeType":"application/json","description":"Inspect one rule by its exact rule_id."}
        ]);
        let templates = templates();
        assert_eq!(serde_json::to_value(&templates).unwrap(), expected);
        for (template, tool) in templates
            .iter()
            .zip(["alerts_get", "cases_get", "exceptions_get"])
        {
            assert_eq!(
                template.description.as_deref(),
                Some(description(tool).as_str())
            );
        }
    }

    #[test]
    fn calls_match_fixed_tool_arguments_and_rule_identity() {
        for (reference, tool, arguments, expect_rule_id) in [
            (
                ResourceRef::CoverageTactic,
                ToolId::DetectionCoverage,
                json!({"group_by":"tactic","limit":200}),
                None,
            ),
            (
                ResourceRef::CoverageTechnique,
                ToolId::DetectionCoverage,
                json!({"group_by":"technique","limit":200}),
                None,
            ),
            (ResourceRef::Doctor, ToolId::StackDoctor, json!({}), None),
            (ResourceRef::Info, ToolId::StackInfo, json!({}), None),
            (
                ResourceRef::PrebuiltRulesStatus,
                ToolId::RulesPrebuiltStatus,
                json!({}),
                None,
            ),
            (
                ResourceRef::Alert {
                    alert_id: "a/b".into(),
                },
                ToolId::AlertsGet,
                json!({"alert_id":"a/b"}),
                None,
            ),
            (
                ResourceRef::Case {
                    case_id: "c".into(),
                },
                ToolId::CasesGet,
                json!({"id":"c"}),
                None,
            ),
            (
                ResourceRef::ExceptionList {
                    namespace_type: "single".into(),
                    list_id: "l".into(),
                },
                ToolId::ExceptionsGet,
                json!({"list_id":"l","namespace":"single","limit":50}),
                None,
            ),
            (
                ResourceRef::ExceptionList {
                    namespace_type: "agnostic".into(),
                    list_id: "x".into(),
                },
                ToolId::ExceptionsGet,
                json!({"list_id":"x","namespace":"agnostic","limit":50}),
                None,
            ),
            (
                ResourceRef::Rule {
                    rule_id: "r".into(),
                },
                ToolId::RulesGet,
                json!({"selector":"r"}),
                Some("r"),
            ),
        ] {
            let call = call_for(&reference);
            assert_eq!(call.tool, tool);
            assert_eq!(Value::Object(call.arguments), arguments);
            assert_eq!(call.expect_rule_id.as_deref(), expect_rule_id);
        }
    }
}
