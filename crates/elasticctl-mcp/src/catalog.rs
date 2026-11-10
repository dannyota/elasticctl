//! Static MCP tool catalog.

use rmcp::model::Tool;

/// The complete MCP tool namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolId {
    AlertContext,
    AlertsGet,
    AlertsList,
    CasesGet,
    CasesList,
    DashboardsGet,
    DashboardsList,
    DataViewsDefaultGet,
    DataViewsGet,
    DataViewsList,
    DetectionCoverage,
    ExceptionsGet,
    ExceptionsList,
    FleetAgentPoliciesGet,
    FleetAgentPoliciesList,
    FleetIntegrationPoliciesGet,
    FleetIntegrationPoliciesList,
    RuleHealth,
    RuleReadiness,
    RulesGet,
    RulesList,
    RulesPrebuiltStatus,
    SearchDsl,
    SearchEsql,
    StackDoctor,
    StackInfo,
}

impl ToolId {
    pub const ALL: [Self; 26] = [
        Self::AlertContext,
        Self::AlertsGet,
        Self::AlertsList,
        Self::CasesGet,
        Self::CasesList,
        Self::DashboardsGet,
        Self::DashboardsList,
        Self::DataViewsDefaultGet,
        Self::DataViewsGet,
        Self::DataViewsList,
        Self::DetectionCoverage,
        Self::ExceptionsGet,
        Self::ExceptionsList,
        Self::FleetAgentPoliciesGet,
        Self::FleetAgentPoliciesList,
        Self::FleetIntegrationPoliciesGet,
        Self::FleetIntegrationPoliciesList,
        Self::RuleHealth,
        Self::RuleReadiness,
        Self::RulesGet,
        Self::RulesList,
        Self::RulesPrebuiltStatus,
        Self::SearchDsl,
        Self::SearchEsql,
        Self::StackDoctor,
        Self::StackInfo,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::RuleReadiness => "rule_readiness",
            Self::RuleHealth => "rule_health",
            Self::DetectionCoverage => "detection_coverage",
            Self::AlertContext => "alert_context",
            Self::AlertsGet => "alerts_get",
            Self::AlertsList => "alerts_list",
            Self::CasesGet => "cases_get",
            Self::CasesList => "cases_list",
            Self::DashboardsGet => "dashboards_get",
            Self::DashboardsList => "dashboards_list",
            Self::DataViewsDefaultGet => "data_views_default_get",
            Self::DataViewsGet => "data_views_get",
            Self::DataViewsList => "data_views_list",
            Self::ExceptionsGet => "exceptions_get",
            Self::ExceptionsList => "exceptions_list",
            Self::FleetAgentPoliciesGet => "fleet_agent_policies_get",
            Self::FleetAgentPoliciesList => "fleet_agent_policies_list",
            Self::FleetIntegrationPoliciesGet => "fleet_integration_policies_get",
            Self::FleetIntegrationPoliciesList => "fleet_integration_policies_list",
            Self::RulesGet => "rules_get",
            Self::RulesList => "rules_list",
            Self::RulesPrebuiltStatus => "rules_prebuilt_status",
            Self::SearchDsl => "search_dsl",
            Self::SearchEsql => "search_esql",
            Self::StackDoctor => "stack_doctor",
            Self::StackInfo => "stack_info",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }
}

/// Return the registered production catalog.
pub fn definitions() -> Vec<Tool> {
    crate::tools::definitions(false)
}

pub(crate) fn definitions_for(allow_query_tools: bool) -> Vec<Tool> {
    crate::tools::definitions(allow_query_tools)
}
