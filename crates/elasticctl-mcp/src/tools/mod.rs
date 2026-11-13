use std::{future::Future, pin::Pin};

use elasticctl_core::Error;
use rmcp::model::Tool;
use tokio_util::sync::CancellationToken;

use crate::{PageInfo, ServerState, catalog::ToolId};

mod compose;
mod content;
mod exceptions;
mod fleet;
mod mutations;
mod plans;
mod query;
mod rules;
mod stack;
mod triage;

#[derive(Clone, Debug)]
pub struct AdapterResult {
    pub data: serde_json::Value,
    pub page: Option<PageInfo>,
    pub row_key: Option<&'static str>,
}

#[derive(Debug)]
pub enum AdapterError {
    InvalidArgument,
    Core(Error),
    Tool(crate::ToolError),
}

mod context;
pub use context::{CallContext, CallProtocol};

pub trait ToolAdapter: Send + Sync {
    fn definitions(&self) -> Vec<Tool>;

    fn call_with_context<'a>(
        &'a self,
        tool: ToolId,
        arguments: Option<&'a rmcp::model::JsonObject>,
        state: &'a ServerState,
        cancellation: CancellationToken,
        _context: CallContext,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<AdapterResult, AdapterError>> + Send + 'a>>
    {
        self.call(tool, arguments, state, cancellation)
    }

    fn call<'a>(
        &'a self,
        tool: ToolId,
        arguments: Option<&'a rmcp::model::JsonObject>,
        state: &'a ServerState,
        cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<AdapterResult, AdapterError>> + Send + 'a>>;
}

pub(crate) fn adapter_for(tool: ToolId) -> Option<&'static dyn ToolAdapter> {
    match tool {
        ToolId::PlanApply | ToolId::PlanDiscard | ToolId::PlanGet | ToolId::PlanList => {
            Some(plans::adapter())
        }
        ToolId::AlertsSetStatusPlan | ToolId::AlertsSetTagsPlan => {
            Some(mutations::alerts::adapter())
        }
        ToolId::CasesCommentPlan | ToolId::CasesCreatePlan | ToolId::CasesSetStatusPlan => {
            Some(mutations::cases::adapter())
        }
        ToolId::RulesCreatePlan => Some(mutations::rules_create::adapter()),
        ToolId::RulesSetEnabledPlan => Some(mutations::rules::adapter()),
        ToolId::AlertContext
        | ToolId::DetectionCoverage
        | ToolId::RuleHealth
        | ToolId::RuleReadiness => Some(compose::adapter()),
        ToolId::DashboardsGet
        | ToolId::DashboardsList
        | ToolId::DataViewsDefaultGet
        | ToolId::DataViewsGet
        | ToolId::DataViewsList => Some(content::adapter()),
        ToolId::FleetAgentPoliciesGet
        | ToolId::FleetAgentPoliciesList
        | ToolId::FleetIntegrationPoliciesGet
        | ToolId::FleetIntegrationPoliciesList => Some(fleet::adapter()),
        ToolId::AlertsGet | ToolId::AlertsList | ToolId::CasesGet | ToolId::CasesList => {
            Some(triage::adapter())
        }
        ToolId::ExceptionsGet | ToolId::ExceptionsList => Some(exceptions::adapter()),
        ToolId::RulesGet | ToolId::RulesList | ToolId::RulesPrebuiltStatus => {
            Some(rules::adapter())
        }
        ToolId::SearchDsl | ToolId::SearchEsql => Some(query::adapter()),
        ToolId::StackDoctor | ToolId::StackInfo => Some(stack::adapter()),
    }
}

pub(crate) fn definitions(options: &crate::ServerOptions) -> Vec<Tool> {
    ToolId::ALL
        .into_iter()
        .filter(|tool| tool.enabled(options))
        .map(|tool| {
            adapter_for(tool)
                .expect("registered adapter")
                .definitions()
                .into_iter()
                .find(|definition| definition.name == tool.name())
                .expect("registered definition")
        })
        .collect()
}
