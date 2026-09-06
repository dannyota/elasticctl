//! Static MCP tool catalog.

use rmcp::model::Tool;

/// The complete 0.7 MCP tool namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolId {
    ExceptionsGet,
    ExceptionsList,
    RulesGet,
    RulesList,
    RulesPrebuiltStatus,
    StackDoctor,
    StackInfo,
}

impl ToolId {
    pub const ALL: [Self; 7] = [
        Self::ExceptionsGet,
        Self::ExceptionsList,
        Self::RulesGet,
        Self::RulesList,
        Self::RulesPrebuiltStatus,
        Self::StackDoctor,
        Self::StackInfo,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::ExceptionsGet => "exceptions_get",
            Self::ExceptionsList => "exceptions_list",
            Self::RulesGet => "rules_get",
            Self::RulesList => "rules_list",
            Self::RulesPrebuiltStatus => "rules_prebuilt_status",
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
    crate::tools::definitions()
}
