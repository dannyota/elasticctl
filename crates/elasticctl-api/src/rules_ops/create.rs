//! Rule creation plans and outcomes.

use super::*;
use crate::Preconditions;

/// A rule creation plan with its preview.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleCreatePlan {
    /// The rule to create.
    pub rule: Rule,
    /// The mutation preview.
    pub preview: MutationPlan,
}

/// The outcome of creating a disabled rule.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RuleCreateOutcome {
    /// Whether the rule was created.
    pub applied: bool,
    /// The created rule ID.
    pub rule_id: String,
    /// Whether the created rule is enabled.
    pub enabled: bool,
}

/// Plan creation of a disabled rule and read its absence.
pub async fn plan_create(_t: &Transport, _rule: Rule) -> Result<(RuleCreatePlan, Preconditions)> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "plan_create is not available in this build",
    ))
}

/// Create the disabled rule in the plan.
pub async fn apply_create(_t: &Transport, _plan: &RuleCreatePlan) -> Result<RuleCreateOutcome> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "apply_create is not available in this build",
    ))
}
