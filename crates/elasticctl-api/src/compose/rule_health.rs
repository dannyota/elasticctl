//! Health of one rule: its last execution, alert volume in a window, and the
//! exception lists that narrow it.
use super::{
    AlertActivity, ExceptionCoverage, Part, RECENT_ALERTS, RuleSnapshot, alert_activity, degrade,
    exception_coverage, snapshot_by_selector, validate_since,
};
use elasticctl_core::{ErrorKind, Result, Transport};
use serde_json::Value;

#[derive(Debug)]
pub struct RuleHealth {
    pub rule: RuleSnapshot,
    pub alerts: Part<AlertActivity>,
    pub exceptions: Part<ExceptionCoverage>,
}

/// Static finding codes, in the order a report lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthFinding {
    RuleDisabled,
    NeverExecuted,
    LastExecutionFailed,
    LastExecutionPartialFailure,
    ExecutionGap,
    NoAlertsInWindow,
    ExceptionListMissing,
}

/// Read the rule by selector, then its alert activity with the five newest
/// alerts, then its exception coverage. The two parts do not depend on each
/// other; a fatal error kind in either fails the call.
pub async fn rule_health(t: &Transport, selector: &str, since: &str) -> Result<RuleHealth> {
    validate_since(since)?;
    let rule = snapshot_by_selector(t, selector).await?;
    let rule_id = rule.rule.rule_id()?.to_owned();
    let alerts = degrade(alert_activity(t, &rule_id, since, RECENT_ALERTS).await)?;
    let exceptions = degrade(exception_coverage(t, &rule.rule).await)?;
    Ok(RuleHealth {
        rule,
        alerts,
        exceptions,
    })
}

impl RuleHealth {
    /// Findings from typed comparisons. Status strings are compared exactly,
    /// so an unknown status yields no execution finding.
    pub fn findings(&self) -> Vec<HealthFinding> {
        let mut out = Vec::new();
        let enabled = self
            .rule
            .rule
            .as_map()
            .get("enabled")
            .and_then(Value::as_bool);
        let execution = self.rule.execution.as_ref();
        if enabled == Some(false) {
            out.push(HealthFinding::RuleDisabled);
        }
        if enabled == Some(true) && execution.is_none() {
            out.push(HealthFinding::NeverExecuted);
        }
        if let Some(e) = execution {
            match e.status.as_str() {
                "failed" => out.push(HealthFinding::LastExecutionFailed),
                "partial failure" => out.push(HealthFinding::LastExecutionPartialFailure),
                _ => {}
            }
            if e.metrics
                .execution_gap_duration_s
                .is_some_and(|gap| gap > 0.0)
            {
                out.push(HealthFinding::ExecutionGap);
            }
        }
        if let Part::Ok(alerts) = &self.alerts
            && alerts.total == 0
        {
            out.push(HealthFinding::NoAlertsInWindow);
        }
        if let Part::Ok(coverage) = &self.exceptions
            && coverage
                .lists
                .iter()
                .any(|row| matches!(&row.facts, Err(e) if e.kind == ErrorKind::NotFound))
        {
            out.push(HealthFinding::ExceptionListMissing);
        }
        out
    }

    /// True when a part or an exception list row is unavailable.
    pub fn partial(&self) -> bool {
        matches!(self.alerts, Part::Unavailable(_))
            || match &self.exceptions {
                Part::Ok(coverage) => coverage.lists.iter().any(|row| row.facts.is_err()),
                Part::Unavailable(_) => true,
                Part::Skipped(_) => false,
            }
    }
}
