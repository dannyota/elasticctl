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

    pub fn partial(&self) -> bool {
        matches!(self.alerts, Part::Unavailable(_))
            || match &self.exceptions {
                Part::Ok(coverage) => coverage.lists.iter().any(|row| row.facts.is_err()),
                Part::Unavailable(_) => true,
                Part::Skipped(_) => false,
            }
    }
}
