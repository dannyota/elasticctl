use super::{
    AlertActivity, ExceptionCoverage, MAX_RELATED_CASES, Part, RuleSnapshot, SkipReason,
    alert_activity, degrade, exception_coverage, is_fatal, is_path_segment, snapshot_by_id,
    validate_since,
};
use crate::{
    alerts::AlertHit,
    alerts_ops,
    cases::{self, Case},
};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::Value;

#[derive(Debug)]
pub struct RelatedCase {
    pub id: String,
    pub title: Option<String>,
    pub detail: std::result::Result<Case, Error>,
}

#[derive(Debug)]
pub struct RelatedCases {
    pub total: usize,
    pub truncated: bool,
    pub cases: Vec<RelatedCase>,
}

#[derive(Debug)]
pub struct AlertContext {
    pub alert: AlertHit,
    pub rule: Part<RuleSnapshot>,
    pub exceptions: Part<ExceptionCoverage>,
    pub cases: Part<RelatedCases>,
    pub activity: Part<AlertActivity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertFinding {
    AlertNotOpen,
    RuleMissing,
    RuleDisabled,
    RuleLastExecutionFailed,
    ExceptionListMissing,
    HasRelatedCase,
}

fn source_str<'a>(source: &'a Value, key: &str) -> Option<&'a str> {
    let pointer = format!("/{}", key.replace('.', "/"));
    match source.get(key) {
        Some(v) => v.as_str(),
        None => source.pointer(&pointer).and_then(Value::as_str),
    }
}

fn unavailable<T>(part: &Part<T>) -> bool {
    matches!(part, Part::Unavailable(_))
}

impl AlertContext {
    pub fn findings(&self) -> Vec<AlertFinding> {
        let mut out = Vec::new();
        if source_str(&self.alert.source, "kibana.alert.workflow_status")
            .is_some_and(|s| s != "open")
        {
            out.push(AlertFinding::AlertNotOpen);
        }
        if matches!(&self.rule, Part::Unavailable(e) if e.kind == ErrorKind::NotFound) {
            out.push(AlertFinding::RuleMissing);
        }
        if let Part::Ok(snapshot) = &self.rule {
            if snapshot
                .rule
                .as_map()
                .get("enabled")
                .and_then(Value::as_bool)
                == Some(false)
            {
                out.push(AlertFinding::RuleDisabled);
            }
            if snapshot
                .execution
                .as_ref()
                .is_some_and(|e| e.status == "failed")
            {
                out.push(AlertFinding::RuleLastExecutionFailed);
            }
        }
        if let Part::Ok(coverage) = &self.exceptions
            && coverage
                .lists
                .iter()
                .any(|l| matches!(&l.facts, Err(e) if e.kind == ErrorKind::NotFound))
        {
            out.push(AlertFinding::ExceptionListMissing);
        }
        if matches!(&self.cases, Part::Ok(c) if c.total > 0) {
            out.push(AlertFinding::HasRelatedCase);
        }
        out
    }

    pub fn partial(&self) -> bool {
        let list_rows =
            matches!(&self.exceptions, Part::Ok(c) if c.lists.iter().any(|l| l.facts.is_err()));
        let case_rows =
            matches!(&self.cases, Part::Ok(c) if c.cases.iter().any(|r| r.detail.is_err()));
        unavailable(&self.rule)
            || unavailable(&self.exceptions)
            || unavailable(&self.cases)
            || unavailable(&self.activity)
            || list_rows
            || case_rows
    }
}

async fn related_cases(t: &Transport, alert_id: &str) -> Result<RelatedCases> {
    let refs = cases::by_alert(t, alert_id).await?;
    let total = refs.len();
    let mut rows = Vec::new();
    for r in refs.into_iter().take(MAX_RELATED_CASES) {
        let detail = cases::get(t, &r.id).await;
        if let Err(e) = &detail
            && is_fatal(e.kind)
        {
            return Err(detail.unwrap_err());
        }
        rows.push(RelatedCase {
            id: r.id,
            title: r.title,
            detail,
        });
    }
    Ok(RelatedCases {
        total,
        truncated: total > MAX_RELATED_CASES,
        cases: rows,
    })
}

fn validate_rule_context(snapshot: RuleSnapshot) -> Result<RuleSnapshot> {
    let invalid = || Error::new(ErrorKind::Http, "invalid rule context field");
    fn optional<T: serde::de::DeserializeOwned>(
        map: &serde_json::Map<String, Value>,
        key: &str,
    ) -> Result<()> {
        if let Some(value) = map.get(key).filter(|v| !v.is_null()) {
            serde_json::from_value::<T>(value.clone())
                .map_err(|_| Error::new(ErrorKind::Http, "invalid rule context field"))?;
        }
        Ok(())
    }
    let map = snapshot.rule.as_map();
    if !map.get("rule_id").is_some_and(Value::is_string) {
        return Err(invalid());
    }
    for key in [
        "name",
        "type",
        "severity",
        "description",
        "language",
        "query",
        "from",
        "interval",
    ] {
        optional::<String>(map, key)?;
    }
    optional::<bool>(map, "enabled")?;
    optional::<serde_json::Number>(map, "risk_score")?;
    for key in ["tags", "index"] {
        optional::<Vec<String>>(map, key)?;
    }
    if let Some(value) = map.get("exceptions_list").filter(|v| !v.is_null()) {
        for entry in value.as_array().ok_or_else(invalid)? {
            let entry = entry.as_object().ok_or_else(invalid)?;
            for key in ["list_id", "namespace_type", "type"] {
                optional::<String>(entry, key)?;
            }
        }
    }
    Ok(snapshot)
}

pub async fn alert_context(t: &Transport, alert_id: &str, since: &str) -> Result<AlertContext> {
    validate_since(since)?;
    if !is_path_segment(alert_id) {
        return Err(Error::new(ErrorKind::Error, "invalid alert id"));
    }
    let alert = alerts_ops::get_one(t, alert_id).await?;
    let rule_id = source_str(&alert.source, "kibana.alert.rule.rule_id").map(str::to_owned);
    let rule = match &rule_id {
        Some(id) => degrade(snapshot_by_id(t, id).await.and_then(validate_rule_context))?,
        None => Part::Skipped(SkipReason::NotApplicable),
    };
    let exceptions = match &rule {
        Part::Ok(snapshot) => degrade(exception_coverage(t, &snapshot.rule).await)?,
        _ => Part::Skipped(SkipReason::DependencyUnavailable),
    };
    let cases = degrade(related_cases(t, alert_id).await)?;
    let activity = match (&rule, &rule_id) {
        (Part::Ok(_), Some(id)) => degrade(alert_activity(t, id, since, 0).await)?,
        _ => Part::Skipped(SkipReason::DependencyUnavailable),
    };
    Ok(AlertContext {
        alert,
        rule,
        exceptions,
        cases,
        activity,
    })
}
