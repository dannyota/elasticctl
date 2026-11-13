use crate::{Rule, normalize, rules, selection};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::Value;
#[derive(Debug)]
pub struct ExecutionMetrics {
    pub total_search_duration_ms: Option<f64>,
    pub total_indexing_duration_ms: Option<f64>,
    pub total_enrichment_duration_ms: Option<f64>,
    pub execution_gap_duration_s: Option<f64>,
}
#[derive(Debug)]
pub struct LastExecution {
    pub status: String,
    pub date: String,
    pub status_order: Option<i64>,
    pub message: Option<String>,
    pub message_truncated: bool,
    pub metrics: ExecutionMetrics,
}
#[derive(Debug)]
pub struct RuleSnapshot {
    pub rule: Rule,
    pub execution: Option<LastExecution>,
}
fn invalid() -> Error {
    Error::new(ErrorKind::Http, "invalid rule execution response")
}
fn optional<T: serde::de::DeserializeOwned>(v: &Value, k: &str) -> Result<Option<T>> {
    v.get(k)
        .map(|v| serde_json::from_value(v.clone()).map_err(|_| invalid()))
        .transpose()
}
fn snapshot(rule: Rule) -> Result<RuleSnapshot> {
    let execution = if let Some(summary) = rule
        .as_map()
        .get("execution_summary")
        .filter(|summary| !summary.is_null())
    {
        let e = summary
            .get("last_execution")
            .filter(|v| v.is_object())
            .ok_or_else(invalid)?;
        let status = e
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?
            .to_owned();
        let date = e
            .get("date")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?
            .to_owned();
        let mut message: Option<String> = optional(e, "message")?;
        let mut message_truncated = false;
        if let Some(m) = &mut message
            && m.len() > super::MESSAGE_BYTES
        {
            let mut end = super::MESSAGE_BYTES;
            while !m.is_char_boundary(end) {
                end -= 1;
            }
            m.truncate(end);
            message_truncated = true;
        }
        let empty = serde_json::json!({});
        let metrics = e.get("metrics").unwrap_or(&empty);
        if !metrics.is_object() {
            return Err(invalid());
        }
        Some(LastExecution {
            status,
            date,
            status_order: optional(e, "status_order")?,
            message,
            message_truncated,
            metrics: ExecutionMetrics {
                total_search_duration_ms: optional(metrics, "total_search_duration_ms")?,
                total_indexing_duration_ms: optional(metrics, "total_indexing_duration_ms")?,
                total_enrichment_duration_ms: optional(metrics, "total_enrichment_duration_ms")?,
                execution_gap_duration_s: optional(metrics, "execution_gap_duration_s")?,
            },
        })
    } else {
        None
    };
    Ok(RuleSnapshot {
        rule: normalize::canonical(&rule),
        execution,
    })
}
pub async fn snapshot_by_id(t: &Transport, rule_id: &str) -> Result<RuleSnapshot> {
    let rule = rules::get(t, rule_id).await?;
    if rule.rule_id()? != rule_id {
        return Err(Error::new(ErrorKind::NotFound, "rule identity mismatch"));
    }
    snapshot(rule)
}
pub async fn snapshot_by_selector(t: &Transport, selector: &str) -> Result<RuleSnapshot> {
    let (_, rule) = selection::to_rule(t, selector).await?;
    snapshot(rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn recorded() -> Rule {
        let value: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/traditional-9.5.1/rules_get.json"
        )))
        .unwrap();
        Rule::from_value(value["response"].clone()).unwrap()
    }
    #[test]
    fn execution_decoder_and_character_boundary() {
        let mut rule = recorded();
        rule.as_map_mut().remove("execution_summary");
        assert!(snapshot(rule.clone()).unwrap().execution.is_none());
        rule.as_map_mut().insert("execution_summary".into(),serde_json::json!({"last_execution":{"status":"failed","date":"today","message":"界".repeat(1000),"metrics":{"unknown":"ignored","total_search_duration_ms":3}}}));
        let execution = snapshot(rule.clone()).unwrap().execution.unwrap();
        assert_eq!(execution.message.as_ref().unwrap().len(), 2046);
        assert!(execution.message_truncated);
        assert_eq!(execution.metrics.total_search_duration_ms, Some(3.0));
        for field in ["status", "date"] {
            let mut bad = rule.clone();
            bad.as_map_mut()["execution_summary"]["last_execution"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert_eq!(snapshot(bad).unwrap_err().kind, ErrorKind::Http);
        }
        for field in [
            "total_search_duration_ms",
            "total_indexing_duration_ms",
            "total_enrichment_duration_ms",
            "execution_gap_duration_s",
        ] {
            let mut bad = rule.clone();
            bad.as_map_mut()["execution_summary"]["last_execution"]["metrics"][field] =
                serde_json::json!("bad");
            assert_eq!(snapshot(bad).unwrap_err().kind, ErrorKind::Http);
        }
    }
}
