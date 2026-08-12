//! The canonical rule representation.
//!
//! Backed by a JSON map rather than a wide struct: the measured create
//! response carries 36 fields, the set varies by rule type, and it grows
//! between Elastic versions. A map preserves unknown fields by construction,
//! which is what round-trip fidelity requires.

use elasticctl_core::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

/// Server-owned fields that change on every write. Stripped before diffing,
/// or every pull would report drift that no one caused.
pub const VOLATILE_FIELDS: [&str; 7] = [
    "id",
    "created_at",
    "created_by",
    "updated_at",
    "updated_by",
    "revision",
    "version",
];

/// Fields the server fills when a create request omits them. Measured by
/// creating a rule with 13 fields and reading back 36.
///
/// A sparse hand-authored file must have these filled before it is compared,
/// or an omitted field reads as drift rather than as "accept the default".
pub fn server_defaults() -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("actions".into(), json!([]));
    m.insert("author".into(), json!([]));
    m.insert("exceptions_list".into(), json!([]));
    m.insert("false_positives".into(), json!([]));
    m.insert("immutable".into(), json!(false));
    m.insert("max_signals".into(), json!(100));
    m.insert("output_index".into(), json!(""));
    m.insert("references".into(), json!([]));
    m.insert("related_integrations".into(), json!([]));
    m.insert("required_fields".into(), json!([]));
    m.insert("risk_score_mapping".into(), json!([]));
    m.insert("rule_source".into(), json!({"type": "internal"}));
    m.insert("setup".into(), json!(""));
    m.insert("severity_mapping".into(), json!([]));
    m.insert("threat".into(), json!([]));
    m.insert("to".into(), json!("now"));
    m
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Rule(Map<String, Value>);

impl Rule {
    pub fn from_value(v: Value) -> Result<Rule> {
        let map = match v {
            Value::Object(m) => m,
            _ => return Err(Error::new(ErrorKind::Error, "a rule must be a JSON object")),
        };
        if !map.contains_key("rule_id") {
            return Err(Error::new(ErrorKind::Error, "a rule must have a rule_id"));
        }
        Ok(Rule(map))
    }

    pub fn into_value(self) -> Value {
        Value::Object(self.0)
    }

    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }

    pub fn as_map_mut(&mut self) -> &mut Map<String, Value> {
        &mut self.0
    }

    fn str_field(&self, key: &str) -> &str {
        self.0.get(key).and_then(Value::as_str).unwrap_or("")
    }

    /// The stable identity used for all state matching. Guaranteed present by
    /// `from_value`, but returned as a `Result` so a hand-built `Rule` cannot
    /// silently match the wrong remote rule.
    pub fn rule_id(&self) -> Result<&str> {
        self.0
            .get("rule_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new(ErrorKind::Error, "rule is missing rule_id"))
    }

    pub fn name(&self) -> &str {
        self.str_field("name")
    }

    pub fn rule_type(&self) -> &str {
        self.str_field("type")
    }

    pub fn severity(&self) -> &str {
        self.str_field("severity")
    }

    pub fn enabled(&self) -> bool {
        self.0
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    pub fn risk_score(&self) -> i64 {
        self.0
            .get("risk_score")
            .and_then(Value::as_i64)
            .unwrap_or(0)
    }

    pub fn tags(&self) -> Vec<&str> {
        self.0
            .get("tags")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }
}

/// The trailer Kibana appends to an NDJSON export. With zero rules it is the
/// entire body, so it must never be parsed as a rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportSummary {
    #[serde(default)]
    pub exported_count: u64,
    #[serde(default)]
    pub exported_rules_count: u64,
    #[serde(default)]
    pub missing_rules_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn probe_rule() -> Value {
        // Trimmed from a real create response on Serverless Security 9.6.0.
        json!({
            "rule_id": "elasticctl-schema-probe",
            "name": "elasticctl schema probe",
            "description": "Temporary rule.",
            "type": "query",
            "language": "kuery",
            "query": "event.category:process",
            "index": ["logs-*"],
            "severity": "low",
            "risk_score": 21,
            "enabled": false,
            "from": "now-6m",
            "interval": "5m",
            "tags": ["elasticctl", "temporary"],
            "id": "6b796e42-99fa-4296-8dc1-a693dd455dd0",
            "created_at": "2026-08-12T17:49:01.682Z",
            "created_by": "2XTe9p8BLjNicQlhfc9W",
            "updated_at": "2026-08-12T17:49:01.682Z",
            "updated_by": "2XTe9p8BLjNicQlhfc9W",
            "revision": 0,
            "version": 1,
            "max_signals": 100,
            "to": "now",
            "rule_source": {"type": "internal"}
        })
    }

    #[test]
    fn accessors_read_the_measured_fields() {
        let r = Rule::from_value(probe_rule()).unwrap();
        assert_eq!(r.rule_id().unwrap(), "elasticctl-schema-probe");
        assert_eq!(r.name(), "elasticctl schema probe");
        assert_eq!(r.rule_type(), "query");
        assert!(!r.enabled());
        assert_eq!(r.severity(), "low");
        assert_eq!(r.risk_score(), 21);
        assert_eq!(r.tags(), vec!["elasticctl", "temporary"]);
    }

    #[test]
    fn every_unknown_field_survives_a_round_trip() {
        let original = probe_rule();
        let r = Rule::from_value(original.clone()).unwrap();
        assert_eq!(r.into_value(), original, "no field may be dropped");
    }

    #[test]
    fn a_rule_without_rule_id_is_rejected() {
        let err = Rule::from_value(json!({"name": "x"})).unwrap_err();
        assert_eq!(err.kind, elasticctl_core::ErrorKind::Error);
        assert!(err.message.contains("rule_id"));
    }

    #[test]
    fn a_non_object_is_rejected() {
        assert!(Rule::from_value(json!(["not", "an", "object"])).is_err());
    }

    #[test]
    fn missing_optional_fields_read_as_sane_defaults() {
        let r = Rule::from_value(json!({"rule_id": "x"})).unwrap();
        assert_eq!(r.name(), "");
        assert_eq!(r.rule_type(), "");
        assert!(!r.enabled());
        assert_eq!(r.risk_score(), 0);
        assert!(r.tags().is_empty());
    }

    #[test]
    fn volatile_field_list_matches_the_measured_set() {
        let mut got = VOLATILE_FIELDS.to_vec();
        got.sort_unstable();
        assert_eq!(
            got,
            [
                "created_at",
                "created_by",
                "id",
                "revision",
                "updated_at",
                "updated_by",
                "version"
            ]
        );
    }

    #[test]
    fn server_defaults_cover_the_sixteen_measured_fields() {
        let d = server_defaults();
        assert_eq!(d.len(), 16);
        assert_eq!(d["max_signals"], json!(100));
        assert_eq!(d["to"], json!("now"));
        assert_eq!(d["actions"], json!([]));
        assert_eq!(d["rule_source"], json!({"type": "internal"}));
        assert_eq!(d["immutable"], json!(false));
        assert_eq!(d["setup"], json!(""));
        assert_eq!(d["output_index"], json!(""));
    }

    #[test]
    fn volatile_and_default_field_sets_do_not_overlap() {
        // A field cannot be both stripped and filled — that would be ambiguous.
        for v in VOLATILE_FIELDS {
            assert!(!server_defaults().contains_key(v), "{v} is in both sets");
        }
    }
}
