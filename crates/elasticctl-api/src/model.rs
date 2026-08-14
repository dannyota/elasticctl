//! The rule, exception-list, and exception-item representations.
//!
//! A measured create response has 36 fields, which vary by rule type and
//! Elastic version. A JSON map preserves unknown fields; a fixed struct would
//! break round trips.

use elasticctl_core::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

/// Server-owned fields that change on every write or execution. They are
/// stripped before diffing to avoid false drift.
pub const VOLATILE_FIELDS: [&str; 8] = [
    "id",
    "created_at",
    "created_by",
    "updated_at",
    "updated_by",
    "revision",
    "version",
    "execution_summary",
];

/// Fields the server fills when a create request omits them.
///
/// Measured: a 13-field create returned 36 fields. Fill these defaults before
/// comparison so omitted values do not appear as drift.
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
        // Validate identity at the shared construction path. A non-string
        // `rule_id` cannot match, name a file, or be reported.
        match map.get("rule_id") {
            Some(Value::String(_)) => {}
            Some(_) => {
                return Err(Error::new(
                    ErrorKind::Error,
                    "a rule's rule_id must be a string",
                ));
            }
            None => return Err(Error::new(ErrorKind::Error, "a rule must have a rule_id")),
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

    /// The stable identity used for state matching.
    ///
    /// `from_value` requires a string `rule_id`, but transparent `Deserialize`
    /// and `as_map_mut` can bypass that validation. Return an error rather than
    /// silently matching the wrong remote rule.
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

/// The trailer Kibana appends to an NDJSON export. It is the entire body for
/// a zero-rule export, so it must not be parsed as a rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportSummary {
    #[serde(default)]
    pub exported_count: u64,
    #[serde(default)]
    pub exported_rules_count: u64,
    #[serde(default)]
    pub missing_rules_count: u64,
    /// Rules selected for export but not returned, likely deleted after
    /// selection. Kept as raw server values.
    #[serde(default)]
    pub missing_rules: Vec<Value>,
    #[serde(default)]
    pub exported_exception_list_count: u64,
    #[serde(default)]
    pub exported_exception_list_item_count: u64,
    #[serde(default)]
    pub missing_exception_lists: Vec<Value>,
    #[serde(default)]
    pub missing_exception_list_items: Vec<Value>,
}

/// Server-owned fields an exception list container changes on every write.
/// Stripped before diffing, like `VOLATILE_FIELDS` is for rules.
pub const LIST_VOLATILE_FIELDS: [&str; 8] = [
    "id",
    "_version",
    "tie_breaker_id",
    "version",
    "created_at",
    "created_by",
    "updated_at",
    "updated_by",
];

/// The container set less `version`: a measured item carries `_version` but no
/// `version`.
pub const ITEM_VOLATILE_FIELDS: [&str; 7] = [
    "id",
    "_version",
    "tie_breaker_id",
    "created_at",
    "created_by",
    "updated_at",
    "updated_by",
];

/// Server-minted fields on an exception item comment. `id`, `created_at`, and
/// `created_by` are measured; `updated_at` and `updated_by` were absent on a
/// freshly created comment but name the same class on every other object in
/// this API, and removing an absent key costs nothing.
pub const COMMENT_VOLATILE_FIELDS: [&str; 5] =
    ["id", "created_at", "created_by", "updated_at", "updated_by"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExceptionList(Map<String, Value>);

impl ExceptionList {
    pub fn from_value(v: Value) -> Result<ExceptionList> {
        let map = match v {
            Value::Object(m) => m,
            _ => {
                return Err(Error::new(
                    ErrorKind::Error,
                    "an exception list must be a JSON object",
                ));
            }
        };
        match map.get("list_id") {
            Some(Value::String(_)) => {}
            Some(_) => {
                return Err(Error::new(
                    ErrorKind::Error,
                    "an exception list's list_id must be a string",
                ));
            }
            None => {
                return Err(Error::new(
                    ErrorKind::Error,
                    "an exception list must have a list_id",
                ));
            }
        }
        Ok(ExceptionList(map))
    }

    pub fn list_id(&self) -> Result<&str> {
        self.0
            .get("list_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new(ErrorKind::Error, "exception list is missing list_id"))
    }

    /// `single` is the API's own default and the value every measured response
    /// carried. An absent value must resolve, or identity would depend on
    /// whether a response happened to include the field.
    pub fn namespace_type(&self) -> &str {
        self.0
            .get("namespace_type")
            .and_then(Value::as_str)
            .unwrap_or("single")
    }

    pub fn list_type(&self) -> &str {
        self.0.get("type").and_then(Value::as_str).unwrap_or("")
    }

    pub fn name(&self) -> &str {
        self.0.get("name").and_then(Value::as_str).unwrap_or("")
    }

    pub fn tags(&self) -> Vec<&str> {
        self.0
            .get("tags")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }

    pub fn key(&self) -> Result<ListKey> {
        Ok(ListKey {
            list_id: self.list_id()?.to_string(),
            namespace_type: self.namespace_type().to_string(),
        })
    }

    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }

    pub fn as_map_mut(&mut self) -> &mut Map<String, Value> {
        &mut self.0
    }

    pub fn into_value(self) -> Value {
        Value::Object(self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExceptionItem(Map<String, Value>);

impl ExceptionItem {
    pub fn from_value(v: Value) -> Result<ExceptionItem> {
        let map = match v {
            Value::Object(m) => m,
            _ => {
                return Err(Error::new(
                    ErrorKind::Error,
                    "an exception item must be a JSON object",
                ));
            }
        };
        match map.get("item_id") {
            Some(Value::String(_)) => {}
            Some(_) => {
                return Err(Error::new(
                    ErrorKind::Error,
                    "an exception item's item_id must be a string",
                ));
            }
            None => {
                return Err(Error::new(
                    ErrorKind::Error,
                    "an exception item must have an item_id",
                ));
            }
        }
        Ok(ExceptionItem(map))
    }

    pub fn item_id(&self) -> Result<&str> {
        self.0
            .get("item_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new(ErrorKind::Error, "exception item is missing item_id"))
    }

    /// An item without a list has no home, so absence is an error rather than
    /// a default.
    pub fn list_id(&self) -> Result<&str> {
        self.0
            .get("list_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new(ErrorKind::Error, "exception item is missing list_id"))
    }

    pub fn namespace_type(&self) -> &str {
        self.0
            .get("namespace_type")
            .and_then(Value::as_str)
            .unwrap_or("single")
    }

    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }

    pub fn as_map_mut(&mut self) -> &mut Map<String, Value> {
        &mut self.0
    }

    pub fn into_value(self) -> Value {
        Value::Object(self.0)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct ListKey {
    pub list_id: String,
    pub namespace_type: String,
}

/// The `{id, list_id, type, namespace_type}` reference a rule carries.
pub struct ExceptionRef {
    pub list_id: String,
    pub namespace_type: String,
    pub ref_type: String,
    pub id: Option<String>,
}

/// Read a rule's `exceptions_list` array. A malformed entry is skipped rather
/// than failing the rule: the field is server-owned and unknown shapes must
/// survive a round trip.
pub fn exception_refs(rule: &Rule) -> Vec<ExceptionRef> {
    let entries = match rule
        .as_map()
        .get("exceptions_list")
        .and_then(Value::as_array)
    {
        Some(a) => a,
        None => return Vec::new(),
    };
    entries
        .iter()
        .filter_map(|entry| {
            let obj = entry.as_object()?;
            let list_id = obj.get("list_id")?.as_str()?.to_string();
            Some(ExceptionRef {
                list_id,
                namespace_type: obj
                    .get("namespace_type")
                    .and_then(Value::as_str)
                    .unwrap_or("single")
                    .to_string(),
                ref_type: obj
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                id: obj.get("id").and_then(Value::as_str).map(str::to_string),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn probe_rule() -> Value {
        // Trimmed from a Serverless Security 9.6.0 create response.
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
    fn a_non_string_rule_id_is_rejected() {
        // State matching requires a readable identity, so construction rejects
        // non-string `rule_id` values.
        let err = Rule::from_value(json!({"rule_id": 123, "name": "x"})).unwrap_err();
        assert_eq!(err.kind, elasticctl_core::ErrorKind::Error);
        assert!(err.message.contains("string"), "{}", err.message);
    }

    #[test]
    fn a_null_rule_id_is_rejected() {
        // `rule_id: null` has no identity and must fail like a numeric value.
        assert!(Rule::from_value(json!({"rule_id": null})).is_err());
    }

    /// `from_value` validates construction, but transparent `Deserialize`
    /// bypasses that validation. Read sites must still handle unreadable IDs.
    #[test]
    fn deserialize_bypasses_the_construction_check() {
        let r: Rule = serde_json::from_value(json!({"rule_id": 123})).unwrap();
        assert!(r.rule_id().is_err());
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
                "execution_summary",
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
        // A field cannot be both stripped and filled.
        for v in VOLATILE_FIELDS {
            assert!(!server_defaults().contains_key(v), "{v} is in both sets");
        }
    }

    /// Trimmed from the measured create response, 2026-08-14, Serverless 9.6.0.
    fn probe_list() -> Value {
        json!({
            "id": "3724d409-4c0f-4630-a1ef-706499730808",
            "list_id": "elasticctl-sample-exceptions",
            "type": "detection",
            "name": "elasticctl sample exceptions",
            "description": "elasticctl sample exception list",
            "immutable": false,
            "namespace_type": "single",
            "os_types": [],
            "tags": ["elasticctl-sample"],
            "version": 1,
            "_version": "WzU3NDksMV0=",
            "tie_breaker_id": "100fd2bc-b559-4c7f-9838-ef9b195c4369",
            "created_at": "2026-08-13T23:38:39.519Z",
            "created_by": "452295856",
            "updated_at": "2026-08-13T23:38:39.519Z",
            "updated_by": "452295856"
        })
    }

    #[test]
    fn a_list_reads_its_identity_and_keeps_unknown_fields() {
        let l = ExceptionList::from_value(probe_list()).unwrap();
        assert_eq!(l.list_id().unwrap(), "elasticctl-sample-exceptions");
        assert_eq!(l.namespace_type(), "single");
        assert_eq!(l.list_type(), "detection");
        assert_eq!(l.tags(), vec!["elasticctl-sample"]);
        assert_eq!(
            l.clone().into_value(),
            probe_list(),
            "no field may be dropped"
        );
    }

    #[test]
    fn a_list_without_list_id_is_rejected() {
        let err = ExceptionList::from_value(json!({"name": "x"})).unwrap_err();
        assert!(err.message.contains("list_id"), "{}", err.message);
    }

    #[test]
    fn namespace_type_defaults_to_single_when_absent() {
        let l = ExceptionList::from_value(json!({"list_id": "x"})).unwrap();
        assert_eq!(
            l.namespace_type(),
            "single",
            "the API omits it on some responses; identity must still resolve"
        );
    }

    #[test]
    fn list_volatile_fields_match_the_measured_set() {
        let mut got = LIST_VOLATILE_FIELDS.to_vec();
        got.sort_unstable();
        assert_eq!(
            got,
            [
                "_version",
                "created_at",
                "created_by",
                "id",
                "tie_breaker_id",
                "updated_at",
                "updated_by",
                "version"
            ]
        );
    }

    #[test]
    fn item_volatile_fields_match_the_measured_set() {
        // Measured: an item carries `_version` but no `version`.
        let mut got = ITEM_VOLATILE_FIELDS.to_vec();
        got.sort_unstable();
        assert_eq!(
            got,
            [
                "_version",
                "created_at",
                "created_by",
                "id",
                "tie_breaker_id",
                "updated_at",
                "updated_by"
            ]
        );
    }

    #[test]
    fn exception_refs_reads_the_measured_reference_shape() {
        let r = Rule::from_value(json!({
            "rule_id": "x",
            "exceptions_list": [{
                "id": "3724d409-4c0f-4630-a1ef-706499730808",
                "list_id": "elasticctl-sample-exceptions",
                "type": "detection",
                "namespace_type": "single"
            }]
        }))
        .unwrap();
        let refs = exception_refs(&r);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].list_id, "elasticctl-sample-exceptions");
        assert_eq!(
            refs[0].id.as_deref(),
            Some("3724d409-4c0f-4630-a1ef-706499730808")
        );
    }

    #[test]
    fn exception_refs_skips_a_malformed_entry_without_failing() {
        let r = Rule::from_value(json!({
            "rule_id": "x",
            "exceptions_list": ["not an object", {"list_id": "good"}]
        }))
        .unwrap();
        let refs = exception_refs(&r);
        assert_eq!(refs.len(), 1, "the readable entry survives");
        assert_eq!(refs[0].list_id, "good");
    }
}
