//! NDJSON and YAML representations of the same `Rule` model.
//!
//! Kibana exports and imports NDJSON, so it preserves rule fidelity. YAML is
//! easier to review.

use crate::model::{ExportSummary, Rule};
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Ndjson,
    Yaml,
}

impl Format {
    /// NDJSON is the default, canonical import format.
    pub fn from_path(p: &Path) -> Format {
        match p.extension().and_then(|e| e.to_str()) {
            Some("yaml") | Some("yml") => Format::Yaml,
            _ => Format::Ndjson,
        }
    }
}

/// An export trailer has no `rule_id` and has an export counter.
fn is_summary(v: &Value) -> bool {
    v.get("rule_id").is_none() && v.get("exported_count").is_some()
}

pub fn encode_ndjson(rules: &[Rule]) -> Result<String> {
    let mut out = String::new();
    for r in rules {
        let line = serde_json::to_string(r)
            .map_err(|e| Error::new(ErrorKind::Error, format!("encoding rule: {e}")))?;
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

pub fn decode_ndjson(body: &str) -> Result<(Vec<Rule>, Option<ExportSummary>)> {
    let mut rules = Vec::new();
    let mut summary = None;

    for (i, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line).map_err(|e| {
            Error::new(
                ErrorKind::Error,
                format!("invalid JSON on line {}: {e}", i + 1),
            )
        })?;

        if is_summary(&value) {
            summary = serde_json::from_value(value).ok();
            continue;
        }
        // Include the line number so large exports identify the rejected rule.
        rules.push(
            Rule::from_value(value).map_err(|e| {
                Error::new(ErrorKind::Error, format!("line {}: {}", i + 1, e.message))
            })?,
        );
    }

    Ok((rules, summary))
}

pub fn encode_yaml(rules: &[Rule]) -> Result<String> {
    serde_yaml_ng::to_string(rules)
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding YAML: {e}")))
}

pub fn decode_yaml(body: &str) -> Result<Vec<Rule>> {
    let values: Vec<Value> = serde_yaml_ng::from_str(body)
        .map_err(|e| Error::new(ErrorKind::Error, format!("parsing YAML: {e}")))?;

    // Apply the same `rule_id` validation as NDJSON. YAML is hand-edited, so
    // it is more likely to omit `rule_id`.
    values
        .into_iter()
        .enumerate()
        .map(|(i, v)| {
            Rule::from_value(v).map_err(|e| {
                Error::new(
                    ErrorKind::Error,
                    format!("rule at index {i}: {}", e.message),
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::Path;

    fn rule(id: &str) -> Rule {
        Rule::from_value(json!({
            "rule_id": id, "name": format!("rule {id}"), "type": "query",
            "query": "event.category:process", "severity": "low", "risk_score": 21
        }))
        .unwrap()
    }

    // A one-rule export contains the rule and a 15-field summary.
    const REAL_EXPORT: &str = concat!(
        r#"{"rule_id":"a","name":"rule a","type":"query"}"#,
        "\n",
        r#"{"exported_count":1,"exported_rules_count":1,"missing_rules":[],"missing_rules_count":0}"#,
        "\n"
    );

    #[test]
    fn decode_ndjson_separates_the_trailer_from_the_rules() {
        let (rules, summary) = decode_ndjson(REAL_EXPORT).unwrap();
        assert_eq!(rules.len(), 1, "the trailer must not be parsed as a rule");
        assert_eq!(rules[0].rule_id().unwrap(), "a");
        assert_eq!(summary.unwrap().exported_count, 1);
    }

    // A zero-rule export contains only the trailer.
    #[test]
    fn decode_ndjson_handles_a_body_that_is_only_a_trailer() {
        let body = r#"{"exported_count":0,"exported_rules_count":0,"missing_rules_count":0}"#;
        let (rules, summary) = decode_ndjson(body).unwrap();
        assert!(rules.is_empty());
        assert_eq!(summary.unwrap().exported_count, 0);
    }

    #[test]
    fn decode_ndjson_tolerates_blank_lines() {
        let body = format!("\n{}\n\n", REAL_EXPORT.trim());
        assert_eq!(decode_ndjson(&body).unwrap().0.len(), 1);
    }

    #[test]
    fn decode_ndjson_reports_the_line_number_of_bad_json() {
        let body = "{\"rule_id\":\"a\"}\nnot json\n";
        let err = decode_ndjson(body).unwrap_err();
        assert!(
            err.message.contains("line 2"),
            "message must locate the fault: {}",
            err.message
        );
    }

    #[test]
    fn decode_ndjson_names_the_line_of_a_rule_it_rejects() {
        let body = "{\"rule_id\":\"a\"}\n{\"name\":\"no id\"}\n";
        let err = decode_ndjson(body).unwrap_err();
        assert!(
            err.message.contains("line 2"),
            "message must locate the fault: {}",
            err.message
        );
        assert!(err.message.contains("rule_id"), "{}", err.message);
    }

    #[test]
    fn decode_ndjson_rejects_a_non_string_rule_id() {
        let err = decode_ndjson("{\"rule_id\":7}\n").unwrap_err();
        assert!(err.message.contains("line 1"), "{}", err.message);
        assert!(err.message.contains("string"), "{}", err.message);
    }

    #[test]
    fn ndjson_round_trips() {
        let rules = vec![rule("a"), rule("b")];
        let encoded = encode_ndjson(&rules).unwrap();
        assert_eq!(
            encoded.lines().count(),
            2,
            "one rule per line, no trailer on write"
        );
        assert_eq!(decode_ndjson(&encoded).unwrap().0, rules);
    }

    #[test]
    fn yaml_round_trips() {
        let rules = vec![rule("a"), rule("b")];
        let encoded = encode_yaml(&rules).unwrap();
        assert_eq!(decode_yaml(&encoded).unwrap(), rules);
    }

    #[test]
    fn the_two_formats_carry_identical_data() {
        let rules = vec![rule("a")];
        let via_ndjson = decode_ndjson(&encode_ndjson(&rules).unwrap()).unwrap().0;
        let via_yaml = decode_yaml(&encode_yaml(&rules).unwrap()).unwrap();
        assert_eq!(
            via_ndjson, via_yaml,
            "YAML and NDJSON are two skins on one model"
        );
    }

    #[test]
    fn format_is_chosen_by_file_extension() {
        assert_eq!(Format::from_path(Path::new("rules.yaml")), Format::Yaml);
        assert_eq!(Format::from_path(Path::new("rules.yml")), Format::Yaml);
        assert_eq!(Format::from_path(Path::new("rules.ndjson")), Format::Ndjson);
        assert_eq!(Format::from_path(Path::new("rules.json")), Format::Ndjson);
        assert_eq!(Format::from_path(Path::new("noextension")), Format::Ndjson);
    }

    #[test]
    fn decode_yaml_rejects_an_entry_without_rule_id() {
        let yaml = "- {name: test}\n";
        let err = decode_yaml(yaml).unwrap_err();
        assert!(
            err.message.contains("index 0"),
            "error must name the index: {}",
            err.message
        );
        assert!(
            err.message.contains("rule_id"),
            "error must mention rule_id: {}",
            err.message
        );
    }

    #[test]
    fn decode_yaml_reports_the_index_of_a_bad_entry() {
        let yaml = "- {rule_id: a, name: test}\n- {name: test}\n";
        let err = decode_yaml(yaml).unwrap_err();
        assert!(
            err.message.contains("index 1"),
            "error must name the index: {}",
            err.message
        );
    }
}
