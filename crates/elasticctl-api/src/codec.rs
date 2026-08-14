//! NDJSON and YAML representations of the same `Rule` model.
//!
//! Kibana exports and imports NDJSON, so it preserves rule fidelity. YAML is
//! easier to review.

use crate::model::{ExceptionItem, ExceptionList, ExportSummary, Rule};
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

/// One line of an export bundle: a rule, an exception-list container, an
/// exception item, or the export trailer.
enum Line {
    Rule,
    List,
    Item,
    Trailer,
}

/// Classify one NDJSON line from an export bundle.
///
/// Order matters. `rule_id` is tested first: a rule misfiled as an item would
/// vanish from `decode_ndjson` silently, whereas an item misfiled as a rule is
/// rejected loudly by `Rule::from_value` with a line number. An exception item
/// carries both `item_id` and `list_id`, so the item test must precede the list
/// test or every item is misfiled as a container. A trailer carries neither an
/// id nor a `list_id`, and the two export routes emit different counters: rules
/// export writes `exported_count`, exception export writes
/// `exported_exception_list_count` and no `exported_count` (measured fact 7).
fn classify(v: &Value) -> Option<Line> {
    if v.get("rule_id").is_some() {
        return Some(Line::Rule);
    }
    if v.get("item_id").is_some() {
        return Some(Line::Item);
    }
    if v.get("list_id").is_some() {
        return Some(Line::List);
    }
    if v.get("exported_count").is_some() || v.get("exported_exception_list_count").is_some() {
        return Some(Line::Trailer);
    }
    None
}

/// An export bundle split into its four line kinds.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Bundle {
    pub rules: Vec<Rule>,
    pub lists: Vec<ExceptionList>,
    pub items: Vec<ExceptionItem>,
    pub summary: Option<ExportSummary>,
}

/// Decode a `_export` body into rules, exception lists, exception items, and
/// the trailer. Every non-empty line must classify as one of the four; an
/// unclassifiable line is an error naming its line number.
pub fn decode_bundle(body: &str) -> Result<Bundle> {
    let mut out = Bundle::default();
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
        // Prefix every construction error with its line number, so large
        // exports identify the rejected object.
        let at = |e: Error| Error::new(ErrorKind::Error, format!("line {}: {}", i + 1, e.message));
        match classify(&value) {
            Some(Line::Rule) => out.rules.push(Rule::from_value(value).map_err(at)?),
            Some(Line::List) => out
                .lists
                .push(ExceptionList::from_value(value).map_err(at)?),
            Some(Line::Item) => out
                .items
                .push(ExceptionItem::from_value(value).map_err(at)?),
            Some(Line::Trailer) => out.summary = serde_json::from_value(value).ok(),
            None => {
                return Err(Error::new(
                    ErrorKind::Error,
                    format!(
                        "line {}: not a rule (no rule_id), exception list (no list_id), exception item (no item_id), or export trailer",
                        i + 1
                    ),
                ));
            }
        }
    }
    Ok(out)
}

/// Encode a bundle as NDJSON: rules, then lists, then items, no trailer. The
/// order matches the server's export and what `_import` expects.
pub fn encode_bundle(bundle: &Bundle) -> Result<String> {
    let mut out = String::new();
    for r in &bundle.rules {
        out.push_str(
            &serde_json::to_string(r)
                .map_err(|e| Error::new(ErrorKind::Error, format!("encoding rule: {e}")))?,
        );
        out.push('\n');
    }
    for l in &bundle.lists {
        out.push_str(
            &serde_json::to_string(l).map_err(|e| {
                Error::new(ErrorKind::Error, format!("encoding exception list: {e}"))
            })?,
        );
        out.push('\n');
    }
    for i in &bundle.items {
        out.push_str(
            &serde_json::to_string(i).map_err(|e| {
                Error::new(ErrorKind::Error, format!("encoding exception item: {e}"))
            })?,
        );
        out.push('\n');
    }
    Ok(out)
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
    let b = decode_bundle(body)?;
    Ok((b.rules, b.summary))
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

    /// The measured four-line export of one rule carrying one exception list,
    /// recorded 2026-08-14 from Serverless 9.6.0. Trimmed to the fields that
    /// matter; every line's *kind* is exactly as recorded.
    const BUNDLE: &str = concat!(
        r#"{"rule_id":"r","name":"R","type":"query","exceptions_list":[{"id":"L","list_id":"l","type":"detection","namespace_type":"single"}]}"#,
        "\n",
        r#"{"id":"L","list_id":"l","type":"detection","name":"L","namespace_type":"single","tie_breaker_id":"t"}"#,
        "\n",
        r#"{"id":"I","item_id":"i","list_id":"l","type":"simple","name":"I","namespace_type":"single","entries":[]}"#,
        "\n",
        r#"{"exported_count":2,"exported_rules_count":1,"missing_rules":[],"missing_rules_count":0,"exported_exception_list_count":1,"exported_exception_list_item_count":1,"missing_exception_lists":[],"missing_exception_list_items":[]}"#,
        "\n"
    );

    #[test]
    fn decode_bundle_separates_all_four_line_kinds() {
        let b = decode_bundle(BUNDLE).unwrap();
        assert_eq!(b.rules.len(), 1);
        assert_eq!(b.lists.len(), 1);
        assert_eq!(b.items.len(), 1);
        assert_eq!(b.summary.as_ref().unwrap().exported_exception_list_count, 1);
    }

    /// The bug this task closes. 0.1.3 answers "line 2: a rule must have a
    /// rule_id" for every rule that carries an exception list.
    #[test]
    fn a_bundle_no_longer_fails_as_a_rule_list() {
        assert!(
            decode_bundle(BUNDLE).is_ok(),
            "measured fact 2: this is the shipped failure"
        );
    }

    /// An item carries both `item_id` and `list_id`, so the item test must run
    /// before the list test or every item is misfiled as a container.
    #[test]
    fn an_item_is_not_classified_as_a_list() {
        let line = r#"{"item_id":"i","list_id":"l","name":"I"}"#;
        let b = decode_bundle(line).unwrap();
        assert_eq!(b.items.len(), 1, "item_id must be tested before list_id");
        assert!(b.lists.is_empty());
    }

    /// Measured fact 7: the exception export trailer has no `exported_count`.
    #[test]
    fn the_exception_export_trailer_is_recognised() {
        let line = r#"{"exported_exception_list_count":1,"exported_exception_list_item_count":2,"missing_exception_lists":[],"missing_exception_list_items":[],"missing_exception_lists_count":0,"missing_exception_list_item_count":0}"#;
        let b = decode_bundle(line).unwrap();
        assert!(b.rules.is_empty() && b.lists.is_empty() && b.items.is_empty());
        assert_eq!(b.summary.unwrap().exported_exception_list_count, 1);
    }

    #[test]
    fn an_unclassifiable_line_is_refused_by_line_number() {
        let body = "{\"rule_id\":\"a\"}\n{\"mystery\":true}\n";
        let err = decode_bundle(body).unwrap_err();
        assert!(err.message.contains("line 2"), "{}", err.message);
        assert!(err.message.contains("no rule_id"), "{}", err.message);
        assert!(err.message.contains("no list_id"), "{}", err.message);
        assert!(err.message.contains("no item_id"), "{}", err.message);
    }

    #[test]
    fn decode_ndjson_still_returns_only_rules_and_the_trailer() {
        let (rules, summary) = decode_ndjson(BUNDLE).unwrap();
        assert_eq!(rules.len(), 1, "the wrapper keeps its old contract");
        assert_eq!(summary.unwrap().exported_count, 2);
    }

    /// `encode_bundle` writes rules, then lists, then items, and never the
    /// trailer; `_import` rejects the trailer. The round-trip also proves the
    /// two new newtypes keep their unknown fields, matching spec 3.2.
    #[test]
    fn encode_bundle_writes_rules_then_lists_then_items_and_no_trailer() {
        let b = decode_bundle(BUNDLE).unwrap(); // 1 rule, 1 list, 1 item, trailer
        let out = encode_bundle(&b).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "the trailer is never written back");
        assert!(lines[0].contains("\"rule_id\""));
        assert!(lines[1].contains("\"list_id\"") && !lines[1].contains("\"item_id\""));
        assert!(lines[2].contains("\"item_id\""));

        let back = decode_bundle(&out).unwrap();
        assert_eq!(back.rules, b.rules, "rules round-trip");
        assert_eq!(back.lists, b.lists, "lists round-trip");
        assert_eq!(back.items, b.items, "items round-trip");
    }
}
