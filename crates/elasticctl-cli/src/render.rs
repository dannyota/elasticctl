//! Turning typed values into text. The only module in the workspace that
//! decides what a human sees.

use crate::cli::{Format, GlobalArgs};
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Map, Value};
use std::io::Write;

/// Every failure exits 1. Usage errors exit 2, but `clap` handles those before
/// a command ever runs.
pub fn exit_code_for(_err: &Error) -> i32 {
    1
}

/// Keep only the named keys, in the order named. An absent key is skipped
/// rather than rendered as null, so a typo does not produce a column of blanks.
pub fn select_fields(value: &Value, fields: &str) -> Value {
    let names: Vec<&str> = fields
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let pick = |obj: &Map<String, Value>| -> Value {
        let mut out = Map::new();
        for n in &names {
            if let Some(v) = obj.get(*n) {
                out.insert((*n).to_string(), v.clone());
            }
        }
        Value::Object(out)
    };

    match value {
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|i| i.as_object().map(&pick).unwrap_or_else(|| i.clone()))
                .collect(),
        ),
        Value::Object(o) => pick(o),
        other => other.clone(),
    }
}

fn cell(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Column order comes from the first row, so it is stable and predictable.
fn columns(rows: &[Value], fields: Option<&str>) -> Vec<String> {
    if let Some(f) = fields {
        return f
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    rows.first()
        .and_then(Value::as_object)
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default()
}

pub fn table(value: &Value, fields: Option<&str>) -> String {
    let rows: Vec<Value> = match value {
        Value::Array(a) => a.clone(),
        Value::Object(_) => vec![value.clone()],
        other => return cell(other),
    };

    if rows.is_empty() {
        return "(no results)".to_string();
    }

    let cols = columns(&rows, fields);
    if cols.is_empty() {
        return "(no results)".to_string();
    }

    let mut widths: Vec<usize> = cols.iter().map(|c| c.len()).collect();
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            cols.iter()
                .enumerate()
                .map(|(i, c)| {
                    let s = r.get(c).map(cell).unwrap_or_default();
                    widths[i] = widths[i].max(s.len());
                    s
                })
                .collect()
        })
        .collect();

    let mut out = String::new();
    for (i, c) in cols.iter().enumerate() {
        out.push_str(&format!("{:width$}  ", c, width = widths[i]));
    }
    out.push('\n');
    for row in body {
        for (i, c) in row.iter().enumerate() {
            out.push_str(&format!("{:width$}  ", c, width = widths[i]));
        }
        out.push('\n');
    }
    out
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub fn to_string(value: &Value, format: Format, fields: Option<&str>) -> Result<String> {
    let value = match fields {
        Some(f) => select_fields(value, f),
        None => value.clone(),
    };

    let encode = |e: serde_json::Error| Error::new(ErrorKind::Error, format!("encoding: {e}"));

    Ok(match format {
        Format::Json => serde_json::to_string_pretty(&value).map_err(encode)? + "\n",
        Format::Yaml => serde_yaml_ng::to_string(&value)
            .map_err(|e| Error::new(ErrorKind::Error, format!("encoding YAML: {e}")))?,
        Format::Jsonl => {
            let items = value
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![value.clone()]);
            let mut s = String::new();
            for i in items {
                s.push_str(&serde_json::to_string(&i).map_err(encode)?);
                s.push('\n');
            }
            s
        }
        Format::Csv => {
            let rows = value
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![value.clone()]);
            let cols = columns(&rows, fields);
            let mut s = cols.join(",");
            s.push('\n');
            for r in rows {
                let line: Vec<String> = cols
                    .iter()
                    .map(|c| csv_escape(&r.get(c).map(cell).unwrap_or_default()))
                    .collect();
                s.push_str(&line.join(","));
                s.push('\n');
            }
            s
        }
        Format::Table => table(&value, fields),
    })
}

/// Write to `--out` when given, otherwise stdout.
pub fn emit(value: &Value, global: &GlobalArgs) -> Result<()> {
    let text = to_string(value, global.effective_format(), global.fields.as_deref())?;
    match &global.out {
        Some(path) => std::fs::write(path, text)
            .map_err(|e| Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))),
        None => {
            print!("{text}");
            std::io::stdout().flush().ok();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rows() -> Value {
        json!([
            {"rule_id": "a", "name": "Alpha", "enabled": true,  "risk_score": 21},
            {"rule_id": "b", "name": "Beta",  "enabled": false, "risk_score": 73}
        ])
    }

    #[test]
    fn table_renders_a_header_and_one_line_per_row() {
        let t = table(&rows(), None);
        assert!(t.contains("rule_id"), "{t}");
        assert!(t.contains("Alpha") && t.contains("Beta"), "{t}");
    }

    #[test]
    fn table_respects_field_selection_and_its_order() {
        let t = table(&rows(), Some("name,rule_id"));
        let header = t.lines().find(|l| l.contains("name")).unwrap();
        let name_at = header.find("name").unwrap();
        let id_at = header.find("rule_id").unwrap();
        assert!(name_at < id_at, "selected order must be honoured: {header}");
        assert!(
            !t.contains("risk_score"),
            "unselected fields must be dropped"
        );
    }

    #[test]
    fn table_of_an_empty_list_is_not_an_error() {
        assert!(
            !table(&json!([]), None).is_empty(),
            "must say something, not panic"
        );
    }

    #[test]
    fn table_of_a_single_object_renders_a_one_row_table() {
        let t = table(&json!({"rule_id": "a", "name": "Alpha"}), None);
        assert!(t.contains("rule_id") && t.contains("Alpha"), "{t}");
    }

    #[test]
    fn table_widens_a_column_to_fit_a_cell_wider_than_its_header() {
        let v = json!({"id": "1234567890", "flag": "x"});
        let t = table(&v, None);
        let header = t.lines().next().unwrap();
        let flag_at = header.find("flag").unwrap();
        assert_eq!(
            flag_at,
            "1234567890".len() + 2,
            "column must widen to fit the longest cell, not just the header: {header}"
        );
    }

    #[test]
    fn table_renders_a_null_cell_as_empty_not_as_the_word_null() {
        let v = json!({"id": "a", "note": null});
        let t = table(&v, None);
        assert!(!t.contains("null"), "{t}");
    }

    #[test]
    fn table_renders_a_nested_object_as_inline_json_without_panicking() {
        let v = json!({"id": "a", "meta": {"k": "v"}});
        let t = table(&v, None);
        assert!(t.contains(r#"{"k":"v"}"#), "{t}");
    }

    #[test]
    fn select_fields_keeps_only_the_named_keys() {
        let v = select_fields(&rows(), "rule_id");
        assert_eq!(v[0].as_object().unwrap().len(), 1);
        assert_eq!(v[0]["rule_id"], "a");
    }

    #[test]
    fn select_fields_ignores_a_name_that_is_not_present() {
        let v = select_fields(&rows(), "rule_id,nonexistent");
        assert_eq!(
            v[0].as_object().unwrap().len(),
            1,
            "absent keys are skipped, not nulled"
        );
    }

    #[test]
    fn select_fields_trims_whitespace_around_names() {
        let v = select_fields(&rows(), " rule_id , name ");
        assert_eq!(v[0].as_object().unwrap().len(), 2);
    }

    #[test]
    fn json_wins_over_an_explicit_format_flag() {
        let g = GlobalArgs {
            json: true,
            format: Some(Format::Csv),
            ..GlobalArgs::default()
        };
        assert_eq!(g.effective_format(), Format::Json);
    }

    #[test]
    fn table_is_the_default_regardless_of_where_output_goes() {
        assert_eq!(GlobalArgs::default().effective_format(), Format::Table);
    }

    #[test]
    fn jsonl_writes_one_compact_object_per_line() {
        let s = to_string(&rows(), Format::Jsonl, None).unwrap();
        assert_eq!(s.lines().count(), 2);
        assert!(s.lines().all(|l| l.starts_with('{') && l.ends_with('}')));
    }

    #[test]
    fn csv_writes_a_header_and_quotes_embedded_commas() {
        let v = json!([{"name": "a,b", "n": 1}]);
        let s = to_string(&v, Format::Csv, None).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines[0], "name,n");
        assert!(lines[1].contains("\"a,b\""), "{}", lines[1]);
    }

    #[test]
    fn csv_escape_doubles_an_embedded_quote_and_wraps_the_field() {
        assert_eq!(csv_escape(r#"He said "hi""#), r#""He said ""hi""""#);
    }

    #[test]
    fn csv_escape_quotes_a_value_containing_a_newline() {
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn exit_code_is_one_for_every_error_kind() {
        use elasticctl_core::{Error, ErrorKind};
        for kind in [ErrorKind::Auth, ErrorKind::NotFound, ErrorKind::Timeout] {
            assert_eq!(exit_code_for(&Error::new(kind, "x")), 1);
        }
    }
}
