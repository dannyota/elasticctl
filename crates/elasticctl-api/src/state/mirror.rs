//! Reading and writing the local mirror: rules and exception lists.

use super::reports::Mirror;
use crate::codec::Format;
use crate::model::{ExceptionItem, ExceptionList, Rule};
use crate::normalize;
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Read the local mirror under `dir`: the rules plus the exception lists they
/// reference.
///
/// A rule file holds a rule followed by any `rule_default` containers that
/// belong to it. Those containers stay in the rule file and are not part of the
/// reconciled `lists`/`items` set: their lifecycle is the owning rule's, not
/// the mirror's.
pub fn read_mirror(dir: &Path) -> Result<Mirror> {
    let mut mirror = Mirror {
        rules: Vec::new(),
        lists: Vec::new(),
        items: Vec::new(),
    };

    let rules_path = super::rules_dir(dir);
    if rules_path.exists() {
        for path in mirror_files(&rules_path)? {
            let body = std::fs::read_to_string(&path).map_err(|e| {
                Error::new(ErrorKind::Error, format!("reading {}: {e}", path.display()))
            })?;
            let (mut rules, _inline) = decode_rule_file(&body, Format::from_path(&path))?;
            mirror.rules.append(&mut rules);
        }
    }

    let lists_path = super::exceptions_dir(dir);
    if lists_path.exists() {
        for path in mirror_files(&lists_path)? {
            let body = std::fs::read_to_string(&path).map_err(|e| {
                Error::new(ErrorKind::Error, format!("reading {}: {e}", path.display()))
            })?;
            let mut list = decode_list_file(&body, Format::from_path(&path))?;
            let items = split_items(&mut list)?;
            mirror.lists.push(list);
            mirror.items.extend(items);
        }
    }

    normalize::sort_rules(&mut mirror.rules);
    normalize::sort_lists(&mut mirror.lists);
    normalize::sort_items(&mut mirror.items);
    Ok(mirror)
}

/// `read_mirror`'s rules, for the rules-only callers.
pub fn read_local(dir: &Path) -> Result<Vec<Rule>> {
    Ok(read_mirror(dir)?.rules)
}

/// The files in a mirror directory that look like rule or list files.
fn mirror_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| Error::new(ErrorKind::Error, format!("reading {}: {e}", dir.display())))?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && super::is_rule_file(&path) {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Decode a rule file: one or more rules, optionally followed by the
/// `rule_default` containers that belong to them.
fn decode_rule_file(body: &str, format: Format) -> Result<(Vec<Rule>, Vec<ExceptionList>)> {
    let values = match format {
        Format::Yaml => serde_yaml_ng::from_str(body)
            .map_err(|e| Error::new(ErrorKind::Error, format!("parsing YAML: {e}")))?,
        Format::Ndjson => body
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| {
                serde_json::from_str(l)
                    .map_err(|e| Error::new(ErrorKind::Error, format!("parsing NDJSON: {e}")))
            })
            .collect::<Result<Vec<Value>>>()?,
    };

    let mut rules = Vec::new();
    let mut lists = Vec::new();
    for value in values {
        if value.get("rule_id").is_some() {
            rules.push(Rule::from_value(value)?);
        } else if value.get("list_id").is_some() {
            lists.push(ExceptionList::from_value(value)?);
        } else {
            return Err(Error::new(
                ErrorKind::Error,
                "a mirror file line has neither rule_id nor list_id",
            ));
        }
    }
    Ok((rules, lists))
}

/// Encode a rule file: the canonical rule, then its inline `rule_default`
/// containers. The caller passes canonical objects.
pub(crate) fn encode_rule_file(
    rule: &Rule,
    inline_lists: &[ExceptionList],
    format: Format,
) -> Result<String> {
    let mut objects = Vec::with_capacity(1 + inline_lists.len());
    objects.push(rule.clone().into_value());
    for list in inline_lists {
        objects.push(list.clone().into_value());
    }
    match format {
        Format::Yaml => serde_yaml_ng::to_string(&objects)
            .map_err(|e| Error::new(ErrorKind::Error, format!("encoding YAML: {e}"))),
        Format::Ndjson => {
            let mut out = String::new();
            for object in &objects {
                out.push_str(
                    &serde_json::to_string(object).map_err(|e| {
                        Error::new(ErrorKind::Error, format!("encoding NDJSON: {e}"))
                    })?,
                );
                out.push('\n');
            }
            Ok(out)
        }
    }
}

/// Encode one exception-list container (with its `items` array) as its own
/// file. The caller passes a canonical container.
pub(crate) fn encode_list_file(list: &ExceptionList, format: Format) -> Result<String> {
    match format {
        Format::Yaml => serde_yaml_ng::to_string(list.as_map())
            .map_err(|e| Error::new(ErrorKind::Error, format!("encoding YAML: {e}"))),
        Format::Ndjson => Ok(format!(
            "{}\n",
            serde_json::to_string(list.as_map())
                .map_err(|e| Error::new(ErrorKind::Error, format!("encoding NDJSON: {e}")))?
        )),
    }
}

fn decode_list_file(body: &str, format: Format) -> Result<ExceptionList> {
    let value = match format {
        Format::Yaml => serde_yaml_ng::from_str(body)
            .map_err(|e| Error::new(ErrorKind::Error, format!("parsing exception list: {e}")))?,
        Format::Ndjson => {
            let line = body
                .lines()
                .find(|l| !l.trim().is_empty())
                .ok_or_else(|| Error::new(ErrorKind::Error, "empty exception list file"))?;
            serde_json::from_str(line.trim())
                .map_err(|e| Error::new(ErrorKind::Error, format!("parsing exception list: {e}")))?
        }
    };
    ExceptionList::from_value(value)
}

/// Split a container's `items` array into items, removing it from the container
/// so container drift compares containers, not their items.
fn split_items(list: &mut ExceptionList) -> Result<Vec<ExceptionItem>> {
    let Some(Value::Array(items)) = list.as_map_mut().remove("items") else {
        return Ok(Vec::new());
    };
    items.into_iter().map(ExceptionItem::from_value).collect()
}
