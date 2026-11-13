use std::collections::{BTreeMap, BTreeSet};

use crate::Rule;
use crate::rules::{self, RuleFilter};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::{Map, Value};

const MITRE: &str = "MITRE ATT&CK";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageGroup {
    Technique,
    Tactic,
    IndexPattern,
    Integration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageRow {
    pub key: String,
    pub name: Option<String>,
    pub tactics: Vec<String>,
    pub enabled_rules: u64,
    pub disabled_rules: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageReport {
    pub group_by: CoverageGroup,
    pub rules: u64,
    pub enabled_rules: u64,
    pub disabled_rules: u64,
    pub unmapped_rules: u64,
    pub rows: Vec<CoverageRow>,
}

#[derive(Default)]
struct Seen {
    name: Option<String>,
    tactics: BTreeSet<String>,
}

pub fn coverage_from_rules(rules: &[Rule], group_by: CoverageGroup) -> Result<CoverageReport> {
    let mut groups: BTreeMap<String, (Seen, u64, u64)> = BTreeMap::new();
    let mut report = CoverageReport {
        group_by,
        rules: rules.len() as u64,
        enabled_rules: 0,
        disabled_rules: 0,
        unmapped_rules: 0,
        rows: Vec::new(),
    };
    for rule in rules {
        let enabled = rule.as_map().get("enabled") == Some(&Value::Bool(true));
        if enabled {
            report.enabled_rules += 1;
        } else {
            report.disabled_rules += 1;
        }
        let keys = rule_keys(rule.as_map(), group_by)?;
        if keys.is_empty() {
            report.unmapped_rules += 1;
        }
        for (key, seen) in keys {
            let (group, enabled_rules, disabled_rules) = groups.entry(key).or_default();
            keep_smallest(&mut group.name, seen.name.as_deref());
            group.tactics.extend(seen.tactics);
            if enabled {
                *enabled_rules += 1;
            } else {
                *disabled_rules += 1;
            }
        }
    }
    report.rows = groups
        .into_iter()
        .map(|(key, (seen, enabled_rules, disabled_rules))| CoverageRow {
            key,
            name: seen.name,
            tactics: seen.tactics.into_iter().collect(),
            enabled_rules,
            disabled_rules,
        })
        .collect();
    report.rows.sort_by(|a, b| {
        b.enabled_rules
            .cmp(&a.enabled_rules)
            .then(b.disabled_rules.cmp(&a.disabled_rules))
            .then_with(|| a.key.cmp(&b.key))
    });
    Ok(report)
}

pub async fn detection_coverage(
    t: &Transport,
    filter: &RuleFilter,
    group_by: CoverageGroup,
) -> Result<CoverageReport> {
    let rules = rules::find_window(t, filter).await?;
    coverage_from_rules(&rules, group_by)
}

fn rule_keys(rule: &Map<String, Value>, group_by: CoverageGroup) -> Result<BTreeMap<String, Seen>> {
    let mut keys: BTreeMap<String, Seen> = BTreeMap::new();
    match group_by {
        CoverageGroup::Technique | CoverageGroup::Tactic => {
            for entry in array(rule, "threat")? {
                let entry = object(entry, "threat")?;
                if string(entry, "framework")? != Some(MITRE) {
                    continue;
                }
                let tactic = field(entry, "tactic")
                    .map(|tactic| object(tactic, "threat.tactic"))
                    .transpose()?;
                let tactic_id = tactic
                    .map(|tactic| string(tactic, "id"))
                    .transpose()?
                    .flatten();
                if group_by == CoverageGroup::Tactic {
                    if let (Some(tactic), Some(id)) = (tactic, tactic_id) {
                        let seen = keys.entry(id.to_owned()).or_default();
                        keep_smallest(&mut seen.name, string(tactic, "name")?);
                    }
                    continue;
                }
                for technique in array(entry, "technique")? {
                    let technique = object(technique, "threat.technique")?;
                    if let Some(id) = string(technique, "id")? {
                        let seen = keys.entry(id.to_owned()).or_default();
                        keep_smallest(&mut seen.name, string(technique, "name")?);
                        seen.tactics.extend(tactic_id.map(str::to_owned));
                    }
                }
            }
        }
        CoverageGroup::IndexPattern => {
            let patterns = array(rule, "index")?;
            if patterns.is_empty()
                && let Some(id) = string(rule, "data_view_id")?
            {
                keys.entry(format!("data_view:{id}")).or_default();
            }
            for pattern in patterns {
                let pattern = pattern.as_str().ok_or_else(|| wrong_type("index"))?;
                keys.entry(pattern.to_owned()).or_default();
            }
        }
        CoverageGroup::Integration => {
            for entry in array(rule, "related_integrations")? {
                let entry = object(entry, "related_integrations")?;
                if let Some(package) = string(entry, "package")? {
                    keys.entry(package.to_owned()).or_default();
                }
            }
        }
    }
    Ok(keys)
}

fn keep_smallest(current: &mut Option<String>, name: Option<&str>) {
    if let Some(name) = name
        && current.as_deref().is_none_or(|current| name < current)
    {
        *current = Some(name.to_owned());
    }
}

fn field<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    map.get(key).filter(|value| !value.is_null())
}

fn array<'a>(map: &'a Map<String, Value>, key: &'static str) -> Result<&'a [Value]> {
    match field(map, key) {
        None => Ok(&[]),
        Some(Value::Array(values)) => Ok(values),
        Some(_) => Err(wrong_type(key)),
    }
}

fn string<'a>(map: &'a Map<String, Value>, key: &'static str) -> Result<Option<&'a str>> {
    match field(map, key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(wrong_type(key)),
    }
}

fn object<'a>(value: &'a Value, what: &'static str) -> Result<&'a Map<String, Value>> {
    value.as_object().ok_or_else(|| wrong_type(what))
}

fn wrong_type(field: &str) -> Error {
    Error::new(
        ErrorKind::Http,
        format!("a rule field {field} has an unexpected type"),
    )
}
