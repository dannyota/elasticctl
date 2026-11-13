use elasticctl_core::{Error, ErrorKind, Result};
use serde::Serialize;

use super::{
    LocalPair, StoredValues, ValueListType, ValueSet, canonical_value, decode_container,
    decode_values, file_stem, invalid,
};

pub const MAX_VALUE_BYTES_WITH_LF: usize = 8_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningKind {
    NonCanonical,
    Duplicates,
    DashLimit,
    EmptyReferenced,
    RuleTypeLimit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Warning {
    pub kind: WarningKind,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct Findings {
    pub refusals: Vec<Error>,
    pub warnings: Vec<Warning>,
}

#[derive(Clone, Debug)]
pub struct LocalValidation {
    pub pair: Option<LocalPair>,
    pub findings: Findings,
}

pub fn validate_local_pair(stem: &str, yaml: &[u8], values: Option<&[u8]>) -> LocalValidation {
    let mut findings = Findings::default();
    match decode_pair(stem, yaml, values) {
        Ok(pair) => {
            findings.warnings = value_warnings(&pair.container.list_type, &pair.values);
            LocalValidation {
                pair: Some(pair),
                findings,
            }
        }
        Err(error) => {
            findings.refusals.push(error);
            LocalValidation {
                pair: None,
                findings,
            }
        }
    }
}

fn decode_pair(stem: &str, yaml: &[u8], values: Option<&[u8]>) -> Result<LocalPair> {
    let yaml = std::str::from_utf8(yaml).map_err(|_| invalid("container file must be UTF-8"))?;
    let container = decode_container(yaml)?;
    super::stems::validate_id(&container.id)?;
    if file_stem(&container.id) != stem {
        return Err(invalid(format!(
            "id {:?} requires file stem {:?}, found {stem:?}",
            container.id,
            file_stem(&container.id)
        )));
    }
    container.list_type.require_supported()?;
    let values = values.ok_or_else(|| invalid("sibling values file is missing"))?;
    let values = std::str::from_utf8(values).map_err(|_| invalid("values file must be UTF-8"))?;
    let values = decode_values(&container.list_type, values)?;
    for value in &values {
        if value.len() >= MAX_VALUE_BYTES_WITH_LF {
            return Err(invalid(
                "one value with its LF exceeds the 8,000,000-byte import bound",
            ));
        }
    }
    Ok(LocalPair {
        stem: stem.to_owned(),
        container,
        values,
    })
}

fn canonical_remedy(kind: &ValueListType, value: &str) -> Result<Option<String>> {
    let canonical = canonical_value(kind, value)?;
    if canonical.as_deref() == Some(value) {
        return Ok(None);
    }
    Ok(Some(match canonical {
        Some(canonical) => format!("non-canonical value {value:?}; use {canonical:?}"),
        None => format!(
            "non-canonical mixed-family range {value:?}; use same-family ascending ranges or CIDR blocks"
        ),
    }))
}

pub fn validate_additions(kind: &ValueListType, additions: &ValueSet) -> Findings {
    let mut findings = Findings::default();
    if let Err(error) = kind.require_supported() {
        findings.refusals.push(error);
        return findings;
    }
    for value in additions {
        if value.len() >= MAX_VALUE_BYTES_WITH_LF {
            findings.refusals.push(invalid(
                "one value with its LF exceeds the 8,000,000-byte import bound",
            ));
        }
        match canonical_remedy(kind, value) {
            Ok(Some(message)) => findings.refusals.push(invalid(message)),
            Err(error) => findings.refusals.push(error),
            Ok(None) => {}
        }
    }
    findings
}

fn value_warnings(kind: &ValueListType, values: &ValueSet) -> Vec<Warning> {
    let mut warnings = noncanonical_warnings(kind, values);
    if let Some(warning) = size_warning(kind, values.iter().map(String::as_str)) {
        warnings.push(warning);
    }
    warnings
}

fn noncanonical_warnings(kind: &ValueListType, values: &ValueSet) -> Vec<Warning> {
    let mut warnings = Vec::new();
    for value in values {
        if let Ok(Some(message)) = canonical_remedy(kind, value) {
            warnings.push(Warning {
                kind: WarningKind::NonCanonical,
                message,
            });
        }
    }
    warnings
}

pub fn stored_warnings(kind: &ValueListType, stored: &StoredValues) -> Vec<Warning> {
    let set = stored.set();
    let mut warnings = noncanonical_warnings(kind, &set);
    if let Some(warning) = size_warning(kind, stored.values.iter().map(String::as_str)) {
        warnings.push(warning);
    }
    if stored.values.len() != set.len() {
        warnings.push(Warning {
            kind: WarningKind::Duplicates,
            message: format!(
                "{} stored values have {} distinct spellings; duplicates are retained",
                stored.values.len(),
                set.len()
            ),
        });
    }
    if *kind == ValueListType::IpRange && stored.dash_count() > 200 {
        warnings.push(Warning {
            kind: WarningKind::DashLimit,
            message: dash_message("current", stored.dash_count()),
        });
    }
    warnings
}

pub fn size_warning<'a>(
    kind: &ValueListType,
    values: impl IntoIterator<Item = &'a str>,
) -> Option<Warning> {
    let count = values
        .into_iter()
        .filter(|value| *kind != ValueListType::IpRange || value.contains('/'))
        .count();
    let limited = match kind {
        ValueListType::Text => true,
        ValueListType::Keyword | ValueListType::Ip | ValueListType::IpRange => count >= 65_536,
        ValueListType::Unsupported(_) => false,
    };
    limited.then(|| Warning { kind: WarningKind::RuleTypeLimit, message: format!("{kind} list ({count} values) works only with custom query, saved query, machine learning, and indicator match rules") })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseOrder {
    AddsFirst,
    RemovesFirst,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedStates {
    pub current: StoredValues,
    pub between: StoredValues,
    pub final_values: StoredValues,
}

pub fn project_states(
    current: &StoredValues,
    adds: &ValueSet,
    removes: &ValueSet,
    order: PhaseOrder,
) -> ProjectedStates {
    let remove = |stored: &StoredValues| {
        StoredValues::new(
            stored
                .values
                .iter()
                .filter(|v| !removes.contains(*v))
                .cloned()
                .collect(),
        )
    };
    let add = |stored: &StoredValues| {
        let present = stored.set();
        let mut values = stored.values.clone();
        values.extend(adds.difference(&present).cloned());
        StoredValues::new(values)
    };
    let (between, final_values) = match order {
        PhaseOrder::AddsFirst => {
            let between = add(current);
            let final_values = remove(&between);
            (between, final_values)
        }
        PhaseOrder::RemovesFirst => {
            let between = remove(current);
            let final_values = add(&between);
            (between, final_values)
        }
    };
    ProjectedStates {
        current: current.clone(),
        between,
        final_values,
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReferenceUse {
    pub installed: Vec<String>,
    pub desired: Vec<String>,
    pub creating: bool,
}

fn dash_message(state: &str, count: usize) -> String {
    format!(
        "{state} state has {count} stored dash values, above 200: Kibana 9.5.1, 9.5.6, and 9.7.0 suppress every event for an exception on this list with either operator; write a single address as a/32 or a/128 and a range as CIDR blocks"
    )
}

pub fn validate_projected(
    kind: &ValueListType,
    states: &ProjectedStates,
    references: &ReferenceUse,
) -> Findings {
    let mut findings = Findings::default();
    if *kind == ValueListType::IpRange {
        let current = states.current.dash_count();
        if current > 200 {
            findings.warnings.push(Warning {
                kind: WarningKind::DashLimit,
                message: dash_message("current", current),
            });
        }
        for (phase, count, allowed) in [
            (
                "between-phases",
                states.between.dash_count(),
                current.max(200),
            ),
            ("final", states.final_values.dash_count(), 200),
        ] {
            if count > allowed {
                findings.refusals.push(Error::new(
                    ErrorKind::Unsupported,
                    dash_message(phase, count),
                ));
            }
        }
    }
    let names: ValueSet = references
        .installed
        .iter()
        .chain(&references.desired)
        .cloned()
        .collect();
    if !names.is_empty() {
        let reason = format!(
            "an empty list under is in list suppresses every event; references: {}",
            names.into_iter().collect::<Vec<_>>().join(", ")
        );
        if references.creating && !references.installed.is_empty() {
            findings.refusals.push(Error::new(
                ErrorKind::Unsupported,
                format!("cannot create a list already named by installed references: {reason}"),
            ));
        }
        if states.current.values.is_empty() && !references.creating {
            findings.warnings.push(Warning {
                kind: WarningKind::EmptyReferenced,
                message: format!("current state is empty: {reason}"),
            });
        }
        for (phase, values) in [
            ("between-phases", &states.between),
            ("final", &states.final_values),
        ] {
            if values.values.is_empty() {
                findings.refusals.push(Error::new(
                    ErrorKind::Unsupported,
                    format!("{phase} state is empty: {reason}"),
                ));
            }
        }
    }
    findings
}
