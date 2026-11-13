use super::{
    MAX_PACKAGES, MAX_PATTERNS, Part, SkipReason, degrade, is_fatal, is_path_segment,
    snapshot_by_selector,
};
use crate::{
    Rule,
    data_views::{self, DataViewSummary},
    fleet::{
        agent_policies, integration_policies::IntegrationPolicySummary, integration_policy_ops,
    },
};
use elasticctl_core::{Error, ErrorKind, Result, Transport, urlencode};
use serde_json::Value;
use std::collections::HashSet;

pub const PATTERN_BYTES: usize = 1_024;
pub const PACKAGE_NAME_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexSource {
    Index,
    DataView,
    None,
}

#[derive(Debug)]
pub struct RuleDataView {
    pub id: String,
    pub found: bool,
    pub title: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug)]
pub struct DataViewFacts {
    pub count: usize,
    pub rule_data_view: Option<RuleDataView>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternState {
    Matches,
    NoMatch,
    Exclusion,
    Unresolved,
}

#[derive(Debug)]
pub struct PatternRow {
    pub pattern: String,
    pub state: PatternState,
    pub counts: Option<(u64, u64, u64)>,
    pub error: Option<Error>,
    pub data_view_ids: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct PatternFacts {
    pub total: usize,
    pub truncated: bool,
    pub rows: Vec<PatternRow>,
}

#[derive(Debug)]
pub struct PackageUse {
    pub install_status: String,
    pub installed_version: Option<String>,
    pub policies: u64,
}

#[derive(Debug)]
pub struct PackageRow {
    pub package: String,
    pub version: Option<String>,
    pub status: std::result::Result<PackageUse, Error>,
}

#[derive(Debug)]
pub struct IntegrationFacts {
    pub total: usize,
    pub truncated: bool,
    pub rows: Vec<PackageRow>,
}

#[derive(Debug)]
pub struct Readiness {
    pub rule: Rule,
    pub index_source: IndexSource,
    pub data_views: Part<DataViewFacts>,
    pub patterns: Part<PatternFacts>,
    pub integrations: Part<IntegrationFacts>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadinessFinding {
    RuleDisabled,
    NoIndexSource,
    DataViewMissing,
    NoPatternMatches,
    PatternUnresolved,
    IntegrationNotInstalled,
    IntegrationWithoutPolicy,
    PatternsTruncated,
    IntegrationsTruncated,
}

enum Source {
    Index(Vec<String>),
    DataView(String),
    None,
}

pub async fn rule_readiness(t: &Transport, selector: &str) -> Result<Readiness> {
    let rule = snapshot_by_selector(t, selector).await?.rule;
    let source = source(&rule);
    let index_source = match source {
        Source::Index(_) => IndexSource::Index,
        Source::DataView(_) => IndexSource::DataView,
        Source::None => IndexSource::None,
    };

    let mut views = None;
    let data_views = match &source {
        Source::None => Part::Skipped(SkipReason::NotApplicable),
        _ => match degrade(data_views::list(t).await)? {
            Part::Ok(list) => {
                let rule_data_view = match &source {
                    Source::DataView(id) => Some(rule_data_view(&list, id)),
                    _ => None,
                };
                let facts = DataViewFacts {
                    count: list.len(),
                    rule_data_view,
                };
                views = Some(list);
                Part::Ok(facts)
            }
            Part::Unavailable(error) => Part::Unavailable(error),
            Part::Skipped(reason) => Part::Skipped(reason),
        },
    };

    let patterns = match source {
        Source::None => Part::Skipped(SkipReason::NotApplicable),
        _ if !t.has_es_url() => Part::Skipped(SkipReason::NotConfigured),
        Source::Index(patterns) => Part::Ok(resolve_patterns(t, patterns, views.as_deref()).await?),
        Source::DataView(_) => {
            let title = match &data_views {
                Part::Ok(DataViewFacts {
                    rule_data_view:
                        Some(RuleDataView {
                            found: true,
                            title: Some(title),
                            ..
                        }),
                    ..
                }) => Some(title.clone()),
                _ => None,
            };
            match title {
                Some(title) => {
                    let patterns = title.split(',').map(str::to_owned).collect();
                    Part::Ok(resolve_patterns(t, patterns, views.as_deref()).await?)
                }
                None => Part::Skipped(SkipReason::DependencyUnavailable),
            }
        }
    };

    let integrations = integrations(t, &rule).await?;
    Ok(Readiness {
        rule,
        index_source,
        data_views,
        patterns,
        integrations,
    })
}

fn source(rule: &Rule) -> Source {
    let map = rule.as_map();
    if let Some(Value::Array(items)) = map.get("index")
        && !items.is_empty()
        && let Some(patterns) = items
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
    {
        return Source::Index(patterns);
    }
    match map.get("data_view_id") {
        Some(Value::String(id)) => Source::DataView(id.clone()),
        _ => Source::None,
    }
}

fn rule_data_view(list: &[DataViewSummary], id: &str) -> RuleDataView {
    match list.iter().find(|view| view.id == id) {
        Some(view) => RuleDataView {
            id: id.to_owned(),
            found: true,
            title: Some(view.title.clone()),
            name: view.name.clone(),
        },
        None => RuleDataView {
            id: id.to_owned(),
            found: false,
            title: None,
            name: None,
        },
    }
}

fn data_view_ids(views: &[DataViewSummary], pattern: &str) -> Vec<String> {
    let mut ids = views
        .iter()
        .filter(|view| view.title.split(',').any(|part| part == pattern))
        .map(|view| view.id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn sendable_pattern(pattern: &str) -> bool {
    !pattern.trim().is_empty()
        && pattern.len() <= PATTERN_BYTES
        && is_path_segment(pattern)
        && !pattern.chars().any(char::is_control)
}

async fn resolve_patterns(
    t: &Transport,
    patterns: Vec<String>,
    views: Option<&[DataViewSummary]>,
) -> Result<PatternFacts> {
    let total = patterns.len();
    let mut rows = Vec::new();
    for pattern in patterns.into_iter().take(MAX_PATTERNS) {
        let (state, counts, error) = if pattern.starts_with('-') {
            (PatternState::Exclusion, None, None)
        } else if !sendable_pattern(&pattern) {
            (PatternState::Unresolved, None, None)
        } else {
            match resolve(t, &pattern).await {
                Ok(counts) => {
                    let state = if counts.0 + counts.1 + counts.2 > 0 {
                        PatternState::Matches
                    } else {
                        PatternState::NoMatch
                    };
                    (state, Some(counts), None)
                }
                Err(e) if is_fatal(e.kind) => return Err(e),
                Err(e) if e.kind == ErrorKind::NotFound => {
                    (PatternState::NoMatch, Some((0, 0, 0)), None)
                }
                Err(e) => (PatternState::Unresolved, None, Some(e)),
            }
        };
        rows.push(PatternRow {
            data_view_ids: views.map(|views| data_view_ids(views, &pattern)),
            pattern,
            state,
            counts,
            error,
        });
    }
    Ok(PatternFacts {
        total,
        truncated: total > MAX_PATTERNS,
        rows,
    })
}

async fn resolve(t: &Transport, pattern: &str) -> Result<(u64, u64, u64)> {
    let body = t
        .get_absolute_es(&format!("/_resolve/index/{}", urlencode(pattern)))
        .await?;
    let count = |key: &str| {
        body.get(key)
            .and_then(Value::as_array)
            .map(|items| items.len() as u64)
            .ok_or_else(|| Error::new(ErrorKind::Http, "invalid resolve index response"))
    };
    Ok((count("indices")?, count("aliases")?, count("data_streams")?))
}

fn is_package_name(name: &str) -> bool {
    (1..=PACKAGE_NAME_BYTES).contains(&name.len())
        && name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

struct RelatedPackages {
    total: usize,
    entries: Vec<(String, Option<String>)>,
}

async fn related_packages(rule: &Rule) -> Result<RelatedPackages> {
    let invalid = || Error::new(ErrorKind::Http, "invalid related integrations on the rule");
    let entries = match rule.as_map().get("related_integrations") {
        None | Some(Value::Null) => {
            return Ok(RelatedPackages {
                total: 0,
                entries: Vec::new(),
            });
        }
        Some(Value::Array(entries)) => entries,
        Some(_) => return Err(invalid()),
    };
    let mut packages: Vec<(String, Option<String>)> = Vec::new();
    let mut seen = HashSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let package = entry
            .get("package")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        let version = match entry.get("version") {
            None | Some(Value::Null) => None,
            Some(Value::String(version)) => Some(version.clone()),
            Some(_) => return Err(invalid()),
        };
        if seen.insert(package) && packages.len() < MAX_PACKAGES {
            packages.push((package.to_owned(), version));
        }
        if (index + 1) % 1_024 == 0 {
            tokio::task::yield_now().await;
        }
    }
    Ok(RelatedPackages {
        total: seen.len(),
        entries: packages,
    })
}

async fn integrations(t: &Transport, rule: &Rule) -> Result<Part<IntegrationFacts>> {
    let packages = match related_packages(rule).await {
        Ok(packages) => packages,
        Err(error) => return Ok(Part::Unavailable(error)),
    };
    let total = packages.total;
    if total == 0 {
        return Ok(Part::Ok(IntegrationFacts {
            total,
            truncated: false,
            rows: Vec::new(),
        }));
    }
    let policies = match integration_policy_ops::list_first_page(t).await {
        Ok(Some(policies)) => policies,
        Ok(None) => {
            return Ok(Part::Unavailable(Error::new(
                ErrorKind::Unsupported,
                "more integration policies than one bounded page",
            )));
        }
        Err(e) if is_fatal(e.kind) => return Err(e),
        Err(e) => return Ok(Part::Unavailable(e)),
    };
    let mut rows = Vec::new();
    for (package, version) in packages.entries {
        let status = package_use(t, &package, &policies).await?;
        rows.push(PackageRow {
            package,
            version,
            status,
        });
    }
    Ok(Part::Ok(IntegrationFacts {
        total,
        truncated: total > MAX_PACKAGES,
        rows,
    }))
}

async fn package_use(
    t: &Transport,
    package: &str,
    policies: &[IntegrationPolicySummary],
) -> Result<std::result::Result<PackageUse, Error>> {
    if !is_package_name(package) {
        return Ok(Err(Error::new(
            ErrorKind::Unsupported,
            "package name outside the accepted grammar",
        )));
    }
    match agent_policies::package_status(t, package).await {
        Ok(status) => Ok(Ok(PackageUse {
            install_status: status.status,
            installed_version: status.installed_version,
            policies: policies
                .iter()
                .filter(|policy| policy.package.name == package)
                .count() as u64,
        })),
        Err(e) if is_fatal(e.kind) => Err(e),
        Err(e) => Ok(Err(e)),
    }
}

impl Readiness {
    pub fn findings(&self) -> Vec<ReadinessFinding> {
        use ReadinessFinding::*;
        let mut findings = Vec::new();
        if self.rule.as_map().get("enabled") == Some(&Value::Bool(false)) {
            findings.push(RuleDisabled);
        }
        if self.index_source == IndexSource::None {
            findings.push(NoIndexSource);
        }
        if let Part::Ok(DataViewFacts {
            rule_data_view: Some(view),
            ..
        }) = &self.data_views
            && self.index_source == IndexSource::DataView
            && !view.found
        {
            findings.push(DataViewMissing);
        }
        let patterns = match &self.patterns {
            Part::Ok(facts) => Some(facts),
            _ => None,
        };
        if let Some(facts) = patterns {
            let mut checked = facts
                .rows
                .iter()
                .filter(|row| row.state != PatternState::Exclusion)
                .peekable();
            if !facts.truncated
                && checked.peek().is_some()
                && checked.all(|row| row.state == PatternState::NoMatch)
            {
                findings.push(NoPatternMatches);
            }
            if facts
                .rows
                .iter()
                .any(|row| row.state == PatternState::Unresolved)
            {
                findings.push(PatternUnresolved);
            }
        }
        let integrations = match &self.integrations {
            Part::Ok(facts) => Some(facts),
            _ => None,
        };
        let used = || {
            integrations
                .into_iter()
                .flat_map(|facts| &facts.rows)
                .filter_map(|row| row.status.as_ref().ok())
        };
        if used().any(|u| u.install_status != "installed") {
            findings.push(IntegrationNotInstalled);
        }
        if used().any(|u| u.install_status == "installed" && u.policies == 0) {
            findings.push(IntegrationWithoutPolicy);
        }
        if patterns.is_some_and(|facts| facts.truncated) {
            findings.push(PatternsTruncated);
        }
        if integrations.is_some_and(|facts| facts.truncated) {
            findings.push(IntegrationsTruncated);
        }
        findings
    }

    pub fn partial(&self) -> bool {
        let patterns = match &self.patterns {
            Part::Ok(facts) => facts
                .rows
                .iter()
                .any(|row| row.state == PatternState::Unresolved),
            part => matches!(part, Part::Unavailable(_)),
        };
        let integrations = match &self.integrations {
            Part::Ok(facts) => facts.rows.iter().any(|row| row.status.is_err()),
            part => matches!(part, Part::Unavailable(_)),
        };
        matches!(self.data_views, Part::Unavailable(_)) || patterns || integrations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_and_package_grammars() {
        for pattern in ["logs-*", "...", ".a", "a..b", "a/b", "%2e%2e", "../_bulk"] {
            assert!(sendable_pattern(pattern), "{pattern}");
        }
        let long = "a".repeat(PATTERN_BYTES + 1);
        for pattern in [
            "",
            " ",
            "\t",
            ".",
            "..",
            "a\u{7}b",
            "a\u{85}b",
            long.as_str(),
        ] {
            assert!(!sendable_pattern(pattern), "{pattern:?}");
        }
        assert!(sendable_pattern(&"a".repeat(PATTERN_BYTES)));
        for name in ["system", "a", "endpoint_2-x", &"a".repeat(128)] {
            assert!(is_package_name(name), "{name}");
        }
        let long = "a".repeat(129);
        for name in [
            "",
            ".",
            "..",
            "../x",
            "A",
            "a.b",
            "a/b",
            "a b",
            "é",
            long.as_str(),
        ] {
            assert!(!is_package_name(name), "{name}");
        }
    }
}
