use super::*;
use crate::{
    PageInfo, ToolFailure, ToolSuccess,
    server::{validate_limit, validate_text},
};
use elasticctl_api::{
    RuleFilter, RuleSource,
    compose::coverage::{self, CoverageGroup, CoverageReport},
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

const DESCRIPTION: &str = "Detection coverage across Elastic Security rules, grouped by MITRE ATT&CK technique, tactic, index pattern, or integration package. Each row counts enabled and disabled rules. Use rules_list with technique or tactic to see the rules behind a row. Reads at most 4,000 rules; near that size a call can need a longer server --timeout. Read-only.";
const DEFAULT_LIMIT: usize = 50;
const MAX_TEXT_BYTES: usize = 1_024;

/// Row grouping.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum GroupBy {
    #[default]
    Technique,
    Tactic,
    IndexPattern,
    Integration,
}

impl From<GroupBy> for CoverageGroup {
    fn from(group_by: GroupBy) -> Self {
        match group_by {
            GroupBy::Technique => Self::Technique,
            GroupBy::Tactic => Self::Tactic,
            GroupBy::IndexPattern => Self::IndexPattern,
            GroupBy::Integration => Self::Integration,
        }
    }
}

impl From<CoverageGroup> for GroupBy {
    fn from(group_by: CoverageGroup) -> Self {
        match group_by {
            CoverageGroup::Technique => Self::Technique,
            CoverageGroup::Tactic => Self::Tactic,
            CoverageGroup::IndexPattern => Self::IndexPattern,
            CoverageGroup::Integration => Self::Integration,
        }
    }
}

/// Rule source, in the rules_list vocabulary.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum SourceInput {
    Custom,
    Customized,
    Prebuilt,
    #[default]
    All,
}

impl From<SourceInput> for RuleSource {
    fn from(source: SourceInput) -> Self {
        match source {
            SourceInput::Custom => Self::Custom,
            SourceInput::Customized => Self::Customized,
            SourceInput::Prebuilt => Self::Prebuilt,
            SourceInput::All => Self::All,
        }
    }
}

fn default_group_by() -> GroupBy {
    GroupBy::Technique
}

fn default_source() -> SourceInput {
    SourceInput::All
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CoverageInput {
    /// What each row counts rules by: technique, tactic, index_pattern, or integration.
    #[serde(default)]
    #[schemars(default = "default_group_by")]
    group_by: GroupBy,
    /// Restrict the corpus to enabled or disabled rules. Absent reads both.
    enabled: Option<bool>,
    #[serde(default)]
    #[schemars(default = "default_source")]
    source: SourceInput,
    /// Exact rule-tag filter. When supplied, it must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    tag: Option<String>,
    #[serde(default = "default_limit")]
    #[schemars(default = "default_limit")]
    #[schemars(range(min = 1, max = 200))]
    limit: usize,
}

impl CoverageInput {
    fn validate(self) -> Result<(usize, CoverageGroup, RuleFilter), AdapterError> {
        validate_limit(self.limit).map_err(|_| AdapterError::InvalidArgument)?;
        if let Some(tag) = &self.tag {
            validate_text("tag", tag, MAX_TEXT_BYTES).map_err(|_| AdapterError::InvalidArgument)?;
        }
        let filter = RuleFilter {
            source: self.source.into(),
            enabled: self.enabled,
            tag: self.tag,
            ..Default::default()
        };
        Ok((self.limit, self.group_by.into(), filter))
    }
}

#[derive(Debug, Serialize, JsonSchema)]
struct CoverageSummaryData {
    rules: u64,
    enabled_rules: u64,
    disabled_rules: u64,
    unmapped_rules: u64,
    /// Groups before the row limit.
    groups: u64,
}

#[derive(Debug, Serialize, JsonSchema)]
struct CoverageRowData {
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// Present only when rows group by technique.
    #[serde(skip_serializing_if = "Option::is_none")]
    tactics: Option<Vec<String>>,
    enabled_rules: u64,
    disabled_rules: u64,
}

#[derive(Debug, Serialize, JsonSchema)]
struct CoverageData {
    group_by: GroupBy,
    summary: CoverageSummaryData,
    rows: Vec<CoverageRowData>,
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum CoverageOutput {
    Success(ToolSuccess<CoverageData>),
    Failure(ToolFailure),
}

pub(super) fn definition() -> Tool {
    let tool = Tool::new("detection_coverage", DESCRIPTION, JsonObject::new())
        .with_input_schema::<CoverageInput>()
        .with_output_schema::<CoverageOutput>()
        .with_annotations(
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(true),
        );
    let mut schema = tool
        .output_schema
        .as_ref()
        .expect("typed output schema is present")
        .as_ref()
        .clone();
    schema.insert("type".into(), Value::String("object".into()));
    tool.with_raw_output_schema(Arc::new(schema))
}

pub(super) async fn call(
    arguments: Option<&JsonObject>,
    state: &ServerState,
    _cancellation: CancellationToken,
) -> Result<AdapterResult, AdapterError> {
    let input: CoverageInput =
        serde_json::from_value(Value::Object(arguments.cloned().unwrap_or_default()))
            .map_err(|_| AdapterError::InvalidArgument)?;
    let (limit, group_by, filter) = input.validate()?;
    let transport = state.transport().await.map_err(AdapterError::Core)?;
    let report = coverage::detection_coverage(transport, &filter, group_by)
        .await
        .map_err(AdapterError::Core)?;
    let (data, page) = project(report, limit);
    let data = serde_json::to_value(data).map_err(|_| {
        AdapterError::Core(Error::new(
            ErrorKind::Http,
            "the coverage report could not be projected",
        ))
    })?;
    Ok(AdapterResult {
        data,
        page: Some(page),
        row_key: Some("rows"),
    })
}

fn project(report: CoverageReport, limit: usize) -> (CoverageData, PageInfo) {
    let groups = report.rows.len();
    let returned = groups.min(limit);
    let truncated = returned < groups;
    let techniques = report.group_by == CoverageGroup::Technique;
    let rows = report
        .rows
        .into_iter()
        .take(returned)
        .map(|row| CoverageRowData {
            key: row.key,
            name: row.name,
            tactics: techniques.then_some(row.tactics),
            enabled_rules: row.enabled_rules,
            disabled_rules: row.disabled_rules,
        })
        .collect();
    let data = CoverageData {
        group_by: report.group_by.into(),
        summary: CoverageSummaryData {
            rules: report.rules,
            enabled_rules: report.enabled_rules,
            disabled_rules: report.disabled_rules,
            unmapped_rules: report.unmapped_rules,
            groups: groups as u64,
        },
        rows,
    };
    let page = PageInfo {
        limit,
        returned,
        total: Some(groups as u64),
        has_more: Some(truncated),
        truncated,
    };
    (data, page)
}
