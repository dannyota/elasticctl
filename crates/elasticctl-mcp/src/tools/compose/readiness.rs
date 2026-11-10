//! The `rule_readiness` task tool: validate the selector, run the fixed read
//! plan, and project counts and statuses. No index, alias, or data stream
//! name from a response is projected.
use super::*;
use crate::server::validate_text;
use elasticctl_api::compose::readiness::{
    self as api, IndexSource, PatternState, Readiness, ReadinessFinding,
};
use serde_json::{Map, Value};

const DESCRIPTION: &str = "Data readiness of one Elastic Security rule: whether each index pattern resolves to indices, aliases, or data streams (counts only), whether its data view exists, and whether its related Fleet integration packages are installed and used by an integration policy. Read-only.";
const MAX_SELECTOR_BYTES: usize = 1_024;

#[derive(Debug, serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReadinessInput {
    /// Exact rule_id or display name. Must contain non-whitespace text and be no more than 1,024 UTF-8 bytes; the supplied value is used unchanged.
    #[schemars(length(min = 1, max = 1024))]
    selector: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct RuleRefData {
    rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    rule_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum IndexSourceData {
    Index,
    DataView,
    None,
}

#[derive(Debug, Serialize, JsonSchema)]
struct RuleDataViewData {
    id: String,
    found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct DataViewsData {
    count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_data_view: Option<RuleDataViewData>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum PatternStateData {
    Matches,
    NoMatch,
    Exclusion,
    Unresolved,
}

#[derive(Debug, Serialize, JsonSchema)]
struct PatternRowData {
    pattern: String,
    state: PatternStateData,
    #[serde(skip_serializing_if = "Option::is_none")]
    indices: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aliases: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_streams: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ToolError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_view_ids: Option<Vec<String>>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct PatternsData {
    total: usize,
    truncated: bool,
    rows: Vec<PatternRowData>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum RowStatusData {
    Ok,
    Unavailable,
}

#[derive(Debug, Serialize, JsonSchema)]
struct PackageRowData {
    package: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    status: RowStatusData,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ToolError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    install_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    installed_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policies: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct IntegrationsData {
    total: usize,
    truncated: bool,
    rows: Vec<PackageRowData>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum FindingData {
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

impl From<ReadinessFinding> for FindingData {
    fn from(finding: ReadinessFinding) -> Self {
        match finding {
            ReadinessFinding::RuleDisabled => Self::RuleDisabled,
            ReadinessFinding::NoIndexSource => Self::NoIndexSource,
            ReadinessFinding::DataViewMissing => Self::DataViewMissing,
            ReadinessFinding::NoPatternMatches => Self::NoPatternMatches,
            ReadinessFinding::PatternUnresolved => Self::PatternUnresolved,
            ReadinessFinding::IntegrationNotInstalled => Self::IntegrationNotInstalled,
            ReadinessFinding::IntegrationWithoutPolicy => Self::IntegrationWithoutPolicy,
            ReadinessFinding::PatternsTruncated => Self::PatternsTruncated,
            ReadinessFinding::IntegrationsTruncated => Self::IntegrationsTruncated,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
struct ReadinessData {
    rule: RuleRefData,
    index_source: IndexSourceData,
    data_views: PartData<DataViewsData>,
    patterns: PartData<PatternsData>,
    integrations: PartData<IntegrationsData>,
    partial: bool,
    findings: Vec<FindingData>,
}

#[allow(dead_code)]
#[allow(clippy::large_enum_variant)] // Schema-only alternatives are never instantiated.
#[derive(JsonSchema)]
#[serde(untagged)]
enum ReadinessOutput {
    Success(crate::result::ToolSuccess<ReadinessData>),
    Failure(crate::result::ToolFailure),
}

pub(super) fn definition() -> Tool {
    let tool = Tool::new("rule_readiness", DESCRIPTION, JsonObject::new())
        .with_input_schema::<ReadinessInput>()
        .with_output_schema::<ReadinessOutput>()
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
        .expect("typed schema")
        .as_ref()
        .clone();
    schema.insert("type".into(), Value::String("object".into()));
    tool.with_raw_output_schema(std::sync::Arc::new(schema))
}

pub(super) async fn call(
    arguments: Option<&JsonObject>,
    state: &ServerState,
    _cancellation: CancellationToken,
) -> Result<AdapterResult, AdapterError> {
    let input: ReadinessInput =
        serde_json::from_value(Value::Object(arguments.cloned().unwrap_or_default()))
            .map_err(|_| AdapterError::InvalidArgument)?;
    validate_text("selector", &input.selector, MAX_SELECTOR_BYTES)
        .map_err(|_| AdapterError::InvalidArgument)?;
    let transport = state.transport().await.map_err(AdapterError::Core)?;
    let report = api::rule_readiness(transport, &input.selector)
        .await
        .map_err(AdapterError::Core)?;
    let data = project(report).map_err(AdapterError::Core)?;
    Ok(AdapterResult {
        data: serde_json::to_value(data).map_err(|_| AdapterError::Core(projection_error()))?,
        page: None,
        row_key: None,
    })
}

fn projection_error() -> Error {
    Error::new(
        ErrorKind::Http,
        "the selected deployment returned an invalid rule projection",
    )
}

fn optional<T: serde::de::DeserializeOwned>(
    map: &Map<String, Value>,
    field: &str,
) -> Result<Option<T>, Error> {
    match map.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|_| projection_error()),
    }
}

fn project(report: Readiness) -> Result<ReadinessData, Error> {
    let findings = report.findings().into_iter().map(Into::into).collect();
    let partial = report.partial();
    let map = report.rule.as_map();
    let rule = RuleRefData {
        rule_id: report
            .rule
            .rule_id()
            .map_err(|_| projection_error())?
            .to_owned(),
        name: optional(map, "name")?,
        rule_type: optional(map, "type")?,
        enabled: optional(map, "enabled")?,
    };
    Ok(ReadinessData {
        rule,
        index_source: match report.index_source {
            IndexSource::Index => IndexSourceData::Index,
            IndexSource::DataView => IndexSourceData::DataView,
            IndexSource::None => IndexSourceData::None,
        },
        data_views: part(report.data_views, |facts| {
            Ok(DataViewsData {
                count: facts.count,
                rule_data_view: facts.rule_data_view.map(|view| RuleDataViewData {
                    id: view.id,
                    found: view.found,
                    title: view.title,
                    name: view.name,
                }),
            })
        })?,
        patterns: part(report.patterns, |facts| {
            Ok(PatternsData {
                total: facts.total,
                truncated: facts.truncated,
                rows: facts.rows.into_iter().map(project_pattern).collect(),
            })
        })?,
        integrations: part(report.integrations, |facts| {
            Ok(IntegrationsData {
                total: facts.total,
                truncated: facts.truncated,
                rows: facts.rows.into_iter().map(project_package).collect(),
            })
        })?,
        partial,
        findings,
    })
}

fn project_pattern(row: api::PatternRow) -> PatternRowData {
    let (indices, aliases, data_streams) = match row.counts {
        Some((indices, aliases, data_streams)) => {
            (Some(indices), Some(aliases), Some(data_streams))
        }
        None => (None, None, None),
    };
    PatternRowData {
        pattern: row.pattern,
        state: match row.state {
            PatternState::Matches => PatternStateData::Matches,
            PatternState::NoMatch => PatternStateData::NoMatch,
            PatternState::Exclusion => PatternStateData::Exclusion,
            PatternState::Unresolved => PatternStateData::Unresolved,
        },
        indices,
        aliases,
        data_streams,
        error: row.error.as_ref().map(tool_error),
        data_view_ids: row.data_view_ids,
    }
}

fn project_package(row: api::PackageRow) -> PackageRowData {
    let mut data = PackageRowData {
        package: row.package,
        version: row.version,
        status: RowStatusData::Ok,
        error: None,
        install_status: None,
        installed_version: None,
        policies: None,
    };
    match row.status {
        Ok(usage) => {
            data.install_status = Some(usage.install_status);
            data.installed_version = usage.installed_version;
            data.policies = Some(usage.policies);
        }
        Err(error) => {
            data.status = RowStatusData::Unavailable;
            data.error = Some(tool_error(&error));
        }
    }
    data
}
