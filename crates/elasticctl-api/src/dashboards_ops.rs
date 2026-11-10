//! Dashboard selection and portable transfer orchestration.

use crate::content_codec::{self, ContentFormat};
use crate::dashboards::{self, Dashboard, DashboardSpec, DashboardSummary};
use crate::data_views;
use crate::ops::{DeleteOutcome, ExportOutcome, MutationPlan};
use crate::saved_objects;
use elasticctl_core::{Error, ErrorKind, Feature, Result, Transport};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

mod bundle;
mod delete;
mod import;
pub use bundle::{
    BundleImportOutcome, BundleImportPlan, apply_bundle_import, export_bundle, plan_bundle_import,
};
pub use delete::{DashboardDeletePlan, apply_delete, plan_delete};
pub use import::{DashboardImportPlan, DashboardImportReport, apply_import, plan_import};

/// Dashboard list filters accepted by the portable command surface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DashboardFilter {
    pub search: Option<String>,
    pub tag: Option<String>,
    pub limit: Option<usize>,
}

/// Dashboard list output after collection, stable-id sorting, and limiting.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DashboardList {
    pub total: u64,
    pub dashboards: Vec<DashboardSummary>,
    pub truncated: bool,
}

/// Resolve a selector from dashboard summaries.
///
/// Stable ids win over titles. A title is only a convenience selector and must
/// identify exactly one dashboard.
pub fn resolve_from_summaries(
    dashboards: &[DashboardSummary],
    selector: &str,
) -> Result<DashboardSummary> {
    if let Some(dashboard) = dashboards.iter().find(|dashboard| dashboard.id == selector) {
        return Ok(dashboard.clone());
    }

    let mut matches: Vec<_> = dashboards
        .iter()
        .filter(|dashboard| dashboard.title == selector)
        .cloned()
        .collect();
    matches.sort_by(|left, right| left.id.cmp(&right.id));
    match matches.as_slice() {
        [] => Err(Error::new(
            ErrorKind::NotFound,
            format!("no dashboard with id or title '{selector}'"),
        )),
        [dashboard] => Ok(dashboard.clone()),
        _ => Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "dashboard title '{selector}' is ambiguous: {}",
                matches
                    .iter()
                    .map(|dashboard| dashboard.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

/// Resolve a dashboard by exact id, then by exact title only after an id miss.
pub async fn resolve(transport: &Transport, selector: &str) -> Result<DashboardSummary> {
    match dashboards::get_selector(transport, selector).await {
        Ok(dashboard) if dashboard.id == selector => summary_from_dashboard(dashboard),
        Ok(dashboard) => Err(Error::new(
            ErrorKind::Http,
            format!(
                "decoding dashboard get: expected id '{selector}', got '{}'",
                dashboard.id
            ),
        )),
        Err(error) if error.kind == ErrorKind::NotFound => {
            let listed = list_op(transport, &DashboardFilter::default()).await?;
            resolve_from_summaries(&listed.dashboards, selector)
        }
        Err(error) => Err(error),
    }
}

/// Page through dashboard summaries, apply filters, and sort by stable id.
pub async fn list_op(transport: &Transport, filter: &DashboardFilter) -> Result<DashboardList> {
    let tags = filter.tag.iter().cloned().collect::<Vec<_>>();
    let mut page_number = 1;
    let mut total = None;
    let mut dashboards = Vec::new();
    let mut ids = BTreeSet::new();

    loop {
        let page =
            dashboards::search(transport, page_number, filter.search.as_deref(), &tags).await?;
        if page.page != page_number || page.per_page != 1000 {
            return Err(Error::new(
                ErrorKind::Http,
                "decoding dashboard search: unexpected page metadata",
            ));
        }
        if let Some(total) = total {
            if page.total != total {
                return Err(Error::new(
                    ErrorKind::Http,
                    "decoding dashboard search: total changed while paging",
                ));
            }
        } else {
            total = Some(page.total);
        }
        let page_len = page.data.len();
        for dashboard in page.data {
            if !ids.insert(dashboard.id.clone()) {
                return Err(Error::new(
                    ErrorKind::Http,
                    format!(
                        "decoding dashboard search: duplicate dashboard id '{}'",
                        dashboard.id
                    ),
                ));
            }
            dashboards.push(dashboard);
        }
        let expected_total = total.expect("set from the first page");
        if dashboards.len() as u64 >= expected_total {
            break;
        }
        if page_len != 1000 {
            return Err(Error::new(
                ErrorKind::Http,
                "decoding dashboard search: page was short before total",
            ));
        }
        page_number += 1;
    }

    dashboards.sort_by(|left, right| left.id.cmp(&right.id));
    let total = total.unwrap_or(0);
    if dashboards.len() as u64 > total {
        return Err(Error::new(
            ErrorKind::Http,
            "decoding dashboard search: returned more dashboards than total",
        ));
    }
    let limit = filter.limit.unwrap_or(usize::MAX);
    let truncated = dashboards.len() > limit;
    dashboards.truncate(limit);
    Ok(DashboardList {
        total,
        dashboards,
        truncated,
    })
}

/// Resolve one selector, then read its complete dashboard.
pub async fn get_op(transport: &Transport, selector: &str) -> Result<Dashboard> {
    let dashboard = resolve(transport, selector).await?;
    dashboards::get(transport, &dashboard.id).await
}

/// Fully read and validate a portable dashboard artifact.
pub fn validate(path: &Path) -> Result<Vec<DashboardSpec>> {
    let body = std::fs::read_to_string(path).map_err(|error| {
        Error::new(
            ErrorKind::Error,
            format!("reading {}: {error}", path.display()),
        )
    })?;
    let mut specs = content_codec::decode_sequence::<DashboardSpec>(
        &body,
        ContentFormat::from_path(path),
        "dashboard",
    )?;
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for spec in &specs {
        dashboards::validate_spec(spec)?;
        if !seen.insert(spec.id.as_str()) {
            duplicates.insert(spec.id.as_str());
        }
    }
    if !duplicates.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            format!(
                "duplicate dashboard ids: {}",
                duplicates.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(specs)
}

fn invalid_plan(message: impl Into<String>) -> Result<()> {
    Err(Error::new(ErrorKind::Error, message))
}

/// Export selected dashboards as a portable JSON or YAML artifact.
pub async fn export(
    transport: &Transport,
    selectors: &[String],
    format: ContentFormat,
) -> Result<ExportOutcome> {
    let selected = if selectors.is_empty() {
        list_op(transport, &DashboardFilter::default())
            .await?
            .dashboards
    } else {
        let mut selected = Vec::with_capacity(selectors.len());
        for selector in selectors {
            selected.push(resolve(transport, selector).await?);
        }
        selected
    };
    let selected: BTreeMap<_, _> = selected
        .into_iter()
        .map(|dashboard| (dashboard.id.clone(), dashboard))
        .collect();
    let mut specs = Vec::with_capacity(selected.len());
    for (id, _) in selected {
        let dashboard = dashboards::get(transport, &id).await?;
        if dashboard.id != id {
            return Err(Error::new(
                ErrorKind::Http,
                format!("dashboard export was short: expected id '{id}'"),
            ));
        }
        if !dashboard.warnings.is_empty() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "dashboard '{id}' cannot be exported through the typed API without loss: {}; use `dashboards bundle export {id}`",
                    dashboard
                        .warnings
                        .iter()
                        .map(|warning| warning.message.as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            ));
        }
        let spec = DashboardSpec {
            id: dashboard.id,
            data: dashboard.data,
        };
        dashboards::validate_spec(&spec)?;
        specs.push(spec);
    }
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    let body = content_codec::encode_sequence(&specs, format)?;
    Ok(ExportOutcome {
        body,
        exported: specs.len() as u64,
        missing: Vec::<Value>::new(),
    })
}

fn summary_from_dashboard(dashboard: Dashboard) -> Result<DashboardSummary> {
    let title = dashboard
        .data
        .get("title")
        .and_then(Value::as_str)
        .filter(|title| !title.trim().is_empty())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                "decoding dashboard get: data.title must be a non-empty string",
            )
        })?;
    Ok(DashboardSummary {
        id: dashboard.id,
        title: title.to_string(),
        description: dashboard
            .data
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        tags: dashboard
            .data
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| {
                tags.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            }),
    })
}
