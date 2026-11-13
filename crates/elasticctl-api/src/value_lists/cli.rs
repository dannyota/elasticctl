use std::path::{Path, PathBuf};

use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;

use super::{
    Container, ContainerAction, DeleteOutcome, ListOutcome, ListPlan, Outcome, PhaseOrder,
    StoredValues, ValueListType, ValueSet, Warning, encode_container, encode_values,
    find_containers, plan_stems, read_list, read_pair, stored_warnings,
};

#[derive(Serialize)]
pub struct ValidationReport {
    pub valid: bool,
    pub id: String,
    pub warnings: Vec<Warning>,
}

pub fn validate_path(path: &Path) -> Result<ValidationReport> {
    let pair = read_pair(path)?;
    let stored = StoredValues::new(pair.values.iter().cloned().collect());
    Ok(ValidationReport {
        valid: true,
        id: pair.container.id,
        warnings: stored_warnings(&pair.container.list_type, &stored),
    })
}

#[derive(Debug, Serialize)]
pub struct ListSummary {
    pub id: String,
    #[serde(rename = "type")]
    pub list_type: ValueListType,
    pub name: String,
    pub description: String,
    pub supported: bool,
}

pub async fn list_op(
    t: &Transport,
    list_type: Option<&ValueListType>,
    search: Option<&str>,
) -> Result<Vec<ListSummary>> {
    if let Some(kind) = list_type {
        kind.require_supported()?;
    }
    let search = search.map(str::to_lowercase);
    Ok(find_containers(t, None, 1000)
        .await?
        .into_iter()
        .map(|r| r.container)
        .filter(|c| list_type.is_none_or(|kind| c.list_type == *kind))
        .filter(|c| {
            search.as_ref().is_none_or(|s| {
                c.id.to_lowercase().contains(s) || c.name.to_lowercase().contains(s)
            })
        })
        .map(|c| ListSummary {
            supported: c.list_type.require_supported().is_ok(),
            id: c.id,
            list_type: c.list_type,
            name: c.name,
            description: c.description,
        })
        .collect())
}

#[derive(Debug, Serialize)]
pub struct GetReport {
    #[serde(flatten)]
    pub container: Container,
    pub distinct_values: usize,
    pub stored_values: usize,
    pub warnings: Vec<Warning>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<ValueSet>,
}

pub async fn get_op(t: &Transport, id: &str, values: bool) -> Result<GetReport> {
    let list = read_list(t, id)
        .await?
        .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("value list {id} not found")))?;
    let set = list.stored.set();
    Ok(GetReport {
        distinct_values: set.len(),
        stored_values: list.stored.values.len(),
        warnings: stored_warnings(&list.container.container.list_type, &list.stored),
        container: list.container.container,
        values: values.then_some(set),
    })
}

#[derive(Debug, Serialize)]
pub struct ExportPair {
    pub container: Container,
    pub values: ValueSet,
}

#[derive(Debug, Serialize)]
pub struct ExportFiles {
    pub id: String,
    pub container: PathBuf,
    pub values: PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ExportReport {
    Pair(ExportPair),
    Files(Vec<ExportFiles>),
}

pub async fn export_op(
    t: &Transport,
    ids: &[String],
    dir: Option<&Path>,
    json: bool,
    report_path: Option<&Path>,
) -> Result<ExportReport> {
    if ids.is_empty() {
        return Err(super::invalid("name at least one value list to export"));
    }
    let stems = plan_stems(ids.iter().map(String::as_str))?;
    if dir.is_none() && ids.len() == 1 && json {
        let report = get_op(t, &ids[0], true).await?;
        return Ok(ExportReport::Pair(ExportPair {
            container: report.container,
            values: report.values.unwrap_or_default(),
        }));
    }
    let dir = dir.unwrap_or(Path::new("."));
    let files: Vec<_> = stems
        .iter()
        .map(|(id, stem)| ExportFiles {
            id: id.clone(),
            container: dir.join(format!("{stem}.yaml")),
            values: dir.join(format!("{stem}.txt")),
        })
        .collect();
    let mut existing = Vec::new();
    for path in files.iter().flat_map(|f| [&f.container, &f.values]) {
        match std::fs::symlink_metadata(path) {
            Ok(_) => existing.push(path.display().to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(super::invalid(format!(
                    "checking {}: {error}",
                    path.display()
                )));
            }
        }
    }
    if !existing.is_empty() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "refusing to overwrite existing files: {}",
                existing.join(", ")
            ),
        ));
    }
    if let Some(report_path) = report_path {
        let report = path_identity(report_path, 0)?;
        for destination in files.iter().flat_map(|f| [&f.container, &f.values]) {
            let target = path_identity(destination, 0)?;
            let same = report == target
                || (cfg!(any(windows, target_os = "macos"))
                    && report
                        .as_os_str()
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&target.as_os_str().to_string_lossy()));
            if same {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    format!(
                        "report path {} aliases exported file {}",
                        report_path.display(),
                        destination.display()
                    ),
                ));
            }
        }
    }
    let mut contents = Vec::new();
    for f in &files {
        let report = get_op(t, &f.id, true).await?;
        contents.push((
            encode_container(&report.container)?,
            encode_values(&report.values.unwrap_or_default()),
        ));
    }
    std::fs::create_dir_all(dir)
        .map_err(|error| super::invalid(format!("creating {}: {error}", dir.display())))?;
    for (f, (container, values)) in files.iter().zip(contents) {
        write_new(&f.container, container.as_bytes())?;
        write_new(&f.values, values.as_bytes())?;
    }
    Ok(ExportReport::Files(files))
}

fn path_identity(path: &Path, depth: usize) -> Result<PathBuf> {
    use std::path::Component;
    if depth > 40 {
        return Err(super::invalid(format!(
            "too many symlinks resolving {}",
            path.display()
        )));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| super::invalid(format!("reading current directory: {error}")))?
            .join(path)
    };
    let mut resolved = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => continue,
            Component::ParentDir => {
                resolved.pop();
                continue;
            }
            _ => resolved.push(component.as_os_str()),
        }
        match std::fs::symlink_metadata(&resolved) {
            Ok(meta) if meta.is_symlink() => {
                let target = std::fs::read_link(&resolved).map_err(|error| {
                    super::invalid(format!("reading symlink {}: {error}", resolved.display()))
                })?;
                let target = if target.is_absolute() {
                    target
                } else {
                    resolved.parent().unwrap_or(Path::new(".")).join(target)
                };
                resolved = path_identity(&target, depth + 1)?;
            }
            Ok(_) => {
                resolved = std::fs::canonicalize(&resolved).map_err(|error| {
                    super::invalid(format!("resolving {}: {error}", resolved.display()))
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(super::invalid(format!(
                    "resolving {}: {error}",
                    resolved.display()
                )));
            }
        }
    }
    Ok(resolved)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| super::invalid(format!("creating {}: {error}", path.display())))?;
    file.write_all(bytes)
        .map_err(|error| super::invalid(format!("writing {}: {error}", path.display())))
}

#[derive(Serialize)]
pub struct ImportPreview<'a> {
    pub id: &'a str,
    #[serde(rename = "type")]
    pub list_type: &'a ValueListType,
    pub container_action: ContainerAction,
    pub adds: &'a ValueSet,
    pub removes: &'a ValueSet,
    pub phase_order: &'static str,
    pub phase_reason: &'a str,
    pub warnings: &'a [Warning],
}

impl<'a> From<&'a ListPlan> for ImportPreview<'a> {
    fn from(plan: &'a ListPlan) -> Self {
        Self {
            id: &plan.local.container.id,
            list_type: &plan.local.container.list_type,
            container_action: plan.container_action,
            adds: &plan.adds,
            removes: &plan.removes,
            phase_order: if plan.adds.is_empty() && plan.removes.is_empty() {
                "none"
            } else {
                match plan.order {
                    PhaseOrder::AddsFirst => "adds_first",
                    PhaseOrder::RemovesFirst => "removes_first",
                }
            },
            phase_reason: &plan.order_reason,
            warnings: &plan.warnings,
        }
    }
}

#[derive(Serialize)]
pub struct MutationReport<T> {
    pub applied: bool,
    pub lists: Vec<T>,
}

impl MutationReport<ListOutcome> {
    pub fn import(lists: Vec<ListOutcome>) -> Self {
        Self {
            applied: lists.iter().all(|r| r.outcome == Outcome::Applied),
            lists,
        }
    }
}

impl MutationReport<DeleteOutcome> {
    pub fn delete(lists: Vec<DeleteOutcome>) -> Self {
        Self {
            applied: lists.iter().all(|r| r.result.outcome == Outcome::Applied),
            lists,
        }
    }
}

#[cfg(test)]
mod tests;
