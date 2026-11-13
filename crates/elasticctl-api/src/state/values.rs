mod cone;
mod pull;

pub(super) use pull::pull_lists;

use crate::diff::FieldChange;
use crate::model::{ExceptionItem, ExceptionList, ListKey, Rule};
use crate::value_lists::{
    self as vl, InstalledReference, ListPlan, LocalPair, RemoteList, Warning,
};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ValueListChange {
    pub id: String,
    pub change: String,
    pub fields: Vec<FieldChange>,
    pub adds: Vec<String>,
    pub removes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ValueListIssue {
    pub id: String,
    pub kind: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct ValueListDrift {
    pub local: usize,
    pub remote: usize,
    pub changes: Vec<ValueListChange>,
    pub refused: Vec<ValueListIssue>,
    pub warnings: Vec<ValueListIssue>,
    pub unreferenced: Vec<String>,
}

impl ValueListDrift {
    pub fn is_clean(&self) -> bool {
        self.refused.is_empty()
            && self
                .changes
                .iter()
                .all(|change| change.change == "unchanged")
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct ValuePlan {
    pub plans: Vec<ListPlan>,
    pub drift: Option<ValueListDrift>,
}

pub(super) fn item_refs(items: &[ExceptionItem]) -> Result<Vec<InstalledReference>> {
    let mut refs = Vec::new();
    for item in items {
        let key = ListKey {
            list_id: item.list_id()?.into(),
            namespace_type: item.namespace_type().into(),
        };
        let mut item = item.clone();
        item.as_map_mut().insert(
            "namespace_type".into(),
            Value::String(key.namespace_type.clone()),
        );
        refs.extend(vl::item_references(&key, &item)?);
    }
    Ok(refs)
}

pub(super) struct Inputs<'a> {
    pub pairs: &'a [LocalPair],
    pub has_root: bool,
    pub lists: &'a [ExceptionList],
    pub items: &'a [ExceptionItem],
    pub local: &'a [Rule],
    pub remote: &'a [Rule],
    pub exception_plan: &'a super::diff::ExceptionPlan,
}

pub(super) async fn plan(t: &Transport, input: Inputs<'_>, pushing: bool) -> Result<ValuePlan> {
    let active = super::referenced_keys(input.local);
    let mirrored: BTreeSet<_> = input
        .lists
        .iter()
        .map(ExceptionList::key)
        .collect::<Result<_>>()?;
    let wanted: BTreeSet<_> = active
        .iter()
        .cloned()
        .chain(super::referenced_keys(input.remote))
        .collect();
    let managed: BTreeSet<_> = wanted.intersection(&mirrored).cloned().collect();
    let selected_items: Vec<_> = input
        .items
        .iter()
        .filter(|i| {
            managed.contains(&ListKey {
                list_id: i.list_id().unwrap_or_default().into(),
                namespace_type: i.namespace_type().into(),
            })
        })
        .cloned()
        .collect();
    let selected_refs = item_refs(&selected_items)?;
    let selected: BTreeSet<_> = selected_refs.iter().map(|r| r.list_id.clone()).collect();
    let mut retained = Vec::new();
    for key in active.difference(&mirrored) {
        match crate::exceptions::get_list(t, key).await {
            Ok(_) => retained.extend(crate::exceptions::find_items(t, key).await?),
            Err(error) if error.kind == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let mut refs = selected_refs;
    refs.extend(item_refs(&retained)?);
    let unreferenced = input
        .pairs
        .iter()
        .filter(|p| !selected.contains(&p.container.id))
        .map(|p| p.container.id.clone())
        .collect();
    let mut drift = ValueListDrift {
        unreferenced,
        ..Default::default()
    };
    if refs.is_empty() {
        return Ok(ValuePlan {
            drift: input.has_root.then_some(drift),
            ..Default::default()
        });
    }
    if pushing {
        vl::require_bootstrapped(t).await?;
    }
    let installed = vl::scan_references(t).await?;
    let mut desired: Vec<_> = installed
        .iter()
        .filter(|r| !managed.contains(&r.container))
        .cloned()
        .collect();
    desired.extend(item_refs(&selected_items)?);
    let ids: BTreeSet<_> = refs.iter().map(|r| r.list_id.clone()).collect();
    let mut plans = Vec::new();
    for id in ids {
        let local = input
            .pairs
            .iter()
            .find(|p| p.container.id == id && selected.contains(&id));
        let container = vl::read_container(t, &id).await?;
        let before = match container {
            Some(container) if container.container.list_type.require_supported().is_ok() => {
                let stored = vl::export_values(t, &id, &container.container.list_type).await?;
                Some(RemoteList { container, stored })
            }
            Some(container) => {
                let error = container
                    .container
                    .list_type
                    .require_supported()
                    .unwrap_err();
                issue(&mut drift, &id, error);
                None
            }
            None => None,
        };
        if input.has_root && selected.contains(&id) {
            drift.local += usize::from(local.is_some());
            drift.remote += usize::from(before.is_some());
            drift.changes.push(change(&id, local, before.as_ref()));
        }
        if let Some(before) = &before {
            warnings(
                &mut drift,
                &id,
                vl::stored_warnings(&before.container.container.list_type, &before.stored),
            );
        }
        let source = local
            .map(|p| &p.container)
            .or_else(|| before.as_ref().map(|r| &r.container.container));
        for reference in refs.iter().filter(|r| r.list_id == id) {
            match source {
                None => issue(
                    &mut drift,
                    &id,
                    Error::new(
                        ErrorKind::NotFound,
                        format!(
                            "value list {id} named by {} has no local or stack source",
                            reference.name()
                        ),
                    ),
                ),
                Some(source) if source.list_type != reference.list_type => issue(
                    &mut drift,
                    &id,
                    Error::new(
                        ErrorKind::Conflict,
                        format!(
                            "value list {id} named by {} has entry type {}, source type {}",
                            reference.name(),
                            reference.list_type,
                            source.list_type
                        ),
                    ),
                ),
                Some(_) => {}
            }
        }
        let pair = local.cloned().or_else(|| {
            before.as_ref().map(|r| LocalPair {
                stem: vl::file_stem(&id),
                container: r.container.container.clone(),
                values: r.stored.set(),
            })
        });
        if let Some(pair) = pair {
            match vl::plan_list(pair, before.clone(), &installed, &desired) {
                Ok(plan) => {
                    warnings(&mut drift, &id, plan.warnings.clone());
                    plans.push(plan);
                }
                Err(error)
                    if !pushing
                        && error.kind == ErrorKind::Error
                        && error.message.contains("non-canonical") =>
                {
                    drift.warnings.push(ValueListIssue {
                        id: id.clone(),
                        kind: "non_canonical".into(),
                        message: error.message,
                    });
                }
                Err(error) => issue(&mut drift, &id, error),
            }
        }
        if let Some(before) = &before {
            if before.container.container.list_type == vl::ValueListType::IpRange
                && before.stored.dash_count() > 200
                && !pushing
            {
                issue(
                    &mut drift,
                    &id,
                    Error::new(
                        ErrorKind::Unsupported,
                        format!(
                            "value list {id} holds {} stored dash values, above 200",
                            before.stored.dash_count()
                        ),
                    ),
                );
            }
            if before.stored.values.is_empty() && !pushing {
                issue(
                    &mut drift,
                    &id,
                    Error::new(
                        ErrorKind::Unsupported,
                        format!("referenced value list {id} is empty"),
                    ),
                );
            }
        }
    }
    if let Err(error) = cone::check(
        &plans,
        &installed,
        &desired,
        input.local,
        input.remote,
        input.exception_plan,
    ) {
        let id = plans
            .iter()
            .find(|p| !p.adds.is_empty() || !p.removes.is_empty())
            .map(|p| p.local.container.id.as_str())
            .unwrap_or_default();
        issue(&mut drift, id, error);
    }
    if pushing && let Some(refusal) = drift.refused.first() {
        return Err(Error::new(kind(&refusal.kind), refusal.message.clone()));
    }
    let show = input.has_root || !drift.refused.is_empty();
    Ok(ValuePlan {
        plans,
        drift: show.then_some(drift),
    })
}

fn kind(kind: &str) -> ErrorKind {
    match kind {
        "not_found" => ErrorKind::NotFound,
        "conflict" => ErrorKind::Conflict,
        "unsupported" => ErrorKind::Unsupported,
        _ => ErrorKind::Error,
    }
}

fn issue(drift: &mut ValueListDrift, id: &str, error: Error) {
    drift.refused.push(ValueListIssue {
        id: id.into(),
        kind: error.kind.as_str().into(),
        message: error.message,
    });
}

fn warnings(drift: &mut ValueListDrift, id: &str, warnings: Vec<Warning>) {
    for warning in warnings {
        let issue = ValueListIssue {
            id: id.into(),
            kind: serde_json::to_value(warning.kind)
                .expect("warning kind serializes")
                .as_str()
                .unwrap()
                .into(),
            message: warning.message,
        };
        if !drift.warnings.contains(&issue) {
            drift.warnings.push(issue);
        }
    }
}

fn change(id: &str, local: Option<&LocalPair>, remote: Option<&RemoteList>) -> ValueListChange {
    let current = remote.map(|r| r.stored.set()).unwrap_or_default();
    let target = local
        .map(|p| p.values.clone())
        .unwrap_or_else(|| current.clone());
    let mut fields = Vec::new();
    if let (Some(local), Some(remote)) = (local, remote) {
        let before = serde_json::to_value(&remote.container.container).unwrap();
        let after = serde_json::to_value(&local.container).unwrap();
        for field in ["type", "name", "description", "meta"] {
            if field == "meta" && local.container.meta.is_none() {
                continue;
            }
            if before.get(field) != after.get(field) {
                fields.push(FieldChange {
                    field: field.into(),
                    before: before.get(field).cloned().unwrap_or(Value::Null),
                    after: after.get(field).cloned().unwrap_or(Value::Null),
                });
            }
        }
    }
    let adds: Vec<_> = target.difference(&current).cloned().collect();
    let removes: Vec<_> = current.difference(&target).cloned().collect();
    let change = match (local, remote) {
        (Some(_), None) => "local_only",
        (None, Some(_)) => "remote_only",
        _ if !fields.is_empty() || !adds.is_empty() || !removes.is_empty() => "changed",
        _ => "unchanged",
    };
    ValueListChange {
        id: id.into(),
        change: change.into(),
        fields,
        adds,
        removes,
    }
}

pub(super) async fn reread(t: &Transport, plan: &ValuePlan) -> Result<()> {
    for list in &plan.plans {
        let id = &list.local.container.id;
        let read = vl::read_container(t, id).await.map_err(|error| {
            if error.kind == ErrorKind::Http && error.http_status.is_none() {
                Error::new(
                    ErrorKind::Conflict,
                    format!(
                        "value list {id} container cannot be validated since preview; re-run: {}",
                        error.message
                    ),
                )
            } else {
                error
            }
        })?;
        if !read.is_some_and(|r| {
            r.container.id == *id && r.container.list_type == list.local.container.list_type
        }) {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!("value list {id} id or type changed since preview; re-run"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod tests;
