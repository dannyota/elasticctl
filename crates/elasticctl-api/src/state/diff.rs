//! `state diff`, and the exception-list drift it shares with push.

use super::reports::{DiffReport, ExceptionDrift, ListChange, Mirror};
use crate::diff::{Change, Drift, FieldChange};
use crate::exceptions;
use crate::model::{ExceptionItem, ExceptionList, ListKey, Rule};
use crate::normalize;
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// A container write `push` will perform, in apply order.
#[derive(Debug, Clone)]
pub(crate) enum ListOp {
    Create(ExceptionList),
    Update(ExceptionList),
}

pub async fn diff(
    t: &Transport,
    dir: &Path,
    selectors: &[String],
    tag: Option<&str>,
) -> Result<DiffReport> {
    let Mirror {
        rules: local_all,
        lists,
        items,
    } = super::mirror::read_mirror(dir)?;
    let scope = super::scope_of(t, selectors, tag, &local_all, "compare").await?;
    let local = scope.narrow(local_all);
    let remote = scope.remote(t).await?;
    let drift = Drift::compute(&local, &remote)?;

    let (exceptions, _, _, _) = exception_plan(t, lists, items, &local, &remote).await?;

    // Omit unchanged rules so the diff shows only differences.
    let changes: Vec<Change> = drift
        .changes
        .iter()
        .filter(|c| !matches!(c, Change::Unchanged { .. }))
        .cloned()
        .collect();

    Ok(DiffReport {
        clean: drift.is_clean() && exceptions.is_clean(),
        local: local.len(),
        remote: remote.len(),
        changes,
        exceptions,
        selected: scope.is_scoped().then(|| scope.selected()),
        local_total: scope.is_scoped().then_some(scope.local_total),
    })
}

/// Field-level drift between two canonical containers.
fn list_field_changes(before: &ExceptionList, after: &ExceptionList) -> Vec<FieldChange> {
    let (b, a) = (before.as_map(), after.as_map());
    let mut keys: Vec<&String> = b.keys().chain(a.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter_map(|k| {
            let bv = b.get(k).cloned().unwrap_or(Value::Null);
            let av = a.get(k).cloned().unwrap_or(Value::Null);
            (bv != av).then(|| FieldChange {
                field: k.clone(),
                before: bv,
                after: av,
            })
        })
        .collect()
}

/// Compare local and remote containers, returning the drift and the ordered
/// container writes `push` should perform.
fn list_drift(
    local: &[ExceptionList],
    remote: &[ExceptionList],
) -> Result<(ExceptionDrift, Vec<ListOp>)> {
    let index = |lists: &[ExceptionList], side: &str| -> Result<BTreeMap<ListKey, ExceptionList>> {
        let mut map = BTreeMap::new();
        for (idx, list) in lists.iter().enumerate() {
            let key = list.key().map_err(|_| {
                Error::new(
                    ErrorKind::Error,
                    format!("{side} exception list at position {idx} has an unreadable list_id"),
                )
            })?;
            if map
                .insert(key.clone(), normalize::canonical_list(list))
                .is_some()
            {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    format!(
                        "{side} has two exception lists with list_id \"{}\" in namespace \"{}\"",
                        key.list_id, key.namespace_type
                    ),
                ));
            }
        }
        Ok(map)
    };

    let local = index(local, "local")?;
    let remote = index(remote, "remote")?;

    let mut changes = Vec::new();
    let mut ops = Vec::new();
    let mut keys: Vec<&ListKey> = local.keys().chain(remote.keys()).collect();
    keys.sort();
    keys.dedup();

    for key in keys {
        match (local.get(key), remote.get(key)) {
            (Some(local_list), None) => {
                changes.push(ListChange::Added {
                    list_id: key.list_id.clone(),
                    name: local_list.name().to_string(),
                });
                ops.push(ListOp::Create(local_list.clone()));
            }
            (None, Some(remote_list)) => {
                changes.push(ListChange::RemoteOnly {
                    list_id: key.list_id.clone(),
                    name: remote_list.name().to_string(),
                });
            }
            (Some(local_list), Some(remote_list)) => {
                let fields = list_field_changes(remote_list, local_list);
                if fields.is_empty() {
                    changes.push(ListChange::Unchanged {
                        list_id: key.list_id.clone(),
                    });
                } else {
                    changes.push(ListChange::Modified {
                        list_id: key.list_id.clone(),
                        name: local_list.name().to_string(),
                        fields,
                    });
                    ops.push(ListOp::Update(local_list.clone()));
                }
            }
            (None, None) => unreachable!("a key came from one of the two maps"),
        }
    }

    Ok((
        ExceptionDrift {
            local: local.len(),
            remote: remote.len(),
            changes,
            dangling: Vec::new(),
        },
        ops,
    ))
}

/// Fetch the remote containers for the given keys, skipping a key with no live
/// container (a dangling pointer `diff` reports in Task 12).
async fn fetch_remote_lists(t: &Transport, keys: &BTreeSet<ListKey>) -> Result<Vec<ExceptionList>> {
    let mut out = Vec::new();
    for key in keys {
        match exceptions::get_list(t, key).await {
            Ok(list) => out.push(list),
            Err(e) if e.kind == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Compute exception drift and the ordered container/item writes, closing over
/// the lists referenced by the local and remote rules in scope. The last
/// element is the set of keys that resolve at apply time: already on the stack
/// or about to be created. `plan_push` refuses any other referenced key before
/// a single write.
pub(crate) async fn exception_plan(
    t: &Transport,
    mirror_lists: Vec<ExceptionList>,
    mirror_items: Vec<ExceptionItem>,
    local_rules: &[Rule],
    remote_rules: &[Rule],
) -> Result<(
    ExceptionDrift,
    Vec<ListOp>,
    Vec<ExceptionItem>,
    BTreeSet<ListKey>,
)> {
    let wanted: BTreeSet<ListKey> = super::referenced_keys(local_rules)
        .into_iter()
        .chain(super::referenced_keys(remote_rules))
        .collect();

    let remote_lists = fetch_remote_lists(t, &wanted).await?;
    let local_lists: Vec<ExceptionList> = mirror_lists
        .into_iter()
        .filter(|l| l.key().map(|k| wanted.contains(&k)).unwrap_or(false))
        .collect();

    let (drift, ops) = list_drift(&local_lists, &remote_lists)?;

    let mut resolvable: BTreeSet<ListKey> =
        remote_lists.iter().filter_map(|l| l.key().ok()).collect();
    for op in &ops {
        if let ListOp::Create(list) = op {
            resolvable.insert(list.key()?);
        }
    }

    // Items are created only for a newly created container in Task 11; item
    // reconciliation inside existing containers is Task 12.
    let items_by_key = group_items(mirror_items);
    let mut item_creates = Vec::new();
    for op in &ops {
        match op {
            ListOp::Create(list) => {
                let key = list.key()?;
                if let Some(items) = items_by_key.get(&key) {
                    item_creates.extend(items.iter().cloned());
                }
            }
            ListOp::Update(_) => {}
        }
    }

    Ok((drift, ops, item_creates, resolvable))
}

fn group_items(items: Vec<ExceptionItem>) -> BTreeMap<ListKey, Vec<ExceptionItem>> {
    let mut map: BTreeMap<ListKey, Vec<ExceptionItem>> = BTreeMap::new();
    for item in items {
        let Ok(list_id) = item.list_id() else {
            continue;
        };
        let key = ListKey {
            list_id: list_id.to_string(),
            namespace_type: item.namespace_type().to_string(),
        };
        map.entry(key).or_default().push(item);
    }
    for grouped in map.values_mut() {
        normalize::sort_items(grouped);
    }
    map
}
