use super::reports::{DanglingPointer, DiffReport, ExceptionDrift, ListChange, Mirror};
use crate::diff::{Change, Drift, FieldChange};
use crate::exceptions;
use crate::model::{ExceptionItem, ExceptionList, ListKey, Rule, exception_refs};
use crate::normalize;
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone)]
pub(crate) enum ListOp {
    Create(ExceptionList),
    Update {
        before: ExceptionList,
        after: ExceptionList,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum ItemOp {
    Create(ExceptionItem),
    Update {
        before: ExceptionItem,
        after: ExceptionItem,
    },
    Remove {
        before: ExceptionItem,
        namespace_type: String,
    },
}

#[derive(Debug)]
pub(crate) struct ExceptionPlan {
    pub drift: ExceptionDrift,
    pub list_ops: Vec<ListOp>,
    pub item_ops: Vec<ItemOp>,
    pub resolvable: BTreeSet<ListKey>,
}

pub async fn diff(
    t: &Transport,
    dir: &Path,
    selectors: &[String],
    tag: Option<&str>,
    search: Option<&str>,
    source: crate::rules::RuleSource,
) -> Result<DiffReport> {
    let Mirror {
        rules: local_all,
        lists,
        items,
    } = super::mirror::read_mirror(dir)?;
    let scope = super::scope_of(t, selectors, tag, search, source, &local_all, "compare").await?;
    let (local, out_of_scope) = if scope.is_scoped() {
        (scope.narrow(local_all), 0)
    } else {
        scope.split_by_source(local_all)
    };
    let remote = scope.remote(t).await?;
    let drift = Drift::compute(&local, &remote)?;

    let plan = exception_plan(t, lists, items, &local, &remote).await?;

    let changes: Vec<Change> = drift
        .changes
        .iter()
        .filter(|c| !matches!(c, Change::Unchanged { .. }))
        .cloned()
        .collect();

    let exceptions = plan.drift;
    Ok(DiffReport {
        clean: drift.is_clean() && exceptions.is_clean(),
        local: local.len(),
        remote: remote.len(),
        changes,
        exceptions,
        out_of_scope,
        selected: scope.is_scoped().then(|| scope.selected()),
        local_total: scope.is_scoped().then_some(scope.local_total),
    })
}

fn map_field_changes(before: &Map<String, Value>, after: &Map<String, Value>) -> Vec<FieldChange> {
    let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter_map(|k| {
            let bv = before.get(k).cloned().unwrap_or(Value::Null);
            let av = after.get(k).cloned().unwrap_or(Value::Null);
            (bv != av).then(|| FieldChange {
                field: k.clone(),
                before: bv,
                after: av,
            })
        })
        .collect()
}

fn list_field_changes(before: &ExceptionList, after: &ExceptionList) -> Vec<FieldChange> {
    map_field_changes(before.as_map(), after.as_map())
}

fn index_lists(lists: &[ExceptionList], side: &str) -> Result<BTreeMap<ListKey, ExceptionList>> {
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
}

fn list_drift(
    local: &BTreeMap<ListKey, ExceptionList>,
    remote: &BTreeMap<ListKey, ExceptionList>,
) -> Result<(ExceptionDrift, Vec<ListOp>)> {
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
                    ops.push(ListOp::Update {
                        before: remote_list.clone(),
                        after: local_list.clone(),
                    });
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

fn dangling_pointers(
    raw_remote: &[Rule],
    live: &BTreeMap<ListKey, String>,
) -> Vec<DanglingPointer> {
    let mut out = Vec::new();
    for rule in raw_remote {
        let Ok(rule_id) = rule.rule_id() else {
            continue;
        };
        for r in exception_refs(rule) {
            let key = ListKey {
                list_id: r.list_id.clone(),
                namespace_type: r.namespace_type.clone(),
            };
            let live_id = live.get(&key).cloned();
            let stored = r.id.clone();
            if live_id.as_deref() != stored.as_deref() {
                out.push(DanglingPointer {
                    rule_id: rule_id.to_string(),
                    list_id: r.list_id,
                    stored_id: stored.map(Value::String).unwrap_or(Value::Null),
                    live_id,
                });
            }
        }
    }
    out
}

fn item_reconciliation(
    both: &BTreeSet<ListKey>,
    local_items: &BTreeMap<ListKey, Vec<ExceptionItem>>,
    remote_items: &BTreeMap<ListKey, Vec<ExceptionItem>>,
) -> Result<(Vec<ListChange>, Vec<ItemOp>)> {
    let index = |items: &[ExceptionItem], side: &str| -> Result<BTreeMap<String, ExceptionItem>> {
        let mut m = BTreeMap::new();
        for i in items {
            let Some(id) = i.item_id().ok() else { continue };
            if m.insert(id.to_string(), i.clone()).is_some() {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    format!("{side} has two exception items with item_id \"{id}\""),
                ));
            }
        }
        Ok(m)
    };

    let mut changes = Vec::new();
    let mut ops = Vec::new();

    for key in both {
        let local = local_items.get(key).cloned().unwrap_or_default();
        let remote = remote_items.get(key).cloned().unwrap_or_default();
        let local_by_id = index(&local, "local")?;
        let remote_by_id = index(&remote, "remote")?;

        let mut ids: Vec<&String> = local_by_id.keys().chain(remote_by_id.keys()).collect();
        ids.sort();
        ids.dedup();

        for item_id in ids {
            match (local_by_id.get(item_id), remote_by_id.get(item_id)) {
                (Some(l), None) => {
                    changes.push(ListChange::ItemAdded {
                        list_id: key.list_id.clone(),
                        item_id: item_id.clone(),
                    });
                    ops.push(ItemOp::Create(l.clone()));
                }
                (None, Some(remote_item)) => {
                    changes.push(ListChange::ItemRemoved {
                        list_id: key.list_id.clone(),
                        item_id: item_id.clone(),
                    });
                    ops.push(ItemOp::Remove {
                        before: normalize::canonical_item(remote_item),
                        namespace_type: key.namespace_type.clone(),
                    });
                }
                (Some(l), Some(r)) => {
                    let local_canon = normalize::canonical_item(l);
                    let remote_canon = normalize::canonical_item(r);
                    if local_canon != remote_canon {
                        let fields = map_field_changes(remote_canon.as_map(), local_canon.as_map());
                        changes.push(ListChange::ItemModified {
                            list_id: key.list_id.clone(),
                            item_id: item_id.clone(),
                            fields,
                        });
                        ops.push(ItemOp::Update {
                            before: remote_canon,
                            after: l.clone(),
                        });
                    }
                }
                (None, None) => unreachable!("an item id came from one of the two maps"),
            }
        }
    }

    Ok((changes, ops))
}

pub(crate) async fn exception_plan(
    t: &Transport,
    mirror_lists: Vec<ExceptionList>,
    mirror_items: Vec<ExceptionItem>,
    local_rules: &[Rule],
    remote_rules: &[Rule],
) -> Result<ExceptionPlan> {
    let wanted: BTreeSet<ListKey> = super::referenced_keys(local_rules)
        .into_iter()
        .chain(super::referenced_keys(remote_rules))
        .collect();

    let remote_lists = fetch_remote_lists(t, &wanted).await?;
    let local_lists: Vec<ExceptionList> = mirror_lists
        .into_iter()
        .filter(|l| l.key().map(|k| wanted.contains(&k)).unwrap_or(false))
        .collect();

    let mut live: BTreeMap<ListKey, String> = BTreeMap::new();
    for list in &remote_lists {
        if let Ok(key) = list.key()
            && let Some(id) = list.as_map().get("id").and_then(Value::as_str)
        {
            live.insert(key, id.to_string());
        }
    }

    let local_indexed = index_lists(&local_lists, "local")?;
    let remote_indexed = index_lists(&remote_lists, "remote")?;
    let (mut drift, ops) = list_drift(&local_indexed, &remote_indexed)?;

    let both: BTreeSet<ListKey> = local_indexed
        .keys()
        .filter(|k| remote_indexed.contains_key(*k))
        .cloned()
        .collect();

    let mut resolvable: BTreeSet<ListKey> =
        remote_lists.iter().filter_map(|l| l.key().ok()).collect();
    for op in &ops {
        if let ListOp::Create(list) = op {
            resolvable.insert(list.key()?);
        }
    }

    let local_items = group_items(mirror_items)?;
    let mut remote_items: BTreeMap<ListKey, Vec<ExceptionItem>> = BTreeMap::new();
    for key in &both {
        remote_items.insert(key.clone(), exceptions::find_items(t, key).await?);
    }

    let mut item_ops = Vec::new();
    for op in &ops {
        if let ListOp::Create(list) = op {
            let key = list.key()?;
            if let Some(items) = local_items.get(&key) {
                item_ops.extend(items.iter().map(|i| ItemOp::Create(i.clone())));
            }
        }
    }

    let (item_changes, reconciled) = item_reconciliation(&both, &local_items, &remote_items)?;
    item_ops.extend(reconciled);

    drift.dangling = dangling_pointers(remote_rules, &live);
    drift.changes.extend(item_changes);

    Ok(ExceptionPlan {
        drift,
        list_ops: ops,
        item_ops,
        resolvable,
    })
}

fn group_items(items: Vec<ExceptionItem>) -> Result<BTreeMap<ListKey, Vec<ExceptionItem>>> {
    let mut map: BTreeMap<ListKey, Vec<ExceptionItem>> = BTreeMap::new();
    for item in items {
        validate_grouped_item(&item)?;
        let key = ListKey {
            list_id: item.list_id()?.to_string(),
            namespace_type: item.namespace_type().to_string(),
        };
        map.entry(key).or_default().push(item);
    }
    for grouped in map.values_mut() {
        normalize::sort_items(grouped);
    }
    Ok(map)
}

fn validate_grouped_item(item: &ExceptionItem) -> Result<()> {
    let item_id = item.item_id()?;
    if item_id.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "exception item field item_id must be a non-empty string",
        ));
    }
    let list_id = item.list_id()?;
    if list_id.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "exception item field list_id must be a non-empty string",
        ));
    }
    match item.as_map().get("namespace_type") {
        None => Ok(()),
        Some(Value::String(value)) if !value.is_empty() => Ok(()),
        Some(_) => Err(Error::new(
            ErrorKind::Error,
            "exception item field namespace_type must be a non-empty string",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouping_rejects_an_item_without_a_list_id() {
        let item = ExceptionItem::from_value(serde_json::json!({
            "item_id": "orphan",
            "type": "simple",
            "entries": [],
        }))
        .unwrap();

        let error = group_items(vec![item]).unwrap_err();

        assert_eq!(error.kind, ErrorKind::Error);
        assert!(error.message.contains("list_id"), "{}", error.message);
    }
}
