//! `state diff`, and the exception-list drift it shares with push.
//!
//! `diff` reports the plan `exception_plan` computes; `push` applies it. The
//! plan is one concern with two consumers, which is why it lives here rather
//! than in either command.

use super::reports::{DanglingPointer, DiffReport, ExceptionDrift, ListChange, Mirror};
use crate::diff::{Change, Drift, FieldChange};
use crate::exceptions;
use crate::model::{ExceptionItem, ExceptionList, ListKey, Rule, exception_refs};
use crate::normalize;
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// A container write `push` will perform, in apply order.
#[derive(Debug, Clone)]
pub(crate) enum ListOp {
    Create(ExceptionList),
    Update(ExceptionList),
}

/// An item write `push` will perform, in apply order.
///
/// `Remove` is the only deletion the state engine performs anywhere. It is
/// sound only because `pull` always writes a container's full item set: the
/// invariant is documented on `item_reconciliation` and at `pull.rs`'s
/// fetch-site cross-reference (spec 5.4). An item absent locally is a delete
/// instruction solely because no item-level selector exists.
#[derive(Debug, Clone)]
pub(crate) enum ItemOp {
    Create(ExceptionItem),
    Update(ExceptionItem),
    Remove {
        list_id: String,
        item_id: String,
        namespace_type: String,
    },
}

/// What `exception_plan` computed: the drift to report and the ordered writes
/// `push` applies.
#[derive(Debug)]
pub(crate) struct ExceptionPlan {
    pub drift: ExceptionDrift,
    pub list_ops: Vec<ListOp>,
    pub item_ops: Vec<ItemOp>,
    /// Keys resolvable at apply time: already on the stack or about to be
    /// created. `plan_push` refuses any other referenced key before a write.
    pub resolvable: BTreeSet<ListKey>,
}

/// Compare the mirror to the stack, defaulting to `--source custom` (spec 5.5).
pub async fn diff(
    t: &Transport,
    dir: &Path,
    selectors: &[String],
    tag: Option<&str>,
) -> Result<DiffReport> {
    diff_with_source(t, dir, selectors, tag, crate::rules::RuleSource::Custom).await
}

/// `diff` with an explicit `--source` scope.
pub async fn diff_with_source(
    t: &Transport,
    dir: &Path,
    selectors: &[String],
    tag: Option<&str>,
    source: crate::rules::RuleSource,
) -> Result<DiffReport> {
    let Mirror {
        rules: local_all,
        lists,
        items,
    } = super::mirror::read_mirror(dir)?;
    let scope = super::scope_of(t, selectors, tag, source, &local_all, "compare").await?;
    // A selector narrows both sides; with none, the `--source` scope decides.
    // A local file outside that scope is reported as `out_of_scope`, never as a
    // pending create (spec 5.5, the 0.1 upgrade guard).
    let (local, out_of_scope) = if scope.is_scoped() {
        (scope.narrow(local_all), 0)
    } else {
        scope.split_by_source(local_all)
    };
    let remote = scope.remote(t).await?;
    let drift = Drift::compute(&local, &remote)?;

    let plan = exception_plan(t, lists, items, &local, &remote).await?;

    // Omit unchanged rules so the diff shows only differences.
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

/// Field-level differences between two object maps, in key order.
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

/// Field-level drift between two canonical containers.
fn list_field_changes(before: &ExceptionList, after: &ExceptionList) -> Vec<FieldChange> {
    map_field_changes(before.as_map(), after.as_map())
}

/// Index containers by identity, canonicalizing each and refusing a duplicate
/// `list_id` within one side.
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

/// Container drift and the ordered container writes. Item drift is computed
/// separately, because items reconcile only for containers present on both
/// sides.
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
/// container (a dangling pointer `diff` reports in spec 4.5).
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

/// Spec 4.5. Compare each remote rule's stored pointer against the live
/// container for its `list_id`. `comparable` has stripped this field by the
/// time `Drift::compute` runs, so the check works on the raw response.
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

/// Compare local and remote items for each container in `both`, emitting
/// `ItemAdded`, `ItemModified`, `ItemRemoved`, or nothing per `item_id`.
/// `ItemRemoved` is the engine's only actionable deletion (spec 5.4).
///
/// `ItemRemoved` assumes the local item set for a mirrored container is
/// complete. That holds because `pull` always writes a container's items in
/// full: state commands resolve selectors to `rule_id`s through `scope_of`,
/// which narrows rules and nothing else, and there is no parameter by which a
/// caller can mirror part of a container's items. If an item-level selector is
/// ever added, an item absent locally stops being a delete instruction and the
/// `ItemRemoved` handling below must be revisited before that selector ships.
fn item_reconciliation(
    both: &BTreeSet<ListKey>,
    local_items: &BTreeMap<ListKey, Vec<ExceptionItem>>,
    remote_items: &BTreeMap<ListKey, Vec<ExceptionItem>>,
) -> Result<(Vec<ListChange>, Vec<ItemOp>)> {
    // A duplicate `item_id` within one side is mirror corruption; refusing
    // matches `index_lists`, which refuses a duplicate `list_id`. First-wins
    // would silently hide which item the operator intended to keep.
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
                (None, Some(_)) => {
                    changes.push(ListChange::ItemRemoved {
                        list_id: key.list_id.clone(),
                        item_id: item_id.clone(),
                    });
                    ops.push(ItemOp::Remove {
                        list_id: key.list_id.clone(),
                        item_id: item_id.clone(),
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
                        ops.push(ItemOp::Update(l.clone()));
                    }
                }
                (None, None) => unreachable!("an item id came from one of the two maps"),
            }
        }
    }

    Ok((changes, ops))
}

/// Compute exception drift and the ordered container/item writes, closing over
/// the lists referenced by the local and remote rules in scope.
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

    // Live container ids, read from the raw fetched containers before
    // `canonical_list` strips `id`. `dangling_pointers` compares the stored
    // pointer against this.
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

    // Only a container present on both sides reconciles its items. A created
    // container writes its items wholesale; a remote-only container is never
    // deleted, so its items are not touched.
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

    let local_items = group_items(mirror_items);
    let mut remote_items: BTreeMap<ListKey, Vec<ExceptionItem>> = BTreeMap::new();
    for key in &both {
        remote_items.insert(key.clone(), exceptions::find_items(t, key).await?);
    }

    let mut item_ops = Vec::new();
    // Items for a newly created container are written wholesale.
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
