use super::reports::PullReport;
use crate::codec::Format;
use crate::exceptions;
use crate::model::{ExceptionItem, ExceptionList, ListKey, Rule};
use crate::normalize;
use crate::rules::RuleSource;
use crate::state::mirror::{encode_list_file, encode_rule_file};
use crate::state::transaction::{
    PullLock, StagedFile, acquire_pull, recover_pull, replace_staged_files,
};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub async fn pull(
    t: &Transport,
    dir: &Path,
    format: Format,
    selectors: &[String],
    tag: Option<&str>,
    search: Option<&str>,
    source: RuleSource,
) -> Result<PullReport> {
    let lock = acquire_pull(dir)?;
    recover_pull(&lock)?;

    let scope = super::scope_of(t, selectors, tag, search, source, &[], "pull").await?;
    let mut remote = scope.remote(t).await?;
    if remote.is_empty()
        && !scope.is_scoped()
        && matches!(scope.source, RuleSource::Custom | RuleSource::Prebuilt)
    {
        crate::rules::verify_source_partition(t).await?;
    }
    normalize::sort_rules(&mut remote);

    let wanted: BTreeSet<ListKey> = super::referenced_keys(&remote);
    let mut fetched: BTreeMap<ListKey, (ExceptionList, Vec<ExceptionItem>)> = BTreeMap::new();
    for key in &wanted {
        let list = match exceptions::get_list(t, key).await {
            Ok(list) => list,
            Err(e) if e.kind == ErrorKind::NotFound => {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!(
                        "a rule references exception list \"{}\" ({}), which does not exist on \
                         this stack",
                        key.list_id, key.namespace_type
                    ),
                ));
            }
            Err(e) => return Err(e),
        };
        let items = exceptions::find_items(t, key).await?;
        fetched.insert(key.clone(), (list, items));
    }

    let all_items: Vec<_> = fetched
        .values()
        .flat_map(|(_, items)| items.iter().cloned())
        .collect();
    let (value_lists, value_list_warnings) = super::values::pull_lists(t, &all_items).await?;

    let (pulled, item_count) = write_mirror(&lock, &remote, &fetched, &value_lists, format)?;

    let target = super::rules_dir(dir);

    Ok(PullReport {
        pulled,
        exception_lists: fetched.len(),
        exception_items: item_count,
        value_lists: value_lists.len(),
        value_list_warnings,
        dir: target.display().to_string(),
        selected: scope.is_scoped().then(|| scope.selected()),
    })
}

fn write_mirror(
    lock: &PullLock,
    remote: &[Rule],
    fetched: &BTreeMap<ListKey, (ExceptionList, Vec<ExceptionItem>)>,
    value_lists: &[crate::value_lists::LocalPair],
    format: Format,
) -> Result<(usize, usize)> {
    let ext = match format {
        Format::Yaml => "yaml",
        Format::Ndjson => "ndjson",
    };

    let mut lists_to_write: Vec<(ListKey, ExceptionList)> = Vec::new();
    let mut inlines: Vec<(ListKey, ExceptionList)> = Vec::new();
    let mut item_count = 0usize;
    for (key, (list, items)) in fetched {
        let mut canonical = normalize::canonical_list(list);
        let canonical_items: Vec<ExceptionItem> =
            items.iter().map(normalize::canonical_item).collect();
        item_count += canonical_items.len();
        let items_value = Value::Array(
            canonical_items
                .iter()
                .map(|i| i.clone().into_value())
                .collect(),
        );
        canonical.as_map_mut().insert("items".into(), items_value);
        if list.list_type() == "rule_default" {
            inlines.push((key.clone(), canonical));
        } else {
            lists_to_write.push((key.clone(), canonical));
        }
    }

    let mut inline_by_rule: BTreeMap<String, Vec<ExceptionList>> = BTreeMap::new();
    for (key, list) in &inlines {
        let owner = remote.iter().find_map(|rule| {
            let matches = crate::model::exception_refs(rule)
                .iter()
                .any(|rf| rf.list_id == key.list_id && rf.namespace_type == key.namespace_type);
            matches
                .then(|| rule.rule_id().ok())
                .flatten()
                .map(str::to_string)
        });
        if let Some(rule_id) = owner {
            inline_by_rule
                .entry(rule_id)
                .or_default()
                .push(list.clone());
        }
    }

    let mut claimed_rules: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut planned_rules: Vec<(String, Rule)> = Vec::with_capacity(remote.len());
    let mut collisions: Vec<String> = crate::value_lists::stem_collisions(
        value_lists
            .iter()
            .map(|pair| (pair.container.id.as_str(), pair.stem.as_str())),
    )
    .into_iter()
    .map(|(a, b)| {
        format!(
            "value lists {a:?} and {b:?} both use stem {:?}",
            crate::value_lists::file_stem(&a)
        )
    })
    .collect();

    for rule in remote {
        let canonical = normalize::canonical(rule);
        let rule_id = canonical.rule_id()?.to_string();
        let filename = super::safe_filename(&rule_id, ext);

        let previous = claimed_rules.entry(filename.clone()).or_default();
        for other in previous.iter() {
            collisions.push(format!(
                "\"{other}\" and \"{rule_id}\" both sanitise to \"{filename}\""
            ));
        }
        if previous.is_empty() {
            planned_rules.push((filename, canonical));
        }
        previous.push(rule_id);
    }

    let mut claimed_lists: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, _) in &lists_to_write {
        let qualified = format!("{} ({})", key.list_id, key.namespace_type);
        let filename = super::safe_filename(&key.list_id, ext);
        let previous = claimed_lists.entry(filename.clone()).or_default();
        for other in previous.iter() {
            collisions.push(format!(
                "\"{other}\" and \"{qualified}\" both sanitise to \"{filename}\""
            ));
        }
        previous.push(qualified);
    }

    if !collisions.is_empty() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "{} filename collision(s); rename one id in each pair: {}",
                collisions.len(),
                collisions.join("; ")
            ),
        ));
    }

    let mut staged = Vec::with_capacity(planned_rules.len() + lists_to_write.len());
    for (filename, canonical) in &planned_rules {
        let rule_id = canonical.rule_id()?;
        let inline = inline_by_rule.get(rule_id).cloned().unwrap_or_default();
        let body = encode_rule_file(canonical, &inline, format)?;
        staged.push(StagedFile {
            relative: Path::new("rules").join(filename),
            bytes: body.into_bytes(),
        });
    }

    for (key, list) in &lists_to_write {
        let filename = super::safe_filename(&key.list_id, ext);
        let body = encode_list_file(list, format)?;
        staged.push(StagedFile {
            relative: Path::new("exceptions").join(filename),
            bytes: body.into_bytes(),
        });
    }
    for pair in value_lists {
        staged.push(StagedFile {
            relative: Path::new("value-lists").join(format!("{}.yaml", pair.stem)),
            bytes: crate::value_lists::encode_container(&pair.container)?.into_bytes(),
        });
        staged.push(StagedFile {
            relative: Path::new("value-lists").join(format!("{}.txt", pair.stem)),
            bytes: crate::value_lists::encode_values(&pair.values).into_bytes(),
        });
    }
    replace_staged_files(lock, &staged)?;

    Ok((planned_rules.len(), item_count))
}

#[cfg(test)]
mod tests;
