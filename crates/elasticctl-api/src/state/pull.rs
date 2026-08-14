//! `state pull`: write the scoped rules and the exception lists they reference.

use super::reports::PullReport;
use crate::codec::Format;
use crate::exceptions;
use crate::model::{ExceptionItem, ExceptionList, ListKey, Rule};
use crate::normalize;
use crate::state::mirror::{encode_list_file, encode_rule_file};
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
) -> Result<PullReport> {
    // Pull reads from the stack, so selectors name stack rules. The directory
    // may not exist yet.
    let scope = super::scope_of(t, selectors, tag, &[], "pull").await?;
    let mut remote = scope.remote(t).await?;
    // Sort unstable server output so collision reports and writes are stable.
    normalize::sort_rules(&mut remote);

    // Spec 5.4: the mirror closes over the lists the scoped rules reference. A
    // rule_default list belongs to one rule and is inlined in its file.
    let wanted: BTreeSet<ListKey> = super::referenced_keys(&remote);
    let mut fetched: BTreeMap<ListKey, (ExceptionList, Vec<ExceptionItem>)> = BTreeMap::new();
    for key in &wanted {
        let list = match exceptions::get_list(t, key).await {
            Ok(list) => list,
            // Refuse rather than silently write a mirror missing a referenced
            // list: that truncation would only surface as a `not_found` at
            // apply time (spec 5.2).
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

    let ext = match format {
        Format::Yaml => "yaml",
        Format::Ndjson => "ndjson",
    };

    // Canonicalize every fetched container, embed its items, then split it by
    // whether it gets its own file or is inlined into its owning rule.
    let mut lists_to_write: Vec<(ListKey, ExceptionList)> = Vec::new();
    let mut inlines: Vec<(ListKey, ExceptionList)> = Vec::new();
    let mut item_count = 0usize;
    for (key, (list, items)) in &fetched {
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

    // Attach each inline list to its owning rule by the (list_id, namespace)
    // reference the rule carries. A list whose rule is out of scope is dropped.
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

    // Plan every filename before writing. Failing after a write would leave a
    // partial mirror and hide later collisions.
    let mut claimed_rules: BTreeMap<String, String> = BTreeMap::new();
    let mut planned_rules: Vec<(String, Rule)> = Vec::with_capacity(remote.len());
    let mut collisions: Vec<String> = Vec::new();

    for rule in &remote {
        let canonical = normalize::canonical(rule);
        let rule_id = canonical.rule_id()?.to_string();
        let filename = super::safe_filename(&rule_id, ext);

        match claimed_rules.get(&filename) {
            Some(other) => collisions.push(format!(
                "\"{other}\" and \"{rule_id}\" both sanitise to \"{filename}\""
            )),
            None => {
                claimed_rules.insert(filename.clone(), rule_id);
                planned_rules.push((filename, canonical));
            }
        }
    }

    let mut claimed_lists: BTreeMap<String, String> = BTreeMap::new();
    for (key, _) in &lists_to_write {
        let qualified = format!("{} ({})", key.list_id, key.namespace_type);
        let filename = super::safe_filename(&key.list_id, ext);
        match claimed_lists.get(&filename) {
            Some(other) => collisions.push(format!(
                "\"{other}\" and \"{qualified}\" both sanitise to \"{filename}\""
            )),
            None => {
                claimed_lists.insert(filename.clone(), qualified);
            }
        }
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

    let target = super::rules_dir(dir);
    std::fs::create_dir_all(&target).map_err(|e| {
        Error::new(
            ErrorKind::Error,
            format!("creating {}: {e}", target.display()),
        )
    })?;

    for (filename, canonical) in &planned_rules {
        let rule_id = canonical.rule_id()?;
        let inline = inline_by_rule.get(rule_id).cloned().unwrap_or_default();
        let body = encode_rule_file(canonical, &inline, format)?;
        let path = target.join(filename);
        std::fs::write(&path, body).map_err(|e| {
            Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
        })?;
    }

    if !lists_to_write.is_empty() {
        let lists_target = super::exceptions_dir(dir);
        std::fs::create_dir_all(&lists_target).map_err(|e| {
            Error::new(
                ErrorKind::Error,
                format!("creating {}: {e}", lists_target.display()),
            )
        })?;
        for (key, list) in &lists_to_write {
            let filename = super::safe_filename(&key.list_id, ext);
            let body = encode_list_file(list, format)?;
            let path = lists_target.join(filename);
            std::fs::write(&path, body).map_err(|e| {
                Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
            })?;
        }
    }

    Ok(PullReport {
        pulled: planned_rules.len(),
        exception_lists: fetched.len(),
        exception_items: item_count,
        dir: target.display().to_string(),
        selected: scope.is_scoped().then(|| scope.selected()),
    })
}
