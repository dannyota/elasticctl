use crate::exceptions;
use crate::model::{ExceptionItem, ListKey, Rule};
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn inject_list_ids(rule: &mut Rule, live: &BTreeMap<ListKey, String>) -> Result<()> {
    let Some(Value::Array(refs)) = rule.as_map_mut().get_mut("exceptions_list") else {
        return Ok(());
    };
    for reference in refs.iter_mut() {
        let Value::Object(map) = reference else {
            continue;
        };
        let Some(list_id) = map.get("list_id").and_then(Value::as_str) else {
            continue;
        };
        let namespace = map
            .get("namespace_type")
            .and_then(Value::as_str)
            .unwrap_or("single");
        let key = ListKey {
            list_id: list_id.to_string(),
            namespace_type: namespace.to_string(),
        };
        match live.get(&key) {
            Some(id) => {
                map.insert("id".into(), json!(id));
            }
            None => {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!(
                        "rule references exception list \"{list_id}\" ({namespace}), whose live \
                         id could not be resolved on this stack"
                    ),
                ));
            }
        }
    }
    Ok(())
}
pub(super) fn value_list_refs(
    items: &[ExceptionItem],
    active_list_keys: &BTreeSet<ListKey>,
) -> BTreeSet<exceptions::ValueListRef> {
    let mut ids = BTreeSet::new();
    for item in items {
        let Ok(list_id) = item.list_id() else {
            continue;
        };
        let key = ListKey {
            list_id: list_id.to_string(),
            namespace_type: item.namespace_type().to_string(),
        };
        if !active_list_keys.contains(&key) {
            continue;
        }
        let Some(entries) = item.as_map().get("entries").and_then(Value::as_array) else {
            continue;
        };
        for entry in entries {
            let Some(obj) = entry.as_object() else {
                continue;
            };
            if obj.get("type").and_then(Value::as_str) != Some("list") {
                continue;
            }
            if let Some(id) = obj
                .get("list")
                .and_then(Value::as_object)
                .and_then(|l| l.get("id"))
                .and_then(Value::as_str)
            {
                ids.insert(exceptions::ValueListRef { id: id.to_string() });
            }
        }
    }
    ids
}
