use crate::model::{ListKey, Rule};
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Value, json};
use std::collections::BTreeMap;

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
