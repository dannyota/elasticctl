use elasticctl_core::{Error, ErrorKind, Feature, Result, Transport, urlencode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    ValueListType,
    reads::{malformed, required_string},
};
use crate::{
    exceptions,
    model::{ExceptionItem, ListKey},
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceOperator {
    Included,
    Excluded,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InstalledReference {
    pub container: ListKey,
    pub item_id: String,
    pub field: String,
    pub operator: ReferenceOperator,
    pub list_id: String,
    pub list_type: ValueListType,
}

impl InstalledReference {
    pub fn name(&self) -> String {
        format!(
            "{} ({}) item {} field {} {:?}",
            self.container.list_id,
            self.container.namespace_type,
            self.item_id,
            self.field,
            self.operator
        )
    }
}

pub fn item_references(key: &ListKey, item: &ExceptionItem) -> Result<Vec<InstalledReference>> {
    let body = Value::Object(item.as_map().clone());
    if required_string(&body, "list_id")? != key.list_id
        || required_string(&body, "namespace_type")? != key.namespace_type
    {
        return Err(malformed(
            "exception item identity does not match its container",
        ));
    }
    let item_id = required_string(&body, "item_id")?;
    let entries = body
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(format!("exception item {item_id} has unreadable entries")))?;
    let mut references = Vec::new();
    for entry in entries {
        let kind = required_string(entry, "type")?;
        if kind != "list" {
            continue;
        }
        let operator = match required_string(entry, "operator")? {
            "included" => ReferenceOperator::Included,
            "excluded" => ReferenceOperator::Excluded,
            _ => {
                return Err(malformed(format!(
                    "exception item {item_id} has an unreadable list operator"
                )));
            }
        };
        let list = entry.get("list").ok_or_else(|| {
            malformed(format!(
                "exception item {item_id} has an unreadable list entry"
            ))
        })?;
        references.push(InstalledReference {
            container: key.clone(),
            item_id: item_id.into(),
            field: required_string(entry, "field")?.into(),
            operator,
            list_id: required_string(list, "id")?.into(),
            list_type: required_string(list, "type")?.to_owned().into(),
        });
    }
    Ok(references)
}

pub(super) fn sort_references(references: &mut [InstalledReference]) {
    references.sort_by_cached_key(|r| {
        (
            r.container.clone(),
            r.item_id.clone(),
            r.field.clone(),
            r.operator,
            r.list_id.clone(),
            r.list_type.to_string(),
        )
    });
}

pub async fn scan_references(t: &Transport) -> Result<Vec<InstalledReference>> {
    t.require_feature(Feature::ExceptionLists).await?;
    let mut references = Vec::new();
    for namespace in ["single", "agnostic"] {
        scan_namespace(t, namespace, &mut references).await?;
    }
    sort_references(&mut references);
    Ok(references)
}

pub(super) async fn scan_namespace(
    t: &Transport,
    namespace: &str,
    references: &mut Vec<InstalledReference>,
) -> Result<()> {
    let body = t
        .get(&format!(
            "/api/exception_lists/_find?page=1&per_page=10000&namespace_type={namespace}"
        ))
        .await?;
    let lists = decode_scan_page(&body)?;
    let mut seen = std::collections::BTreeSet::new();
    for list in lists {
        let key = ListKey {
            list_id: required_string(&list, "list_id")?.into(),
            namespace_type: required_string(&list, "namespace_type")?.into(),
        };
        if key.namespace_type != namespace || !seen.insert(key.clone()) {
            return Err(malformed(
                "invalid or duplicated exception container in reference scan",
            ));
        }
        let read = exceptions::get_list(t, &key).await?;
        if read.key()? != key {
            return Err(malformed(
                "exception container changed identity during reference scan",
            ));
        }
        let body = t.get(&format!("/api/exception_lists/items/_find?list_id={}&namespace_type={}&page=1&per_page=10000", urlencode(&key.list_id), urlencode(&key.namespace_type))).await?;
        let items = decode_scan_page(&body)?;
        let mut seen_items = std::collections::BTreeSet::new();
        for item in items {
            let item = ExceptionItem::from_value(item)?;
            if !seen_items.insert(item.item_id()?.to_owned()) {
                return Err(malformed("duplicate exception item in reference scan"));
            }
            references.extend(item_references(&key, &item)?);
        }
    }
    Ok(())
}

pub(super) fn decode_scan_page(body: &Value) -> Result<Vec<Value>> {
    let total = body
        .get("total")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("invalid reference scan total"))?;
    if total > 10_000 {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "reference scan exceeds the 10,000-object read window",
        ));
    }
    let data = body
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("invalid reference scan data"))?;
    let per_page = body
        .get("per_page")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("invalid reference scan page size"))?;
    if body.get("page").and_then(Value::as_u64) != Some(1)
        || per_page == 0
        || per_page > 10_000
        || total > per_page
        || data.len() as u64 != total
    {
        return Err(malformed(
            "refusing incomplete or inconsistent reference scan page",
        ));
    }
    Ok(data.clone())
}
