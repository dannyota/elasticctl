//! Typed wrappers for the exception-list API.
//!
//! Functions use the stable `list_id` plus `namespace_type` identity, never the
//! volatile saved-object `id` (spec 4.5). The one exception is `export_lists`,
//! which fetches `id` at the single boundary where the route demands it.

use crate::model::{ExceptionItem, ExceptionList, ListKey};
use elasticctl_core::{Error, ErrorKind, Result, Transport, urlencode};
use serde_json::Value;
use std::collections::BTreeMap;

const BASE: &str = "/api/exception_lists";
const ITEMS: &str = "/api/exception_lists/items";

/// Elasticsearch's `_find` result window, shared with rules: `from + size` must
/// not exceed 10,000. A server that caps `per_page` lower simply returns fewer
/// objects with a larger `total`, which the paging loop handles.
const RESULT_WINDOW: u32 = 10_000;

#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    pub list_type: Option<String>,
    pub tag: Option<String>,
    pub namespace: Option<String>,
}

/// Decode the shared `{data, page, per_page, total}` envelope.
fn decode_find(body: &Value) -> (Vec<Value>, u64) {
    let total = body["total"].as_u64().unwrap_or(0);
    let data = body["data"].as_array().cloned().unwrap_or_default();
    (data, total)
}

/// Read every object a `_find` route serves, paging until `total` is reached.
///
/// Refuses a page that returns nothing while `total` is still ahead: a short
/// read is indistinguishable from objects deleted between pages, and a mirror
/// built on it would silently drop them.
async fn find_paged(t: &Transport, path_for: impl Fn(u32) -> String) -> Result<Vec<Value>> {
    let mut out: Vec<Value> = Vec::new();
    let mut page = 1u32;
    loop {
        let body = t.get(&path_for(page)).await?;
        let (data, total) = decode_find(&body);
        let before = out.len();
        out.extend(data);
        if (out.len() as u64) >= total {
            return Ok(out);
        }
        if out.len() == before {
            return Err(short_read(total, out.len()));
        }
        page += 1;
    }
}

fn short_read(counted: u64, returned: usize) -> Error {
    Error::new(
        ErrorKind::Http,
        format!(
            "the server counted {counted} objects and returned {returned}. Refusing a partial \
             read: a short read is indistinguishable from objects having been deleted."
        ),
    )
}

pub async fn find_lists(t: &Transport, f: &ListFilter) -> Result<Vec<ExceptionList>> {
    let values = find_paged(t, |page| {
        let mut path = format!("{BASE}/_find?page={page}&per_page={RESULT_WINDOW}");
        if let Some(ns) = &f.namespace {
            path.push_str(&format!("&namespace_type={}", urlencode(ns)));
        }
        path
    })
    .await?;

    let lists = values
        .into_iter()
        .map(ExceptionList::from_value)
        .collect::<Result<Vec<_>>>()?;
    Ok(filter_lists(lists, f))
}

/// `type` and `tag` are filtered client-side. The list `_find` route's only
/// measured query filter is `namespace_type`; the KQL field names a server-side
/// filter for these two would need are not in the measured tables, so inventing
/// them here would be guessing. Both are fields on the returned object.
fn filter_lists(mut lists: Vec<ExceptionList>, f: &ListFilter) -> Vec<ExceptionList> {
    if let Some(ty) = &f.list_type {
        lists.retain(|l| l.list_type() == ty.as_str());
    }
    if let Some(tag) = &f.tag {
        lists.retain(|l| l.tags().contains(&tag.as_str()));
    }
    lists
}

pub async fn get_list(t: &Transport, key: &ListKey) -> Result<ExceptionList> {
    let body = t
        .get(&format!(
            "{BASE}?list_id={}&namespace_type={}",
            urlencode(&key.list_id),
            urlencode(&key.namespace_type),
        ))
        .await?;
    ExceptionList::from_value(body)
}

pub async fn find_items(t: &Transport, key: &ListKey) -> Result<Vec<ExceptionItem>> {
    let values = find_paged(t, |page| {
        format!(
            "{ITEMS}/_find?list_id={}&namespace_type={}&page={page}&per_page={RESULT_WINDOW}",
            urlencode(&key.list_id),
            urlencode(&key.namespace_type),
        )
    })
    .await?;

    values.into_iter().map(ExceptionItem::from_value).collect()
}

/// Map each key to the live container `id` on this stack. A key with no live
/// container is absent from the map rather than mapped to a placeholder, so
/// callers distinguish "exists here with this id" from "does not exist here".
pub async fn resolve_ids(t: &Transport, keys: &[ListKey]) -> Result<BTreeMap<ListKey, String>> {
    let mut map = BTreeMap::new();
    for key in keys {
        match get_list(t, key).await {
            Ok(list) => {
                if let Some(id) = list.as_map().get("id").and_then(Value::as_str) {
                    map.insert(key.clone(), id.to_string());
                }
            }
            Err(e) if e.kind == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn list(id: &str, list_type: &str, tags: &[&str]) -> ExceptionList {
        ExceptionList::from_value(json!({
            "list_id": id, "type": list_type, "tags": tags, "name": "L"
        }))
        .unwrap()
    }

    #[test]
    fn filter_lists_matches_type_exactly() {
        let lists = vec![list("a", "detection", &[]), list("b", "endpoint", &[])];
        let f = ListFilter {
            list_type: Some("detection".into()),
            ..Default::default()
        };
        let out = filter_lists(lists, &f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].list_id().unwrap(), "a");
    }

    #[test]
    fn filter_lists_matches_a_tag_anywhere_in_the_list() {
        let lists = vec![
            list("a", "detection", &["prod", "x"]),
            list("b", "detection", &["dev"]),
        ];
        let f = ListFilter {
            tag: Some("prod".into()),
            ..Default::default()
        };
        let out = filter_lists(lists, &f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].list_id().unwrap(), "a");
    }
}
