//! Typed wrappers for the exception-list API.
//!
//! Functions use the stable `list_id` plus `namespace_type` identity, never the
//! volatile saved-object `id` (spec 4.5). The one exception is `export_lists`,
//! which fetches `id` at the single boundary where the route demands it.

use crate::model::{ExceptionItem, ExceptionList, ListKey};
use crate::normalize;
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

impl ListFilter {
    /// The KQL `filter` for this selection, or `None` when nothing filters.
    ///
    /// The list `_find` route filters over `exception-list.attributes.*` — the
    /// saved-object type name, not the rules vertical's `alert.attributes.*`
    /// (measured, spec 7.7). Values are quoted and escaped like `rules::to_kql`.
    pub fn to_kql(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        if let Some(ty) = &self.list_type {
            parts.push(format!(
                "exception-list.attributes.type: \"{}\"",
                kql_escape(ty)
            ));
        }
        if let Some(tag) = &self.tag {
            parts.push(format!(
                "exception-list.attributes.tags: \"{}\"",
                kql_escape(tag)
            ));
        }
        (!parts.is_empty()).then(|| parts.join(" AND "))
    }
}

/// Escape a value for use inside a double-quoted KQL literal. Backslashes are
/// escaped first so an inserted quote escape is not doubled.
fn kql_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
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
    let kql = f.to_kql();
    let values = find_paged(t, |page| {
        let mut path = format!("{BASE}/_find?page={page}&per_page={RESULT_WINDOW}");
        if let Some(ns) = &f.namespace {
            path.push_str(&format!("&namespace_type={}", urlencode(ns)));
        }
        // An empty filter is a 400 (measured, spec 7.7), so it is omitted,
        // never sent as `filter=`.
        if let Some(k) = &kql {
            path.push_str(&format!("&filter={}", urlencode(k)));
        }
        path
    })
    .await?;

    values.into_iter().map(ExceptionList::from_value).collect()
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

pub async fn create_list(t: &Transport, l: &ExceptionList) -> Result<ExceptionList> {
    let payload = normalize::canonical_list(l);
    let response = t.post(BASE, Some(&payload.into_value())).await?;
    ExceptionList::from_value(response)
}

pub async fn update_list(t: &Transport, l: &ExceptionList) -> Result<ExceptionList> {
    let payload = normalize::canonical_list(l);
    let response = t.put(BASE, &payload.into_value()).await?;
    ExceptionList::from_value(response)
}

pub async fn delete_list(t: &Transport, key: &ListKey) -> Result<ExceptionList> {
    let body = t
        .delete(&format!(
            "{BASE}?list_id={}&namespace_type={}",
            urlencode(&key.list_id),
            urlencode(&key.namespace_type),
        ))
        .await?;
    ExceptionList::from_value(body)
}

pub async fn create_item(t: &Transport, i: &ExceptionItem) -> Result<ExceptionItem> {
    let payload = normalize::canonical_item(i);
    let response = t.post(ITEMS, Some(&payload.into_value())).await?;
    ExceptionItem::from_value(response)
}

pub async fn update_item(t: &Transport, i: &ExceptionItem) -> Result<ExceptionItem> {
    let payload = normalize::canonical_item(i);
    let response = t.put(ITEMS, &payload.into_value()).await?;
    ExceptionItem::from_value(response)
}

pub async fn delete_item(t: &Transport, item_id: &str, namespace: &str) -> Result<ExceptionItem> {
    let body = t
        .delete(&format!(
            "{ITEMS}?item_id={}&namespace_type={}",
            urlencode(item_id),
            urlencode(namespace),
        ))
        .await?;
    ExceptionItem::from_value(body)
}

/// Export the given containers and their items as NDJSON.
///
/// The export route is the one path that refuses `list_id` alone (measured,
/// fact E), so each key is resolved to its live container `id` first. Identity
/// stays `list_id` plus `namespace_type` everywhere; the `id` is fetched only
/// here, at the boundary that demands it. A key with no live container is
/// refused rather than skipped: a silently dropped key is a short export
/// reported as a success.
pub async fn export_lists(t: &Transport, keys: &[ListKey]) -> Result<String> {
    let ids = resolve_ids(t, keys).await?;

    // Name every missing key at once, the way the mirror names every colliding
    // filename pair: one refusal per run beats a re-run per missing key.
    let missing: Vec<String> = keys
        .iter()
        .filter(|k| !ids.contains_key(*k))
        .map(|k| format!("{} ({})", k.list_id, k.namespace_type))
        .collect();
    if !missing.is_empty() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("exception list not found: {}", missing.join(", ")),
        ));
    }

    let mut out = String::new();
    for key in keys {
        let id = ids.get(key).expect("every key resolved before export");
        let path = format!(
            "{BASE}/_export?id={}&list_id={}&namespace_type={}&include_expired_exceptions=true",
            urlencode(id),
            urlencode(&key.list_id),
            urlencode(&key.namespace_type),
        );
        let body = t.post_text(&path, None).await?;
        out.push_str(&body);
        if !body.ends_with('\n') {
            out.push('\n');
        }
    }
    Ok(out)
}

pub async fn import_lists(t: &Transport, ndjson: &str, overwrite: bool) -> Result<Value> {
    t.post_multipart_ndjson(&format!("{BASE}/_import?overwrite={overwrite}"), ndjson)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_kql_is_none_when_nothing_filters() {
        assert_eq!(ListFilter::default().to_kql(), None);
    }

    #[test]
    fn to_kql_filters_type_over_the_measured_prefix() {
        let f = ListFilter {
            list_type: Some("detection".into()),
            ..Default::default()
        };
        assert_eq!(
            f.to_kql().unwrap(),
            "exception-list.attributes.type: \"detection\""
        );
    }

    #[test]
    fn to_kql_filters_tags_over_the_measured_prefix() {
        let f = ListFilter {
            tag: Some("alpha".into()),
            ..Default::default()
        };
        assert_eq!(
            f.to_kql().unwrap(),
            "exception-list.attributes.tags: \"alpha\""
        );
    }

    #[test]
    fn to_kql_combines_clauses_with_and() {
        let f = ListFilter {
            list_type: Some("detection".into()),
            tag: Some("alpha".into()),
            ..Default::default()
        };
        assert_eq!(
            f.to_kql().unwrap(),
            "exception-list.attributes.type: \"detection\" AND \
             exception-list.attributes.tags: \"alpha\""
        );
    }

    #[test]
    fn to_kql_escapes_a_quote_in_the_value() {
        let f = ListFilter {
            tag: Some("a\"b".into()),
            ..Default::default()
        };
        let kql = f.to_kql().unwrap();
        assert!(kql.contains("a\\\"b"), "{kql}");
    }
}
