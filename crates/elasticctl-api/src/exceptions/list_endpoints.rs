//! Exception list and item endpoints, pagination, and export.

use crate::model::{ExceptionItem, ExceptionList, ListKey};
use crate::normalize;
use crate::ops::ExportOutcome;
use crate::rules::{kql_escape, kql_escape_wildcard};
use elasticctl_core::{Error, ErrorKind, Feature, Result, Transport, urlencode};
use serde::Deserialize;
use serde_json::{Value, json};
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
    /// Friendly name-substring search (spec 4.7).
    pub search: Option<String>,
}

impl ListFilter {
    /// The KQL `filter` for this selection, or `None` when nothing filters.
    ///
    /// The list `_find` route filters over the namespace's saved-object type,
    /// not the rules vertical's `alert.attributes.*` (measured, spec 7.7).
    /// Values are quoted and escaped like `rules::to_kql`.
    pub fn to_kql(&self) -> Option<String> {
        let object_type = match self.namespace.as_deref() {
            Some("agnostic") => "exception-list-agnostic",
            _ => "exception-list",
        };
        let mut parts: Vec<String> = Vec::new();
        if let Some(ty) = &self.list_type {
            parts.push(format!(
                "{object_type}.attributes.type: \"{}\"",
                kql_escape(ty)
            ));
        }
        if let Some(tag) = &self.tag {
            parts.push(format!(
                "{object_type}.attributes.tags: \"{}\"",
                kql_escape(tag)
            ));
        }
        if let Some(search) = &self.search {
            parts.push(format!(
                "{object_type}.attributes.name: \"*{}*\"",
                kql_escape_wildcard(search)
            ));
        }
        (!parts.is_empty()).then(|| parts.join(" AND "))
    }
}

/// Decode the shared `{data, page, per_page, total}` envelope.
fn decode_find(body: &Value) -> Result<(Vec<Value>, u64)> {
    let object = body.as_object().ok_or_else(|| {
        Error::new(
            ErrorKind::Http,
            "invalid exception _find response: expected an object",
        )
    })?;
    let data = object
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| find_field_error("data", "an array"))?;
    let page = required_positive_find_number(object, "page")?;
    let per_page = required_positive_find_number(object, "per_page")?;
    let total = object
        .get("total")
        .and_then(Value::as_u64)
        .ok_or_else(|| find_field_error("total", "a non-negative integer"))?;

    let returned = data.len() as u64;
    if returned > per_page {
        return Err(Error::new(
            ErrorKind::Http,
            format!(
                "invalid exception _find response: page {page} returned {returned} objects, \
                 exceeding per_page {per_page}"
            ),
        ));
    }
    if returned > total {
        return Err(Error::new(
            ErrorKind::Http,
            format!(
                "invalid exception _find response: page {page} returned {returned} objects, \
                 exceeding total {total}"
            ),
        ));
    }
    Ok((data, total))
}

fn required_positive_find_number(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<u64> {
    let value = object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| find_field_error(field, "a positive integer"))?;
    if value == 0 {
        return Err(find_field_error(field, "a positive integer"));
    }
    Ok(value)
}

fn find_field_error(field: &str, expected: &str) -> Error {
    Error::new(
        ErrorKind::Http,
        format!("invalid exception _find response field {field}: expected {expected}"),
    )
}

/// Read every object a `_find` route serves, paging until `total` is reached.
///
/// Refuses a page that returns nothing while `total` is still ahead: a short
/// read is indistinguishable from objects deleted between pages, and a mirror
/// built on it would silently drop them.
async fn find_paged(t: &Transport, path_for: impl Fn(u32) -> String) -> Result<Vec<Value>> {
    t.require_feature(Feature::ExceptionLists).await?;
    let mut out: Vec<Value> = Vec::new();
    let mut page = 1u32;
    loop {
        let body = t.get(&path_for(page)).await?;
        let (data, total) = decode_find(&body)?;
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
    t.require_feature(Feature::ExceptionLists).await?;
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
    t.require_feature(Feature::ExceptionLists).await?;
    let payload = normalize::canonical_list(l);
    let response = t.post(BASE, Some(&payload.into_value())).await?;
    ExceptionList::from_value(response)
}

pub async fn update_list(t: &Transport, l: &ExceptionList) -> Result<ExceptionList> {
    t.require_feature(Feature::ExceptionLists).await?;
    let payload = normalize::canonical_list(l);
    let response = t.put(BASE, &payload.into_value()).await?;
    ExceptionList::from_value(response)
}

pub async fn delete_list(t: &Transport, key: &ListKey) -> Result<ExceptionList> {
    t.require_feature(Feature::ExceptionLists).await?;
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
    t.require_feature(Feature::ExceptionLists).await?;
    let payload = normalize::canonical_item(i);
    let response = t.post(ITEMS, Some(&payload.into_value())).await?;
    ExceptionItem::from_value(response)
}

pub async fn update_item(t: &Transport, i: &ExceptionItem) -> Result<ExceptionItem> {
    t.require_feature(Feature::ExceptionLists).await?;
    let payload = normalize::canonical_item(i);
    let response = t.put(ITEMS, &payload.into_value()).await?;
    ExceptionItem::from_value(response)
}

pub async fn delete_item(t: &Transport, item_id: &str, namespace: &str) -> Result<ExceptionItem> {
    t.require_feature(Feature::ExceptionLists).await?;
    let body = t
        .delete(&format!(
            "{ITEMS}?item_id={}&namespace_type={}",
            urlencode(item_id),
            urlencode(namespace),
        ))
        .await?;
    ExceptionItem::from_value(body)
}

/// The required final line of one exception-list export response.
///
/// This deliberately does not reuse `ExportSummary`: that type defaults absent
/// fields for importing historical bundles, while this live endpoint boundary
/// must reject a response that does not state its measured outcome.
#[derive(Deserialize)]
struct ExceptionExportTrailer {
    exported_exception_list_count: u64,
    exported_exception_list_item_count: u64,
    missing_exception_lists: Vec<Value>,
    missing_exception_list_items: Vec<Value>,
}

struct DecodedExceptionExport {
    exported_lists: u64,
    missing: Vec<Value>,
}

fn decode_exception_export(body: &str, key: &ListKey) -> Result<DecodedExceptionExport> {
    let trailer = body
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| Error::new(ErrorKind::Http, "missing exception export trailer"))?;
    let trailer: ExceptionExportTrailer = serde_json::from_str(trailer).map_err(|e| {
        Error::new(
            ErrorKind::Http,
            format!("invalid exception export trailer: {e}"),
        )
    })?;
    if trailer.exported_exception_list_count > 1 {
        return Err(Error::new(
            ErrorKind::Http,
            "contradictory exception export trailer: one request exported more than one list",
        ));
    }

    let mut missing = trailer.missing_exception_lists;
    missing.extend(trailer.missing_exception_list_items);
    for value in &mut missing {
        add_missing_identity(value, key);
    }

    // The item count is required even though one container export may carry
    // any number of items. Destructure it so the wire contract remains
    // explicit at this boundary.
    let _ = trailer.exported_exception_list_item_count;
    Ok(DecodedExceptionExport {
        exported_lists: trailer.exported_exception_list_count,
        missing,
    })
}

fn add_missing_identity(value: &mut Value, key: &ListKey) {
    if let Some(object) = value.as_object_mut() {
        if !object.get("list_id").is_some_and(Value::is_string) {
            object.insert("list_id".to_string(), Value::String(key.list_id.clone()));
        }
        if !object.get("namespace_type").is_some_and(Value::is_string) {
            object.insert(
                "namespace_type".to_string(),
                Value::String(key.namespace_type.clone()),
            );
        }
        return;
    }

    *value = json!({
        "list_id": key.list_id,
        "namespace_type": key.namespace_type,
        "missing": std::mem::take(value),
    });
}

/// Export the given containers and their items as NDJSON.
///
/// The export route is the one path that refuses `list_id` alone (measured,
/// fact E), so each key is resolved to its live container `id` first. Identity
/// stays `list_id` plus `namespace_type` everywhere; the `id` is fetched only
/// here, at the boundary that demands it. A key with no live container is
/// refused rather than skipped: a silently dropped key is a short export
/// reported as a success.
pub async fn export_lists(t: &Transport, keys: &[ListKey]) -> Result<ExportOutcome> {
    t.require_feature(Feature::ExceptionLists).await?;
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

    let mut body = String::new();
    let mut exported = 0u64;
    let mut missing = Vec::new();
    for key in keys {
        let id = ids.get(key).expect("every key resolved before export");
        let path = format!(
            "{BASE}/_export?id={}&list_id={}&namespace_type={}&include_expired_exceptions=true",
            urlencode(id),
            urlencode(&key.list_id),
            urlencode(&key.namespace_type),
        );
        let response = t.post_text(&path, None).await?;
        let decoded = decode_exception_export(&response, key)?;
        exported = exported
            .checked_add(decoded.exported_lists)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Http,
                    "invalid exception export trailers: exported-list count overflow",
                )
            })?;
        missing.extend(decoded.missing);
        body.push_str(&response);
        if !response.ends_with('\n') {
            body.push('\n');
        }
    }
    Ok(ExportOutcome {
        body,
        exported,
        missing,
    })
}

pub async fn import_lists(t: &Transport, ndjson: &str, overwrite: bool) -> Result<Value> {
    t.require_feature(Feature::ExceptionLists).await?;
    t.post_multipart_ndjson(&format!("{BASE}/_import?overwrite={overwrite}"), ndjson)
        .await
}

pub async fn count_items(t: &Transport, key: &ListKey) -> Result<u64> {
    t.require_feature(Feature::ExceptionLists).await?;
    t.get(&format!(
        "{ITEMS}/_find?list_id={}&namespace_type={}&page=1&per_page=1",
        urlencode(&key.list_id),
        urlencode(&key.namespace_type)
    ))
    .await?
    .get("total")
    .and_then(Value::as_u64)
    .ok_or_else(|| Error::new(ErrorKind::Http, "invalid exception item count"))
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
    fn to_kql_uses_the_agnostic_saved_object_type_for_that_namespace() {
        let f = ListFilter {
            tag: Some("alpha".into()),
            namespace: Some("agnostic".into()),
            ..Default::default()
        };
        assert_eq!(
            f.to_kql().unwrap(),
            "exception-list-agnostic.attributes.tags: \"alpha\""
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
    fn to_kql_search_matches_name_substring_over_the_measured_prefix() {
        let f = ListFilter {
            search: Some("Sub".into()),
            ..Default::default()
        };
        assert_eq!(
            f.to_kql().unwrap(),
            "exception-list.attributes.name: \"*Sub*\""
        );
    }

    #[test]
    fn to_kql_search_uses_the_agnostic_saved_object_type_for_that_namespace() {
        let f = ListFilter {
            search: Some("Sub".into()),
            namespace: Some("agnostic".into()),
            ..Default::default()
        };
        assert_eq!(
            f.to_kql().unwrap(),
            "exception-list-agnostic.attributes.name: \"*Sub*\""
        );
    }

    #[test]
    fn to_kql_search_combines_with_other_clauses() {
        let f = ListFilter {
            list_type: Some("detection".into()),
            search: Some("Sub".into()),
            ..Default::default()
        };
        assert_eq!(
            f.to_kql().unwrap(),
            "exception-list.attributes.type: \"detection\" AND \
             exception-list.attributes.name: \"*Sub*\""
        );
    }

    #[test]
    fn to_kql_search_escapes_wildcards_in_the_name() {
        let f = ListFilter {
            search: Some("a*b?c".into()),
            ..Default::default()
        };
        assert_eq!(
            f.to_kql().unwrap(),
            "exception-list.attributes.name: \"*a\\*b\\?c*\""
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
