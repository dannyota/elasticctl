//! Typed wrappers for the exception-list API.
//!
//! Functions use the stable `list_id` plus `namespace_type` identity, never the
//! volatile saved-object `id` (spec 4.5). The one exception is `export_lists`,
//! which fetches `id` at the single boundary where the route demands it.

use crate::codec::{self, Bundle, Format};
use crate::model::{ExceptionItem, ExceptionList, ListKey};
use crate::normalize;
use crate::ops::{DeleteOutcome, ExportOutcome, ImportPlan, ImportReport, MutationPlan};
use crate::rules::kql_escape;
use elasticctl_core::{Error, ErrorKind, Result, Transport, urlencode};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

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

/// Whether the value-list data streams (`.lists-default`, `.items-default`)
/// are bootstrapped.
///
/// `GET /api/lists/index` answers 404 when they are not, so a 404 is the
/// absent case rather than an error (spec 7.7). Only a status outside the
/// success range other than 404 is returned as an error. `pub(crate)` because
/// it is shared by `doctor` and the push preview, not part of the public API.
pub(crate) async fn value_lists_bootstrapped(t: &Transport) -> Result<bool> {
    match t.get("/api/lists/index").await {
        Ok(body) => Ok(body["list_index"].as_bool().unwrap_or(false)
            && body["list_item_index"].as_bool().unwrap_or(false)),
        Err(e) if e.kind == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
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

/// The two namespaces a `list_id` can live in. Spec 4.5: `namespace_type` is
/// half of a list's identity, so a command that scopes to one namespace and a
/// command that scopes to the other read disjoint objects.
const NAMESPACES: [&str; 2] = ["single", "agnostic"];

/// The report `list` renders: every matching container, in stable order.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListReport {
    pub total: usize,
    pub lists: Vec<ExceptionList>,
}

/// The report `get` renders: one container and every item inside it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListDetail {
    pub list: ExceptionList,
    pub items: Vec<ExceptionItem>,
}

/// The namespaces a command scoped by `--namespace` reads, or every namespace
/// when the flag is absent.
fn namespaces_to_search(namespace: Option<&str>) -> Vec<&str> {
    match namespace {
        Some(ns) => vec![ns],
        None => NAMESPACES.to_vec(),
    }
}

/// Resolve a `list_id` selector to its `ListKey`.
///
/// With `--namespace`, the selector is looked up in that namespace alone. A
/// miss is `not_found` naming the selector. Without the flag, the namespace has
/// to be found: a list that exists in neither is refused with `not_found`, and
/// one that exists in both is refused with `conflict` naming `--namespace` as
/// the remedy rather than silently picking a side (spec 4.5, 5.2).
async fn resolve_list_key(
    t: &Transport,
    list_id: &str,
    namespace: Option<&str>,
) -> Result<ListKey> {
    if let Some(ns) = namespace {
        let key = ListKey {
            list_id: list_id.to_string(),
            namespace_type: ns.to_string(),
        };
        match get_list(t, &key).await {
            Ok(_) => return Ok(key),
            // Name the selector, not the raw server 404 (spec 4.3).
            Err(e) if e.kind == ErrorKind::NotFound => {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!("exception list not found: {list_id} ({ns})"),
                ));
            }
            Err(e) => return Err(e),
        }
    }

    let mut matches = Vec::new();
    for ns in NAMESPACES {
        let key = ListKey {
            list_id: list_id.to_string(),
            namespace_type: ns.to_string(),
        };
        match get_list(t, &key).await {
            Ok(_) => matches.push(key),
            Err(e) if e.kind == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    match matches.len() {
        1 => Ok(matches.pop().expect("one match")),
        0 => Err(Error::new(
            ErrorKind::NotFound,
            format!("exception list not found: {list_id}"),
        )),
        _ => Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "exception list '{list_id}' exists in both the 'single' and 'agnostic' \
                 namespaces; pass --namespace to select one"
            ),
        )),
    }
}

/// Every live container's key, in the requested namespace or both.
async fn all_list_keys(t: &Transport, namespace: Option<&str>) -> Result<Vec<ListKey>> {
    let mut keys = Vec::new();
    for ns in namespaces_to_search(namespace) {
        let filter = ListFilter {
            namespace: Some(ns.to_string()),
            ..Default::default()
        };
        for list in find_lists(t, &filter).await? {
            keys.push(list.key()?);
        }
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

/// Resolve selectors and an optional tag to list keys. `None` means "every
/// list". A selector matching nothing is refused by `resolve_list_key`; a tag
/// matching nothing is refused here even when a selector resolved (spec 4.3).
async fn resolve_selection(
    t: &Transport,
    selectors: &[String],
    tag: Option<&str>,
    namespace: Option<&str>,
    noun: &str,
) -> Result<Option<Vec<ListKey>>> {
    if selectors.is_empty() && tag.is_none() {
        return Ok(None);
    }

    let mut keys = Vec::new();
    for s in selectors {
        keys.push(resolve_list_key(t, s, namespace).await?);
    }

    let mut tag_matched = false;
    if let Some(tag) = tag {
        for ns in namespaces_to_search(namespace) {
            let filter = ListFilter {
                tag: Some(tag.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            };
            for list in find_lists(t, &filter).await? {
                tag_matched = true;
                keys.push(list.key()?);
            }
        }
        if !tag_matched {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("No exception lists matched tag '{tag}'; nothing to {noun}"),
            ));
        }
    }

    keys.sort();
    keys.dedup();
    Ok(Some(keys))
}

/// Every matching container. With no `--namespace`, both namespaces are read
/// and merged so an `agnostic` container is never silently omitted: a list
/// command that showed only half the namespace space would be lying (spec 5.2).
pub async fn list_op(t: &Transport, f: &ListFilter) -> Result<ListReport> {
    let mut lists = Vec::new();
    if f.namespace.is_some() {
        lists = find_lists(t, f).await?;
    } else {
        for ns in NAMESPACES {
            let mut per_ns = f.clone();
            per_ns.namespace = Some(ns.to_string());
            lists.extend(find_lists(t, &per_ns).await?);
        }
    }
    normalize::sort_lists(&mut lists);
    let total = lists.len();
    Ok(ListReport { total, lists })
}

/// Resolve a selector and fetch the container with all of its items.
pub async fn get_op(t: &Transport, list_id: &str, namespace: Option<&str>) -> Result<ListDetail> {
    let key = resolve_list_key(t, list_id, namespace).await?;
    let list = get_list(t, &key).await?;
    let items = find_items(t, &key).await?;
    Ok(ListDetail { list, items })
}

/// Parse and validate a local file without contacting a server.
///
/// Exception bundles use NDJSON. YAML bundle input is unsupported, so YAML
/// paths are refused rather than half-decoded.
pub fn validate_op(path: &Path) -> Result<Bundle> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| Error::new(ErrorKind::Error, format!("reading {}: {e}", path.display())))?;
    if Format::from_path(path) == Format::Yaml {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!(
                "{} is YAML, which cannot represent exception lists or items; validate an NDJSON bundle",
                path.display()
            ),
        ));
    }
    codec::decode_bundle(&body)
}

/// Export the selected containers and their items.
///
/// The body is the raw `_export` concatenation, which `_import` accepts
/// verbatim. YAML bundle export is unsupported.
pub async fn export_op(
    t: &Transport,
    list_ids: &[String],
    tag: Option<&str>,
    namespace: Option<&str>,
    format: Format,
) -> Result<ExportOutcome> {
    if format == Format::Yaml {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "exception bundles have no YAML form; re-run with --format-file ndjson",
        ));
    }
    let keys = match resolve_selection(t, list_ids, tag, namespace, "export").await? {
        Some(keys) => keys,
        None => all_list_keys(t, namespace).await?,
    };
    let body = export_lists(t, &keys).await?;
    Ok(ExportOutcome {
        body,
        exported: keys.len() as u64,
        missing: Vec::new(),
    })
}

/// What `plan_delete_op` resolved, so the apply acts on exactly the keys the
/// preview named rather than re-resolving a bare `list_id` after the guard.
#[derive(Debug, Clone, PartialEq)]
pub struct DeletePlan {
    pub preview: MutationPlan,
    pub keys: Vec<ListKey>,
}

/// Resolve every selector before previewing, so the preview is accurate and an
/// unresolved selector fails before any write. The resolved keys travel with
/// the plan so the apply cannot resolve a different namespace than the preview
/// showed.
pub async fn plan_delete_op(
    t: &Transport,
    list_ids: &[String],
    namespace: Option<&str>,
) -> Result<DeletePlan> {
    let mut details = Vec::with_capacity(list_ids.len());
    let mut targets = Vec::with_capacity(list_ids.len());
    let mut keys = Vec::with_capacity(list_ids.len());
    for id in list_ids {
        let key = resolve_list_key(t, id, namespace).await?;
        details.push(format!("{id}  ({})", key.namespace_type));
        targets.push(id.clone());
        keys.push(key);
    }
    Ok(DeletePlan {
        preview: MutationPlan {
            preview_action: format!("Delete {} exception list(s)", targets.len()),
            preview_details: details,
            targets,
        },
        keys,
    })
}

/// Continue after per-container failures so the result records every deletion
/// and every container that remains.
pub async fn apply_delete_op(t: &Transport, plan: &DeletePlan) -> Result<DeleteOutcome> {
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    for key in &plan.keys {
        match delete_list(t, key).await {
            Ok(_) => deleted.push(json!({
                "list_id": key.list_id,
                "namespace_type": key.namespace_type,
            })),
            Err(e) => failed.push(json!({"list_id": key.list_id, "error": e.message})),
        }
    }
    Ok(DeleteOutcome {
        applied: true,
        deleted,
        failed,
        total: plan.keys.len(),
    })
}

/// Compute the import preview and the NDJSON to upload.
///
/// The file is decoded as a bundle, never as rules only: `decode_ndjson` drops
/// exception lines and would leave the operator with rules referencing lists
/// that were never created. The preview counts containers and items, so an
/// items-only file previews as the non-zero mutation it is. The transport is
/// `None` unless `skip_existing` is set, so a dry run that only reads the file
/// never needs a credential.
pub async fn plan_import_op(
    t: Option<&Transport>,
    path: &Path,
    overwrite: bool,
    skip_existing: bool,
) -> Result<ImportPlan> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| Error::new(ErrorKind::Error, format!("reading {}: {e}", path.display())))?;

    if Format::from_path(path) == Format::Yaml {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!(
                "{} is YAML, which cannot represent exception lists or items; import an NDJSON bundle",
                path.display()
            ),
        ));
    }

    let bundle = codec::decode_bundle(&body)?;

    // The exception import route imports containers and items only. A file that
    // also carries rules would drop them silently (spec 5.2).
    if !bundle.rules.is_empty() {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!(
                "this file carries {} rule(s), which the exception import route cannot import; \
                 use `rules import` for a rules bundle",
                bundle.rules.len()
            ),
        ));
    }

    // An item whose list_id is unreadable has no home; uploading it would
    // strand it (spec 5.2). Refuse before any skip decision so both paths share
    // the guard instead of one silently defaulting to an empty list_id.
    for item in &bundle.items {
        if item.list_id().is_err() {
            return Err(Error::new(
                ErrorKind::Error,
                format!(
                    "an exception item ('{}') has no readable list_id",
                    item.item_id().unwrap_or("<unreadable>")
                ),
            ));
        }
    }

    let total = bundle.lists.len() + bundle.items.len();
    let mut lists = bundle.lists;
    let mut items = bundle.items;
    let mut skipped: Vec<Value> = Vec::new();

    if skip_existing {
        let t = t.ok_or_else(|| {
            Error::new(ErrorKind::Error, "import --skip-existing needs a transport")
        })?;
        let keys: Vec<ListKey> = lists
            .iter()
            .map(ExceptionList::key)
            .collect::<Result<_>>()?;
        let existing = resolve_ids(t, &keys).await?;

        let mut keep = Vec::with_capacity(lists.len());
        let mut skip_keys = Vec::new();
        for list in lists {
            let key = list.key()?;
            if existing.contains_key(&key) {
                skipped.push(json!({
                    "list_id": key.list_id,
                    "namespace_type": key.namespace_type,
                    "reason": "exists",
                }));
                skip_keys.push(key);
            } else {
                keep.push(list);
            }
        }
        lists = keep;

        // Items inside a skipped container are skipped with it: their home was
        // never written, so writing them alone would strand them.
        if !skip_keys.is_empty() {
            let skip_set: std::collections::BTreeSet<ListKey> = skip_keys.into_iter().collect();
            items.retain(|i| {
                let key = ListKey {
                    list_id: i.list_id().expect("list_id validated above").to_string(),
                    namespace_type: i.namespace_type().to_string(),
                };
                !skip_set.contains(&key)
            });
        }
    }

    let mut details = Vec::with_capacity(lists.len() + items.len() + skipped.len());
    for l in &lists {
        details.push(format!("{}  {}  import", l.list_id()?, l.name()));
    }
    for i in &items {
        details.push(format!("{}  {}  import", i.item_id()?, i.list_id()?));
    }
    details.extend(skipped.iter().map(|s| {
        format!(
            "{}  skip (already exists)",
            s["list_id"].as_str().unwrap_or_default()
        )
    }));

    let mut targets = Vec::with_capacity(lists.len() + items.len());
    for l in &lists {
        targets.push(l.list_id()?.to_string());
    }
    for i in &items {
        targets.push(i.item_id()?.to_string());
    }

    let qualifier = if overwrite {
        ", overwriting existing".to_string()
    } else if skip_existing && !skipped.is_empty() {
        format!(", skipping {} that already exist", skipped.len())
    } else {
        String::new()
    };
    let preview = MutationPlan {
        preview_action: format!(
            "Import {} exception list(s) and {} item(s) from {}{qualifier}",
            lists.len(),
            items.len(),
            path.display()
        ),
        preview_details: details,
        targets,
    };

    // Kibana's import accepts export trailers, but this plan may skip objects.
    // Re-encode only the planned objects so stale trailer counts do not describe
    // containers or items that will not be uploaded.
    let ndjson = codec::encode_bundle(&Bundle {
        rules: Vec::new(),
        lists,
        items,
        summary: None,
    })?;

    Ok(ImportPlan {
        preview,
        ndjson,
        total,
        skipped,
    })
}

/// Upload the NDJSON `plan_import_op` prepared.
pub async fn apply_import_op(t: &Transport, ndjson: &str, overwrite: bool) -> Result<ImportReport> {
    // Do not upload empty NDJSON when every container already exists.
    if ndjson.is_empty() {
        return Ok(ImportReport {
            succeeded: json!(0),
            failed: json!([]),
        });
    }

    let response = import_lists(t, ndjson, overwrite).await?;
    let succeeded = response.get("success_count").cloned().unwrap_or(json!(0));
    let failed = response.get("errors").cloned().unwrap_or_else(|| json!([]));
    Ok(ImportReport { succeeded, failed })
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
