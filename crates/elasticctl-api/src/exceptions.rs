//! Typed wrappers for the exception-list API.
//!
//! Functions use the stable `list_id` plus `namespace_type` identity, never the
//! volatile saved-object `id` (spec 4.5). The one exception is `export_lists`,
//! which fetches `id` at the single boundary where the route demands it.

mod list_endpoints;
mod value_lists;
pub use list_endpoints::{
    ListFilter, count_items, create_item, create_list, delete_item, delete_list, export_lists,
    find_items, find_lists, get_list, import_lists, resolve_ids, update_item, update_list,
};
pub(crate) use value_lists::{ValueListRef, value_list_exists, value_lists_bootstrapped};

use crate::codec::{self, Bundle, Format};
use crate::model::{ExceptionItem, ExceptionList, ListKey};
use crate::normalize;
use crate::ops::{DeleteOutcome, ExportOutcome, ImportPlan, ImportReport, MutationPlan};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

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
    export_lists(t, &keys).await
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
    let mut resolved = BTreeSet::new();
    for id in list_ids {
        resolved.insert(resolve_list_key(t, id, namespace).await?);
    }
    let keys: Vec<_> = resolved.into_iter().collect();
    let targets: Vec<_> = keys
        .iter()
        .map(|key| format!("{} ({})", key.list_id, key.namespace_type))
        .collect();
    Ok(DeletePlan {
        preview: MutationPlan {
            preview_action: format!("Delete {} exception list(s)", targets.len()),
            preview_details: targets.clone(),
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
            Err(e) => failed.push(json!({
                "list_id": key.list_id,
                "namespace_type": key.namespace_type,
                "error": e.message,
            })),
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
    crate::ops::decode_import_report(&response, "exceptions")
}
