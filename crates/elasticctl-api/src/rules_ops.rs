//! Rules command orchestration, above the endpoint wrappers in `rules`.
//!
//! The `-cli` crate resolves context, applies the guard, and renders; this
//! module does the work between them so a future MCP server can call the same
//! functions and serialize the same structs.

use crate::codec::{self, Format};
use crate::model::{ListKey, Rule, exception_refs, server_defaults};
use crate::normalize;
use crate::ops::{DeleteOutcome, ExportOutcome, ImportPlan, ImportReport, MutationPlan};
use crate::rules::{self, BulkAction, RuleFilter, RuleSource};
use crate::selection;
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;
use serde_json::{Value, json};
use std::path::Path;

/// Kibana validates an exception pointer as a string before it re-resolves the
/// reference against the target stack. This deterministic placeholder is
/// upload-only: the server replaces it with the live container id.
const EXCEPTION_POINTER_PLACEHOLDER: &str = "00000000-0000-0000-0000-000000000000";

/// The report `list` renders: every matching rule, in server order.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuleListReport {
    pub total: usize,
    pub rules: Vec<Rule>,
}

/// The report an `enable`/`disable` apply renders. Field order is the
/// serialized JSON key order and is contractual: the root `Cargo.toml` enables
/// `serde_json`'s `preserve_order`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SetEnabledOutcome {
    pub applied: bool,
    pub succeeded: u64,
    pub failed: u64,
    pub skipped: u64,
    pub total: u64,
}

/// One rule's validation entry.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuleValidation {
    pub rule_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: String,
    pub defaults_applied: Vec<String>,
}

/// The report `validate` renders.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ValidateReport {
    pub valid: bool,
    pub count: usize,
    pub rules: Vec<RuleValidation>,
}

/// The report a preview renders.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PreviewReport {
    pub rule: String,
    pub preview_id: Option<String>,
    pub invocations: u32,
    pub hits: Option<u64>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub hits_error: Option<String>,
    pub sample: Vec<Value>,
}

pub async fn list(t: &Transport, filter: &RuleFilter) -> Result<RuleListReport> {
    let rules = rules::find_all(t, filter).await?;
    if rules.is_empty() && is_unselected_source_query(filter) {
        rules::verify_source_partition(t).await?;
    }
    let total = rules.len();
    Ok(RuleListReport { total, rules })
}

/// A `rules list` filter has no positional selectors. Any remaining clause
/// deliberately narrows the result and must not trigger a corpus proof.
fn is_unselected_source_query(filter: &RuleFilter) -> bool {
    matches!(filter.source, RuleSource::Custom | RuleSource::Prebuilt)
        && filter.enabled.is_none()
        && filter.rule_type.is_none()
        && filter.severity.is_none()
        && filter.tag.is_none()
        && filter.name.is_none()
        && filter.query.is_none()
        && filter.search.is_none()
}

/// Resolve a selector and fetch the rule, canonicalized so output is stable.
pub async fn get_one(t: &Transport, selector: &str) -> Result<Rule> {
    let rule_id = selection::to_rule_id(t, selector).await?;
    let rule = rules::get(t, &rule_id).await?;
    Ok(normalize::canonical(&rule))
}

/// Parse and validate a local file without contacting a server.
///
/// The codecs reject missing or non-string `rule_id` values. Keep the
/// per-rule check because derived `Rule::Deserialize` bypasses that
/// validation. Check every rule so one report names every invalid index.
pub fn validate(path: &Path) -> Result<ValidateReport> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| Error::new(ErrorKind::Error, format!("reading {}: {e}", path.display())))?;

    let rules = match Format::from_path(path) {
        Format::Yaml => codec::decode_yaml(&body)?,
        Format::Ndjson => codec::decode_ndjson(&body)?.0,
    };

    let defaults = server_defaults();
    let mut reports = Vec::with_capacity(rules.len());
    let mut failures = Vec::new();

    for (i, r) in rules.iter().enumerate() {
        match r.rule_id() {
            Ok(rule_id) => {
                // Show server defaults applied to sparse rules.
                let mut applied: Vec<String> = defaults
                    .keys()
                    .filter(|k| !r.as_map().contains_key(*k))
                    .cloned()
                    .collect();
                applied.sort();
                reports.push(RuleValidation {
                    rule_id: rule_id.to_string(),
                    name: r.name().to_string(),
                    rule_type: r.rule_type().to_string(),
                    defaults_applied: applied,
                });
            }
            // Do not report a blank rule ID as valid.
            Err(e) => failures.push(format!("rule at index {i}: {}", e.message)),
        }
    }

    if !failures.is_empty() {
        // An invalid rule invalidates the file. Return a classified error,
        // not a partial success payload.
        return Err(Error::new(ErrorKind::Error, failures.join("; ")));
    }

    Ok(ValidateReport {
        valid: true,
        count: rules.len(),
        rules: reports,
    })
}

/// Resolve every selector to its rule ID and rule before previewing, so the
/// preview is accurate and unresolved selectors fail before mutation.
async fn resolve_targets(t: &Transport, selectors: &[String]) -> Result<Vec<(String, Rule)>> {
    let mut out = Vec::with_capacity(selectors.len());
    for s in selectors {
        let rule_id = selection::to_rule_id(t, s).await?;
        let rule = rules::get(t, &rule_id).await?;
        out.push((rule_id, rule));
    }
    Ok(out)
}

pub async fn plan_set_enabled(
    t: &Transport,
    selectors: &[String],
    enable: bool,
) -> Result<MutationPlan> {
    let resolved = resolve_targets(t, selectors).await?;
    let preview_details = resolved
        .iter()
        .map(|(id, r)| {
            let from = if r.enabled() { "enabled" } else { "disabled" };
            let to = if enable { "enabled" } else { "disabled" };
            format!("{id}  {}  {from} -> {to}", r.name())
        })
        .collect();
    let verb = if enable { "Enable" } else { "Disable" };
    Ok(MutationPlan {
        preview_action: format!("{verb} {} rule(s)", resolved.len()),
        preview_details,
        targets: resolved.into_iter().map(|(id, _)| id).collect(),
    })
}

pub async fn apply_set_enabled(
    t: &Transport,
    plan: &MutationPlan,
    enable: bool,
) -> Result<SetEnabledOutcome> {
    let action = if enable {
        BulkAction::Enable
    } else {
        BulkAction::Disable
    };
    let o = rules::bulk_by_rule_ids(t, action, &plan.targets, false).await?;
    Ok(SetEnabledOutcome {
        applied: true,
        succeeded: o.succeeded,
        failed: o.failed,
        skipped: o.skipped,
        total: o.total,
    })
}

pub async fn plan_delete(t: &Transport, selectors: &[String]) -> Result<MutationPlan> {
    let resolved = resolve_targets(t, selectors).await?;
    let preview_details = resolved
        .iter()
        .map(|(id, r)| format!("{id}  {}", r.name()))
        .collect();
    Ok(MutationPlan {
        preview_action: format!("Delete {} rule(s)", resolved.len()),
        preview_details,
        targets: resolved.into_iter().map(|(id, _)| id).collect(),
    })
}

/// Continue after per-rule failures so the result records every deletion and
/// every rule that remains.
pub async fn apply_delete(t: &Transport, plan: &MutationPlan) -> Result<DeleteOutcome> {
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    for id in &plan.targets {
        match rules::delete(t, id).await {
            Ok(_) => deleted.push(json!({"rule_id": id})),
            Err(e) => failed.push(json!({"rule_id": id, "error": e.message})),
        }
    }
    Ok(DeleteOutcome {
        applied: true,
        deleted,
        failed,
        total: plan.targets.len(),
    })
}

/// Fetch, canonicalize, and sort selected rules by rule ID. Exports from an
/// unchanged stack are byte-identical for version-control review. Scoped by
/// `source`; the `all` default lives on the clap flag (spec 5.5).
///
/// A source scope without a selector or tag resolves to the matching rule IDs
/// first, so the subset export transfers only the subset (spec 4.3). A selector
/// or tag is an explicit narrowing and overrides the source default, matching
/// the state commands (spec 5.3).
pub async fn export_rules(
    t: &Transport,
    selectors: &[String],
    tag: Option<&str>,
    source: RuleSource,
    format: Format,
) -> Result<ExportOutcome> {
    let selection: Option<Vec<String>> =
        if selectors.is_empty() && tag.is_none() && source != RuleSource::All {
            let scoped = rules::find_all(
                t,
                &RuleFilter {
                    source,
                    ..Default::default()
                },
            )
            .await?;
            if scoped.is_empty() {
                if matches!(source, RuleSource::Custom | RuleSource::Prebuilt) {
                    rules::verify_source_partition(t).await?;
                }
                return Ok(ExportOutcome {
                    body: String::new(),
                    exported: 0,
                    missing: Vec::new(),
                });
            }
            Some(
                scoped
                    .iter()
                    .filter_map(|r| r.rule_id().ok().map(str::to_owned))
                    .collect(),
            )
        } else {
            // Export reads from the stack, so every selector names a server rule.
            selection::resolve(t, selectors, tag, None, &[], "export").await?
        };

    let mut bundle = rules::export(t, selection.as_deref()).await?;
    for r in &mut bundle.rules {
        *r = normalize::canonical(r);
    }
    normalize::sort_rules(&mut bundle.rules);

    let body = match format {
        // YAML carries rules only. A bundle with exception objects has no YAML
        // form, so refuse rather than silently drop them (spec 5.2).
        Format::Yaml => {
            if !bundle.lists.is_empty() || !bundle.items.is_empty() {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    format!(
                        "this export carries {} exception list(s) and {} item(s), which the \
                         YAML format cannot represent; re-run with --format-file ndjson",
                        bundle.lists.len(),
                        bundle.items.len()
                    ),
                ));
            }
            codec::encode_yaml(&bundle.rules)?
        }
        // The bundle's lists and items must survive the export or importing
        // the file elsewhere recreates a rule pointing at a missing list.
        Format::Ndjson => codec::encode_bundle(&bundle)?,
    };

    // A requested but missing rule was deleted after selection. Report it in
    // `missing` so a short export has a nonzero exit code.
    let missing = bundle
        .summary
        .as_ref()
        .map(|s| s.missing_rules.clone())
        .unwrap_or_default();

    Ok(ExportOutcome {
        body,
        exported: bundle.rules.len() as u64,
        missing,
    })
}

/// Compute the import preview and the NDJSON to upload.
///
/// With `--skip-existing`, check existing rule IDs before the preview so it
/// shows only rules that would import. That query is a read, so it belongs
/// here and does not violate the no-write rule. The transport is `None` unless
/// `skip_existing` is set, so a dry run that only reads the file never needs
/// one.
pub async fn plan_import(
    t: Option<&Transport>,
    path: &Path,
    overwrite: bool,
    skip_existing: bool,
) -> Result<ImportPlan> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| Error::new(ErrorKind::Error, format!("reading {}: {e}", path.display())))?;

    let format = Format::from_path(path);
    let mut bundle = match format {
        // YAML has no exception-bundle representation. Preserve its existing
        // rules-only behavior, then upload it as Kibana's required NDJSON.
        Format::Yaml => codec::Bundle {
            rules: codec::decode_yaml(&body)?,
            ..Default::default()
        },
        // Rules export emits rules, exception containers, and exception items
        // in one NDJSON bundle. Import must retain all three so Kibana can
        // recreate containers and resolve their server-owned pointers.
        Format::Ndjson => codec::decode_bundle(&body)?,
    };
    let total = bundle.rules.len();

    let mut skipped: Vec<Value> = Vec::new();

    if skip_existing {
        let t = t.ok_or_else(|| {
            Error::new(ErrorKind::Error, "import --skip-existing needs a transport")
        })?;
        let ids: Vec<String> = bundle
            .rules
            .iter()
            .filter_map(|r| r.rule_id().ok().map(str::to_owned))
            .collect();
        let existing = rules::existing_rule_ids(t, &ids).await?;

        let mut keep = Vec::with_capacity(bundle.rules.len());
        for rule in std::mem::take(&mut bundle.rules) {
            match rule.rule_id() {
                Ok(id) if existing.contains(id) => {
                    skipped.push(json!({"rule_id": id, "reason": "exists"}));
                }
                _ => keep.push(rule),
            }
        }
        bundle.rules = keep;
    }

    if format == Format::Ndjson {
        retain_referenced_exception_objects(&mut bundle);
    }
    add_upload_pointer_placeholders(&mut bundle);

    let mut details: Vec<String> = bundle
        .rules
        .iter()
        .map(|r| format!("{}  {}  import", r.rule_id().unwrap_or(""), r.name()))
        .collect();
    details.extend(skipped.iter().map(|s| {
        format!(
            "{}  skip (already exists)",
            s["rule_id"].as_str().unwrap_or("")
        )
    }));

    let qualifier = if overwrite {
        ", overwriting existing".to_string()
    } else if skip_existing && !skipped.is_empty() {
        format!(", skipping {} that already exist", skipped.len())
    } else {
        String::new()
    };
    let preview = MutationPlan {
        preview_action: format!(
            "Import {} rule(s) from {}{qualifier}",
            bundle.rules.len(),
            path.display()
        ),
        preview_details: details,
        targets: bundle
            .rules
            .iter()
            .filter_map(|r| r.rule_id().ok().map(str::to_owned))
            .collect(),
    };

    // Kibana's import takes NDJSON regardless of the source file's format.
    // A source NDJSON bundle keeps its exception members; YAML remains rules
    // only because that format cannot represent containers or items.
    let ndjson = match format {
        Format::Yaml => codec::encode_ndjson(&bundle.rules)?,
        Format::Ndjson => codec::encode_bundle(&bundle)?,
    };

    Ok(ImportPlan {
        preview,
        ndjson,
        total,
        skipped,
    })
}

/// Keep only containers and items a rule scheduled for upload references.
/// `rules import` is guarded as a rule mutation, so an exception-only or
/// unreferenced object must never become an unpreviewed side effect. Namespace
/// is part of stable list identity, so equal `list_id` values in `single` and
/// `agnostic` remain disjoint.
fn retain_referenced_exception_objects(bundle: &mut codec::Bundle) {
    let wanted: std::collections::BTreeSet<ListKey> = bundle
        .rules
        .iter()
        .flat_map(exception_refs)
        .map(|reference| ListKey {
            list_id: reference.list_id,
            namespace_type: reference.namespace_type,
        })
        .collect();

    bundle
        .lists
        .retain(|list| list.key().is_ok_and(|key| wanted.contains(&key)));
    bundle.items.retain(|item| {
        item.list_id().is_ok_and(|list_id| {
            wanted.contains(&ListKey {
                list_id: list_id.to_string(),
                namespace_type: item.namespace_type().to_string(),
            })
        })
    });
}

/// Make every readable exception reference acceptable to Kibana's import
/// schema. This deliberately changes only the transient upload bundle; source
/// files remain pointer-free and malformed/unreadable entries survive intact.
fn add_upload_pointer_placeholders(bundle: &mut codec::Bundle) {
    for rule in &mut bundle.rules {
        let Some(Value::Array(references)) = rule.as_map_mut().get_mut("exceptions_list") else {
            continue;
        };
        for reference in references {
            let Value::Object(reference) = reference else {
                continue;
            };
            if reference.get("list_id").is_some_and(Value::is_string) {
                reference.insert(
                    "id".to_string(),
                    Value::String(EXCEPTION_POINTER_PLACEHOLDER.to_string()),
                );
            }
        }
    }
}

/// Upload the NDJSON `plan_import` prepared.
pub async fn apply_import(t: &Transport, ndjson: &str, overwrite: bool) -> Result<ImportReport> {
    // Do not upload empty NDJSON when every rule already exists.
    if ndjson.is_empty() {
        return Ok(ImportReport {
            succeeded: json!(0),
            failed: json!([]),
        });
    }

    let response = rules::import(t, ndjson, overwrite).await?;

    // Normalize Kibana's response to the bulk-action shape so partial imports
    // use the existing exit-code rule, refusing a malformed success body.
    crate::ops::decode_import_report(&response, "rules")
}

/// Retry once only when the first search finds no hits.
///
/// The preview already completed each invocation. A newly written alert can
/// miss the first search because of Elasticsearch's refresh interval. Retrying
/// only zero hits avoids delay for matching rules and false zero results.
async fn fetch_hits(
    transport: &Transport,
    space: &str,
    preview_id: &str,
    sample: usize,
) -> Result<rules::PreviewHits> {
    let first = rules::preview_hits(transport, space, preview_id, sample).await?;
    if first.total > 0 {
        return Ok(first);
    }
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    rules::preview_hits(transport, space, preview_id, sample).await
}

/// Preview a rule. An existing file path wins; otherwise the source is a rule
/// ID or name from the stack. This supports unpushed local rules.
pub async fn preview_rule(
    t: &Transport,
    source: &str,
    invocations: u32,
    sample: u32,
    space: &str,
) -> Result<PreviewReport> {
    let path = Path::new(source);

    let rule = if path.exists() {
        let body = std::fs::read_to_string(path).map_err(|e| {
            Error::new(ErrorKind::Error, format!("reading {}: {e}", path.display()))
        })?;
        let rules = match Format::from_path(path) {
            Format::Yaml => codec::decode_yaml(&body)?,
            Format::Ndjson => codec::decode_ndjson(&body)?.0,
        };
        rules.into_iter().next().ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                format!("{} contains no rules", path.display()),
            )
        })?
    } else {
        let rule_id = selection::to_rule_id(t, source).await?;
        rules::get(t, &rule_id).await?
    };

    // The API requires an explicit end of the window it simulates over.
    let timeframe_end = now_rfc3339();
    let result = rules::preview(t, &rule, invocations, &timeframe_end).await?;

    // Preserve the preview when reading hits fails. Set `hits` to null and
    // report the error in `hits_error`.
    let (hits, hits_error, sample_hits) = match &result.preview_id {
        None => (
            None,
            Some("the server returned no preview_id".to_string()),
            Vec::new(),
        ),
        Some(preview_id) => match fetch_hits(t, space, preview_id, sample as usize).await {
            Ok(h) => (Some(h.total), None, h.sample),
            Err(e) => (None, Some(e.message), Vec::new()),
        },
    };

    Ok(PreviewReport {
        rule: rule.name().to_string(),
        preview_id: result.preview_id,
        invocations,
        hits,
        errors: result.errors,
        warnings: result.warnings,
        hits_error,
        sample: sample_hits,
    })
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Format directly to avoid a date dependency; the API accepts UTC ISO-8601.
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's days-from-civil inverse, used without a date dependency.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod date_tests {
    use super::*;

    /// Independently computed epoch days catch plausible arithmetic errors
    /// that would shift a preview's `timeframeEnd`.
    #[test]
    fn civil_from_days_matches_independently_computed_epoch_days() {
        let cases = [
            (0, (1970, 1, 1), "epoch"),
            (19782, (2024, 2, 29), "leap day"),
            (11017, (2000, 3, 1), "century leap year (2000 % 400 == 0)"),
            (20818, (2026, 12, 31), "year end"),
            (20819, (2027, 1, 1), "year rollover"),
            // 2100 is divisible by 100 but not 400, so it is not a leap year.
            (47541, (2100, 3, 1), "century non-leap (2100 % 400 != 0)"),
            (
                47540,
                (2100, 2, 28),
                "day before the century non-leap rollover",
            ),
        ];

        for (day, expected, label) in cases {
            assert_eq!(civil_from_days(day), expected, "{label}: day {day}");
        }
    }

    /// The API requires this exact `timeframeEnd` format.
    #[test]
    fn now_rfc3339_matches_the_shape_the_api_requires() {
        let s = now_rfc3339();
        let bytes = s.as_bytes();

        assert_eq!(s.len(), 24, "{s}");
        assert!(bytes[4] == b'-' && bytes[7] == b'-', "{s}");
        assert_eq!(bytes[10], b'T', "{s}");
        assert!(bytes[13] == b':' && bytes[16] == b':', "{s}");
        assert_eq!(bytes[19], b'.', "{s}");
        assert_eq!(&s[20..], "000Z", "{s}");
        assert!(
            s[..19]
                .chars()
                .enumerate()
                .all(|(i, c)| { matches!(i, 4 | 7 | 10 | 13 | 16) || c.is_ascii_digit() }),
            "every non-separator position must be a digit: {s}"
        );
    }
}
