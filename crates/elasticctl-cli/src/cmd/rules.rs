//! Rule commands.

use crate::context::Context;
use crate::guard::{self, Preview};
use crate::resolve;
use elasticctl_api::codec::{self, Format as FileFormat};
use elasticctl_api::model::{Rule, server_defaults};
use elasticctl_api::normalize;
use elasticctl_api::rules::{self as api, BulkAction, RuleFilter};
use elasticctl_api::selection;
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Value, json};
use std::path::Path;

/// Summary shown by `rules list`. Use `rules get` or `rules export` for full
/// rule bodies.
///
/// An unreadable `rule_id` is a server anomaly. Flag it as
/// `resolve::UNREADABLE_RULE_ID` instead of hiding it or failing the listing.
fn summarize(r: &Rule) -> Value {
    json!({
        "rule_id": r.rule_id().unwrap_or(resolve::UNREADABLE_RULE_ID),
        "name": r.name(),
        "type": r.rule_type(),
        "enabled": r.enabled(),
        "severity": r.severity(),
        "risk_score": r.risk_score(),
        "tags": r.tags(),
    })
}

pub async fn list(ctx: &Context, filter: &RuleFilter) -> Result<Value> {
    // Check the credential first so a missing one names the profile instead
    // of returning Transport's generic error.
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let found = api::find_all(transport, filter).await?;
    Ok(Value::Array(found.iter().map(summarize).collect()))
}

pub async fn get(ctx: &Context, selector: &str) -> Result<Value> {
    ctx.require_credential()?;
    let rule_id = resolve::to_rule_id(ctx, selector).await?;
    let transport = ctx.transport().await?;
    let rule = api::get(transport, &rule_id).await?;
    Ok(normalize::canonical(&rule).into_value())
}

/// Validates a local file without contacting a server.
///
/// The codecs reject missing or non-string `rule_id` values. Keep the
/// per-rule check because derived `Rule::Deserialize` bypasses that
/// validation, and because this loop reports server defaults. Check every
/// rule so one report names every invalid index.
pub fn validate(path: &Path) -> Result<Value> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| Error::new(ErrorKind::Error, format!("reading {}: {e}", path.display())))?;

    let rules = match FileFormat::from_path(path) {
        FileFormat::Yaml => codec::decode_yaml(&body)?,
        FileFormat::Ndjson => codec::decode_ndjson(&body)?.0,
    };

    let defaults = server_defaults();
    let mut reports = Vec::with_capacity(rules.len());
    let mut failures = Vec::new();

    for (i, r) in rules.iter().enumerate() {
        match r.rule_id() {
            Ok(rule_id) => {
                // Show server defaults applied to sparse rules.
                let mut applied: Vec<&String> = defaults
                    .keys()
                    .filter(|k| !r.as_map().contains_key(*k))
                    .collect();
                applied.sort();
                reports.push(json!({
                    "rule_id": rule_id,
                    "name": r.name(),
                    "type": r.rule_type(),
                    "defaults_applied": applied,
                }));
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

    Ok(json!({"valid": true, "count": rules.len(), "rules": reports}))
}

/// Resolve every selector before previewing so the preview is accurate and
/// unresolved selectors fail before mutation.
async fn resolve_all(ctx: &Context, selectors: &[String]) -> Result<Vec<(String, Rule)>> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;

    let mut out = Vec::new();
    for s in selectors {
        let rule_id = resolve::to_rule_id(ctx, s).await?;
        let rule = api::get(transport, &rule_id).await?;
        out.push((rule_id, rule));
    }
    Ok(out)
}

pub async fn set_enabled(ctx: &Context, selectors: &[String], enabled: bool) -> Result<Value> {
    let targets = resolve_all(ctx, selectors).await?;
    let verb = if enabled { "Enable" } else { "Disable" };

    let details: Vec<String> = targets
        .iter()
        .map(|(id, r)| {
            let from = if r.enabled() { "enabled" } else { "disabled" };
            let to = if enabled { "enabled" } else { "disabled" };
            format!("{id}  {}  {from} -> {to}", r.name())
        })
        .collect();

    let preview = Preview {
        action: format!("{verb} {} rule(s)", targets.len()),
        details,
    };

    // Derive the guard path from the flag that selects the verb so it cannot
    // name the wrong mutating command.
    let path = if enabled {
        "rules enable"
    } else {
        "rules disable"
    };
    if !guard::check(ctx, path, &preview) {
        return Ok(json!({"applied": false, "total": targets.len()}));
    }

    let ids: Vec<String> = targets.iter().map(|(id, _)| id.clone()).collect();
    let action = if enabled {
        BulkAction::Enable
    } else {
        BulkAction::Disable
    };
    let transport = ctx.transport().await?;
    let outcome = api::bulk_by_rule_ids(transport, action, &ids, false).await?;

    Ok(json!({
        "applied": true,
        "succeeded": outcome.succeeded,
        "failed": outcome.failed,
        "skipped": outcome.skipped,
        "total": outcome.total,
    }))
}

pub async fn delete(ctx: &Context, selectors: &[String]) -> Result<Value> {
    let targets = resolve_all(ctx, selectors).await?;

    let preview = Preview {
        action: format!("Delete {} rule(s)", targets.len()),
        details: targets
            .iter()
            .map(|(id, r)| format!("{id}  {}", r.name()))
            .collect(),
    };

    if !guard::check(ctx, "rules delete", &preview) {
        return Ok(json!({"applied": false, "total": targets.len()}));
    }

    // Continue after per-rule failures so the result records every deletion
    // and every rule that remains.
    let transport = ctx.transport().await?;
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    for (id, _) in &targets {
        match api::delete(transport, id).await {
            Ok(_) => deleted.push(json!({"rule_id": id})),
            Err(e) => failed.push(json!({"rule_id": id, "error": e.message})),
        }
    }

    Ok(json!({
        "applied": true,
        "deleted": deleted,
        "failed": failed,
        "total": targets.len(),
    }))
}

/// Resolve selectors and a tag to the rule IDs to export.
///
/// `None` means all rules and occurs only without selectors or a tag. Reject
/// an empty selection so a non-matching tag cannot export every rule.
async fn export_selection(
    ctx: &Context,
    selectors: &[String],
    tag: Option<&str>,
) -> Result<Option<Vec<String>>> {
    let transport = ctx.transport().await?;
    // Export reads from the stack, so every selector names a server rule.
    selection::resolve(transport, selectors, tag, &[], "export").await
}

/// Fetch, canonicalize, and sort selected rules by rule ID. Exports from an
/// unchanged stack are byte-identical for version-control review.
///
/// Write the file directly because `--format-file`, not `--format` or
/// `--json`, controls its format. With `out`, return a confirmation; `main`
/// writes it to stdout so it cannot overwrite the exported file.
pub async fn export(
    ctx: &Context,
    selectors: &[String],
    tag: Option<&str>,
    out: Option<&Path>,
    format: FileFormat,
) -> Result<Value> {
    ctx.require_credential()?;
    let selection = export_selection(ctx, selectors, tag).await?;

    let transport = ctx.transport().await?;
    let (mut rules, summary) = api::export(transport, selection.as_deref()).await?;
    for r in &mut rules {
        *r = normalize::canonical(r);
    }
    normalize::sort_rules(&mut rules);

    let text = match format {
        FileFormat::Yaml => codec::encode_yaml(&rules)?,
        FileFormat::Ndjson => codec::encode_ndjson(&rules)?,
    };

    // A requested but missing rule was deleted after selection. Report it in
    // `failed` so a short export has a nonzero exit code.
    let missing = summary.map(|s| s.missing_rules).unwrap_or_default();

    match out {
        Some(path) => {
            std::fs::write(path, &text).map_err(|e| {
                Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
            })?;
            Ok(json!({
                "exported": rules.len(),
                "path": path.display().to_string(),
                "failed": missing,
            }))
        }
        // Without `--out`, return raw content with the failure report. `main`
        // writes `text` unchanged and derives the exit code from `failed`.
        None => Ok(json!({
            "text": text,
            "failed": missing,
        })),
    }
}

/// Import a local file into the server. The guard previews the mutation and
/// uploads only with `--yes`.
///
/// With `--skip-existing`, check existing rule IDs before the preview so it
/// shows only rules that would import.
pub async fn import(
    ctx: &Context,
    path: &Path,
    overwrite: bool,
    skip_existing: bool,
) -> Result<Value> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| Error::new(ErrorKind::Error, format!("reading {}: {e}", path.display())))?;

    let rules = match FileFormat::from_path(path) {
        FileFormat::Yaml => codec::decode_yaml(&body)?,
        FileFormat::Ndjson => codec::decode_ndjson(&body)?.0,
    };
    let total = rules.len();

    let mut skipped: Vec<Value> = Vec::new();
    let mut to_upload = rules;

    if skip_existing {
        ctx.require_credential()?;
        let transport = ctx.transport().await?;
        let ids: Vec<String> = to_upload
            .iter()
            .filter_map(|r| r.rule_id().ok().map(str::to_owned))
            .collect();
        let existing = api::existing_rule_ids(transport, &ids).await?;

        let mut keep = Vec::with_capacity(to_upload.len());
        for rule in to_upload {
            match rule.rule_id() {
                Ok(id) if existing.contains(id) => {
                    skipped.push(json!({"rule_id": id, "reason": "exists"}));
                }
                _ => keep.push(rule),
            }
        }
        to_upload = keep;
    }

    let mut details: Vec<String> = to_upload
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
    let preview = Preview {
        action: format!(
            "Import {} rule(s) from {}{qualifier}",
            to_upload.len(),
            path.display()
        ),
        details,
    };

    if !guard::check(ctx, "rules import", &preview) {
        return Ok(json!({
            "applied": false,
            "total": total,
            "skipped": skipped,
            "pending": to_upload.len(),
        }));
    }

    ctx.require_credential()?;
    let transport = ctx.transport().await?;

    // Do not upload empty NDJSON when every rule already exists.
    if to_upload.is_empty() {
        return Ok(json!({
            "applied": true,
            "succeeded": 0,
            "failed": [],
            "skipped": skipped,
            "total": total,
        }));
    }

    // Kibana's import takes NDJSON regardless of the source file's format.
    let ndjson = codec::encode_ndjson(&to_upload)?;
    let response = api::import(transport, &ndjson, overwrite).await?;

    // Normalize Kibana's response to the bulk-action shape so partial imports
    // use the existing exit-code rule.
    let succeeded = response.get("success_count").cloned().unwrap_or(json!(0));
    let failed = response.get("errors").cloned().unwrap_or_else(|| json!([]));

    Ok(json!({
        "applied": true,
        "succeeded": succeeded,
        "failed": failed,
        "skipped": skipped,
        "total": total,
    }))
}

/// Maximum matched documents returned with a preview.
const MAX_SAMPLE: u32 = 100;

/// Retry once only when the first search finds no hits.
///
/// The preview already completed each invocation. A newly written alert can
/// miss the first search because of Elasticsearch's refresh interval. Retrying
/// only zero hits avoids delay for matching rules and false zero results.
async fn fetch_hits(
    transport: &elasticctl_core::Transport,
    space: &str,
    preview_id: &str,
    sample: usize,
) -> Result<api::PreviewHits> {
    let first = api::preview_hits(transport, space, preview_id, sample).await?;
    if first.total > 0 {
        return Ok(first);
    }
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    api::preview_hits(transport, space, preview_id, sample).await
}

/// Preview a rule. An existing file path wins; otherwise the source is a rule
/// ID or name from the stack. This supports unpushed local rules.
pub async fn preview(ctx: &Context, source: &str, invocations: u32, sample: u32) -> Result<Value> {
    // Preview posts to the server for both local and stack rules. Check the
    // credential first so a missing one names the profile.
    ctx.require_credential()?;
    if sample > MAX_SAMPLE {
        return Err(Error::new(
            ErrorKind::Error,
            format!("--sample must be {MAX_SAMPLE} or fewer, got {sample}"),
        ));
    }
    let path = Path::new(source);

    let rule = if path.exists() {
        let body = std::fs::read_to_string(path).map_err(|e| {
            Error::new(ErrorKind::Error, format!("reading {}: {e}", path.display()))
        })?;
        let rules = match FileFormat::from_path(path) {
            FileFormat::Yaml => codec::decode_yaml(&body)?,
            FileFormat::Ndjson => codec::decode_ndjson(&body)?.0,
        };
        rules.into_iter().next().ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                format!("{} contains no rules", path.display()),
            )
        })?
    } else {
        let rule_id = resolve::to_rule_id(ctx, source).await?;
        let transport = ctx.transport().await?;
        api::get(transport, &rule_id).await?
    };

    // The API requires an explicit end of the window it simulates over.
    let transport = ctx.transport().await?;
    let timeframe_end = now_rfc3339();
    let result = api::preview(transport, &rule, invocations, &timeframe_end).await?;

    // Preserve the preview when reading hits fails. Set `hits` to null and
    // report the error in `hits_error`.
    let (hits, hits_error, sample_hits) = match &result.preview_id {
        None => (
            Value::Null,
            json!("the server returned no preview_id"),
            Vec::new(),
        ),
        Some(preview_id) => {
            let space = ctx.resolved.profile.space.clone();
            match fetch_hits(transport, &space, preview_id, sample as usize).await {
                Ok(h) => (json!(h.total), Value::Null, h.sample),
                Err(e) => (Value::Null, json!(e.message), Vec::new()),
            }
        }
    };

    Ok(json!({
        "rule": rule.name(),
        "preview_id": result.preview_id,
        "invocations": invocations,
        "hits": hits,
        "errors": result.errors,
        "warnings": result.warnings,
        "hits_error": hits_error,
        "sample": sample_hits,
    }))
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
