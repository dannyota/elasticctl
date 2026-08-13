//! The rules command group.

use crate::context::Context;
use crate::guard::{self, Preview};
use crate::resolve;
use elasticctl_api::codec::{self, Format as FileFormat};
use elasticctl_api::model::{Rule, server_defaults};
use elasticctl_api::normalize;
use elasticctl_api::rules::{self as api, BulkAction, RuleFilter};
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Value, json};
use std::path::Path;

/// The summary shape shown by `rules list`. Full rule bodies are available
/// through `rules get` and `rules export`.
///
/// A rule with an unreadable `rule_id` is a server-side anomaly, not
/// something the operator can act on the way they can a bad local file — so
/// it is flagged visibly (`resolve::UNREADABLE_RULE_ID`) rather than either
/// hidden behind a blank string or failing the whole listing over one row.
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
    // A live connection is required below; check the credential first so a
    // missing one produces its profile-naming message, not the generic one
    // `Transport::new` would give.
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

/// Local only. Never contacts a server, so it works offline and in CI.
///
/// Both codec paths now reject a rule whose `rule_id` is absent or not a
/// string, naming the line or the index, so a file that decodes has usable
/// identities. The per-rule check below is kept as defence — `Rule` can still
/// be built through its derived `Deserialize`, which skips that validation —
/// and because this loop also has to report which server defaults each rule
/// would take on. Every rule is checked, not just the first bad one, so a
/// mixed file names every failing index at once.
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
                // Show what a sparse file becomes, so the operator is not
                // surprised by fields they never wrote.
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
            // Do not emit an empty-string rule_id for this entry: a blank
            // identity next to "valid": true is exactly the false clean
            // bill of health this check exists to prevent.
            Err(e) => failures.push(format!("rule at index {i}: {}", e.message)),
        }
    }

    if !failures.is_empty() {
        // One bad rule invalidates the whole file — reported the same way a
        // decode failure already is: a single classified error, not a
        // partial report with "valid": false buried in a success payload.
        return Err(Error::new(ErrorKind::Error, failures.join("; ")));
    }

    Ok(json!({"valid": true, "count": rules.len(), "rules": reports}))
}

/// Resolve every selector before previewing, so the preview reflects reality
/// and an unresolvable selector fails before anything changes.
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

    // One function serves both `enable` and `disable`; the path passed to the
    // guard is derived from the same `enabled` flag that already chose the
    // verb, so the string cannot lie about which command is mutating.
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

    // Delete one at a time, continuing past a per-rule failure, so a partial
    // failure reports exactly which rules survived and which did not — an
    // early `?` return here would drop everything already deleted on the
    // floor, leaving the operator unable to tell what state the rules are
    // actually in.
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

/// Turn selectors and a tag into the exact set of rule ids to export.
///
/// `None` means "the whole space" and is only ever produced by asking for
/// nothing. An empty *selection* is refused instead: a tag that matches
/// nothing quietly becoming "everything" is the same failure mode an unscoped
/// bulk action would be.
async fn export_selection(
    ctx: &Context,
    selectors: &[String],
    tag: Option<&str>,
) -> Result<Option<Vec<String>>> {
    if selectors.is_empty() && tag.is_none() {
        return Ok(None);
    }

    let mut ids: Vec<String> = Vec::new();
    for s in selectors {
        ids.push(resolve::to_rule_id(ctx, s).await?);
    }

    // The tag's contribution is tracked separately: a tag that matched
    // nothing must not disappear into a union that a selector rescued.
    let mut tag_matched = false;
    if let Some(tag) = tag {
        let transport = ctx.transport().await?;
        let filter = RuleFilter {
            tag: Some(tag.to_string()),
            ..Default::default()
        };
        for rule in api::find_all(transport, &filter).await? {
            tag_matched = true;
            ids.push(rule.rule_id()?.to_string());
        }
    }

    ids.sort();
    ids.dedup();

    // A `--tag` that matched nothing is a miss worth reporting even when a
    // selector resolved and rescued the union: a typo'd tag must not silently
    // shrink the export. This is also the empty-selection refusal — with no
    // selectors, the tag's zero matches leave `ids` empty.
    if let Some(t) = tag
        && !tag_matched
    {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("No rules matched tag '{t}'; nothing to export"),
        ));
    }

    // Defensive: unreachable today — a selector either resolves or fails, and
    // the whole-space case returned `Ok(None)` above — but the message must
    // name what was asked for, not emit a blank selector.
    if ids.is_empty() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!(
                "No rules matched the selector(s) '{}'; nothing to export",
                selectors.join("', '")
            ),
        ));
    }
    Ok(Some(ids))
}

/// Fetch the selected rules, canonicalize them, and sort by rule_id. Two
/// exports from an unchanged stack are byte-identical, which is what makes the
/// file reviewable in version control.
///
/// The write happens here, directly, rather than through the generic render
/// path: `--format`/`--json` govern how a command's *report* is rendered and
/// must never reshape the exported rule file itself (`--format-file` owns
/// that). When `out` is given, the file is written now and a small
/// confirmation is returned in its place — `main` redirects that confirmation
/// to stdout rather than letting it flow back through the same `--out` a
/// second time, which would clobber the file just written.
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

    // A rule the server was asked for and did not return was deleted between
    // selection and export. Reporting a short export as a success would hide
    // that; `failed` is the shape `render::exit_code_for_value` already reads.
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
        // Without --out there is nowhere else for the content to go: return
        // it alongside the same `failed` report the --out arm carries, so a
        // short export still trips `exit_code_for_value`. `main` recognizes
        // the `text` field, writes it raw to stdout (bypassing
        // `--format`/`--json` so the exported file content is never
        // re-encoded), and reads the exit code from the `failed` field.
        None => Ok(json!({
            "text": text,
            "failed": missing,
        })),
    }
}

/// Local file to server. Guarded: it mutates, so it previews before it
/// uploads and only uploads once `--yes` is passed.
///
/// With `--skip-existing`, the server is asked which of the file's rule ids
/// already exist *before* the preview runs. That is what makes the dry run
/// honest — it previously listed every rule as if it would import, which is
/// exactly the warning an operator re-running an import needed.
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

    // Every rule in the file already exists: there is nothing to upload, and
    // posting an empty NDJSON would be a request that can only fail.
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

    // Kibana reports success_count/rules_count/errors, not the
    // succeeded/failed/total shape the bulk-action endpoint uses. Translate
    // onto that same shared shape so a partial failure trips
    // render::exit_code_for_value's existing convention instead of a new one.
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

/// A sample larger than this is refused. The command exists to answer "did it
/// match"; dumping a thousand alert documents answers something else, slowly.
const MAX_SAMPLE: u32 = 100;

/// One extra attempt, and only when the first sees nothing.
///
/// Every simulated invocation has completed by the time the preview responds —
/// each has its own `logs` entry — so there is nothing to poll. What remains
/// is Elasticsearch's one-second default refresh interval: alerts written
/// microseconds ago can legitimately be invisible to the first search.
/// Retrying only on a zero means a rule that matched pays nothing, and a rule
/// that really matched nothing pays one second rather than reporting a false
/// zero.
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

/// Preview a rule. The selector is a file path when one exists on disk,
/// otherwise a rule_id or name on the stack — previewing an unpushed local
/// rule is the main reason this command exists.
pub async fn preview(ctx: &Context, source: &str, invocations: u32, sample: u32) -> Result<Value> {
    // Previewing always ends in a POST to the server, whether the rule body
    // comes from disk or from the stack, so check the credential up front —
    // the same shape `get`/`list`/`export` use to fail with a message naming
    // the profile, instead of the generic one `transport()` would give.
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

    // A failed read degrades: `hits` becomes null and `hits_error` says why,
    // while the preview's own id, errors, and warnings are reported as before.
    // Preview is a diagnostic — losing the count must not lose the run.
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
    // Formatted without pulling in a date library; the API accepts UTC ISO-8601.
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

/// Howard Hinnant's days-from-civil inverse. Avoids a dependency for the one
/// timestamp this command needs.
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

    /// Every epoch-day input was independently computed with
    /// `date -u -d '<date>' +%s`, divided by 86400. A wrong-but-plausible
    /// sign flip in `div_euclid`/`rem_euclid` or an off-by-one in the
    /// `era`/`yoe`/`doy` arithmetic would otherwise pass the whole suite
    /// silently — the only symptom would be `timeframeEnd` quietly shifting
    /// the window a preview evaluates over.
    #[test]
    fn civil_from_days_matches_independently_computed_epoch_days() {
        let cases = [
            (0, (1970, 1, 1), "epoch"),
            (19782, (2024, 2, 29), "leap day"),
            (11017, (2000, 3, 1), "century leap year (2000 % 400 == 0)"),
            (20818, (2026, 12, 31), "year end"),
            (20819, (2027, 1, 1), "year rollover"),
            // 2100 is divisible by 100 but not 400, so it is not a leap
            // year: day 47540 is 2100-02-28, and 2100-03-01 is 47541, not
            // 47540. (Verified with `date -u -d 2100-03-01 +%s`; a table
            // supplied during review had this one off by a day.)
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

    /// The API rejects any `timeframeEnd` that is not exactly this shape, so
    /// the format string itself — not just the underlying instant — is
    /// pinned here.
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
