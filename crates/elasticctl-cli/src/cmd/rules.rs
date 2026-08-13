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
/// `codec::decode_yaml`/`decode_ndjson` only reject a rule that is missing
/// its `rule_id` *key* — `Rule::from_value` does not check that the value is
/// a string, so a hand-editing slip like an unquoted `rule_id: 123` decodes
/// without error. `rule_id()` is what actually catches that, so every rule
/// is re-checked here rather than trusting decode success to mean "usable".
/// Every rule is checked, not just the first bad one, so a mixed file names
/// every failing index at once instead of stopping at the first.
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

/// Fetch every rule, canonicalize it, and sort by rule_id. Two exports from
/// an unchanged stack are byte-identical, which is what makes the file
/// reviewable in version control.
///
/// The write happens here, directly, rather than through the generic render
/// path: `--format`/`--json` govern how a command's *report* is rendered and
/// must never reshape the exported rule file itself (`--format-file` owns
/// that). When `out` is given, the file is written now and a small
/// confirmation is returned in its place — `main` redirects that
/// confirmation to stdout rather than letting it flow back through the same
/// `--out` a second time, which would clobber the file just written.
pub async fn export(ctx: &Context, out: Option<&Path>, format: FileFormat) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let (mut rules, _summary) = api::export(transport).await?;
    for r in &mut rules {
        *r = normalize::canonical(r);
    }
    normalize::sort_rules(&mut rules);

    let text = match format {
        FileFormat::Yaml => codec::encode_yaml(&rules)?,
        FileFormat::Ndjson => codec::encode_ndjson(&rules)?,
    };

    match out {
        Some(path) => {
            std::fs::write(path, &text).map_err(|e| {
                Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
            })?;
            Ok(json!({"exported": rules.len(), "path": path.display().to_string()}))
        }
        // Without --out there is nowhere else for the content to go: return
        // it as the payload. `main` recognizes this shape and writes the raw
        // text to stdout, bypassing `--format`/`--json` so the exported file
        // content is never re-encoded.
        None => Ok(Value::String(text)),
    }
}

/// Local file to server. Guarded: it mutates, so it previews from the file's
/// own contents (no server round trip needed for that) and only uploads once
/// `--yes` is passed.
pub async fn import(ctx: &Context, path: &Path, overwrite: bool) -> Result<Value> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| Error::new(ErrorKind::Error, format!("reading {}: {e}", path.display())))?;

    let rules = match FileFormat::from_path(path) {
        FileFormat::Yaml => codec::decode_yaml(&body)?,
        FileFormat::Ndjson => codec::decode_ndjson(&body)?.0,
    };

    let preview = Preview {
        action: format!(
            "Import {} rule(s) from {}{}",
            rules.len(),
            path.display(),
            if overwrite {
                ", overwriting existing"
            } else {
                ""
            }
        ),
        details: rules
            .iter()
            .map(|r| format!("{}  {}", r.rule_id().unwrap_or(""), r.name()))
            .collect(),
    };

    if !guard::check(ctx, "rules import", &preview) {
        return Ok(json!({"applied": false, "total": rules.len()}));
    }

    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    // Kibana's import takes NDJSON regardless of the source file's format.
    let ndjson = codec::encode_ndjson(&rules)?;
    let response = api::import(transport, &ndjson, overwrite).await?;

    // Kibana reports success_count/rules_count/errors, not the
    // succeeded/failed/total shape the bulk-action endpoint uses. Translate
    // onto that same shared shape so a partial failure trips
    // render::exit_code_for_value's existing convention instead of a new one.
    let succeeded = response.get("success_count").cloned().unwrap_or(json!(0));
    let failed = response.get("errors").cloned().unwrap_or_else(|| json!([]));
    let total = response
        .get("rules_count")
        .cloned()
        .unwrap_or_else(|| json!(rules.len()));

    Ok(json!({
        "applied": true,
        "succeeded": succeeded,
        "failed": failed,
        "total": total,
    }))
}

/// Preview a rule. The selector is a file path when one exists on disk,
/// otherwise a rule_id or name on the stack — previewing an unpushed local
/// rule is the main reason this command exists.
pub async fn preview(ctx: &Context, source: &str, invocations: u32) -> Result<Value> {
    // Previewing always ends in a POST to the server, whether the rule body
    // comes from disk or from the stack, so check the credential up front —
    // the same shape `get`/`list`/`export` use to fail with a message naming
    // the profile, instead of the generic one `transport()` would give.
    ctx.require_credential()?;
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

    Ok(json!({
        "rule": rule.name(),
        "preview_id": result.preview_id,
        "invocations": invocations,
        "errors": result.errors,
        "warnings": result.warnings,
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
