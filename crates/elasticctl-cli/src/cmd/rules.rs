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

    if !guard::check(ctx, &preview) {
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

    if !guard::check(ctx, &preview) {
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
