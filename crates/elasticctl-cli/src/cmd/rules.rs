//! The rules command group.

use crate::context::Context;
use crate::resolve;
use elasticctl_api::codec::{self, Format as FileFormat};
use elasticctl_api::model::{Rule, server_defaults};
use elasticctl_api::normalize;
use elasticctl_api::rules::{self as api, RuleFilter};
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Value, json};
use std::path::Path;

/// The summary shape shown by `rules list`. Full rule bodies are available
/// through `rules get` and `rules export`.
fn summarize(r: &Rule) -> Value {
    json!({
        "rule_id": r.rule_id().unwrap_or(""),
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
pub fn validate(path: &Path) -> Result<Value> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| Error::new(ErrorKind::Error, format!("reading {}: {e}", path.display())))?;

    let rules = match FileFormat::from_path(path) {
        FileFormat::Yaml => codec::decode_yaml(&body)?,
        FileFormat::Ndjson => codec::decode_ndjson(&body)?.0,
    };

    let defaults = server_defaults();
    let reports: Vec<Value> = rules
        .iter()
        .map(|r| {
            // Show what a sparse file becomes, so the operator is not
            // surprised by fields they never wrote.
            let mut applied: Vec<&String> = defaults
                .keys()
                .filter(|k| !r.as_map().contains_key(*k))
                .collect();
            applied.sort();
            json!({
                "rule_id": r.rule_id().unwrap_or(""),
                "name": r.name(),
                "type": r.rule_type(),
                "defaults_applied": applied,
            })
        })
        .collect();

    Ok(json!({"valid": true, "count": rules.len(), "rules": reports}))
}
