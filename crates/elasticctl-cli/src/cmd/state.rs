//! The configuration-as-code loop: pull, diff, push.

use crate::context::Context;
use crate::guard::{self, Preview};
use elasticctl_api::codec::{self, Format as FileFormat};
use elasticctl_api::diff::{Change, Drift};
use elasticctl_api::model::Rule;
use elasticctl_api::normalize;
use elasticctl_api::report::{ChangeReport, ReportEntry};
use elasticctl_api::rules as api;
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn rules_dir(dir: &Path) -> PathBuf {
    dir.join("rules")
}

/// Rule ids are caller-supplied strings, not guaranteed to be UUIDs. Replace
/// anything that would escape the directory or break on a filesystem.
fn safe_filename(rule_id: &str, ext: &str) -> String {
    let safe: String = rule_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{safe}.{ext}")
}

fn read_local(dir: &Path) -> Result<Vec<Rule>> {
    let rules_path = rules_dir(dir);
    if !rules_path.exists() {
        return Ok(Vec::new());
    }

    let entries = std::fs::read_dir(&rules_path).map_err(|e| {
        Error::new(
            ErrorKind::Error,
            format!("reading {}: {e}", rules_path.display()),
        )
    })?;

    let mut rules = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| {
            Error::new(ErrorKind::Error, format!("reading {}: {e}", path.display()))
        })?;
        match FileFormat::from_path(&path) {
            FileFormat::Yaml => rules.extend(codec::decode_yaml(&body)?),
            FileFormat::Ndjson => rules.extend(codec::decode_ndjson(&body)?.0),
        }
    }

    normalize::sort_rules(&mut rules);
    Ok(rules)
}

pub async fn pull(ctx: &Context, dir: &Path, format: FileFormat) -> Result<Value> {
    ctx.require_credential()?;
    let transport = ctx.transport().await?;
    let remote = api::find_all(transport, &Default::default()).await?;

    let target = rules_dir(dir);
    std::fs::create_dir_all(&target).map_err(|e| {
        Error::new(
            ErrorKind::Error,
            format!("creating {}: {e}", target.display()),
        )
    })?;

    let ext = match format {
        FileFormat::Yaml => "yaml",
        FileFormat::Ndjson => "ndjson",
    };

    let mut written = 0;
    for rule in &remote {
        // Canonicalise before encoding: `serde_json` runs with
        // `preserve_order`, so encoding a rule straight from the API would
        // emit keys in API response order rather than sorted order, and two
        // pulls from an unchanged stack would not be byte-identical.
        let canonical = normalize::canonical(rule);
        let rule_id = canonical.rule_id()?.to_string();
        let body = match format {
            FileFormat::Yaml => codec::encode_yaml(std::slice::from_ref(&canonical))?,
            FileFormat::Ndjson => codec::encode_ndjson(std::slice::from_ref(&canonical))?,
        };
        let path = target.join(safe_filename(&rule_id, ext));
        std::fs::write(&path, body).map_err(|e| {
            Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
        })?;
        written += 1;
    }

    Ok(json!({"pulled": written, "dir": target.display().to_string()}))
}

pub async fn diff(ctx: &Context, dir: &Path) -> Result<Value> {
    ctx.require_credential()?;
    let local = read_local(dir)?;
    let transport = ctx.transport().await?;
    let remote = api::find_all(transport, &Default::default()).await?;
    let drift = Drift::compute(&local, &remote)?;

    // Unchanged rules are omitted: a diff should show what differs.
    let changes: Vec<&Change> = drift
        .changes
        .iter()
        .filter(|c| !matches!(c, Change::Unchanged { .. }))
        .collect();

    Ok(json!({
        "clean": drift.is_clean(),
        "local": local.len(),
        "remote": remote.len(),
        "changes": changes,
    }))
}

pub async fn push(ctx: &Context, dir: &Path, report_path: Option<&Path>) -> Result<Value> {
    ctx.require_credential()?;
    let local = read_local(dir)?;
    let transport = ctx.transport().await?;
    let remote = api::find_all(transport, &Default::default()).await?;
    let drift = Drift::compute(&local, &remote)?;

    let by_id = |id: &str| local.iter().find(|r| r.rule_id().ok() == Some(id)).cloned();
    let remote_by_id = |id: &str| {
        remote
            .iter()
            .find(|r| r.rule_id().ok() == Some(id))
            .cloned()
    };

    let actionable = drift.actionable();
    let details: Vec<String> = actionable
        .iter()
        .map(|c| match c {
            Change::Added { rule_id, name } => format!("{rule_id}  {name}  create"),
            Change::Modified {
                rule_id,
                name,
                fields,
            } => {
                let names: Vec<&str> = fields.iter().map(|f| f.field.as_str()).collect();
                format!("{rule_id}  {name}  update ({})", names.join(", "))
            }
            _ => String::new(),
        })
        .collect();

    let mut entries: Vec<ReportEntry> = Vec::new();

    // Remote-only rules are recorded before anything is applied, so they
    // appear in the report even on a dry run — and, since `actionable()`
    // deliberately excludes `RemoteOnly`, they can never reach the loop
    // below that actually mutates the stack. Local absence is not a delete
    // instruction: push never deletes a remote rule.
    for c in &drift.changes {
        if let Change::RemoteOnly { rule_id, name } = c {
            entries.push(ReportEntry {
                rule_id: rule_id.clone(),
                name: name.clone(),
                action: "skipped_remote_only".into(),
                before: remote_by_id(rule_id).map(|r| normalize::canonical(&r).into_value()),
                after: None,
                applied: false,
                error: None,
            });
        }
    }

    let preview = Preview {
        action: format!(
            "Push {} rule change(s) from {}",
            actionable.len(),
            dir.display()
        ),
        details,
    };

    let applying = guard::check(ctx, &preview);

    if applying {
        for c in &actionable {
            let (rule_id, name, action) = match c {
                Change::Added { rule_id, name } => (rule_id.clone(), name.clone(), "create"),
                Change::Modified { rule_id, name, .. } => (rule_id.clone(), name.clone(), "update"),
                // `actionable()` only yields Added/Modified.
                _ => continue,
            };

            let Some(desired) = by_id(&rule_id) else {
                continue;
            };
            let before = remote_by_id(&rule_id).map(|r| normalize::canonical(&r).into_value());

            // A failure on one rule must not abort the rest: a partial push
            // still has to be fully auditable, so every outcome is recorded
            // rather than propagated with `?`.
            let outcome = if action == "create" {
                api::create(transport, &desired).await
            } else {
                api::update(transport, &desired).await
            };

            match outcome {
                Ok(applied) => entries.push(ReportEntry {
                    rule_id,
                    name,
                    action: action.into(),
                    before,
                    after: Some(normalize::canonical(&applied).into_value()),
                    applied: true,
                    error: None,
                }),
                Err(e) => entries.push(ReportEntry {
                    rule_id,
                    name,
                    action: action.into(),
                    before,
                    after: None,
                    applied: false,
                    error: Some(e.message),
                }),
            }
        }
    }

    let report = ChangeReport {
        profile: ctx.resolved.name.clone(),
        host: ctx.resolved.profile.host(),
        space: ctx.resolved.profile.space.clone(),
        applied: applying,
        entries,
    };

    if let Some(path) = report_path {
        let body = serde_json::to_string_pretty(&report)
            .map_err(|e| Error::new(ErrorKind::Error, format!("encoding report: {e}")))?;
        std::fs::write(path, body).map_err(|e| {
            Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
        })?;
    }

    let (created, updated, skipped, failed) = report.counts();
    Ok(json!({
        "applied": applying,
        "created": created,
        "updated": updated,
        "skipped_remote_only": skipped,
        "failed": failed,
    }))
}
