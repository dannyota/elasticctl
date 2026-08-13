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
use std::collections::HashMap;
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

/// Whether a directory entry is one this scan should attempt to parse as a
/// rule file. Deliberately narrower than `FileFormat::from_path`, which
/// defaults an unrecognised extension to NDJSON — correct for `--out`/
/// `--path`, where the user named the file deliberately, but wrong here: the
/// whole reason `pull` writes one file per rule is per-rule git history,
/// which makes a `README.md` or a stray `.DS_Store` living next to the rule
/// files an expected occurrence, not an authoring mistake to fail on.
fn is_rule_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("ndjson") | Some("json") | Some("yaml") | Some("yml")
    )
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
        if !path.is_file() || !is_rule_file(&path) {
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
    // `safe_filename` correctly closes path traversal by replacing every
    // character outside `[A-Za-z0-9_-]` with `_`, but that same replacement
    // can make two distinct rule ids collide on one filename (e.g. "a/b" and
    // "a_b" both sanitise to "a_b"). An unnoticed collision would silently
    // drop a rule from the local mirror while `written` kept counting both —
    // the same class of authoring conflict `Drift::compute` already refuses
    // to paper over for a duplicate `rule_id`, so it is refused here too.
    let mut claimed: HashMap<String, String> = HashMap::new();
    for rule in &remote {
        // Canonicalise before encoding: `serde_json` runs with
        // `preserve_order`, so encoding a rule straight from the API would
        // emit keys in API response order rather than sorted order, and two
        // pulls from an unchanged stack would not be byte-identical.
        let canonical = normalize::canonical(rule);
        let rule_id = canonical.rule_id()?.to_string();
        let filename = safe_filename(&rule_id, ext);

        if let Some(other_id) = claimed.get(&filename) {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "rule ids \"{other_id}\" and \"{rule_id}\" both sanitise to the filename \"{filename}\"; rename one of them"
                ),
            ));
        }
        claimed.insert(filename.clone(), rule_id.clone());

        let body = match format {
            FileFormat::Yaml => codec::encode_yaml(std::slice::from_ref(&canonical))?,
            FileFormat::Ndjson => codec::encode_ndjson(std::slice::from_ref(&canonical))?,
        };
        let path = target.join(&filename);
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

    let applying = guard::check(ctx, "state push", &preview);

    // Every actionable change gets an entry regardless of `applying`: the
    // report exists to record what was *proposed*, not only what was
    // applied, so a dry run must not silently omit pending creates and
    // updates from `--report` (nor from the JSON summary's `pending` count
    // below) — a script piping `state push --json` has no other way to
    // learn what would change.
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

        if !applying {
            entries.push(ReportEntry {
                rule_id,
                name,
                action: action.into(),
                before,
                after: Some(normalize::canonical(&desired).into_value()),
                applied: false,
                error: None,
            });
            continue;
        }

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
    let pending = report.pending();
    Ok(json!({
        "applied": applying,
        "created": created,
        "updated": updated,
        "skipped_remote_only": skipped,
        "failed": failed,
        "pending": pending,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_rule(dir: &Path, filename: &str, rule_id: &str) {
        std::fs::write(
            dir.join(filename),
            format!("{{\"rule_id\":\"{rule_id}\",\"name\":\"{rule_id}\",\"type\":\"query\"}}\n"),
        )
        .unwrap();
    }

    #[test]
    fn is_rule_file_accepts_the_four_recognised_extensions_and_rejects_others() {
        for ext in ["ndjson", "json", "yaml", "yml"] {
            assert!(is_rule_file(Path::new(&format!("a.{ext}"))), "{ext}");
        }
        for ext in ["md", "txt", "DS_Store", "ndjson.bak"] {
            assert!(!is_rule_file(Path::new(&format!("a.{ext}"))), "{ext}");
        }
        assert!(!is_rule_file(Path::new("noextension")));
    }

    // A README lives next to per-rule files as a matter of course — the
    // whole reason `pull` writes one file per rule is per-rule git history,
    // and a directory kept in git tends to grow a README. It must not turn
    // `diff`/`push` into an "invalid JSON on line 1" failure.
    #[test]
    fn read_local_skips_non_rule_files_and_reads_the_valid_ones() {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        write_rule(&rules, "a.ndjson", "a");
        std::fs::write(rules.join("README.md"), "not a rule\n").unwrap();
        std::fs::write(rules.join("notes.txt"), "also not a rule\n").unwrap();
        std::fs::create_dir_all(rules.join(".hidden")).unwrap();

        let found = read_local(dir.path()).unwrap();
        assert_eq!(found.len(), 1, "only the .ndjson file should be read");
        assert_eq!(found[0].rule_id().unwrap(), "a");
    }

    #[test]
    fn read_local_returns_empty_for_a_directory_of_only_unrecognised_files() {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(rules.join("README.md"), "not a rule\n").unwrap();
        std::fs::write(rules.join("notes.txt"), "also not a rule\n").unwrap();

        let found = read_local(dir.path()).unwrap();
        assert!(found.is_empty());
    }
}
