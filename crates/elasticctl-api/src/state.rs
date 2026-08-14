//! State orchestration: pull, diff, and push.

use crate::codec::{self, Format};
use crate::diff::{Change, Drift};
use crate::model::Rule;
use crate::normalize;
use crate::report::{ChangeReport, ReportEntry};
use crate::rules as api;
use crate::selection;
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The resolved deployment the change report records as its target.
///
/// Plain values, not `Context` or clap types, so `-api` may take them directly.
/// The caller builds this from its resolved profile.
#[derive(Debug, Clone, PartialEq)]
pub struct StackIdentity {
    pub profile: String,
    pub host: String,
    pub space: String,
}

/// The report `pull` renders.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PullReport {
    pub pulled: usize,
    pub dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<usize>,
}

/// The report `diff` renders.
///
/// Field order is the serialized JSON key order and is contractual: the root
/// `Cargo.toml` enables `serde_json`'s `preserve_order`, so reordering these
/// fields would silently change rendered output.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiffReport {
    pub clean: bool,
    pub local: usize,
    pub remote: usize,
    pub changes: Vec<Change>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_total: Option<usize>,
}

/// The summary `push` renders.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PushReport {
    pub applied: bool,
    pub created: usize,
    pub updated: usize,
    pub skipped_remote_only: usize,
    pub failed: usize,
    pub pending: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_total: Option<usize>,
}

/// What `plan_push` computed and `apply_push` performs.
///
/// The preview fields feed the caller's guard banner; `report` is the change
/// ticket; `summary` is the JSON report.
#[derive(Debug, Clone)]
pub struct PushPlan {
    pub preview_action: String,
    pub preview_details: Vec<String>,
    pub report: ChangeReport,
    pub summary: PushReport,
    /// The exact rules the preview described, resolved once at plan time so
    /// `apply_push` never re-reads the mirror after the guard.
    desired: BTreeMap<String, Rule>,
}

fn rules_dir(dir: &Path) -> PathBuf {
    dir.join("rules")
}

/// Rule IDs are caller-supplied strings. Replace characters that could escape
/// the directory or are unsafe in filenames.
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

/// Whether this scan should parse a directory entry as a rule file. Unlike
/// `FileFormat::from_path`, ignore unknown extensions because rule directories
/// commonly contain files such as `README.md` and `.DS_Store`.
fn is_rule_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("ndjson") | Some("json") | Some("yaml") | Some("yml")
    )
}

/// Read the local rule mirror under `dir/rules`.
pub fn read_local(dir: &Path) -> Result<Vec<Rule>> {
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
        match Format::from_path(&path) {
            Format::Yaml => rules.extend(codec::decode_yaml(&body)?),
            Format::Ndjson => rules.extend(codec::decode_ndjson(&body)?.0),
        }
    }

    normalize::sort_rules(&mut rules);
    Ok(rules)
}

/// Rules selected for a scoped run.
///
/// `None` in `rule_ids` means no selector was given and the command acts on
/// all rules.
struct Scope {
    rule_ids: Option<Vec<String>>,
    local_total: usize,
}

impl Scope {
    fn is_scoped(&self) -> bool {
        self.rule_ids.is_some()
    }

    fn selected(&self) -> usize {
        self.rule_ids.as_ref().map(Vec::len).unwrap_or(0)
    }

    /// Keep only scoped rules. An unscoped run keeps all rules.
    fn narrow(&self, rules: Vec<Rule>) -> Vec<Rule> {
        match &self.rule_ids {
            None => rules,
            Some(ids) => rules
                .into_iter()
                .filter(|r| r.rule_id().is_ok_and(|id| ids.iter().any(|s| s == id)))
                .collect(),
        }
    }

    /// Read only the scoped remote rules. A scoped run uses filtered `_find`
    /// requests rather than reading the full corpus.
    async fn remote(&self, t: &Transport) -> Result<Vec<Rule>> {
        match &self.rule_ids {
            None => api::find_all(t, &Default::default()).await,
            Some(ids) => api::find_by_rule_ids(t, ids).await,
        }
    }

    /// Describe the scope for the guard banner. Return nothing when unscoped.
    fn describe(&self) -> String {
        match &self.rule_ids {
            None => String::new(),
            Some(ids) => format!(
                " (selection: {} of {} local rules)",
                ids.len(),
                self.local_total
            ),
        }
    }
}

/// Resolve selectors against local rules, then the stack.
///
/// `local` is empty for `pull`, which reads from the stack and whose selectors
/// therefore name stack rules.
async fn scope_of(
    t: &Transport,
    selectors: &[String],
    tag: Option<&str>,
    local: &[Rule],
    noun: &str,
) -> Result<Scope> {
    let rule_ids = selection::resolve(t, selectors, tag, local, noun).await?;
    Ok(Scope {
        rule_ids,
        local_total: local.len(),
    })
}

pub async fn pull(
    t: &Transport,
    dir: &Path,
    format: Format,
    selectors: &[String],
    tag: Option<&str>,
) -> Result<PullReport> {
    // Pull reads from the stack, so selectors name stack rules. The directory
    // may not exist yet.
    let scope = scope_of(t, selectors, tag, &[], "pull").await?;
    let mut remote = scope.remote(t).await?;
    // Sort unstable server output so collision reports and writes are stable.
    normalize::sort_rules(&mut remote);

    let ext = match format {
        Format::Yaml => "yaml",
        Format::Ndjson => "ndjson",
    };

    // `safe_filename` prevents path traversal but can map distinct rule IDs to
    // one filename (for example, `a/b` and `a_b`). A collision would silently
    // omit a rule from the mirror.
    //
    // Plan all filenames before writing. Failing after a write would leave a
    // partial directory and hide later collisions.
    let mut claimed: BTreeMap<String, String> = BTreeMap::new();
    let mut collisions: Vec<String> = Vec::new();
    let mut planned: Vec<(String, Rule)> = Vec::with_capacity(remote.len());

    for rule in &remote {
        // Canonicalize before encoding. `serde_json` preserves response key
        // order, which would otherwise make unchanged pulls differ.
        let canonical = normalize::canonical(rule);
        let rule_id = canonical.rule_id()?.to_string();
        let filename = safe_filename(&rule_id, ext);

        match claimed.get(&filename) {
            Some(other) => collisions.push(format!(
                "\"{other}\" and \"{rule_id}\" both sanitise to \"{filename}\""
            )),
            None => {
                claimed.insert(filename.clone(), rule_id);
                planned.push((filename, canonical));
            }
        }
    }

    if !collisions.is_empty() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "{} filename collision(s); rename one rule id in each pair: {}",
                collisions.len(),
                collisions.join("; ")
            ),
        ));
    }

    let target = rules_dir(dir);
    std::fs::create_dir_all(&target).map_err(|e| {
        Error::new(
            ErrorKind::Error,
            format!("creating {}: {e}", target.display()),
        )
    })?;

    for (filename, canonical) in &planned {
        let body = match format {
            Format::Yaml => codec::encode_yaml(std::slice::from_ref(canonical))?,
            Format::Ndjson => codec::encode_ndjson(std::slice::from_ref(canonical))?,
        };
        let path = target.join(filename);
        std::fs::write(&path, body).map_err(|e| {
            Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
        })?;
    }

    Ok(PullReport {
        pulled: planned.len(),
        dir: target.display().to_string(),
        selected: scope.is_scoped().then(|| scope.selected()),
    })
}

pub async fn diff(
    t: &Transport,
    dir: &Path,
    selectors: &[String],
    tag: Option<&str>,
) -> Result<DiffReport> {
    let local_all = read_local(dir)?;
    let scope = scope_of(t, selectors, tag, &local_all, "compare").await?;
    let local = scope.narrow(local_all);
    let remote = scope.remote(t).await?;
    let drift = Drift::compute(&local, &remote)?;

    // Omit unchanged rules so the diff shows only differences.
    let changes: Vec<Change> = drift
        .changes
        .iter()
        .filter(|c| !matches!(c, Change::Unchanged { .. }))
        .cloned()
        .collect();

    Ok(DiffReport {
        clean: drift.is_clean(),
        local: local.len(),
        remote: remote.len(),
        changes,
        selected: scope.is_scoped().then(|| scope.selected()),
        local_total: scope.is_scoped().then_some(scope.local_total),
    })
}

/// Compute the push preview and dry-run report without mutating the stack.
pub async fn plan_push(
    t: &Transport,
    dir: &Path,
    selectors: &[String],
    tag: Option<&str>,
    identity: &StackIdentity,
) -> Result<PushPlan> {
    let local_all = read_local(dir)?;
    // Resolve locally first because disk-only rules have no remote ID and may
    // be created by a scoped push.
    let scope = scope_of(t, selectors, tag, &local_all, "apply").await?;
    let local = scope.narrow(local_all);
    let remote = scope.remote(t).await?;
    let drift = Drift::compute(&local, &remote)?;

    let by_id = |id: &str| local.iter().find(|r| r.rule_id().ok() == Some(id)).cloned();
    let remote_by_id = |id: &str| {
        remote
            .iter()
            .find(|r| r.rule_id().ok() == Some(id))
            .cloned()
    };

    let actionable = drift.actionable();
    let preview_details: Vec<String> = actionable
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
    let mut desired: BTreeMap<String, Rule> = BTreeMap::new();

    // Record remote-only rules before applying changes, including in dry runs.
    // `actionable()` excludes them because push never deletes remote rules.
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

    // Record every actionable change as a pending entry. The report and JSON
    // `pending` count describe proposed creates and updates.
    for c in &actionable {
        let (rule_id, name, action) = match c {
            Change::Added { rule_id, name } => (rule_id.clone(), name.clone(), "create"),
            Change::Modified { rule_id, name, .. } => (rule_id.clone(), name.clone(), "update"),
            // `actionable()` yields only Added and Modified changes.
            _ => continue,
        };

        let Some(desired_rule) = by_id(&rule_id) else {
            continue;
        };
        let before = remote_by_id(&rule_id).map(|r| normalize::canonical(&r).into_value());

        desired.insert(rule_id.clone(), desired_rule.clone());

        entries.push(ReportEntry {
            rule_id,
            name,
            action: action.into(),
            before,
            after: Some(normalize::canonical(&desired_rule).into_value()),
            applied: false,
            error: None,
        });
    }

    // Name the selection so a scoped preview differs from a full preview.
    let preview_action = format!(
        "Push {} rule change(s) from {}{}",
        actionable.len(),
        dir.display(),
        scope.describe()
    );

    let report = ChangeReport {
        profile: identity.profile.clone(),
        host: identity.host.clone(),
        space: identity.space.clone(),
        applied: false,
        entries,
    };
    let summary = push_summary(
        &report,
        scope.is_scoped().then(|| scope.selected()),
        scope.is_scoped().then_some(scope.local_total),
    );

    Ok(PushPlan {
        preview_action,
        preview_details,
        report,
        summary,
        desired,
    })
}

/// Perform the mutations `plan_push` proposed.
///
/// The caller runs this only after its guard approves; a caller that never
/// calls it has performed a dry run by construction. It reads only from the
/// plan, never the mirror, so the preview and the apply cannot diverge.
pub async fn apply_push(t: &Transport, mut plan: PushPlan) -> Result<PushPlan> {
    let mut entries = Vec::with_capacity(plan.report.entries.len());
    for entry in plan.report.entries {
        if entry.action != "create" && entry.action != "update" {
            // `skipped_remote_only` entries pass through untouched.
            entries.push(entry);
            continue;
        }

        let Some(desired) = plan.desired.get(&entry.rule_id) else {
            // `plan_push` records a desired rule for every actionable change,
            // so this is defensive. Record the inconsistency as a failure
            // rather than dropping the planned mutation from the report.
            let missing = entry.rule_id.clone();
            entries.push(ReportEntry {
                rule_id: entry.rule_id,
                name: entry.name,
                action: entry.action,
                before: entry.before,
                after: None,
                applied: false,
                error: Some(format!("the plan has no desired rule for \"{missing}\"")),
            });
            continue;
        };
        let before = entry.before;
        let is_create = entry.action == "create";

        // Continue after a per-rule failure so the report records every
        // outcome.
        let outcome = if is_create {
            api::create(t, desired).await
        } else {
            api::update(t, desired).await
        };

        match outcome {
            Ok(applied) => entries.push(ReportEntry {
                rule_id: entry.rule_id,
                name: entry.name,
                action: entry.action,
                before,
                after: Some(normalize::canonical(&applied).into_value()),
                applied: true,
                error: None,
            }),
            Err(e) => entries.push(ReportEntry {
                rule_id: entry.rule_id,
                name: entry.name,
                action: entry.action,
                before,
                after: None,
                applied: false,
                error: Some(e.message),
            }),
        }
    }

    let (selected, local_total) = (plan.summary.selected, plan.summary.local_total);
    plan.report.entries = entries;
    plan.report.applied = true;
    plan.summary = push_summary(&plan.report, selected, local_total);
    Ok(plan)
}

fn push_summary(
    report: &ChangeReport,
    selected: Option<usize>,
    local_total: Option<usize>,
) -> PushReport {
    let (created, updated, skipped, failed) = report.counts();
    PushReport {
        applied: report.applied,
        created,
        updated,
        skipped_remote_only: skipped,
        failed,
        pending: report.pending(),
        selected,
        local_total,
    }
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

    // Rule directories commonly contain a README. Do not parse it as a rule
    // or fail `diff` and `push`.
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
