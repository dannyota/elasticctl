//! State orchestration: pull, diff, and push.
//!
//! Split by concern: report types, mirror file I/O, and one module per command.
//! `mod.rs` holds the shared selection scope and the filename helpers every
//! command uses.

mod diff;
mod mirror;
mod pull;
mod push;
mod reports;

pub use diff::diff;
pub use mirror::{read_local, read_mirror};
pub use pull::pull;
pub use push::{PushPlan, apply_push, plan_push};
pub use reports::{
    DanglingPointer, DiffReport, ExceptionDrift, ListChange, Mirror, PullReport, PushReport,
    StackIdentity,
};

use crate::model::{ListKey, Rule};
use crate::selection;
use elasticctl_core::{Result, Transport};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn rules_dir(dir: &Path) -> PathBuf {
    dir.join("rules")
}

fn exceptions_dir(dir: &Path) -> PathBuf {
    dir.join("exceptions")
}

/// Rule IDs are caller-supplied strings. Replace characters that could escape
/// the directory or are unsafe in filenames.
fn safe_filename(id: &str, ext: &str) -> String {
    let safe: String = id
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

/// Whether this scan should parse a directory entry as a rule or list file.
/// Unlike `FileFormat::from_path`, ignore unknown extensions because mirror
/// directories commonly contain files such as `README.md` and `.DS_Store`.
fn is_rule_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("ndjson") | Some("json") | Some("yaml") | Some("yml")
    )
}

/// The `ListKey` of every exception list the rules reference, deduplicated.
fn referenced_keys(rules: &[Rule]) -> BTreeSet<ListKey> {
    let mut wanted = BTreeSet::new();
    for rule in rules {
        for reference in crate::model::exception_refs(rule) {
            wanted.insert(ListKey {
                list_id: reference.list_id,
                namespace_type: reference.namespace_type,
            });
        }
    }
    wanted
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
            None => crate::rules::find_all(t, &Default::default()).await,
            Some(ids) => crate::rules::find_by_rule_ids(t, ids).await,
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
