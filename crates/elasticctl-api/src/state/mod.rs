mod diff;
mod mirror;
mod pull;
mod push;
mod reports;
mod transaction;

pub use diff::diff;
pub use mirror::{read_local, read_mirror};
pub use pull::pull;
pub use push::{PushPlan, apply_push, plan_push};
pub use reports::{
    DanglingPointer, DiffReport, ExceptionDrift, ListChange, Mirror, PullReport, PushReport,
    StackIdentity,
};

use crate::model::{ListKey, Rule};
use crate::rules::{RuleFilter, RuleSource};
use crate::selection;
use elasticctl_core::{Result, Transport};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn rules_dir(dir: &Path) -> PathBuf {
    dir.join("rules")
}

fn exceptions_dir(dir: &Path) -> PathBuf {
    dir.join("exceptions")
}

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

fn is_rule_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("ndjson") | Some("json") | Some("yaml") | Some("yml")
    )
}

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

struct Scope {
    rule_ids: Option<Vec<String>>,
    source: RuleSource,
    local_total: usize,
}

impl Scope {
    fn is_scoped(&self) -> bool {
        self.rule_ids.is_some()
    }

    fn selected(&self) -> usize {
        self.rule_ids.as_ref().map(Vec::len).unwrap_or(0)
    }

    fn narrow(&self, rules: Vec<Rule>) -> Vec<Rule> {
        match &self.rule_ids {
            None => rules,
            Some(ids) => rules
                .into_iter()
                .filter(|r| r.rule_id().is_ok_and(|id| ids.iter().any(|s| s == id)))
                .collect(),
        }
    }

    fn split_by_source(&self, rules: Vec<Rule>) -> (Vec<Rule>, usize) {
        let mut kept = Vec::with_capacity(rules.len());
        let mut out_of_scope = 0;
        for rule in rules {
            if in_source(self.source, &rule) {
                kept.push(rule);
            } else {
                out_of_scope += 1;
            }
        }
        (kept, out_of_scope)
    }

    async fn remote(&self, t: &Transport) -> Result<Vec<Rule>> {
        match &self.rule_ids {
            None => {
                crate::rules::find_all(
                    t,
                    &RuleFilter {
                        source: self.source,
                        ..Default::default()
                    },
                )
                .await
            }
            Some(ids) => crate::rules::find_by_rule_ids(t, ids).await,
        }
    }

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

fn in_source(source: RuleSource, rule: &Rule) -> bool {
    match source {
        RuleSource::All => true,
        RuleSource::Custom => !is_prebuilt(rule),
        RuleSource::Prebuilt => is_prebuilt(rule),
        RuleSource::Customized => rule
            .as_map()
            .get("rule_source")
            .and_then(Value::as_object)
            .and_then(|rs| rs.get("is_customized"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

fn is_prebuilt(rule: &Rule) -> bool {
    rule.as_map().get("immutable").and_then(Value::as_bool) == Some(true)
}

async fn scope_of(
    t: &Transport,
    selectors: &[String],
    tag: Option<&str>,
    search: Option<&str>,
    source: RuleSource,
    local: &[Rule],
    noun: &str,
) -> Result<Scope> {
    let rule_ids = selection::resolve(t, selectors, tag, search, local, noun).await?;
    Ok(Scope {
        rule_ids,
        source,
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
