//! The self-managed corpus fill. Disabled marker rules bring the space to
//! exactly 4,000 rules for the coverage timing, then leave by explicit
//! `rule_id`. The fill never runs on Serverless or Hosted.

use std::collections::BTreeSet;
use std::path::Path;

use elasticctl_api::rules::{self, BulkAction, BulkOutcome, RuleFilter};
use elasticctl_core::{Flavor, Profile, Transport};
use serde_json::{Value, json};

use crate::{LIVE_PREFIX, LIVE_TAG, LiveCleanup, TestResult, checked, cli, json_output};

/// The space size the coverage timing needs: eight 500-rule pages.
pub(crate) const FILL_TARGET: u64 = 4_000;
/// Rules per guarded import and per bulk delete.
pub(crate) const FILL_CHUNK: usize = 500;
pub(crate) const SAMPLE_TAG: &str = "elasticctl-sample";
pub(crate) const FILL_PREFIX: &str = "elasticctl-sample-fill-";

/// A fill the contract created: `count` rules named `<prefix><n>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuleFill {
    pub(crate) prefix: String,
    pub(crate) count: usize,
    pub(crate) pre_total: u64,
}

/// The remote operations the fill uses. The live implementation calls the
/// existing guarded helpers; offline tests record calls and inject failures.
pub(crate) trait FillRemote {
    /// Deployment flavor from the cached capability probe.
    fn flavor(&mut self) -> TestResult<Flavor>;
    /// Rules in the space, from one `_find?page=1&per_page=1`.
    fn rule_total(&mut self) -> TestResult<u64>;
    /// Import one chunk. `cleanup` is passed so a test can prove the fill is
    /// registered before any rule is written.
    fn import_chunk(&mut self, cleanup: &LiveCleanup, ndjson: &str, rules: usize) -> TestResult;
    /// Which of these rule ids exist.
    fn existing(&mut self, ids: &[String]) -> TestResult<BTreeSet<String>>;
    /// Delete exactly these rule ids.
    fn delete(&mut self, ids: &[String]) -> TestResult<BulkOutcome>;
}

pub(crate) fn fill_prefix(nonce: &str) -> String {
    format!("{FILL_PREFIX}{nonce}-")
}

pub(crate) fn fill_ids(prefix: &str, count: usize) -> Vec<String> {
    (1..=count).map(|n| format!("{prefix}{n}")).collect()
}

/// One generated rule: disabled, marker-tagged, and over the marker index.
pub(crate) fn fill_rule(rule_id: &str, index: &str) -> Value {
    json!({
        "rule_id": rule_id,
        "name": rule_id,
        "description": "Created by elasticctl's live conformance suite. Safe to delete.",
        "type": "query",
        "language": "kuery",
        "query": format!("marker: \"{LIVE_TAG}\""),
        "index": [index],
        "severity": "low",
        "risk_score": 21,
        "enabled": false,
        "from": "now-6m",
        "interval": "5m",
        "tags": [SAMPLE_TAG, LIVE_TAG],
    })
}

pub(crate) fn fill_ndjson(ids: &[String], index: &str) -> String {
    ids.iter()
        .map(|id| format!("{}\n", fill_rule(id, index)))
        .collect()
}

/// Fill the space to exactly 4,000 rules when the probe reports a
/// self-managed stack. Returns `None` for every other flavor. The fill is
/// registered with cleanup before the first chunk, so every failure path,
/// including a partly imported chunk, leaves its rules to cleanup.
pub(crate) fn fill_corpus(
    remote: &mut impl FillRemote,
    cleanup: &mut LiveCleanup,
    index: &str,
    nonce: &str,
) -> TestResult<Option<RuleFill>> {
    if remote.flavor()? != Flavor::SelfManaged {
        return Ok(None);
    }
    if !index.starts_with(LIVE_PREFIX) {
        return Err("Corpus fill index is not a marker index.".to_string());
    }
    let pre_total = remote.rule_total()?;
    if pre_total > FILL_TARGET {
        return Err("Corpus fill refused: the space holds more than 4,000 rules.".to_string());
    }
    let count = usize::try_from(FILL_TARGET - pre_total)
        .map_err(|_| "Corpus fill count does not fit in memory.".to_string())?;
    let prefix = fill_prefix(nonce);
    cleanup.rule_fill(prefix.clone(), count);
    for chunk in fill_ids(&prefix, count).chunks(FILL_CHUNK) {
        remote.import_chunk(cleanup, &fill_ndjson(chunk, index), chunk.len())?;
    }
    if remote.rule_total()? != FILL_TARGET {
        return Err("Corpus fill did not reach exactly 4,000 rules.".to_string());
    }
    Ok(Some(RuleFill {
        prefix,
        count,
        pre_total,
    }))
}

/// Delete a fill by explicit `rule_id`, chunk by chunk. Only ids that exist
/// are sent, so a partly imported chunk is removed without an empty or
/// unmatched delete. Each chunk is read again to prove nothing remains.
pub(crate) fn delete_fill(remote: &mut impl FillRemote, prefix: &str, count: usize) -> TestResult {
    if !prefix.starts_with(FILL_PREFIX) || prefix.len() <= FILL_PREFIX.len() {
        return Err("Corpus fill prefix is not marker-scoped.".to_string());
    }
    for chunk in fill_ids(prefix, count).chunks(FILL_CHUNK) {
        let found = remote.existing(chunk)?;
        let present: Vec<String> = chunk
            .iter()
            .filter(|id| found.contains(*id))
            .cloned()
            .collect();
        if !present.is_empty() {
            let outcome = remote.delete(&present)?;
            if outcome.failed != 0 || outcome.succeeded != present.len() as u64 {
                return Err("Corpus fill delete did not remove every present rule.".to_string());
            }
        }
        let left = remote.existing(chunk)?;
        if chunk.iter().any(|id| left.contains(id)) {
            return Err("Corpus fill rules remain after delete.".to_string());
        }
    }
    Ok(())
}

/// The contract's own delete after the coverage timing. The space must return
/// to its pre-fill total; only then is the cleanup registration dropped.
pub(crate) fn unfill_corpus(
    remote: &mut impl FillRemote,
    cleanup: &mut LiveCleanup,
    fill: &RuleFill,
) -> TestResult {
    delete_fill(remote, &fill.prefix, fill.count)?;
    if remote.rule_total()? != fill.pre_total {
        return Err("Rule total did not return to its pre-fill value.".to_string());
    }
    cleanup.forget_rule_fill(&fill.prefix, fill.count);
    Ok(())
}

/// The live remote. `import` holds the CLI config and the scratch directory;
/// cleanup builds the remote without them because it only deletes.
pub(crate) struct LiveFillRemote<'a> {
    pub(crate) runtime: &'a tokio::runtime::Runtime,
    pub(crate) transport: &'a Transport,
    pub(crate) import: Option<(&'a Path, &'a Path)>,
    pub(crate) chunks: usize,
}

impl FillRemote for LiveFillRemote<'_> {
    fn flavor(&mut self) -> TestResult<Flavor> {
        self.runtime
            .block_on(self.transport.capabilities())
            .map(|capabilities| capabilities.flavor)
            .map_err(|e| format!("Corpus fill probe failed: {}.", e.kind.as_str()))
    }

    fn rule_total(&mut self) -> TestResult<u64> {
        self.runtime
            .block_on(rules::find_page(
                self.transport,
                &RuleFilter::default(),
                1,
                1,
            ))
            .map(|(_, total)| total)
            .map_err(|e| format!("Corpus fill total read failed: {}.", e.kind.as_str()))
    }

    fn import_chunk(&mut self, _cleanup: &LiveCleanup, ndjson: &str, rules: usize) -> TestResult {
        let (config, scratch) = self
            .import
            .ok_or_else(|| "Corpus fill import is not configured.".to_string())?;
        self.chunks += 1;
        let path = scratch.join(format!("compose-fill-{}.ndjson", self.chunks));
        std::fs::write(&path, ndjson)
            .map_err(|_| "Corpus fill chunk could not be written.".to_string())?;
        let out = checked(
            cli(config)
                .args(["rules", "import", "--path"])
                .arg(&path)
                .args(["--yes", "--json"]),
            "corpus fill import",
        )
        .map_err(|_| "Corpus fill import failed.".to_string())?;
        let report = json_output(&out, "corpus fill import")
            .map_err(|_| "Corpus fill import returned invalid JSON.".to_string())?;
        if report["applied"] != true
            || report["succeeded"] != rules as u64
            || report["total"] != rules as u64
            || !report["failed"].as_array().is_some_and(Vec::is_empty)
        {
            return Err("Corpus fill import did not report every rule.".to_string());
        }
        Ok(())
    }

    fn existing(&mut self, ids: &[String]) -> TestResult<BTreeSet<String>> {
        self.runtime
            .block_on(rules::existing_rule_ids(self.transport, ids))
            .map_err(|e| format!("Corpus fill read failed: {}.", e.kind.as_str()))
    }

    fn delete(&mut self, ids: &[String]) -> TestResult<BulkOutcome> {
        self.runtime
            .block_on(rules::bulk_by_rule_ids(
                self.transport,
                BulkAction::Delete,
                ids,
                false,
            ))
            .map_err(|e| format!("Corpus fill delete failed: {}.", e.kind.as_str()))
    }
}

/// The cleanup entry point for a registered fill.
pub(crate) fn delete_rule_fill(profile: &Profile, prefix: &str, count: usize) -> TestResult {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|_| "Corpus fill cleanup runtime could not be started.".to_string())?;
    let transport = Transport::new(profile)
        .map_err(|e| format!("Corpus fill cleanup transport failed: {}.", e.kind.as_str()))?;
    delete_fill(
        &mut LiveFillRemote {
            runtime: &runtime,
            transport: &transport,
            import: None,
            chunks: 0,
        },
        prefix,
        count,
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const INDEX: &str = "elasticctl-live-compose-index-1";

    /// A recording remote. `created` is the fake space's fill rules.
    pub(crate) struct FakeFill {
        pub(crate) flavor: Flavor,
        pub(crate) base_total: u64,
        pub(crate) created: BTreeSet<String>,
        pub(crate) events: Vec<String>,
        /// Fail this 1-based chunk after creating this many of its rules.
        pub(crate) fail_chunk: Option<(usize, usize)>,
        pub(crate) delete_failures: usize,
        pub(crate) delete_attempts: usize,
        pub(crate) deleted_ids: Vec<String>,
        pub(crate) imported: Vec<Value>,
        pub(crate) registered_before_write: Vec<bool>,
        pub(crate) extra_after_delete: u64,
    }

    impl FakeFill {
        pub(crate) fn new(flavor: Flavor, base_total: u64) -> Self {
            Self {
                flavor,
                base_total,
                created: BTreeSet::new(),
                events: Vec::new(),
                fail_chunk: None,
                delete_failures: 0,
                delete_attempts: 0,
                deleted_ids: Vec::new(),
                imported: Vec::new(),
                registered_before_write: Vec::new(),
                extra_after_delete: 0,
            }
        }
    }

    impl FillRemote for FakeFill {
        fn flavor(&mut self) -> TestResult<Flavor> {
            self.events.push("flavor".to_string());
            Ok(self.flavor)
        }

        fn rule_total(&mut self) -> TestResult<u64> {
            self.events.push("total".to_string());
            Ok(self.base_total + self.created.len() as u64 + self.extra_after_delete)
        }

        fn import_chunk(
            &mut self,
            cleanup: &LiveCleanup,
            ndjson: &str,
            rules: usize,
        ) -> TestResult {
            let chunk = self
                .events
                .iter()
                .filter(|e| e.starts_with("import"))
                .count()
                + 1;
            self.events.push(format!("import-{chunk}"));
            let rows: Vec<Value> = ndjson
                .lines()
                .map(|line| serde_json::from_str(line).expect("fill line is JSON"))
                .collect();
            assert_eq!(rows.len(), rules);
            let prefixes: Vec<&str> = rows
                .iter()
                .map(|row| row["rule_id"].as_str().expect("rule_id"))
                .collect();
            self.registered_before_write.push(prefixes.iter().all(|id| {
                cleanup
                    .rule_fills
                    .iter()
                    .any(|(prefix, count)| fill_ids(prefix, *count).iter().any(|own| own == id))
            }));
            let keep = match self.fail_chunk {
                Some((failing, created)) if failing == chunk => created,
                _ => rows.len(),
            };
            for row in rows.iter().take(keep) {
                self.created
                    .insert(row["rule_id"].as_str().expect("rule_id").to_string());
            }
            self.imported.extend(rows);
            if keep < rules {
                return Err("injected chunk failure".to_string());
            }
            Ok(())
        }

        fn existing(&mut self, ids: &[String]) -> TestResult<BTreeSet<String>> {
            self.events.push("existing".to_string());
            Ok(ids
                .iter()
                .filter(|id| self.created.contains(*id))
                .cloned()
                .collect())
        }

        fn delete(&mut self, ids: &[String]) -> TestResult<BulkOutcome> {
            self.events.push("delete".to_string());
            self.delete_attempts += 1;
            if self.delete_failures > 0 {
                self.delete_failures -= 1;
                return Err("injected delete failure".to_string());
            }
            for id in ids {
                assert!(id.starts_with(FILL_PREFIX), "delete targets only fill ids");
                assert!(self.created.remove(id), "delete targets only present ids");
                self.deleted_ids.push(id.clone());
            }
            Ok(BulkOutcome {
                succeeded: ids.len() as u64,
                failed: 0,
                skipped: 0,
                total: ids.len() as u64,
            })
        }
    }

    fn quiet_cleanup() -> LiveCleanup {
        let mut cleanup = LiveCleanup::for_test();
        cleanup.finished = true;
        cleanup
    }

    #[test]
    fn fill_never_runs_for_serverless_or_hosted_probes() {
        for flavor in [Flavor::Serverless, Flavor::ElasticCloudHosted] {
            let mut cleanup = quiet_cleanup();
            let mut remote = FakeFill::new(flavor, 10);
            assert_eq!(
                fill_corpus(&mut remote, &mut cleanup, INDEX, "n").unwrap(),
                None
            );
            assert_eq!(remote.events, ["flavor"]);
            assert!(cleanup.rule_fills.is_empty());
            assert!(remote.imported.is_empty());
        }
    }

    #[test]
    fn fill_refuses_a_space_above_four_thousand_rules() {
        let mut cleanup = quiet_cleanup();
        let mut remote = FakeFill::new(Flavor::SelfManaged, 4_001);
        let error = fill_corpus(&mut remote, &mut cleanup, INDEX, "n").unwrap_err();
        assert_eq!(
            error,
            "Corpus fill refused: the space holds more than 4,000 rules."
        );
        assert_eq!(remote.events, ["flavor", "total"]);
        assert!(cleanup.rule_fills.is_empty());

        let mut remote = FakeFill::new(Flavor::SelfManaged, 4_000);
        let fill = fill_corpus(&mut remote, &mut cleanup, INDEX, "n")
            .unwrap()
            .expect("an exact space still records its fill");
        assert_eq!(fill.count, 0);
        assert!(remote.imported.is_empty());
    }

    #[test]
    fn fill_registration_precedes_the_first_chunk() {
        let mut cleanup = quiet_cleanup();
        let mut remote = FakeFill::new(Flavor::SelfManaged, 2_900);
        let fill = fill_corpus(&mut remote, &mut cleanup, INDEX, "nonce")
            .unwrap()
            .expect("self-managed fill runs");
        assert_eq!(fill.count, 1_100);
        assert_eq!(fill.pre_total, 2_900);
        assert_eq!(fill.prefix, "elasticctl-sample-fill-nonce-");
        assert_eq!(
            remote.events,
            [
                "flavor", "total", "import-1", "import-2", "import-3", "total"
            ]
        );
        assert_eq!(remote.registered_before_write, [true, true, true]);
        assert_eq!(
            cleanup.rule_fills,
            BTreeSet::from([("elasticctl-sample-fill-nonce-".to_string(), 1_100)])
        );
        let sizes: Vec<usize> = fill_ids(&fill.prefix, fill.count)
            .chunks(FILL_CHUNK)
            .map(<[String]>::len)
            .collect();
        assert_eq!(sizes, [500, 500, 100]);
    }

    #[test]
    fn generated_fill_rules_are_disabled_and_marker_scoped() {
        let mut cleanup = quiet_cleanup();
        let mut remote = FakeFill::new(Flavor::SelfManaged, 3_390);
        let fill = fill_corpus(&mut remote, &mut cleanup, INDEX, "n")
            .unwrap()
            .unwrap();
        assert_eq!(remote.imported.len(), 610);
        let mut ids = BTreeSet::new();
        for rule in &remote.imported {
            let id = rule["rule_id"].as_str().unwrap();
            assert!(id.starts_with(&fill.prefix) && id.starts_with(FILL_PREFIX));
            assert!(ids.insert(id.to_string()), "rule ids are distinct");
            assert_eq!(rule["enabled"], false);
            assert_eq!(rule["type"], "query");
            assert_eq!(rule["index"], json!([INDEX]));
            assert!(rule["index"][0].as_str().unwrap().starts_with(LIVE_PREFIX));
            assert_eq!(rule["tags"], json!([SAMPLE_TAG, LIVE_TAG]));
            assert_eq!(rule["name"], rule["rule_id"]);
        }
        assert_eq!(ids, fill_ids(&fill.prefix, 610).into_iter().collect());
        assert!(
            fill_corpus(
                &mut FakeFill::new(Flavor::SelfManaged, 1),
                &mut quiet_cleanup(),
                "unmarked-index",
                "n"
            )
            .is_err()
        );
    }

    #[test]
    fn a_failed_chunk_still_deletes_what_was_created() {
        let mut cleanup = quiet_cleanup();
        let mut remote = FakeFill::new(Flavor::SelfManaged, 2_900);
        remote.fail_chunk = Some((2, 200));
        assert!(fill_corpus(&mut remote, &mut cleanup, INDEX, "n").is_err());
        assert_eq!(remote.created.len(), 700);
        assert_eq!(cleanup.rule_fills.len(), 1, "the fill stays registered");

        let failures =
            cleanup.clean_rule_fills(|prefix, count| delete_fill(&mut remote, prefix, count));
        assert!(failures.is_empty(), "{failures:?}");
        assert!(remote.created.is_empty());
        assert_eq!(remote.deleted_ids.len(), 700);
        assert_eq!(
            remote.events.iter().filter(|e| *e == "delete").count(),
            2,
            "the empty third chunk sends no delete"
        );
    }

    #[test]
    fn a_failed_delete_fails_cleanup_and_is_retried() {
        let mut cleanup = quiet_cleanup();
        cleanup.rule_fill(fill_prefix("n"), 3);
        let mut remote = FakeFill::new(Flavor::SelfManaged, 0);
        remote.created = fill_ids(&fill_prefix("n"), 3).into_iter().collect();
        remote.delete_failures = usize::MAX;
        let failures =
            cleanup.clean_rule_fills(|prefix, count| delete_fill(&mut remote, prefix, count));
        assert_eq!(failures.len(), 1);
        assert!(failures[0].starts_with("cleanup left rule fill elasticctl-sample-fill-n-"));
        assert_eq!(remote.delete_attempts, 3);
        assert_eq!(remote.created.len(), 3);

        remote.delete_failures = 1;
        remote.delete_attempts = 0;
        let failures =
            cleanup.clean_rule_fills(|prefix, count| delete_fill(&mut remote, prefix, count));
        assert!(failures.is_empty());
        assert_eq!(remote.delete_attempts, 2);
        assert!(remote.created.is_empty());
    }

    #[test]
    fn the_contract_delete_requires_the_pre_fill_total() {
        let mut cleanup = quiet_cleanup();
        let mut remote = FakeFill::new(Flavor::SelfManaged, 3_000);
        let fill = fill_corpus(&mut remote, &mut cleanup, INDEX, "n")
            .unwrap()
            .unwrap();
        remote.extra_after_delete = 1;
        assert_eq!(
            unfill_corpus(&mut remote, &mut cleanup, &fill).unwrap_err(),
            "Rule total did not return to its pre-fill value."
        );
        assert_eq!(
            cleanup.rule_fills.len(),
            1,
            "an unverified fill stays registered"
        );

        remote.extra_after_delete = 0;
        unfill_corpus(&mut remote, &mut cleanup, &fill).unwrap();
        assert!(cleanup.rule_fills.is_empty());
    }

    #[test]
    fn fill_delete_refuses_an_unmarked_prefix() {
        let mut remote = FakeFill::new(Flavor::SelfManaged, 0);
        for prefix in ["", "elasticctl-sample-fill-", "custom-rule-"] {
            assert_eq!(
                delete_fill(&mut remote, prefix, 2).unwrap_err(),
                "Corpus fill prefix is not marker-scoped."
            );
        }
        assert!(remote.events.is_empty());
    }
}
