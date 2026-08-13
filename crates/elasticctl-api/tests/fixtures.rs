//! Offline checks over the recorded fixtures.
//!
//! A fixture is a sample of real traffic. This test is what makes a re-record
//! after an Elastic upgrade produce a diff something reacts to: if a response
//! shape changes, or a fixture stops decoding through the same path the live
//! client uses, it fails here.

use elasticctl_api::Rule;
use elasticctl_api::codec;
use elasticctl_api::rules;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn fixture_sets() -> Vec<PathBuf> {
    let mut sets = Vec::new();
    for entry in fs::read_dir(fixtures_root()).expect("fixtures root") {
        let path = entry.expect("fixtures entry").path();
        if path.is_dir() {
            sets.push(path);
        }
    }
    sets.sort();
    sets
}

/// The rule every recorded set creates and then deletes.
fn probe_rule(rules: &[Rule]) -> &Rule {
    rules
        .iter()
        .find(|r| r.rule_id().ok() == Some("elasticctl-fixture-probe"))
        .expect("the probe rule must be present")
}

#[test]
fn every_fixture_parses_and_carries_its_metadata() {
    let sets = fixture_sets();
    assert!(!sets.is_empty(), "no fixture sets under tests/fixtures");

    for set in &sets {
        let mut files = Vec::new();
        for entry in fs::read_dir(set).expect("fixture set") {
            let path = entry.expect("fixture set entry").path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                files.push(path);
            }
        }
        assert!(!files.is_empty(), "{} has no JSON fixtures", set.display());
        files.sort();

        for file in files {
            let body = fs::read_to_string(&file).expect("read fixture");
            let value: Value = serde_json::from_str(&body)
                .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", file.display()));
            for field in ["flavor", "version", "operation"] {
                assert!(
                    value.get(field).and_then(Value::as_str).is_some(),
                    "{} must carry a string `{field}`",
                    file.display()
                );
            }
        }
    }
}

#[test]
fn rules_export_decodes_to_the_probe_rule_and_trailer() {
    for set in fixture_sets() {
        let body = fs::read_to_string(set.join("rules_export.json")).expect("rules_export fixture");
        let value: Value = serde_json::from_str(&body).expect("rules_export is JSON");
        let ndjson = value["response"]["ndjson"]
            .as_str()
            .expect("rules_export must carry response.ndjson as a string");

        let (rules, summary) = codec::decode_ndjson(ndjson).expect("decode export ndjson");
        let summary = summary.expect("export must carry the exported_count trailer");
        assert_eq!(summary.exported_count, 1, "a scoped export holds one rule");
        assert_eq!(rules.len(), 1, "a scoped export holds one rule line");
        let probe = probe_rule(&rules);
        assert_eq!(probe.name(), "elasticctl fixture probe");
    }
}

#[test]
fn rules_find_decodes_to_the_probe_rule() {
    for set in fixture_sets() {
        let body = fs::read_to_string(set.join("rules_find.json")).expect("rules_find fixture");
        let value: Value = serde_json::from_str(&body).expect("rules_find is JSON");

        let (rules, total) = rules::decode_find(&value["response"]).expect("decode find response");
        assert!(total >= 1, "a scoped find must report at least one rule");
        let probe = probe_rule(&rules);
        assert_eq!(probe.name(), "elasticctl fixture probe");
    }
}

/// A fixture set recorded before an exchange existed simply lacks its file:
/// the self-managed set is re-recorded on demand from the local lab, not on
/// every change. So each new exchange is asserted wherever it was recorded,
/// and separately asserted to exist somewhere — a missing recording must not
/// pass silently in every set at once.
fn sets_with(file: &str) -> Vec<PathBuf> {
    fixture_sets()
        .into_iter()
        .filter(|s| s.join(file).exists())
        .collect()
}

fn fixture_body(path: &Path) -> Value {
    let body = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()))
}

#[test]
fn preview_hits_are_recorded_with_the_index_and_field_that_found_them() {
    let sets = sets_with("rules_preview_hits.json");
    assert!(
        !sets.is_empty(),
        "no set records rules_preview_hits; the preview hit count rests on it"
    );

    for set in sets {
        let v = fixture_body(&set.join("rules_preview_hits.json"));
        let index = v["request"]["index"].as_str().expect("request.index");
        assert!(
            index.starts_with(".preview.alerts-security.alerts-"),
            "{} recorded an unexpected preview index: {index}",
            set.display()
        );
        assert!(
            v["request"]["matched_by"].as_str().is_some(),
            "{} must record which field matched",
            set.display()
        );
        let total = v["response"]["hits"]["total"]["value"]
            .as_u64()
            .expect("hits.total.value");
        assert!(
            total >= 1,
            "{}: a recording with zero hits proves nothing — a wrong field name \
             looks exactly the same. Re-record.",
            set.display()
        );
    }
}

#[test]
fn the_name_filter_find_returns_the_probe_rule() {
    let sets = sets_with("rules_find_by_name.json");
    assert!(!sets.is_empty(), "no set records rules_find_by_name");

    for set in sets {
        let v = fixture_body(&set.join("rules_find_by_name.json"));
        assert!(
            v["request"]["filter"]
                .as_str()
                .expect("request.filter")
                .starts_with("alert.attributes.name:"),
            "{} must record the KQL path the name lookup uses",
            set.display()
        );
        let (rules, total) = rules::decode_find(&v["response"]).expect("decode find response");
        assert!(
            total >= 1,
            "{}: a name filter matching nothing proves nothing about the path",
            set.display()
        );
        assert_eq!(probe_rule(&rules).name(), "elasticctl fixture probe");
    }
}

#[test]
fn the_spaces_probe_returns_ids() {
    let sets = sets_with("spaces.json");
    assert!(!sets.is_empty(), "no set records spaces");

    for set in sets {
        let v = fixture_body(&set.join("spaces.json"));
        let spaces = v["response"].as_array().expect("spaces response is an array");
        assert!(!spaces.is_empty(), "{}", set.display());
        for space in spaces {
            assert!(
                space["id"].as_str().is_some(),
                "{} every space must carry a string id: {space}",
                set.display()
            );
        }
    }
}
