//! Offline checks for recorded fixtures.
//!
//! A fixture is recorded traffic. These tests fail when an Elastic upgrade
//! changes a response shape or bypasses the live client's decode path.

use elasticctl_api::Rule;
use elasticctl_api::codec;
use elasticctl_api::rules;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const V0_2_FIXTURES: [&str; 15] = [
    "exception_lists_find.json",
    "exception_list_get.json",
    "exception_list_items_find.json",
    "exception_list_create.json",
    "exception_item_create.json",
    "exception_list_export.json",
    "exception_list_import.json",
    "rules_export_bundle.json",
    "rules_import_bundle.json",
    "prebuilt_status.json",
    "prebuilt_install.json",
    "lists_index.json",
    "rules_find_source_custom.json",
    "rules_find_source_prebuilt.json",
    "rules_find_source_customized.json",
];

/// Search fixtures added in 0.3. They are recorded together by the search
/// probe; the decode test below reads their responses.
const V0_3_SEARCH_FIXTURES: [&str; 6] = [
    "esql_query.json",
    "search_pit_open.json",
    "search_pit_page.json",
    "search_pit_close.json",
    "data_views.json",
    "detection_engine_index.json",
];

/// Triage fixtures added in 0.4, recorded by the alerts probe.
const V0_4_ALERT_FIXTURES: [&str; 7] = [
    "signals_search.json",
    "signals_status_ids.json",
    "signals_status_query.json",
    "signals_tags.json",
    "signals_assignees.json",
    "users_find.json",
    "profile_suggest.json",
];

/// Case fixtures added in 0.4.1, recorded by the cases probe.
const V0_4_1_CASE_FIXTURES: [&str; 8] = [
    "cases_find.json",
    "case_get.json",
    "case_create.json",
    "case_update_status.json",
    "case_conflict.json",
    "case_comment.json",
    "case_attach.json",
    "case_delete.json",
];

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

/// The rule that every recorded set creates and deletes.
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

        // The search fixtures are recorded as a set; a set missing any of them
        // predates the search probe.
        let missing: Vec<&str> = V0_3_SEARCH_FIXTURES
            .iter()
            .copied()
            .filter(|name| !set.join(name).is_file())
            .collect();
        assert!(
            missing.is_empty(),
            "{} lacks search fixture(s): {}",
            set.display(),
            missing.join(", ")
        );

        // The alert fixtures are recorded as a set; a set missing any of them
        // predates the alerts probe.
        let missing: Vec<&str> = V0_4_ALERT_FIXTURES
            .iter()
            .copied()
            .filter(|name| !set.join(name).is_file())
            .collect();
        assert!(
            missing.is_empty(),
            "{} lacks alert fixture(s): {}",
            set.display(),
            missing.join(", ")
        );

        // The case fixtures are recorded as a set; a set missing any of them
        // predates the cases probe.
        let missing: Vec<&str> = V0_4_1_CASE_FIXTURES
            .iter()
            .copied()
            .filter(|name| !set.join(name).is_file())
            .collect();
        assert!(
            missing.is_empty(),
            "{} lacks case fixture(s): {}",
            set.display(),
            missing.join(", ")
        );
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
        assert_eq!(
            summary.exported_count, 3,
            "the bundle total counts its rule, list, and item"
        );
        assert_eq!(
            summary.exported_rules_count, 1,
            "a scoped export holds one rule"
        );
        assert_eq!(summary.exported_exception_list_count, 1);
        assert_eq!(summary.exported_exception_list_item_count, 1);
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

/// Fixture sets recorded before an exchange lack its file. The self-managed
/// set is re-recorded from the local lab on demand. Assert each new exchange
/// where recorded and assert that it exists in at least one set.
fn sets_with(file: &str) -> Vec<PathBuf> {
    fixture_sets()
        .into_iter()
        .filter(|s| s.join(file).exists())
        .collect()
}

fn fixture_body(path: &Path) -> Value {
    let body = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()))
}

#[test]
fn every_flavor_carries_every_v0_2_exchange() {
    for set in fixture_sets() {
        let missing: Vec<&str> = V0_2_FIXTURES
            .iter()
            .copied()
            .filter(|name| !set.join(name).is_file())
            .collect();
        assert!(
            missing.is_empty(),
            "{} lacks v0.2 fixture exchange(s): {}",
            set.display(),
            missing.join(", ")
        );
    }
}

#[test]
fn exception_export_bundle_decodes_to_the_fixed_list_and_item() {
    for set in fixture_sets() {
        let value = fixture_body(&set.join("exception_list_export.json"));
        let ndjson = value["response"]["ndjson"]
            .as_str()
            .expect("exception_list_export must carry response.ndjson as a string");
        let bundle = codec::decode_bundle(ndjson).expect("decode exception export NDJSON");

        assert!(
            bundle.rules.is_empty(),
            "{}: exception export has no rules",
            set.display()
        );
        assert_eq!(
            bundle.lists.len(),
            1,
            "{}: one scoped exception list",
            set.display()
        );
        assert_eq!(
            bundle.items.len(),
            1,
            "{}: one scoped exception item",
            set.display()
        );
        assert_eq!(
            bundle.lists[0].list_id().expect("list id"),
            "elasticctl-sample-exceptions",
            "{}: export must retain the fixed list id",
            set.display()
        );
        assert_eq!(
            bundle.items[0].item_id().expect("item id"),
            "elasticctl-sample-exception-item",
            "{}: export must retain the fixed item id",
            set.display()
        );
        assert_eq!(
            bundle.items[0].list_id().expect("item list id"),
            "elasticctl-sample-exceptions",
            "{}: item must point to the fixed list",
            set.display()
        );
    }
}

#[test]
fn rule_export_bundle_decodes_to_the_fixed_rule_list_and_item() {
    for set in fixture_sets() {
        let value = fixture_body(&set.join("rules_export_bundle.json"));
        let ndjson = value["response"]["ndjson"]
            .as_str()
            .expect("rules_export_bundle must carry response.ndjson as a string");
        let bundle = codec::decode_bundle(ndjson).expect("decode rule export NDJSON");

        assert_eq!(bundle.rules.len(), 1, "{}: one scoped rule", set.display());
        assert_eq!(
            bundle.lists.len(),
            1,
            "{}: one referenced list",
            set.display()
        );
        assert_eq!(
            bundle.items.len(),
            1,
            "{}: one referenced item",
            set.display()
        );
        assert_eq!(
            bundle.rules[0].rule_id().expect("rule id"),
            "elasticctl-fixture-probe",
            "{}: export must retain the fixed rule id",
            set.display()
        );
        assert_eq!(
            bundle.lists[0].list_id().expect("list id"),
            "elasticctl-sample-exceptions",
            "{}: export must retain the fixed list id",
            set.display()
        );
        assert_eq!(
            bundle.items[0].item_id().expect("item id"),
            "elasticctl-sample-exception-item",
            "{}: export must retain the fixed item id",
            set.display()
        );
    }
}

#[test]
fn source_find_fixtures_keep_the_exact_scoped_kql() {
    let expected = [
        (
            "rules_find_source_custom.json",
            "alert.attributes.params.immutable: false AND alert.attributes.params.ruleId: \"elasticctl-fixture-probe\"",
        ),
        (
            "rules_find_source_prebuilt.json",
            "alert.attributes.params.immutable: true AND alert.attributes.params.ruleId: \"elasticctl-fixture-probe\"",
        ),
        (
            "rules_find_source_customized.json",
            "alert.attributes.params.ruleSource.isCustomized: true AND alert.attributes.params.ruleId: \"elasticctl-fixture-probe\"",
        ),
    ];

    for set in fixture_sets() {
        for (file, filter) in expected {
            let value = fixture_body(&set.join(file));
            assert_eq!(
                value["request"]["filter"].as_str(),
                Some(filter),
                "{} must retain the exact scoped source filter",
                set.join(file).display()
            );
        }
    }
}

#[test]
fn source_partition_is_exhaustive_for_the_scoped_probe_corpus() {
    for set in fixture_sets() {
        let all = fixture_body(&set.join("rules_find.json"));
        let custom = fixture_body(&set.join("rules_find_source_custom.json"));
        let prebuilt = fixture_body(&set.join("rules_find_source_prebuilt.json"));
        let total = |fixture: &Value| {
            fixture["response"]["total"]
                .as_u64()
                .expect("source fixture response.total")
        };

        assert_eq!(
            total(&custom) + total(&prebuilt),
            total(&all),
            "{}: immutable must partition the scoped probe corpus",
            set.display()
        );
    }
}

#[test]
fn lists_index_records_either_the_valid_result_or_classified_404() {
    for set in fixture_sets() {
        let value = fixture_body(&set.join("lists_index.json"));
        match (value.get("response"), value.get("error")) {
            (Some(response), None) => {
                assert!(
                    response["list_index"].is_boolean(),
                    "{}: successful list index response needs list_index bool",
                    set.display()
                );
                assert!(
                    response["list_item_index"].is_boolean(),
                    "{}: successful list index response needs list_item_index bool",
                    set.display()
                );
            }
            (None, Some(error)) => {
                assert_eq!(
                    error["kind"].as_str(),
                    Some("not_found"),
                    "{}: absent list indices must remain a classified 404",
                    set.display()
                );
                assert_eq!(
                    error["http_status"].as_u64(),
                    Some(404),
                    "{}: absent list indices must retain their HTTP status",
                    set.display()
                );
            }
            _ => panic!(
                "{}: lists_index requires exactly one response or error envelope",
                set.display()
            ),
        }
    }
}

fn is_identity_key(key: &str) -> bool {
    matches!(
        key.rsplit('.').next().unwrap_or(key),
        "created_by" | "updated_by" | "closed_by" | "pushed_by" | "tie_breaker_id" | "_version"
    )
}

/// A string leaf under an identity key must be a redaction placeholder, not
/// real identity: either the blanket `"REDACTED"` `scrub` writes when the
/// key itself is sensitive, or a per-profile `u_REDACTED_<n>` uid placeholder
/// `scrub_placeholder_values` writes in its place (uid is deliberately never
/// blanket-redacted — see `SCRUB_FIELDS`'s comment in `xtask/src/main.rs`).
/// Substring match, not exact equality, so both shapes pass: a real,
/// unredacted value never contains the literal word "REDACTED".
fn is_redacted_placeholder(value: &str) -> bool {
    value.contains("REDACTED")
}

fn assert_identity_value_redacted(value: &Value, context: &str) {
    match value {
        Value::Null => {}
        Value::String(value) => assert!(
            is_redacted_placeholder(value),
            "{context}: expected a redacted placeholder, found {value:?}"
        ),
        Value::Array(values) => {
            for value in values {
                assert_identity_value_redacted(value, context);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                assert_identity_value_redacted(value, context);
            }
        }
        other => panic!("{context}: unredacted identity value {other}"),
    }
}

fn assert_no_real_identity_values(value: &Value, context: &str) {
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                let child_context = format!("{context}.{key}");
                if is_identity_key(key) {
                    assert_identity_value_redacted(value, &child_context);
                } else if key == "ndjson" {
                    let text = value.as_str().unwrap_or_else(|| {
                        panic!("{child_context}: NDJSON response must be a string")
                    });
                    for (line, body) in text
                        .lines()
                        .filter(|line| !line.trim().is_empty())
                        .enumerate()
                    {
                        let nested: Value = serde_json::from_str(body).unwrap_or_else(|error| {
                            panic!("{child_context} line {} is not JSON: {error}", line + 1)
                        });
                        assert_no_real_identity_values(
                            &nested,
                            &format!("{child_context} line {}", line + 1),
                        );
                    }
                } else {
                    assert_no_real_identity_values(value, &child_context);
                }
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                assert_no_real_identity_values(value, &format!("{context}[{index}]"));
            }
        }
        _ => {}
    }
}

#[test]
fn fixture_identity_and_version_fields_are_recursively_redacted() {
    for set in fixture_sets() {
        for entry in fs::read_dir(&set).expect("fixture set") {
            let path = entry.expect("fixture set entry").path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
                assert_no_real_identity_values(&fixture_body(&path), &path.display().to_string());
            }
        }
    }
}

#[test]
fn preview_hits_decode_through_the_production_path_and_carry_the_matched_field() {
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

        // The production query hardcodes this field. A fallback to `name` must
        // not pass the fixture check.
        let matched_by = v["request"]["matched_by"]
            .as_str()
            .expect("request.matched_by");
        assert_eq!(
            matched_by,
            "kibana.alert.rule.uuid",
            "{}: production preview_hits queries this field; a fallback recording \
             would no longer match the live client. Re-record.",
            set.display()
        );

        // Decode the recorded response through the live client's path.
        let hits = rules::decode_preview_hits(&v["response"]);
        assert!(
            hits.total >= 1,
            "{}: a recording with zero hits proves nothing — a wrong field name \
             looks exactly the same. Re-record.",
            set.display()
        );

        // The returned document must contain the queried field and value.
        // Otherwise the match is coincidental.
        let carried = hits
            .sample
            .first()
            .and_then(|s| s.get("_source"))
            .and_then(|s| s.get(matched_by));
        assert!(
            carried.is_some(),
            "{}: the returned document must carry the matched field {matched_by}",
            set.display()
        );
        assert_eq!(
            carried,
            v["request"]["body"]["query"]["term"].get(matched_by),
            "{}: the returned document's {matched_by} must equal the queried value",
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
        let spaces = v["response"]
            .as_array()
            .expect("spaces response is an array");
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

#[test]
fn search_fixtures_decode_through_the_production_paths() {
    for set in fixture_sets() {
        let esql_value = fixture_body(&set.join("esql_query.json"));
        let esql = elasticctl_api::search::esql::decode(&esql_value["response"])
            .expect("decode esql_query response");
        let seq = esql
            .columns
            .iter()
            .position(|column| column.name == "seq")
            .unwrap_or_else(|| panic!("{}: esql_query has no seq column", set.display()));
        assert_eq!(
            esql.values.len(),
            2,
            "{}: LIMIT 2 must return two rows",
            set.display()
        );
        assert_eq!(
            esql.values[0][seq].as_i64(),
            Some(1),
            "{}: sorted ascending",
            set.display()
        );
        assert_eq!(
            esql.values[1][seq].as_i64(),
            Some(2),
            "{}: sorted ascending",
            set.display()
        );

        let page_value = fixture_body(&set.join("search_pit_page.json"));
        assert!(
            page_value["request"]["pit"].is_object()
                && page_value["request"]["sort"].is_array()
                && page_value["request"]["query"].is_object(),
            "{}: search_pit_page must retain its exchange request",
            set.display()
        );
        let page = elasticctl_api::search::dsl::decode(&page_value["response"])
            .expect("decode search_pit_page response");
        assert_eq!(
            page.total,
            Some(3),
            "{}: three seeded documents",
            set.display()
        );
        assert_eq!(
            page.hits.len(),
            2,
            "{}: a size-2 page returns two hits",
            set.display()
        );
        assert!(
            page.hits.iter().all(|hit| hit.source["seq"].is_number()),
            "{}: hits must carry their seq source",
            set.display()
        );
    }
}

#[test]
fn alert_fixtures_decode_through_the_typed_decoders() {
    use elasticctl_api::{alerts, profiles};
    for set in fixture_sets() {
        let read = |name: &str| -> Value {
            serde_json::from_str(&fs::read_to_string(set.join(name)).expect(name)).expect(name)
        };

        let search = read("signals_search.json");
        let page = alerts::decode_page(&search["response"]).expect("signals_search decodes");
        assert!(
            !page.hits.is_empty(),
            "{}: the recorded search must carry alert rows",
            set.display()
        );

        for name in [
            "signals_status_ids.json",
            "signals_status_query.json",
            "signals_tags.json",
            "signals_assignees.json",
        ] {
            let doc = read(name);
            alerts::decode_outcome(&doc["response"])
                .unwrap_or_else(|e| panic!("{}/{name}: {e}", set.display()));
        }

        let users = read("users_find.json");
        profiles::decode_internal(&users["response"]).expect("users_find decodes");

        let suggest = read("profile_suggest.json");
        if let Some(response) = suggest.get("response") {
            profiles::decode_public(response).expect("profile_suggest decodes");
        } else {
            // Serverless: the public route answers 410; the fixture records
            // the error envelope instead of a response.
            assert_eq!(suggest["error"]["http_status"], serde_json::json!(410));
        }
    }
}

#[test]
fn case_fixtures_decode_through_the_typed_decoders() {
    use elasticctl_api::cases;
    for set in fixture_sets() {
        let read = |name: &str| -> Value {
            serde_json::from_str(&fs::read_to_string(set.join(name)).expect(name)).expect(name)
        };
        let (cases, total) =
            cases::decode_find(&read("cases_find.json")["response"]).expect("find");
        assert!(total >= cases.len() as u64);
        assert!(
            !cases.is_empty(),
            "{}: the recorded find must carry the marker case",
            set.display()
        );
        for name in [
            "case_get.json",
            "case_create.json",
            "case_comment.json",
            "case_attach.json",
        ] {
            cases::decode_case(&read(name)["response"])
                .unwrap_or_else(|e| panic!("{}/{name}: {e}", set.display()));
        }
        let updated = read("case_update_status.json");
        assert!(
            updated["response"].is_array(),
            "bulk update returns an array"
        );
        cases::decode_case(&updated["response"][0]).expect("updated case decodes");
        let conflict = read("case_conflict.json");
        assert!(
            conflict.get("error").is_some(),
            "the stale-version exchange records an error fixture"
        );
        assert_eq!(
            conflict["error"]["kind"],
            serde_json::json!("conflict"),
            "{}: the stale-version PATCH must classify as a conflict",
            set.display()
        );
        assert_eq!(
            conflict["error"]["http_status"],
            serde_json::json!(409),
            "{}: the stale-version PATCH must record the real 409",
            set.display()
        );

        // case_delete: a 204 has no body, so the response side is empty; the
        // request path carries the id array, JSON-encoded then URL-encoded
        // (`elasticctl_api::cases::delete_path`) — assert on a stable
        // substring rather than the whole path, since the placeholder id is
        // itself a scrubbing artifact, not a documented contract.
        let deleted = read("case_delete.json");
        assert!(
            deleted["response"].is_null(),
            "{}: a 204 delete has no recorded body",
            set.display()
        );
        let deleted_id = deleted["request"]["ids"][0]
            .as_str()
            .expect("case_delete request carries the deleted id");
        let deleted_path = deleted["request"]["path"]
            .as_str()
            .expect("case_delete request carries the issued path");
        assert!(
            deleted_path.contains(&format!("%5B%22{deleted_id}")),
            "{}: the delete path must carry the URL-encoded JSON id array: {deleted_path}",
            set.display()
        );
    }
}
