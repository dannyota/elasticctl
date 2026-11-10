//! Fixture normalization and the private log.
//!
//! Recorded exchanges are held until the step ends, then scrubbed with the
//! final placeholder map, so an id learned late is still replaced in every
//! fixture. Raw bodies, timings, and measurements that must stay out of the
//! public fixtures go to an owner-only file under the ignored `target/`.

use crate::fixtures::{RecordedFixture, error_fixture, exchange_fixture};
use crate::recorder::compose::requests::Planned;
use crate::recorder::markers::{
    ALERT_FIXTURE_TIMESTAMP, ALERT_SEARCH_VOLATILE_FIELDS, CASE_DURATION_VOLATILE_FIELDS,
};
use crate::recorder::preview::RULE_VOLATILE_FIELDS;
use crate::scrub::hosts::{recording_hosts, scrub_hosts};
use crate::scrub::{
    scrub_alert_timestamps, scrub_alert_urls, scrub_placeholder_values, strip_volatile,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The alert field whose presence is a private measurement. It never
/// reaches a fixture.
pub(super) const CASE_IDS_FIELD: &str = "kibana.alert.case_ids";

/// Stands in for the alerts backing index, which is not a marker name.
pub(super) const ALERT_INDEX_PLACEHOLDER: &str = "elasticctl-fixture-alert-index";

/// Prefixes of a marker index, alias, data stream, or backing index name.
const MARKER_NAME_PREFIXES: [&str; 2] = ["elasticctl-sample-", ".ds-elasticctl-sample-"];

/// Resolve keys whose values are not index names.
const RESOLVE_NON_NAME_KEYS: [&str; 3] = ["attributes", "timestamp_field", "mode"];

/// True when every name a `_resolve/index` body holds, at any depth, is a
/// marker name: top-level entries and the aliases, indices, data streams,
/// and backing indices nested in them. Attribute words, the timestamp
/// field, and the index mode are not names.
pub(super) fn resolve_names_are_markers(body: &Value) -> bool {
    fn walk(value: &Value) -> bool {
        match value {
            Value::String(name) => MARKER_NAME_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix)),
            Value::Array(items) => items.iter().all(walk),
            Value::Object(map) => map
                .iter()
                .all(|(key, value)| RESOLVE_NON_NAME_KEYS.contains(&key.as_str()) || walk(value)),
            Value::Null | Value::Bool(_) | Value::Number(_) => true,
        }
    }
    ["indices", "aliases", "data_streams"]
        .iter()
        .all(|key| body.get(*key).is_some_and(Value::is_array))
        && walk(body)
}

/// Rule fields that change on every create. Only the top level is cleared:
/// a recursive strip of `id` would also remove the `threat` ids.
const RULE_TOP_LEVEL_VOLATILE: [&str; 3] = ["id", "created_at", "updated_at"];

fn zero_numbers(value: &mut Value) {
    match value {
        Value::Number(number) => {
            *value = if number.is_f64() {
                json!(0.0)
            } else {
                json!(0)
            };
        }
        Value::Object(map) => map.values_mut().for_each(zero_numbers),
        Value::Array(items) => items.iter_mut().for_each(zero_numbers),
        _ => {}
    }
}

/// Normalize one rule body. `execution_summary` stays: its keys, status,
/// message, and metric types are the evidence. Its date becomes the fixed
/// placeholder and every metric becomes zero of the same number kind; the
/// real values go to the private log.
pub(super) fn normalize_rule(rule: &mut Value) {
    let Some(map) = rule.as_object_mut() else {
        return;
    };
    for field in RULE_TOP_LEVEL_VOLATILE {
        map.remove(field);
    }
    if let Some(Value::Array(lists)) = map.get_mut("exceptions_list") {
        for list in lists.iter_mut().filter_map(Value::as_object_mut) {
            list.remove("id");
        }
    }
    if let Some(last) = map
        .get_mut("execution_summary")
        .and_then(|summary| summary.get_mut("last_execution"))
        .and_then(Value::as_object_mut)
    {
        if last.get("date").is_some_and(Value::is_string) {
            last.insert("date".into(), json!(ALERT_FIXTURE_TIMESTAMP));
        }
        if let Some(metrics) = last.get_mut("metrics") {
            zero_numbers(metrics);
        }
    }
}

/// Normalize every rule in a `_find` page.
pub(super) fn normalize_rule_page(page: &mut Value) {
    if let Some(Value::Array(rules)) = page.get_mut("data") {
        rules.iter_mut().for_each(normalize_rule);
    }
}

/// Normalize an exception item page the way item fixtures already are.
pub(super) fn normalize_items(page: &mut Value) {
    strip_volatile(page, RULE_VOLATILE_FIELDS);
}

/// Normalize a signals search the way the alert probe's fixture is, drop
/// the private case-ids field, and replace each hit's backing index with
/// the placeholder.
pub(super) fn normalize_alert_search(response: &mut Value) {
    strip_volatile(response, ALERT_SEARCH_VOLATILE_FIELDS);
    strip_volatile(response, &[CASE_IDS_FIELD]);
    scrub_alert_timestamps(response);
    scrub_alert_urls(response);
    if let Some(Value::Array(hits)) = response.pointer_mut("/hits/hits") {
        for hit in hits.iter_mut().filter_map(Value::as_object_mut) {
            if hit.contains_key("_index") {
                hit.insert("_index".into(), json!(ALERT_INDEX_PLACEHOLDER));
            }
        }
    }
}

/// Normalize the cases-by-alert rows the way case fixtures are. The route
/// uses camel-case timestamps, which the suffix rule does not match.
pub(super) fn normalize_cases_by_alert(response: &mut Value) {
    scrub_alert_timestamps(response);
    strip_volatile(response, CASE_DURATION_VOLATILE_FIELDS);
    if let Value::Array(rows) = response {
        for row in rows.iter_mut().filter_map(Value::as_object_mut) {
            for key in ["createdAt", "updatedAt", "closedAt"] {
                if row.get(key).is_some_and(Value::is_string) {
                    row.insert(key.into(), json!(ALERT_FIXTURE_TIMESTAMP));
                }
            }
        }
    }
}

enum Outcome {
    Response(Value),
    Error(elasticctl_core::Error),
}

struct Pending {
    name: &'static str,
    request: Value,
    outcome: Outcome,
}

/// Exchanges held until the step ends.
#[derive(Default)]
pub(super) struct Exchanges {
    pending: Vec<Pending>,
}

impl Exchanges {
    pub(super) fn response(&mut self, name: &'static str, planned: &Planned, response: Value) {
        self.pending.push(Pending {
            name,
            request: planned.descriptor(),
            outcome: Outcome::Response(response),
        });
    }

    pub(super) fn error(
        &mut self,
        name: &'static str,
        planned: &Planned,
        error: elasticctl_core::Error,
    ) {
        self.pending.push(Pending {
            name,
            request: planned.descriptor(),
            outcome: Outcome::Error(error),
        });
    }

    /// Scrub every held exchange with the final placeholder map.
    pub(super) fn into_fixtures(
        self,
        flavor: &str,
        version: &str,
        placeholders: &BTreeMap<String, String>,
    ) -> Vec<RecordedFixture> {
        self.pending
            .into_iter()
            .map(|pending| {
                let mut request = pending.request;
                scrub_placeholder_values(&mut request, placeholders);
                match pending.outcome {
                    Outcome::Response(mut response) => {
                        scrub_placeholder_values(&mut response, placeholders);
                        exchange_fixture(pending.name, flavor, version, request, response)
                    }
                    Outcome::Error(mut error) => {
                        for (real, placeholder) in placeholders {
                            if !real.is_empty() {
                                error.message = error.message.replace(real, placeholder);
                            }
                        }
                        let mut fixture = error_fixture(pending.name, flavor, version, error);
                        let mut request = request;
                        crate::scrub::scrub(&mut request);
                        scrub_hosts(&mut request, &recording_hosts());
                        fixture.document["request"] = request;
                        fixture
                    }
                }
            })
            .collect()
    }
}

/// Owner-only record of raw bodies, timings, and private measurements.
#[derive(Default)]
pub(super) struct PrivateLog {
    target: Option<String>,
    entries: Map<String, Value>,
}

fn safe_label(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

impl PrivateLog {
    pub(super) fn set_target(&mut self, flavor: &str, version: &str) {
        let label = format!("{flavor}-{version}");
        self.target = safe_label(&label).then_some(label);
    }

    /// Set one top-level entry.
    pub(super) fn set(&mut self, key: &str, value: Value) {
        self.entries.insert(key.to_string(), value);
    }

    /// Add one value under a named section.
    pub(super) fn add(&mut self, section: &str, key: &str, value: Value) {
        let entry = self
            .entries
            .entry(section.to_string())
            .or_insert_with(|| json!({}));
        if let Value::Object(map) = entry {
            map.insert(key.to_string(), value);
        }
    }

    #[cfg(test)]
    pub(super) fn get(&self, key: &str) -> Option<&Value> {
        self.entries.get(key)
    }

    pub(super) fn path(&self, workspace: &Path) -> PathBuf {
        workspace
            .join("target")
            .join("record-private")
            .join(self.target.as_deref().unwrap_or("unknown"))
            .join("compose.json")
    }

    /// Write the log with mode 0600. Errors carry only a static message.
    pub(super) fn write(&self, workspace: &Path) -> Result<PathBuf, &'static str> {
        const FAILED: &str = "record-compose private log write failed";
        let path = self.path(workspace);
        let parent = path.parent().ok_or(FAILED)?;
        std::fs::create_dir_all(parent).map_err(|_| FAILED)?;
        let encoded =
            serde_json::to_vec_pretty(&Value::Object(self.entries.clone())).map_err(|_| FAILED)?;
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            options.mode(0o600);
            if path.exists() {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|_| FAILED)?;
            }
        }
        let mut file = options.open(&path).map_err(|_| FAILED)?;
        file.write_all(&encoded).map_err(|_| FAILED)?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::compose::requests::{rule_get, signals_activity};

    fn executed_rule() -> Value {
        json!({
            "id": "so-1",
            "rule_id": "elasticctl-sample-alert-probe",
            "created_at": "2026-11-10T01:02:03.000Z",
            "updated_at": "2026-11-10T01:02:03.000Z",
            "created_by": "operator",
            "threat": [{"framework": "MITRE ATT&CK", "tactic": {"id": "TA0002"},
                "technique": [{"id": "T1059", "subtechnique": [{"id": "T1059.001"}]}]}],
            "exceptions_list": [{"id": "list-so", "list_id": "elasticctl-sample-exceptions",
                "namespace_type": "single", "type": "detection"}],
            "execution_summary": {"last_execution": {
                "date": "2026-11-10T01:03:00.000Z", "status": "succeeded", "status_order": 0,
                "message": "Rule execution completed successfully",
                "metrics": {"total_search_duration_ms": 17, "execution_gap_duration_s": 1.5}
            }}
        })
    }

    #[test]
    fn rule_normalization_keeps_threat_ids_and_the_execution_shape() {
        let mut rule = executed_rule();
        normalize_rule(&mut rule);
        assert!(rule.get("id").is_none());
        assert!(rule.get("created_at").is_none());
        assert!(rule.get("updated_at").is_none());
        assert!(rule["exceptions_list"][0].get("id").is_none());
        assert_eq!(
            rule["exceptions_list"][0]["list_id"],
            "elasticctl-sample-exceptions"
        );
        assert_eq!(rule["threat"][0]["tactic"]["id"], "TA0002");
        assert_eq!(rule["threat"][0]["technique"][0]["id"], "T1059");
        assert_eq!(
            rule["threat"][0]["technique"][0]["subtechnique"][0]["id"],
            "T1059.001"
        );
        let last = &rule["execution_summary"]["last_execution"];
        assert_eq!(last["date"], ALERT_FIXTURE_TIMESTAMP);
        assert_eq!(last["status"], "succeeded");
        assert_eq!(last["status_order"], 0);
        assert_eq!(last["message"], "Rule execution completed successfully");
        assert!(last["metrics"]["total_search_duration_ms"].is_u64());
        assert_eq!(last["metrics"]["total_search_duration_ms"], 0);
        assert!(last["metrics"]["execution_gap_duration_s"].is_f64());
    }

    #[test]
    fn rule_page_normalization_applies_to_every_row() {
        let mut page = json!({"page": 1, "perPage": 500, "total": 2,
            "data": [executed_rule(), executed_rule()]});
        normalize_rule_page(&mut page);
        for rule in page["data"].as_array().expect("rows") {
            assert!(rule.get("id").is_none());
            assert_eq!(rule["threat"][0]["technique"][0]["id"], "T1059");
        }
        assert_eq!(page["total"], 2);
    }

    #[test]
    fn alert_search_normalization_drops_case_ids_and_run_state() {
        let mut response = json!({
            "took": 3, "_shards": {"total": 1},
            "hits": {"total": {"value": 1, "relation": "eq"}, "max_score": null, "hits": [{
                "_id": "a1", "_score": null, "sort": [1, "a1"],
                "_source": {"@timestamp": "2026-11-10T01:03:00.000Z",
                    "kibana.alert.case_ids": ["c1"],
                    "kibana.alert.url": "https://private.example.internal/x",
                    "kibana.alert.rule.execution.uuid": "run-1"}
            }]},
            "aggregations": {"status": {"buckets": [{"key": "open", "doc_count": 1}]}}
        });
        response["hits"]["hits"][0]["_index"] =
            json!(".internal.alerts-security.alerts-private-space-000001");
        normalize_alert_search(&mut response);
        let hit = &response["hits"]["hits"][0];
        assert_eq!(hit["_index"], ALERT_INDEX_PLACEHOLDER);
        assert!(!response.to_string().contains("alerts-security"));
        assert!(hit["_source"].get(CASE_IDS_FIELD).is_none());
        assert!(hit.get("sort").is_none());
        assert!(response.get("took").is_none());
        assert_eq!(hit["_source"]["@timestamp"], ALERT_FIXTURE_TIMESTAMP);
        assert!(!response.to_string().contains("private.example"));
        assert_eq!(
            response["aggregations"]["status"]["buckets"][0]["doc_count"],
            1
        );
    }

    #[test]
    fn resolve_validation_reaches_every_nested_name() {
        let marker = json!({
            "indices": [{"name": "elasticctl-sample-alert-events", "attributes": ["open", "hidden"],
                "aliases": ["elasticctl-sample-alias"], "data_stream": "elasticctl-sample-ds",
                "mode": "standard"}],
            "aliases": [{"name": "elasticctl-sample-alias", "indices": ["elasticctl-sample-alert-events"]}],
            "data_streams": [{"name": "elasticctl-sample-ds", "timestamp_field": "@timestamp",
                "backing_indices": [".ds-elasticctl-sample-ds-REDACTED-000001"]}]
        });
        assert!(resolve_names_are_markers(&marker));
        assert!(resolve_names_are_markers(
            &json!({"indices": [], "aliases": [], "data_streams": []})
        ));
        for (pointer, leaked) in [
            ("/indices/0/aliases/0", "prod-secrets"),
            ("/indices/0/data_stream", "logs-private"),
            ("/aliases/0/indices/0", "customer-data"),
            (
                "/data_streams/0/backing_indices/0",
                ".ds-logs-private-2026.11.10-000001",
            ),
            ("/indices/0/name", "other-index"),
        ] {
            let mut body = marker.clone();
            *body.pointer_mut(pointer).expect("pointer") = json!(leaked);
            assert!(!resolve_names_are_markers(&body), "{pointer}");
        }
        let mut unknown = marker.clone();
        unknown["indices"][0]["new_field"] = json!("unlisted-name");
        assert!(!resolve_names_are_markers(&unknown));
        assert!(!resolve_names_are_markers(&json!({"indices": []})));
    }

    #[test]
    fn cases_by_alert_normalization_pins_camel_case_timestamps() {
        let mut response = json!([{"id": "c1", "title": "elasticctl sample case",
            "createdAt": "2026-11-10T01:03:00.000Z", "totals": {"alerts": 1, "userComments": 0}}]);
        normalize_cases_by_alert(&mut response);
        assert_eq!(response[0]["createdAt"], ALERT_FIXTURE_TIMESTAMP);
        assert_eq!(response[0]["totals"]["alerts"], 1);
    }

    #[test]
    fn exchanges_scrub_with_the_final_placeholder_map() {
        let mut exchanges = Exchanges::default();
        exchanges.response(
            "rule_get_executed",
            &rule_get("elasticctl-sample-alert-probe"),
            json!({"note": "list-so and a1"}),
        );
        exchanges.error(
            "resolve_index_not_found",
            &signals_activity(),
            elasticctl_core::Error::with_status(
                elasticctl_core::ErrorKind::NotFound,
                404,
                "no such index [a1]",
            ),
        );
        let placeholders = BTreeMap::from([
            (
                "list-so".to_string(),
                "elasticctl-fixture-exception-list".to_string(),
            ),
            ("a1".to_string(), "elasticctl-fixture-alert-1".to_string()),
        ]);
        let fixtures = exchanges.into_fixtures("serverless", "9.7.0", &placeholders);
        assert_eq!(
            fixtures[0].document["response"]["note"],
            "elasticctl-fixture-exception-list and elasticctl-fixture-alert-1"
        );
        assert_eq!(fixtures[0].document["request"]["method"], "GET");
        assert_eq!(fixtures[1].document["error"]["kind"], "not_found");
        assert_eq!(fixtures[1].document["error"]["http_status"], 404);
        assert_eq!(
            fixtures[1].document["error"]["message"],
            "no such index [elasticctl-fixture-alert-1]"
        );
        assert_eq!(
            fixtures[1].document["request"]["path"],
            "/api/detection_engine/signals/search"
        );
    }

    #[test]
    fn private_log_lands_under_ignored_target_with_owner_only_mode() {
        let dir = std::env::temp_dir().join(format!(
            "elasticctl-compose-log-{}-{}",
            std::process::id(),
            line!()
        ));
        let mut log = PrivateLog::default();
        log.set_target("serverless", "9.7.0");
        log.set("kibana_alert_case_ids_present", json!(true));
        log.add("timings_ms", "cases_by_alert", json!(12));
        let path = log.write(&dir).expect("write");
        assert_eq!(
            path,
            dir.join("target/record-private/serverless-9.7.0/compose.json")
        );
        let written: Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");
        assert_eq!(written["kibana_alert_case_ids_present"], true);
        assert_eq!(written["timings_ms"]["cases_by_alert"], 12);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).expect("cleanup");

        let mut unsafe_target = PrivateLog::default();
        unsafe_target.set_target("../x", "9");
        assert!(unsafe_target.path(&dir).ends_with("unknown/compose.json"));
    }
}
