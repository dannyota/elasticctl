pub(crate) mod hosts;

use crate::recorder::markers::ALERT_FIXTURE_TIMESTAMP;
use crate::recorder::preview::RULE_VOLATILE_FIELDS;
use crate::scrub::hosts::scrub_hosts;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const SCRUB_FIELDS: &[&str] = &[
    "username",
    "full_name",
    "email",
    "created_by",
    "updated_by",
    "closed_by",
    "pushed_by",
    "tie_breaker_id",
    "_version",
    "realm_name",
];

pub(crate) fn scrub(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                if is_sensitive(k) {
                    redact(val);
                } else {
                    scrub(val);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(scrub),
        Value::String(text) => {
            if let Some(redacted) = redact_backing_index_date(text) {
                *text = redacted;
            }
        }
        _ => {}
    }
}

fn redact_backing_index_date(name: &str) -> Option<String> {
    let rest = name.strip_prefix(".ds-")?;
    let (head, generation) = rest.rsplit_once('-')?;
    let (stream, date) = head.rsplit_once('-')?;
    let is_date = date.len() == 10
        && date.bytes().enumerate().all(|(i, byte)| {
            if i == 4 || i == 7 {
                byte == b'.'
            } else {
                byte.is_ascii_digit()
            }
        });
    let is_generation = !generation.is_empty() && generation.bytes().all(|b| b.is_ascii_digit());
    let is_stream = !stream.is_empty()
        && stream.to_lowercase() == stream
        && !stream.chars().any(|c| {
            matches!(
                c,
                ' ' | '\\' | '/' | '*' | '?' | '"' | '<' | '>' | '|' | ',' | '#' | ':'
            )
        });
    (is_stream && is_date && is_generation).then(|| format!(".ds-{stream}-REDACTED-{generation}"))
}

fn is_sensitive(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let leaf = lower.rsplit('.').next().unwrap_or(&lower);
    lower.contains("api_key")
        || lower.contains("apikey")
        || lower == "kibana.alert.rule.uuid"
        || matches!(leaf, "authorization" | "password" | "encoded")
        || SCRUB_FIELDS.contains(&leaf)
}

pub(crate) fn redact(val: &mut Value) {
    match val {
        Value::String(_) => *val = json!("REDACTED"),
        Value::Null => {}
        Value::Object(m) => {
            for leaf in m.values_mut() {
                redact(leaf);
            }
        }
        Value::Array(a) => {
            for item in a.iter_mut() {
                redact(item);
            }
        }
        _ => *val = json!("REDACTED"),
    }
}

pub(crate) fn strip_volatile(v: &mut Value, fields: &[&str]) {
    match v {
        Value::Object(m) => {
            m.retain(|key, _| !fields.contains(&key.as_str()));
            for value in m.values_mut() {
                strip_volatile(value, fields);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| strip_volatile(x, fields)),
        _ => {}
    }
}

pub(crate) fn scrub_status(status: &mut Value) {
    let Some(status) = status.as_object_mut() else {
        return;
    };
    for field in ["name", "uuid", "metrics"] {
        status.remove(field);
    }
}

pub(crate) const LICENSE_VOLATILE_FIELDS: &[&str] = &[
    "uid",
    "issue_date",
    "issue_date_in_millis",
    "expiry_date",
    "expiry_date_in_millis",
];

pub(crate) fn strip_pit_token(v: &mut Value) {
    let Some(map) = v.as_object_mut() else {
        return;
    };
    map.remove("id");
    if let Some(Value::Object(pit)) = map.get_mut("pit") {
        pit.remove("id");
    }
}

const DATA_VIEW_IDENTITY_FIELDS: &[&str] = &["id", "title", "name", "namespaces"];

pub(crate) fn redact_authenticate_metadata(v: &mut Value) {
    if let Some(metadata) = v.get_mut("metadata") {
        redact(metadata);
    }
}

pub(crate) fn redact_data_views(v: &mut Value) {
    let Some(views) = v.get_mut("data_view").and_then(Value::as_array_mut) else {
        return;
    };
    for view in views.iter_mut() {
        let Some(map) = view.as_object_mut() else {
            continue;
        };
        for field in DATA_VIEW_IDENTITY_FIELDS {
            if let Some(value) = map.get_mut(*field) {
                redact(value);
            }
        }
    }
}

pub(crate) fn scrub_placeholder_values(v: &mut Value, map: &BTreeMap<String, String>) {
    match v {
        Value::String(s) => {
            for (real, placeholder) in map {
                if !real.is_empty() && s.contains(real.as_str()) {
                    *s = s.replace(real.as_str(), placeholder.as_str());
                }
            }
        }
        Value::Object(m) => m
            .values_mut()
            .for_each(|x| scrub_placeholder_values(x, map)),
        Value::Array(a) => a.iter_mut().for_each(|x| scrub_placeholder_values(x, map)),
        _ => {}
    }
}

const ALERT_TIMESTAMP_KEYS: &[&str] = &[
    "kibana.alert.last_detected",
    "kibana.alert.original_time",
    "kibana.alert.intended_timestamp",
    "kibana.alert.rule.execution.timestamp",
];

fn is_alert_timestamp_key(key: &str) -> bool {
    key == "@timestamp"
        || key.ends_with("_at")
        || key.ends_with(".start")
        || key.ends_with(".end")
        || ALERT_TIMESTAMP_KEYS.contains(&key)
}

pub(crate) fn scrub_alert_timestamps(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (key, value) in m.iter_mut() {
                if value.is_string() && is_alert_timestamp_key(key) {
                    *value = json!(ALERT_FIXTURE_TIMESTAMP);
                } else {
                    scrub_alert_timestamps(value);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(scrub_alert_timestamps),
        _ => {}
    }
}

const ALERT_FIXTURE_URL: &str =
    "https://REDACTED.example.invalid/app/security/alerts/redirect/elasticctl-fixture-redacted";

pub(crate) fn scrub_alert_urls(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (key, value) in m.iter_mut() {
                if key == "kibana.alert.url" && value.is_string() {
                    *value = json!(ALERT_FIXTURE_URL);
                } else {
                    scrub_alert_urls(value);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(scrub_alert_urls),
        _ => {}
    }
}

pub(crate) fn scrub_ndjson(text: &str, hosts: &[String]) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut v: Value = serde_json::from_str(line).expect("export line is JSON");
        scrub(&mut v);
        scrub_hosts(&mut v, hosts);
        strip_volatile(&mut v, RULE_VOLATILE_FIELDS);
        out.push_str(&serde_json::to_string(&v).expect("encode scrubbed export line"));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::markers::ALERT_FIXTURE_TIMESTAMP;
    use serde_json::{Value, json};
    use std::collections::BTreeMap;

    #[test]
    fn scrub_redacts_only_the_backing_index_date() {
        let mut value = json!({
            "_index": ".ds-.alerts-security.alerts-default-2026.11.09-000001",
            "indices": [
                ".ds-logs-system.auth-default-2026.01.31-000012",
                ".ds-logs@prod-2026.11.09-000001",
                ".ds-logs-café-2026.11.09-000001",
                ".ds-logs\u{a0}prod-2026.11.09-000001",
                ".ds-logs\u{2102}-2026.11.09-000001"
            ],
            "keep": [
                ".alerts-security.alerts-default",
                ".ds-no-date-000001",
                ".ds-x-2026.11.09-",
                ".ds--2026.11.09-000001",
                "logs-2026.11.09-000001",
                ".ds-a-2026.11.09-000001,.ds-b-2026.11.10-000002",
                ".ds-a b-2026.11.09-000001",
                ".ds-Upper-2026.11.09-000001",
                "https://host.invalid/.ds-a-2026.11.09-000001"
            ]
        });

        scrub(&mut value);

        assert_eq!(
            value,
            json!({
                "_index": ".ds-.alerts-security.alerts-default-REDACTED-000001",
                "indices": [
                    ".ds-logs-system.auth-default-REDACTED-000012",
                    ".ds-logs@prod-REDACTED-000001",
                    ".ds-logs-café-REDACTED-000001",
                    ".ds-logs\u{a0}prod-REDACTED-000001",
                    ".ds-logs\u{2102}-REDACTED-000001"
                ],
                "keep": [
                    ".alerts-security.alerts-default",
                    ".ds-no-date-000001",
                    ".ds-x-2026.11.09-",
                    ".ds--2026.11.09-000001",
                    "logs-2026.11.09-000001",
                    ".ds-a-2026.11.09-000001,.ds-b-2026.11.10-000002",
                    ".ds-a b-2026.11.09-000001",
                    ".ds-Upper-2026.11.09-000001",
                    "https://host.invalid/.ds-a-2026.11.09-000001"
                ]
            })
        );
    }

    #[test]
    fn status_scrub_removes_instance_identity_and_runtime_metrics() {
        let mut status = json!({
            "name": "private-instance-name",
            "uuid": "private-instance-uuid",
            "version": {
                "number": "9.6.0",
                "build_hash": "public-product-build"
            },
            "metrics": {"process": {"uptime_in_millis": 42}}
        });

        scrub_status(&mut status);

        assert_eq!(
            status,
            json!({
                "version": {
                    "number": "9.6.0",
                    "build_hash": "public-product-build"
                }
            })
        );
    }

    #[test]
    fn dotted_identity_keys_are_scrubbed() {
        let mut v = json!({
            "kibana.alert.rule.created_by": "someone",
            "kibana.alert.rule.name": "keep me",
            "nested": {
                "updated_by": "someone else",
                "tie_breaker_id": 42,
                "_version": {"value": "server-owned"}
            }
        });
        scrub(&mut v);
        assert_eq!(v["kibana.alert.rule.created_by"], "REDACTED");
        assert_eq!(v["nested"]["updated_by"], "REDACTED");
        assert_eq!(v["nested"]["tie_breaker_id"], "REDACTED");
        assert_eq!(v["nested"]["_version"]["value"], "REDACTED");
        assert_eq!(v["kibana.alert.rule.name"], "keep me");
    }

    #[test]
    fn ndjson_scrub_redacts_identity_and_recording_hosts() {
        let text = concat!(
            r#"{"created_by":7,"updated_by":"operator","tie_breaker_id":"stack","_version":4,"kibana.alert.url":"https://cluster.example:9243/app"}"#,
            "\n"
        );
        let scrubbed = scrub_ndjson(text, &["cluster.example:9243".to_string()]);
        let value: Value = serde_json::from_str(scrubbed.trim()).expect("scrubbed NDJSON is JSON");

        assert_eq!(value["created_by"], "REDACTED");
        assert_eq!(value["updated_by"], "REDACTED");
        assert_eq!(value["tie_breaker_id"], "REDACTED");
        assert_eq!(value["_version"], "REDACTED");
        assert_eq!(
            value["kibana.alert.url"],
            "https://REDACTED.example.invalid/app"
        );
    }

    #[test]
    fn strip_volatile_drops_only_the_named_fields_everywhere() {
        let mut value = json!({
            "took": 1,
            "keep": "me",
            "hits": {"hits": [{"_source": {"seq": 1}, "_score": 1.0, "sort": [1, 0]}]},
            "nested": [{"took": 2, "value": 3}]
        });

        strip_volatile(&mut value, &["took", "_score", "sort"]);

        assert_eq!(
            value,
            json!({
                "keep": "me",
                "hits": {"hits": [{"_source": {"seq": 1}}]},
                "nested": [{"value": 3}]
            })
        );
    }

    #[test]
    fn strip_volatile_drops_license_trial_fields() {
        let mut value = json!({
            "license": {
                "status": "active",
                "uid": "per-trial-uuid",
                "type": "trial",
                "issue_date": "2026-08-16",
                "expiry_date_in_millis": 1,
                "issued_to": "cluster"
            }
        });

        strip_volatile(&mut value, LICENSE_VOLATILE_FIELDS);

        assert_eq!(
            value,
            json!({"license": {"status": "active", "type": "trial", "issued_to": "cluster"}})
        );
    }

    #[test]
    fn strip_pit_token_removes_the_token_from_open_response_and_page_request() {
        let mut open = json!({"id": "opaque-token", "_shards": {"total": 1}});
        strip_pit_token(&mut open);
        assert_eq!(open, json!({"_shards": {"total": 1}}));

        let mut request = json!({
            "size": 2,
            "sort": [{"seq": "asc"}, {"_shard_doc": "asc"}],
            "pit": {"id": "opaque-token", "keep_alive": "1m"},
            "query": {"match_all": {}}
        });
        strip_pit_token(&mut request);
        assert_eq!(
            request,
            json!({
                "size": 2,
                "sort": [{"seq": "asc"}, {"_shard_doc": "asc"}],
                "pit": {"keep_alive": "1m"},
                "query": {"match_all": {}}
            })
        );
    }

    #[test]
    fn redact_authenticate_metadata_redacts_every_leaf_regardless_of_key_shape() {
        let mut value = json!({
            "username": "REDACTED",
            "metadata": {
                "saml(http://saml.elastic-cloud.com/attributes/email)": ["real@example.com"],
                "saml(http://saml.elastic-cloud.com/attributes/uiam/authentication/access_token)": ["essu_realtoken"],
                "nested": {"still": "sensitive"}
            }
        });

        redact_authenticate_metadata(&mut value);

        assert_eq!(
            value["metadata"]["saml(http://saml.elastic-cloud.com/attributes/email)"][0],
            "REDACTED"
        );
        assert_eq!(
            value["metadata"]["saml(http://saml.elastic-cloud.com/attributes/uiam/authentication/access_token)"]
                [0],
            "REDACTED"
        );
        assert_eq!(value["metadata"]["nested"]["still"], "REDACTED");
        assert_eq!(value["username"], "REDACTED");
    }

    #[test]
    fn redact_authenticate_metadata_leaves_an_empty_object_untouched() {
        let mut value = json!({"metadata": {}});
        redact_authenticate_metadata(&mut value);
        assert_eq!(value, json!({"metadata": {}}));
    }

    #[test]
    fn redact_data_views_redacts_identity_but_keeps_configuration() {
        let mut value = json!({
            "data_view": [
                {
                    "id": "security-solution-alert-default",
                    "title": ".alerts-security.alerts-default",
                    "name": "Security solution alert default",
                    "namespaces": ["default"],
                    "allowNoIndex": false,
                    "timeFieldName": "@timestamp"
                }
            ]
        });

        redact_data_views(&mut value);

        assert_eq!(
            value,
            json!({
                "data_view": [
                    {
                        "id": "REDACTED",
                        "title": "REDACTED",
                        "name": "REDACTED",
                        "namespaces": ["REDACTED"],
                        "allowNoIndex": false,
                        "timeFieldName": "@timestamp"
                    }
                ]
            })
        );
    }

    #[test]
    fn scrub_placeholder_values_rewrites_substring_matches_too() {
        let mut map = BTreeMap::new();
        map.insert(
            "abc123realid".to_string(),
            "elasticctl-fixture-alert-1".to_string(),
        );
        let mut value = json!({
            "_id": "abc123realid",
            "signal_ids": ["abc123realid"],
            "kibana.alert.url": "https://host/app/security/alerts/redirect/abc123realid?index=x",
            "unrelated": "nothing to see here"
        });

        scrub_placeholder_values(&mut value, &map);

        assert_eq!(value["_id"], "elasticctl-fixture-alert-1");
        assert_eq!(value["signal_ids"][0], "elasticctl-fixture-alert-1");
        assert_eq!(
            value["kibana.alert.url"],
            "https://host/app/security/alerts/redirect/elasticctl-fixture-alert-1?index=x"
        );
        assert_eq!(value["unrelated"], "nothing to see here");
    }

    #[test]
    fn scrub_alert_urls_replaces_the_whole_value() {
        let mut value = json!({
            "kibana.alert.url": "https://REDACTED.example.invalid/app/security/alerts/redirect/deadbeef?index=x&timestamp=2026-09-01T05:48:22.428Z",
            "kibana.alert.rule.name": "keep me"
        });

        scrub_alert_urls(&mut value);

        assert_eq!(value["kibana.alert.url"], ALERT_FIXTURE_URL);
        assert_eq!(value["kibana.alert.rule.name"], "keep me");
    }

    #[test]
    fn scrub_alert_timestamps_rewrites_matching_keys_only() {
        let mut value = json!({
            "@timestamp": "2026-08-30T21:14:02.000Z",
            "kibana.alert.workflow_status_updated_at": "2026-08-30T21:14:02.000Z",
            "kibana.alert.start": "2026-08-30T21:14:02.000Z",
            "kibana.alert.end": "2026-08-30T21:14:02.000Z",
            "kibana.alert.original_time": "2026-08-30T21:14:02.000Z",
            "kibana.alert.last_detected": "2026-08-30T21:14:02.000Z",
            "kibana.alert.intended_timestamp": "2026-08-30T21:14:02.000Z",
            "kibana.alert.rule.execution.timestamp": "2026-08-30T21:14:02.000Z",
            "kibana.alert.workflow_status": "open"
        });

        scrub_alert_timestamps(&mut value);

        assert_eq!(value["@timestamp"], ALERT_FIXTURE_TIMESTAMP);
        assert_eq!(
            value["kibana.alert.workflow_status_updated_at"],
            ALERT_FIXTURE_TIMESTAMP
        );
        assert_eq!(value["kibana.alert.start"], ALERT_FIXTURE_TIMESTAMP);
        assert_eq!(value["kibana.alert.end"], ALERT_FIXTURE_TIMESTAMP);
        assert_eq!(
            value["kibana.alert.original_time"], ALERT_FIXTURE_TIMESTAMP,
            "explicit key shapes are rewritten too, not just the _at/.start/.end suffix pattern"
        );
        assert_eq!(value["kibana.alert.last_detected"], ALERT_FIXTURE_TIMESTAMP);
        assert_eq!(
            value["kibana.alert.intended_timestamp"],
            ALERT_FIXTURE_TIMESTAMP
        );
        assert_eq!(
            value["kibana.alert.rule.execution.timestamp"],
            ALERT_FIXTURE_TIMESTAMP
        );
        assert_eq!(value["kibana.alert.workflow_status"], "open");
    }
}
