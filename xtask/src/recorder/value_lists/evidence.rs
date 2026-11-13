//! Value-list envelopes preserve opaque concurrency tokens.

use crate::fixtures::{RecordedFixture, error_fixture, exchange_fixture};
use crate::scrub::hosts::scrub_hosts;
use crate::scrub::{scrub_alert_timestamps, scrub_placeholder_values};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct Evidence {
    pub(super) flavor: String,
    pub(super) version: String,
    pub(super) fixtures: Vec<RecordedFixture>,
    pub(super) hosts: Vec<String>,
    ids: BTreeMap<String, String>,
    identities: BTreeSet<String>,
}

// Remove versions before shared scrubbing, then restore them at their paths.
fn take_versions(value: &mut Value, path: String, versions: &mut Vec<(String, Value)>) {
    match value {
        Value::Object(map) => {
            if let Some(version) = map.remove("_version") {
                versions.push((path.clone(), version));
            }
            for (key, child) in map {
                let key = key.replace('~', "~0").replace('/', "~1");
                take_versions(child, format!("{path}/{key}"), versions);
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter_mut().enumerate() {
                take_versions(child, format!("{path}/{index}"), versions);
            }
        }
        _ => {}
    }
}

fn register_ids(value: &Value, ids: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if matches!(key.as_str(), "id" | "item_id" | "list_id" | "value_list_id")
                    && let Some(id) = child.as_str()
                {
                    let next = ids.len() + 1;
                    ids.entry(id.to_string())
                        .or_insert_with(|| format!("elasticctl-fixture-value-list-id-{next}"));
                }
                register_ids(child, ids);
            }
        }
        Value::Array(array) => array.iter().for_each(|child| register_ids(child, ids)),
        _ => {}
    }
}

fn register_private_values(original: &Value, scrubbed: &Value, identities: &mut BTreeSet<String>) {
    match (original, scrubbed) {
        (Value::String(value), Value::String(redacted))
            if redacted == "REDACTED" && !value.is_empty() =>
        {
            identities.insert(value.clone());
        }
        (Value::Object(original), Value::Object(scrubbed)) => {
            for (key, value) in original {
                // Opaque versions stay public and must survive unchanged.
                if key != "_version"
                    && let Some(redacted) = scrubbed.get(key)
                {
                    register_private_values(value, redacted, identities);
                }
            }
        }
        (Value::Array(original), Value::Array(scrubbed)) => {
            for (value, redacted) in original.iter().zip(scrubbed) {
                register_private_values(value, redacted, identities);
            }
        }
        _ => {}
    }
}

fn token_character(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-')
}

fn scrub_identities(value: &mut Value, identities: &BTreeSet<String>) {
    match value {
        Value::String(text) => {
            let mut redacted = String::new();
            let mut copied = 0;
            for (start, _) in text.char_indices() {
                if start < copied
                    || text[..start]
                        .chars()
                        .next_back()
                        .is_some_and(token_character)
                {
                    continue;
                }
                let identity = identities
                    .iter()
                    .filter(|identity| {
                        text[start..].starts_with(identity.as_str())
                            && !text[start + identity.len()..]
                                .chars()
                                .next()
                                .is_some_and(token_character)
                    })
                    .max_by_key(|identity| identity.len());
                if let Some(identity) = identity {
                    redacted.push_str(&text[copied..start]);
                    redacted.push_str("REDACTED");
                    copied = start + identity.len();
                }
            }
            redacted.push_str(&text[copied..]);
            *text = redacted;
        }
        Value::Object(map) => map
            .values_mut()
            .for_each(|value| scrub_identities(value, identities)),
        Value::Array(array) => array
            .iter_mut()
            .for_each(|value| scrub_identities(value, identities)),
        _ => {}
    }
}

fn scrub_cursors(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "cursor" && child.is_string() {
                    *child = json!("elasticctl-fixture-cursor");
                } else {
                    scrub_cursors(child);
                }
            }
        }
        Value::Array(array) => array.iter_mut().for_each(scrub_cursors),
        _ => {}
    }
}

impl Evidence {
    pub(super) fn new(hosts: Vec<String>) -> Self {
        Self {
            hosts,
            ..Self::default()
        }
    }

    pub(super) fn private(&mut self, value: String) {
        self.ids.insert(value, "REDACTED".to_string());
    }

    pub(super) fn observe(&mut self, value: &Value) {
        register_ids(value, &mut self.ids);
        let mut scrubbed = value.clone();
        crate::scrub::scrub(&mut scrubbed);
        register_private_values(value, &scrubbed, &mut self.identities);
    }

    pub(super) fn response(&mut self, name: &'static str, body: Value) {
        self.exchange(name, Value::Null, body);
    }

    pub(super) fn http_response(&mut self, name: &'static str, status: u16, body: Value) {
        self.response(name, body);
        self.fixtures.last_mut().unwrap().document["http_status"] = json!(status);
    }

    pub(super) fn exchange(&mut self, name: &'static str, mut request: Value, mut body: Value) {
        self.observe(&request);
        self.observe(&body);
        let mut versions = Vec::new();
        // Export strings remain byte-for-byte as received, including order and duplicates.
        for (root, value) in [("/request", &mut request), ("/response", &mut body)] {
            take_versions(value, root.to_string(), &mut versions);
            scrub_identities(value, &self.identities);
            scrub_placeholder_values(value, &self.ids);
            scrub_alert_timestamps(value);
            scrub_cursors(value);
        }
        let mut fixture = exchange_fixture(name, &self.flavor, &self.version, request, body);
        for (path, version) in versions {
            if let Some(parent) = fixture.document.pointer_mut(&path) {
                parent["_version"] = version;
            }
        }
        scrub_hosts(&mut fixture.document, &self.hosts);
        if fixture.document["request"].is_null() {
            fixture.document.as_object_mut().unwrap().remove("request");
        }
        self.fixtures.push(fixture);
    }

    pub(super) fn refusal(&mut self, name: &'static str, mut error: elasticctl_core::Error) {
        // A remote error's prose can quote identities outside the named scrub fields.
        error.message = "value-list recording endpoint refused request".to_string();
        self.fixtures
            .push(error_fixture(name, &self.flavor, &self.version, error));
    }
}
