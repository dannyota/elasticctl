use crate::recorder::preview::{
    PREVIEW_HITS_RESPONSE_VOLATILE_FIELDS, PREVIEW_VOLATILE_FIELDS, RULE_VOLATILE_FIELDS,
};
use crate::scrub::hosts::{recording_hosts, scrub_hosts};
use crate::scrub::{scrub, strip_volatile};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub(crate) struct RecordedFixture {
    pub(crate) name: &'static str,
    pub(crate) document: Value,
}

pub(crate) struct Recording {
    pub(crate) dir: PathBuf,
    pub(crate) fixtures: Vec<RecordedFixture>,
}

pub(crate) fn response_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    mut body: Value,
    headers: Option<&BTreeMap<String, String>>,
) -> RecordedFixture {
    let hosts = recording_hosts();
    scrub(&mut body);
    scrub_hosts(&mut body, &hosts);
    let mut document =
        json!({"flavor": flavor, "version": version, "operation": name, "response": body});
    if let Some(headers) = headers {
        let redacted: BTreeMap<&str, &str> = headers
            .keys()
            .map(|key| (key.as_str(), "REDACTED"))
            .collect();
        document["headers"] = json!(redacted);
    }
    RecordedFixture { name, document }
}

pub(crate) fn exchange_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    mut request: Value,
    mut body: Value,
) -> RecordedFixture {
    let hosts = recording_hosts();
    scrub(&mut request);
    scrub(&mut body);
    scrub_hosts(&mut request, &hosts);
    scrub_hosts(&mut body, &hosts);
    RecordedFixture {
        name,
        document: json!({
            "flavor": flavor,
            "version": version,
            "operation": name,
            "request": request,
            "response": body,
        }),
    }
}

pub(crate) fn rule_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    mut body: Value,
) -> RecordedFixture {
    strip_volatile(&mut body, RULE_VOLATILE_FIELDS);
    response_fixture(name, flavor, version, body, None)
}

pub(crate) fn rule_exchange_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    request: Value,
    mut body: Value,
) -> RecordedFixture {
    strip_volatile(&mut body, RULE_VOLATILE_FIELDS);
    exchange_fixture(name, flavor, version, request, body)
}

pub(crate) fn preview_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    mut body: Value,
) -> RecordedFixture {
    strip_volatile(&mut body, PREVIEW_VOLATILE_FIELDS);
    response_fixture(name, flavor, version, body, None)
}

pub(crate) fn preview_exchange_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    mut request: Value,
    mut body: Value,
) -> RecordedFixture {
    strip_volatile(&mut request, PREVIEW_VOLATILE_FIELDS);
    strip_volatile(&mut body, PREVIEW_VOLATILE_FIELDS);
    strip_volatile(&mut body, PREVIEW_HITS_RESPONSE_VOLATILE_FIELDS);
    exchange_fixture(name, flavor, version, request, body)
}

pub(crate) fn error_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    error: elasticctl_core::Error,
) -> RecordedFixture {
    let hosts = recording_hosts();
    let mut envelope = error.to_envelope()["error"].clone();
    scrub(&mut envelope);
    scrub_hosts(&mut envelope, &hosts);
    RecordedFixture {
        name,
        document: json!({
            "flavor": flavor,
            "version": version,
            "operation": name,
            "error": envelope,
        }),
    }
}

pub(super) fn integration_policy_error_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    error: elasticctl_core::Error,
) -> RecordedFixture {
    let mut envelope = json!({
        "kind": error.kind.as_str(),
        "message": "Fleet integration-policy recording endpoint returned an error",
    });
    if let Some(status) = error.http_status {
        envelope["http_status"] = json!(status);
    }
    RecordedFixture {
        name,
        document: json!({
            "flavor": flavor,
            "version": version,
            "operation": name,
            "error": envelope,
        }),
    }
}

pub(crate) fn write_recording(recording: Recording) -> elasticctl_core::Result<()> {
    std::fs::create_dir_all(&recording.dir).map_err(|error| {
        elasticctl_core::Error::new(
            elasticctl_core::ErrorKind::Error,
            format!(
                "creating fixture directory {}: {error}",
                recording.dir.display()
            ),
        )
    })?;
    for fixture in recording.fixtures {
        let path = recording.dir.join(format!("{}.json", fixture.name));
        let encoded = serde_json::to_string_pretty(&fixture.document).map_err(|error| {
            elasticctl_core::Error::new(
                elasticctl_core::ErrorKind::Error,
                format!("encoding fixture {}: {error}", fixture.name),
            )
        })?;
        std::fs::write(&path, encoded).map_err(|error| {
            elasticctl_core::Error::new(
                elasticctl_core::ErrorKind::Error,
                format!("writing fixture {}: {error}", path.display()),
            )
        })?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_hits_fixture_strips_response_runtime_fields_and_still_uses_the_checked_decoder() {
        let fixture = preview_exchange_fixture(
            "rules_preview_hits",
            "serverless",
            "9.6.0",
            json!({"sort": [{"@timestamp": {"order": "desc"}}]}),
            json!({
                "took": 7,
                "_shards": {"total": 3, "successful": 3, "skipped": 0, "failed": 0},
                "hits": {
                    "total": {"value": 1, "relation": "eq"},
                    "hits": [{
                        "_index": ".preview.alerts-security.alerts-rollover",
                        "sort": [123],
                        "_source": {"kibana.alert.rule.uuid": "fixture-preview"}
                    }]
                }
            }),
        );
        let response = &fixture.document["response"];

        assert!(response.get("took").is_none());
        assert!(response.get("_shards").is_none());
        assert!(response["hits"]["hits"][0].get("_index").is_none());
        assert!(response["hits"]["hits"][0].get("sort").is_none());
        assert_eq!(
            fixture.document["request"]["sort"],
            json!([{"@timestamp": {"order": "desc"}}]),
            "the production request sort is evidence, not response runtime state"
        );
        elasticctl_api::rules::decode_preview_hits_checked(response)
            .expect("the scrubbed response must use the checked production decoder");
    }

    #[test]
    fn integration_policy_error_fixtures_keep_only_classification_and_a_local_message() {
        let fixture = integration_policy_error_fixture(
            "integration_policy_not_found",
            "test",
            "9.6.0",
            elasticctl_core::Error::with_status(
                elasticctl_core::ErrorKind::NotFound,
                404,
                "owner@example.com at https://private.example/opaque-id uses ${secret.ref}",
            ),
        );

        assert_eq!(fixture.document["error"]["kind"], "not_found");
        assert_eq!(fixture.document["error"]["http_status"], 404);
        assert_eq!(
            fixture.document["error"]["message"],
            "Fleet integration-policy recording endpoint returned an error"
        );
        let encoded = fixture.document.to_string();
        for private in [
            "owner@example.com",
            "private.example",
            "opaque-id",
            "secret.ref",
        ] {
            assert!(!encoded.contains(private), "fixture leaked {private}");
        }
    }
}
