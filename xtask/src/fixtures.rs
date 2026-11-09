//! Recorded envelopes and disk writing.

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

/// Build one scrubbed response fixture. Fixture documents stay in memory until
/// the recording session has cleaned every marker-owned object.
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

/// Build one scrubbed request/response exchange. A response alone cannot prove
/// which index and field were queried, so query-sensitive operations retain a
/// scrubbed request alongside the response.
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

/// Record a rule, list, or item response, stripping the volatile server-owned
/// fields so a re-record of the same object is byte-identical.
pub(crate) fn rule_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    mut body: Value,
) -> RecordedFixture {
    strip_volatile(&mut body, RULE_VOLATILE_FIELDS);
    response_fixture(name, flavor, version, body, None)
}

/// Record a rule, list, or item exchange, stripping the same volatile fields
/// from the response body.
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

/// Record a preview response, stripping the per-run preview fields.
pub(crate) fn preview_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    mut body: Value,
) -> RecordedFixture {
    strip_volatile(&mut body, PREVIEW_VOLATILE_FIELDS);
    response_fixture(name, flavor, version, body, None)
}

/// Record a preview-hits exchange, stripping per-run fields from both the
/// request (the preview id in the query) and the response (the alert hits).
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

/// Record a classified endpoint error without inventing a success body.
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

/// Task 8 records classified Fleet lifecycle failures without copying a
/// server-provided message into a public fixture. Fleet errors can name a
/// user, deployment, policy, or secret reference, while the classification
/// and HTTP status are sufficient route-contract evidence.
pub(crate) fn integration_policy_error_fixture(
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
