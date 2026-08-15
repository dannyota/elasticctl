//! Fixture recorder: drive a live stack and write scrubbed exchanges.
//!
//! Fixtures capture what Elastic sent. Hand-written mocks capture assumptions,
//! which is where API bugs hide.

mod conformance;

use elasticctl_core::urlencode;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;

const RULE_ID: &str = "elasticctl-fixture-probe";
const LIST_ID: &str = "elasticctl-sample-exceptions";
const ITEM_ID: &str = "elasticctl-sample-exception-item";
const NAMESPACE_TYPE: &str = "single";
const MARKER_TAGS: [&str; 2] = ["elasticctl", "fixture"];
const SCRATCH_DOC_ID: &str = "elasticctl-sample-fixture";
const SCRATCH_MARKER: &str = "elasticctl_fixture_marker";

const SCRUB_FIELDS: &[&str] = &[
    "username",
    "full_name",
    "email",
    "created_by",
    "updated_by",
    "tie_breaker_id",
    "_version",
];

/// Replace credentials and operator identity before writing a fixture. Recorded
/// fixtures are committed to a public repository.
///
/// Scrub server-owned identity and version fields while preserving their shape.
/// Keep these fields in the list even when they appear unused.
fn scrub(v: &mut Value) {
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
        _ => {}
    }
}

/// Match both full keys and their final dot-separated segment. Alert documents
/// can flatten identity fields such as `kibana.alert.rule.created_by`.
fn is_sensitive(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let leaf = lower.rsplit('.').next().unwrap_or(&lower);
    lower.contains("api_key")
        || lower.contains("apikey")
        || matches!(leaf, "authorization" | "password" | "encoded")
        || SCRUB_FIELDS.contains(&leaf)
}

/// Extract a recording authority without URL userinfo.
///
/// The transport removes userinfo before issuing a request. This helper uses
/// the same final-`@` rule while preparing the fixture host scrubber, so a
/// credential cannot survive in a recorded URL value.
fn recording_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    (!host.is_empty()).then(|| host.to_string())
}

/// Return the recording stack's bare hostnames.
///
/// Read them from the environment because every write path needs them and each
/// run talks to one stack.
fn recording_hosts() -> Vec<String> {
    [
        "ELASTICCTL_KIBANA_URL",
        "ELASTICCTL_ES_URL",
        "ELASTICCTL_INGEST_URL",
    ]
    .iter()
    .filter_map(|k| std::env::var(k).ok())
    .filter_map(|url| recording_host(&url))
    .collect()
}

fn is_authority_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'[' | b']')
}

fn authority_token_end(bytes: &[u8], start: usize) -> usize {
    let mut index = start;
    let mut in_ipv6 = false;
    while index < bytes.len() {
        match bytes[index] {
            b'[' => in_ipv6 = true,
            b']' if in_ipv6 => in_ipv6 = false,
            byte if !in_ipv6
                && (byte.is_ascii_whitespace()
                    || matches!(
                        byte,
                        b'/' | b'?'
                            | b'#'
                            | b','
                            | b';'
                            | b'\''
                            | b'"'
                            | b'('
                            | b')'
                            | b'<'
                            | b'>'
                            | b'['
                            | b']'
                    )) =>
            {
                break;
            }
            _ => {}
        }
        index += 1;
    }
    index
}

fn replace_bounded_authority(value: &str, authority: &str) -> String {
    if authority.is_empty() {
        return value.to_string();
    }

    let bytes = value.as_bytes();
    let authority = authority.as_bytes();
    let mut scrubbed = String::with_capacity(value.len());
    let mut copied_end = 0;
    let mut index = 0;

    while index + authority.len() <= bytes.len() {
        let before_is_safe =
            index == 0 || (!is_authority_char(bytes[index - 1]) && bytes[index - 1] != b'@');
        let end = index + authority.len();
        let after_is_safe =
            end == bytes.len() || (!is_authority_char(bytes[end]) && bytes[end] != b'@');

        if before_is_safe && after_is_safe && bytes[index..end].eq_ignore_ascii_case(authority) {
            scrubbed.push_str(&value[copied_end..index]);
            scrubbed.push_str("REDACTED.example.invalid");
            copied_end = end;
            index = end;
        } else {
            index += 1;
        }
    }

    scrubbed.push_str(&value[copied_end..]);
    scrubbed
}

fn default_port_host(authority: &str, default_port: u16) -> Option<&str> {
    authority.rsplit_once(':').and_then(|(host, port)| {
        (!host.is_empty() && port.parse::<u16>().ok() == Some(default_port)).then_some(host)
    })
}

/// Remove userinfo from a URL authority without changing its path or query.
///
/// Fixture values can contain the configured host with credentials that were
/// never part of the transport URL. Removing only the host would leave those
/// credentials in the public fixture.
fn strip_url_userinfo(value: &str) -> String {
    let mut scrubbed = String::with_capacity(value.len());
    let mut remaining = value;

    while let Some(scheme_end) = remaining.find("://") {
        let authority_start = scheme_end + 3;
        scrubbed.push_str(&remaining[..authority_start]);
        remaining = &remaining[authority_start..];

        let authority_end = authority_token_end(remaining.as_bytes(), 0);
        let (authority, tail) = remaining.split_at(authority_end);
        scrubbed.push_str(
            authority
                .rfind('@')
                .map_or(authority, |index| &authority[index + 1..]),
        );
        remaining = tail;
    }
    scrubbed.push_str(remaining);
    scrubbed
}

/// Replace the configured authority in every absolute URL.
///
/// URL hostnames compare case-insensitively. A configured
/// `https://host:443` can also appear in a response as `https://host/...`, and
/// `http://host:80` likewise loses `:80`. Do not derive a bare-host match for
/// non-default ports: `host:9243` and `host` can identify different
/// deployments.
fn scrub_recording_authority_urls(value: &str, configured_authority: &str) -> String {
    let mut scrubbed = String::new();
    let mut remaining = value;

    while let Some(scheme_end) = remaining.find("://") {
        let authority_start = scheme_end + 3;
        let scheme = remaining[..scheme_end]
            .rsplit(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .next()
            .unwrap_or("");
        scrubbed.push_str(&remaining[..authority_start]);
        remaining = &remaining[authority_start..];

        let authority_end = authority_token_end(remaining.as_bytes(), 0);
        let (authority, tail) = remaining.split_at(authority_end);
        let default_port = if scheme.eq_ignore_ascii_case("https") {
            Some(443)
        } else if scheme.eq_ignore_ascii_case("http") {
            Some(80)
        } else {
            None
        };
        let normalized_default = default_port.and_then(|port| {
            default_port_host(configured_authority, port).map(|configured_host| {
                authority.eq_ignore_ascii_case(configured_host)
                    || default_port_host(authority, port)
                        .is_some_and(|host| host.eq_ignore_ascii_case(configured_host))
            })
        });

        if authority.eq_ignore_ascii_case(configured_authority) || normalized_default == Some(true)
        {
            scrubbed.push_str("REDACTED.example.invalid");
        } else {
            scrubbed.push_str(authority);
        }
        remaining = tail;
    }
    scrubbed.push_str(remaining);
    scrubbed
}

/// Replace the recording stack's hostname wherever it appears in a value.
///
/// `is_sensitive` checks keys, but an alert document stores the project URL in
/// `kibana.alert.url`, where identity is in the *value*. Sweep every recorded
/// string and keep the path so the document shape remains intact.
fn scrub_hosts(v: &mut Value, hosts: &[String]) {
    match v {
        Value::String(s) => {
            *s = strip_url_userinfo(s);
            for h in hosts {
                *s = replace_bounded_authority(s, h);
                *s = scrub_recording_authority_urls(s, h);
            }
        }
        Value::Object(m) => m.values_mut().for_each(|x| scrub_hosts(x, hosts)),
        Value::Array(a) => a.iter_mut().for_each(|x| scrub_hosts(x, hosts)),
        _ => {}
    }
}

/// Redact a sensitive value without changing its type. Strings become
/// "REDACTED", containers keep their shape with redacted leaves, and null
/// stays null because a null `full_name` or `email` is absent, not secret.
fn redact(val: &mut Value) {
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

/// Scrub a raw NDJSON export body line by line. The export fixture stores the
/// response as an opaque string, so parse and reserialize each line before
/// applying the same redaction used for parsed bodies.
fn scrub_ndjson(text: &str, hosts: &[String]) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut v: Value = serde_json::from_str(line).expect("export line is JSON");
        scrub(&mut v);
        scrub_hosts(&mut v, hosts);
        out.push_str(&serde_json::to_string(&v).expect("encode scrubbed export line"));
        out.push('\n');
    }
    out
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("record") => record().await,
        Some("seed") => seed().await,
        Some("conformance") => {
            if let Err(error) = conformance::run(&args[1..]).await {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: cargo xtask [record|seed|conformance]");
            std::process::exit(2);
        }
    }
}

/// Build a transport from the environment as the CLI does. The caller supplies
/// the default timeout; `ELASTICCTL_TIMEOUT` overrides it.
fn transport_from_env(default_timeout_secs: u64) -> elasticctl_core::Transport {
    let timeout_secs = std::env::var("ELASTICCTL_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_timeout_secs);
    let mut profile = elasticctl_core::Profile {
        kibana_url: std::env::var("ELASTICCTL_KIBANA_URL").expect("ELASTICCTL_KIBANA_URL"),
        es_url: std::env::var("ELASTICCTL_ES_URL").ok(),
        api_key: Some(std::env::var("ELASTICCTL_API_KEY").expect("ELASTICCTL_API_KEY")),
        username: None,
        password: None,
        space: std::env::var("ELASTICCTL_SPACE").unwrap_or_else(|_| "default".into()),
        verify: true,
        timeout_secs,
    };
    profile.strip_userinfo();
    elasticctl_core::Transport::new(&profile).expect("transport")
}

struct RecordedFixture {
    name: &'static str,
    document: Value,
}

struct Recording {
    dir: PathBuf,
    fixtures: Vec<RecordedFixture>,
}

/// Build one scrubbed response fixture. Fixture documents stay in memory until
/// the recording session has cleaned every marker-owned object.
fn response_fixture(
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
fn exchange_fixture(
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

/// Record a classified endpoint error without inventing a success body.
fn error_fixture(
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

fn write_recording(recording: Recording) -> elasticctl_core::Result<()> {
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

/// Scratch index queried by the preview probe. It carries the
/// `elasticctl-sample` marker and avoids the `logs-` prefix: `logs-*-*` matches
/// Elastic's template and would reject a plain document write.
const PREVIEW_PROBE_INDEX: &str = "elasticctl-sample-fixture";
/// Base name for the preview probe. Append a per-run suffix because preview
/// alerts are never deleted; the fallback must not match a stale alert.
const PREVIEW_PROBE_NAME: &str = "elasticctl fixture preview probe";
/// Fixed instead of "now": the probe document falls inside this window, so the
/// recording is reproducible and needs no date arithmetic.
const PREVIEW_TIMEFRAME_END: &str = "2026-08-12T18:00:00.000Z";
const PREVIEW_DOC_TIMESTAMP: &str = "2026-08-12T17:57:00.000Z";

/// Return a per-run suffix so a re-record cannot match leftover preview alerts.
fn run_token() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().to_string())
        .unwrap_or_else(|_| std::process::id().to_string())
}

/// Request and response that found preview hits. Keep them separate from the
/// fixture write so the caller can clean up first.
struct PreviewHitsExchange {
    request: Value,
    response: Value,
}

/// Record what a preview actually wrote.
///
/// `rules/preview` returns a `previewId` but no hit count, so read the count from
/// the preview alerts index. This records the index name, preview-ID field,
/// project-key access, and the first attempt that can see the alerts.
///
/// Return `Err` rather than panicking and return the exchange for the caller to
/// write after deleting the scratch index and probe rule. No hits are an error,
/// not a fixture claiming a field matched.
#[derive(Default)]
struct CleanupOwnership {
    rule: bool,
    item: bool,
    list: bool,
    scratch_index: bool,
}

#[derive(Default)]
struct CleanupResponses {
    rule: Option<Value>,
}

struct RecordingSession<'a> {
    transport: &'a elasticctl_core::Transport,
    ownership: CleanupOwnership,
}

fn recording_error(message: impl Into<String>) -> elasticctl_core::Error {
    elasticctl_core::Error::new(elasticctl_core::ErrorKind::Error, message)
}

fn has_marker_tags(value: &Value) -> bool {
    let tags = value.get("tags").and_then(Value::as_array);
    MARKER_TAGS.iter().all(|tag| {
        tags.is_some_and(|tags| tags.iter().any(|candidate| candidate.as_str() == Some(tag)))
    })
}

fn owns_rule(value: &Value) -> bool {
    value.get("rule_id").and_then(Value::as_str) == Some(RULE_ID) && has_marker_tags(value)
}

fn owns_list(value: &Value) -> bool {
    value.get("list_id").and_then(Value::as_str) == Some(LIST_ID)
        && value
            .get("namespace_type")
            .and_then(Value::as_str)
            .unwrap_or("single")
            == NAMESPACE_TYPE
        && has_marker_tags(value)
}

fn owns_item(value: &Value) -> bool {
    value.get("item_id").and_then(Value::as_str) == Some(ITEM_ID)
        && value.get("list_id").and_then(Value::as_str) == Some(LIST_ID)
        && value
            .get("namespace_type")
            .and_then(Value::as_str)
            .unwrap_or("single")
            == NAMESPACE_TYPE
        && has_marker_tags(value)
}

fn owns_scratch_index(value: &Value) -> bool {
    value["_source"][SCRATCH_MARKER].as_bool() == Some(true)
}

async fn require_absent_rule(t: &elasticctl_core::Transport) -> elasticctl_core::Result<()> {
    match t
        .get(&format!("/api/detection_engine/rules?rule_id={RULE_ID}"))
        .await
    {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: rule {RULE_ID} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

async fn require_absent_list(t: &elasticctl_core::Transport) -> elasticctl_core::Result<()> {
    match t
        .get(&format!(
            "/api/exception_lists?list_id={}&namespace_type={NAMESPACE_TYPE}",
            urlencode(LIST_ID)
        ))
        .await
    {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: exception list {LIST_ID} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

async fn require_absent_item(t: &elasticctl_core::Transport) -> elasticctl_core::Result<()> {
    match t
        .get(&format!(
            "/api/exception_lists/items?item_id={}&namespace_type={NAMESPACE_TYPE}",
            urlencode(ITEM_ID)
        ))
        .await
    {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: exception item {ITEM_ID} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

async fn require_absent_scratch_index(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    match t.get_absolute_es(&format!("/{PREVIEW_PROBE_INDEX}")).await {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: scratch index {PREVIEW_PROBE_INDEX} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

async fn create_marked_list(session: &mut RecordingSession<'_>) -> elasticctl_core::Result<Value> {
    require_absent_list(session.transport).await?;
    let body = json!({
        "list_id": LIST_ID,
        "namespace_type": NAMESPACE_TYPE,
        "name": "elasticctl sample exceptions",
        "description": "Recorded by cargo xtask record. Safe to delete.",
        "type": "detection",
        "tags": MARKER_TAGS,
    });
    let created = session
        .transport
        .post("/api/exception_lists", Some(&body))
        .await?;
    if !owns_list(&created) {
        return Err(recording_error(
            "exception list create response did not prove the fixed marker identity",
        ));
    }
    session.ownership.list = true;
    Ok(created)
}

async fn create_marked_item(session: &mut RecordingSession<'_>) -> elasticctl_core::Result<Value> {
    require_absent_item(session.transport).await?;
    let body = json!({
        "item_id": ITEM_ID,
        "list_id": LIST_ID,
        "namespace_type": NAMESPACE_TYPE,
        "name": "elasticctl sample exception item",
        "description": "Recorded by cargo xtask record. Safe to delete.",
        "type": "simple",
        "entries": [{
            "field": "process.name",
            "operator": "included",
            "type": "match",
            "value": "elasticctl-sample.exe",
        }],
        "tags": MARKER_TAGS,
    });
    let created = session
        .transport
        .post("/api/exception_lists/items", Some(&body))
        .await?;
    if !owns_item(&created) {
        return Err(recording_error(
            "exception item create response did not prove the fixed marker identity",
        ));
    }
    session.ownership.item = true;
    Ok(created)
}

async fn create_marked_rule(
    session: &mut RecordingSession<'_>,
    list_server_id: &str,
) -> elasticctl_core::Result<(Value, Value)> {
    require_absent_rule(session.transport).await?;
    let body = json!({
        "rule_id": RULE_ID,
        "name": "elasticctl fixture probe",
        "description": "Recorded by cargo xtask record. Safe to delete.",
        "type": "query",
        "language": "kuery",
        "query": "*:*",
        "index": ["logs-*"],
        "severity": "low",
        "risk_score": 21,
        "enabled": false,
        "from": "now-6m",
        "interval": "5m",
        "tags": MARKER_TAGS,
        "exceptions_list": [{
            "id": list_server_id,
            "list_id": LIST_ID,
            "namespace_type": NAMESPACE_TYPE,
            "type": "detection",
        }],
    });
    let created = session
        .transport
        .post("/api/detection_engine/rules", Some(&body))
        .await?;
    if !owns_rule(&created) {
        return Err(recording_error(
            "rule create response did not prove the fixed marker identity",
        ));
    }
    session.ownership.rule = true;
    Ok((body, created))
}

impl RecordingSession<'_> {
    async fn cleanup(&mut self) -> elasticctl_core::Result<CleanupResponses> {
        let mut errors = Vec::new();
        let mut responses = CleanupResponses::default();

        if self.ownership.rule {
            match self
                .transport
                .get(&format!("/api/detection_engine/rules?rule_id={RULE_ID}"))
                .await
            {
                Ok(rule) if owns_rule(&rule) => {
                    match self
                        .transport
                        .delete(&format!("/api/detection_engine/rules?rule_id={RULE_ID}"))
                        .await
                    {
                        Ok(deleted) => {
                            self.ownership.rule = false;
                            responses.rule = Some(deleted);
                        }
                        Err(error) => {
                            errors.push(format!("deleting rule {RULE_ID}: {}", error.message))
                        }
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete rule {RULE_ID}: its marker fields no longer match"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                    self.ownership.rule = false;
                }
                Err(error) => errors.push(format!("checking rule {RULE_ID}: {}", error.message)),
            }
        }

        if self.ownership.item {
            match self
                .transport
                .get(&format!(
                    "/api/exception_lists/items?item_id={}&namespace_type={NAMESPACE_TYPE}",
                    urlencode(ITEM_ID)
                ))
                .await
            {
                Ok(item) if owns_item(&item) => {
                    match self
                        .transport
                        .delete(&format!(
                            "/api/exception_lists/items?item_id={}&namespace_type={NAMESPACE_TYPE}",
                            urlencode(ITEM_ID)
                        ))
                        .await
                    {
                        Ok(_) => self.ownership.item = false,
                        Err(error) => {
                            errors.push(format!("deleting item {ITEM_ID}: {}", error.message))
                        }
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete item {ITEM_ID}: its marker fields no longer match"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                    self.ownership.item = false;
                }
                Err(error) => errors.push(format!("checking item {ITEM_ID}: {}", error.message)),
            }
        }

        if self.ownership.list {
            match self
                .transport
                .get(&format!(
                    "/api/exception_lists?list_id={}&namespace_type={NAMESPACE_TYPE}",
                    urlencode(LIST_ID)
                ))
                .await
            {
                Ok(list) if owns_list(&list) => {
                    match self
                        .transport
                        .delete(&format!(
                            "/api/exception_lists?list_id={}&namespace_type={NAMESPACE_TYPE}",
                            urlencode(LIST_ID)
                        ))
                        .await
                    {
                        Ok(_) => self.ownership.list = false,
                        Err(error) => {
                            errors.push(format!("deleting list {LIST_ID}: {}", error.message))
                        }
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete list {LIST_ID}: its marker fields no longer match"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                    self.ownership.list = false;
                }
                Err(error) => errors.push(format!("checking list {LIST_ID}: {}", error.message)),
            }
        }

        if self.ownership.scratch_index {
            match self
                .transport
                .get_absolute_es(&format!("/{PREVIEW_PROBE_INDEX}/_doc/{SCRATCH_DOC_ID}"))
                .await
            {
                Ok(document) if owns_scratch_index(&document) => {
                    match self
                        .transport
                        .delete_absolute_es(&format!("/{PREVIEW_PROBE_INDEX}"))
                        .await
                    {
                        Ok(_) => self.ownership.scratch_index = false,
                        Err(error) => errors.push(format!(
                            "deleting scratch index {PREVIEW_PROBE_INDEX}: {}",
                            error.message
                        )),
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete scratch index {PREVIEW_PROBE_INDEX}: its marker field no longer matches"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                    self.ownership.scratch_index = false;
                }
                Err(error) => errors.push(format!(
                    "checking scratch index {PREVIEW_PROBE_INDEX}: {}",
                    error.message
                )),
            }
        }

        if errors.is_empty() {
            Ok(responses)
        } else {
            Err(recording_error(format!(
                "cleanup failed: {}",
                errors.join("; ")
            )))
        }
    }
}

async fn record_preview_hits(
    session: &mut RecordingSession<'_>,
    space: &str,
) -> elasticctl_core::Result<PreviewHitsExchange> {
    require_absent_scratch_index(session.transport).await?;
    let t = session.transport;
    let doc = json!({
        "@timestamp": PREVIEW_DOC_TIMESTAMP,
        SCRATCH_MARKER: true,
        "event": {"category": ["process"], "type": ["start"], "code": "1"},
        "process": {
            "name": "elasticctl-sample.exe",
            "executable": "C:\\elasticctl-sample\\elasticctl-sample.exe",
            "command_line": "elasticctl-sample.exe --fixture"
        },
        "host": {"name": "elasticctl-sample-host"}
    });
    t.post_absolute_es(
        &format!("/{PREVIEW_PROBE_INDEX}/_doc/{SCRATCH_DOC_ID}?refresh=wait_for"),
        &doc,
    )
    .await?;
    let proof = t
        .get_absolute_es(&format!("/{PREVIEW_PROBE_INDEX}/_doc/{SCRATCH_DOC_ID}"))
        .await?;
    if !owns_scratch_index(&proof) {
        return Err(recording_error(
            "scratch index write did not prove the fixed marker identity",
        ));
    }
    session.ownership.scratch_index = true;

    let probe_name = format!("{PREVIEW_PROBE_NAME} {}", run_token());
    let preview_body = json!({
        "name": probe_name,
        "description": "Recorded by cargo xtask record. Safe to delete.",
        "type": "query",
        "language": "kuery",
        "query": "*:*",
        "index": [PREVIEW_PROBE_INDEX],
        "severity": "low",
        "risk_score": 21,
        "from": "now-6m",
        "interval": "5m",
        "tags": MARKER_TAGS,
        "invocationCount": 1,
        "timeframeEnd": PREVIEW_TIMEFRAME_END
    });
    let preview = t
        .post("/api/detection_engine/rules/preview", Some(&preview_body))
        .await?;
    let preview_id = preview["previewId"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let index = format!(
        ".preview.alerts-security.alerts-{}",
        urlencode(if space.is_empty() { "default" } else { space })
    );
    let by_uuid = json!({
        "size": 3,
        "track_total_hits": true,
        "query": {"term": {"kibana.alert.rule.uuid": preview_id}},
        "sort": [{"@timestamp": {"order": "desc"}}]
    });
    let hits_of = |value: &Value| value["hits"]["total"]["value"].as_u64().unwrap_or(0);

    let mut response = t
        .post_absolute_es(
            &format!("/{index}/_search?ignore_unavailable=true"),
            &by_uuid,
        )
        .await?;
    let mut uuid_attempts = 1;
    if hits_of(&response) == 0 {
        tokio::time::sleep(std::time::Duration::from_millis(1_000)).await;
        response = t
            .post_absolute_es(
                &format!("/{index}/_search?ignore_unavailable=true"),
                &by_uuid,
            )
            .await?;
        uuid_attempts = 2;
    }
    if hits_of(&response) > 0 {
        return Ok(PreviewHitsExchange {
            request: json!({
                "index": index,
                "body": by_uuid,
                "matched_by": "kibana.alert.rule.uuid",
                "attempts_until_hits": uuid_attempts,
            }),
            response,
        });
    }

    let by_name = json!({
        "size": 3,
        "track_total_hits": true,
        "query": {"match_phrase": {"kibana.alert.rule.name": probe_name}}
    });
    let fallback = t
        .post_absolute_es(
            &format!("/{index}/_search?ignore_unavailable=true"),
            &by_name,
        )
        .await?;
    if hits_of(&fallback) > 0 {
        return Ok(PreviewHitsExchange {
            request: json!({
                "index": index,
                "body": by_name,
                "matched_by": "kibana.alert.rule.name",
                "attempts_until_hits": 1,
            }),
            response: fallback,
        });
    }

    Err(recording_error(format!(
        "no preview alerts found in {index}: kibana.alert.rule.uuid \
         ({uuid_attempts} search(es)) and kibana.alert.rule.name (1 search) \
         both returned zero hits"
    )))
}

fn prebuilt_is_current(status: &Value) -> elasticctl_core::Result<bool> {
    let fields = [
        "rules_not_installed",
        "rules_not_updated",
        "timelines_not_installed",
        "timelines_not_updated",
    ];
    fields.iter().try_fold(true, |current, field| {
        let count = status.get(*field).and_then(Value::as_u64).ok_or_else(|| {
            recording_error(format!(
                "prebuilt status field {field} must be a non-negative integer"
            ))
        })?;
        Ok(current && count == 0)
    })
}

fn prebuilt_install_is_noop(response: &Value) -> elasticctl_core::Result<bool> {
    let fields = [
        "rules_installed",
        "rules_updated",
        "timelines_installed",
        "timelines_updated",
    ];
    fields.iter().try_fold(true, |current, field| {
        let count = response
            .get(*field)
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                recording_error(format!(
                    "prebuilt install field {field} must be a non-negative integer"
                ))
            })?;
        Ok(current && count == 0)
    })
}

async fn record_session(session: &mut RecordingSession<'_>) -> elasticctl_core::Result<Recording> {
    let responded = session.transport.get_with_headers("/api/status").await?;
    let status = responded.body.clone();
    let version = status["version"]["number"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let flavor = std::env::var("ELASTICCTL_FIXTURE_FLAVOR").unwrap_or_else(|_| {
        status["version"]["build_flavor"]
            .as_str()
            .unwrap_or("default")
            .to_string()
    });
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests/fixtures")
        .join(format!("{flavor}-{version}"));
    let mut recording = Recording {
        dir,
        fixtures: vec![response_fixture(
            "status",
            &flavor,
            &version,
            status,
            Some(&responded.headers),
        )],
    };
    let t = session.transport;

    recording.fixtures.push(response_fixture(
        "authenticate",
        &flavor,
        &version,
        t.get_absolute_es("/_security/_authenticate").await?,
        None,
    ));
    recording.fixtures.push(response_fixture(
        "spaces",
        &flavor,
        &version,
        t.get("/api/spaces/space").await?,
        None,
    ));
    if let Ok(license) = t.get_absolute_es("/_license").await {
        recording.fixtures.push(response_fixture(
            "license", &flavor, &version, license, None,
        ));
    }

    match t.get("/api/lists/index").await {
        Ok(response) => recording.fixtures.push(response_fixture(
            "lists_index",
            &flavor,
            &version,
            response,
            None,
        )),
        Err(error) => {
            recording
                .fixtures
                .push(error_fixture("lists_index", &flavor, &version, error))
        }
    }

    let prebuilt_before = t
        .get("/api/detection_engine/rules/prepackaged/_status")
        .await?;
    if !prebuilt_is_current(&prebuilt_before)? {
        return Err(recording_error(
            "prebuilt rules or timelines are missing or outdated; run the separately guarded `cargo xtask seed` before recording",
        ));
    }
    recording.fixtures.push(response_fixture(
        "prebuilt_status",
        &flavor,
        &version,
        prebuilt_before.clone(),
        None,
    ));
    let prebuilt_install = t
        .put("/api/detection_engine/rules/prepackaged", &Value::Null)
        .await?;
    if !prebuilt_install_is_noop(&prebuilt_install)? {
        return Err(recording_error(
            "prebuilt install changed the stack despite a no-op status; refusing to record a mutation",
        ));
    }
    let prebuilt_after = t
        .get("/api/detection_engine/rules/prepackaged/_status")
        .await?;
    if prebuilt_after != prebuilt_before {
        return Err(recording_error(
            "prebuilt status changed after the measured no-op install",
        ));
    }
    recording.fixtures.push(response_fixture(
        "prebuilt_install",
        &flavor,
        &version,
        prebuilt_install,
        None,
    ));

    let list = create_marked_list(session).await?;
    let list_server_id = list["id"]
        .as_str()
        .ok_or_else(|| recording_error("exception list create response is missing id"))?
        .to_string();
    recording.fixtures.push(response_fixture(
        "exception_list_create",
        &flavor,
        &version,
        list,
        None,
    ));
    let item = create_marked_item(session).await?;
    recording.fixtures.push(response_fixture(
        "exception_item_create",
        &flavor,
        &version,
        item,
        None,
    ));
    let (rule_body, rule) = create_marked_rule(session, &list_server_id).await?;
    recording.fixtures.push(response_fixture(
        "rules_create",
        &flavor,
        &version,
        rule,
        None,
    ));

    let list_filter = format!("exception-list.attributes.list_id: \"{LIST_ID}\"");
    let lists_find = t
        .get(&format!(
            "/api/exception_lists/_find?page=1&per_page=2&namespace_type={NAMESPACE_TYPE}&filter={}",
            urlencode(&list_filter)
        ))
        .await?;
    recording.fixtures.push(exchange_fixture(
        "exception_lists_find",
        &flavor,
        &version,
        json!({"filter": list_filter}),
        lists_find,
    ));
    recording.fixtures.push(response_fixture(
        "exception_list_get",
        &flavor,
        &version,
        t.get(&format!(
            "/api/exception_lists?list_id={}&namespace_type={NAMESPACE_TYPE}",
            urlencode(LIST_ID)
        ))
        .await?,
        None,
    ));
    recording.fixtures.push(response_fixture(
        "exception_list_items_find",
        &flavor,
        &version,
        t.get(&format!(
            "/api/exception_lists/items/_find?list_id={}&namespace_type={NAMESPACE_TYPE}&page=1&per_page=2",
            urlencode(LIST_ID)
        ))
        .await?,
        None,
    ));

    let rule_filter = format!("alert.attributes.params.ruleId: \"{RULE_ID}\"");
    let rules_find = t
        .get(&format!(
            "/api/detection_engine/rules/_find?page=1&per_page=2&filter={}",
            urlencode(&rule_filter)
        ))
        .await?;
    recording.fixtures.push(response_fixture(
        "rules_find",
        &flavor,
        &version,
        rules_find,
        None,
    ));
    let name_filter = "alert.attributes.name: \"elasticctl fixture probe\"";
    recording.fixtures.push(exchange_fixture(
        "rules_find_by_name",
        &flavor,
        &version,
        json!({"filter": name_filter}),
        t.get(&format!(
            "/api/detection_engine/rules/_find?page=1&per_page=2&filter={}",
            urlencode(name_filter)
        ))
        .await?,
    ));
    for (name, source_filter) in [
        (
            "rules_find_source_custom",
            format!("alert.attributes.params.immutable: false AND {rule_filter}"),
        ),
        (
            "rules_find_source_prebuilt",
            format!("alert.attributes.params.immutable: true AND {rule_filter}"),
        ),
        (
            "rules_find_source_customized",
            format!("alert.attributes.params.ruleSource.isCustomized: true AND {rule_filter}"),
        ),
    ] {
        let response = t
            .get(&format!(
                "/api/detection_engine/rules/_find?page=1&per_page=2&filter={}",
                urlencode(&source_filter)
            ))
            .await?;
        recording.fixtures.push(exchange_fixture(
            name,
            &flavor,
            &version,
            json!({"filter": source_filter}),
            response,
        ));
    }

    recording.fixtures.push(response_fixture(
        "rules_get",
        &flavor,
        &version,
        t.get(&format!("/api/detection_engine/rules?rule_id={RULE_ID}"))
            .await?,
        None,
    ));
    recording.fixtures.push(response_fixture(
        "rules_patch",
        &flavor,
        &version,
        t.patch(
            "/api/detection_engine/rules",
            &json!({"rule_id": RULE_ID, "enabled": true}),
        )
        .await?,
        None,
    ));
    recording.fixtures.push(response_fixture(
        "rules_bulk_disable",
        &flavor,
        &version,
        t.post(
            "/api/detection_engine/rules/_bulk_action",
            Some(&json!({"action": "disable", "query": rule_filter})),
        )
        .await?,
        None,
    ));

    let preview_body = {
        let mut body = rule_body
            .as_object()
            .cloned()
            .expect("rule body is an object");
        body.remove("rule_id");
        body.insert("invocationCount".into(), json!(1));
        body.insert("timeframeEnd".into(), json!(PREVIEW_TIMEFRAME_END));
        Value::Object(body)
    };
    recording.fixtures.push(response_fixture(
        "rules_preview",
        &flavor,
        &version,
        t.post("/api/detection_engine/rules/preview", Some(&preview_body))
            .await?,
        None,
    ));
    let space = std::env::var("ELASTICCTL_SPACE").unwrap_or_else(|_| "default".into());
    let preview_hits = record_preview_hits(session, &space).await?;
    recording.fixtures.push(exchange_fixture(
        "rules_preview_hits",
        &flavor,
        &version,
        preview_hits.request,
        preview_hits.response,
    ));

    let exception_export_path = format!(
        "/api/exception_lists/_export?id={}&list_id={}&namespace_type={NAMESPACE_TYPE}&include_expired_exceptions=true",
        urlencode(&list_server_id),
        urlencode(LIST_ID)
    );
    let exception_export = t.post_text(&exception_export_path, None).await?;
    let exception_bundle = elasticctl_api::codec::decode_bundle(&exception_export)?;
    if exception_bundle.lists.len() != 1
        || exception_bundle.items.len() != 1
        || exception_bundle.lists[0].list_id()? != LIST_ID
        || exception_bundle.items[0].item_id()? != ITEM_ID
        || exception_bundle.items[0].list_id()? != LIST_ID
    {
        return Err(recording_error(
            "scoped exception export did not contain exactly the marker list and item",
        ));
    }
    let hosts = recording_hosts();
    recording.fixtures.push(response_fixture(
        "exception_list_export",
        &flavor,
        &version,
        json!({"ndjson": scrub_ndjson(&exception_export, &hosts)}),
        None,
    ));
    recording.fixtures.push(exchange_fixture(
        "exception_list_import",
        &flavor,
        &version,
        json!({"overwrite": true, "list_id": LIST_ID, "namespace_type": NAMESPACE_TYPE}),
        t.post_multipart_ndjson(
            "/api/exception_lists/_import?overwrite=true",
            &exception_export,
        )
        .await?,
    ));

    let rule_export = t
        .post_text(
            "/api/detection_engine/rules/_export",
            Some(&json!({"objects": [{"rule_id": RULE_ID}]})),
        )
        .await?;
    let rule_bundle = elasticctl_api::codec::decode_bundle(&rule_export)?;
    if rule_bundle.rules.len() != 1
        || rule_bundle.lists.len() != 1
        || rule_bundle.items.len() != 1
        || rule_bundle.rules[0].rule_id()? != RULE_ID
        || rule_bundle.lists[0].list_id()? != LIST_ID
        || rule_bundle.items[0].item_id()? != ITEM_ID
        || rule_bundle.items[0].list_id()? != LIST_ID
    {
        return Err(recording_error(
            "scoped rule export did not contain exactly the marker rule, list, and item",
        ));
    }
    let scrubbed_rule_export = scrub_ndjson(&rule_export, &hosts);
    recording.fixtures.push(response_fixture(
        "rules_export",
        &flavor,
        &version,
        json!({"ndjson": scrubbed_rule_export.clone()}),
        None,
    ));
    recording.fixtures.push(response_fixture(
        "rules_export_bundle",
        &flavor,
        &version,
        json!({"ndjson": scrubbed_rule_export}),
        None,
    ));
    recording.fixtures.push(exchange_fixture(
        "rules_import_bundle",
        &flavor,
        &version,
        json!({"overwrite": true, "objects": [{"rule_id": RULE_ID}]}),
        t.post_multipart_ndjson(
            "/api/detection_engine/rules/_import?overwrite=true",
            &rule_export,
        )
        .await?,
    ));

    Ok(recording)
}

async fn record() {
    let transport = transport_from_env(60);
    let mut session = RecordingSession {
        transport: &transport,
        ownership: CleanupOwnership::default(),
    };
    let recorded = record_session(&mut session).await;
    let cleanup = session.cleanup().await;

    let recording = match (recorded, cleanup) {
        (Ok(recording), Ok(cleanup)) => {
            if let Some(rule) = cleanup.rule {
                let flavor = recording
                    .fixtures
                    .first()
                    .and_then(|fixture| fixture.document["flavor"].as_str())
                    .unwrap_or("default")
                    .to_string();
                let version = recording
                    .fixtures
                    .first()
                    .and_then(|fixture| fixture.document["version"].as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let mut recording = recording;
                recording.fixtures.push(response_fixture(
                    "rules_delete",
                    &flavor,
                    &version,
                    rule,
                    None,
                ));
                recording
            } else {
                recording
            }
        }
        (Err(record_error), Ok(_)) => {
            eprintln!("record failed after cleanup: {}", record_error.message);
            std::process::exit(1);
        }
        (Ok(_), Err(cleanup_error)) => {
            eprintln!("record cleanup failed: {}", cleanup_error.message);
            std::process::exit(1);
        }
        (Err(record_error), Err(cleanup_error)) => {
            eprintln!(
                "record failed after cleanup: {}; cleanup also failed: {}",
                record_error.message, cleanup_error.message
            );
            std::process::exit(1);
        }
    };

    let flavor = recording
        .fixtures
        .first()
        .and_then(|fixture| fixture.document["flavor"].as_str())
        .unwrap_or("default")
        .to_string();
    let version = recording
        .fixtures
        .first()
        .and_then(|fixture| fixture.document["version"].as_str())
        .unwrap_or("unknown")
        .to_string();
    if let Err(error) = write_recording(recording) {
        eprintln!("record failed after cleanup: {}", error.message);
        std::process::exit(1);
    }
    println!("recorded {flavor} {version}");
}

async fn seed() {
    // A prepackaged install can exceed the normal 60-second timeout on a fresh
    // stack. Use a higher default while keeping `ELASTICCTL_TIMEOUT` as an
    // override.
    let t = transport_from_env(600);
    // Prebuilt Elastic rules give pull, diff, and preview real data.
    let installed = t
        .put("/api/detection_engine/rules/prepackaged", &json!({}))
        .await
        .expect("install prebuilt rules");
    println!(
        "{}",
        serde_json::to_string_pretty(&installed).unwrap_or_default()
    );
}

#[cfg(test)]
mod scrub_tests {
    use super::*;

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
    fn recording_host_removes_userinfo_and_keeps_the_authority() {
        assert_eq!(
            recording_host("https://alice:secret@cluster.example:9243/s/default?x=1#fragment"),
            Some("cluster.example:9243".to_string())
        );
        assert_eq!(
            recording_host(
                "https://user:pa@ss@host.example:443/path@not-userinfo?x=@query#@fragment"
            ),
            Some("host.example:443".to_string())
        );
        assert_eq!(
            recording_host("https://plain.example:5601/path?x=1#fragment"),
            Some("plain.example:5601".to_string())
        );
    }

    #[test]
    fn host_scrub_removes_url_userinfo_before_replacing_the_host() {
        let mut value = json!({
            "url": "https://alice:secret@cluster.example:9243/app/rules?x=1#detail"
        });

        scrub_hosts(&mut value, &["cluster.example:9243".to_string()]);

        assert_eq!(
            value["url"],
            "https://REDACTED.example.invalid/app/rules?x=1#detail"
        );
    }

    #[test]
    fn host_scrub_removes_userinfo_from_each_url_in_a_string() {
        let mut value = json!({
            "urls": "https://alice:secret@cluster.example:9243 https://bob:hidden@cluster.example:9243/b"
        });

        scrub_hosts(&mut value, &["cluster.example:9243".to_string()]);

        assert_eq!(
            value["urls"],
            "https://REDACTED.example.invalid https://REDACTED.example.invalid/b"
        );
    }

    #[test]
    fn host_scrub_matches_a_normalized_default_port_url() {
        let mut value = json!({"url": "https://internal.example/app/rules"});

        scrub_hosts(&mut value, &["internal.example:443".to_string()]);

        assert_eq!(value["url"], "https://REDACTED.example.invalid/app/rules");
    }

    #[test]
    fn host_scrub_matches_a_case_normalized_default_port_url() {
        let mut value = json!({"url": "https://internal.example/app/rules"});

        scrub_hosts(&mut value, &["INTERNAL.example:443".to_string()]);

        assert_eq!(value["url"], "https://REDACTED.example.invalid/app/rules");
    }

    #[test]
    fn host_scrub_matches_zero_padded_default_ports() {
        let mut value = json!({
            "https": "https://internal.example/app/rules",
            "http": "http://internal.example/app/rules"
        });

        scrub_hosts(
            &mut value,
            &[
                "internal.example:0443".to_string(),
                "internal.example:0080".to_string(),
            ],
        );

        assert_eq!(value["https"], "https://REDACTED.example.invalid/app/rules");
        assert_eq!(value["http"], "http://REDACTED.example.invalid/app/rules");
    }

    #[test]
    fn host_scrub_matches_a_normalized_http_default_port_url() {
        let mut value = json!({"url": "http://internal.example/app/rules"});

        scrub_hosts(&mut value, &["internal.example:80".to_string()]);

        assert_eq!(value["url"], "http://REDACTED.example.invalid/app/rules");
    }

    #[test]
    fn host_scrub_does_not_normalize_a_nondefault_port() {
        let mut value = json!({"url": "https://internal.example/app/rules"});

        scrub_hosts(&mut value, &["internal.example:9243".to_string()]);

        assert_eq!(value["url"], "https://internal.example/app/rules");
    }

    #[test]
    fn host_scrub_leaves_plain_at_sign_text_unchanged() {
        let mut value = json!({"note": "contact ops@example.com before recording"});

        scrub_hosts(&mut value, &["cluster.example:9243".to_string()]);

        assert_eq!(value["note"], "contact ops@example.com before recording");
    }
}

#[cfg(test)]
#[test]
fn scrub_hosts_handles_authority_boundaries() {
    // This fails if a configured authority is matched case-sensitively,
    // extends into an adjacent authority character, or does not recognize
    // punctuation-delimited default-port URL authorities.
    let cases = [
        (
            "comma-delimited HTTPS canonical default port",
            "https://internal.example:443,",
            "internal.example:443",
            "https://REDACTED.example.invalid,",
        ),
        (
            "comma-delimited HTTPS default port",
            "https://internal.example:0443,",
            "internal.example:443",
            "https://REDACTED.example.invalid,",
        ),
        (
            "semicolon-delimited HTTP canonical default port",
            "http://internal.example:80;",
            "internal.example:80",
            "http://REDACTED.example.invalid;",
        ),
        (
            "semicolon-delimited HTTP default port",
            "http://internal.example:0080;",
            "internal.example:80",
            "http://REDACTED.example.invalid;",
        ),
        (
            "single-quoted authority",
            "https://internal.example:0443'",
            "internal.example:443",
            "https://REDACTED.example.invalid'",
        ),
        (
            "double-quoted authority",
            "http://internal.example:0080\"",
            "internal.example:80",
            "http://REDACTED.example.invalid\"",
        ),
        (
            "parenthesized authority",
            "https://internal.example:0443)",
            "internal.example:443",
            "https://REDACTED.example.invalid)",
        ),
        (
            "angle-bracketed authority",
            "http://internal.example:0080>",
            "internal.example:80",
            "http://REDACTED.example.invalid>",
        ),
        (
            "square-bracketed authority",
            "https://internal.example:0443]",
            "internal.example:443",
            "https://REDACTED.example.invalid]",
        ),
        (
            "whitespace-separated authorities",
            "https://cluster.example:9243 https://cluster.example:9243/b",
            "cluster.example:9243",
            "https://REDACTED.example.invalid https://REDACTED.example.invalid/b",
        ),
        (
            "mixed-case authority",
            "https://CLUSTER.ExAmPlE:9243/app",
            "cluster.example:9243",
            "https://REDACTED.example.invalid/app",
        ),
        (
            "userinfo authority",
            "https://alice:secret@cluster.example:9243/app",
            "cluster.example:9243",
            "https://REDACTED.example.invalid/app",
        ),
        (
            "bracketed IPv6 authority",
            "https://[2001:DB8::1]:0443/app",
            "[2001:db8::1]:443",
            "https://REDACTED.example.invalid/app",
        ),
        (
            "exact authority in plain text",
            "Connect to CLUSTER.example:9243 now",
            "cluster.example:9243",
            "Connect to REDACTED.example.invalid now",
        ),
        (
            "longer hostname remains visible",
            "https://cluster.example:9243.evil/app",
            "cluster.example:9243",
            "https://cluster.example:9243.evil/app",
        ),
        (
            "prefixed hostname remains visible",
            "https://evilcluster.example:9243/app",
            "cluster.example:9243",
            "https://evilcluster.example:9243/app",
        ),
        (
            "bare nondefault host remains visible",
            "https://cluster.example/app",
            "cluster.example:9243",
            "https://cluster.example/app",
        ),
        (
            "bare HTTPS default host is redacted",
            "https://internal.example/app",
            "internal.example:443",
            "https://REDACTED.example.invalid/app",
        ),
        (
            "bare HTTP default host is redacted",
            "http://internal.example/app",
            "internal.example:80",
            "http://REDACTED.example.invalid/app",
        ),
        (
            "plain at-sign text remains visible",
            "contact ops@example.com before recording",
            "example.com",
            "contact ops@example.com before recording",
        ),
        (
            "plain authority followed by at-sign remains visible",
            "example.com@ops.invalid",
            "example.com",
            "example.com@ops.invalid",
        ),
        (
            "configured default authority does not scrub plain email text",
            "ops@example.com",
            "example.com:443",
            "ops@example.com",
        ),
        (
            "configured default authority does not scrub trailing at-sign text",
            "example.com@ops.invalid",
            "example.com:443",
            "example.com@ops.invalid",
        ),
    ];

    for (name, input, host, expected) in cases {
        let mut value = json!(input);
        scrub_hosts(&mut value, &[host.to_string()]);
        assert_eq!(value, json!(expected), "{name}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
