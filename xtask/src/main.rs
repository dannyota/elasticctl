//! Fixture recorder: drive a live stack and write scrubbed exchanges.
//!
//! Fixtures capture what Elastic sent. Hand-written mocks capture assumptions,
//! which is where API bugs hide.

mod conformance;
mod conformance_matrix;

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

/// The alerts probe (triage spec section 9): a marker rule over a marker
/// index, generating alerts the recorder transitions, tags, and assigns
/// through every triage route before closing them out. Alert documents live
/// in the shared `.alerts-security.alerts-*` index and have no public delete
/// API, so residual *closed* marker alerts are the accepted deviation (spec
/// section 9); the marker rule and index are still deleted by `cleanup`.
const ALERT_RULE_ID: &str = "elasticctl-sample-alert-probe";
const ALERT_RULE_NAME: &str = "elasticctl sample alert probe";
const ALERT_PROBE_INDEX: &str = "elasticctl-sample-alert-events";
const ALERT_MARKER_TAG: &str = "elasticctl-sample";

/// Fixed replacement for every alert timestamp value the recorder scrubs.
/// Kept present, not stripped: the alert decoders require every declared
/// field (spec section 9).
const ALERT_FIXTURE_TIMESTAMP: &str = "2026-01-01T00:00:00.000Z";

/// How long to poll `signals/search` for the marker rule's first alert
/// before giving up. The rule scheduler can lag by more than one interval.
const ALERT_POLL_ATTEMPTS: u32 = 30;
const ALERT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// The cases probe (triage spec section 9, added 0.4.1): a marker case
/// created, driven through every mutation route — including attaching the
/// alerts probe's still-open marker alert — then deleted. Unlike alerts,
/// cases delete cleanly through a public API, so zero residue is tolerated:
/// there is no "closed is fine" escape hatch here.
const CASE_TITLE: &str = "elasticctl sample case";
const CASE_TAG: &str = "elasticctl-sample";
const CASE_COMMENT: &str = "elasticctl sample comment";

/// Fixed replacement for every case/comment `version` value the recorder
/// scrubs. Real values are Kibana's base64-encoded `[seq_no, primary_term]`
/// optimistic-concurrency token and change on every mutation, so they must
/// not survive a fixture unscrubbed (spec §8); this decodes to `[0,1]`, a
/// plausible-looking initial token.
const CASE_VERSION_PLACEHOLDER: &str = "WzAsMV0=";
/// Fixed replacement for the marker case's server-generated id.
const CASE_ID_PLACEHOLDER: &str = "elasticctl-fixture-case";
/// Fixed replacement for the alert's `kibana.alert.rule.uuid` inside the
/// attach body's `rule.id` field — the same server-owned, per-rule-creation
/// uuid `is_sensitive` already redacts wherever it appears under its own
/// dotted key; here it appears under a plain `id` key instead, so it needs
/// its own placeholder rewrite.
const CASE_RULE_UUID_PLACEHOLDER: &str = "elasticctl-fixture-case-rule-uuid";

/// Case workflow-duration numerics (triage spec section 9, added 0.4.1):
/// elapsed real time between the recorder's own steps, so a re-record's
/// values never match the prior recording's. Stripped like any other
/// volatile field (`strip_volatile`), not substituted, since they carry no
/// information a decoder needs — `Case` has no typed field for them, they
/// only ever land in `extra`.
const CASE_DURATION_VOLATILE_FIELDS: &[&str] = &[
    "duration",
    "time_to_acknowledge",
    "time_to_investigate",
    "time_to_resolve",
];

/// Volatile fields on every recorded triage mutation response: the raw
/// update-by-query envelope (`signals_status_ids`/`signals_tags`/
/// `signals_assignees`/`signals_status_query`) and `profile_suggest` all
/// carry `took`/`timed_out` (spec section 9); none of the mutation envelopes
/// carry `_shards`, but stripping it if present is harmless.
const TRIAGE_ENVELOPE_VOLATILE_FIELDS: &[&str] = &["took", "timed_out", "_shards"];

/// Additional volatile fields on the `signals_search` response beyond the
/// envelope fields above: relevance scores (meaningless on a `term` query and
/// non-deterministic across runs), the per-execution rule-run uuid (already
/// the treatment `PREVIEW_VOLATILE_FIELDS` gives the same field on the
/// preview-hits probe), and each hit's `sort` array, which embeds a raw
/// epoch-millis recording time the string-only timestamp scrub cannot reach
/// (numeric, not a string) — the DSL search fixtures already strip `sort` via
/// `DSL_VOLATILE_FIELDS` for the same reason; this mirrors that.
const ALERT_SEARCH_VOLATILE_FIELDS: &[&str] = &[
    "took",
    "timed_out",
    "_shards",
    "_score",
    "max_score",
    "kibana.alert.rule.execution.uuid",
    "sort",
];

const SCRUB_FIELDS: &[&str] = &[
    "username",
    "full_name",
    "email",
    "created_by",
    "updated_by",
    // `closed_by` and `pushed_by` are the same shape as `created_by`/
    // `updated_by` (a whole identity object, including a `profile_uid` leaf
    // not itself in this list), surfaced by the 0.4.1 cases probe
    // (`case_update_status`, and comment pushes to an external service).
    // Without them here, `profile_uid` under these keys would only be
    // scrubbed if it happened to collide with a value already in the
    // per-profile placeholder map (see `scrub_placeholder_values`) — a real
    // uid could otherwise reach a committed fixture.
    "closed_by",
    "pushed_by",
    "tie_breaker_id",
    "_version",
    // User-profile identity surfaced by the 0.4 alerts probe
    // (`profile_suggest`, `users_find`). `uid` is deliberately absent here:
    // it is rewritten to a per-profile placeholder, not blanket-redacted
    // (see `scrub_placeholder_values`).
    "realm_name",
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
        // The preview rule id is per-run; the preview-hits test asserts it is
        // present and matches the query, so redact rather than strip it.
        || lower == "kibana.alert.rule.uuid"
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

/// Drop fields that vary on every run from a recorded search response.
///
/// This is separate from `scrub`, which redacts identity in place. Volatile
/// fields are removed, not redacted: a search fixture that kept `took` or a hit
/// `sort` array would make every re-record a false diff without proving
/// anything. The operator's request keeps its own deterministic `sort`.
fn strip_volatile(v: &mut Value, fields: &[&str]) {
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

/// License fields minted per trial activation. A lab re-starts its trial each
/// session, so these change on every re-record and must be dropped for
/// byte-identical fixtures (spec §8).
const LICENSE_VOLATILE_FIELDS: &[&str] = &[
    "uid",
    "issue_date",
    "issue_date_in_millis",
    "expiry_date",
    "expiry_date_in_millis",
];

/// Remove the per-run PIT token wherever a search exchange stores it.
///
/// The `_pit` open response carries the token as `id` and the `_search`
/// request as `pit.id`; the `_search` response carries it as `pit_id`, which
/// `DSL_VOLATILE_FIELDS` already drops. Strip the two named forms so a
/// re-record of the same data is byte-identical (spec §8).
fn strip_pit_token(v: &mut Value) {
    let Some(map) = v.as_object_mut() else {
        return;
    };
    map.remove("id");
    if let Some(Value::Object(pit)) = map.get_mut("pit") {
        pit.remove("id");
    }
}

/// Data-view fields that name the deployment's real views. `scrub` handles
/// operator identity, but these identify the project and must not leave the
/// fixture. Only their values are redacted; the rest of the view keeps its
/// shape so the fixture still proves the endpoint's structure.
const DATA_VIEW_IDENTITY_FIELDS: &[&str] = &["id", "title", "name", "namespaces"];

/// Redact the `_authenticate` response's `metadata` object wholesale.
///
/// For an API-key-authenticated request this is normally `{}`, but
/// Elasticsearch surfaces the underlying user's *cached* metadata regardless
/// of the current auth method. For an identity that has ever signed in via
/// SAML/OIDC, that has been observed to include the literal SSO access and
/// refresh tokens and the user's email, under provider-specific claim-URI
/// keys such as `saml(http://saml.elastic-cloud.com/attributes/email)` —
/// shapes `scrub`'s key-name allowlist cannot anticipate. No known key set
/// makes this field safe to allowlist, so every leaf is redacted regardless
/// of key name; nothing in elasticctl decodes `metadata`.
fn redact_authenticate_metadata(v: &mut Value) {
    if let Some(metadata) = v.get_mut("metadata") {
        redact(metadata);
    }
}

fn redact_data_views(v: &mut Value) {
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

/// Rewrite every occurrence of a mapped alert id or profile uid to its fixed
/// placeholder, wherever it appears **inside** a string value — not only
/// where the whole value equals it. Kibana embeds the real alert uuid inside
/// a longer string in `kibana.alert.url` (`.../redirect/<uuid>?...`), which a
/// whole-string match would miss entirely. Alert ids and uids are rewritten,
/// never stripped: the alert and profile decoders require the field present,
/// only its value is sensitive (spec section 9). The mapped keys are
/// server-generated random ids/uuids, so an accidental substring collision
/// with unrelated content is not a realistic risk.
fn scrub_placeholder_values(v: &mut Value, map: &BTreeMap<String, String>) {
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

/// `kibana.alert.*` fields that don't fit the `_at`/`.start`/`.end` suffix
/// pattern but are still live timestamps on every recorded alert: the
/// detection time, the rule-execution time, and the intended run time.
const ALERT_TIMESTAMP_KEYS: &[&str] = &[
    "kibana.alert.last_detected",
    "kibana.alert.original_time",
    "kibana.alert.intended_timestamp",
    "kibana.alert.rule.execution.timestamp",
];

/// True for the alert timestamp key shapes the recorder normalizes:
/// `@timestamp`, any key ending `_at`, `.start`, or `.end`, and the explicit
/// names in `ALERT_TIMESTAMP_KEYS`. Alert documents flatten `kibana.alert.*`
/// fields into dotted keys directly on `_source`, not nested objects, so a
/// suffix match on the key is enough for the fields that follow the pattern.
fn is_alert_timestamp_key(key: &str) -> bool {
    key == "@timestamp"
        || key.ends_with("_at")
        || key.ends_with(".start")
        || key.ends_with(".end")
        || ALERT_TIMESTAMP_KEYS.contains(&key)
}

/// Rewrite alert timestamp values to a fixed placeholder in place, keeping
/// the field present for the decoders (spec section 9).
fn scrub_alert_timestamps(v: &mut Value) {
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

/// Fixed replacement for `kibana.alert.url`. Kibana builds this value as
/// `/app/security/alerts/redirect/<alertUuid>?index=…&timestamp=<@timestamp>`
/// — both the alert uuid (the real, unscrubbed `_id`) and a live wall-clock
/// timestamp are embedded inside a single string value. The substring id
/// rewrite in `scrub_placeholder_values` fixes the first; this fixes the
/// second by replacing the whole value outright, since nothing in elasticctl
/// decodes `kibana.alert.url`.
const ALERT_FIXTURE_URL: &str =
    "https://REDACTED.example.invalid/app/security/alerts/redirect/elasticctl-fixture-redacted";

fn scrub_alert_urls(v: &mut Value) {
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

/// Format the current time as RFC3339 UTC with millisecond precision, e.g.
/// `2026-09-01T12:34:56.789Z`. The workspace has no date-formatting
/// dependency, so this hand-rolls it from `SystemTime` using Howard
/// Hinnant's civil-from-days algorithm
/// (<https://howardhinnant.github.io/date_algorithms.html>).
fn now_rfc3339() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let millis = now.as_millis() as i64;
    let secs = millis.div_euclid(1000);
    let ms = millis.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{ms:03}Z")
}

/// Convert a day count since the Unix epoch (1970-01-01) to a proleptic
/// Gregorian (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day)
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
        strip_volatile(&mut v, RULE_VOLATILE_FIELDS);
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
        Some("conformance-matrix") => {
            if let Err(error) = conformance_matrix::run(&args[1..]).await {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: cargo xtask [record|seed|conformance|conformance-matrix]");
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

/// Record a rule, list, or item response, stripping the volatile server-owned
/// fields so a re-record of the same object is byte-identical.
fn rule_fixture(
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
fn rule_exchange_fixture(
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
fn preview_fixture(
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
fn preview_exchange_fixture(
    name: &'static str,
    flavor: &str,
    version: &str,
    mut request: Value,
    mut body: Value,
) -> RecordedFixture {
    strip_volatile(&mut request, PREVIEW_VOLATILE_FIELDS);
    strip_volatile(&mut body, PREVIEW_VOLATILE_FIELDS);
    exchange_fixture(name, flavor, version, request, body)
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

/// Scratch index queried by the search probe. Like `PREVIEW_PROBE_INDEX`, it
/// avoids the `logs-` prefix; each document carries the `elasticctl-sample`
/// marker in its `marker` field.
const SEARCH_PROBE_INDEX: &str = "elasticctl-sample-search";
/// Value of the `marker` field every search probe document carries.
const SEARCH_MARKER: &str = "elasticctl-sample";
/// ES|QL response fields that vary per run. They are dropped before writing a
/// fixture so a re-record of the same data is byte-identical (spec §8).
const ESQL_VOLATILE_FIELDS: &[&str] = &[
    "took",
    "start_time_in_millis",
    "completion_time_in_millis",
    "expiration_time_in_millis",
    "cpu_nanos",
    "read_nanos",
    "bytes_read",
    "values_loaded",
    "documents_found",
    "rows_emitted",
    "is_partial",
    "is_running",
];
/// Query DSL response fields that vary per run (spec §8).
const DSL_VOLATILE_FIELDS: &[&str] = &["took", "_shards", "_score", "sort", "pit_id"];
/// Server-owned fields on rules, lists, and items that change on every create:
/// the saved-object `id` and the `created_at`/`updated_at` timestamps. They must
/// not survive a fixture (spec §8). A space or data-view `id` is stable and
/// meaningful, so this strip applies only to rule, list, and item fixtures.
const RULE_VOLATILE_FIELDS: &[&str] = &["id", "created_at", "updated_at", "execution_summary"];
/// Per-run fields in a preview and its alert hits: the preview id, execution
/// timestamps and uuids, the generated rule id, and the per-run name/reason
/// suffix. A preview writes fresh alerts each run, so these must not survive a
/// fixture (spec §8); the fixture keeps the alert structure and hit count.
const PREVIEW_VOLATILE_FIELDS: &[&str] = &[
    "previewId",
    "duration",
    "_id",
    "rule_id",
    "kibana.alert.uuid",
    "kibana.alert.rule.rule_id",
    "kibana.alert.rule.execution.uuid",
    "kibana.alert.rule.execution.timestamp",
    "kibana.alert.rule.created_at",
    "kibana.alert.rule.updated_at",
    "kibana.alert.rule.name",
    "kibana.alert.reason",
    "kibana.alert.url",
    "kibana.alert.start",
    "kibana.alert.last_detected",
];

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
    search_index: bool,
    alert_rule: bool,
    alert_index: bool,
    /// Set once, when `record_alerts` is about to create the marker rule or
    /// index, and never cleared back to `false` even after a successful
    /// delete (unlike `alert_rule`/`alert_index` above, which toggle off
    /// once deleted and gate whether `cleanup` attempts one). Gates
    /// `cleanup`'s final re-verification that the object is actually gone —
    /// the only in-session proof of that for a lab session that gets torn
    /// down right after.
    alert_rule_claimed: bool,
    alert_index_claimed: bool,
    /// Set before `record_cases` issues the case-create write, cleared once
    /// `record_cases` has verified its own delete. A case has no fixed,
    /// caller-chosen id to re-check the way `rule`/`list`/`item` do, so
    /// `cleanup`'s sweep for this flag identifies it by title+tag instead
    /// (`sweep_delete_marker_cases`).
    case: bool,
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

fn owns_search_index(value: &Value) -> bool {
    value["_source"]["marker"].as_str() == Some(SEARCH_MARKER)
}

fn owns_alert_rule(value: &Value) -> bool {
    value.get("rule_id").and_then(Value::as_str) == Some(ALERT_RULE_ID)
        && value
            .get("tags")
            .and_then(Value::as_array)
            .is_some_and(|tags| {
                tags.iter()
                    .any(|tag| tag.as_str() == Some(ALERT_MARKER_TAG))
            })
}

fn owns_alert_index(value: &Value) -> bool {
    value["_source"]["marker"].as_str() == Some(ALERT_MARKER_TAG)
}

/// True when a case create response proves the fixed marker identity: the
/// exact title AND the marker tag, mirroring `owns_rule`'s AND semantics.
fn owns_case(value: &Value) -> bool {
    value.get("title").and_then(Value::as_str) == Some(CASE_TITLE)
        && value
            .get("tags")
            .and_then(Value::as_array)
            .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(CASE_TAG)))
}

/// The query filter that names every alert the probe rule produced.
fn alert_probe_filter() -> Value {
    json!({"term": {"kibana.alert.rule.rule_id": ALERT_RULE_ID}})
}

/// Every alert the probe rule produced that has not been closed. Closed
/// residue from an earlier run is the accepted deviation (spec section 9).
fn alert_probe_open_filter() -> Value {
    json!({
        "bool": {
            "filter": [alert_probe_filter()],
            "must_not": [{"term": {"kibana.alert.workflow_status": "closed"}}]
        }
    })
}

async fn require_no_open_marker_alerts(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    let body = json!({"query": alert_probe_open_filter(), "size": 0, "track_total_hits": true});
    let response = t
        .post(elasticctl_api::alerts::SEARCH_PATH, Some(&body))
        .await?;
    let total = response
        .pointer("/hits/total/value")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if total > 0 {
        return Err(recording_error(format!(
            "refusing to record: {total} non-closed alert(s) already carry rule_id {ALERT_RULE_ID}"
        )));
    }
    Ok(())
}

/// Best-effort disable of the marker rule (idempotent: a rule that is
/// already gone or already disabled is not an error, so its result is
/// ignored), then close every marker alert by query, checking after each
/// attempt. Retries up to 5 times, 3 seconds apart, to absorb a rule
/// execution that was already in flight when disabled. Shared by
/// `record_alerts`'s own residue step and `cleanup`'s last-resort sweep.
async fn sweep_close_marker_alerts(t: &elasticctl_core::Transport) -> elasticctl_core::Result<()> {
    let _ = t
        .patch(
            "/api/detection_engine/rules",
            &json!({"rule_id": ALERT_RULE_ID, "enabled": false}),
        )
        .await;
    let close_query_request = json!({
        "query": alert_probe_filter(),
        "status": "closed",
        "conflicts": "abort",
        "reason": "automated_closure",
    });
    for _ in 0..5 {
        if require_no_open_marker_alerts(t).await.is_ok() {
            return Ok(());
        }
        t.post(
            elasticctl_api::alerts::STATUS_PATH,
            Some(&close_query_request),
        )
        .await
        .map_err(|error| {
            recording_error(format!("close-by-query sweep retry: {}", error.message))
        })?;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    require_no_open_marker_alerts(t).await
}

/// The `_find` filter that names every marker case: the fixed title AND the
/// fixed tag together, matching `owns_case`'s AND semantics.
fn case_marker_filter() -> elasticctl_api::cases_ops::CaseFilter {
    elasticctl_api::cases_ops::CaseFilter {
        search: Some(CASE_TITLE.to_string()),
        tag: Some(CASE_TAG.to_string()),
        ..Default::default()
    }
}

async fn find_marker_cases(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<(Vec<elasticctl_api::cases::Case>, u64)> {
    let query = elasticctl_api::cases_ops::find_query(
        &case_marker_filter(),
        1,
        elasticctl_api::cases_ops::PAGE_SIZE,
    );
    elasticctl_api::cases::find_page(t, &query).await
}

async fn require_no_marker_cases(t: &elasticctl_core::Transport) -> elasticctl_core::Result<()> {
    let (cases, total) = find_marker_cases(t).await?;
    if total > 0 || !cases.is_empty() {
        return Err(recording_error(format!(
            "refusing to record: {total} case(s) already carry title {CASE_TITLE:?} and tag \
             {CASE_TAG}. Manual remediation: find the id(s) via GET {}?{} then DELETE {} with \
             the matching ?ids=[...] query.",
            elasticctl_api::cases::FIND_PATH,
            elasticctl_api::cases_ops::find_query(
                &case_marker_filter(),
                1,
                elasticctl_api::cases_ops::PAGE_SIZE
            ),
            elasticctl_api::cases::CASES_PATH,
        )));
    }
    Ok(())
}

/// Delete every marker case found by title+tag, then re-verify none remain.
/// Cases tolerate zero residue (spec section 9) — unlike the alerts probe's
/// accepted closed-alert deviation, there is no "closed is fine" escape
/// hatch here. Shared by `record_cases`'s own delete step and `cleanup`'s
/// last-resort sweep.
async fn sweep_delete_marker_cases(t: &elasticctl_core::Transport) -> elasticctl_core::Result<()> {
    let (cases, _) = find_marker_cases(t).await?;
    let ids: Vec<String> = cases
        .into_iter()
        .filter(|c| c.title == CASE_TITLE && c.tags.iter().any(|tag| tag == CASE_TAG))
        .map(|c| c.id)
        .collect();
    if !ids.is_empty() {
        elasticctl_api::cases::delete(t, &ids).await?;
    }
    require_no_marker_cases(t).await
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

async fn require_absent_search_index(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    match t.get_absolute_es(&format!("/{SEARCH_PROBE_INDEX}")).await {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: scratch index {SEARCH_PROBE_INDEX} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

async fn require_absent_alert_rule(t: &elasticctl_core::Transport) -> elasticctl_core::Result<()> {
    match t
        .get(&format!(
            "/api/detection_engine/rules?rule_id={ALERT_RULE_ID}"
        ))
        .await
    {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: rule {ALERT_RULE_ID} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

async fn require_absent_alert_index(t: &elasticctl_core::Transport) -> elasticctl_core::Result<()> {
    match t.get_absolute_es(&format!("/{ALERT_PROBE_INDEX}")).await {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: scratch index {ALERT_PROBE_INDEX} already exists and is not cleanup-owned"
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

        if self.ownership.search_index {
            match self
                .transport
                .get_absolute_es(&format!("/{SEARCH_PROBE_INDEX}/_doc/1"))
                .await
            {
                Ok(document) if owns_search_index(&document) => {
                    match self
                        .transport
                        .delete_absolute_es(&format!("/{SEARCH_PROBE_INDEX}"))
                        .await
                    {
                        Ok(_) => self.ownership.search_index = false,
                        Err(error) => errors.push(format!(
                            "deleting scratch index {SEARCH_PROBE_INDEX}: {}",
                            error.message
                        )),
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete scratch index {SEARCH_PROBE_INDEX}: its marker field no longer matches"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                    self.ownership.search_index = false;
                }
                Err(error) => errors.push(format!(
                    "checking scratch index {SEARCH_PROBE_INDEX}: {}",
                    error.message
                )),
            }
        }

        if self.ownership.alert_rule {
            match self
                .transport
                .get(&format!(
                    "/api/detection_engine/rules?rule_id={ALERT_RULE_ID}"
                ))
                .await
            {
                Ok(rule) if owns_alert_rule(&rule) => {
                    match self
                        .transport
                        .delete(&format!(
                            "/api/detection_engine/rules?rule_id={ALERT_RULE_ID}"
                        ))
                        .await
                    {
                        Ok(_) => self.ownership.alert_rule = false,
                        Err(error) => {
                            errors.push(format!("deleting rule {ALERT_RULE_ID}: {}", error.message))
                        }
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete rule {ALERT_RULE_ID}: its marker fields no longer match"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                    self.ownership.alert_rule = false;
                }
                Err(error) => {
                    errors.push(format!("checking rule {ALERT_RULE_ID}: {}", error.message))
                }
            }
        }

        if self.ownership.alert_index {
            match self
                .transport
                .get_absolute_es(&format!("/{ALERT_PROBE_INDEX}/_doc/1"))
                .await
            {
                Ok(document) if owns_alert_index(&document) => {
                    match self
                        .transport
                        .delete_absolute_es(&format!("/{ALERT_PROBE_INDEX}"))
                        .await
                    {
                        Ok(_) => self.ownership.alert_index = false,
                        Err(error) => errors.push(format!(
                            "deleting alert index {ALERT_PROBE_INDEX}: {}",
                            error.message
                        )),
                    }
                }
                Ok(_) => errors.push(format!(
                    "refusing to delete alert index {ALERT_PROBE_INDEX}: its marker field no longer matches"
                )),
                Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {
                    self.ownership.alert_index = false;
                }
                Err(error) => errors.push(format!(
                    "checking alert index {ALERT_PROBE_INDEX}: {}",
                    error.message
                )),
            }
        }

        // Cases have no fixed id to re-check by, so this is a title+tag
        // sweep-and-verify rather than a get/delete pair like the blocks
        // above. `record_cases` already clears this flag on its own
        // successful delete, so this only fires when it failed midway.
        if self.ownership.case
            && let Err(error) = sweep_delete_marker_cases(self.transport).await
        {
            errors.push(format!("verifying case probe baseline: {}", error.message));
        }

        // A raw total-rule-count comparison would be unsound here: this same
        // pass also deletes the unrelated fixture-probe rule (`self.ownership.rule`,
        // above), so "before" and "after" would straddle a second, independent
        // deletion and always disagree by one. `require_absent_alert_rule` and
        // `require_absent_alert_index` below are what prove the alert probe
        // itself adds and removes exactly one rule and one index — the only
        // in-session proof of that, since a lab session is torn down right
        // after and can't rely on "the next run's baseline check will catch
        // it".
        if self.ownership.alert_rule_claimed
            && let Err(error) = require_absent_alert_rule(self.transport).await
        {
            errors.push(format!(
                "verifying the alert probe rule is gone: {}",
                error.message
            ));
        }
        if self.ownership.alert_index_claimed
            && let Err(error) = require_absent_alert_index(self.transport).await
        {
            errors.push(format!(
                "verifying the alert probe index is gone: {}",
                error.message
            ));
        }

        // Last resort: a query-scoped close, retried, before failing on open
        // residue. This covers the one thing the existence checks above
        // cannot: no *open* marker alert (closed residue is the accepted
        // deviation, spec section 9). `sweep_close_marker_alerts` is the same
        // helper `record_alerts` uses for its own residue step.
        if let Err(error) = sweep_close_marker_alerts(self.transport).await {
            errors.push(format!(
                "verifying alert probe baseline: {}. Manual remediation: POST {} with \
                 body {{\"query\":{{\"term\":{{\"kibana.alert.rule.rule_id\":\"{ALERT_RULE_ID}\"}}}},\
                 \"status\":\"closed\",\"conflicts\":\"abort\"}}",
                error.message,
                elasticctl_api::alerts::STATUS_PATH,
            ));
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

/// Record the search probe: a marker-scoped scratch index seeded with three
/// documents, the ES|QL and Query DSL exchanges over them, then the Kibana
/// data-view and default-index lookups. The index is deleted by `cleanup`.
async fn record_search(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    flavor: &str,
    version: &str,
) -> elasticctl_core::Result<()> {
    require_absent_search_index(session.transport).await?;
    let t = session.transport;

    for (id, seq) in [("1", 1_i64), ("2", 2), ("3", 3)] {
        let doc = json!({
            "seq": seq,
            "message": format!("elasticctl sample search document {seq}"),
            "marker": SEARCH_MARKER,
        });
        t.post_absolute_es(&format!("/{SEARCH_PROBE_INDEX}/_doc/{id}"), &doc)
            .await?;
    }
    let proof = t
        .get_absolute_es(&format!("/{SEARCH_PROBE_INDEX}/_doc/1"))
        .await?;
    if !owns_search_index(&proof) {
        return Err(recording_error(
            "search index write did not prove the fixed marker identity",
        ));
    }
    session.ownership.search_index = true;
    // `_refresh` rejects a body, so use the GET form, which sends none.
    t.get_absolute_es(&format!("/{SEARCH_PROBE_INDEX}/_refresh"))
        .await?;

    let esql_query = format!("FROM {SEARCH_PROBE_INDEX} | SORT seq ASC | LIMIT 2");
    let mut esql_response = t
        .post_absolute_es("/_query", &json!({"query": esql_query}))
        .await?;
    strip_volatile(&mut esql_response, ESQL_VOLATILE_FIELDS);
    recording.fixtures.push(response_fixture(
        "esql_query",
        flavor,
        version,
        esql_response,
        None,
    ));

    let mut pit_open = t
        .post_absolute_es(
            &format!("/{SEARCH_PROBE_INDEX}/_pit?keep_alive=1m"),
            &json!({}),
        )
        .await?;
    let pit_id = pit_open["id"]
        .as_str()
        .ok_or_else(|| recording_error("pit open response is missing id"))?
        .to_string();
    strip_volatile(&mut pit_open, DSL_VOLATILE_FIELDS);
    strip_pit_token(&mut pit_open);
    recording.fixtures.push(exchange_fixture(
        "search_pit_open",
        flavor,
        version,
        json!({"index": SEARCH_PROBE_INDEX, "keep_alive": "1m"}),
        pit_open,
    ));

    let mut pit_page_request = json!({
        "size": 2,
        "sort": [{"seq": "asc"}, {"_shard_doc": "asc"}],
        "pit": {"id": pit_id, "keep_alive": "1m"},
        "query": {"match_all": {}}
    });
    let mut pit_page = t.post_absolute_es("/_search", &pit_page_request).await?;
    strip_volatile(&mut pit_page, DSL_VOLATILE_FIELDS);
    strip_pit_token(&mut pit_page_request);
    recording.fixtures.push(exchange_fixture(
        "search_pit_page",
        flavor,
        version,
        pit_page_request,
        pit_page,
    ));

    let pit_close = t
        .delete_absolute_es_json("/_pit", &json!({"id": pit_id}))
        .await?;
    recording.fixtures.push(response_fixture(
        "search_pit_close",
        flavor,
        version,
        pit_close,
        None,
    ));

    let mut data_views = t.get("/api/data_views").await?;
    redact_data_views(&mut data_views);
    recording.fixtures.push(response_fixture(
        "data_views",
        flavor,
        version,
        data_views,
        None,
    ));
    recording.fixtures.push(response_fixture(
        "detection_engine_index",
        flavor,
        version,
        t.get("/api/detection_engine/index").await?,
        None,
    ));

    Ok(())
}

/// What `record_alerts_probe` hands to `record_cases` (to attach against)
/// and to `close_and_clean_alerts` (to finish the close-by-query exchange).
struct AlertsProbe {
    /// The real `_id` of the still-open marker alert `record_cases` attaches.
    first_id: String,
    /// Real alert doc id (and uuid, when present) -> fixed placeholder.
    id_map: BTreeMap<String, String>,
    /// The first activated profile uid, used as the case's assignee.
    assignee_uid: String,
    /// Real profile uid -> fixed placeholder.
    uid_map: BTreeMap<String, String>,
}

/// Record the alerts probe: a marker rule over a marker index, generating an
/// alert the recorder transitions, tags, and assigns through every triage
/// route (triage spec section 9). Runs after `record_search`, and stops with
/// one open marker alert still live so `record_cases` has a real alert to
/// attach. Split out of the original single-function `record_alerts` (now
/// `record_alerts_probe` + `close_and_clean_alerts`) so `record_session` can
/// run `record_cases` between the two; every pre-write ownership claim and
/// marker check below is unchanged from the single-function version.
async fn record_alerts_probe(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    flavor: &str,
    version: &str,
) -> elasticctl_core::Result<AlertsProbe> {
    require_absent_alert_rule(session.transport).await?;
    require_absent_alert_index(session.transport).await?;
    require_no_open_marker_alerts(session.transport).await?;

    let t = session.transport;

    // Claim ownership before issuing the write, not after a successful
    // response: a transport failure on a create the server actually applied
    // (e.g. the response is lost but the write landed) must not orphan an
    // enabled, 1-minute-interval rule or a scratch index. `cleanup` already
    // re-verifies the marker fields before deleting anything, so claiming
    // early cannot cause it to delete a foreign object.
    session.ownership.alert_index = true;
    session.ownership.alert_index_claimed = true;
    for (id, seq) in [("1", 1_i64), ("2", 2), ("3", 3)] {
        let doc = json!({
            "@timestamp": now_rfc3339(),
            "marker": ALERT_MARKER_TAG,
            "message": format!("elasticctl sample alert event {seq}"),
        });
        t.post_absolute_es(&format!("/{ALERT_PROBE_INDEX}/_doc/{id}"), &doc)
            .await?;
    }
    let proof = t
        .get_absolute_es(&format!("/{ALERT_PROBE_INDEX}/_doc/1"))
        .await?;
    if !owns_alert_index(&proof) {
        return Err(recording_error(
            "alert index write did not prove the fixed marker identity",
        ));
    }
    // `_refresh` rejects a body, so use the GET form, which sends none.
    t.get_absolute_es(&format!("/{ALERT_PROBE_INDEX}/_refresh"))
        .await?;

    let rule_body = json!({
        "rule_id": ALERT_RULE_ID,
        "name": ALERT_RULE_NAME,
        "description": "Recorded by cargo xtask record. Safe to delete.",
        "type": "query",
        "language": "kuery",
        "query": "marker: elasticctl-sample",
        "index": [ALERT_PROBE_INDEX],
        "severity": "low",
        "risk_score": 21,
        "enabled": true,
        "from": "now-10m",
        "interval": "1m",
        "tags": [ALERT_MARKER_TAG],
    });
    session.ownership.alert_rule = true;
    session.ownership.alert_rule_claimed = true;
    let created_rule = t
        .post("/api/detection_engine/rules", Some(&rule_body))
        .await?;
    if !owns_alert_rule(&created_rule) {
        return Err(recording_error(
            "alert rule create response did not prove the fixed marker identity",
        ));
    }

    // Poll on the *open* filter, not the bare rule-id filter: closed residue
    // from an earlier run (the accepted deviation, spec section 9) would
    // otherwise satisfy the readiness check before this session's rule ever
    // fires, and the same query becomes the recorded `signals_search`
    // exchange, so it must capture only this session's own alerts.
    //
    // The rest of the body is the PRODUCTION body, not a hand-rolled probe
    // shape: `alerts_ops::default_sort()` and `RESOLVE_SOURCE_FIELDS` are the
    // exact sort and `_source` include `alerts_ops` sends on every read, so
    // this recording proves — for the first time against a live stack —
    // that the `kibana.alert.uuid` sort tiebreaker doesn't error and that a
    // dotted `_source` include actually returns flat dotted keys (triage
    // spec section 10). Composed from the `-api` crate so recorder and
    // production cannot drift apart.
    let search_request = json!({
        "query": alert_probe_open_filter(),
        "sort": elasticctl_api::alerts_ops::default_sort(),
        "size": 10,
        "track_total_hits": true,
        "_source": elasticctl_api::alerts_ops::RESOLVE_SOURCE_FIELDS,
    });
    let mut search_response = Value::Null;
    let mut found = false;
    for attempt in 0..ALERT_POLL_ATTEMPTS {
        search_response = t
            .post(elasticctl_api::alerts::SEARCH_PATH, Some(&search_request))
            .await?;
        let total = search_response
            .pointer("/hits/total/value")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if total > 0 {
            found = true;
            break;
        }
        if attempt + 1 < ALERT_POLL_ATTEMPTS {
            tokio::time::sleep(ALERT_POLL_INTERVAL).await;
        }
    }
    if !found {
        let minutes = ALERT_POLL_ATTEMPTS * ALERT_POLL_INTERVAL.as_secs() as u32 / 60;
        return Err(recording_error(format!(
            "no alerts appeared for rule_id {ALERT_RULE_ID} after {ALERT_POLL_ATTEMPTS} \
             attempts over ~{minutes} minutes; the rule scheduler may be lagging — rerun this \
             flavor"
        )));
    }

    let page = elasticctl_api::alerts::decode_page(&search_response).map_err(|error| {
        recording_error(format!(
            "decoding signals_search response: {}",
            error.message
        ))
    })?;
    if page.hits.is_empty() {
        return Err(recording_error(
            "signals_search reported a positive total but decoded zero hits",
        ));
    }
    // Prove the dotted `_source` include actually returns the requested
    // fields against flat dotted keys — an assumption `resolve_ids` (and so
    // every mutation preview) rests on, never before exercised against a
    // live stack (triage spec section 10). A hit whose restricted `_source`
    // is missing a requested field would otherwise pass silently: `hits` is
    // still non-empty, decode still succeeds, and the fixture would record
    // broken behavior as if it were proven.
    for hit in &page.hits {
        for field in elasticctl_api::alerts_ops::RESOLVE_SOURCE_FIELDS {
            if hit.source.get(*field).is_none() {
                return Err(recording_error(format!(
                    "signals_search's `_source` include did not return `{field}` on hit {}: \
                     the dotted _source include may not work against flat dotted keys",
                    hit.id
                )));
            }
        }
    }
    let mut id_map: BTreeMap<String, String> = BTreeMap::new();
    for (i, hit) in page.hits.iter().enumerate() {
        let placeholder = format!("elasticctl-fixture-alert-{}", i + 1);
        id_map.insert(hit.id.clone(), placeholder.clone());
        if let Some(uuid) = hit.source.get("kibana.alert.uuid").and_then(Value::as_str) {
            id_map.insert(uuid.to_string(), placeholder);
        }
    }
    let first_id = page.hits[0].id.clone();

    {
        let mut request = search_request.clone();
        let mut response = search_response.clone();
        strip_volatile(&mut response, ALERT_SEARCH_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &id_map);
        scrub_placeholder_values(&mut response, &id_map);
        scrub_alert_timestamps(&mut response);
        scrub_alert_urls(&mut response);
        recording.fixtures.push(exchange_fixture(
            "signals_search",
            flavor,
            version,
            request,
            response,
        ));
    }

    // Acknowledge the first alert by id. The live response settles whether
    // the `signal_ids` form accepts `reason` (triage spec section 10).
    let with_reason = json!({
        "signal_ids": [first_id.clone()],
        "status": "acknowledged",
        "reason": "false_positive",
    });
    let (ids_status_request, ids_status_response, ids_reason_accepted) = match t
        .post(elasticctl_api::alerts::STATUS_PATH, Some(&with_reason))
        .await
    {
        Ok(response) => (with_reason, response, true),
        Err(error) => {
            println!(
                "signals/status signal_ids+reason failed ({}); retrying without reason",
                error.message
            );
            let without_reason = json!({
                "signal_ids": [first_id.clone()],
                "status": "acknowledged",
            });
            let response = t
                .post(elasticctl_api::alerts::STATUS_PATH, Some(&without_reason))
                .await?;
            (without_reason, response, false)
        }
    };
    println!("signals/status signal_ids-form reason accepted: {ids_reason_accepted}");
    elasticctl_api::alerts::decode_outcome(&ids_status_response).map_err(|error| {
        recording_error(format!(
            "decoding signals_status_ids response: {}",
            error.message
        ))
    })?;
    {
        let mut request = ids_status_request;
        let mut response = ids_status_response;
        strip_volatile(&mut response, TRIAGE_ENVELOPE_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &id_map);
        scrub_placeholder_values(&mut response, &id_map);
        recording.fixtures.push(exchange_fixture(
            "signals_status_ids",
            flavor,
            version,
            request,
            response,
        ));
    }

    // Add then remove a tag on the same alert; record the add.
    let add_tags_request = json!({
        "ids": [first_id.clone()],
        "tags": {"tags_to_add": ["triage-check"], "tags_to_remove": []},
    });
    let add_tags_response = t
        .post(elasticctl_api::alerts::TAGS_PATH, Some(&add_tags_request))
        .await?;
    elasticctl_api::alerts::decode_outcome(&add_tags_response).map_err(|error| {
        recording_error(format!("decoding signals_tags response: {}", error.message))
    })?;
    let remove_tags_request = json!({
        "ids": [first_id.clone()],
        "tags": {"tags_to_add": [], "tags_to_remove": ["triage-check"]},
    });
    t.post(
        elasticctl_api::alerts::TAGS_PATH,
        Some(&remove_tags_request),
    )
    .await?;
    {
        let mut request = add_tags_request;
        let mut response = add_tags_response;
        strip_volatile(&mut response, TRIAGE_ENVELOPE_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &id_map);
        scrub_placeholder_values(&mut response, &id_map);
        recording.fixtures.push(exchange_fixture(
            "signals_tags",
            flavor,
            version,
            request,
            response,
        ));
    }

    // Activated user profiles. `uid` is rewritten to a per-profile
    // placeholder, never blanket-redacted: the assignees exchange below
    // needs it to stay a decodable, distinguishable value.
    let users_body = t
        .get_internal(&elasticctl_api::profiles::internal_find_path(""))
        .await?;
    let profiles_list =
        elasticctl_api::profiles::decode_internal(&users_body).map_err(|error| {
            recording_error(format!("decoding users_find response: {}", error.message))
        })?;
    let assignee_uid = profiles_list
        .first()
        .ok_or_else(|| {
            recording_error(
                "users_find returned no activated profiles; the assignees probe needs at least one",
            )
        })?
        .uid
        .clone();
    let mut uid_map: BTreeMap<String, String> = BTreeMap::new();
    for (i, profile) in profiles_list.iter().enumerate() {
        uid_map.insert(profile.uid.clone(), format!("u_REDACTED_{}", i + 1));
    }
    {
        let mut response = users_body;
        scrub_placeholder_values(&mut response, &uid_map);
        recording.fixtures.push(response_fixture(
            "users_find",
            flavor,
            version,
            response,
            None,
        ));
    }

    // Assign then unassign the first activated uid; record the add.
    let add_assignees_request = json!({
        "ids": [first_id.clone()],
        "assignees": {"add": [assignee_uid.clone()], "remove": []},
    });
    let add_assignees_response = t
        .post(
            elasticctl_api::alerts::ASSIGNEES_PATH,
            Some(&add_assignees_request),
        )
        .await?;
    elasticctl_api::alerts::decode_outcome(&add_assignees_response).map_err(|error| {
        recording_error(format!(
            "decoding signals_assignees response: {}",
            error.message
        ))
    })?;
    let remove_assignees_request = json!({
        "ids": [first_id.clone()],
        "assignees": {"add": [], "remove": [assignee_uid.clone()]},
    });
    t.post(
        elasticctl_api::alerts::ASSIGNEES_PATH,
        Some(&remove_assignees_request),
    )
    .await?;
    {
        let mut request = add_assignees_request;
        let mut response = add_assignees_response;
        strip_volatile(&mut response, TRIAGE_ENVELOPE_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &id_map);
        scrub_placeholder_values(&mut response, &id_map);
        scrub_placeholder_values(&mut request, &uid_map);
        scrub_placeholder_values(&mut response, &uid_map);
        recording.fixtures.push(exchange_fixture(
            "signals_assignees",
            flavor,
            version,
            request,
            response,
        ));
    }

    // Profile suggest, public route. Serverless answers 410; record
    // whichever shape the live route actually returns.
    match t
        .post_absolute_es(
            elasticctl_api::profiles::PUBLIC_SUGGEST_PATH,
            &json!({"name": "", "size": 10}),
        )
        .await
    {
        Ok(mut response) => {
            let suggested =
                elasticctl_api::profiles::decode_public(&response).map_err(|error| {
                    recording_error(format!(
                        "decoding profile_suggest response: {}",
                        error.message
                    ))
                })?;
            let mut next_index = uid_map.len();
            for profile in &suggested {
                if !uid_map.contains_key(&profile.uid) {
                    next_index += 1;
                    uid_map.insert(profile.uid.clone(), format!("u_REDACTED_{next_index}"));
                }
            }
            strip_volatile(&mut response, TRIAGE_ENVELOPE_VOLATILE_FIELDS);
            scrub_placeholder_values(&mut response, &uid_map);
            recording.fixtures.push(response_fixture(
                "profile_suggest",
                flavor,
                version,
                response,
                None,
            ));
        }
        Err(error) => {
            recording
                .fixtures
                .push(error_fixture("profile_suggest", flavor, version, error))
        }
    }

    // Disable the rule now, at the end of the probe, not at the start of the
    // close: every triage exchange this function needs is already recorded,
    // and `record_cases` runs next, driving several more live HTTP round
    // trips before `close_and_clean_alerts` gets a turn. Leaving the rule
    // enabled for that whole interval lets its 1-minute schedule keep firing
    // and stacking up fresh alerts underneath `record_cases`, which both
    // inflates the final close-by-query's `total` well past what
    // `sweep_close_marker_alerts`'s 15-second retry budget was sized for and
    // invites a genuine version-conflict race between an in-flight execution
    // and that close. Disabling here bounds the alert volume to what this
    // probe itself produced, the same as the single-function original.
    t.patch(
        "/api/detection_engine/rules",
        &json!({"rule_id": ALERT_RULE_ID, "enabled": false}),
    )
    .await?;

    Ok(AlertsProbe {
        first_id,
        id_map,
        assignee_uid,
        uid_map,
    })
}

/// Close every marker alert the probe produced, verifying the close sweep
/// leaves no open residue. Split out of `record_alerts` (see
/// `record_alerts_probe`, which already disabled the rule) so `record_cases`
/// can run in between while one alert is still open.
async fn close_and_clean_alerts(
    t: &elasticctl_core::Transport,
    recording: &mut Recording,
    flavor: &str,
    version: &str,
    id_map: &BTreeMap<String, String>,
) -> elasticctl_core::Result<()> {
    // Best-effort: `record_alerts_probe` already disabled the rule before
    // `record_cases` ran. Repeating it here is idempotent and cheap, and
    // guards against a future caller that skips straight to this function.
    let _ = t
        .patch(
            "/api/detection_engine/rules",
            &json!({"rule_id": ALERT_RULE_ID, "enabled": false}),
        )
        .await;

    // Close every marker alert by query. This is also the residue step: the
    // session's alerts end closed (triage spec section 9). Retried up to 5
    // times, 3 seconds apart: `record_cases` attaches one of these alerts to
    // a case just before this runs, and that attach writes
    // `kibana.alert.case_ids` back onto the alert document — a write that
    // can still be settling when this call lands, producing a genuine
    // transient version conflict on exactly the attached document (`abort`
    // makes the whole call fail rather than partially succeed). The request
    // itself, including `conflicts: abort`, is unchanged from production.
    let close_query_request = json!({
        "query": alert_probe_filter(),
        "status": "closed",
        "conflicts": "abort",
        "reason": "automated_closure",
    });
    let mut close_query_response = None;
    for attempt in 1..=5 {
        match t
            .post(
                elasticctl_api::alerts::STATUS_PATH,
                Some(&close_query_request),
            )
            .await
        {
            Ok(response) => {
                close_query_response = Some(response);
                break;
            }
            Err(error) if attempt < 5 => {
                println!(
                    "signals/status close-by-query attempt {attempt} failed transiently \
                     ({}); retrying",
                    error.message
                );
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
            Err(error) => {
                return Err(recording_error(format!(
                    "close-by-query: {}",
                    error.message
                )));
            }
        }
    }
    let close_query_response =
        close_query_response.expect("loop above returns Some or an Err before exiting");
    elasticctl_api::alerts::decode_outcome(&close_query_response).map_err(|error| {
        recording_error(format!(
            "decoding signals_status_query response: {}",
            error.message
        ))
    })?;
    {
        let mut request = close_query_request;
        let mut response = close_query_response;
        strip_volatile(&mut response, TRIAGE_ENVELOPE_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, id_map);
        scrub_placeholder_values(&mut response, id_map);
        recording.fixtures.push(exchange_fixture(
            "signals_status_query",
            flavor,
            version,
            request,
            response,
        ));
    }

    // Verify and retry: an execution that was already in progress when the
    // rule was disabled can still land alerts after the close above.
    // `sweep_close_marker_alerts` is the same helper `cleanup`'s last-resort
    // sweep uses.
    sweep_close_marker_alerts(t).await.map_err(|error| {
        recording_error(format!(
            "alert probe left open residue after retrying the close-by-query sweep: {}",
            error.message
        ))
    })?;

    Ok(())
}

/// Register every id/version a case-shaped response carries into `case_map`,
/// so this step's own fixture and every later one scrub consistently.
/// Comment ids are discovered, not assumed: whatever shape the live
/// `comments` array actually carries is what gets a placeholder.
fn register_case_extras(
    value: &Value,
    case_map: &mut BTreeMap<String, String>,
    next_comment: &mut usize,
) {
    // `case_update_status`'s response is a bare array of cases rather than
    // one case object — recurse into each element so a future call site that
    // passes the array directly (instead of unwrapping it first) still
    // registers every version, defense in depth against the exact bug this
    // function had before: passing the array itself found nothing, since
    // `Value::get` on an array never matches an object key.
    if let Some(array) = value.as_array() {
        for item in array {
            register_case_extras(item, case_map, next_comment);
        }
        return;
    }
    if let Some(version) = value.get("version").and_then(Value::as_str) {
        case_map
            .entry(version.to_string())
            .or_insert_with(|| CASE_VERSION_PLACEHOLDER.to_string());
    }
    if let Some(comments) = value.get("comments").and_then(Value::as_array) {
        for comment in comments {
            if let Some(id) = comment.get("id").and_then(Value::as_str)
                && !case_map.contains_key(id)
            {
                *next_comment += 1;
                case_map.insert(
                    id.to_string(),
                    format!("elasticctl-fixture-case-comment-{next_comment}"),
                );
            }
            if let Some(version) = comment.get("version").and_then(Value::as_str) {
                case_map
                    .entry(version.to_string())
                    .or_insert_with(|| CASE_VERSION_PLACEHOLDER.to_string());
            }
        }
    }
    // `cases_find`'s response nests each case one level deeper, under
    // `cases`, rather than being a case itself — recurse into each one so
    // its own version/comments still get registered regardless of step
    // order.
    if let Some(cases) = value.get("cases").and_then(Value::as_array) {
        for case in cases {
            register_case_extras(case, case_map, next_comment);
        }
    }
}

/// The cases probe (triage spec section 9): create a marker case, drive it
/// through every mutation route — including attaching `probe.first_id`, the
/// alerts probe's still-open marker alert — then delete it and prove zero
/// residue. Runs between `record_alerts_probe` and `close_and_clean_alerts`
/// so that alert is still open when the attach exchange needs it.
async fn record_cases(
    session: &mut RecordingSession<'_>,
    recording: &mut Recording,
    flavor: &str,
    version: &str,
    probe: &AlertsProbe,
) -> elasticctl_core::Result<()> {
    require_no_marker_cases(session.transport).await?;

    let t = session.transport;
    let mut case_map: BTreeMap<String, String> = BTreeMap::new();
    let mut next_comment = 0usize;

    // Claim ownership before issuing the write, not after a successful
    // response: unlike the rule/list/item probes, a case has no fixed,
    // caller-chosen id to re-check later, so if the response is lost after
    // the server applied the write, only a title+tag search
    // (`sweep_delete_marker_cases`) can find it regardless of when ownership
    // was claimed — the same reasoning `record_alerts_probe` uses for the
    // alert rule and index.
    session.ownership.case = true;
    let create_request = json!({
        "title": CASE_TITLE,
        "description": CASE_TITLE,
        "tags": [CASE_TAG],
        "severity": "low",
        "assignees": [{"uid": probe.assignee_uid}],
        "connector": {"id": "none", "name": "none", "type": ".none", "fields": null},
        "settings": {"syncAlerts": false},
        "owner": elasticctl_api::cases::OWNER,
    });
    let create_response = t
        .post(elasticctl_api::cases::CASES_PATH, Some(&create_request))
        .await?;
    if !owns_case(&create_response) {
        return Err(recording_error(
            "case create response did not prove the fixed marker identity",
        ));
    }
    let created = elasticctl_api::cases::decode_case(&create_response).map_err(|error| {
        recording_error(format!("decoding case_create response: {}", error.message))
    })?;
    let case_id = created.id.clone();
    case_map.insert(case_id.clone(), CASE_ID_PLACEHOLDER.to_string());
    register_case_extras(&create_response, &mut case_map, &mut next_comment);
    {
        let mut request = create_request;
        let mut response = create_response;
        scrub_alert_timestamps(&mut response);
        strip_volatile(&mut response, CASE_DURATION_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &case_map);
        scrub_placeholder_values(&mut response, &case_map);
        scrub_placeholder_values(&mut request, &probe.uid_map);
        scrub_placeholder_values(&mut response, &probe.uid_map);
        recording.fixtures.push(exchange_fixture(
            "case_create",
            flavor,
            version,
            request,
            response,
        ));
    }

    // case_get
    let get_response = t.get(&elasticctl_api::cases::case_path(&case_id)).await?;
    elasticctl_api::cases::decode_case(&get_response).map_err(|error| {
        recording_error(format!("decoding case_get response: {}", error.message))
    })?;
    register_case_extras(&get_response, &mut case_map, &mut next_comment);
    {
        let mut response = get_response;
        scrub_alert_timestamps(&mut response);
        strip_volatile(&mut response, CASE_DURATION_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut response, &case_map);
        scrub_placeholder_values(&mut response, &probe.uid_map);
        recording.fixtures.push(response_fixture(
            "case_get", flavor, version, response, None,
        ));
    }

    // cases_find: scoped by the fixed title AND tag together, composed from
    // the real `cases_ops::find_query` (so recorder and production cannot
    // drift apart) — never an unscoped `_find`; this measures the exact
    // filter params the CLI sends.
    let find_query_string = elasticctl_api::cases_ops::find_query(
        &case_marker_filter(),
        1,
        elasticctl_api::cases_ops::PAGE_SIZE,
    );
    let find_response = t
        .get(&format!(
            "{}?{find_query_string}",
            elasticctl_api::cases::FIND_PATH
        ))
        .await?;
    let (found, found_total) =
        elasticctl_api::cases::decode_find(&find_response).map_err(|error| {
            recording_error(format!("decoding cases_find response: {}", error.message))
        })?;
    if found_total == 0 || !found.iter().any(|c| c.id == case_id) {
        return Err(recording_error(
            "scoped cases_find did not contain the marker case",
        ));
    }
    register_case_extras(&find_response, &mut case_map, &mut next_comment);
    {
        let mut request = json!({"query": find_query_string});
        let mut response = find_response;
        scrub_alert_timestamps(&mut response);
        strip_volatile(&mut response, CASE_DURATION_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &case_map);
        scrub_placeholder_values(&mut response, &case_map);
        scrub_placeholder_values(&mut response, &probe.uid_map);
        recording.fixtures.push(exchange_fixture(
            "cases_find",
            flavor,
            version,
            request,
            response,
        ));
    }

    // case_comment
    let comment_request = json!({
        "type": "user",
        "comment": CASE_COMMENT,
        "owner": elasticctl_api::cases::OWNER,
    });
    let comment_response = t
        .post(
            &elasticctl_api::cases::comments_path(&case_id),
            Some(&comment_request),
        )
        .await?;
    elasticctl_api::cases::decode_case(&comment_response).map_err(|error| {
        recording_error(format!("decoding case_comment response: {}", error.message))
    })?;
    register_case_extras(&comment_response, &mut case_map, &mut next_comment);
    {
        let mut request = comment_request;
        let mut response = comment_response;
        scrub_alert_timestamps(&mut response);
        strip_volatile(&mut response, CASE_DURATION_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &case_map);
        scrub_placeholder_values(&mut response, &case_map);
        scrub_placeholder_values(&mut response, &probe.uid_map);
        recording.fixtures.push(exchange_fixture(
            "case_comment",
            flavor,
            version,
            request,
            response,
        ));
    }

    // case_attach: the still-open marker alert from `record_alerts_probe`.
    // `plan_attach` is the real production function (composed from -api so
    // recorder and production cannot drift apart), used here only to
    // resolve the alert's rule id/name/index — `record_alerts_probe`'s own
    // signals_search fixture deliberately restricts `_source` to
    // `RESOLVE_SOURCE_FIELDS` (proving that minimal shape works, spec
    // section 10) and does not carry the rule uuid this needs. The comment
    // POST itself is issued directly so the exact request body is recorded.
    let attach_plan =
        elasticctl_api::cases_ops::plan_attach(t, &case_id, std::slice::from_ref(&probe.first_id))
            .await
            .map_err(|error| recording_error(format!("planning case attach: {}", error.message)))?;
    let group = attach_plan.groups.first().ok_or_else(|| {
        recording_error("case attach plan produced no rule group for the marker alert")
    })?;
    // The alert's `kibana.alert.rule.uuid` — the same server-owned,
    // per-rule-creation uuid `is_sensitive` already redacts under its own
    // dotted key elsewhere, but here it appears under a plain `id` key.
    case_map.insert(
        group.rule_id.clone(),
        CASE_RULE_UUID_PLACEHOLDER.to_string(),
    );
    let attach_request = json!({
        "type": "alert",
        "alertId": group.alert_ids,
        "index": group.indices,
        "rule": {"id": group.rule_id, "name": group.rule_name},
        "owner": elasticctl_api::cases::OWNER,
    });
    let attach_response = t
        .post(
            &elasticctl_api::cases::comments_path(&case_id),
            Some(&attach_request),
        )
        .await?;
    let attached = elasticctl_api::cases::decode_case(&attach_response).map_err(|error| {
        recording_error(format!("decoding case_attach response: {}", error.message))
    })?;
    register_case_extras(&attach_response, &mut case_map, &mut next_comment);
    {
        let mut request = attach_request;
        let mut response = attach_response;
        scrub_alert_timestamps(&mut response);
        strip_volatile(&mut response, CASE_DURATION_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &case_map);
        scrub_placeholder_values(&mut response, &case_map);
        scrub_placeholder_values(&mut request, &probe.id_map);
        scrub_placeholder_values(&mut response, &probe.id_map);
        scrub_placeholder_values(&mut response, &probe.uid_map);
        recording.fixtures.push(exchange_fixture(
            "case_attach",
            flavor,
            version,
            request,
            response,
        ));
    }

    // case_update_status: close with the latest known version.
    let close_version = attached.version.clone();
    let close_request = json!({
        "cases": [{"id": case_id, "version": close_version, "status": "closed"}],
    });
    let close_response = t
        .patch(elasticctl_api::cases::CASES_PATH, &close_request)
        .await?;
    let closed_array = close_response.as_array().ok_or_else(|| {
        recording_error("decoding case_update_status response: expected an array")
    })?;
    let closed_first = closed_array
        .first()
        .ok_or_else(|| recording_error("case_update_status response array is empty"))?;
    let closed = elasticctl_api::cases::decode_case(closed_first).map_err(|error| {
        recording_error(format!(
            "decoding case_update_status response: {}",
            error.message
        ))
    })?;
    if closed.status != "closed" {
        return Err(recording_error(format!(
            "case_update_status did not close the case (status: {})",
            closed.status
        )));
    }
    register_case_extras(closed_first, &mut case_map, &mut next_comment);
    {
        let mut request = close_request;
        let mut response = close_response;
        scrub_alert_timestamps(&mut response);
        strip_volatile(&mut response, CASE_DURATION_VOLATILE_FIELDS);
        scrub_placeholder_values(&mut request, &case_map);
        scrub_placeholder_values(&mut response, &case_map);
        scrub_placeholder_values(&mut response, &probe.uid_map);
        recording.fixtures.push(exchange_fixture(
            "case_update_status",
            flavor,
            version,
            request,
            response,
        ));
    }

    // case_conflict: reuse the now-stale pre-close version, attempting
    // `open`. This measures the optimistic-concurrency contract (triage
    // spec section 10): a stale version must answer 409.
    let conflict_request = json!({
        "cases": [{"id": case_id, "version": close_version, "status": "open"}],
    });
    match t
        .patch(elasticctl_api::cases::CASES_PATH, &conflict_request)
        .await
    {
        Err(error) if error.kind == elasticctl_core::ErrorKind::Conflict => {
            let mut sanitized = error;
            for (real, placeholder) in &case_map {
                if !real.is_empty() {
                    sanitized.message = sanitized
                        .message
                        .replace(real.as_str(), placeholder.as_str());
                }
            }
            recording
                .fixtures
                .push(error_fixture("case_conflict", flavor, version, sanitized));
        }
        Err(error) => {
            return Err(recording_error(format!(
                "case_conflict: stale-version PATCH failed with an unexpected error \
                 (kind={:?}, status={:?}) instead of 409 — this is a discovery about the \
                 optimistic-concurrency contract, not a transient failure: {}",
                error.kind, error.http_status, error.message
            )));
        }
        Ok(response) => {
            return Err(recording_error(format!(
                "case_conflict: stale-version PATCH SUCCEEDED instead of 409 (response: \
                 {response}) — the API does not enforce optimistic concurrency the way the \
                 spec documents. Update the spec and `apply_status`'s remediation text before \
                 recording further flavors."
            )));
        }
    }

    // case_delete
    let delete_ids = vec![case_id.clone()];
    let delete_url = elasticctl_api::cases::delete_path(&delete_ids)?;
    let delete_response = t.delete(&delete_url).await?;
    {
        let mut request = json!({"ids": delete_ids, "path": delete_url});
        let mut response = delete_response;
        scrub_placeholder_values(&mut request, &case_map);
        scrub_placeholder_values(&mut response, &case_map);
        recording.fixtures.push(exchange_fixture(
            "case_delete",
            flavor,
            version,
            request,
            response,
        ));
    }

    match t.get(&elasticctl_api::cases::case_path(&case_id)).await {
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => {}
        Ok(_) => return Err(recording_error("case still exists after case_delete")),
        Err(error) => {
            return Err(recording_error(format!(
                "verifying case deleted: {}",
                error.message
            )));
        }
    }
    require_no_marker_cases(t).await?;
    session.ownership.case = false;

    Ok(())
}

async fn record_session(session: &mut RecordingSession<'_>) -> elasticctl_core::Result<Recording> {
    let responded = session.transport.get_with_headers("/api/status").await?;
    let mut status = responded.body.clone();
    // The `metrics` object is a runtime snapshot (load, memory, uptime, cpu,
    // `last_updated`) that changes on every poll, so a re-record is not
    // byte-identical. Drop it (spec §8); flavor and version come from the
    // stable `version` object.
    strip_volatile(&mut status, &["metrics"]);
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

    let mut authenticate = t.get_absolute_es("/_security/_authenticate").await?;
    redact_authenticate_metadata(&mut authenticate);
    recording.fixtures.push(response_fixture(
        "authenticate",
        &flavor,
        &version,
        authenticate,
        None,
    ));
    recording.fixtures.push(response_fixture(
        "spaces",
        &flavor,
        &version,
        t.get("/api/spaces/space").await?,
        None,
    ));
    if let Ok(mut license) = t.get_absolute_es("/_license").await {
        strip_volatile(&mut license, LICENSE_VOLATILE_FIELDS);
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
    recording.fixtures.push(rule_fixture(
        "exception_list_create",
        &flavor,
        &version,
        list,
    ));
    let item = create_marked_item(session).await?;
    recording.fixtures.push(rule_fixture(
        "exception_item_create",
        &flavor,
        &version,
        item,
    ));
    let (rule_body, rule) = create_marked_rule(session, &list_server_id).await?;
    recording
        .fixtures
        .push(rule_fixture("rules_create", &flavor, &version, rule));

    let list_filter = format!("exception-list.attributes.list_id: \"{LIST_ID}\"");
    let lists_find = t
        .get(&format!(
            "/api/exception_lists/_find?page=1&per_page=2&namespace_type={NAMESPACE_TYPE}&filter={}",
            urlencode(&list_filter)
        ))
        .await?;
    recording.fixtures.push(rule_exchange_fixture(
        "exception_lists_find",
        &flavor,
        &version,
        json!({"filter": list_filter}),
        lists_find,
    ));
    recording.fixtures.push(rule_fixture(
        "exception_list_get",
        &flavor,
        &version,
        t.get(&format!(
            "/api/exception_lists?list_id={}&namespace_type={NAMESPACE_TYPE}",
            urlencode(LIST_ID)
        ))
        .await?,
    ));
    recording.fixtures.push(rule_fixture(
        "exception_list_items_find",
        &flavor,
        &version,
        t.get(&format!(
            "/api/exception_lists/items/_find?list_id={}&namespace_type={NAMESPACE_TYPE}&page=1&per_page=2",
            urlencode(LIST_ID)
        ))
        .await?,
    ));

    let rule_filter = format!("alert.attributes.params.ruleId: \"{RULE_ID}\"");
    let rules_find = t
        .get(&format!(
            "/api/detection_engine/rules/_find?page=1&per_page=2&filter={}",
            urlencode(&rule_filter)
        ))
        .await?;
    recording
        .fixtures
        .push(rule_fixture("rules_find", &flavor, &version, rules_find));
    let name_filter = "alert.attributes.name: \"elasticctl fixture probe\"";
    recording.fixtures.push(rule_exchange_fixture(
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
        recording.fixtures.push(rule_exchange_fixture(
            name,
            &flavor,
            &version,
            json!({"filter": source_filter}),
            response,
        ));
    }

    recording.fixtures.push(rule_fixture(
        "rules_get",
        &flavor,
        &version,
        t.get(&format!("/api/detection_engine/rules?rule_id={RULE_ID}"))
            .await?,
    ));
    recording.fixtures.push(rule_fixture(
        "rules_patch",
        &flavor,
        &version,
        t.patch(
            "/api/detection_engine/rules",
            &json!({"rule_id": RULE_ID, "enabled": true}),
        )
        .await?,
    ));
    recording.fixtures.push(rule_fixture(
        "rules_bulk_disable",
        &flavor,
        &version,
        t.post(
            "/api/detection_engine/rules/_bulk_action",
            Some(&json!({"action": "disable", "query": rule_filter})),
        )
        .await?,
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
    recording.fixtures.push(preview_fixture(
        "rules_preview",
        &flavor,
        &version,
        t.post("/api/detection_engine/rules/preview", Some(&preview_body))
            .await?,
    ));
    let space = std::env::var("ELASTICCTL_SPACE").unwrap_or_else(|_| "default".into());
    let preview_hits = record_preview_hits(session, &space).await?;
    recording.fixtures.push(preview_exchange_fixture(
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
    recording.fixtures.push(rule_exchange_fixture(
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
    recording.fixtures.push(rule_exchange_fixture(
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

    record_search(session, &mut recording, &flavor, &version).await?;
    let probe = record_alerts_probe(session, &mut recording, &flavor, &version).await?;
    record_cases(session, &mut recording, &flavor, &version, &probe).await?;
    close_and_clean_alerts(
        session.transport,
        &mut recording,
        &flavor,
        &version,
        &probe.id_map,
    )
    .await?;

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
                recording
                    .fixtures
                    .push(rule_fixture("rules_delete", &flavor, &version, rule));
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
    fn civil_from_days_matches_known_epoch_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
        assert_eq!(civil_from_days(1_700_000_000 / 86_400), (2023, 11, 14));
        assert_eq!(civil_from_days(1_893_456_000 / 86_400), (2030, 1, 1));
    }

    #[test]
    fn now_rfc3339_is_well_formed_and_close_to_the_wall_clock() {
        let formatted = now_rfc3339();
        assert_eq!(formatted.len(), "2026-09-01T12:34:56.789Z".len());
        assert!(formatted.starts_with("20"), "{formatted}");
        assert!(formatted.ends_with('Z'), "{formatted}");
        let parsed: Value = json!(formatted);
        assert!(parsed.is_string());
    }

    #[test]
    fn scrub_placeholder_values_rewrites_substring_matches_too() {
        // The regression this guards: Kibana embeds the real alert uuid
        // inside a longer string (`kibana.alert.url`'s
        // `.../redirect/<uuid>?...`); a whole-string-only match misses it
        // entirely.
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

    #[test]
    fn owns_alert_rule_checks_id_and_marker_tag() {
        assert!(owns_alert_rule(&json!({
            "rule_id": ALERT_RULE_ID,
            "tags": [ALERT_MARKER_TAG]
        })));
        assert!(!owns_alert_rule(
            &json!({"rule_id": ALERT_RULE_ID, "tags": []})
        ));
        assert!(!owns_alert_rule(
            &json!({"rule_id": "other", "tags": [ALERT_MARKER_TAG]})
        ));
    }

    #[test]
    fn owns_alert_index_checks_the_marker_field() {
        assert!(owns_alert_index(
            &json!({"_source": {"marker": ALERT_MARKER_TAG}})
        ));
        assert!(!owns_alert_index(&json!({"_source": {"marker": "other"}})));
    }
}
