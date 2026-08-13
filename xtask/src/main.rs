//! Fixture recorder: drive a live stack and write scrubbed exchanges.
//!
//! Fixtures capture what Elastic sent. Hand-written mocks capture assumptions,
//! which is where API bugs hide.

use elasticctl_core::urlencode;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Replace credentials and operator identity before writing a fixture. Recorded
/// fixtures are committed to a public repository.
///
/// Scrub identity fields (`username`, `full_name`, `email`, `created_by`, and
/// `updated_by`) to preserve response *shape* without archiving the recorder.
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
        || matches!(
            leaf,
            "authorization"
                | "password"
                | "encoded"
                | "username"
                | "full_name"
                | "email"
                | "created_by"
                | "updated_by"
        )
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
    .filter_map(|u| {
        let rest = u.split("://").nth(1).unwrap_or(&u).to_string();
        let host = rest.split(['/', '?', '#']).next().unwrap_or("").to_string();
        (!host.is_empty()).then_some(host)
    })
    .collect()
}

/// Replace the recording stack's hostname wherever it appears in a value.
///
/// `is_sensitive` checks keys, but an alert document stores the project URL in
/// `kibana.alert.url`, where identity is in the *value*. Sweep every recorded
/// string and keep the path so the document shape remains intact.
fn scrub_hosts(v: &mut Value, hosts: &[String]) {
    match v {
        Value::String(s) => {
            for h in hosts {
                if s.contains(h.as_str()) {
                    *s = s.replace(h.as_str(), "REDACTED.example.invalid");
                }
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
fn scrub_ndjson(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut v: Value = serde_json::from_str(line).expect("export line is JSON");
        scrub(&mut v);
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
        _ => {
            eprintln!("usage: cargo xtask [record|seed]");
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
    let profile = elasticctl_core::Profile {
        kibana_url: std::env::var("ELASTICCTL_KIBANA_URL").expect("ELASTICCTL_KIBANA_URL"),
        es_url: std::env::var("ELASTICCTL_ES_URL").ok(),
        api_key: Some(std::env::var("ELASTICCTL_API_KEY").expect("ELASTICCTL_API_KEY")),
        username: None,
        password: None,
        space: std::env::var("ELASTICCTL_SPACE").unwrap_or_else(|_| "default".into()),
        verify: true,
        timeout_secs,
    };
    elasticctl_core::Transport::new(&profile).expect("transport")
}

fn write_fixture(dir: &PathBuf, name: &str, flavor: &str, version: &str, body: Value) {
    write_fixture_inner(dir, name, flavor, version, body, None)
}

/// Like `write_fixture`, but also record which response headers were present.
///
/// Only the status fixture needs headers. Deployment flavor is not derivable
/// from the response body, and the Hosted/self-managed header is required to
/// test detection offline.
///
/// Redact header *values* instead of recording them. `x-found-handling-cluster`
/// carries the deployment's cluster ID, while detection reads only presence.
fn write_fixture_with_headers(
    dir: &PathBuf,
    name: &str,
    flavor: &str,
    version: &str,
    body: Value,
    headers: &BTreeMap<String, String>,
) {
    let redacted: BTreeMap<&str, &str> = headers.keys().map(|k| (k.as_str(), "REDACTED")).collect();
    write_fixture_inner(dir, name, flavor, version, body, Some(json!(redacted)))
}

fn write_fixture_inner(
    dir: &PathBuf,
    name: &str,
    flavor: &str,
    version: &str,
    mut body: Value,
    headers: Option<Value>,
) {
    scrub(&mut body);
    scrub_hosts(&mut body, &recording_hosts());
    let mut doc =
        json!({"flavor": flavor, "version": version, "operation": name, "response": body});
    if let Some(h) = headers {
        doc["headers"] = h;
    }
    std::fs::create_dir_all(dir).expect("create fixture dir");
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_string_pretty(&doc).expect("encode"))
        .expect("write fixture");
    println!("wrote {}", path.display());
}

/// Like `write_fixture`, but also records the request.
///
/// A response alone cannot prove which index and field were queried: an empty
/// result and a wrong field name look identical.
fn write_exchange(
    dir: &PathBuf,
    name: &str,
    flavor: &str,
    version: &str,
    mut request: Value,
    mut body: Value,
) {
    scrub(&mut body);
    let hosts = recording_hosts();
    // Sweep the request too: it contains the index, query, and possibly an
    // absolute ES URL with the recording host.
    scrub_hosts(&mut request, &hosts);
    scrub_hosts(&mut body, &hosts);
    let doc = json!({
        "flavor": flavor,
        "version": version,
        "operation": name,
        "request": request,
        "response": body,
    });
    std::fs::create_dir_all(dir).expect("create fixture dir");
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_string_pretty(&doc).expect("encode"))
        .expect("write fixture");
    println!("wrote {}", path.display());
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
async fn record_preview_hits(
    t: &elasticctl_core::Transport,
    space: &str,
) -> elasticctl_core::Result<PreviewHitsExchange> {
    // The probe rule must match this document.
    let doc = json!({
        "@timestamp": PREVIEW_DOC_TIMESTAMP,
        "event": {"category": ["process"], "type": ["start"], "code": "1"},
        "process": {
            "name": "elasticctl-sample.exe",
            "executable": "C:\\elasticctl-sample\\elasticctl-sample.exe",
            "command_line": "elasticctl-sample.exe --fixture"
        },
        "host": {"name": "elasticctl-sample-host"}
    });
    t.post_absolute_es(
        &format!("/{PREVIEW_PROBE_INDEX}/_doc?refresh=wait_for"),
        &doc,
    )
    .await?;

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
        "tags": ["elasticctl", "fixture"],
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
    println!("preview id: {preview_id}");

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

    let search = |body: Value| {
        let index = index.clone();
        async move {
            t.post_absolute_es(&format!("/{index}/_search?ignore_unavailable=true"), &body)
                .await
        }
    };

    let hits_of = |v: &Value| v["hits"]["total"]["value"].as_u64().unwrap_or(0);

    // Try immediately, then after Elasticsearch's default one-second refresh
    // interval. Record which attempt first sees the alerts.
    let mut response = search(by_uuid.clone()).await?;
    let mut uuid_attempts = 1;
    if hits_of(&response) == 0 {
        // The recorder performs one operation at a time.
        std::thread::sleep(std::time::Duration::from_millis(1000));
        response = search(by_uuid.clone()).await?;
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

    // The UUID field is a guess. Fall back to this run's unique probe name and
    // record the response so the actual field is discoverable.
    println!("no hits by kibana.alert.rule.uuid; retrying by rule name");
    let by_name = json!({
        "size": 3,
        "track_total_hits": true,
        "query": {"match_phrase": {"kibana.alert.rule.name": probe_name}}
    });
    let fallback = search(by_name.clone()).await?;
    if hits_of(&fallback) > 0 {
        return Ok(PreviewHitsExchange {
            request: json!({
                "index": index,
                "body": by_name,
                "matched_by": "kibana.alert.rule.name",
                // This fallback follows the UUID retries, so its attempt count
                // starts at one for this query.
                "attempts_until_hits": 1,
            }),
            response: fallback,
        });
    }

    Err(elasticctl_core::Error::new(
        elasticctl_core::ErrorKind::Error,
        format!(
            "no preview alerts found in {index}: kibana.alert.rule.uuid \
             ({uuid_attempts} search(es)) and kibana.alert.rule.name (1 search) \
             both returned zero hits"
        ),
    ))
}

async fn record() {
    let t = transport_from_env(60);

    let responded = t.get_with_headers("/api/status").await.expect("status");
    let status = responded.body.clone();
    let version = status["version"]["number"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    // Elastic Cloud Hosted reports `build_flavor: "traditional"`, like a
    // self-managed stack. Recording ECH without `ELASTICCTL_FIXTURE_FLAVOR`
    // would overwrite the self-managed fixture set, so pass the deployment
    // flavor explicitly.
    let flavor = std::env::var("ELASTICCTL_FIXTURE_FLAVOR").unwrap_or_else(|_| {
        status["version"]["build_flavor"]
            .as_str()
            .unwrap_or("default")
            .to_string()
    });
    // Anchor on the manifest directory, not the process CWD. Running `cargo
    // xtask record` from `lab/` must not write to `lab/tests/fixtures`.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests/fixtures")
        .join(format!("{flavor}-{version}"));

    write_fixture_with_headers(
        &dir,
        "status",
        &flavor,
        &version,
        status,
        &responded.headers,
    );

    let auth = t
        .get_absolute_es("/_security/_authenticate")
        .await
        .expect("authenticate");
    write_fixture(&dir, "authenticate", &flavor, &version, auth);

    // `info` returned a hardcoded null license tier and no space list. Record
    // both values from their source endpoints.
    let spaces = t.get("/api/spaces/space").await.expect("spaces");
    write_fixture(&dir, "spaces", &flavor, &version, spaces);

    // The license endpoint does not exist on Serverless, so this call is
    // expected to fail there. Record it only on success and report either
    // result.
    match t.get_absolute_es("/_license").await {
        Ok(license) => write_fixture(&dir, "license", &flavor, &version, license),
        Err(e) => println!(
            "no license endpoint on this stack ({}): {}",
            flavor, e.message
        ),
    }

    // Use a distinctive ID so failed cleanup is visible in the UI.
    let rule_id = "elasticctl-fixture-probe";
    let body = json!({
        "rule_id": rule_id, "name": "elasticctl fixture probe",
        "description": "Recorded by cargo xtask record. Safe to delete.",
        "type": "query", "language": "kuery", "query": "*:*", "index": ["logs-*"],
        "severity": "low", "risk_score": 21, "enabled": false,
        "from": "now-6m", "interval": "5m", "tags": ["elasticctl", "fixture"]
    });

    let created = t
        .post("/api/detection_engine/rules", Some(&body))
        .await
        .expect("create");
    write_fixture(&dir, "rules_create", &flavor, &version, created);

    // Find after create and scope the query to the probe rule. An unscoped find
    // would write every custom rule's query, index, and actions to the public
    // repository; `scrub` cannot remove content stored in values.
    let find = t
        .get(&format!(
            "/api/detection_engine/rules/_find?page=1&per_page=2&filter={}",
            urlencode(&format!("alert.attributes.params.ruleId: \"{rule_id}\""))
        ))
        .await
        .expect("find");
    write_fixture(&dir, "rules_find", &flavor, &version, find);

    // Scope by the probe rule's name. This is the filter path
    // `resolve::to_rule_id` uses instead of walking the corpus, so record it as
    // a fact rather than an assumption.
    let name_filter = "alert.attributes.name: \"elasticctl fixture probe\"";
    let find_by_name = t
        .get(&format!(
            "/api/detection_engine/rules/_find?page=1&per_page=2&filter={}",
            urlencode(name_filter)
        ))
        .await
        .expect("find by name");
    write_exchange(
        &dir,
        "rules_find_by_name",
        &flavor,
        &version,
        json!({"filter": name_filter}),
        find_by_name,
    );

    let got = t
        .get(&format!("/api/detection_engine/rules?rule_id={rule_id}"))
        .await
        .expect("get");
    write_fixture(&dir, "rules_get", &flavor, &version, got);

    let patched = t
        .patch(
            "/api/detection_engine/rules",
            &json!({"rule_id": rule_id, "enabled": true}),
        )
        .await
        .expect("patch");
    write_fixture(&dir, "rules_patch", &flavor, &version, patched);

    let bulk = t
        .post(
            "/api/detection_engine/rules/_bulk_action",
            Some(&json!({
                "action": "disable",
                "query": format!("alert.attributes.params.ruleId: \"{rule_id}\"")
            })),
        )
        .await
        .expect("bulk");
    write_fixture(&dir, "rules_bulk_disable", &flavor, &version, bulk);

    let preview_body = {
        let mut b = body.as_object().unwrap().clone();
        b.remove("rule_id");
        b.insert("invocationCount".into(), json!(1));
        b.insert("timeframeEnd".into(), json!("2026-08-12T18:00:00.000Z"));
        Value::Object(b)
    };
    let preview = t
        .post("/api/detection_engine/rules/preview", Some(&preview_body))
        .await
        .expect("preview");
    write_fixture(&dir, "rules_preview", &flavor, &version, preview);

    let space = std::env::var("ELASTICCTL_SPACE").unwrap_or_else(|_| "default".into());
    let hits = record_preview_hits(&t, &space).await;

    // Drop the scratch index on every path so recording leaves the stack
    // unchanged.
    let cleanup = t
        .delete_absolute_es(&format!("/{PREVIEW_PROBE_INDEX}"))
        .await;
    if let Err(e) = &cleanup {
        println!(
            "WARNING: could not delete {PREVIEW_PROBE_INDEX}: {}",
            e.message
        );
    }

    // Export before deleting the rule so the fixture contains a real rule line.
    // Scope the export to the probe rule: a fixture samples traffic; it is not
    // an archive of every rule, including Elastic's prebuilt content.
    let export = t
        .post_text(
            "/api/detection_engine/rules/_export",
            Some(&json!({"objects": [{"rule_id": rule_id}]})),
        )
        .await;

    // Delete the probe rule on every path before returning an export or
    // preview-hit error. A failed recording must not strand it on a live
    // project.
    let deleted = t
        .delete(&format!("/api/detection_engine/rules?rule_id={rule_id}"))
        .await;
    if let Err(e) = &deleted {
        println!(
            "WARNING: could not delete probe rule {rule_id}: {}",
            e.message
        );
    }

    // Both cleanups have run; now surface any failure.
    let exchange = hits.expect("record preview hits");

    let export = export.expect("export");
    let (_, _summary) = elasticctl_api::codec::decode_ndjson(&export).expect("decode export");
    write_fixture(
        &dir,
        "rules_export",
        &flavor,
        &version,
        json!({"ndjson": scrub_ndjson(&export)}),
    );

    let deleted = deleted.expect("delete");
    write_fixture(&dir, "rules_delete", &flavor, &version, deleted);

    write_exchange(
        &dir,
        "rules_preview_hits",
        &flavor,
        &version,
        exchange.request,
        exchange.response,
    );

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
mod tests {
    use super::*;

    #[test]
    fn dotted_identity_keys_are_scrubbed() {
        let mut v = json!({
            "kibana.alert.rule.created_by": "someone",
            "kibana.alert.rule.name": "keep me",
            "nested": {"updated_by": "someone else"}
        });
        scrub(&mut v);
        assert_eq!(v["kibana.alert.rule.created_by"], "REDACTED");
        assert_eq!(v["nested"]["updated_by"], "REDACTED");
        assert_eq!(v["kibana.alert.rule.name"], "keep me");
    }
}
