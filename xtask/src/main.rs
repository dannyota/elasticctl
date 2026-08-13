//! Fixture recorder. Drives a live stack and writes scrubbed exchanges.
//!
//! Fixtures encode what Elastic actually sent. Hand-written mocks encode what
//! we assumed, which is exactly where API bugs hide.

use elasticctl_core::urlencode;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Anything that could carry a credential or the operator's identity is
/// replaced before a fixture is written. A recorded fixture is committed to a
/// public repository.
///
/// The identity fields (`username`, `full_name`, `email`, `created_by`,
/// `updated_by`) are scrubbed because a fixture exists to pin the response
/// *shape*, not to archive who recorded it. They are not dead code — leave
/// them in the list.
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

/// An alert document stores rule metadata under dotted keys
/// (`kibana.alert.rule.created_by`), and a whole-key comparison misses every
/// one of them. Match the last dot-separated segment as well, so a nested
/// identity field is scrubbed wherever the server chose to flatten it.
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

/// The stack this recording came from, as bare hostnames.
///
/// Read from the environment rather than threaded through, because every write
/// path needs them and the recorder only ever talks to one stack per run.
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

/// Replace the recording stack's hostname anywhere it appears in a value.
///
/// `is_sensitive` is a key allowlist, and an alert document puts the project's
/// URL under `kibana.alert.url` — a key no allowlist would think to name,
/// carrying identity in the *value*. Any recorded string can carry the host, so
/// the sweep is over values and runs on every fixture. The path is kept so the
/// document's shape still reads true; only the host that names the owner's
/// project goes.
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

/// Redact a sensitive value without changing its type: a string becomes
/// "REDACTED", a container keeps its shape with every leaf redacted, and null
/// stays null — a null `full_name`/`email` is an absence, not a secret. An
/// `api_key` can be an object in a real response, and collapsing it to a string
/// would destroy the shape the fixture exists to pin.
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
/// response as an opaque string, so `scrub`'s object walk never reaches the
/// identity fields inside it; parse each line, scrub it, and re-serialize so
/// the exported text is redacted the same way a parsed body is.
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

/// Build a transport from the environment, the same way the CLI would. The
/// caller supplies the default timeout; `ELASTICCTL_TIMEOUT` overrides it.
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

/// Like `write_fixture`, but also records which response headers were present.
///
/// Only the status fixture needs this: deployment flavor is not derivable from
/// any response body, and the header that separates Hosted from self-managed is
/// evidence a fixture has to carry or the detection path has nothing offline to
/// test against.
///
/// Header *values* are redacted, not recorded. `x-found-handling-cluster`
/// carries the deployment's cluster id, and these fixtures are public. The
/// detection reads presence, never the value, so a redacted value proves
/// exactly as much as the real one.
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

/// Like `write_fixture`, but records the request as well.
///
/// For an exchange whose whole point is *which* index and *which* field were
/// asked for, a response on its own proves nothing — an empty result and a
/// wrong field name look identical.
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
    // The request is swept too: it embeds the index and query the recorder
    // built, and an absolute ES URL would carry the host.
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

/// Scratch index the preview probe queries. Carries the `elasticctl-sample`
/// marker so a failed run is identifiable, and deliberately avoids a `logs-`
/// prefix: `logs-*-*` matches Elastic's own template, which would turn this
/// into a data stream and reject a plain document write.
const PREVIEW_PROBE_INDEX: &str = "elasticctl-sample-fixture";
/// Base of the preview probe's name. A per-run suffix is appended because
/// preview alerts are never deleted, so a constant name could be satisfied by
/// a stale alert from an earlier recording — the suffix keeps the fallback
/// scoped to this run's own alerts.
const PREVIEW_PROBE_NAME: &str = "elasticctl fixture preview probe";
/// Fixed rather than "now": the probe document is written at a fixed instant
/// inside the window this end implies, so the recording is reproducible and
/// needs no date arithmetic.
const PREVIEW_TIMEFRAME_END: &str = "2026-08-12T18:00:00.000Z";
const PREVIEW_DOC_TIMESTAMP: &str = "2026-08-12T17:57:00.000Z";

/// A per-run suffix so a re-record's fallback cannot match a previous run's
/// leftover preview alerts.
fn run_token() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().to_string())
        .unwrap_or_else(|_| std::process::id().to_string())
}

/// The request that found the hits, alongside the search response. Kept apart
/// from the fixture write so the caller runs its cleanups before anything is
/// written to disk.
struct PreviewHitsExchange {
    request: Value,
    response: Value,
}

/// Record what a preview actually wrote.
///
/// `rules/preview` returns a `previewId` and no hit count, so the count has to
/// come from the preview alerts index. Three things are unproven and this is
/// what proves them: the index name, the field carrying the preview id, and
/// whether a project-scoped key may read it. A fourth — whether the alerts are
/// visible to search the moment the preview returns — is measured by recording
/// which attempt first saw them.
///
/// Returns `Err` rather than panicking, and returns the exchange rather than
/// writing it, so the caller deletes the scratch index and the probe rule on
/// every path. A recording that finds no hits is an error, never a fixture
/// that claims a field matched when nothing did.
async fn record_preview_hits(
    t: &elasticctl_core::Transport,
    space: &str,
) -> elasticctl_core::Result<PreviewHitsExchange> {
    // One document the probe rule is certain to match.
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

    // Attempt 1 immediately, attempt 2 after Elasticsearch's default
    // one-second refresh interval. Which one first sees the alerts is the
    // measurement.
    let mut response = search(by_uuid.clone()).await?;
    let mut uuid_attempts = 1;
    if hits_of(&response) == 0 {
        // Blocking sleep: the recorder does one thing at a time.
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

    // The uuid field is a guess. Fall back to a query scoped by this probe's
    // own, run-unique rule name, which still names an object this recorder
    // created, and record what came back so the real field is discoverable
    // instead of merely absent.
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
                // The fallback runs only after the uuid retries, so this is
                // the first search of *this* query — its own attempt count,
                // not the uuid query's.
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
    // Elastic Cloud Hosted reports `build_flavor: "traditional"`, the same
    // value a self-managed stack reports, so recording ECH would overwrite the
    // self-managed fixture set. The deployment flavor is not derivable from the
    // status body and the recorder must be told it.
    let flavor = std::env::var("ELASTICCTL_FIXTURE_FLAVOR").unwrap_or_else(|_| {
        status["version"]["build_flavor"]
            .as_str()
            .unwrap_or("default")
            .to_string()
    });
    // Anchor on the manifest directory, not the process CWD: `cargo xtask
    // record` run from `lab/` must not write to `lab/tests/fixtures`.
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

    // `info` reported a hardcoded null licence tier and no space list. Both
    // have to come from somewhere; these record where.
    let spaces = t.get("/api/spaces/space").await.expect("spaces");
    write_fixture(&dir, "spaces", &flavor, &version, spaces);

    // Serverless has no licence tiers — features gate on project tier — so
    // this call is expected to fail there. Record it only where it succeeds,
    // and print what happened either way.
    match t.get_absolute_es("/_license").await {
        Ok(license) => write_fixture(&dir, "license", &flavor, &version, license),
        Err(e) => println!(
            "no license endpoint on this stack ({}): {}",
            flavor, e.message
        ),
    }

    // Use a distinctive id so a failed cleanup is obvious in the UI.
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

    // Find after create, and scoped to the probe rule. An unscoped find would
    // write every custom rule's query, index, and actions into a public repo,
    // and `scrub` cannot help: that content lives in values, not keys.
    let find = t
        .get(&format!(
            "/api/detection_engine/rules/_find?page=1&per_page=2&filter={}",
            urlencode(&format!("alert.attributes.params.ruleId: \"{rule_id}\""))
        ))
        .await
        .expect("find");
    write_fixture(&dir, "rules_find", &flavor, &version, find);

    // Scoped by the probe rule's own name. This is the filter path
    // `resolve::to_rule_id` will use instead of walking every page of the
    // corpus, so it has to be a recorded fact, not an assumption.
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

    // Always drop the scratch index, on every path: a recording session must
    // leave the stack exactly as it found it.
    let cleanup = t
        .delete_absolute_es(&format!("/{PREVIEW_PROBE_INDEX}"))
        .await;
    if let Err(e) = &cleanup {
        println!(
            "WARNING: could not delete {PREVIEW_PROBE_INDEX}: {}",
            e.message
        );
    }

    // Export before delete, so the fixture contains a real rule line. The
    // export is scoped to the probe rule: a fixture is a representative sample
    // of real traffic, not an archive, and a full export would commit every
    // rule (including Elastic's prebuilt content) into a public repo.
    let export = t
        .post_text(
            "/api/detection_engine/rules/_export",
            Some(&json!({"objects": [{"rule_id": rule_id}]})),
        )
        .await;

    // Always delete the probe rule, on every path, before surfacing the export
    // or preview-hits error: a failed recording must not strand the rule on a
    // live project.
    let deleted = t
        .delete(&format!("/api/detection_engine/rules?rule_id={rule_id}"))
        .await;
    if let Err(e) = &deleted {
        println!(
            "WARNING: could not delete probe rule {rule_id}: {}",
            e.message
        );
    }

    // Both cleanups have run; only now is it safe to surface failures.
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
    // The prepackaged install exceeds the recorder's normal 60s timeout on a
    // fresh stack; give it a default well above the install time, still
    // overridable via `ELASTICCTL_TIMEOUT`.
    let t = transport_from_env(600);
    // Installing prebuilt Elastic rules gives pull, diff, and preview real data.
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
