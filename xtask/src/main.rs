//! Fixture recorder. Drives a live stack and writes scrubbed exchanges.
//!
//! Fixtures encode what Elastic actually sent. Hand-written mocks encode what
//! we assumed, which is exactly where API bugs hide.

use elasticctl_core::urlencode;
use serde_json::{Value, json};
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

fn write_fixture(dir: &PathBuf, name: &str, flavor: &str, version: &str, mut body: Value) {
    scrub(&mut body);
    let doc = json!({"flavor": flavor, "version": version, "operation": name, "response": body});
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
    request: Value,
    mut body: Value,
) {
    scrub(&mut body);
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
/// A name no other rule on the stack has, so the diagnostic fallback below
/// stays scoped to this recorder's own object.
const PREVIEW_PROBE_NAME: &str = "elasticctl fixture preview probe";
/// Fixed rather than "now": the probe document is written at a fixed instant
/// inside the window this end implies, so the recording is reproducible and
/// needs no date arithmetic.
const PREVIEW_TIMEFRAME_END: &str = "2026-08-12T18:00:00.000Z";
const PREVIEW_DOC_TIMESTAMP: &str = "2026-08-12T17:57:00.000Z";

/// Record what a preview actually wrote.
///
/// `rules/preview` returns a `previewId` and no hit count, so the count has to
/// come from the preview alerts index. Three things are unproven and this is
/// what proves them: the index name, the field carrying the preview id, and
/// whether a project-scoped key may read it. A fourth — whether the alerts are
/// visible to search the moment the preview returns — is measured by recording
/// which attempt first saw them.
///
/// Returns `Err` rather than panicking so the caller can delete the scratch
/// index on every path.
async fn record_preview_hits(
    t: &elasticctl_core::Transport,
    dir: &PathBuf,
    flavor: &str,
    version: &str,
    space: &str,
) -> elasticctl_core::Result<()> {
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

    let preview_body = json!({
        "name": PREVIEW_PROBE_NAME,
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

    // Attempt 1 immediately, attempt 2 after Elasticsearch's default
    // one-second refresh interval. Which one first sees the alerts is the
    // measurement.
    let mut response = search(by_uuid.clone()).await?;
    let mut attempts = 1;
    if response["hits"]["total"]["value"].as_u64().unwrap_or(0) == 0 {
        // Blocking sleep: the recorder does one thing at a time.
        std::thread::sleep(std::time::Duration::from_millis(1000));
        response = search(by_uuid.clone()).await?;
        attempts = 2;
    }

    let mut request = json!({
        "index": index,
        "body": by_uuid,
        "matched_by": "kibana.alert.rule.uuid",
        "attempts_until_hits": attempts,
    });

    if response["hits"]["total"]["value"].as_u64().unwrap_or(0) == 0 {
        // The uuid field is a guess. Fall back to a query scoped by this
        // probe's own unique rule name, which is still scoped to an object
        // this recorder created, and record what came back so the real field
        // is discoverable instead of merely absent.
        println!("no hits by kibana.alert.rule.uuid; retrying by rule name");
        let by_name = json!({
            "size": 3,
            "track_total_hits": true,
            "query": {"match_phrase": {"kibana.alert.rule.name": PREVIEW_PROBE_NAME}}
        });
        let fallback = search(by_name.clone()).await?;
        if fallback["hits"]["total"]["value"].as_u64().unwrap_or(0) > 0 {
            response = fallback;
            request = json!({
                "index": index,
                "body": by_name,
                "matched_by": "kibana.alert.rule.name",
                "attempts_until_hits": attempts,
            });
        }
    }

    let total = response["hits"]["total"]["value"].as_u64().unwrap_or(0);
    if total == 0 {
        println!(
            "WARNING: no preview alerts found in {index}. \
             The index name or the query field is wrong; inspect the index by hand \
             before Task 11 relies on either."
        );
    }

    write_exchange(dir, "rules_preview_hits", flavor, version, request, response);
    Ok(())
}

async fn record() {
    let t = transport_from_env(60);

    let status = t.get("/api/status").await.expect("status");
    let version = status["version"]["number"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let flavor = status["version"]["build_flavor"]
        .as_str()
        .unwrap_or("default")
        .to_string();
    // Anchor on the manifest directory, not the process CWD: `cargo xtask
    // record` run from `lab/` must not write to `lab/tests/fixtures`.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests/fixtures")
        .join(format!("{flavor}-{version}"));

    write_fixture(&dir, "status", &flavor, &version, status);

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
        Err(e) => println!("no license endpoint on this stack ({}): {}", flavor, e.message),
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
    let hits = record_preview_hits(&t, &dir, &flavor, &version, &space).await;
    // Always drop the scratch index, on every path: a recording session must
    // leave the stack exactly as it found it.
    let cleanup = t
        .delete_absolute_es(&format!("/{PREVIEW_PROBE_INDEX}"))
        .await;
    if let Err(e) = &cleanup {
        println!("WARNING: could not delete {PREVIEW_PROBE_INDEX}: {}", e.message);
    }
    hits.expect("record preview hits");

    // Export before delete, so the fixture contains a real rule line. The
    // export is scoped to the probe rule: a fixture is a representative sample
    // of real traffic, not an archive, and a full export would commit every
    // rule (including Elastic's prebuilt content) into a public repo.
    let export = t
        .post_text(
            "/api/detection_engine/rules/_export",
            Some(&json!({"objects": [{"rule_id": rule_id}]})),
        )
        .await
        .expect("export");
    let (_, _summary) = elasticctl_api::codec::decode_ndjson(&export).expect("decode export");
    write_fixture(
        &dir,
        "rules_export",
        &flavor,
        &version,
        json!({"ndjson": scrub_ndjson(&export)}),
    );

    let deleted = t
        .delete(&format!("/api/detection_engine/rules?rule_id={rule_id}"))
        .await
        .expect("delete");
    write_fixture(&dir, "rules_delete", &flavor, &version, deleted);

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
