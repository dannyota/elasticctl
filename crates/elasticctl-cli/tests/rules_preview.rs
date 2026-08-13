use assert_cmd::Command;
use serde_json::json;
use std::fs;
use wiremock::matchers::{body_partial_json, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config_for(dir: &std::path::Path, uri: &str) -> std::path::PathBuf {
    let p = dir.join("config.toml");
    fs::write(&p, format!(
        "current = \"default\"\n\n[profiles.default]\nkibana_url = \"{uri}\"\napi_key = \"essu_t\"\nspace = \"default\"\nverify = true\ntimeout_secs = 5\n"
    )).unwrap();
    p
}

async fn previewing_server(logs: serde_json::Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/preview"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"previewId": "pv-1", "logs": logs})),
        )
        .mount(&server)
        .await;
    server
}

/// Serves a preview search with `total` hits and `returned` documents.
async fn mount_preview_search(server: &MockServer, total: u64, returned: usize) {
    let hits: Vec<serde_json::Value> = (0..returned)
        .map(|i| {
            json!({
                "_id": format!("alert-{i}"),
                "_source": {
                    "@timestamp": "2026-08-13T00:00:00.000Z",
                    "process": {"name": "sample.exe"},
                    "kibana.alert.rule.uuid": "pv-1"
                }
            })
        })
        .collect();
    Mock::given(method("POST"))
        .and(path_regex(r"^/\.preview\..*/_search$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": total, "relation": "eq"}, "hits": hits}
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn preview_of_a_local_file_reports_the_preview_id() {
    let server = previewing_server(json!([{"errors": [], "warnings": []}])).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("r.yaml");
    fs::write(
        &src,
        "- rule_id: abc\n  name: A\n  type: query\n  query: '*:*'\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "preview", "--json", "--config"])
        .arg(&cfg)
        .arg(src.to_str().unwrap())
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["preview_id"], "pv-1");
    assert_eq!(v["errors"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn warnings_from_every_log_entry_are_collected() {
    let server = previewing_server(json!([
        {"errors": [], "warnings": ["Unable to find matching indices for logs-*"]},
        {"errors": [], "warnings": ["second warning"]}
    ]))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("r.yaml");
    fs::write(
        &src,
        "- rule_id: abc\n  name: A\n  type: query\n  query: '*:*'\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "preview", "--json", "--config"])
        .arg(&cfg)
        .arg(src.to_str().unwrap())
        .output()
        .unwrap();

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let warnings = v["warnings"].as_array().unwrap();
    assert_eq!(
        warnings.len(),
        2,
        "warnings from every invocation must surface"
    );
}

#[tokio::test]
async fn errors_are_reported_without_failing_the_command() {
    // A rule error is a finding, not a CLI failure.
    let server = previewing_server(json!([{"errors": ["bad query syntax"], "warnings": []}])).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("r.yaml");
    fs::write(
        &src,
        "- rule_id: abc\n  name: A\n  type: query\n  query: '*:*'\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "preview", "--json", "--config"])
        .arg(&cfg)
        .arg(src.to_str().unwrap())
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "a rule error is a result, not a CLI failure"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["errors"][0], "bad query syntax");
}

/// A selector that is not a local path must resolve through the stack. The
/// fetched rule, not a placeholder, must reach the preview endpoint.
#[tokio::test]
async fn preview_of_a_rule_id_resolves_it_from_the_stack() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rule_id": "abc",
            "name": "Stack Rule",
            "type": "query",
            "language": "kuery",
            "query": "process.name:cmd.exe"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/preview"))
        // Preview must receive the fetched rule's content.
        .and(body_partial_json(
            json!({"name": "Stack Rule", "query": "process.name:cmd.exe"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "previewId": "pv-stack",
            "logs": [{"errors": [], "warnings": []}]
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());

    // This nonexistent path must use stack resolution.
    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "preview", "abc", "--json", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["preview_id"], "pv-stack");
    assert_eq!(
        v["rule"], "Stack Rule",
        "the reported rule must be the one fetched from the stack: {v}"
    );
}

/// An existing file with no rules must fail with an error naming its path.
#[tokio::test]
async fn a_file_with_no_rules_fails_with_a_message_naming_the_path() {
    let dir = tempfile::tempdir().unwrap();
    // The empty file must fail before any network call.
    let cfg = config_for(dir.path(), "http://127.0.0.1:1");
    let src = dir.path().join("empty.yaml");
    fs::write(&src, "[]\n").unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "preview", "--json", "--config"])
        .arg(&cfg)
        .arg(src.to_str().unwrap())
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value =
        serde_json::from_slice(&out.stderr).expect("error envelope on stderr");
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains(src.to_str().unwrap()) || msg.contains("empty.yaml"),
        "error must name the path: {msg}"
    );
    assert!(msg.contains("no rules"), "{msg}");
}

#[tokio::test]
async fn preview_never_prints_a_dry_run_banner() {
    // Preview writes no alerts, so it must not be guarded.
    let server = previewing_server(json!([{"errors": [], "warnings": []}])).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("r.yaml");
    fs::write(
        &src,
        "- rule_id: abc\n  name: A\n  type: query\n  query: '*:*'\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "preview", "--config"])
        .arg(&cfg)
        .arg(src.to_str().unwrap())
        .output()
        .unwrap();

    assert!(!String::from_utf8_lossy(&out.stderr).contains("DRY RUN"));
}

/// The command must report the alert hit count, including when no documents
/// are returned.
#[tokio::test]
async fn preview_reports_the_hit_count() {
    let server = previewing_server(json!([{"errors": [], "warnings": []}])).await;
    mount_preview_search(&server, 4, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("r.yaml");
    fs::write(
        &src,
        "- rule_id: abc\n  name: A\n  type: query\n  query: '*:*'\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "preview", "--json", "--config"])
        .arg(&cfg)
        .arg(src.to_str().unwrap())
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["hits"], 4);
    assert_eq!(v["hits_error"], serde_json::Value::Null);
    assert_eq!(
        v["sample"].as_array().unwrap().len(),
        0,
        "no --sample asked"
    );
}

#[tokio::test]
async fn sample_returns_the_matched_documents() {
    let server = previewing_server(json!([{"errors": [], "warnings": []}])).await;
    mount_preview_search(&server, 4, 2).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("r.yaml");
    fs::write(
        &src,
        "- rule_id: abc\n  name: A\n  type: query\n  query: '*:*'\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "preview", "--sample", "2", "--json", "--config"])
        .arg(&cfg)
        .arg(src.to_str().unwrap())
        .output()
        .unwrap();

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["hits"], 4);
    let sample = v["sample"].as_array().unwrap();
    assert_eq!(sample.len(), 2);
    assert_eq!(sample[0]["_source"]["process"]["name"], "sample.exe");
}

/// An unreadable preview index must not fail the run. The preview id, errors,
/// and warnings still show whether the rule executed.
#[tokio::test]
async fn an_unreadable_preview_index_degrades_instead_of_failing() {
    let server = previewing_server(json!([{"errors": [], "warnings": ["w"]}])).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/\.preview\..*/_search$"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "no access"})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config_for(dir.path(), &server.uri());
    let src = dir.path().join("r.yaml");
    fs::write(
        &src,
        "- rule_id: abc\n  name: A\n  type: query\n  query: '*:*'\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "preview", "--json", "--config"])
        .arg(&cfg)
        .arg(src.to_str().unwrap())
        .output()
        .unwrap();

    assert!(out.status.success(), "a lost count is not a failed preview");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["hits"], serde_json::Value::Null);
    assert_eq!(v["hits_error"], "no access");
    assert_eq!(v["preview_id"], "pv-1");
    assert_eq!(v["warnings"][0], "w");
}

#[tokio::test]
async fn a_sample_beyond_the_cap_is_refused_before_anything_is_sent() {
    let dir = tempfile::tempdir().unwrap();
    // The sample limit must fail before contacting this unreachable host.
    let cfg = config_for(dir.path(), "http://127.0.0.1:1");
    let src = dir.path().join("r.yaml");
    fs::write(
        &src,
        "- rule_id: abc\n  name: A\n  type: query\n  query: '*:*'\n",
    )
    .unwrap();

    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "preview", "--sample", "500", "--json", "--config"])
        .arg(&cfg)
        .arg(src.to_str().unwrap())
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert!(
        v["error"]["message"].as_str().unwrap().contains("100"),
        "{v}"
    );
}
