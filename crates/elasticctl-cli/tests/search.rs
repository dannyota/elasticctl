use assert_cmd::Command;
use serde_json::json;
use std::fs;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn bin() -> Command {
    Command::cargo_bin("elasticctl").unwrap()
}

fn write_config(dir: &std::path::Path, es_url: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    fs::write(
        &path,
        format!(
            r#"
current = "default"
[profiles.default]
kibana_url = "{es_url}"
es_url = "{es_url}"
api_key = "essu_test"
space = "default"
verify = true
timeout_secs = 5
"#
        ),
    )
    .unwrap();
    path
}

#[tokio::test]
async fn search_esql_renders_columns_as_a_table() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/_query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "columns": [{"name": "seq", "type": "long"}],
            "values": [[1], [2]],
            "is_partial": false
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["search", "esql", "FROM x | LIMIT 2"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("seq"));
    assert!(stdout.contains("1"));
}

#[tokio::test]
async fn search_esql_peek_appends_server_limit() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/_query"))
        .and(body_partial_json(json!({"query": "FROM x | LIMIT 101"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "columns": [{"name": "seq", "type": "long"}],
            "values": [[1]],
            "is_partial": false
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["search", "esql", "FROM x"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
}

#[tokio::test]
async fn search_esql_peek_appends_server_limit_from_flag() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/_query"))
        .and(body_partial_json(json!({"query": "FROM x | LIMIT 8"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "columns": [{"name": "seq", "type": "long"}],
            "values": [[1]],
            "is_partial": false
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["search", "esql", "FROM x", "--limit", "7"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
}

#[tokio::test]
async fn search_esql_peek_reports_the_client_side_cap() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    let values: Vec<Vec<serde_json::Value>> = (1..=101).map(|n| vec![json!(n)]).collect();
    Mock::given(method("POST"))
        .and(path("/_query"))
        .and(body_partial_json(json!({"query": "FROM x | LIMIT 101"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "columns": [{"name": "seq", "type": "long"}],
            "values": values,
            "is_partial": false
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["search", "esql", "FROM x"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("capped at 100 rows"), "{stderr}");
}

#[tokio::test]
async fn search_esql_peek_keeps_existing_limit_unchanged() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/_query"))
        .and(body_partial_json(json!({"query": "FROM x | LIMIT 2"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "columns": [{"name": "seq", "type": "long"}],
            "values": [[1]],
            "is_partial": false
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["search", "esql", "FROM x | LIMIT 2"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
}

#[tokio::test]
async fn search_esql_out_writes_jsonl_by_default() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    let out_path = dir.path().join("results.ndjson");

    Mock::given(method("POST"))
        .and(path("/_query/async"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "a1", "is_running": true})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/_query/async/a1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "is_running": false, "is_partial": false,
            "columns": [{"name": "seq", "type": "long"}],
            "values": [[1, 2]]
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/_query/async/a1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["search", "esql", "FROM x | LIMIT 2", "--out"])
        .arg(&out_path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = fs::read_to_string(&out_path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(
        lines.iter().all(|l| l.starts_with('{') && l.ends_with('}')),
        "{text}"
    );
    assert!(lines[0].contains("\"seq\":1"), "{text}");
}

#[tokio::test]
async fn search_esql_out_csv_renders_client_side_from_columnar_rows() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    let out_path = dir.path().join("results.csv");

    Mock::given(method("POST"))
        .and(path("/_query/async"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "a1", "is_running": true})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/_query/async/a1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "is_running": false, "is_partial": false,
            "columns": [
                {"name": "seq", "type": "long"},
                {"name": "message", "type": "text"}
            ],
            "values": [[1, 2], ["a", "b"]]
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/_query/async/a1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["search", "esql", "FROM x | LIMIT 2", "--out"])
        .arg(&out_path)
        .args(["--format", "csv"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = fs::read_to_string(&out_path).unwrap();
    assert_eq!(text, "seq,message\n1,a\n2,b\n");
}

#[tokio::test]
async fn search_esql_out_csv_truncates_to_the_limit() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    let out_path = dir.path().join("results.csv");

    Mock::given(method("POST"))
        .and(path("/_query/async"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "a1", "is_running": true})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/_query/async/a1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "is_running": false, "is_partial": false,
            "columns": [
                {"name": "seq", "type": "long"},
                {"name": "message", "type": "text"}
            ],
            "values": [[1, 2, 3], ["a", "b", "c"]]
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/_query/async/a1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["search", "esql", "FROM x", "--out"])
        .arg(&out_path)
        .args(["--format", "csv", "--limit", "2"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = fs::read_to_string(&out_path).unwrap();
    assert_eq!(text, "seq,message\n1,a\n2,b\n");
}

#[tokio::test]
async fn search_dsl_renders_sources_as_a_table() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/idx/_search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 2, "relation": "eq"}, "hits": [
                {"_index": "idx", "_id": "a", "_source": {"seq": 1}},
                {"_index": "idx", "_id": "b", "_source": {"seq": 2}}
            ]}
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args([
            "search",
            "dsl",
            "{\"query\": {\"match_all\": {}}}",
            "--index",
            "idx",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("seq"), "{stdout}");
    assert!(stdout.contains("1"), "{stdout}");
    assert!(stdout.contains("2"), "{stdout}");
}

#[tokio::test]
async fn search_dsl_with_meta_renders_hit_metadata() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/idx/_search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 2, "relation": "eq"}, "hits": [
                {"_index": "idx", "_id": "a", "_score": 1.5, "_source": {"seq": 1}},
                {"_index": "idx", "_id": "b", "_score": 2.5, "_source": {"seq": 2}}
            ]}
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args([
            "search",
            "dsl",
            "{\"query\": {\"match_all\": {}}}",
            "--index",
            "idx",
            "--with-meta",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        value,
        json!([
            {"seq": 1, "_id": "a", "_index": "idx", "_score": 1.5},
            {"seq": 2, "_id": "b", "_index": "idx", "_score": 2.5}
        ])
    );
}

#[tokio::test]
async fn search_dsl_without_meta_renders_sources_only() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    Mock::given(method("POST"))
        .and(path("/idx/_search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 2, "relation": "eq"}, "hits": [
                {"_index": "idx", "_id": "a", "_score": 1.5, "_source": {"seq": 1}},
                {"_index": "idx", "_id": "b", "_score": 2.5, "_source": {"seq": 2}}
            ]}
        })))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args([
            "search",
            "dsl",
            "{\"query\": {\"match_all\": {}}}",
            "--index",
            "idx",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value, json!([{"seq": 1}, {"seq": 2}]));
    assert!(!stdout.contains("_id"), "{stdout}");
    assert!(!stdout.contains("_index"), "{stdout}");
    assert!(!stdout.contains("_score"), "{stdout}");
}

#[tokio::test]
async fn search_dsl_out_writes_jsonl_by_default() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    let out_path = dir.path().join("results.ndjson");

    Mock::given(method("POST"))
        .and(path("/idx/_pit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "pit-1"})))
        .mount(&server)
        .await;
    // A single page whose hits carry no `sort` ends the stream after one request.
    Mock::given(method("POST"))
        .and(path("/_search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 2, "relation": "eq"}, "hits": [
                {"_source": {"seq": 1}},
                {"_source": {"seq": 2}}
            ]}
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/_pit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"succeeded": true})))
        .mount(&server)
        .await;

    let out = bin()
        .args(["--config", cfg.to_str().unwrap()])
        .args(["search", "dsl", "{\"query\": {\"match_all\": {}}}", "--out"])
        .arg(&out_path)
        .args(["--index", "idx"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = fs::read_to_string(&out_path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(
        lines.iter().all(|l| l.starts_with('{') && l.ends_with('}')),
        "{text}"
    );
    assert!(lines[0].contains("\"seq\":1"), "{text}");
}
