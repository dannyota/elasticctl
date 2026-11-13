use assert_cmd::Command;
use serde_json::{Value, json};
use std::{fs, path::Path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};
mod common;

fn fixture(name: &str) -> Value {
    let set = if name.starts_with("esql_async_") {
        "serverless-9.7.0"
    } else {
        "traditional-9.5.1"
    };
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(set)
        .join(format!("{name}.json"));
    serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap()["response"].clone()
}

async fn server(state: bool, reopen_case: bool) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(|_: &Request| true)
        .respond_with(move |r: &Request| {
            let p = r.url.path();
            let name = match (r.method.as_str(), p) {
                ("GET", "/api/status") => "status",
                ("GET", "/api/spaces/space") => "spaces",
                ("GET", "/_license") => "license",
                ("GET", "/_security/_authenticate") => "authenticate",
                ("GET", "/api/lists/index") => {
                    return ResponseTemplate::new(200)
                        .set_body_json(json!({"list_index": true, "list_item_index": true}));
                }
                ("GET", "/api/detection_engine/rules/_find") if state => {
                    let mut rule = fixture("rules_get");
                    rule["exceptions_list"] = json!([]);
                    return ResponseTemplate::new(200).set_body_json(
                        json!({"data": [rule], "total": 1, "page": 1, "perPage": 100}),
                    );
                }
                ("PUT", "/api/detection_engine/rules") if state => {
                    let body: Value = serde_json::from_slice(&r.body).unwrap();
                    return ResponseTemplate::new(200).set_body_json(body);
                }
                ("GET", "/api/detection_engine/rules/_find") => "rules_find",
                ("GET", "/api/detection_engine/rules") => "rules_get",
                ("POST", "/api/detection_engine/rules/_bulk_action") => "rules_bulk_disable",
                ("POST", "/api/detection_engine/rules/_export") => "rules_export",
                ("GET", "/api/exception_lists/_find") => "exception_lists_find",
                ("GET", "/api/exception_lists/items/_find") => "exception_list_items_find",
                ("GET", "/api/exception_lists")
                    if r.url
                        .query_pairs()
                        .any(|(k, v)| k == "namespace_type" && v == "agnostic") =>
                {
                    return ResponseTemplate::new(404).set_body_json(
                        json!({"statusCode": 404, "message": "list absent in agnostic namespace"}),
                    );
                }
                ("GET", "/api/exception_lists") => "exception_list_get",
                ("DELETE", "/api/exception_lists") => "exception_list_get",
                ("GET", "/api/data_views") => "data_views_list",
                ("GET", "/api/data_views/default") => "data_view_default_get",
                ("POST", "/api/data_views/default") => "data_view_default_set",
                ("GET", p) if p.starts_with("/api/data_views/data_view/") => "data_view_get",
                ("GET", "/api/dashboards") => "dashboard_search",
                ("GET", p) if p.starts_with("/api/dashboards/") => "dashboard_get",
                ("DELETE", p) if p.starts_with("/api/dashboards/") => {
                    return ResponseTemplate::new(204);
                }
                ("POST", "/api/saved_objects/_export") => "dashboard_bundle_export",
                ("GET", "/api/fleet/agent_policies") => "agent_policies_list",
                (
                    "GET",
                    "/api/fleet/agent_policies/elasticctl-sample-integration-policy-parent",
                ) => "integration_policy_parent_get",
                ("GET", p) if p.starts_with("/api/fleet/agent_policies/") => "agent_policy_get",
                ("POST", "/api/fleet/agent_policies/delete") => "agent_policy_delete",
                ("GET", "/api/fleet/package_policies") => "integration_policies_list",
                ("GET", p) if p.starts_with("/api/fleet/package_policies/") => {
                    "integration_policy_get"
                }
                ("DELETE", p) if p.starts_with("/api/fleet/package_policies/") => {
                    "integration_policy_delete"
                }
                ("GET", "/api/fleet/epm/packages/system") => "package_system",
                ("GET", "/api/fleet/epm/packages/system/2.23.4") => "package_system_metadata",
                ("POST", "/api/detection_engine/signals/search") => "signals_search",
                ("POST", "/api/detection_engine/signals/status") => "signals_status_ids",
                ("GET", "/api/cases/_find") => "cases_find",
                ("GET", p) if p.starts_with("/api/cases/") && reopen_case => {
                    return ResponseTemplate::new(200)
                        .set_body_json(fixture("case_update_status")[0].clone());
                }
                ("GET", p) if p.starts_with("/api/cases/") => "case_get",
                ("PATCH", "/api/cases") => {
                    let body: Value = serde_json::from_slice(&r.body).unwrap();
                    let mut response = fixture("case_update_status");
                    response[0]["status"] = body["cases"][0]["status"].clone();
                    return ResponseTemplate::new(200).set_body_json(response);
                }
                ("POST", "/logs-*/_pit" | "/logs-%2A/_pit") => {
                    let mut response = fixture("search_pit_open");
                    response["id"] = json!("pit-1");
                    return ResponseTemplate::new(200).set_body_json(response);
                }
                ("DELETE", "/_pit") => "search_pit_close",
                ("POST", "/_query") => "esql_query",
                ("POST", "/_query/async") => "esql_async_start",
                ("GET", p) if p.starts_with("/_query/async/") => "esql_async_get",
                ("DELETE", p) if p.starts_with("/_query/async/") => "esql_async_delete",
                ("POST", p) if p.ends_with("/_search") => "search_pit_page",
                _ => {
                    return ResponseTemplate::new(404)
                        .set_body_json(json!({"statusCode": 404, "message": "unmocked route"}));
                }
            };
            let value = fixture(name);
            if let Some(text) = value
                .as_str()
                .or_else(|| value.get("ndjson").and_then(Value::as_str))
            {
                ResponseTemplate::new(200).set_body_string(text)
            } else {
                ResponseTemplate::new(200).set_body_json(value)
            }
        })
        .mount(&server)
        .await;
    server
}

async fn capture(args: &[&str]) -> Value {
    let state = args[0] == "state";
    let server = server(state, args.starts_with(&["cases", "open"])).await;
    let uri = server.uri();
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config_for(dir.path(), &uri);
    let config = fs::read_to_string(&cfg).unwrap();
    fs::write(
        &cfg,
        config.replace("api_key =", &format!("es_url = \"{uri}\"\napi_key =")),
    )
    .unwrap();
    fs::create_dir_all(dir.path().join("mirror/rules")).unwrap();
    let mut rule = fixture("rules_get");
    rule["exceptions_list"] = json!([]);
    rule["description"] = json!("Dispatch success update");
    fs::write(
        dir.path().join("mirror/rules/probe.ndjson"),
        format!("{rule}\n"),
    )
    .unwrap();
    let expanded: Vec<_> = args
        .iter()
        .map(|a| a.replace("ROOT", dir.path().to_str().unwrap()))
        .collect();
    let mut cmd = Command::cargo_bin("elasticctl").unwrap();
    for key in [
        "PROFILE",
        "CONFIG",
        "KIBANA_URL",
        "ES_URL",
        "API_KEY",
        "SPACE",
        "TIMEOUT",
    ] {
        cmd.env_remove(format!("ELASTICCTL_{key}"));
    }
    let out = cmd
        .args(["--config", cfg.to_str().unwrap(), "--profile", "default"])
        .args(&expanded)
        .output()
        .unwrap();
    let normalize = |s: &[u8]| {
        let mut text = String::from_utf8(s.to_vec()).unwrap();
        let raw = dir.path().to_str().unwrap().to_string();
        let canonical = fs::canonicalize(dir.path())
            .map(|p| p.to_str().unwrap().to_string())
            .unwrap_or_else(|_| raw.clone());
        let mut roots = vec![canonical.clone(), raw.clone()];
        for root in [&canonical, &raw] {
            roots.push(root.replace('\\', "\\\\"));
            if let Some(stripped) = root.strip_prefix(r"\\?\") {
                roots.push(stripped.to_string());
                roots.push(stripped.replace('\\', "\\\\"));
            }
        }
        roots.sort_by_key(|r| std::cmp::Reverse(r.len()));
        for root in roots.iter().filter(|r| !r.is_empty()) {
            text = text.replace(root.as_str(), "ROOT");
        }
        let mut out = String::with_capacity(text.len());
        let mut rest = text.as_str();
        while let Some(at) = rest.find("ROOT") {
            out.push_str(&rest[..at + 4]);
            rest = &rest[at + 4..];
            let end = rest
                .find(|c: char| !(c.is_alphanumeric() || "._-/\\".contains(c)))
                .unwrap_or(rest.len());
            out.push_str(&rest[..end].replace("\\\\", "/").replace('\\', "/"));
            rest = &rest[end..];
        }
        out.push_str(rest);
        out.replace(&uri, "HOST")
            .replace(uri.trim_start_matches("http://"), "HOST")
            .replace(
                concat!("\"", env!("CARGO_PKG_VERSION"), "\""),
                "\"VERSION\"",
            )
    };
    let requests: Vec<_> = server.received_requests().await.unwrap().iter().map(|r| {
        json!({"method": r.method.as_str(), "path": r.url.path(), "query": r.url.query(), "body": normalize(&r.body)})
    }).collect();
    let output = dir.path().join("out");
    if args.contains(&"--out") {
        assert!(output.is_file(), "missing output file: {args:?}, {out:?}");
        if !args.windows(2).any(|pair| pair == ["--limit", "0"]) {
            assert!(!fs::read(&output).unwrap().is_empty());
        }
        if args.starts_with(&["dashboards", "bundle", "export"]) {
            assert_eq!(
                fs::read_to_string(&output).unwrap(),
                fixture("dashboard_bundle_export")["ndjson"]
                    .as_str()
                    .unwrap()
            );
        }
    }
    let pull = dir
        .path()
        .join("pull/rules/elasticctl-fixture-probe.ndjson");
    if args.starts_with(&["state", "pull"]) {
        assert!(pull.is_file(), "missing pulled rule: {out:?}");
    }
    let result = json!({"args": args, "code": out.status.code(), "stdout": normalize(&out.stdout),
        "stderr": normalize(&out.stderr), "requests": requests,
        "out": fs::read(output).ok().map(|b| normalize(&b)),
        "pulled_rule": fs::read(pull).ok().map(|b| normalize(&b))});
    assert!(
        out.status.success(),
        "successful dispatch required: {result}"
    );
    assert!(
        !requests.is_empty(),
        "remote command sent no requests: {result}"
    );
    result
}

async fn pin(name: &str, cases: &[&[&str]]) {
    let mut results = Vec::new();
    for args in cases {
        results.push(capture(args).await);
    }
    insta::assert_json_snapshot!(name, results);
}

async fn mutation(name: &str, args: &[&str]) {
    let mut dry = args.to_vec();
    dry.push("--json");
    let dry_result = capture(&dry).await;
    for request in dry_result["requests"].as_array().unwrap() {
        let read = request["method"] == "GET"
            || request["method"] == "HEAD"
            || request["path"] == "/api/detection_engine/signals/search";
        assert!(read, "dry run sent a mutation: {dry_result}");
    }
    dry.push("--yes");
    let applied = capture(&dry).await;
    assert!(
        applied["requests"].as_array().unwrap().iter().any(|r| {
            r["method"] != "GET"
                && r["method"] != "HEAD"
                && r["path"] != "/api/detection_engine/signals/search"
        }),
        "apply sent no mutation: {applied}"
    );
    insta::assert_json_snapshot!(name, json!({"dry_run": dry_result, "apply": applied}));
}

#[tokio::test]
async fn rules_success() {
    pin(
        "rules_reads",
        &[
            &["rules", "list", "--json"],
            &["rules", "get", "elasticctl-fixture-probe", "--json"],
            &["rules", "export", "--out", "ROOT/out", "--json"],
        ],
    )
    .await;
    mutation(
        "rules_disable",
        &["rules", "disable", "elasticctl-fixture-probe"],
    )
    .await;
}

#[tokio::test]
async fn exceptions_success() {
    pin(
        "exceptions_reads",
        &[
            &["exceptions", "list", "--json"],
            &[
                "exceptions",
                "get",
                "elasticctl-sample-exceptions",
                "--json",
            ],
        ],
    )
    .await;
    mutation(
        "exceptions_delete",
        &["exceptions", "delete", "elasticctl-sample-exceptions"],
    )
    .await;
}

#[tokio::test]
async fn data_views_success() {
    pin(
        "data_views_reads",
        &[
            &["data-views", "list", "--json"],
            &[
                "data-views",
                "get",
                "elasticctl-sample-data-view-source",
                "--json",
            ],
        ],
    )
    .await;
    mutation(
        "data_views_default_set",
        &[
            "data-views",
            "default",
            "set",
            "elasticctl-sample-data-view-source",
        ],
    )
    .await;
}

#[tokio::test]
async fn dashboards_success() {
    pin(
        "dashboards_reads",
        &[
            &["dashboards", "list", "--json"],
            &["dashboards", "get", "elasticctl-sample-dashboard", "--json"],
            &[
                "dashboards",
                "bundle",
                "export",
                "elasticctl-sample-dashboard",
                "--out",
                "ROOT/out",
                "--json",
            ],
        ],
    )
    .await;
    mutation(
        "dashboards_delete",
        &["dashboards", "delete", "elasticctl-sample-dashboard"],
    )
    .await;
}

#[tokio::test]
async fn fleet_agent_policies_success() {
    pin(
        "fleet_agent_policies_reads",
        &[
            &["fleet", "agent-policies", "list", "--json"],
            &[
                "fleet",
                "agent-policies",
                "get",
                "elasticctl-sample-agent-policy",
                "--json",
            ],
        ],
    )
    .await;
    mutation(
        "fleet_agent_policies_delete",
        &[
            "fleet",
            "agent-policies",
            "delete",
            "elasticctl-sample-agent-policy",
        ],
    )
    .await;
}

#[tokio::test]
async fn fleet_integration_policies_success() {
    pin(
        "fleet_integration_policies_reads",
        &[
            &["fleet", "integration-policies", "list", "--json"],
            &[
                "fleet",
                "integration-policies",
                "get",
                "elasticctl-sample-integration-policy",
                "--json",
            ],
        ],
    )
    .await;
    mutation(
        "fleet_integration_policies_delete",
        &[
            "fleet",
            "integration-policies",
            "delete",
            "elasticctl-sample-integration-policy",
        ],
    )
    .await;
}

#[tokio::test]
async fn state_success() {
    pin(
        "state_reads",
        &[&["state", "pull", "--dir", "ROOT/pull", "--json"]],
    )
    .await;
    mutation("state_push", &["state", "push", "--dir", "ROOT/mirror"]).await;
}

#[tokio::test]
async fn search_success() {
    pin(
        "search_reads",
        &[
            &[
                "search",
                "esql",
                "FROM logs-* | WHERE seq > 1 | LIMIT 2",
                "--json",
            ],
            &[
                "search",
                "dsl",
                "{\"query\":{\"term\":{\"marker\":\"elasticctl-sample\"}}}",
                "--index",
                "logs-*",
                "--limit",
                "2",
                "--json",
            ],
        ],
    )
    .await;
}

#[tokio::test]
async fn alerts_success() {
    pin(
        "alerts_reads",
        &[
            &["alerts", "list", "--json"],
            &["alerts", "get", "elasticctl-fixture-alert-1", "--json"],
        ],
    )
    .await;
    mutation(
        "alerts_ack",
        &["alerts", "ack", "elasticctl-fixture-alert-1"],
    )
    .await;
    mutation(
        "alerts_open",
        &["alerts", "open", "elasticctl-fixture-alert-1"],
    )
    .await;
    mutation(
        "alerts_close",
        &["alerts", "close", "elasticctl-fixture-alert-1"],
    )
    .await;
}

#[tokio::test]
async fn cases_success() {
    pin(
        "cases_reads",
        &[
            &["cases", "list", "--status", "open", "--json"],
            &["cases", "get", "elasticctl-fixture-case", "--json"],
        ],
    )
    .await;
    mutation(
        "cases_close",
        &["cases", "close", "elasticctl-fixture-case"],
    )
    .await;
    mutation("cases_open", &["cases", "open", "elasticctl-fixture-case"]).await;
}

#[tokio::test]
async fn health_success() {
    pin(
        "health_reads",
        &[
            &["config", "test", "--json"],
            &["doctor", "--json"],
            &["info", "--json"],
        ],
    )
    .await;
}

#[tokio::test]
async fn list_search() {
    pin(
        "list_search",
        &[
            &[
                "fleet",
                "agent-policies",
                "list",
                "--search",
                "sample agent",
                "--json",
            ],
            &[
                "fleet",
                "agent-policies",
                "list",
                "--search",
                "SaMpLe-AgEnT",
                "--json",
            ],
            &[
                "fleet",
                "integration-policies",
                "list",
                "--search",
                "system",
                "--json",
            ],
            &[
                "fleet",
                "integration-policies",
                "list",
                "--search",
                "SaMpLe-InTeGrAtIoN",
                "--json",
            ],
            &["data-views", "list", "--search", "@timestamp", "--json"],
            &["data-views", "list", "--search", "SaMpLe SoUrCe", "--json"],
            &[
                "dashboards",
                "list",
                "--search",
                "elasticctl sample dashboard",
                "--json",
            ],
            &[
                "rules",
                "list",
                "--search",
                "elasticctl fixture probe",
                "--json",
            ],
            &[
                "exceptions",
                "list",
                "--namespace",
                "single",
                "--search",
                "elasticctl sample exceptions",
                "--json",
            ],
            &[
                "alerts",
                "list",
                "--search",
                "elasticctl sample alert probe",
                "--json",
            ],
            &[
                "cases",
                "list",
                "--search",
                "elasticctl sample case",
                "--json",
            ],
        ],
    )
    .await;
}

#[tokio::test]
async fn bulk_out() {
    pin(
        "bulk_out",
        &[
            &[
                "search",
                "dsl",
                "{\"query\":{\"term\":{\"marker\":\"elasticctl-sample\"}}}",
                "--index",
                "logs-*",
                "--limit",
                "2",
                "--out",
                "ROOT/out",
            ],
            &["alerts", "list", "--limit", "2", "--out", "ROOT/out"],
            &["cases", "list", "--out", "ROOT/out"],
            &["cases", "list", "--limit", "0", "--out", "ROOT/out"],
        ],
    )
    .await;
}

#[tokio::test]
async fn esql_out() {
    pin(
        "esql_out",
        &[
            &[
                "search",
                "esql",
                "FROM elasticctl-sample-search | SORT seq ASC | LIMIT 2",
                "--out",
                "ROOT/out",
            ],
            &[
                "search",
                "esql",
                "FROM elasticctl-sample-search | SORT seq ASC | LIMIT 2",
                "--out",
                "ROOT/out",
                "--format",
                "csv",
            ],
        ],
    )
    .await;
}
