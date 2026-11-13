use assert_cmd::Command;
use serde_json::{Value, json};
use std::{fs, path::Path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};
mod common;

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/traditional-9.5.1")
        .join(format!("{name}.json"));
    serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap()["response"].clone()
}

async fn server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(|_: &Request| true)
        .respond_with(|r: &Request| {
            let p = r.url.path();
            let name = match (r.method.as_str(), p) {
                (_, "/api/status") => "status",
                (_, "/api/spaces/space") => "spaces",
                (_, "/_license") => "license",
                (_, "/_security/_authenticate") => "authenticate",
                (_, "/api/detection_engine/index") => "detection_engine_index",
                (_, "/api/detection_engine/rules/prepackaged/_status") => "prebuilt_status",
                (_, "/api/detection_engine/rules/prepackaged") => "prebuilt_install",
                (_, "/api/detection_engine/rules/_find") => "rules_find",
                (_, "/api/detection_engine/rules/_export") => "rules_export",
                (_, "/api/detection_engine/rules/_bulk_action") => "rules_bulk_disable",
                (_, "/api/detection_engine/rules/_import") => "rules_import_bundle",
                (_, "/api/detection_engine/rules/_preview") => "rules_preview",
                (_, "/api/detection_engine/rules") => "rules_get",
                (_, "/api/exception_lists/_find") => "exception_lists_find",
                (_, "/api/exception_lists/items/_find") => "exception_list_items_find",
                (_, "/api/exception_lists/_export") => "exception_list_export",
                (_, "/api/exception_lists/_import") => "exception_list_import",
                (_, "/api/exception_lists") => "exception_list_get",
                (_, "/api/data_views") => "data_views_list",
                (_, "/api/data_views/default") => "data_view_default_get",
                (_, "/api/data_views/data_view") => "data_view_create",
                (_, p) if p.starts_with("/api/data_views/data_view/") => "data_view_get",
                (_, "/api/dashboards") => "dashboard_search",
                (_, p) if p.starts_with("/api/dashboards/") => "dashboard_get",
                (_, "/api/saved_objects/_export") => "dashboard_bundle_export",
                (_, "/api/saved_objects/_import") => "dashboard_import",
                (_, "/api/fleet/agent_policies") => "agent_policies_list",
                (_, p) if p.starts_with("/api/fleet/agent_policies/") => "agent_policy_get",
                (_, "/api/fleet/package_policies") => "integration_policies_list",
                (_, p) if p.starts_with("/api/fleet/package_policies/") => "integration_policy_get",
                (_, "/api/detection_engine/signals/search") => "signals_search",
                (_, "/api/detection_engine/signals/status") => "signals_status_ids",
                (_, "/api/detection_engine/signals/tags") => "signals_tags",
                (_, "/api/detection_engine/signals/assignees") => "signals_assignees",
                (_, "/api/cases/_find") => "cases_find",
                ("PATCH", "/api/cases") => "case_update_status",
                ("POST", "/api/cases") => "case_create",
                (_, p) if p.ends_with("/comments") => "case_comment",
                (_, p) if p.starts_with("/api/cases/") => "case_get",
                (_, "/_query" | "/_query/async") => "esql_query",
                (_, p) if p.ends_with("/_search") => "signals_search",
                _ => return ResponseTemplate::new(404),
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

async fn capture(args: &[&str], invalid_config: bool, warning: bool) -> Value {
    let server = if invalid_config {
        None
    } else {
        Some(server().await)
    };
    let uri = server
        .as_ref()
        .map(MockServer::uri)
        .unwrap_or_else(|| "http://127.0.0.1:1".into());
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config_for(dir.path(), &uri);

    #[cfg(unix)]
    if warning {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o644)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = warning;
    let rule = fixture("rules_get");
    fs::write(dir.path().join("rule.ndjson"), format!("{rule}\n")).unwrap();
    fs::create_dir(dir.path().join("mirror")).unwrap();
    fs::create_dir(dir.path().join("mirror/rules")).unwrap();
    fs::write(
        dir.path().join("mirror/rules/probe.ndjson"),
        format!("{rule}\n"),
    )
    .unwrap();
    let expanded: Vec<_> = args
        .iter()
        .map(|a| a.replace("ROOT", dir.path().to_str().unwrap()))
        .collect();
    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .env_remove("ELASTICCTL_PROFILE")
        .env_remove("ELASTICCTL_CONFIG")
        .env_remove("ELASTICCTL_KIBANA_URL")
        .env_remove("ELASTICCTL_ES_URL")
        .env_remove("ELASTICCTL_API_KEY")
        .env_remove("ELASTICCTL_SPACE")
        .env_remove("ELASTICCTL_TIMEOUT")
        .args(["--config", cfg.to_str().unwrap()])
        .args(if invalid_config {
            vec!["--profile", "missing"]
        } else {
            vec![]
        })
        .args(&expanded)
        .output()
        .unwrap();
    let requests: Vec<_> = if let Some(server) = &server {
        server.received_requests().await.unwrap()
    } else {
        vec![]
    }
    .iter()
    .map(|r| {
        json!({
            "method": r.method.as_str(), "url": r.url.as_str().replace(&uri, "HOST"),
            "body": String::from_utf8(r.body.clone()).unwrap(),
        })
    })
    .collect();
    let normalize = |s: &[u8]| {
        String::from_utf8(s.to_vec())
            .unwrap()
            .replace(dir.path().to_str().unwrap(), "ROOT")
            .replace(&uri, "HOST")
            .replace(uri.trim_start_matches("http://"), "HOST")
            .replace(
                concat!("\"", env!("CARGO_PKG_VERSION"), "\""),
                "\"VERSION\"",
            )
    };
    json!({"args": args, "code": out.status.code(), "stdout": normalize(&out.stdout),
        "stderr": normalize(&out.stderr), "requests": requests,
        "out": fs::read(dir.path().join("out")).ok().map(|b| normalize(&b))})
}

async fn pin(name: &str, cases: &[&str], invalid: bool) {
    let mut results = vec![];
    for case in cases {
        let args: Vec<_> = case.split_whitespace().collect();
        let result = capture(&args, invalid, false).await;
        if invalid {
            assert_ne!(result["code"], 2, "{result}");
            assert_eq!(result["requests"], json!([]));
        }
        results.push(result);
    }
    if invalid {
        insta::assert_json_snapshot!(name, results);
    } else {
        for result in results {
            assert_ne!(result["code"], 2, "CLI arguments must parse: {result}");
            if !result["args"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "--yes")
            {
                let writes: Vec<_> = result["requests"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|r| r["method"] != "GET" && r["method"] != "HEAD")
                    .filter(|r| !r["url"].as_str().unwrap().contains("_export"))
                    .filter(|r| !r["url"].as_str().unwrap().contains("_query"))
                    .filter(|r| !r["url"].as_str().unwrap().contains("_search"))
                    .collect();
                assert!(writes.is_empty(), "dry run sent writes: {result}");
            }
        }
    }
}

#[tokio::test]
async fn dispatch_family_streams_and_exit_codes() {
    pin(
        "families",
        &[
            "config init --json",
            "config list --json",
            "config show --json",
            "config test --json",
            "doctor --json",
            "info --json",
            "rules list --json",
            "rules get elasticctl-fixture-probe --json",
            "rules validate --path ROOT/rule.ndjson --json",
            "rules export --json",
            "rules preview elasticctl-fixture-probe --json",
            "rules import --path ROOT/rule.ndjson --json",
            "rules prebuilt status --json",
            "rules prebuilt install --json",
            "exceptions list --json",
            "exceptions get elasticctl-sample-exceptions --json",
            "exceptions export --json",
            "data-views list --json",
            "data-views get elasticctl-sample-data-view --json",
            "data-views export --json",
            "data-views default get --json",
            "data-views default set elasticctl-sample-data-view --json",
            "data-views default unset --json",
            "dashboards list --json",
            "dashboards get elasticctl-sample-dashboard --json",
            "dashboards export --json",
            "dashboards bundle export --json",
            "dashboards bundle import --path ROOT/rule.ndjson --json",
            "fleet agent-policies list --json",
            "fleet agent-policies get elasticctl-sample-agent-policy --json",
            "fleet agent-policies export --all-custom --json",
            "fleet integration-policies list --json",
            "fleet integration-policies get elasticctl-sample-integration-policy --json",
            "fleet integration-policies export --all-custom --json",
            "state pull --dir ROOT/pull --json",
            "state diff --dir ROOT/mirror --json",
            "state push --dir ROOT/mirror --json",
            "search esql FROM_logs --json",
            "search dsl {} --index logs-* --json",
            "alerts list --json",
            "alerts get probe --json",
            "cases list --json",
            "cases get probe --json",
            "commands --json",
            "completion bash --json",
            "exceptions validate --path ROOT/rule.ndjson --json",
            "exceptions import --path ROOT/rule.ndjson --json",
            "data-views validate --path ROOT/rule.ndjson --json",
            "data-views import --path ROOT/rule.ndjson --json",
            "dashboards validate --path ROOT/rule.ndjson --json",
            "dashboards import --path ROOT/rule.ndjson --json",
            "fleet agent-policies validate --path ROOT/rule.ndjson --json",
            "fleet agent-policies import --path ROOT/rule.ndjson --json",
            "fleet integration-policies validate --path ROOT/rule.ndjson --json",
            "fleet integration-policies import --path ROOT/rule.ndjson --json",
            "rules enable elasticctl-fixture-probe --json",
            "rules enable elasticctl-fixture-probe --yes --json",
            "rules disable elasticctl-fixture-probe --json",
            "rules disable elasticctl-fixture-probe --yes --json",
            "rules delete elasticctl-fixture-probe --json",
            "rules delete elasticctl-fixture-probe --yes --json",
            "exceptions delete elasticctl-sample-exceptions --json",
            "exceptions delete elasticctl-sample-exceptions --yes --json",
            "data-views delete elasticctl-sample-data-view --json",
            "data-views delete elasticctl-sample-data-view --yes --json",
            "dashboards delete elasticctl-sample-dashboard --json",
            "dashboards delete elasticctl-sample-dashboard --yes --json",
            "fleet agent-policies delete elasticctl-sample-agent-policy --json",
            "fleet agent-policies delete elasticctl-sample-agent-policy --yes --json",
            "fleet integration-policies delete elasticctl-sample-integration-policy --json",
            "fleet integration-policies delete elasticctl-sample-integration-policy --yes --json",
            "alerts ack probe --json",
            "alerts ack probe --yes --json",
            "alerts open probe --json",
            "alerts open probe --yes --json",
            "alerts close probe --json",
            "alerts close probe --yes --json",
            "alerts tag probe --add triage --json",
            "alerts tag probe --add triage --yes --json",
            "alerts assign probe --add uid:probe --json",
            "alerts assign probe --add uid:probe --yes --json",
            "cases create --title probe --json",
            "cases create --title probe --yes --json",
            "cases close probe --json",
            "cases close probe --yes --json",
            "cases open probe --json",
            "cases open probe --yes --json",
            "cases delete probe --json",
            "cases delete probe --yes --json",
            "cases attach probe --alert probe --json",
            "cases attach probe --alert probe --yes --json",
            "cases comment probe --message probe --json",
            "cases comment probe --message probe --yes --json",
        ],
        true,
    )
    .await;
}

#[tokio::test]
async fn dispatch_validation_precedes_context() {
    pin(
        "validation",
        &[
            "rules export --format-file invalid",
            "exceptions export --format-file invalid",
            "data-views export --format-file invalid",
            "dashboards export --format-file invalid",
            "fleet agent-policies export --all-custom --format-file invalid",
            "fleet integration-policies export --all-custom --format-file invalid",
            "state pull --dir ROOT/pull --format-file invalid",
            "rules enable",
            "rules disable",
            "rules delete",
            "exceptions delete",
            "dashboards delete",
            "rules list --enabled --disabled",
            "data-views import --path ROOT/rule.ndjson",
            "dashboards import --path ROOT/rule.ndjson",
            "dashboards bundle import --path ROOT/rule.ndjson",
            "fleet agent-policies import --path ROOT/rule.ndjson",
            "fleet integration-policies import --path ROOT/rule.ndjson",
        ],
        true,
    )
    .await;
}

#[tokio::test]
async fn dispatch_request_order_and_guard_contract() {
    for apply in [false, true] {
        let mut args = vec!["rules", "disable", "elasticctl-fixture-probe", "--json"];
        if apply {
            args.push("--yes");
        }
        let result = capture(&args, false, false).await;
        assert_eq!(result["code"], 0, "{result}");
        let requests = result["requests"].as_array().unwrap();
        assert_eq!(requests[0]["method"], "GET");
        assert!(
            requests[0]["url"]
                .as_str()
                .unwrap()
                .contains("/api/detection_engine/rules?")
        );
        assert_eq!(requests.len(), if apply { 2 } else { 1 }, "{result}");
        let stderr = result["stderr"].as_str().unwrap();
        for target in ["profile: default", "HOST", "space: default"] {
            assert!(stderr.contains(target), "{result}");
        }
        assert!(stderr.starts_with(if apply { "Applying:" } else { "[DRY RUN]" }));
        if apply {
            assert_eq!(requests[1]["method"], "POST");
            assert!(
                requests[1]["url"]
                    .as_str()
                    .unwrap()
                    .ends_with("/api/detection_engine/rules/_bulk_action"),
                "{result}"
            );
            let body: Value = serde_json::from_str(requests[1]["body"].as_str().unwrap()).unwrap();
            assert_eq!(
                body,
                json!({"action": "disable", "query": "alert.attributes.params.ruleId: \"elasticctl-fixture-probe\""})
            );
        }
    }
}

#[tokio::test]
async fn dispatch_output_routing_contract() {
    pin(
        "routing",
        &[
            "config list --out ROOT/out",
            "config list --out ROOT/out --format json",
            "config list --out ROOT/out --format jsonl",
            "config list --out ROOT/out --format yaml",
            "config list --out ROOT/out --format csv",
            "rules validate --path ROOT/rule.ndjson --out ROOT/out --json",
            "rules export --format yaml",
            "rules export --out ROOT/out --json",
            "exceptions export --format csv",
            "data-views export --format yaml",
            "dashboards export --format csv",
            "dashboards bundle export --format yaml",
            "dashboards bundle export --out ROOT/out --json",
            "fleet agent-policies export --all-custom --format csv",
            "fleet integration-policies export --all-custom --out ROOT/out --json",
            "search esql FROM_logs --out ROOT/out",
            "search dsl {} --index logs-* --out ROOT/out --format json",
            "alerts list --out ROOT/out",
            "cases list --out ROOT/out",
            "alerts get probe --json",
            "cases get probe --json",
        ],
        true,
    )
    .await;
    #[cfg(unix)]
    insta::assert_json_snapshot!(
        "warning",
        capture(&["config", "list", "--json"], true, true).await
    );
}
