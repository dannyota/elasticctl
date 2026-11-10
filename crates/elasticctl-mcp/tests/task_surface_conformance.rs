//! Whole-surface protocol contracts with recorded upstream responses.
#[allow(dead_code)]
mod support;

use elasticctl_core::Resolved;
use rmcp::{
    ClientLifecycleMode, ClientServiceExt, RoleClient,
    model::{
        CallToolRequestParams, GetPromptRequestParams, ProtocolVersion, ReadResourceRequestParams,
    },
    transport::async_rw::AsyncRwTransport,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use support::{Harness, initialize, options, request};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use wiremock::{Mock, MockServer, Request, ResponseTemplate, matchers::any};

struct TapWriter {
    inner: tokio::io::DuplexStream,
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl tokio::io::AsyncWrite for TapWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buffer) {
            Poll::Ready(Ok(written)) => {
                this.bytes
                    .lock()
                    .expect("tap lock")
                    .extend_from_slice(&buffer[..written]);
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

const RULE: &str = "elasticctl-sample-alert-probe";
const ALERT: &str = "elasticctl-fixture-alert-1";
const SENTINEL: &str = "essu_0123456789012345678901234567890123456789";
const CAP: usize = 262_144;

fn fixture(name: &str) -> Value {
    let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/serverless-9.7.0")
        .join(format!("{name}.json"));
    let recorded: Value = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
    recorded
        .get("response")
        .unwrap_or(&recorded["error"])
        .clone()
}
fn target(server: &MockServer) -> Resolved {
    target_uri(server.uri())
}
fn target_uri(uri: String) -> Resolved {
    let mut t = support::target();
    t.profile.kibana_url = uri.clone();
    t.profile.es_url = Some(uri);
    t.profile.api_key = Some("fake-auth".into());
    t
}
fn schema(schema: &Value, value: &Value) {
    let validator = jsonschema::validator_for(schema).unwrap();
    let errors: Vec<_> = validator.iter_errors(value).collect();
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}
fn success_arguments(name: &str) -> Value {
    match name {
        "alert_context" => json!({"alert_id":"elasticctl-fixture-alert-1"}),
        "alerts_get" => json!({"alert_id":"elasticctl-fixture-alert-1"}),
        "cases_get" => json!({"id":"elasticctl-fixture-case"}),
        "data_views_get" => json!({"selector":"elasticctl-sample-data-view-source"}),
        "dashboards_get" => json!({"selector":"elasticctl-sample-dashboard"}),
        "fleet_agent_policies_get" => json!({"selector":"elasticctl-sample-agent-policy"}),
        "fleet_integration_policies_get" => {
            json!({"selector":"elasticctl-sample-integration-policy"})
        }
        "rules_get" | "rule_health" | "rule_readiness" => {
            json!({"selector":"elasticctl-sample-alert-probe"})
        }
        "exceptions_get" => json!({"list_id":"elasticctl-sample-exceptions","namespace":"single"}),
        "search_esql" => json!({"query":"FROM logs-*"}),
        "search_dsl" => json!({"index":"logs-*","query":{"match_all":{}}}),
        _ => json!({}),
    }
}

fn resources() -> Vec<(String, &'static str)> {
    vec![
        (
            "elasticctl://stack/coverage/tactic".into(),
            "detection_coverage",
        ),
        (
            "elasticctl://stack/coverage/technique".into(),
            "detection_coverage",
        ),
        ("elasticctl://stack/doctor".into(), "stack_doctor"),
        ("elasticctl://stack/info".into(), "stack_info"),
        (
            "elasticctl://stack/prebuilt-rules/status".into(),
            "rules_prebuilt_status",
        ),
        (format!("elasticctl://stack/alerts/{ALERT}"), "alerts_get"),
        (
            "elasticctl://stack/cases/elasticctl-fixture-case".into(),
            "cases_get",
        ),
        (
            "elasticctl://stack/exception-lists/single/elasticctl-sample-exceptions".into(),
            "exceptions_get",
        ),
        (format!("elasticctl://stack/rules/{RULE}"), "rules_get"),
    ]
}

struct Stack {
    bodies: BTreeMap<&'static str, Value>,
    rule: Value,
    corpus: Vec<Value>,
    missing_list: bool,
    retry: bool,
    finds: AtomicUsize,
    empty_source: bool,
    error_package: bool,
}
impl Stack {
    fn new() -> Self {
        let names = [
            "status",
            "spaces",
            "license",
            "authenticate",
            "signals_search_rule_activity",
            "cases_find",
            "case_get",
            "cases_by_alert",
            "data_views_list",
            "data_view_get",
            "data_view_default_get",
            "dashboard_search",
            "dashboard_get",
            "agent_policies_list",
            "agent_policy_get",
            "integration_policies_list",
            "integration_policy_get",
            "integration_policy_parent_get",
            "rules_find_sorted_page",
            "prebuilt_status",
            "exception_lists_find",
            "exception_list_get",
            "exception_list_items_find",
            "exception_items_count",
            "esql_query",
            "resolve_index_match",
            "package_system",
            "rules_preview_hits",
        ];
        let bodies = names.into_iter().map(|n| (n, fixture(n))).collect();
        let rule = fixture("rule_get_executed");
        Self {
            bodies,
            corpus: vec![rule.clone()],
            rule,
            missing_list: false,
            retry: false,
            finds: AtomicUsize::new(0),
            empty_source: false,
            error_package: false,
        }
    }
    fn response(&self, req: &Request) -> ResponseTemplate {
        let p = req.url.path();
        let q: BTreeMap<_, _> = req.url.query_pairs().into_owned().collect();
        let mut status = 200;
        let mut body = if p == "/api/detection_engine/rules" {
            if q.get("rule_id")
                .is_some_and(|id| id == self.rule["name"].as_str().unwrap())
            {
                status = 404;
                fixture("resolve_index_not_found")
            } else {
                self.rule.clone()
            }
        } else if p == "/api/detection_engine/rules/_find" {
            let n = self.finds.fetch_add(1, Ordering::SeqCst);
            let page: usize = q.get("page").unwrap().parse().unwrap();
            let size: usize = q.get("per_page").unwrap().parse().unwrap();
            let mut body = self.bodies["rules_find_sorted_page"].clone();
            let by_name = q.get("filter").is_some_and(|f| f.contains("name"));
            let rows = if by_name {
                std::slice::from_ref(&self.rule)
            } else {
                self.corpus.as_slice()
            };
            let start = ((page - 1) * size).min(rows.len());
            let end = (page * size).min(rows.len());
            body["data"] = json!(rows[start..end]);
            body["page"] = json!(page);
            body["perPage"] = json!(size);
            body["total"] = json!(rows.len());
            if self.retry && n == 7 {
                body["data"][0]["rule_id"] = self.corpus[0]["rule_id"].clone();
            }
            if self.empty_source {
                body["data"] = json!([]);
                body["total"] = json!(0);
            }
            body
        } else {
            let name = match p {
                "/api/status" => "status",
                "/api/spaces/space" => "spaces",
                "/_license" => "license",
                "/_security/_authenticate" => "authenticate",
                "/api/detection_engine/signals/search" => "signals_search_rule_activity",
                "/api/cases/_find" => "cases_find",
                "/api/data_views" => "data_views_list",
                "/api/data_views/default" => "data_view_default_get",
                "/api/dashboards" => "dashboard_search",
                "/api/fleet/agent_policies" => "agent_policies_list",
                "/api/fleet/package_policies" => "integration_policies_list",
                "/api/detection_engine/rules/prepackaged/_status" => "prebuilt_status",
                "/api/exception_lists/_find" => "exception_lists_find",
                "/api/exception_lists" => "exception_list_get",
                "/api/exception_lists/items/_find" => "exception_list_items_find",
                "/_query" => "esql_query",
                "/api/lists/index" => {
                    status = 404;
                    "resolve_index_match"
                }
                p if p.starts_with("/api/cases/alerts/") => "cases_by_alert",
                p if p.starts_with("/api/cases/") => "case_get",
                p if p.starts_with("/api/data_views/data_view/") => "data_view_get",
                p if p.starts_with("/api/dashboards/") => "dashboard_get",
                "/api/fleet/agent_policies/elasticctl-sample-integration-policy-parent" => {
                    "integration_policy_parent_get"
                }
                p if p.starts_with("/api/fleet/agent_policies/") => "agent_policy_get",
                p if p.starts_with("/api/fleet/package_policies/") => "integration_policy_get",
                p if p.starts_with("/api/fleet/epm/packages/") => "package_system",
                p if p.starts_with("/_resolve/index/") => "resolve_index_match",
                p if p.ends_with("/_search") => "rules_preview_hits",
                _ => panic!("unexpected upstream {} {}", req.method, req.url),
            };
            if (p == "/api/exception_lists"
                && self.missing_list
                && q.get("list_id").is_some_and(|id| id == "list-0"))
                || (p.ends_with("/missing") && self.error_package)
            {
                status = 404;
                let mut e = fixture("resolve_index_not_found");
                e["message"] = json!(SENTINEL);
                e
            } else {
                self.bodies[name].clone()
            }
        };
        if p == "/api/detection_engine/signals/search" {
            let input: Value = serde_json::from_slice(&req.body).unwrap();
            if input["query"]["ids"].is_object() {
                let hit = body["hits"]["hits"][0].clone();
                body["hits"]["hits"] = json!([hit]);
                body["hits"]["total"]["value"] = json!(1);
                body.as_object_mut().unwrap().remove("aggregations");
            }
        }
        ResponseTemplate::new(status).set_body_json(body)
    }
}
async fn stack(config: Stack) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(move |r: &Request| config.response(r))
        .mount(&server)
        .await;
    server
}

// Preserve container types when poisoning fields that typed upstream decoders retain.
fn seed_strings(value: &mut Value) {
    match value {
        Value::String(text) => *text = SENTINEL.into(),
        Value::Array(rows) => rows.iter_mut().for_each(seed_strings),
        Value::Object(fields) => fields.values_mut().for_each(seed_strings),
        _ => {}
    }
}
fn seed_excluded(value: &mut Value, kept: &[&str]) {
    for (key, field) in value.as_object_mut().unwrap() {
        if !kept.contains(&key.as_str()) {
            seed_strings(field);
        }
    }
}

fn assert_poisoned(value: &Value, pointers: &[&str]) {
    for pointer in pointers {
        assert!(
            value
                .pointer(pointer)
                .unwrap()
                .to_string()
                .contains(SENTINEL),
            "unpoisoned field: {pointer}"
        );
    }
}

async fn sweep(query: bool, sentinel: bool) {
    let mut config = Stack::new();
    if sentinel {
        config.rule["execution_summary"]["last_execution"]["message"] =
            json!(format!("{}{SENTINEL}", "x".repeat(2048)));
        config.rule["execution_summary"]["last_execution"]["metrics"]["excluded"] = json!(SENTINEL);
        config.rule["author"] = json!([SENTINEL]);
        for field in ["created_by", "updated_by", "author", "setup"] {
            seed_strings(&mut config.rule[field]);
        }
        config.rule["exceptions_list"][0]["id"] = json!(SENTINEL);
        assert_poisoned(
            &config.rule,
            &[
                "/execution_summary/last_execution/message",
                "/execution_summary/last_execution/metrics/excluded",
                "/created_by",
                "/updated_by",
                "/author",
                "/setup",
                "/exceptions_list/0/id",
            ],
        );
        config.corpus = vec![config.rule.clone()];
        let case = config.bodies.get_mut("case_get").unwrap();
        let mut user = case["created_by"].clone();
        user["full_name"] = json!(SENTINEL);
        seed_strings(&mut user);
        for field in ["created_by", "updated_by", "closed_by"] {
            case[field] = user.clone();
        }
        case["category"] = json!(SENTINEL);
        case["customFields"] = json!([{"key": SENTINEL, "type": "text", "value": SENTINEL}]);
        case["observables"] = json!([{
            "id": SENTINEL, "typeKey": "hostname", "value": SENTINEL,
            "description": SENTINEL, "createdAt": case["created_at"], "updatedAt": null
        }]);
        case["external_service"] = json!({
            "connector_id": SENTINEL, "connector_name": SENTINEL,
            "external_id": SENTINEL, "external_title": SENTINEL,
            "external_url": format!("https://example.invalid/{SENTINEL}"),
            "pushed_at": case["created_at"], "pushed_by": user
        });
        seed_excluded(
            config.bodies.get_mut("case_get").unwrap(),
            &[
                "id",
                "title",
                "status",
                "severity",
                "tags",
                "description",
                "created_at",
                "updated_at",
                "totalComment",
            ],
        );
        let case = config.bodies.get_mut("case_get").unwrap();
        case["customFields"][0]["type"] = json!("text");
        case["observables"][0]["typeKey"] = json!("hostname");
        case["observables"][0]["createdAt"] = case["created_at"].clone();
        case["external_service"]["pushed_at"] = case["created_at"].clone();
        case["external_service"]["external_url"] =
            json!(format!("https://example.invalid/{SENTINEL}"));
        assert_poisoned(
            &config.bodies["case_get"],
            &[
                "/created_by",
                "/updated_by",
                "/closed_by",
                "/external_service",
                "/assignees",
                "/category",
                "/customFields",
                "/observables",
                "/connector",
                "/owner",
                "/version",
            ],
        );
        for row in config
            .bodies
            .get_mut("cases_by_alert")
            .unwrap()
            .as_array_mut()
            .unwrap()
        {
            seed_excluded(row, &["id", "title"]);
            assert_poisoned(row, &["/description", "/status", "/createdAt"]);
        }
        for hit in config
            .bodies
            .get_mut("signals_search_rule_activity")
            .unwrap()["hits"]["hits"]
            .as_array_mut()
            .unwrap()
        {
            seed_excluded(
                &mut hit["_source"],
                &[
                    "@timestamp",
                    "kibana.alert.rule.rule_id",
                    "kibana.alert.rule.name",
                    "kibana.alert.severity",
                    "kibana.alert.risk_score",
                    "kibana.alert.workflow_status",
                    "kibana.alert.reason",
                    "kibana.alert.workflow_tags",
                ],
            );
        }
        let mut package = fixture("package_system_metadata");
        package["item"]["vars"] =
            package["item"]["policy_templates"][0]["inputs"][0]["vars"].clone();
        package["item"]["installationInfo"] =
            config.bodies["package_system"]["item"]["installationInfo"].clone();
        seed_excluded(
            &mut package["item"],
            &["name", "version", "status", "installationInfo"],
        );
        assert_poisoned(
            &package,
            &["/item/vars", "/item/policy_templates", "/item/data_streams"],
        );
        config.bodies.insert("package_system", package);
        for row in config.bodies.get_mut("integration_policies_list").unwrap()["items"]
            .as_array_mut()
            .unwrap()
        {
            row["vars"] = json!({"excluded": {"type": "text", "value": SENTINEL}});
            seed_strings(&mut row["inputs"]);
            seed_strings(&mut row["vars"]);
            assert_poisoned(row, &["/inputs", "/vars"]);
        }
        for name in ["exception_list_get", "exception_list_items_find"] {
            let body = config.bodies.get_mut(name).unwrap();
            if name == "exception_list_get" {
                for key in ["created_by", "updated_by"] {
                    seed_strings(&mut body[key]);
                    assert_poisoned(body, &[&format!("/{key}")]);
                }
            } else {
                for row in body["data"].as_array_mut().unwrap() {
                    for key in ["created_by", "updated_by", "_version", "tie_breaker_id"] {
                        seed_strings(&mut row[key]);
                        assert_poisoned(row, &[&format!("/{key}")]);
                    }
                }
            }
        }
        for key in ["indices", "aliases", "data_streams"] {
            config.bodies.get_mut("resolve_index_match").unwrap()[key] =
                json!([{ "name": SENTINEL }]);
            assert_poisoned(&config.bodies["resolve_index_match"], &[&format!("/{key}")]);
        }
        config.rule["related_integrations"]
            .as_array_mut()
            .unwrap()
            .push(json!({"package":"missing"}));
        config.error_package = true;
    }
    let mock = stack(config).await;
    let (cw, sr) = tokio::io::duplex(1_048_576);
    let (sw, cr) = tokio::io::duplex(1_048_576);
    let mut opts = options();
    opts.allow_query_tools = query;
    let wire = Arc::new(Mutex::new(Vec::new()));
    let writer = TapWriter {
        inner: sw,
        bytes: wire.clone(),
    };
    let task = tokio::spawn(elasticctl_mcp::serve_io(target(&mock), opts, sr, writer));
    let client = ()
        .serve_with_lifecycle(
            AsyncRwTransport::<RoleClient, _, _>::new_client(cr, cw),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .unwrap();
    let catalog = serde_json::to_value(client.list_tools(None).await.unwrap()).unwrap();
    assert_eq!(
        catalog["tools"].as_array().unwrap().len(),
        if query { 26 } else { 24 }
    );
    for tool in catalog["tools"].as_array().unwrap() {
        let name = tool["name"].as_str().unwrap();
        for (args, error) in [
            (success_arguments(name), false),
            (json!({"unexpected":true}), true),
        ] {
            let reply = client
                .call_tool(
                    CallToolRequestParams::new(name.to_owned())
                        .with_arguments(args.as_object().unwrap().clone()),
                )
                .await
                .unwrap();
            assert_eq!(reply.is_error, Some(error), "{name}: {reply:?}");
            schema(
                &tool["outputSchema"],
                reply.structured_content.as_ref().unwrap(),
            );

            if sentinel && !error {
                let data = &reply.structured_content.as_ref().unwrap()["data"];
                match name {
                    "alert_context" => {
                        assert_eq!(data["rule"]["status"], "ok");
                        assert_eq!(data["cases"]["status"], "ok");
                        assert_eq!(data["cases"]["value"]["cases"][0]["status"], "ok");
                        assert_eq!(data["exceptions"]["status"], "ok");
                        assert_eq!(data["activity"]["status"], "ok");
                        assert_eq!(
                            data["rule"]["value"]["execution"]["message"]
                                .as_str()
                                .unwrap()
                                .len(),
                            2048
                        );
                        assert_eq!(
                            data["rule"]["value"]["execution"]["message_truncated"],
                            true
                        );
                    }
                    "rule_health" => {
                        assert_eq!(data["alerts"]["status"], "ok");
                        assert_eq!(data["exceptions"]["status"], "ok");
                    }
                    "rule_readiness" => {
                        assert_eq!(data["patterns"]["status"], "ok");
                        assert_eq!(data["patterns"]["value"]["rows"][0]["indices"], 1);
                        assert_eq!(data["integrations"]["status"], "ok");
                        assert_eq!(data["integrations"]["value"]["rows"][0]["status"], "ok");
                        assert_eq!(
                            data["integrations"]["value"]["rows"][1]["status"],
                            "unavailable"
                        );
                    }
                    "detection_coverage" => assert_eq!(data["summary"]["rules"], 1),
                    _ => {}
                }
            }
            if sentinel {
                assert!(
                    !serde_json::to_string(&reply).unwrap().contains(SENTINEL),
                    "{name}"
                );
            }
        }
    }
    for (uri, tool) in resources() {
        let reply = serde_json::to_value(
            client
                .read_resource(ReadResourceRequestParams::new(uri.clone()))
                .await
                .unwrap(),
        )
        .unwrap();
        let text = reply["contents"][0]["text"].as_str().unwrap();
        let body: Value = serde_json::from_str(text).unwrap();
        let declared = catalog["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == tool)
            .unwrap();
        schema(&declared["outputSchema"], &body);
        assert!(body["data"].is_object());
        assert_eq!(reply["contents"][0]["uri"], uri);
        if sentinel {
            assert!(!text.contains(SENTINEL));
        }
    }
    for (name, args) in [
        ("triage_alert", json!({"alert_id":ALERT})),
        ("review_rule_health", json!({"rule":RULE})),
        ("check_rule_readiness", json!({"rule":RULE})),
        ("review_detection_coverage", json!({})),
    ] {
        let mut p = GetPromptRequestParams::new(name);
        p.arguments = Some(args.as_object().unwrap().clone());
        let reply = client.get_prompt(p).await.unwrap();
        if sentinel {
            assert!(!serde_json::to_string(&reply).unwrap().contains(SENTINEL));
        }
    }
    client.cancel().await.unwrap();
    task.await.unwrap().unwrap();
    if sentinel {
        assert!(!String::from_utf8_lossy(&wire.lock().unwrap()).contains(SENTINEL));
    }
}
#[tokio::test]
async fn whole_catalog_and_nine_resource_schemas() {
    sweep(true, false).await;
}

#[tokio::test]
async fn sentinel_child() {
    if std::env::var_os("SURFACE_SENTINEL_CHILD").is_none() {
        return;
    }
    sweep(false, true).await;
}
#[tokio::test]
async fn sentinel_never_reaches_stdout_or_stderr() {
    let output = tokio::task::spawn_blocking(|| {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "sentinel_child", "--nocapture"])
            .env("SURFACE_SENTINEL_CHILD", "1")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SENTINEL));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SENTINEL));
    assert!(
        output.status.success(),
        "child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn maximum_stack() -> Stack {
    let mut s = Stack::new();
    let reference = s.rule["exceptions_list"][0].clone();
    s.rule["exceptions_list"] = json!(
        (0..5)
            .map(|i| {
                let mut r = reference.clone();
                r["list_id"] = json!(format!("list-{i}"));
                r
            })
            .collect::<Vec<_>>()
    );
    let case = s.bodies["cases_by_alert"][0].clone();
    s.bodies.insert(
        "cases_by_alert",
        json!(
            (0..5)
                .map(|i| {
                    let mut r = case.clone();
                    r["id"] = json!(format!("case-{i}"));
                    r
                })
                .collect::<Vec<_>>()
        ),
    );
    s.rule["index"] = json!((0..16).map(|i| format!("pattern-{i}")).collect::<Vec<_>>());
    let integration = s.rule["related_integrations"][0].clone();
    s.rule["related_integrations"] = json!(
        (0..8)
            .map(|i| {
                let mut r = integration.clone();
                r["package"] = json!(format!("package-{i}"));
                r
            })
            .collect::<Vec<_>>()
    );
    s
}
fn corpus(s: &mut Stack, size: usize) {
    let recorded = fixture("rules_find_sorted_page")["data"][0].clone();
    s.corpus = (0..size)
        .map(|i| {
            let mut row = recorded.clone();
            row["rule_id"] = json!(format!("rule-{i:04}"));
            row
        })
        .collect();
}
fn expected_paths(
    tool: &str,
    missing: bool,
    exclusion: bool,
    policies_over: bool,
    count: usize,
    named: bool,
) -> Vec<String> {
    let rule = "/api/detection_engine/rules";
    let find = "/api/detection_engine/rules/_find";
    let signals = "/api/detection_engine/signals/search";
    let mut paths: Vec<String> = Vec::new();
    if tool == "detection_coverage" || tool == "rules_list" {
        return vec![find.into(); count];
    }
    if tool == "alert_context" {
        paths.push(signals.into());
    }
    paths.push(rule.into());
    if named {
        paths.extend([find.into(), rule.into()]);
    }
    if tool == "rule_health" {
        paths.push(signals.into());
    }
    if tool == "rule_health" || tool == "alert_context" {
        for i in 0..5 {
            paths.push("/api/exception_lists".into());
            if !missing || i != 0 {
                paths.push("/api/exception_lists/items/_find".into());
            }
        }
    }
    if tool == "alert_context" {
        paths.push(format!("/api/cases/alerts/{ALERT}"));
        paths.extend((0..5).map(|i| format!("/api/cases/case-{i}")));
        paths.push(signals.into());
    }
    if tool == "rule_readiness" {
        paths.push("/api/data_views".into());
        paths.extend((usize::from(exclusion)..16).map(|i| format!("/_resolve/index/pattern-{i}")));
        paths.push("/api/fleet/package_policies".into());
        if !policies_over {
            paths.extend((0..8).map(|i| format!("/api/fleet/epm/packages/package-{i}")));
        }
    }
    paths
}
async fn counts(degraded: bool) {
    let rows = if degraded {
        vec![
            ("alert_context", "missing lists", 18),
            ("rule_health", "missing lists", 13),
            ("rule_readiness", "exclusion", 28),
            ("rule_readiness", "1001 policies", 21),
            ("detection_coverage", "4001 rules", 1),
        ]
    } else {
        vec![
            ("alert_context", "maximum", 19),
            ("rule_health", "maximum", 14),
            ("rule_readiness", "maximum", 29),
            ("detection_coverage", "4000 rules", 8),
            ("detection_coverage", "retry", 16),
            ("rules_list", "normal", 1),
            ("rules_list", "empty source", 4),
        ]
    };
    for (tool, variant, count) in rows {
        let mut config = maximum_stack();
        config.missing_list = variant == "missing lists";
        let exclusion = variant == "exclusion";
        let over = variant == "1001 policies";
        if exclusion {
            config.rule["index"][0] = json!("-excluded");
        }
        if over {
            let body = config.bodies.get_mut("integration_policies_list").unwrap();
            let row = body["items"][0].clone();
            let policies: Vec<_> = (0..1001)
                .map(|i| {
                    let mut r = row.clone();
                    r["id"] = json!(format!("policy-{i}"));
                    r
                })
                .collect();
            body["items"] = json!(&policies[..1000]);
            body["total"] = json!(policies.len());
            body["perPage"] = json!(1000);
        }
        if tool == "detection_coverage" {
            corpus(
                &mut config,
                if variant == "4001 rules" { 4001 } else { 4000 },
            );
        }
        config.retry = variant == "retry";
        config.empty_source = variant == "empty source";
        let named = tool == "rule_health" || tool == "rule_readiness";
        let args = if named {
            json!({"selector":config.rule["name"]})
        } else if tool == "alert_context" {
            json!({"alert_id":ALERT})
        } else if config.empty_source {
            json!({"source":"custom"})
        } else {
            json!({})
        };
        let missing = config.missing_list;
        let mock = stack(config).await;
        let mut h = Harness::start(target(&mock), options());
        // Warm the capability cache outside the measured request plan.
        let warm = request(
            &mut h,
            true,
            1,
            "tools/call",
            json!({"name":"exceptions_list","arguments":{}}),
        )
        .await;
        assert_eq!(warm["result"]["isError"], false);
        let before = mock.received_requests().await.unwrap().len();
        let reply = request(
            &mut h,
            true,
            2,
            "tools/call",
            json!({"name":tool,"arguments":args}),
        )
        .await;
        assert_eq!(
            reply["result"]["isError"],
            variant == "4001 rules",
            "{tool} {variant} {args}: {reply}"
        );
        let received = mock.received_requests().await.unwrap();
        let requests = &received[before..];
        assert_eq!(
            requests.len(),
            count,
            "{tool} {variant} {args}: {:?}",
            requests.iter().map(|r| &r.url).collect::<Vec<_>>()
        );
        let actual: Vec<_> = requests.iter().map(|r| r.url.path().to_owned()).collect();
        assert_eq!(
            actual,
            expected_paths(tool, missing, exclusion, over, count, named),
            "{tool} {variant} {args}"
        );
        for r in requests {
            assert_eq!(
                r.method.as_str(),
                if r.url.path().ends_with("signals/search") {
                    "POST"
                } else {
                    "GET"
                }
            );
        }
        h.close_input();
        h.join().await.unwrap();
    }
}
#[tokio::test]
async fn maximum_work_request_counts() {
    counts(false).await;
}
#[tokio::test]
async fn degraded_input_request_counts() {
    counts(true).await;
}

#[tokio::test]
async fn structured_resource_text_at_cap_and_one_byte_above_on_both_paths() {
    for current in [true, false] {
        let config = Stack::new();
        let shared = Arc::new(Mutex::new(config));
        let server = MockServer::start().await;
        let responder = shared.clone();
        Mock::given(any())
            .respond_with(move |r: &Request| responder.lock().unwrap().response(r))
            .mount(&server)
            .await;
        let mut h = Harness::start(target(&server), options());
        initialize(&mut h, current).await;
        shared.lock().unwrap().rule["description"] = json!("");
        let params = json!({"uri":format!("elasticctl://stack/rules/{RULE}")});
        let baseline = request(&mut h, current, 1, "resources/read", params.clone()).await;
        let length = baseline["result"]["contents"][0]["text"]
            .as_str()
            .unwrap()
            .len();
        shared.lock().unwrap().rule["description"] = json!("x".repeat(CAP - length));
        let exact = request(&mut h, current, 2, "resources/read", params.clone()).await;
        assert_eq!(
            exact["result"]["contents"][0]["text"]
                .as_str()
                .unwrap()
                .len(),
            CAP
        );
        shared.lock().unwrap().rule["description"] = json!("x".repeat(CAP - length + 1));
        let over = request(&mut h, current, 3, "resources/read", params).await;
        assert_eq!(
            over["error"],
            json!({"code":-32603,"message":"Resource read failed","data":{"kind":"unsupported","http_status":null,"code":"result_too_large"}})
        );
        h.close_input();
        h.join().await.unwrap();
    }
}

#[tokio::test]
async fn oversized_after_resource_child() {
    let Ok(uri) = std::env::var("SURFACE_OVERSIZE_URI") else {
        return;
    };
    let current = std::env::var("SURFACE_CURRENT").unwrap() == "true";
    let (mut cw, sr) = tokio::io::duplex(1_048_576);
    let (sw, cr) = tokio::io::duplex(1_048_576);
    let task = tokio::spawn(elasticctl_mcp::serve_io(target_uri(uri), options(), sr, sw));
    let mut output = BufReader::new(cr);
    if !current {
        let mut init = serde_json::to_vec(&support::legacy_initialize(1000)).unwrap();
        init.push(b'\n');
        cw.write_all(&init).await.unwrap();
        let mut line = String::new();
        output.read_line(&mut line).await.unwrap();
        assert!(serde_json::from_str::<Value>(&line).unwrap()["result"].is_object());
    }
    let mut params = json!({"uri":format!("elasticctl://stack/rules/{RULE}")});
    if current {
        params["_meta"] = support::current_metadata();
    }
    let mut frame = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":1,"method":"resources/read","params":params}),
    )
    .unwrap();
    frame.push(b'\n');
    cw.write_all(&frame).await.unwrap();
    let mut line = String::new();
    output.read_line(&mut line).await.unwrap();
    assert!(
        serde_json::from_str::<Value>(&line).unwrap()["result"]["contents"][0]["text"].is_string()
    );
    cw.write_all(&vec![b'x'; 262_145]).await.unwrap();
    cw.write_all(b"\n").await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("oversized input terminates without caller EOF")
        .unwrap()
        .unwrap();
    line.clear();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), output.read_line(&mut line))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    drop(cw);
}
#[tokio::test]
async fn oversized_line_after_resource_has_static_diagnostic_on_both_paths() {
    let mock = stack(Stack::new()).await;
    for current in [true, false] {
        let uri = mock.uri();
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "oversized_after_resource_child", "--nocapture"])
                .env("SURFACE_OVERSIZE_URI", uri)
                .env("SURFACE_CURRENT", current.to_string())
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.stderr,
            b"MCP input frame exceeds the configured limit\n"
        );
    }
}

#[tokio::test]
async fn mixed_admission_keeps_lists_and_prompts_available() {
    tokio::time::timeout(Duration::from_secs(30), mixed_admission())
        .await
        .expect("mixed admission watchdog expired");
}

async fn mixed_admission() {
    let mock = stack(Stack::new()).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("http://{}", listener.local_addr().unwrap());
    let upstream = *mock.address();
    let (release, gate) = tokio::sync::watch::channel(false);
    // Forward requests for wiremock recording, but hold responses until explicitly released.
    let proxy = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (socket, _) = accepted.unwrap();
                    let mut gate = gate.clone();
                    connections.spawn(async move {
                        let mut socket = BufReader::new(socket);
                        let mut header = String::new();
                        loop {
                            let mut line = String::new();
                            assert_ne!(socket.read_line(&mut line).await.unwrap(), 0);
                            header.push_str(&line);
                            if line == "\r\n" { break; }
                        }
                        let mut remote = tokio::net::TcpStream::connect(upstream).await.unwrap();
                        remote.write_all(header.as_bytes()).await.unwrap();
                        gate.wait_for(|released| *released).await.unwrap();
                        tokio::io::copy_bidirectional(&mut socket, &mut remote).await.unwrap();
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    result.unwrap();
                }
            }
        }
    });
    let (cw, sr) = tokio::io::duplex(1_048_576);
    let (sw, cr) = tokio::io::duplex(1_048_576);
    let task = tokio::spawn(elasticctl_mcp::serve_io(target_uri(uri), options(), sr, sw));
    let client = ()
        .serve_with_lifecycle(
            AsyncRwTransport::<RoleClient, _, _>::new_client(cr, cw),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .unwrap();
    let mut held = tokio::task::JoinSet::new();
    for resource in [false, false, true, true] {
        let peer = client.peer().clone();
        held.spawn(async move {
            if resource {
                serde_json::to_value(
                    peer.read_resource(ReadResourceRequestParams::new(format!(
                        "elasticctl://stack/rules/{RULE}"
                    )))
                    .await
                    .unwrap(),
                )
                .unwrap()
            } else {
                serde_json::to_value(
                    peer.call_tool(
                        CallToolRequestParams::new("rules_get")
                            .with_arguments(json!({"selector":RULE}).as_object().unwrap().clone()),
                    )
                    .await
                    .unwrap(),
                )
                .unwrap()
            }
        });
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if mock
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path() == "/api/detection_engine/rules")
                .count()
                == 4
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let before = mock.received_requests().await.unwrap().len();
    tokio::time::timeout(Duration::from_secs(30), async {
        let busy = client
            .call_tool(
                CallToolRequestParams::new("rules_get")
                    .with_arguments(json!({"selector":RULE}).as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        assert_eq!(busy.structured_content.unwrap()["error"]["code"], "busy");
        let err = client
            .read_resource(ReadResourceRequestParams::new(format!(
                "elasticctl://stack/rules/{RULE}"
            )))
            .await
            .unwrap_err();
        let rmcp::service::ServiceError::McpError(err) = err else {
            panic!("protocol error")
        };
        assert_eq!(err.code.0, -32603);
        assert_eq!(err.data.unwrap()["code"], "busy");
        assert_eq!(client.list_tools(None).await.unwrap().tools.len(), 24);
        assert_eq!(
            client.list_resources(None).await.unwrap().resources.len(),
            5
        );
        assert_eq!(
            client
                .list_resource_templates(None)
                .await
                .unwrap()
                .resource_templates
                .len(),
            4
        );
        assert_eq!(client.list_prompts(None).await.unwrap().prompts.len(), 4);
        client
            .get_prompt(GetPromptRequestParams::new("review_detection_coverage"))
            .await
            .unwrap();
        assert_eq!(mock.received_requests().await.unwrap().len(), before);
    })
    .await
    .expect("busy responses, lists, and prompt finish while four calls are held");
    assert!(
        held.try_join_next().is_none(),
        "admitted calls remain held through every assertion"
    );
    release.send(true).unwrap();
    while let Some(reply) = held.join_next().await {
        let reply = reply.unwrap();
        assert!(reply.get("contents").is_some() || reply["isError"] == false);
    }
    let recovered = client
        .call_tool(CallToolRequestParams::new("rules_list"))
        .await
        .unwrap();
    assert_eq!(recovered.is_error, Some(false));
    client.cancel().await.unwrap();
    task.await.unwrap().unwrap();
    proxy.abort();
    proxy.await.unwrap_err();
}
