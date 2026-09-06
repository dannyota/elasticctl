use super::*;
use std::cell::{Cell, RefCell};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Stdio};
use std::rc::Rc;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_FRAME_BYTES: usize = 1_048_576;
const REPLY_TIMEOUT: Duration = Duration::from_secs(75);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(7);

#[test]
fn bounded_frame_reader_accepts_the_exact_limit_without_retaining_the_newline() {
    let mut source = std::io::Cursor::new([vec![b'x'; MAX_FRAME_BYTES], vec![b'\n']].concat());

    let frame = read_bounded_frame(&mut source).expect("exact boundary is accepted");

    assert_eq!(frame.as_deref(), Some(&vec![b'x'; MAX_FRAME_BYTES][..]));
}

#[test]
fn bounded_frame_reader_rejects_an_oversized_unterminated_frame_before_it_is_allocated() {
    let sentinel = "mcp-child-secret-sentinel";
    let mut source = TrackingBufRead::new(
        [vec![b'x'; MAX_FRAME_BYTES], sentinel.as_bytes().to_vec()].concat(),
        4096,
    );

    let error = read_bounded_frame(&mut source).expect_err("oversized frame is rejected");

    assert_eq!(error, "MCP child response frame exceeded the size limit.");
    assert!(!error.contains(sentinel));
    assert_eq!(
        source.consumed(),
        MAX_FRAME_BYTES,
        "reader must stop before consuming the sentinel tail"
    );
}

#[test]
fn truncated_or_invalid_protocol_data_returns_static_failures() {
    let sentinel = "mcp-child-secret-sentinel";
    let mut truncated = std::io::Cursor::new(sentinel.as_bytes());
    let truncated_error = read_bounded_frame(&mut truncated).expect_err("newline is required");
    let invalid_error = parse_response_frame(format!("{{{sentinel}}}\n").as_bytes())
        .expect_err("invalid JSON is rejected");

    assert_eq!(truncated_error, "MCP child response frame was truncated.");
    assert_eq!(invalid_error, "MCP child response was not valid JSON.");
    assert!(!truncated_error.contains(sentinel));
    assert!(!invalid_error.contains(sentinel));
}

#[test]
fn malformed_tool_projection_returns_a_static_failure() {
    let sentinel = "mcp-child-secret-sentinel";
    let response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{"type": "text", "text": format!("{{\"target\":\"{sentinel}\"}}") }],
            "structuredContent": {"target": sentinel},
        },
    });

    let error = successful_tool_content(&response, 1, "stack_info")
        .expect_err("missing result fields are rejected");

    assert_eq!(error, "MCP success envelope contained unexpected fields.");
    assert!(!error.contains(sentinel));
}

#[test]
fn tools_list_rejects_a_nonempty_next_cursor() {
    let sentinel = "mcp-child-secret-sentinel";
    let catalog = json!({
        "result": {
            "tools": required_catalog(),
            "nextCursor": sentinel,
        },
    });

    let error =
        validate_catalog(&catalog, false).expect_err("additional catalog pages are rejected");

    assert_eq!(
        error,
        "MCP tools/list response included an unexpected continuation cursor."
    );
    assert!(!error.contains(sentinel));
}

/// The default MCP child must not advertise the opt-in query tools. Removing
/// the child-mode gate would expose synchronous query access to every caller.
#[test]
fn default_catalog_rejects_opt_in_query_tools() {
    let mut tools = required_catalog();
    tools.insert(18, json!({"name": "search_dsl"}));
    tools.insert(19, json!({"name": "search_esql"}));
    let catalog = json!({"result": {"tools": tools, "nextCursor": null}});

    let error = validate_catalog(&catalog, false)
        .expect_err("the default catalog must exclude opt-in query tools");

    assert_eq!(
        error,
        "MCP tools/list catalog differs from the required read catalog."
    );
}

/// The query-enabled MCP child has its own exact catalog. Accepting a partial
/// or reordered extension would stop this smoke from detecting flag drift.
#[test]
fn query_catalog_requires_both_opt_in_query_tools_in_order() {
    let mut tools = required_catalog();
    tools.insert(18, json!({"name": "search_dsl"}));
    tools.insert(19, json!({"name": "search_esql"}));
    let catalog = json!({"result": {"tools": tools, "nextCursor": null}});

    validate_catalog(&catalog, true)
        .expect("the query-enabled catalog must contain the exact 22 tools");
}

#[test]
fn selected_projection_rejects_unknown_and_missing_required_fields() {
    let fields = ["id", "name", "namespace"];
    let unknown = json!({"id":"owned","name":"owned","namespace":"default","secret":"no"});
    let missing = json!({"id":"owned","name":"owned"});

    assert_eq!(
        validate_selected_projection(
            &unknown,
            &fields,
            &["id", "name", "namespace"],
            "Fleet detail"
        )
        .expect_err("unknown fields must not reach MCP output"),
        "MCP Fleet detail exposed an unexpected field."
    );
    assert_eq!(
        validate_selected_projection(
            &missing,
            &fields,
            &["id", "name", "namespace"],
            "Fleet detail"
        )
        .expect_err("required identity fields must remain projected"),
        "MCP Fleet detail omitted a required field."
    );
}

#[test]
fn selected_projection_accepts_only_the_safe_required_fields() {
    let value = json!({"id":"owned","name":"owned","namespace":"default"});
    validate_selected_projection(
        &value,
        &["id", "name", "namespace"],
        &["id", "name", "namespace"],
        "Fleet detail",
    )
    .expect("the safe projection is accepted");
}

#[test]
fn inspection_projection_validators_reject_sensitive_fields_and_page_mismatches() {
    validate_new_inspection_validator_samples().expect("safe inspection samples must validate");
    validate_new_inspection_validator_rejections()
        .expect("each inspection validator must reject its named unsafe mutation");
}

#[test]
fn query_projection_validators_reject_malformed_rows_hits_and_empty_page_mismatches() {
    validate_new_query_validator_samples().expect("safe query samples must validate");
    validate_new_query_validator_rejections()
        .expect("each query validator must reject its named malformed shape");
}

#[test]
fn normalized_not_found_tool_errors_have_the_only_safe_error_shape() {
    validate_new_not_found_error_samples().expect("normalized not-found is accepted");
    validate_new_not_found_error_rejections()
        .expect("each normalized not-found envelope mutation is rejected");
}

#[test]
fn normalized_not_found_accepts_only_the_call_path_status_and_complete_envelope() {
    for status in [None, Some(404)] {
        normalized_not_found_content(&not_found_response(status), 1, "test", status)
            .expect("valid not-found envelope");
    }
    for mutation in [
        "outer_key",
        "content_key",
        "text_mismatch",
        "success",
        "invalid_status",
    ] {
        let mut response = not_found_response(None);
        match mutation {
            "outer_key" => {
                response["extra"] = json!(true);
            }
            "content_key" => {
                response["result"]["content"][0]["extra"] = json!(true);
            }
            "text_mismatch" => {
                response["result"]["content"][0]["text"] = json!("{}");
            }
            "success" => {
                response["result"]["isError"] = json!(false);
            }
            "invalid_status" => {
                response["result"]["structuredContent"]["error"]["http_status"] = json!(500);
                response["result"]["content"][0]["text"] = Value::String(
                    serde_json::to_string(&response["result"]["structuredContent"])
                        .expect("sample serializes"),
                );
            }
            _ => unreachable!(),
        }
        assert!(
            normalized_not_found_content(&response, 1, "test", None).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn content_provisioning_boundaries_never_return_cli_output() {
    let sentinel = "mcp-content-private-sentinel";
    let mut command = bin();
    command.arg(format!("--{sentinel}"));
    let error = seed_content_boundary(
        checked(&mut command, "injected content import"),
        "MCP data-view import failed.",
    )
    .expect_err("the command must fail");
    assert_eq!(error, "MCP data-view import failed.");
    assert!(!error.contains(sentinel));
}

#[cfg(target_os = "linux")]
#[test]
fn reader_start_failure_reaps_the_owned_child_before_returning() {
    let mut command = std::process::Command::new("sleep");
    command
        .arg("60")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn().expect("child starts");
    let pid = child.id();

    let error = match McpChild::from_child(child, |_, _| {
        Err(std::io::Error::other("injected reader startup failure"))
    }) {
        Ok(_) => panic!("reader startup failure must be returned"),
        Err(error) => error,
    };

    assert_eq!(error, "MCP child response reader could not be started.");
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "child must be reaped before the setup error returns"
    );
}

#[test]
fn joining_stdout_panic_still_joins_stderr() {
    let stderr_joined = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&stderr_joined);
    let mut child = McpChild {
        child: None,
        stdin: None,
        replies: mpsc::channel().1,
        stdout_reader: Some(thread::spawn(|| panic!("injected stdout reader panic"))),
        stderr_reader: Some(thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            observed.store(true, Ordering::SeqCst);
        })),
        next_id: 1,
    };

    let error = child
        .join_readers()
        .expect_err("stdout panic is reported after both joins");

    assert_eq!(error, "MCP child reader thread failed.");
    assert!(stderr_joined.load(Ordering::SeqCst));
}

struct RecordingChildren {
    events: Rc<RefCell<Vec<&'static str>>>,
    failure: &'static str,
}

impl McpChildHarness for RecordingChildren {
    type Child = bool;

    fn spawn(&mut self, allow_query_tools: bool) -> TestResult<Self::Child> {
        let event = if allow_query_tools {
            "spawn-query"
        } else {
            "spawn-default"
        };
        self.events.borrow_mut().push(event);
        if self.failure == event {
            Err(event.to_string())
        } else {
            Ok(allow_query_tools)
        }
    }

    fn exercise(&mut self, child: &mut Self::Child, allow_query_tools: bool) -> TestResult {
        assert_eq!(*child, allow_query_tools);
        let event = if allow_query_tools {
            "exercise-query"
        } else {
            "exercise-default"
        };
        self.events.borrow_mut().push(event);
        if self.failure == event {
            Err(event.to_string())
        } else {
            Ok(())
        }
    }

    fn shutdown(&mut self, child: &mut Self::Child) -> TestResult {
        let event = if *child {
            "shutdown-query"
        } else {
            "shutdown-default"
        };
        self.events.borrow_mut().push(event);
        if self.failure == event {
            Err(event.to_string())
        } else {
            Ok(())
        }
    }
}

struct ChildRunSteps {
    events: Rc<RefCell<Vec<&'static str>>>,
    failure: &'static str,
}

impl McpRunSteps for ChildRunSteps {
    fn run_contract(&mut self) -> TestResult {
        self.events.borrow_mut().push("contract");
        run_mcp_children(&mut RecordingChildren {
            events: Rc::clone(&self.events),
            failure: self.failure,
        })
    }
    fn finish_fleet(&mut self) -> TestResult {
        self.events.borrow_mut().push("finish-fleet");
        Ok(())
    }
    fn finish_general(&mut self) -> TestResult {
        self.events.borrow_mut().push("finish-general");
        Ok(())
    }
    fn audit_baseline(&mut self) -> TestResult {
        self.events.borrow_mut().push("audit-baseline");
        Ok(())
    }
}

fn assert_child_failure(failure: &'static str, expected_prefix: &[&'static str]) {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut steps = ChildRunSteps {
        events: Rc::clone(&events),
        failure,
    };
    assert_eq!(
        run_mcp_steps(&mut steps),
        Err(McpOutcomeFailure::Contract(failure.to_string()))
    );
    let mut expected = vec!["contract"];
    expected.extend_from_slice(expected_prefix);
    expected.extend(["finish-fleet", "finish-general", "audit-baseline"]);
    assert_eq!(*events.borrow(), expected, "{failure}");
}

#[test]
fn mcp_default_spawn_failure_runs_all_cleanup_steps() {
    assert_child_failure("spawn-default", &["spawn-default"]);
}

#[test]
fn mcp_default_protocol_failure_attempts_shutdown_and_all_cleanup_steps() {
    assert_child_failure(
        "exercise-default",
        &["spawn-default", "exercise-default", "shutdown-default"],
    );
}

#[test]
fn mcp_default_shutdown_failure_runs_all_cleanup_steps() {
    assert_child_failure(
        "shutdown-default",
        &["spawn-default", "exercise-default", "shutdown-default"],
    );
}

#[test]
fn mcp_query_spawn_failure_runs_all_cleanup_steps() {
    assert_child_failure(
        "spawn-query",
        &[
            "spawn-default",
            "exercise-default",
            "shutdown-default",
            "spawn-query",
        ],
    );
}

#[test]
fn mcp_query_protocol_failure_attempts_shutdown_and_all_cleanup_steps() {
    assert_child_failure(
        "exercise-query",
        &[
            "spawn-default",
            "exercise-default",
            "shutdown-default",
            "spawn-query",
            "exercise-query",
            "shutdown-query",
        ],
    );
}

#[test]
fn mcp_query_shutdown_failure_runs_all_cleanup_steps() {
    assert_child_failure(
        "shutdown-query",
        &[
            "spawn-default",
            "exercise-default",
            "shutdown-default",
            "spawn-query",
            "exercise-query",
            "shutdown-query",
        ],
    );
}

#[test]
fn mcp_fixture_ownership_precedes_first_write() {
    let mut cleanup = LiveCleanup::for_test();
    cleanup.finished = true;
    let wrote = Cell::new(false);
    with_registered_mcp_fixtures(
        &mut cleanup,
        |_| Ok(Some("original-default".to_string())),
        |ids, cleanup| {
            assert!(cleanup.rules.contains(&ids.rule_id));
            assert!(cleanup.rules.contains(&ids.alert_rule));
            assert!(cleanup.lists.contains(&ids.list_id));
            assert!(
                cleanup
                    .items
                    .contains(&(ids.list_id.clone(), ids.item_id.clone()))
            );
            assert!(cleanup.indices.contains(&ids.index));
            assert!(cleanup.data_views.contains(&ids.data_view));
            assert!(cleanup.dashboards.contains(&ids.dashboard));
            assert!(cleanup.alert_rules.contains(&ids.alert_rule));
            assert!(
                cleanup
                    .case_scopes
                    .contains(&(ids.case_title.clone(), LIVE_TAG.to_string()))
            );
            assert_eq!(
                cleanup.default_data_view,
                Some(Some("original-default".to_string()))
            );
            wrote.set(true);
            Ok(())
        },
    )
    .expect("registered ownership permits the first write");
    assert!(wrote.get());

    let mut cleanup = LiveCleanup::for_test();
    cleanup.finished = true;
    let body_called = Cell::new(false);
    assert!(
        with_registered_mcp_fixtures(
            &mut cleanup,
            |_| Err("default read failed".to_string()),
            |_, _| {
                body_called.set(true);
                Ok(())
            },
        )
        .is_err()
    );
    assert!(!body_called.get());
}

#[test]
fn mcp_case_scope_precedes_create_and_id_registration() {
    let title = "mcp-case-scope";
    let mut cleanup = LiveCleanup::for_test();
    cleanup.finished = true;
    cleanup.case_scope(title, LIVE_TAG);
    let observed_scope = Cell::new(false);
    let case_id = create_registered_case(&mut cleanup, title, |cleanup| {
        observed_scope.set(
            cleanup
                .case_scopes
                .contains(&(title.to_string(), LIVE_TAG.to_string())),
        );
        Ok(json!({"id":"case-id"}))
    })
    .expect("decoded id is registered");
    assert_eq!(case_id, "case-id");
    assert!(observed_scope.get());
    assert!(cleanup.cases.contains("case-id"));

    let mut missing_scope = LiveCleanup::for_test();
    missing_scope.finished = true;
    let called = Cell::new(false);
    assert!(
        create_registered_case(&mut missing_scope, title, |_| {
            called.set(true);
            Ok(json!({"id":"unexpected"}))
        })
        .is_err()
    );
    assert!(!called.get());

    for response in [Err("create failed".to_string()), Ok(json!({}))] {
        let mut cleanup = LiveCleanup::for_test();
        cleanup.finished = true;
        cleanup.case_scope(title, LIVE_TAG);
        assert!(create_registered_case(&mut cleanup, title, |_| response).is_err());
        assert!(
            cleanup
                .case_scopes
                .contains(&(title.to_string(), LIVE_TAG.to_string()))
        );
    }
}

struct TrackingBufRead {
    bytes: Vec<u8>,
    position: usize,
    chunk_size: usize,
}

impl TrackingBufRead {
    fn new(bytes: Vec<u8>, chunk_size: usize) -> Self {
        Self {
            bytes,
            position: 0,
            chunk_size,
        }
    }

    fn consumed(&self) -> usize {
        self.position
    }
}

impl Read for TrackingBufRead {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let available = self.fill_buf()?;
        let count = available.len().min(output.len());
        output[..count].copy_from_slice(&available[..count]);
        self.consume(count);
        Ok(count)
    }
}

impl BufRead for TrackingBufRead {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        let end = (self.position + self.chunk_size).min(self.bytes.len());
        Ok(&self.bytes[self.position..end])
    }

    fn consume(&mut self, amount: usize) {
        self.position = (self.position + amount).min(self.bytes.len());
    }
}

struct McpFixtureIds {
    rule_id: String,
    list_id: String,
    item_id: String,
    index: String,
    data_view: String,
    dashboard: String,
    alert_rule: String,
    case_title: String,
}

fn with_registered_mcp_fixtures<T>(
    cleanup: &mut LiveCleanup,
    read_default: impl FnOnce(&Profile) -> TestResult<Option<String>>,
    body: impl FnOnce(&McpFixtureIds, &mut LiveCleanup) -> TestResult<T>,
) -> TestResult<T> {
    let ids = McpFixtureIds {
        rule_id: unique_name("mcp-rule"),
        list_id: unique_name("mcp-exceptions"),
        item_id: unique_name("mcp-exception-item"),
        index: unique_name("mcp-index"),
        data_view: unique_name("mcp-data-view"),
        dashboard: unique_name("mcp-dashboard"),
        alert_rule: unique_name("mcp-alert-rule"),
        case_title: unique_name("mcp-case"),
    };
    cleanup.rule(ids.rule_id.clone());
    cleanup.list(ids.list_id.clone());
    cleanup.item(ids.list_id.clone(), ids.item_id.clone());
    cleanup.index(ids.index.clone());
    cleanup.data_view(ids.data_view.clone());
    cleanup.dashboard(ids.dashboard.clone());
    cleanup.rule(ids.alert_rule.clone());
    cleanup.alert_rule(ids.alert_rule.clone());
    cleanup.case_scope(ids.case_title.clone(), LIVE_TAG);
    let original_default = read_default(&cleanup.profile)?;
    cleanup.restore_default_data_view(original_default);
    body(&ids, cleanup)
}

pub(super) fn run_contract(
    config: &Path,
    scratch: &Path,
    cleanup: &mut LiveCleanup,
    lease: &mut crate::fleet::fixture::FleetFixtureLease,
) -> TestResult {
    with_registered_mcp_fixtures(cleanup, read_validated_default_data_view, |ids, cleanup| {
        let rule_id = &ids.rule_id;
        let list_id = &ids.list_id;
        let item_id = &ids.item_id;
        let index = &ids.index;
        let data_view = &ids.data_view;
        let dashboard = &ids.dashboard;
        let alert_rule = &ids.alert_rule;
        let case_title = &ids.case_title;
        let exceptions = scratch.join("mcp-exceptions.ndjson");
        std::fs::write(
            &exceptions,
            exception_bundle(
                list_id,
                item_id,
                json!([{
                    "field": "host.name",
                    "operator": "included",
                    "type": "match",
                    "value": "elasticctl-live-mcp-smoke",
                }]),
            ),
        )
        .map_err(|_| "MCP live exception fixture could not be written.".to_string())?;
        checked(
            cli(config)
                .args(["exceptions", "import", "--path"])
                .arg(&exceptions)
                .arg("--yes"),
            "MCP live exception import",
        )
        .map_err(|_| "MCP live exception import failed.".to_string())?;

        let rule = scratch.join("mcp-rule.ndjson");
        std::fs::write(
            &rule,
            query_rule(rule_id, index, "host.name: *", Some(list_id)),
        )
        .map_err(|_| "MCP live rule fixture could not be written.".to_string())?;
        checked(
            cli(config)
                .args(["rules", "import", "--path"])
                .arg(&rule)
                .arg("--yes"),
            "MCP live rule import",
        )
        .map_err(|_| "MCP live rule import failed.".to_string())?;

        seed_mcp_content(
            config,
            scratch,
            &cleanup.profile,
            index,
            data_view,
            dashboard,
        )?;
        let profile = cleanup.profile.clone();
        let (alert_id, case_id) =
            prepare_mcp_alert_and_case(&profile, index, alert_rule, case_title, cleanup)?;
        let fleet_runtime = tokio::runtime::Runtime::new()
            .map_err(|_| "MCP Fleet runtime could not be started.".to_string())?;
        fleet_runtime
            .block_on(lease.prepare())
            .map_err(|_| "MCP Fleet fixture could not be prepared.".to_string())?;

        let mut children = LiveMcpChildren {
            config,
            rule_id,
            list_id,
            item_id,
            data_view,
            dashboard,
            alert_rule,
            alert_id: &alert_id,
            case_title,
            case_id: &case_id,
            index,
            lease,
        };
        run_mcp_children(&mut children)
    })
}

trait McpChildHarness {
    type Child;

    fn spawn(&mut self, allow_query_tools: bool) -> TestResult<Self::Child>;
    fn exercise(&mut self, child: &mut Self::Child, allow_query_tools: bool) -> TestResult;
    fn shutdown(&mut self, child: &mut Self::Child) -> TestResult;
}

fn run_mcp_children(harness: &mut impl McpChildHarness) -> TestResult {
    let mut default_child = harness.spawn(false)?;
    let default_protocol = harness.exercise(&mut default_child, false);
    let default_shutdown = harness.shutdown(&mut default_child);
    default_protocol?;
    default_shutdown?;

    let mut query_child = harness.spawn(true)?;
    let query_protocol = harness.exercise(&mut query_child, true);
    let query_shutdown = harness.shutdown(&mut query_child);
    query_protocol?;
    query_shutdown
}

struct LiveMcpChildren<'a> {
    config: &'a Path,
    rule_id: &'a str,
    list_id: &'a str,
    item_id: &'a str,
    data_view: &'a str,
    dashboard: &'a str,
    alert_rule: &'a str,
    alert_id: &'a str,
    case_title: &'a str,
    case_id: &'a str,
    index: &'a str,
    lease: &'a crate::fleet::fixture::FleetFixtureLease,
}

impl McpChildHarness for LiveMcpChildren<'_> {
    type Child = McpChild;

    fn spawn(&mut self, allow_query_tools: bool) -> TestResult<Self::Child> {
        McpChild::spawn(self.config, allow_query_tools)
    }

    fn exercise(&mut self, child: &mut Self::Child, allow_query_tools: bool) -> TestResult {
        if allow_query_tools {
            exercise_query_protocol(child, self.index)
        } else {
            exercise_protocol(
                child,
                self.rule_id,
                self.list_id,
                self.item_id,
                self.data_view,
                self.dashboard,
                self.alert_rule,
                self.alert_id,
                self.case_title,
                self.case_id,
                self.index,
                self.lease,
            )
        }
    }

    fn shutdown(&mut self, child: &mut Self::Child) -> TestResult {
        child.shutdown()
    }
}

fn create_registered_case(
    cleanup: &mut LiveCleanup,
    title: &str,
    create: impl FnOnce(&LiveCleanup) -> TestResult<Value>,
) -> TestResult<String> {
    if !cleanup
        .case_scopes
        .contains(&(title.to_string(), LIVE_TAG.to_string()))
    {
        return Err("MCP case cleanup scope was not registered.".to_string());
    }
    let row = create(cleanup)?;
    let id = row
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "MCP case response had no id.".to_string())?
        .to_string();
    cleanup.case(id.clone());
    Ok(id)
}

fn prepare_mcp_alert_and_case(
    profile: &Profile,
    index: &str,
    rule_id: &str,
    title: &str,
    cleanup: &mut LiveCleanup,
) -> TestResult<(String, String)> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|_| "MCP triage runtime could not be started.".to_string())?;
    let profile = profile.clone();
    let alert_profile = profile.clone();
    let index = index.to_string();
    let rule_id = rule_id.to_string();
    let alert_id = runtime.block_on(async move {
        let transport = Transport::new(&alert_profile).map_err(|_| "MCP triage transport could not be created.".to_string())?;
        let rule = elasticctl_api::model::Rule::from_value(json!({
            "rule_id":rule_id,"name":rule_id,"description":"MCP smoke marker",
            "type":"query","language":"kuery","query":format!("marker: \"{LIVE_TAG}\""),
            "index":[index],"severity":"low","risk_score":21,"enabled":true,
            "from":"now-10m","interval":"1m","tags":[LIVE_TAG],
        })).map_err(|_| "MCP alert rule could not be built.".to_string())?;
        elasticctl_api::rules::create(&transport, &rule).await.map_err(|_| "MCP alert rule could not be created.".to_string())?;
        let mut alert = None;
        for attempt in 0..TRIAGE_POLL_ATTEMPTS {
            let page = elasticctl_api::alerts::search(&transport, &json!({"query":open_marker_rule_alerts_query(&rule_id),"sort":elasticctl_api::alerts_ops::default_sort(),"size":10,"track_total_hits":true,"_source":elasticctl_api::alerts_ops::RESOLVE_SOURCE_FIELDS})).await.map_err(|_| "MCP alert poll failed.".to_string())?;
            if let Some(hit) = page.hits.first() { alert = Some(hit.id.clone()); break; }
            if attempt + 1 < TRIAGE_POLL_ATTEMPTS { tokio::time::sleep(TRIAGE_POLL_INTERVAL).await; }
        }
        let alert = alert.ok_or_else(|| "MCP alert did not appear.".to_string())?;
        Ok::<_, String>(alert)
    })?;
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|_| "MCP case runtime could not be started.".to_string())?;
    let profile = profile.clone();
    let title_owned = title.to_string();
    let case_id = create_registered_case(cleanup, title, move |_| {
        runtime.block_on(async move {
            let transport = Transport::new(&profile)
                .map_err(|_| "MCP triage transport could not be created.".to_string())?;
            let plan = elasticctl_api::cases_ops::plan_create(
                &transport,
                &title_owned,
                Some("MCP smoke case".to_string()),
                vec![LIVE_TAG.to_string()],
                Some("low".to_string()),
                &[],
            )
            .await
            .map_err(|_| "MCP case plan failed.".to_string())?;
            elasticctl_api::cases_ops::apply_create(&transport, &plan)
                .await
                .map_err(|_| "MCP case could not be created.".to_string())
        })
    })?;
    Ok((alert_id, case_id))
}

fn seed_mcp_content(
    config: &Path,
    scratch: &Path,
    profile: &Profile,
    index: &str,
    data_view: &str,
    dashboard: &str,
) -> TestResult {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|_| "MCP content runtime could not be started.".to_string())?;
    let transport = Transport::new(profile)
        .map_err(|_| "MCP content transport could not be created.".to_string())?;
    runtime.block_on(async {
        for seq in 1..=3_i64 {
            transport
                .post_absolute_es(
                    &format!("/{index}/_doc?refresh=wait_for"),
                    &json!({
                        "@timestamp": current_rfc3339(), "seq": seq,
                        "message": format!("elasticctl MCP smoke {seq}"), "marker": LIVE_TAG,
                    }),
                )
                .await
                .map_err(|_| "MCP content document could not be indexed.".to_string())?;
        }
        refresh_content_index(&transport, index)
            .await
            .map_err(|_| "MCP content index could not be refreshed.".to_string())
    })?;
    let view_path = scratch.join("mcp-data-view.json");
    write_json_artifact(
        &view_path,
        &data_view_artifact(data_view, index),
        "MCP data view",
    )?;
    let view = seed_content_boundary(
        checked(
            cli(config)
                .args(["data-views", "import", "--path"])
                .arg(&view_path)
                .args(["--yes", "--json"]),
            "MCP data-view import",
        ),
        "MCP data-view import failed.",
    )?;
    let view_report = seed_content_boundary(
        json_output(&view, "MCP data-view import"),
        "MCP data-view import returned invalid JSON.",
    )?;
    seed_content_boundary(
        assert_single_import_report(&view_report, data_view, "MCP data-view import"),
        "MCP data-view import returned an invalid report.",
    )?;
    seed_content_boundary(
        set_cli_default(config, Some(data_view), "MCP data-view default"),
        "MCP data-view default could not be set.",
    )?;
    let dashboard_path = scratch.join("mcp-dashboard.json");
    write_json_artifact(
        &dashboard_path,
        &dashboard_artifact(dashboard, data_view, "MCP smoke"),
        "MCP dashboard",
    )?;
    let dashboard_out = seed_content_boundary(
        checked(
            cli(config)
                .args(["dashboards", "import", "--path"])
                .arg(&dashboard_path)
                .args(["--yes", "--json"]),
            "MCP dashboard import",
        ),
        "MCP dashboard import failed.",
    )?;
    let dashboard_report = seed_content_boundary(
        json_output(&dashboard_out, "MCP dashboard import"),
        "MCP dashboard import returned invalid JSON.",
    )?;
    seed_content_boundary(
        assert_single_import_report(&dashboard_report, dashboard, "MCP dashboard import"),
        "MCP dashboard import returned an invalid report.",
    )
}

fn seed_content_boundary<T>(result: TestResult<T>, static_error: &'static str) -> TestResult<T> {
    result.map_err(|_| static_error.to_string())
}

#[allow(clippy::too_many_arguments)] // Existing fixture values remain independent until Task 6A's setup review lands.
fn exercise_protocol(
    child: &mut McpChild,
    rule_id: &str,
    list_id: &str,
    item_id: &str,
    data_view: &str,
    dashboard: &str,
    alert_rule: &str,
    alert_id: &str,
    case_title: &str,
    case_id: &str,
    index: &str,
    lease: &crate::fleet::fixture::FleetFixtureLease,
) -> TestResult {
    let initialize = child.request(
        "initialize",
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "elasticctl-live-smoke",
                "version": env!("CARGO_PKG_VERSION"),
            },
        }),
    )?;
    if initialize
        .get("result")
        .and_then(Value::as_object)
        .and_then(|result| result.get("protocolVersion"))
        .and_then(Value::as_str)
        != Some("2025-11-25")
    {
        return Err("MCP initialize did not negotiate the legacy protocol.".to_string());
    }
    child.notify("notifications/initialized", json!({}))?;

    let catalog = child.request("tools/list", json!({}))?;
    validate_catalog(&catalog, false)?;
    child.method_not_found("search_esql")?;
    child.method_not_found("search_dsl")?;

    let exceptions_get = child.tool(
        "exceptions_get",
        json!({
            "list_id": list_id,
            "namespace": "single",
            "limit": 10,
        }),
    )?;
    validate_exceptions_get(&exceptions_get, list_id, item_id)?;

    let exceptions_list = child.tool(
        "exceptions_list",
        json!({
            "tag": LIVE_TAG,
            "namespace": "single",
            "limit": 10,
        }),
    )?;
    validate_exceptions_list(&exceptions_list, list_id)?;

    let rules_get = child.tool("rules_get", json!({"selector": rule_id}))?;
    validate_rules_get(&rules_get, rule_id, list_id)?;

    let rules_list = child.tool(
        "rules_list",
        json!({
            "tag": LIVE_TAG,
            "search": rule_id,
            "source": "custom",
            "limit": 10,
        }),
    )?;
    validate_rules_list(&rules_list, rule_id)?;

    let prebuilt = child.tool("rules_prebuilt_status", json!({}))?;
    validate_prebuilt_status(&prebuilt)?;

    let doctor = child.tool("stack_doctor", json!({}))?;
    validate_doctor(&doctor)?;

    let info = child.tool("stack_info", json!({}))?;
    validate_stack_info(&info)?;

    exercise_inspection_reads(
        child, data_view, dashboard, alert_rule, alert_id, case_title, case_id, index, lease,
    )
}

fn exercise_query_protocol(child: &mut McpChild, index: &str) -> TestResult {
    initialize_child(child, true)?;
    let esql = child.tool(
        "search_esql",
        json!({"query": format!("FROM {index} | WHERE seq >= 1 | SORT seq ASC | KEEP seq, marker"), "limit": 2}),
    )?;
    validate_esql_rows(&esql)?;
    let esql_empty = child.tool(
        "search_esql",
        json!({"query": format!("FROM {index} | WHERE seq < 0 | KEEP seq, marker"), "limit": 2}),
    )?;
    validate_esql_empty(&esql_empty)?;
    let dsl = child.tool(
        "search_dsl",
        json!({"index": index, "query": {"range": {"seq": {"gte": 1}}}, "fields": ["seq", "marker"], "sort": [{"seq": "asc"}], "limit": 2}),
    )?;
    validate_dsl_hits(&dsl, index)?;
    let dsl_empty = child.tool(
        "search_dsl",
        json!({"index": index, "query": {"range": {"seq": {"lt": 0}}}, "fields": ["seq", "marker"], "sort": [{"seq": "asc"}], "limit": 2}),
    )?;
    validate_dsl_empty(&dsl_empty)
}

fn initialize_child(child: &mut McpChild, allow_query_tools: bool) -> TestResult {
    let initialize = child.request("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"elasticctl-live-smoke","version":env!("CARGO_PKG_VERSION")}}))?;
    if initialize
        .pointer("/result/protocolVersion")
        .and_then(Value::as_str)
        != Some("2025-11-25")
    {
        return Err("MCP initialize did not negotiate the legacy protocol.".to_string());
    }
    child.notify("notifications/initialized", json!({}))?;
    let catalog = child.request("tools/list", json!({}))?;
    validate_catalog(&catalog, allow_query_tools)
}

#[allow(clippy::too_many_arguments)] // Each live assertion receives only the identity it owns.
fn exercise_inspection_reads(
    child: &mut McpChild,
    data_view: &str,
    dashboard: &str,
    alert_rule: &str,
    alert_id: &str,
    case_title: &str,
    case_id: &str,
    index: &str,
    lease: &crate::fleet::fixture::FleetFixtureLease,
) -> TestResult {
    let alerts = child.tool(
        "alerts_list",
        json!({"rule": alert_rule, "status":"open", "limit":10}),
    )?;
    validate_alerts_list(&alerts, alert_rule)?;
    validate_empty_list(
        &child.tool(
            "alerts_list",
            json!({"rule":alert_rule,"search":unique_name("missing"),"limit":10}),
        )?,
        "alerts",
    )?;
    validate_alert_get(
        &child.tool("alerts_get", json!({"alert_id":alert_id}))?,
        alert_id,
        alert_rule,
    )?;
    child.not_found(
        "alerts_get",
        json!({"alert_id":unique_name("missing-alert")}),
        None,
    )?;
    let cases = child.tool(
        "cases_list",
        json!({"search":case_title,"tag":LIVE_TAG,"limit":10}),
    )?;
    validate_cases_list(&cases, case_id, case_title)?;
    validate_empty_list(
        &child.tool(
            "cases_list",
            json!({"search":unique_name("missing"),"limit":10}),
        )?,
        "cases",
    )?;
    validate_case_get(
        &child.tool("cases_get", json!({"id":case_id}))?,
        case_id,
        case_title,
    )?;
    child.not_found(
        "cases_get",
        json!({"id":unique_name("missing-case")}),
        Some(404),
    )?;
    let views = child.tool("data_views_list", json!({"search":data_view,"limit":10}))?;
    validate_data_views_list(&views, data_view, index)?;
    validate_empty_list(
        &child.tool(
            "data_views_list",
            json!({"search":unique_name("missing"),"limit":10}),
        )?,
        "data_views",
    )?;
    validate_data_view_get(
        &child.tool("data_views_get", json!({"selector":data_view}))?,
        data_view,
        index,
    )?;
    child.not_found(
        "data_views_get",
        json!({"selector":unique_name("missing-view")}),
        None,
    )?;
    validate_default_data_view(&child.tool("data_views_default_get", json!({}))?, data_view)?;
    let dashboards = child.tool("dashboards_list", json!({"search":dashboard,"limit":10}))?;
    validate_dashboards_list(&dashboards, dashboard)?;
    validate_empty_list(
        &child.tool(
            "dashboards_list",
            json!({"search":unique_name("missing"),"limit":10}),
        )?,
        "dashboards",
    )?;
    validate_dashboard_get(
        &child.tool("dashboards_get", json!({"selector":dashboard}))?,
        dashboard,
        data_view,
    )?;
    child.not_found(
        "dashboards_get",
        json!({"selector":unique_name("missing-dashboard")}),
        None,
    )?;
    let agent_list = child.tool(
        "fleet_agent_policies_list",
        json!({"search":lease.parent_id(),"limit":10}),
    )?;
    validate_agent_policy_list(&agent_list, lease.parent_id())?;
    validate_empty_list(
        &child.tool(
            "fleet_agent_policies_list",
            json!({"search":unique_name("missing"),"limit":10}),
        )?,
        "agent_policies",
    )?;
    validate_agent_policy_get(
        &child.tool(
            "fleet_agent_policies_get",
            json!({"selector":lease.parent_id()}),
        )?,
        lease.parent_id(),
    )?;
    child.not_found(
        "fleet_agent_policies_get",
        json!({"selector":unique_name("missing-agent-policy")}),
        None,
    )?;
    let integration_list = child.tool(
        "fleet_integration_policies_list",
        json!({"search":lease.integration_id(),"limit":10}),
    )?;
    validate_integration_policy_list(&integration_list, lease.integration_id(), lease.parent_id())?;
    validate_empty_list(
        &child.tool(
            "fleet_integration_policies_list",
            json!({"search":unique_name("missing"),"limit":10}),
        )?,
        "integration_policies",
    )?;
    validate_integration_policy_get(
        &child.tool(
            "fleet_integration_policies_get",
            json!({"selector":lease.integration_id()}),
        )?,
        lease.integration_id(),
        lease.parent_id(),
    )?;
    child.not_found(
        "fleet_integration_policies_get",
        json!({"selector":unique_name("missing-integration-policy")}),
        None,
    )?;
    Ok(())
}

fn validate_selected_projection(
    value: &Value,
    allowed: &[&str],
    required: &[&str],
    projection: &str,
) -> TestResult {
    let object = value
        .as_object()
        .ok_or_else(|| format!("MCP {projection} was not an object."))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("MCP {projection} exposed an unexpected field."));
    }
    if required.iter().any(|key| !object.contains_key(*key)) {
        return Err(format!("MCP {projection} omitted a required field."));
    }
    Ok(())
}

fn validate_alerts_list(content: &Value, rule_id: &str) -> TestResult {
    let data = object_field(content, "data", "alerts_list")?;
    assert_exact_keys(data, &["alerts"], "alerts_list data")?;
    let alerts = map_array_field(data, "alerts", "alerts_list data")?;
    if alerts.is_empty() {
        return Err("MCP alerts_list returned no owned alerts.".to_string());
    }
    for alert in alerts {
        let alert = alert
            .as_object()
            .ok_or_else(|| "MCP alerts_list row was not an object.".to_string())?;
        assert_allowed_keys(alert, &["id", "index", "source"], "alerts_list row")?;
        require_nonempty_string(alert, "id", "alerts_list row")?;
        require_nonempty_string(alert, "index", "alerts_list row")?;
        let source = map_object_field(alert, "source", "alerts_list row")?;
        assert_allowed_keys(
            source,
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
            "alerts_list source",
        )?;
        require_matching_string(
            source,
            "kibana.alert.rule.rule_id",
            rule_id,
            "alerts_list source",
        )?;
        validate_owned_alert_source(source, rule_id, "alerts_list source")?;
    }
    validate_page_rows(content, 10, alerts.len(), false)
}

fn validate_alert_get(content: &Value, alert_id: &str, rule_id: &str) -> TestResult {
    let alert = object_field(content, "data", "alerts_get")?;
    assert_allowed_keys(alert, &["id", "index", "source"], "alerts_get data")?;
    require_matching_string(alert, "id", alert_id, "alerts_get data")?;
    require_nonempty_string(alert, "index", "alerts_get data")?;
    let source = map_object_field(alert, "source", "alerts_get data")?;
    assert_allowed_keys(
        source,
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
        "alerts_get source",
    )?;
    validate_owned_alert_source(source, rule_id, "alerts_get source")?;
    require_null_page(content, "alerts_get")
}

fn validate_owned_alert_source(
    source: &serde_json::Map<String, Value>,
    rule_id: &str,
    context: &'static str,
) -> TestResult {
    require_matching_string(source, "kibana.alert.rule.rule_id", rule_id, context)?;
    require_matching_string(source, "kibana.alert.rule.name", rule_id, context)?;
    require_matching_string(source, "kibana.alert.severity", "low", context)?;
    require_matching_string(source, "kibana.alert.workflow_status", "open", context)?;
    require_nonempty_string(source, "@timestamp", context)?;
    if source
        .get("kibana.alert.risk_score")
        .and_then(Value::as_f64)
        != Some(21.0)
    {
        return Err(format!(
            "MCP {context} did not preserve the owned risk score."
        ));
    }
    if source
        .get("kibana.alert.workflow_tags")
        .is_some_and(|tags| {
            !tags
                .as_array()
                .is_some_and(|tags| tags.iter().all(Value::is_string))
        })
    {
        return Err(format!("MCP {context} had invalid workflow tags."));
    }
    Ok(())
}

fn validate_cases_list(content: &Value, case_id: &str, title: &str) -> TestResult {
    let data = object_field(content, "data", "cases_list")?;
    assert_exact_keys(data, &["cases"], "cases_list data")?;
    let cases = map_array_field(data, "cases", "cases_list data")?;
    if cases.len() != 1 {
        return Err("MCP cases_list did not return exactly one owned case.".to_string());
    }
    validate_case_row(
        cases[0]
            .as_object()
            .ok_or_else(|| "MCP cases_list row was not an object.".to_string())?,
        case_id,
        Some(title),
    )?;
    validate_page_rows(content, 10, 1, false)
}
fn validate_case_get(content: &Value, case_id: &str, title: &str) -> TestResult {
    let case = object_field(content, "data", "cases_get")?;
    validate_case_row(case, case_id, Some(title))?;
    require_null_page(content, "cases_get")
}
fn validate_case_row(
    case: &serde_json::Map<String, Value>,
    case_id: &str,
    title: Option<&str>,
) -> TestResult {
    assert_allowed_keys(
        case,
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
        "case data",
    )?;
    require_matching_string(case, "id", case_id, "case data")?;
    if let Some(title) = title {
        require_matching_string(case, "title", title, "case data")?;
    } else {
        require_nonempty_string(case, "title", "case data")?;
    }
    require_matching_string(case, "status", "open", "case data")?;
    require_matching_string(case, "severity", "low", "case data")?;
    require_matching_string(case, "description", "MCP smoke case", "case data")?;
    for field in ["created_at", "updated_at"] {
        if case.contains_key(field) {
            require_nonempty_string(case, field, "case data")?;
        }
    }
    if !case
        .get("tags")
        .and_then(Value::as_array)
        .is_some_and(|tags| tags.len() == 1 && tags[0].as_str() == Some(LIVE_TAG))
        || case.get("totalComment").and_then(Value::as_u64).is_none()
    {
        return Err("MCP case data omitted owned values.".to_string());
    }
    Ok(())
}

fn validate_data_views_list(content: &Value, id: &str, index: &str) -> TestResult {
    let data = object_field(content, "data", "data_views_list")?;
    assert_exact_keys(data, &["data_views"], "data_views_list data")?;
    let rows = map_array_field(data, "data_views", "data_views_list data")?;
    if rows.len() != 1 {
        return Err("MCP data_views_list did not return exactly one owned data view.".to_string());
    };
    let row = rows[0]
        .as_object()
        .ok_or_else(|| "MCP data_views_list row was not an object.".to_string())?;
    assert_allowed_keys(
        row,
        &["id", "title", "name", "timeFieldName"],
        "data_views_list row",
    )?;
    require_matching_string(row, "id", id, "data_views_list row")?;
    require_matching_string(row, "title", index, "data_views_list row")?;
    require_matching_string(row, "name", id, "data_views_list row")?;
    require_matching_string(row, "timeFieldName", "@timestamp", "data_views_list row")?;
    validate_page_rows(content, 10, 1, false)
}
fn validate_data_view_get(content: &Value, id: &str, index: &str) -> TestResult {
    let data = object_field(content, "data", "data_views_get")?;
    assert_exact_keys(data, &["data_view"], "data_views_get data")?;
    let row = map_object_field(data, "data_view", "data_views_get data")?;
    assert_allowed_keys(
        row,
        &[
            "id",
            "title",
            "name",
            "timeFieldName",
            "type",
            "allowNoIndex",
            "allowHidden",
            "sourceFilters",
            "fieldFormats",
            "runtimeFieldMap",
            "fieldAttrs",
            "typeMeta",
        ],
        "data_views_get data_view",
    )?;
    require_matching_string(row, "id", id, "data_views_get data_view")?;
    require_matching_string(row, "title", index, "data_views_get data_view")?;
    require_matching_string(row, "name", id, "data_views_get data_view")?;
    require_matching_string(
        row,
        "timeFieldName",
        "@timestamp",
        "data_views_get data_view",
    )?;
    for field in ["type"] {
        if row.contains_key(field) {
            require_nonempty_string(row, field, "data_views_get data_view")?;
        }
    }
    for field in ["allowNoIndex", "allowHidden"] {
        if row.contains_key(field) && !row.get(field).is_some_and(Value::is_boolean) {
            return Err("MCP data_views_get data view had an invalid boolean field.".to_string());
        }
    }
    for field in ["sourceFilters"] {
        if row.contains_key(field) && !row.get(field).is_some_and(Value::is_array) {
            return Err("MCP data_views_get data view had an invalid array field.".to_string());
        }
    }
    for field in ["fieldFormats", "runtimeFieldMap", "fieldAttrs", "typeMeta"] {
        if row.contains_key(field) && !row.get(field).is_some_and(Value::is_object) {
            return Err("MCP data_views_get data view had an invalid object field.".to_string());
        }
    }
    require_null_page(content, "data_views_get")
}
fn validate_default_data_view(content: &Value, id: &str) -> TestResult {
    let data = object_field(content, "data", "data_views_default_get")?;
    assert_exact_keys(data, &["id"], "data_views_default_get data")?;
    require_matching_string(data, "id", id, "data_views_default_get data")?;
    require_null_page(content, "data_views_default_get")
}
fn validate_dashboards_list(content: &Value, id: &str) -> TestResult {
    let data = object_field(content, "data", "dashboards_list")?;
    assert_exact_keys(data, &["dashboards"], "dashboards_list data")?;
    let rows = map_array_field(data, "dashboards", "dashboards_list data")?;
    if rows.len() != 1 {
        return Err("MCP dashboards_list did not return exactly one owned dashboard.".to_string());
    };
    let row = rows[0]
        .as_object()
        .ok_or_else(|| "MCP dashboards_list row was not an object.".to_string())?;
    assert_allowed_keys(
        row,
        &["id", "title", "description", "tags"],
        "dashboards_list row",
    )?;
    require_matching_string(row, "id", id, "dashboards_list row")?;
    require_matching_string(row, "title", id, "dashboards_list row")?;
    if row
        .get("description")
        .is_some_and(|description| !description.is_string())
        || row.get("tags").is_some_and(|tags| {
            !tags
                .as_array()
                .is_some_and(|tags| tags.iter().all(Value::is_string))
        })
    {
        return Err("MCP dashboards_list row had an invalid optional field type.".to_string());
    }
    validate_page_rows(content, 10, 1, false)
}
fn validate_dashboard_get(content: &Value, id: &str, data_view: &str) -> TestResult {
    let data = object_field(content, "data", "dashboards_get")?;
    assert_exact_keys(data, &["id", "data"], "dashboards_get data")?;
    require_matching_string(data, "id", id, "dashboards_get data")?;
    let body = map_object_field(data, "data", "dashboards_get data")?;
    require_matching_string(body, "title", id, "dashboards_get data")?;
    let panels = map_array_field(body, "panels", "dashboards_get data")?;
    let reference = panels
        .first()
        .and_then(Value::as_object)
        .and_then(|panel| panel.get("config"))
        .and_then(Value::as_object)
        .and_then(|config| config.get("data_source"))
        .and_then(Value::as_object)
        .ok_or_else(|| "MCP dashboards_get data omitted its panel data source.".to_string())?;
    if reference.get("type").and_then(Value::as_str) != Some("data_view_reference")
        || reference.get("ref_id").and_then(Value::as_str) != Some(data_view)
    {
        return Err("MCP dashboards_get data omitted its owned data-view reference.".to_string());
    }
    require_null_page(content, "dashboards_get")
}

fn validate_agent_policy_list(content: &Value, id: &str) -> TestResult {
    validate_fleet_list(
        content,
        "fleet_agent_policies_list",
        "agent_policies",
        id,
        false,
        None,
    )
}
fn validate_agent_policy_get(content: &Value, id: &str) -> TestResult {
    let data = object_field(content, "data", "fleet_agent_policies_get")?;
    validate_agent_policy(data, id, true)?;
    require_null_page(content, "fleet_agent_policies_get")
}
fn validate_integration_policy_list(content: &Value, id: &str, parent: &str) -> TestResult {
    validate_fleet_list(
        content,
        "fleet_integration_policies_list",
        "integration_policies",
        id,
        true,
        Some(parent),
    )
}
fn validate_integration_policy_get(content: &Value, id: &str, parent: &str) -> TestResult {
    let data = object_field(content, "data", "fleet_integration_policies_get")?;
    validate_integration_policy(data, id, parent, true)?;
    require_null_page(content, "fleet_integration_policies_get")
}
fn validate_fleet_list(
    content: &Value,
    tool: &'static str,
    key: &'static str,
    id: &str,
    integration: bool,
    parent: Option<&str>,
) -> TestResult {
    let data = object_field(content, "data", tool)?;
    assert_exact_keys(data, &[key], "Fleet list data")?;
    let rows = map_array_field(data, key, "Fleet list data")?;
    if rows.len() != 1 {
        return Err(format!(
            "MCP {tool} did not return exactly one owned policy."
        ));
    };
    let row = rows[0]
        .as_object()
        .ok_or_else(|| format!("MCP {tool} row was not an object."))?;
    if integration {
        validate_integration_policy(row, id, parent.expect("parent"), false)?
    } else {
        validate_agent_policy(row, id, false)?
    };
    validate_page_rows(content, 10, 1, false)
}
fn validate_agent_policy(
    row: &serde_json::Map<String, Value>,
    id: &str,
    detail: bool,
) -> TestResult {
    let allowed = if detail {
        &[
            "id",
            "name",
            "namespace",
            "description",
            "agents",
            "status",
            "attached_integrations",
            "blocked_by",
        ][..]
    } else {
        &["id", "name", "namespace", "description", "agents"][..]
    };
    assert_allowed_keys(row, allowed, "Fleet agent policy")?;
    let required = if detail {
        &[
            "id",
            "name",
            "namespace",
            "agents",
            "attached_integrations",
            "blocked_by",
        ][..]
    } else {
        &["id", "name", "namespace"][..]
    };
    if required.iter().any(|field| !row.contains_key(*field)) {
        return Err("MCP Fleet agent policy omitted a required field.".to_string());
    }
    for field in ["id", "name", "namespace"] {
        require_nonempty_string(row, field, "Fleet agent policy")?
    }
    require_matching_string(row, "id", id, "Fleet agent policy")?;
    if row
        .get("description")
        .is_some_and(|value| !value.is_string())
        || row.get("agents").is_some_and(|value| !value.is_u64())
        || row.get("status").is_some_and(|value| !value.is_string())
        || row.get("attached_integrations").is_some_and(|value| {
            !value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string))
        })
        || row.get("blocked_by").is_some_and(|value| {
            !value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string))
        })
    {
        return Err("MCP Fleet agent policy contained an invalid field type.".to_string());
    }
    if detail
        && (!row.get("agents").is_some_and(Value::is_u64)
            || !row
                .get("attached_integrations")
                .is_some_and(Value::is_array)
            || !row.get("blocked_by").is_some_and(Value::is_array))
    {
        return Err("MCP Fleet agent policy omitted detail values.".to_string());
    };
    Ok(())
}
fn validate_integration_policy(
    row: &serde_json::Map<String, Value>,
    id: &str,
    parent: &str,
    detail: bool,
) -> TestResult {
    let allowed = if detail {
        &[
            "id",
            "name",
            "namespace",
            "description",
            "policy_ids",
            "package",
            "affected_agents",
            "blocked_by",
        ][..]
    } else {
        &[
            "id",
            "name",
            "namespace",
            "description",
            "policy_ids",
            "package",
        ][..]
    };
    assert_allowed_keys(row, allowed, "Fleet integration policy")?;
    let required = if detail {
        &[
            "id",
            "name",
            "namespace",
            "policy_ids",
            "package",
            "affected_agents",
            "blocked_by",
        ][..]
    } else {
        &["id", "name", "namespace", "policy_ids", "package"][..]
    };
    if required.iter().any(|field| !row.contains_key(*field)) {
        return Err("MCP Fleet integration policy omitted a required field.".to_string());
    }
    for field in ["id", "name", "namespace"] {
        require_nonempty_string(row, field, "Fleet integration policy")?
    }
    require_matching_string(row, "id", id, "Fleet integration policy")?;
    let policies = row
        .get("policy_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| "MCP Fleet integration policy omitted policy ids.".to_string())?;
    if policies.len() != 1 || !policies.iter().all(|value| value.as_str() == Some(parent)) {
        return Err("MCP Fleet integration policy omitted its owned parent relation.".to_string());
    };
    let package = map_object_field(row, "package", "Fleet integration policy")?;
    assert_exact_keys(package, &["name", "version"], "Fleet package")?;
    require_matching_string(package, "name", "system", "Fleet package")?;
    require_nonempty_string(package, "version", "Fleet package")?;
    if row
        .get("description")
        .is_some_and(|value| !value.is_string())
        || row
            .get("affected_agents")
            .is_some_and(|value| !value.is_u64())
        || row.get("blocked_by").is_some_and(|value| {
            !value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string))
        })
    {
        return Err("MCP Fleet integration policy contained an invalid field type.".to_string());
    }
    if detail
        && (!row.get("affected_agents").is_some_and(Value::is_u64)
            || !row.get("blocked_by").is_some_and(Value::is_array))
    {
        return Err("MCP Fleet integration policy omitted detail values.".to_string());
    };
    Ok(())
}

fn validate_empty_list(content: &Value, key: &'static str) -> TestResult {
    let data = object_field(content, "data", "list result")?;
    assert_exact_keys(data, &[key], "empty list data")?;
    let rows = map_array_field(data, key, "list result")?;
    if !rows.is_empty() {
        return Err(format!("MCP {key} empty list contained rows."));
    };
    validate_page_rows(content, 10, 0, false)
}
fn validate_page_rows(content: &Value, limit: u64, returned: usize, truncated: bool) -> TestResult {
    let page = object_field(content, "page", "tool result")?;
    assert_exact_keys(
        page,
        &["limit", "returned", "total", "has_more", "truncated"],
        "tool result page",
    )?;
    if page.get("limit").and_then(Value::as_u64) != Some(limit)
        || page.get("returned").and_then(Value::as_u64) != Some(returned as u64)
        || page.get("truncated") != Some(&Value::Bool(truncated))
        || page.get("has_more") != Some(&Value::Bool(truncated))
    {
        return Err("MCP tool result page did not match returned rows.".to_string());
    };
    if let Some(total) = page.get("total").and_then(Value::as_u64) {
        if total < returned as u64 {
            return Err("MCP tool result page total was smaller than returned rows.".to_string());
        }
    } else {
        return Err("MCP tool result page omitted total.".to_string());
    };
    Ok(())
}
fn validate_esql_rows(content: &Value) -> TestResult {
    let data = object_field(content, "data", "search_esql")?;
    assert_exact_keys(
        data,
        &["columns", "values", "is_partial"],
        "search_esql data",
    )?;
    let columns = map_array_field(data, "columns", "search_esql data")?;
    if columns.len() != 2 {
        return Err("MCP search_esql columns differed from the requested projection.".to_string());
    }
    for (column, (name, kind)) in columns.iter().zip([("seq", "long"), ("marker", "keyword")]) {
        let column = column
            .as_object()
            .ok_or_else(|| "MCP search_esql column was not an object.".to_string())?;
        assert_exact_keys(column, &["name", "type"], "search_esql column")?;
        require_matching_string(column, "name", name, "search_esql column")?;
        require_matching_string(column, "type", kind, "search_esql column")?;
    }
    if data.get("is_partial") != Some(&Value::Bool(false)) {
        return Err("MCP search_esql did not preserve a complete result.".to_string());
    }
    let values = map_array_field(data, "values", "search_esql data")?;
    if values.len() != 2
        || values[0]
            .as_array()
            .and_then(|r| r.first())
            .and_then(Value::as_i64)
            != Some(1)
        || values[1]
            .as_array()
            .and_then(|r| r.first())
            .and_then(Value::as_i64)
            != Some(2)
        || values
            .iter()
            .any(|row| row.as_array().is_none_or(|row| row.len() != 2))
        || values
            .iter()
            .any(|r| r.as_array().and_then(|r| r.get(1)).and_then(Value::as_str) != Some(LIVE_TAG))
    {
        return Err("MCP search_esql rows did not preserve owned values.".to_string());
    };
    validate_query_page(content, 2, 2, true)
}
fn validate_esql_empty(content: &Value) -> TestResult {
    let data = object_field(content, "data", "search_esql")?;
    assert_exact_keys(
        data,
        &["columns", "values", "is_partial"],
        "search_esql data",
    )?;
    let columns = map_array_field(data, "columns", "search_esql data")?;
    if columns.len() != 2 || data.get("is_partial") != Some(&Value::Bool(false)) {
        return Err("MCP search_esql empty query changed its projection.".to_string());
    }
    for (column, (name, kind)) in columns.iter().zip([("seq", "long"), ("marker", "keyword")]) {
        let column = column
            .as_object()
            .ok_or_else(|| "MCP search_esql column was not an object.".to_string())?;
        assert_exact_keys(column, &["name", "type"], "search_esql column")?;
        require_matching_string(column, "name", name, "search_esql column")?;
        require_matching_string(column, "type", kind, "search_esql column")?;
    }
    if !map_array_field(data, "values", "search_esql data")?.is_empty() {
        return Err("MCP search_esql empty query returned rows.".to_string());
    };
    validate_query_page(content, 2, 0, false)
}
fn validate_dsl_hits(content: &Value, index: &str) -> TestResult {
    let data = object_field(content, "data", "search_dsl")?;
    assert_exact_keys(data, &["hits"], "search_dsl data")?;
    let hits = map_array_field(data, "hits", "search_dsl data")?;
    if hits.len() != 2 {
        return Err("MCP search_dsl did not return two hits.".to_string());
    };
    for (seq, hit) in [1_i64, 2].into_iter().zip(hits) {
        let hit = hit
            .as_object()
            .ok_or_else(|| "MCP search_dsl hit was not an object.".to_string())?;
        assert_exact_keys(hit, &["id", "index", "score", "source"], "search_dsl hit")?;
        require_nonempty_string(hit, "id", "search_dsl hit")?;
        require_matching_string(hit, "index", index, "search_dsl hit")?;
        if !hit
            .get("score")
            .is_some_and(|score| score.is_null() || score.is_number())
        {
            return Err("MCP search_dsl hit had an invalid score.".to_string());
        }
        let source = map_object_field(hit, "source", "search_dsl hit")?;
        assert_exact_keys(source, &["seq", "marker"], "search_dsl source")?;
        if source.get("seq").and_then(Value::as_i64) != Some(seq)
            || source.get("marker").and_then(Value::as_str) != Some(LIVE_TAG)
        {
            return Err("MCP search_dsl hit did not preserve owned source.".to_string());
        }
    }
    validate_query_page(content, 2, 2, true)
}
fn validate_dsl_empty(content: &Value) -> TestResult {
    let data = object_field(content, "data", "search_dsl")?;
    assert_exact_keys(data, &["hits"], "search_dsl data")?;
    if !map_array_field(data, "hits", "search_dsl data")?.is_empty() {
        return Err("MCP search_dsl empty query returned hits.".to_string());
    };
    validate_query_page(content, 2, 0, false)
}
fn validate_query_page(
    content: &Value,
    limit: u64,
    returned: usize,
    truncated: bool,
) -> TestResult {
    let page = object_field(content, "page", "query result")?;
    assert_exact_keys(
        page,
        &["limit", "returned", "total", "has_more", "truncated"],
        "query result page",
    )?;
    let expected_more = if truncated {
        Value::Bool(true)
    } else {
        Value::Null
    };
    if page.get("limit").and_then(Value::as_u64) != Some(limit)
        || page.get("returned").and_then(Value::as_u64) != Some(returned as u64)
        || page.get("total") != Some(&Value::Null)
        || page.get("truncated") != Some(&Value::Bool(truncated))
        || page.get("has_more") != Some(&expected_more)
    {
        return Err("MCP query page did not match bounded result rows.".to_string());
    };
    Ok(())
}

struct McpChild {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    replies: Receiver<Result<Option<Vec<u8>>, &'static str>>,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<()>>,
    next_id: u64,
}

struct ChildOwner {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<()>>,
}

impl ChildOwner {
    fn new(child: Child) -> Self {
        Self {
            child: Some(child),
            stdin: None,
            stdout_reader: None,
            stderr_reader: None,
        }
    }

    fn into_child(mut self, replies: Receiver<Result<Option<Vec<u8>>, &'static str>>) -> McpChild {
        McpChild {
            child: self.child.take(),
            stdin: self.stdin.take(),
            replies,
            stdout_reader: self.stdout_reader.take(),
            stderr_reader: self.stderr_reader.take(),
            next_id: 1,
        }
    }
}

impl Drop for ChildOwner {
    fn drop(&mut self) {
        self.stdin.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = join_reader_handles(&mut self.stdout_reader, &mut self.stderr_reader);
    }
}

impl McpChild {
    fn spawn(config: &Path, allow_query_tools: bool) -> TestResult<Self> {
        let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin!("elasticctl"));
        command
            .arg("--config")
            .arg(config)
            .args(["mcp", "serve"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if allow_query_tools {
            command.arg("--allow-query-tools");
        }
        let child = command
            .spawn()
            .map_err(|_| "MCP child could not be started.".to_string())?;
        Self::from_child(child, |name, task| {
            thread::Builder::new().name(name.to_string()).spawn(task)
        })
    }

    fn from_child<F>(child: Child, mut start_reader: F) -> TestResult<Self>
    where
        F: FnMut(&'static str, Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>>,
    {
        let mut owner = ChildOwner::new(child);
        let stdin = owner
            .child
            .as_mut()
            .and_then(|child| child.stdin.take())
            .ok_or_else(|| "MCP child stdin could not be opened.".to_string())?;
        owner.stdin = Some(stdin);
        let stdout = owner
            .child
            .as_mut()
            .and_then(|child| child.stdout.take())
            .ok_or_else(|| "MCP child stdout could not be opened.".to_string())?;
        let stderr = owner
            .child
            .as_mut()
            .and_then(|child| child.stderr.take())
            .ok_or_else(|| "MCP child stderr could not be opened.".to_string())?;
        let (sender, replies) = mpsc::channel();
        let stdout_reader = start_reader(
            "elasticctl-mcp-live-stdout",
            Box::new(move || {
                let mut reader = BufReader::new(stdout);
                loop {
                    let frame = read_bounded_frame(&mut reader);
                    let terminal = !matches!(frame, Ok(Some(_)));
                    if sender.send(frame).is_err() || terminal {
                        return;
                    }
                }
            }),
        )
        .map_err(|_| "MCP child response reader could not be started.".to_string())?;
        owner.stdout_reader = Some(stdout_reader);
        let stderr_reader = start_reader(
            "elasticctl-mcp-live-stderr",
            Box::new(move || {
                let mut stderr = stderr;
                let _ = std::io::copy(&mut stderr, &mut std::io::sink());
            }),
        )
        .map_err(|_| "MCP child stderr reader could not be started.".to_string())?;
        owner.stderr_reader = Some(stderr_reader);
        Ok(owner.into_child(replies))
    }

    fn request(&mut self, method: &'static str, params: Value) -> TestResult<Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        let response = self.receive(method)?;
        if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(format!("MCP {method} response was not JSON-RPC 2.0."));
        }
        if response.get("id").and_then(Value::as_u64) != Some(id) {
            return Err(format!(
                "MCP {method} response id did not match its request."
            ));
        }
        if response.get("error").is_some() || response.get("result").is_none() {
            return Err(format!("MCP {method} request returned an error."));
        }
        Ok(response)
    }

    fn notify(&mut self, method: &'static str, params: Value) -> TestResult {
        self.send(json!({"jsonrpc": "2.0", "method": method, "params": params}))
    }

    fn tool(&mut self, tool: &'static str, arguments: Value) -> TestResult<Value> {
        let response = self.request("tools/call", json!({"name": tool, "arguments": arguments}))?;
        successful_tool_content(&response, self.next_id - 1, tool)
    }

    fn method_not_found(&mut self, tool: &'static str) -> TestResult {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":{}}}))?;
        let response = self.receive("tools/call")?;
        if response.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
            && response.get("id").and_then(Value::as_u64) == Some(id)
            && response.pointer("/error/code").and_then(Value::as_i64) == Some(-32601)
        {
            Ok(())
        } else {
            Err(format!(
                "MCP {tool} was unexpectedly available to the default child."
            ))
        }
    }

    fn not_found(
        &mut self,
        tool: &'static str,
        arguments: Value,
        http_status: Option<u64>,
    ) -> TestResult {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":arguments}}))?;
        let response = self.receive("tools/call")?;
        normalized_not_found_content(&response, id, tool, http_status)
    }

    fn send(&mut self, request: Value) -> TestResult {
        let mut frame = serde_json::to_vec(&request)
            .map_err(|_| "MCP request could not be serialized.".to_string())?;
        frame.push(b'\n');
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| "MCP child stdin is closed.".to_string())?;
        stdin
            .write_all(&frame)
            .map_err(|_| "MCP request could not be written.".to_string())?;
        stdin
            .flush()
            .map_err(|_| "MCP request could not be flushed.".to_string())
    }

    fn receive(&mut self, method: &'static str) -> TestResult<Value> {
        let frame = match self.replies.recv_timeout(REPLY_TIMEOUT) {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) => return Err(format!("MCP {method} closed stdout before replying.")),
            Ok(Err(error)) => {
                self.force_stop();
                return Err(error.to_string());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.force_stop();
                return Err(format!("MCP {method} reply timed out."));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.force_stop();
                return Err("MCP child response reader stopped unexpectedly.".to_string());
            }
        };
        parse_response_frame(&frame)
    }

    fn shutdown(&mut self) -> TestResult {
        self.stdin.take();
        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        loop {
            let Some(child) = self.child.as_mut() else {
                return Err("MCP child was unavailable during shutdown.".to_string());
            };
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.child.take();
                    self.join_readers()?;
                    if status.success() {
                        return Ok(());
                    }
                    return Err("MCP child exited unsuccessfully.".to_string());
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    self.child.take();
                    let _ = self.join_readers();
                    return Err("MCP child did not stop after stdin closed.".to_string());
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    self.child.take();
                    let _ = self.join_readers();
                    return Err("MCP child status could not be read.".to_string());
                }
            }
        }
    }

    fn join_readers(&mut self) -> TestResult {
        if join_reader_handles(&mut self.stdout_reader, &mut self.stderr_reader) {
            return Err("MCP child reader thread failed.".to_string());
        }
        Ok(())
    }

    fn force_stop(&mut self) {
        self.stdin.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = self.join_readers();
    }
}

fn join_reader_handles(
    stdout_reader: &mut Option<JoinHandle<()>>,
    stderr_reader: &mut Option<JoinHandle<()>>,
) -> bool {
    let stdout_failed = stdout_reader
        .take()
        .is_some_and(|reader| reader.join().is_err());
    let stderr_failed = stderr_reader
        .take()
        .is_some_and(|reader| reader.join().is_err());
    stdout_failed || stderr_failed
}

impl Drop for McpChild {
    fn drop(&mut self) {
        self.force_stop();
    }
}

fn read_bounded_frame<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, &'static str> {
    let mut frame = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|_| "MCP child response stream could not be read.")?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err("MCP child response frame was truncated.")
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let content = newline.map_or(available.len(), |index| index);
        if content > MAX_FRAME_BYTES.saturating_sub(frame.len()) {
            return Err("MCP child response frame exceeded the size limit.");
        }
        frame.extend_from_slice(&available[..content]);
        reader.consume(content + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(frame));
        }
    }
}

fn parse_response_frame(frame: &[u8]) -> TestResult<Value> {
    serde_json::from_slice(frame).map_err(|_| "MCP child response was not valid JSON.".to_string())
}

fn required_catalog() -> Vec<Value> {
    [
        "alerts_get",
        "alerts_list",
        "cases_get",
        "cases_list",
        "dashboards_get",
        "dashboards_list",
        "data_views_default_get",
        "data_views_get",
        "data_views_list",
        "exceptions_get",
        "exceptions_list",
        "fleet_agent_policies_get",
        "fleet_agent_policies_list",
        "fleet_integration_policies_get",
        "fleet_integration_policies_list",
        "rules_get",
        "rules_list",
        "rules_prebuilt_status",
        "stack_doctor",
        "stack_info",
    ]
    .into_iter()
    .map(|name| json!({"name": name}))
    .collect()
}

fn validate_catalog(catalog: &Value, allow_query_tools: bool) -> TestResult {
    let result = catalog
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| "MCP tools/list response has no tool catalog.".to_string())?;
    assert_allowed_keys(result, &["tools", "nextCursor"], "tools/list response")?;
    if result
        .get("nextCursor")
        .is_some_and(|cursor| !cursor.is_null())
    {
        return Err(
            "MCP tools/list response included an unexpected continuation cursor.".to_string(),
        );
    }
    let tools = result
        .get("tools")
        .and_then(Value::as_array)
        .ok_or_else(|| "MCP tools/list response has no tool catalog.".to_string())?;
    let names = tools
        .iter()
        .map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "MCP tools/list response has an invalid tool catalog.".to_string())?;
    let mut required = vec![
        "alerts_get",
        "alerts_list",
        "cases_get",
        "cases_list",
        "dashboards_get",
        "dashboards_list",
        "data_views_default_get",
        "data_views_get",
        "data_views_list",
        "exceptions_get",
        "exceptions_list",
        "fleet_agent_policies_get",
        "fleet_agent_policies_list",
        "fleet_integration_policies_get",
        "fleet_integration_policies_list",
        "rules_get",
        "rules_list",
        "rules_prebuilt_status",
        "stack_doctor",
        "stack_info",
    ];
    if allow_query_tools {
        required.splice(18..18, ["search_dsl", "search_esql"]);
    }
    if names != required {
        return Err("MCP tools/list catalog differs from the required read catalog.".to_string());
    }
    Ok(())
}

fn successful_tool_content(response: &Value, id: u64, tool: &'static str) -> TestResult<Value> {
    if response.get("id").and_then(Value::as_u64) != Some(id) {
        return Err(format!("MCP {tool} response id did not match its request."));
    }
    let result = response
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("MCP {tool} response has an invalid success envelope."))?;
    if result.get("isError") == Some(&Value::Bool(true)) {
        return Err(format!("MCP {tool} returned a tool error."));
    }
    let structured = result
        .get("structuredContent")
        .filter(|value| value.is_object())
        .ok_or_else(|| format!("MCP {tool} response has an invalid success envelope."))?;
    let content = result
        .get("content")
        .and_then(Value::as_array)
        .filter(|content| content.len() == 1)
        .and_then(|content| content.first())
        .and_then(Value::as_object)
        .filter(|content| content.get("type").and_then(Value::as_str) == Some("text"))
        .and_then(|content| content.get("text").and_then(Value::as_str))
        .ok_or_else(|| format!("MCP {tool} response has an invalid success envelope."))?;
    let parsed = serde_json::from_str::<Value>(content)
        .map_err(|_| format!("MCP {tool} response text was not valid JSON."))?;
    if parsed != *structured {
        return Err(format!(
            "MCP {tool} response text differed from structured content."
        ));
    }
    let structured_object = structured
        .as_object()
        .ok_or_else(|| format!("MCP {tool} response has an invalid success envelope."))?;
    assert_exact_keys(
        structured_object,
        &["target", "data", "page"],
        "success envelope",
    )?;
    let target = object_field(structured, "target", "success envelope")?;
    assert_exact_keys(target, &["profile", "host", "space"], "target")?;
    for field in ["profile", "host", "space"] {
        require_nonempty_string(target, field, "target")?;
    }
    Ok(structured.clone())
}

fn validate_exceptions_get(content: &Value, list_id: &str, item_id: &str) -> TestResult {
    let data = object_field(content, "data", "exceptions_get")?;
    assert_exact_keys(data, &["container", "items"], "exceptions_get data")?;
    let container = map_object_field(data, "container", "exceptions_get data")?;
    validate_exception_container(container, list_id)?;
    let items = map_array_field(data, "items", "exceptions_get data")?;
    if items.len() != 1 {
        return Err("MCP exceptions_get did not return exactly one owned item.".to_string());
    }
    let item = items[0]
        .as_object()
        .ok_or_else(|| "MCP exceptions_get item was not an object.".to_string())?;
    assert_allowed_keys(
        item,
        &[
            "item_id",
            "name",
            "description",
            "entries",
            "os_types",
            "tags",
        ],
        "exceptions_get item",
    )?;
    require_matching_string(item, "item_id", item_id, "exceptions_get item")?;
    if !item.get("entries").is_some_and(Value::is_array)
        || item
            .get("entries")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        return Err("MCP exceptions_get item omitted its entries.".to_string());
    }
    validate_page(content, 10)?;
    Ok(())
}

fn validate_exceptions_list(content: &Value, list_id: &str) -> TestResult {
    let data = object_field(content, "data", "exceptions_list")?;
    assert_exact_keys(data, &["lists"], "exceptions_list data")?;
    let lists = map_array_field(data, "lists", "exceptions_list data")?;
    if lists.len() != 1 {
        return Err("MCP exceptions_list did not return exactly one owned container.".to_string());
    }
    let container = lists[0]
        .as_object()
        .ok_or_else(|| "MCP exceptions_list container was not an object.".to_string())?;
    validate_exception_container(container, list_id)?;
    validate_page(content, 10)
}

fn validate_exception_container(
    container: &serde_json::Map<String, Value>,
    list_id: &str,
) -> TestResult {
    assert_allowed_keys(
        container,
        &[
            "list_id",
            "namespace_type",
            "name",
            "description",
            "type",
            "tags",
        ],
        "exception container",
    )?;
    require_matching_string(container, "list_id", list_id, "exception container")?;
    require_matching_string(container, "namespace_type", "single", "exception container")?;
    for field in ["name", "description", "type"] {
        require_nonempty_string(container, field, "exception container")?;
    }
    if !container
        .get("tags")
        .and_then(Value::as_array)
        .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(LIVE_TAG)))
    {
        return Err("MCP exception container omitted its marker tag.".to_string());
    }
    Ok(())
}

fn validate_rules_get(content: &Value, rule_id: &str, list_id: &str) -> TestResult {
    let rule = object_field(content, "data", "rules_get")?;
    assert_exact_keys(
        rule,
        &[
            "rule_id",
            "name",
            "type",
            "enabled",
            "severity",
            "risk_score",
            "tags",
            "description",
            "language",
            "query",
            "index",
            "from",
            "interval",
            "exceptions_list",
        ],
        "rules_get data",
    )?;
    require_matching_string(rule, "rule_id", rule_id, "rules_get data")?;
    if rule.get("enabled") != Some(&Value::Bool(false)) {
        return Err("MCP rules_get did not preserve the disabled rule state.".to_string());
    }
    for field in ["description", "language", "query", "from", "interval"] {
        require_nonempty_string(rule, field, "rules_get data")?;
    }
    if !rule.get("index").is_some_and(Value::is_array)
        || rule
            .get("index")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        return Err("MCP rules_get omitted the rule index.".to_string());
    }
    let exceptions = map_array_field(rule, "exceptions_list", "rules_get data")?;
    if exceptions.len() != 1 {
        return Err("MCP rules_get did not return exactly one exception reference.".to_string());
    }
    let exception = exceptions[0]
        .as_object()
        .ok_or_else(|| "MCP rules_get exception reference was not an object.".to_string())?;
    assert_exact_keys(
        exception,
        &["list_id", "namespace_type", "type"],
        "rules_get exception reference",
    )?;
    require_matching_string(
        exception,
        "list_id",
        list_id,
        "rules_get exception reference",
    )?;
    require_matching_string(
        exception,
        "namespace_type",
        "single",
        "rules_get exception reference",
    )?;
    require_matching_string(
        exception,
        "type",
        "detection",
        "rules_get exception reference",
    )?;
    require_null_page(content, "rules_get")
}

fn validate_rules_list(content: &Value, rule_id: &str) -> TestResult {
    let data = object_field(content, "data", "rules_list")?;
    assert_exact_keys(data, &["rules"], "rules_list data")?;
    let rules = map_array_field(data, "rules", "rules_list data")?;
    if rules.len() != 1 {
        return Err("MCP rules_list did not return exactly one owned rule.".to_string());
    }
    let rule = rules[0]
        .as_object()
        .ok_or_else(|| "MCP rules_list row was not an object.".to_string())?;
    assert_exact_keys(
        rule,
        &[
            "rule_id",
            "name",
            "type",
            "enabled",
            "severity",
            "risk_score",
            "tags",
        ],
        "rules_list row",
    )?;
    require_matching_string(rule, "rule_id", rule_id, "rules_list row")?;
    if rule.get("enabled") != Some(&Value::Bool(false)) {
        return Err("MCP rules_list did not preserve the disabled rule state.".to_string());
    }
    if !rule
        .get("tags")
        .and_then(Value::as_array)
        .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(LIVE_TAG)))
    {
        return Err("MCP rules_list omitted the marker tag.".to_string());
    }
    validate_page(content, 10)
}

fn validate_prebuilt_status(content: &Value) -> TestResult {
    let data = object_field(content, "data", "rules_prebuilt_status")?;
    let fields = [
        "installed",
        "not_installed",
        "not_updated",
        "custom_installed",
        "customized",
        "timelines_installed",
        "timelines_not_installed",
        "timelines_not_updated",
    ];
    assert_exact_keys(data, &fields, "rules_prebuilt_status data")?;
    if fields
        .iter()
        .any(|field| data.get(*field).and_then(Value::as_u64).is_none())
    {
        return Err("MCP rules_prebuilt_status contained a non-counter field.".to_string());
    }
    if fields[..5]
        .iter()
        .all(|field| data.get(*field).and_then(Value::as_u64) == Some(0))
    {
        return Err("MCP rules_prebuilt_status reported no rule-state counters.".to_string());
    }
    require_null_page(content, "rules_prebuilt_status")
}

fn validate_doctor(content: &Value) -> TestResult {
    let data = object_field(content, "data", "stack_doctor")?;
    assert_exact_keys(data, &["ok", "checks"], "stack_doctor data")?;
    if !data.get("ok").is_some_and(Value::is_boolean) {
        return Err("MCP stack_doctor omitted its boolean status.".to_string());
    }
    let checks = map_array_field(data, "checks", "stack_doctor data")?;
    if checks.is_empty() {
        return Err("MCP stack_doctor returned no checks.".to_string());
    }
    for check in checks {
        let check = check
            .as_object()
            .ok_or_else(|| "MCP stack_doctor check was not an object.".to_string())?;
        assert_exact_keys(check, &["check", "status"], "stack_doctor check")?;
        require_nonempty_string(check, "check", "stack_doctor check")?;
        if !matches!(
            check.get("status").and_then(Value::as_str),
            Some("ok" | "warn" | "fail")
        ) {
            return Err("MCP stack_doctor emitted an invalid check status.".to_string());
        }
    }
    require_null_page(content, "stack_doctor")
}

fn validate_stack_info(content: &Value) -> TestResult {
    let data = object_field(content, "data", "stack_info")?;
    assert_exact_keys(
        data,
        &["version", "flavor", "license", "spaces"],
        "stack_info data",
    )?;
    for field in ["version", "flavor"] {
        require_nonempty_string(data, field, "stack_info data")?;
    }
    if !data
        .get("license")
        .is_some_and(|license| license.is_string() || license.is_null())
    {
        return Err("MCP stack_info emitted an invalid license.".to_string());
    }
    if !data.get("spaces").is_some_and(|spaces| {
        spaces.is_null()
            || spaces.as_array().is_some_and(|spaces| {
                !spaces.is_empty()
                    && spaces
                        .iter()
                        .all(|space| space.as_str().is_some_and(|space| !space.is_empty()))
            })
    }) {
        return Err("MCP stack_info emitted invalid spaces.".to_string());
    }
    require_null_page(content, "stack_info")
}

fn validate_page(content: &Value, limit: u64) -> TestResult {
    let page = object_field(content, "page", "tool result")?;
    assert_exact_keys(
        page,
        &["limit", "returned", "total", "has_more", "truncated"],
        "tool result page",
    )?;
    if page.get("limit").and_then(Value::as_u64) != Some(limit)
        || page.get("returned").and_then(Value::as_u64) != Some(1)
        || page.get("total").and_then(Value::as_u64) != Some(1)
        || page.get("has_more") != Some(&Value::Bool(false))
        || page.get("truncated") != Some(&Value::Bool(false))
    {
        return Err("MCP tool result page did not describe one complete row.".to_string());
    }
    Ok(())
}

fn require_null_page(content: &Value, tool: &'static str) -> TestResult {
    if content.get("page") != Some(&Value::Null) {
        return Err(format!("MCP {tool} unexpectedly included page metadata."));
    }
    Ok(())
}

fn object_field<'a>(
    value: &'a Value,
    field: &'static str,
    context: &'static str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("MCP {context} omitted object field {field}."))
}

fn map_object_field<'a>(
    value: &'a serde_json::Map<String, Value>,
    field: &'static str,
    context: &'static str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("MCP {context} omitted object field {field}."))
}

fn map_array_field<'a>(
    value: &'a serde_json::Map<String, Value>,
    field: &'static str,
    context: &'static str,
) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("MCP {context} omitted array field {field}."))
}

fn require_nonempty_string(
    value: &serde_json::Map<String, Value>,
    field: &'static str,
    context: &'static str,
) -> TestResult {
    if !value
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|text| !text.is_empty())
    {
        return Err(format!("MCP {context} omitted nonempty field {field}."));
    }
    Ok(())
}

fn require_matching_string(
    value: &serde_json::Map<String, Value>,
    field: &'static str,
    expected: &str,
    context: &'static str,
) -> TestResult {
    if value.get(field).and_then(Value::as_str) != Some(expected) {
        return Err(format!("MCP {context} did not match owned field {field}."));
    }
    Ok(())
}

fn assert_exact_keys(
    value: &serde_json::Map<String, Value>,
    expected: &[&str],
    context: &'static str,
) -> TestResult {
    if value.len() != expected.len() || expected.iter().any(|field| !value.contains_key(*field)) {
        return Err(format!("MCP {context} contained unexpected fields."));
    }
    Ok(())
}

fn assert_allowed_keys(
    value: &serde_json::Map<String, Value>,
    allowed: &[&str],
    context: &'static str,
) -> TestResult {
    if value.keys().any(|field| !allowed.contains(&field.as_str())) {
        return Err(format!("MCP {context} contained unexpected fields."));
    }
    Ok(())
}

fn normalized_not_found_content(
    response: &Value,
    id: u64,
    tool: &'static str,
    http_status: Option<u64>,
) -> TestResult {
    let outer = response
        .as_object()
        .ok_or_else(|| format!("MCP {tool} returned an invalid tool error."))?;
    assert_exact_keys(outer, &["jsonrpc", "id", "result"], "tool error response")?;
    if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(format!("MCP {tool} error response was not JSON-RPC 2.0."));
    }
    if response.get("id").and_then(Value::as_u64) != Some(id) {
        return Err(format!(
            "MCP {tool} error response id did not match its request."
        ));
    }
    let result = response
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("MCP {tool} returned an invalid tool error."))?;
    assert_exact_keys(
        result,
        &["content", "structuredContent", "isError"],
        "tool error result",
    )?;
    if result.get("isError") != Some(&Value::Bool(true)) {
        return Err(format!("MCP {tool} did not return a tool error."));
    }
    let structured = result
        .get("structuredContent")
        .filter(|value| value.is_object())
        .ok_or_else(|| format!("MCP {tool} returned an invalid tool error."))?;
    let item = result
        .get("content")
        .and_then(Value::as_array)
        .filter(|content| content.len() == 1)
        .ok_or_else(|| format!("MCP {tool} returned an invalid tool error."))?;
    let item = item[0]
        .as_object()
        .ok_or_else(|| format!("MCP {tool} returned an invalid tool error."))?;
    assert_exact_keys(item, &["type", "text"], "tool error content")?;
    if item.get("type").and_then(Value::as_str) != Some("text") {
        return Err(format!("MCP {tool} returned an invalid tool error."));
    }
    let text = item
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("MCP {tool} returned an invalid tool error."))?;
    if serde_json::from_str::<Value>(text)
        .map_err(|_| format!("MCP {tool} error text was not valid JSON."))?
        != *structured
    {
        return Err(format!(
            "MCP {tool} error text differed from structured content."
        ));
    }
    let error = structured
        .get("error")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("MCP {tool} returned an invalid tool error."))?;
    assert_exact_keys(
        structured.as_object().expect("checked"),
        &["target", "error"],
        "tool error envelope",
    )?;
    let target = structured
        .get("target")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("MCP {tool} returned an invalid tool error."))?;
    assert_exact_keys(target, &["profile", "host", "space"], "tool error target")?;
    for field in ["profile", "host", "space"] {
        require_nonempty_string(target, field, "tool error target")?;
    }
    assert_exact_keys(
        error,
        &["kind", "http_status", "code", "message"],
        "tool error",
    )?;
    if error.get("kind").and_then(Value::as_str) != Some("not_found")
        || error.get("http_status") != Some(&http_status.map_or(Value::Null, Value::from))
        || error.get("code").and_then(Value::as_str) != Some("elastic_not_found")
        || error.get("message").and_then(Value::as_str)
            != Some("The selected resource was not found.")
    {
        return Err(format!("MCP {tool} did not normalize a not-found error."));
    }
    Ok(())
}

fn sample_page(returned: usize, total: Value, truncated: bool) -> Value {
    json!({"limit":10,"returned":returned,"total":total,"has_more":truncated,"truncated":truncated})
}
fn sample_query_page(returned: usize, truncated: bool) -> Value {
    json!({"limit":2,"returned":returned,"total":null,"has_more":if truncated {json!(true)} else {Value::Null},"truncated":truncated})
}

fn validate_new_inspection_validator_samples() -> TestResult {
    let alert_source = json!({"@timestamp":"now","kibana.alert.rule.rule_id":"rule","kibana.alert.rule.name":"rule","kibana.alert.severity":"low","kibana.alert.risk_score":21,"kibana.alert.workflow_status":"open","kibana.alert.workflow_tags":[LIVE_TAG]});
    let alert = json!({"data":{"alerts":[{"id":"alert","index":"index","source":alert_source.clone()}]},"page":sample_page(1,json!(1),false)});
    validate_alerts_list(&alert, "rule")?;
    validate_alert_get(
        &json!({"data":{"id":"alert","index":"index","source":alert_source},"page":null}),
        "alert",
        "rule",
    )?;
    let case = json!({"id":"case","title":"case","status":"open","severity":"low","tags":[LIVE_TAG],"description":"MCP smoke case","created_at":"now","updated_at":"now","totalComment":0});
    validate_cases_list(
        &json!({"data":{"cases":[case.clone()]},"page":sample_page(1,json!(1),false)}),
        "case",
        "case",
    )?;
    validate_case_get(&json!({"data":case,"page":null}), "case", "case")?;
    let view = json!({"id":"view","title":"index","name":"view","timeFieldName":"@timestamp"});
    validate_data_views_list(
        &json!({"data":{"data_views":[view.clone()]},"page":sample_page(1,json!(1),false)}),
        "view",
        "index",
    )?;
    validate_data_view_get(
        &json!({"data":{"data_view":view},"page":null}),
        "view",
        "index",
    )?;
    validate_default_data_view(&json!({"data":{"id":"view"},"page":null}), "view")?;
    let dashboard = json!({"id":"dash","title":"dash"});
    validate_dashboards_list(
        &json!({"data":{"dashboards":[dashboard]},"page":sample_page(1,json!(1),false)}),
        "dash",
    )?;
    validate_dashboard_get(
        &json!({"data":{"id":"dash","data":{"title":"dash","panels":[{"config":{"data_source":{"type":"data_view_reference","ref_id":"view"}}}]}},"page":null}),
        "dash",
        "view",
    )?;
    let agent = json!({"id":"agent","name":"agent","namespace":"default","agents":0});
    validate_agent_policy_list(
        &json!({"data":{"agent_policies":[agent.clone()]},"page":sample_page(1,json!(1),false)}),
        "agent",
    )?;
    validate_agent_policy_get(
        &json!({"data":{"id":"agent","name":"agent","namespace":"default","agents":0,"attached_integrations":[],"blocked_by":[]},"page":null}),
        "agent",
    )?;
    let integration = json!({"id":"integration","name":"integration","namespace":"default","policy_ids":["agent"],"package":{"name":"system","version":"1"}});
    validate_integration_policy_list(
        &json!({"data":{"integration_policies":[integration.clone()]},"page":sample_page(1,json!(1),false)}),
        "integration",
        "agent",
    )?;
    validate_integration_policy_get(
        &json!({"data":{"id":"integration","name":"integration","namespace":"default","policy_ids":["agent"],"package":{"name":"system","version":"1"},"affected_agents":0,"blocked_by":[]},"page":null}),
        "integration",
        "agent",
    )?;
    for key in [
        "alerts",
        "cases",
        "data_views",
        "dashboards",
        "agent_policies",
        "integration_policies",
    ] {
        validate_empty_list(
            &json!({"data":{key:[]},"page":sample_page(0,json!(0),false)}),
            key,
        )?;
    }
    Ok(())
}
fn validate_new_inspection_validator_rejections() -> TestResult {
    type Validator = fn(&Value) -> TestResult;
    struct Case {
        tool: &'static str,
        value: Value,
        closed: &'static str,
        list: bool,
        validator: Validator,
    }
    fn alerts_list(v: &Value) -> TestResult {
        validate_alerts_list(v, "rule")
    }
    fn alerts_get(v: &Value) -> TestResult {
        validate_alert_get(v, "alert", "rule")
    }
    fn cases_list(v: &Value) -> TestResult {
        validate_cases_list(v, "case", "case")
    }
    fn cases_get(v: &Value) -> TestResult {
        validate_case_get(v, "case", "case")
    }
    fn views_list(v: &Value) -> TestResult {
        validate_data_views_list(v, "view", "index")
    }
    fn views_get(v: &Value) -> TestResult {
        validate_data_view_get(v, "view", "index")
    }
    fn default_view(v: &Value) -> TestResult {
        validate_default_data_view(v, "view")
    }
    fn dashboards_list(v: &Value) -> TestResult {
        validate_dashboards_list(v, "dash")
    }
    fn dashboards_get(v: &Value) -> TestResult {
        validate_dashboard_get(v, "dash", "view")
    }
    fn agent_list(v: &Value) -> TestResult {
        validate_agent_policy_list(v, "agent")
    }
    fn agent_get(v: &Value) -> TestResult {
        validate_agent_policy_get(v, "agent")
    }
    fn integration_list(v: &Value) -> TestResult {
        validate_integration_policy_list(v, "integration", "agent")
    }
    fn integration_get(v: &Value) -> TestResult {
        validate_integration_policy_get(v, "integration", "agent")
    }

    let alert = json!({"id":"alert","index":"index","source":{"@timestamp":"now","kibana.alert.rule.rule_id":"rule","kibana.alert.rule.name":"rule","kibana.alert.severity":"low","kibana.alert.risk_score":21,"kibana.alert.workflow_status":"open"}});
    let case = json!({"id":"case","title":"case","status":"open","severity":"low","tags":[LIVE_TAG],"description":"MCP smoke case","totalComment":0});
    let view = json!({"id":"view","title":"index","name":"view","timeFieldName":"@timestamp"});
    let dashboard = json!({"id":"dash","title":"dash"});
    let agent = json!({"id":"agent","name":"agent-name","namespace":"default"});
    let integration = json!({"id":"integration","name":"integration-name","namespace":"default","policy_ids":["agent"],"package":{"name":"system","version":"1"}});
    let cases = vec![
        Case {
            tool: "alerts_list",
            value: json!({"data":{"alerts":[alert.clone()]},"page":sample_page(1,json!(1),false)}),
            closed: "/data/alerts/0",
            list: true,
            validator: alerts_list,
        },
        Case {
            tool: "alerts_get",
            value: json!({"data":alert,"page":null}),
            closed: "/data",
            list: false,
            validator: alerts_get,
        },
        Case {
            tool: "cases_list",
            value: json!({"data":{"cases":[case.clone()]},"page":sample_page(1,json!(1),false)}),
            closed: "/data/cases/0",
            list: true,
            validator: cases_list,
        },
        Case {
            tool: "cases_get",
            value: json!({"data":case,"page":null}),
            closed: "/data",
            list: false,
            validator: cases_get,
        },
        Case {
            tool: "data_views_list",
            value: json!({"data":{"data_views":[view.clone()]},"page":sample_page(1,json!(1),false)}),
            closed: "/data/data_views/0",
            list: true,
            validator: views_list,
        },
        Case {
            tool: "data_views_get",
            value: json!({"data":{"data_view":view.clone()},"page":null}),
            closed: "/data/data_view",
            list: false,
            validator: views_get,
        },
        Case {
            tool: "data_views_default_get",
            value: json!({"data":{"id":"view"},"page":null}),
            closed: "/data",
            list: false,
            validator: default_view,
        },
        Case {
            tool: "dashboards_list",
            value: json!({"data":{"dashboards":[dashboard]},"page":sample_page(1,json!(1),false)}),
            closed: "/data/dashboards/0",
            list: true,
            validator: dashboards_list,
        },
        Case {
            tool: "dashboards_get",
            value: json!({"data":{"id":"dash","data":{"title":"dash","panels":[{"config":{"data_source":{"type":"data_view_reference","ref_id":"view"}}}]}},"page":null}),
            closed: "/data",
            list: false,
            validator: dashboards_get,
        },
        Case {
            tool: "fleet_agent_policies_list",
            value: json!({"data":{"agent_policies":[agent.clone()]},"page":sample_page(1,json!(1),false)}),
            closed: "/data/agent_policies/0",
            list: true,
            validator: agent_list,
        },
        Case {
            tool: "fleet_agent_policies_get",
            value: json!({"data":{"id":"agent","name":"agent-name","namespace":"default","agents":0,"attached_integrations":[],"blocked_by":[]},"page":null}),
            closed: "/data",
            list: false,
            validator: agent_get,
        },
        Case {
            tool: "fleet_integration_policies_list",
            value: json!({"data":{"integration_policies":[integration.clone()]},"page":sample_page(1,json!(1),false)}),
            closed: "/data/integration_policies/0",
            list: true,
            validator: integration_list,
        },
        Case {
            tool: "fleet_integration_policies_get",
            value: json!({"data":{"id":"integration","name":"integration-name","namespace":"default","policy_ids":["agent"],"package":{"name":"system","version":"1"},"affected_agents":0,"blocked_by":[]},"page":null}),
            closed: "/data",
            list: false,
            validator: integration_get,
        },
    ];
    for case in cases {
        (case.validator)(&case.value)
            .map_err(|_| format!("{} valid sample was rejected.", case.tool))?;
        for (name, change) in [
            ("unknown", "secret_sentinel"),
            ("missing", ""),
            ("wrong_id", "wrong"),
        ] {
            let mut value = case.value.clone();
            let row = value
                .pointer_mut(case.closed)
                .and_then(Value::as_object_mut)
                .expect("closed sample object");
            match name {
                "unknown" => {
                    row.insert(change.to_string(), json!(true));
                }
                "missing" => {
                    row.remove("id");
                }
                "wrong_id" => {
                    row.insert("id".to_string(), json!(7));
                }
                _ => unreachable!(),
            }
            if (case.validator)(&value).is_ok() {
                return Err(format!("{} accepted {name} mutation.", case.tool));
            }
        }
        let mut value = case.value.clone();
        value["page"] = if case.list {
            let mut page = sample_page(1, json!(1), false);
            page["returned"] = json!(0);
            page
        } else {
            json!({})
        };
        if (case.validator)(&value).is_ok() {
            return Err(format!("{} accepted a page mutation.", case.tool));
        }
    }
    for key in [
        "alerts",
        "cases",
        "data_views",
        "dashboards",
        "agent_policies",
        "integration_policies",
    ] {
        let value = json!({"data":{key:[]},"page":sample_page(0,json!(0),false)});
        validate_empty_list(&value, key)?;
        let mut sibling = value.clone();
        sibling["data"]["secret_sentinel"] = json!(true);
        if validate_empty_list(&sibling, key).is_ok() {
            return Err(format!("{key} empty list accepted sibling."));
        }
        let mut page = value;
        page["page"]["returned"] = json!(1);
        if validate_empty_list(&page, key).is_ok() {
            return Err(format!("{key} empty list accepted returned mismatch."));
        }
    }
    let typed_cases = [
        (
            "dashboard optional types",
            validate_dashboards_list(
                &json!({"data":{"dashboards":[{"id":"dash","title":"dash","description":1,"tags":[1]}]},"page":sample_page(1,json!(1),false)}),
                "dash",
            ),
        ),
        (
            "agent detail string arrays",
            validate_agent_policy_get(
                &json!({"data":{"id":"agent","name":"agent-name","namespace":"default","agents":0,"attached_integrations":[1],"blocked_by":[1]},"page":null}),
                "agent",
            ),
        ),
        (
            "integration detail string arrays",
            validate_integration_policy_get(
                &json!({"data":{"id":"integration","name":"integration-name","namespace":"default","policy_ids":["agent"],"package":{"name":"system","version":"1"},"affected_agents":0,"blocked_by":[1]},"page":null}),
                "integration",
                "agent",
            ),
        ),
    ];
    for (name, result) in typed_cases {
        if result.is_ok() {
            return Err(format!("{name} was accepted."));
        }
    }
    Ok(())
}
fn validate_new_query_validator_samples() -> TestResult {
    validate_esql_rows(
        &json!({"data":{"columns":[{"name":"seq","type":"long"},{"name":"marker","type":"keyword"}],"values":[[1,LIVE_TAG],[2,LIVE_TAG]],"is_partial":false},"page":sample_query_page(2,true)}),
    )?;
    validate_esql_empty(
        &json!({"data":{"columns":[{"name":"seq","type":"long"},{"name":"marker","type":"keyword"}],"values":[],"is_partial":false},"page":sample_query_page(0,false)}),
    )?;
    validate_dsl_hits(
        &json!({"data":{"hits":[{"id":"1","index":"index","score":null,"source":{"seq":1,"marker":LIVE_TAG}},{"id":"2","index":"index","score":1.0,"source":{"seq":2,"marker":LIVE_TAG}}]},"page":sample_query_page(2,true)}),
        "index",
    )?;
    validate_dsl_empty(&json!({"data":{"hits":[]},"page":sample_query_page(0,false)}))
}
fn validate_new_query_validator_rejections() -> TestResult {
    let cases = [
        (
            "esql unknown data key",
            validate_esql_rows(
                &json!({"data":{"columns":[{"name":"seq","type":"long"},{"name":"marker","type":"keyword"}],"values":[[1,LIVE_TAG],[2,LIVE_TAG]],"is_partial":false,"secret_sentinel":true},"page":sample_query_page(2,true)}),
            ),
        ),
        (
            "esql missing column type",
            validate_esql_rows(
                &json!({"data":{"columns":[{"name":"seq"},{"name":"marker","type":"keyword"}],"values":[[1,LIVE_TAG],[2,LIVE_TAG]],"is_partial":false},"page":sample_query_page(2,true)}),
            ),
        ),
        (
            "esql wrong row width",
            validate_esql_rows(
                &json!({"data":{"columns":[{"name":"seq","type":"long"},{"name":"marker","type":"keyword"}],"values":[[1,LIVE_TAG,"extra"],[2,LIVE_TAG]],"is_partial":false},"page":sample_query_page(2,true)}),
            ),
        ),
        (
            "esql empty mismatched page",
            validate_esql_empty(
                &json!({"data":{"columns":[{"name":"seq","type":"long"},{"name":"marker","type":"keyword"}],"values":[],"is_partial":false},"page":sample_query_page(1,false)}),
            ),
        ),
        (
            "esql empty unknown key",
            validate_esql_empty(
                &json!({"data":{"columns":[{"name":"seq","type":"long"},{"name":"marker","type":"keyword"}],"values":[],"is_partial":false,"secret_sentinel":true},"page":sample_query_page(0,false)}),
            ),
        ),
        (
            "dsl unknown hit key",
            validate_dsl_hits(
                &json!({"data":{"hits":[{"id":"1","index":"index","score":null,"source":{"seq":1,"marker":LIVE_TAG},"secret_sentinel":true},{"id":"2","index":"index","score":null,"source":{"seq":2,"marker":LIVE_TAG}}]},"page":sample_query_page(2,true)}),
                "index",
            ),
        ),
        (
            "dsl missing score",
            validate_dsl_hits(
                &json!({"data":{"hits":[{"id":"1","index":"index","source":{"seq":1,"marker":LIVE_TAG}},{"id":"2","index":"index","score":null,"source":{"seq":2,"marker":LIVE_TAG}}]},"page":sample_query_page(2,true)}),
                "index",
            ),
        ),
        (
            "dsl wrong score",
            validate_dsl_hits(
                &json!({"data":{"hits":[{"id":"1","index":"index","score":"high","source":{"seq":1,"marker":LIVE_TAG}},{"id":"2","index":"index","score":null,"source":{"seq":2,"marker":LIVE_TAG}}]},"page":sample_query_page(2,true)}),
                "index",
            ),
        ),
        (
            "dsl malformed source",
            validate_dsl_hits(
                &json!({"data":{"hits":[{"id":"1","index":"index","score":null,"source":{"seq":"one","marker":LIVE_TAG}},{"id":"2","index":"index","score":null,"source":{"seq":2,"marker":LIVE_TAG}}]},"page":sample_query_page(2,true)}),
                "index",
            ),
        ),
        (
            "dsl empty mismatched page",
            validate_dsl_empty(&json!({"data":{"hits":[]},"page":sample_query_page(1,false)})),
        ),
        (
            "dsl empty unknown key",
            validate_dsl_empty(
                &json!({"data":{"hits":[],"secret_sentinel":true},"page":sample_query_page(0,false)}),
            ),
        ),
    ];
    for (name, result) in cases {
        if result.is_ok() {
            return Err(format!(
                "MCP query validator accepted unsafe mutation: {name}."
            ));
        }
    }
    Ok(())
}
fn validate_new_not_found_error_samples() -> TestResult {
    normalized_not_found_content(&not_found_response(None), 1, "test", None)?;
    normalized_not_found_content(&not_found_response(Some(404)), 1, "test", Some(404))
}
fn not_found_response(http_status: Option<u64>) -> Value {
    let structured = json!({"target":{"profile":"test","host":"test","space":"default"},"error":{"kind":"not_found","http_status":http_status,"code":"elastic_not_found","message":"The selected resource was not found."}});
    json!({"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":serde_json::to_string(&structured).expect("sample serializes")}],"structuredContent":structured}})
}
fn validate_new_not_found_error_rejections() -> TestResult {
    for mutation in ["outer", "content", "text", "success", "status"] {
        let mut response = not_found_response(None);
        match mutation {
            "outer" => response["extra"] = json!(true),
            "content" => response["result"]["content"][0]["extra"] = json!(true),
            "text" => response["result"]["content"][0]["text"] = json!("{}"),
            "success" => response["result"]["isError"] = json!(false),
            "status" => {
                response["result"]["structuredContent"]["error"]["http_status"] = json!(500);
                response["result"]["content"][0]["text"] = Value::String(
                    serde_json::to_string(&response["result"]["structuredContent"])
                        .expect("sample serializes"),
                );
            }
            _ => unreachable!(),
        }
        if normalized_not_found_content(&response, 1, "test", None).is_ok() {
            return Err(format!(
                "MCP not-found validator accepted unsafe mutation: {mutation}."
            ));
        }
    }
    Ok(())
}
