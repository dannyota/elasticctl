//! Process-level startup and stdio contracts for `mcp serve`.
//!
//! The child helpers remove every inherited Elastic setting. Each test provides
//! only the target and timeout values it needs, so environment precedence is
//! exercised without changing the test runner's process environment.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[cfg(unix)]
use std::{ffi::OsStr, time::Instant};

const CREDENTIAL_SENTINEL: &str = "essu_credential-sentinel";
const TARGET_SENTINEL: &str = "target-sentinel.invalid";
const ARGUMENT_SENTINEL: &str = "argument-sentinel";

const ELASTIC_ENV: &[&str] = &[
    "ELASTICCTL_KIBANA_URL",
    "ELASTICCTL_ES_URL",
    "ELASTICCTL_API_KEY",
    "ELASTICCTL_USERNAME",
    "ELASTICCTL_PASSWORD",
    "ELASTICCTL_SPACE",
    "ELASTICCTL_TIMEOUT",
];

#[derive(Debug)]
struct ChildOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn binaries() -> [&'static str; 2] {
    ["elasticctl", "elkctl"]
}

fn command(bin: &str, args: &[String]) -> Command {
    let binary = match bin {
        "elasticctl" => env!("CARGO_BIN_EXE_elasticctl"),
        "elkctl" => env!("CARGO_BIN_EXE_elkctl"),
        other => panic!("unknown CLI binary {other}"),
    };
    let mut command = Command::new(binary);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ELASTIC_ENV {
        command.env_remove(name);
    }
    command
}

fn spawn(bin: &str, args: &[String]) -> Child {
    command(bin, args).spawn().expect("CLI child starts")
}

fn spawn_with_env(bin: &str, args: &[String], environment: &[(&str, &str)]) -> Child {
    let mut command = command(bin, args);
    for (name, value) in environment {
        command.env(name, value);
    }
    command.spawn().expect("CLI child starts")
}

fn output_after_eof(child: Child) -> ChildOutput {
    let output = child.wait_with_output().expect("CLI child exits");
    ChildOutput {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn read_json_line(stdout: &mut BufReader<ChildStdout>) -> Value {
    let mut line = String::new();
    let bytes = stdout.read_line(&mut line).expect("read MCP response line");
    assert_ne!(bytes, 0, "MCP server closed stdout before responding");
    serde_json::from_str(&line).expect("MCP response is JSON")
}

fn write_json(child: &mut Child, value: Value) {
    let mut frame = serde_json::to_vec(&value).expect("request serializes");
    frame.push(b'\n');
    child
        .stdin
        .as_mut()
        .expect("stdin stays open")
        .write_all(&frame)
        .expect("write MCP request");
    child
        .stdin
        .as_mut()
        .expect("stdin stays open")
        .flush()
        .expect("flush MCP request");
}

fn close_and_collect(mut child: Child, mut stdout: BufReader<ChildStdout>) -> ChildOutput {
    child.stdin.take();
    let status = child.wait().expect("CLI child exits after EOF");
    let mut stdout_tail = Vec::new();
    stdout
        .read_to_end(&mut stdout_tail)
        .expect("read remaining stdout");
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .expect("stderr is piped")
        .read_to_end(&mut stderr)
        .expect("read stderr");
    ChildOutput {
        status,
        stdout: stdout_tail,
        stderr,
    }
}

fn current_metadata() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

fn current_list_request(id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/list",
        "params": {"_meta": current_metadata()},
    })
}

fn current_stack_info_request(id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "_meta": current_metadata(),
            "name": "stack_info",
            "arguments": {},
        },
    })
}

fn legacy_initialize(id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "0"},
        },
    })
}

fn config_for(
    dir: &std::path::Path,
    profile: &str,
    kibana_url: &str,
    es_url: Option<&str>,
    timeout_secs: u64,
    verify: bool,
) -> std::path::PathBuf {
    let path = dir.join("mcp-config.toml");
    let es_url = es_url
        .map(|value| format!("es_url = \"{value}\"\n"))
        .unwrap_or_default();
    std::fs::write(
        &path,
        format!(
            "current = \"{profile}\"\n\n[profiles.{profile}]\n\
             kibana_url = \"{kibana_url}\"\n{es_url}\
             api_key = \"{CREDENTIAL_SENTINEL}\"\n\
             space = \"default\"\nverify = {verify}\ntimeout_secs = {timeout_secs}\n"
        ),
    )
    .expect("write test config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("make config owner-only");
    }
    path
}

fn args_with_config(path: &std::path::Path) -> Vec<String> {
    vec![
        "--config".to_string(),
        path.display().to_string(),
        "mcp".to_string(),
        "serve".to_string(),
    ]
}

fn static_diagnostic(output: &ChildOutput, status: i32, kind: &str, message: &str) {
    assert_eq!(output.status.code(), Some(status));
    assert!(output.stdout.is_empty(), "stdout: {:?}", output.stdout);
    let diagnostic: Value = serde_json::from_slice(&output.stderr).expect("one JSON diagnostic");
    let inner = diagnostic
        .get("error")
        .or_else(|| diagnostic.get("warning"))
        .expect("diagnostic envelope");
    assert_eq!(inner["kind"], kind, "{diagnostic}");
    assert_eq!(inner["message"], message, "{diagnostic}");
}

fn assert_private(output: &ChildOutput, values: &[&str]) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for value in values {
        assert!(!text.contains(value), "output leaked {value:?}: {text}");
    }
}

fn current_list(bin: &str, args: &[String]) -> (Value, ChildOutput) {
    let mut child = spawn(bin, args);
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut stdout = BufReader::new(stdout);
    write_json(&mut child, current_list_request(1));
    let reply = read_json_line(&mut stdout);
    let output = close_and_collect(child, stdout);
    (reply, output)
}

fn current_stack_info(
    bin: &str,
    args: &[String],
    environment: &[(&str, &str)],
) -> (Value, ChildOutput) {
    let mut child = spawn_with_env(bin, args, environment);
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut stdout = BufReader::new(stdout);
    write_json(&mut child, current_stack_info_request(2));
    let reply = read_json_line(&mut stdout);
    let output = close_and_collect(child, stdout);
    (reply, output)
}

fn tool_names(reply: &Value) -> Vec<&str> {
    reply["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect()
}

async fn mount_info_routes(server: &MockServer, delay: Duration) {
    for prefix in ["", "/s/routed"] {
        Mock::given(method("GET"))
            .and(path(format!("{prefix}/api/status")))
            .respond_with(ResponseTemplate::new(200).set_delay(delay).set_body_json(
                json!({"version": {"number": "9.6.0", "build_flavor": "traditional"}}),
            ))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{prefix}/api/spaces/space")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(delay)
                    .set_body_json(json!([{"id": "routed"}])),
            )
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{prefix}/_license")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(delay)
                    .set_body_json(json!({"license": {"type": "enterprise"}})),
            )
            .mount(server)
            .await;
    }
}

#[test]
fn both_binaries_leave_protocol_stdout_empty_until_input_and_exit_cleanly_on_eof() {
    for bin in binaries() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let config = config_for(
            dir.path(),
            "analyst",
            "https://kibana.example.test",
            None,
            30,
            true,
        );
        let args = args_with_config(&config);
        let mut child = spawn(bin, &args);
        let stdout = child.stdout.take().expect("stdout is piped");
        let (sent, received) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            reader.read_line(&mut line).expect("read protocol stdout");
            sent.send(()).expect("report protocol activity");
            line
        });

        assert!(
            received.recv_timeout(Duration::from_millis(250)).is_err(),
            "{bin} wrote protocol stdout before a request"
        );
        child.stdin.take();
        assert!(child.wait().expect("clean EOF exits").success());
        assert!(reader.join().expect("reader joins").is_empty());
        let mut stderr = Vec::new();
        child
            .stderr
            .take()
            .expect("stderr is piped")
            .read_to_end(&mut stderr)
            .expect("read stderr");
        assert!(
            stderr.is_empty(),
            "{bin} stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
    }
}

#[test]
fn both_binaries_serve_current_and_legacy_catalog_discovery() {
    let expected = vec![
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
    for bin in binaries() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let config = config_for(
            dir.path(),
            "analyst",
            "https://kibana.example.test",
            None,
            30,
            true,
        );
        let args = args_with_config(&config);
        let (reply, output) = current_list(bin, &args);
        assert!(output.status.success(), "{bin}: {:?}", output);
        assert_eq!(reply["result"]["resultType"], "complete");
        assert_eq!(tool_names(&reply), expected, "{bin}");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());

        let mut child = spawn(bin, &args);
        let stdout = child.stdout.take().expect("stdout is piped");
        let mut stdout = BufReader::new(stdout);
        write_json(&mut child, legacy_initialize(3));
        let initialized = read_json_line(&mut stdout);
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
        write_json(
            &mut child,
            json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}}),
        );
        let listed = read_json_line(&mut stdout);
        assert_eq!(tool_names(&listed), expected, "{bin}");
        let output = close_and_collect(child, stdout);
        assert!(output.status.success(), "{bin}: {:?}", output);
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn query_startup_flag_adds_only_the_two_query_tools_for_both_binaries() {
    let expected = vec![
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
        "search_dsl",
        "search_esql",
        "stack_doctor",
        "stack_info",
    ];
    for bin in binaries() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let config = config_for(
            dir.path(),
            "analyst",
            "https://kibana.example.test",
            None,
            30,
            true,
        );
        let mut args = args_with_config(&config);
        args.push("--allow-query-tools".to_string());
        let (reply, output) = current_list(bin, &args);
        assert!(output.status.success(), "{bin}: {output:?}");
        assert_eq!(tool_names(&reply), expected, "{bin}");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn forbidden_globals_are_rejected_before_config_access_for_both_binaries() {
    let cases: &[&[&str]] = &[
        &["mcp", "serve", "--yes"],
        &["mcp", "serve", "--out", ARGUMENT_SENTINEL],
        &["mcp", "serve", "--fields", ARGUMENT_SENTINEL],
        &["mcp", "serve", "--json"],
        &["mcp", "serve", "--format", "table"],
        &["mcp", "serve", "--debug"],
    ];
    let dir = tempfile::tempdir().expect("temporary directory");
    let private_config = dir.path().join(format!("not-a-config-{ARGUMENT_SENTINEL}"));
    std::fs::create_dir(&private_config).expect("make private invalid config path");
    for bin in binaries() {
        for case in cases {
            let mut args = case.iter().map(ToString::to_string).collect::<Vec<_>>();
            args.extend(["--config".to_string(), private_config.display().to_string()]);
            let output = output_after_eof(spawn(bin, &args));
            static_diagnostic(
                &output,
                2,
                "error",
                "MCP serve accepts only --config, --profile, --space, and --timeout.",
            );
            assert_private(&output, &[ARGUMENT_SENTINEL, CREDENTIAL_SENTINEL]);
        }
    }
}

#[test]
fn malformed_mcp_arguments_are_static_and_never_echo_input() {
    let cases = [
        vec![
            format!("--timeout={ARGUMENT_SENTINEL}"),
            "mcp".to_string(),
            "serve".to_string(),
        ],
        vec![
            "--format".to_string(),
            ARGUMENT_SENTINEL.to_string(),
            "mcp".to_string(),
            "serve".to_string(),
        ],
        vec![
            "--timeout".to_string(),
            ARGUMENT_SENTINEL.to_string(),
            "--profile".to_string(),
            "analyst".to_string(),
            "mcp".to_string(),
            "serve".to_string(),
        ],
        vec![
            "--timeout=bad".to_string(),
            "--timeout".to_string(),
            "worse".to_string(),
            "mcp".to_string(),
            "serve".to_string(),
        ],
        vec![
            "--debug".to_string(),
            "--debug".to_string(),
            "mcp".to_string(),
            "serve".to_string(),
        ],
        vec![
            "mcp".to_string(),
            format!("--{ARGUMENT_SENTINEL}"),
            "serve".to_string(),
        ],
        vec![
            "mcp".to_string(),
            "serve".to_string(),
            format!("--{ARGUMENT_SENTINEL}"),
        ],
        vec![
            "mcp".to_string(),
            "serve".to_string(),
            "--unknown".to_string(),
            ARGUMENT_SENTINEL.to_string(),
        ],
        vec![
            "mcp".to_string(),
            "serve".to_string(),
            "--timeout".to_string(),
        ],
        vec![
            "--timeout".to_string(),
            "--profile".to_string(),
            "analyst".to_string(),
            "mcp".to_string(),
            "serve".to_string(),
        ],
        vec![
            format!("--timeout={ARGUMENT_SENTINEL}"),
            "mcp".to_string(),
            "serve".to_string(),
            "--help".to_string(),
        ],
    ];
    for bin in binaries() {
        for args in &cases {
            let output = output_after_eof(spawn(bin, args));
            assert_eq!(output.status.code(), Some(2), "{bin} {args:?}: {output:?}");
            static_diagnostic(&output, 2, "error", "Invalid MCP serve arguments.");
            assert_private(&output, &[ARGUMENT_SENTINEL, CREDENTIAL_SENTINEL]);
        }
    }
}

#[test]
fn ordinary_parse_errors_remain_formatted_and_selector_words_do_not_enable_mcp_privacy_mode() {
    let invalid = vec![format!("--{ARGUMENT_SENTINEL}"), "rules".to_string()];
    let output = output_after_eof(spawn("elasticctl", &invalid));
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(ARGUMENT_SENTINEL),
        "ordinary clap error keeps its existing formatted input"
    );

    let dir = tempfile::tempdir().expect("temporary directory");
    let private_config = dir.path().join("ordinary-selector-config");
    std::fs::create_dir(&private_config).expect("make private invalid config path");
    for selector in ["mcp", "serve"] {
        let args = vec![
            "rules".to_string(),
            "get".to_string(),
            selector.to_string(),
            "--config".to_string(),
            private_config.display().to_string(),
        ];
        let output = output_after_eof(spawn("elasticctl", &args));
        assert_eq!(output.status.code(), Some(1));
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("Invalid MCP serve arguments."),
            "ordinary selector {selector:?} must retain its command path"
        );
    }
}

#[test]
fn mcp_help_and_version_keep_claps_normal_display_output() {
    for args in [
        vec!["mcp".to_string(), "--help".to_string()],
        vec!["mcp".to_string(), "serve".to_string(), "--help".to_string()],
        vec!["--version".to_string()],
    ] {
        let output = output_after_eof(spawn("elasticctl", &args));
        assert!(output.status.success());
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn startup_config_and_target_failures_are_static_and_private() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let missing_profile = config_for(
        dir.path(),
        "present",
        "https://kibana.example.test",
        None,
        30,
        true,
    );
    let missing_args = vec![
        "--config".to_string(),
        missing_profile.display().to_string(),
        "--profile".to_string(),
        format!("missing-{ARGUMENT_SENTINEL}"),
        "mcp".to_string(),
        "serve".to_string(),
    ];
    let output = output_after_eof(spawn("elasticctl", &missing_args));
    static_diagnostic(
        &output,
        1,
        "not_found",
        "MCP startup configuration could not be resolved.",
    );
    assert_private(&output, &[ARGUMENT_SENTINEL, CREDENTIAL_SENTINEL]);

    let malformed = dir
        .path()
        .join(format!("malformed-{ARGUMENT_SENTINEL}.toml"));
    std::fs::write(&malformed, format!("bad = \"{CREDENTIAL_SENTINEL}"))
        .expect("write malformed config");
    let args = vec![
        "--config".to_string(),
        malformed.display().to_string(),
        "mcp".to_string(),
        "serve".to_string(),
    ];
    let output = output_after_eof(spawn("elasticctl", &args));
    static_diagnostic(
        &output,
        1,
        "error",
        "MCP startup configuration could not be resolved.",
    );
    assert_private(&output, &[ARGUMENT_SENTINEL, CREDENTIAL_SENTINEL]);

    let unreadable = dir.path().join(format!("unreadable-{ARGUMENT_SENTINEL}"));
    std::fs::create_dir(&unreadable).expect("make unreadable config path");
    let args = vec![
        "--config".to_string(),
        unreadable.display().to_string(),
        "mcp".to_string(),
        "serve".to_string(),
    ];
    let output = output_after_eof(spawn("elasticctl", &args));
    static_diagnostic(
        &output,
        1,
        "error",
        "MCP startup configuration could not be resolved.",
    );
    assert_private(&output, &[ARGUMENT_SENTINEL, CREDENTIAL_SENTINEL]);

    for (kibana_url, es_url) in [
        (format!("https://https://{TARGET_SENTINEL}"), None),
        (
            "https://kibana.example.test".to_string(),
            Some(format!("https://https://{TARGET_SENTINEL}")),
        ),
    ] {
        let config = config_for(
            dir.path(),
            "malformed-target",
            &kibana_url,
            es_url.as_deref(),
            30,
            true,
        );
        let output = output_after_eof(spawn("elasticctl", &args_with_config(&config)));
        static_diagnostic(&output, 1, "error", "MCP server failed.");
        assert_private(&output, &[TARGET_SENTINEL, CREDENTIAL_SENTINEL]);
    }
}

#[test]
fn invalid_environment_timeout_is_static_and_private() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let config = config_for(
        dir.path(),
        "analyst",
        "https://kibana.example.test",
        None,
        30,
        true,
    );
    let args = args_with_config(&config);
    let output = output_after_eof(spawn_with_env(
        "elasticctl",
        &args,
        &[("ELASTICCTL_TIMEOUT", ARGUMENT_SENTINEL)],
    ));
    static_diagnostic(
        &output,
        1,
        "error",
        "MCP startup configuration could not be resolved.",
    );
    assert_private(
        &output,
        &[ARGUMENT_SENTINEL, TARGET_SENTINEL, CREDENTIAL_SENTINEL],
    );
}

#[test]
fn resolved_timeout_range_is_checked_before_protocol_startup() {
    let dir = tempfile::tempdir().expect("temporary directory");
    for timeout in [0, 121] {
        let config = config_for(
            dir.path(),
            "range",
            "https://kibana.example.test",
            None,
            timeout,
            true,
        );
        let output = output_after_eof(spawn("elasticctl", &args_with_config(&config)));
        static_diagnostic(
            &output,
            1,
            "error",
            "MCP timeout must be between 1 and 120 seconds.",
        );
    }

    for timeout in [1, 120] {
        let config = config_for(
            dir.path(),
            "range",
            "https://kibana.example.test",
            None,
            timeout,
            true,
        );
        let (reply, output) = current_list("elasticctl", &args_with_config(&config));
        assert_eq!(reply["id"], 1);
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn permission_and_tls_warnings_are_static_and_do_not_name_the_target() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temporary directory");
    let config = config_for(
        dir.path(),
        "private-profile",
        &format!("https://{TARGET_SENTINEL}"),
        None,
        30,
        true,
    );
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644))
        .expect("make config permissive");
    let (_, output) = current_list("elasticctl", &args_with_config(&config));
    assert!(output.status.success());
    let diagnostic: Value = serde_json::from_slice(&output.stderr).expect("static warning JSON");
    assert_eq!(diagnostic["warning"]["kind"], "insecure_config_permissions");
    assert_eq!(
        diagnostic["warning"]["message"],
        "Config file permissions allow access by other users; set mode 0600."
    );
    assert_private(
        &output,
        &[
            TARGET_SENTINEL,
            CREDENTIAL_SENTINEL,
            "private-profile",
            &config.display().to_string(),
        ],
    );

    let config = config_for(
        dir.path(),
        "tls-profile",
        &format!("https://{TARGET_SENTINEL}"),
        None,
        30,
        false,
    );
    let (_, output) = current_list("elasticctl", &args_with_config(&config));
    assert!(output.status.success());
    let diagnostic: Value = serde_json::from_slice(&output.stderr).expect("static warning JSON");
    assert_eq!(diagnostic["warning"]["kind"], "insecure_tls_verification");
    assert_eq!(
        diagnostic["warning"]["message"],
        "TLS certificate verification is disabled for the MCP target."
    );
    assert_private(
        &output,
        &[
            TARGET_SENTINEL,
            CREDENTIAL_SENTINEL,
            "tls-profile",
            &config.display().to_string(),
        ],
    );
}

#[tokio::test]
async fn accepted_globals_resolve_identically_before_between_and_after_mcp_words() {
    let server = MockServer::start().await;
    mount_info_routes(&server, Duration::ZERO).await;
    let dir = tempfile::tempdir().expect("temporary directory");
    let config = config_for(dir.path(), "analyst", &server.uri(), None, 30, true);
    let config = config.display().to_string();
    let cases = [
        vec![
            "--config",
            &config,
            "--profile",
            "analyst",
            "--space",
            "routed",
            "mcp",
            "serve",
        ],
        vec![
            "mcp",
            "--config",
            &config,
            "--profile",
            "analyst",
            "--space",
            "routed",
            "serve",
        ],
        vec![
            "mcp",
            "serve",
            "--config",
            &config,
            "--profile",
            "analyst",
            "--space",
            "routed",
        ],
    ];
    let mut targets = Vec::new();
    for bin in binaries() {
        for case in &cases {
            let args = case
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>();
            let (reply, output) = current_stack_info(bin, &args, &[]);
            assert!(output.status.success(), "{bin}: {:?}", output);
            assert!(output.stderr.is_empty(), "{bin}: {:?}", output);
            assert_eq!(reply["result"]["isError"], false, "{bin}: {reply}");
            assert_eq!(
                reply["result"]["structuredContent"]["data"]["version"], "9.6.0",
                "{bin}: {reply}"
            );
            targets.push(reply["result"]["structuredContent"]["target"].clone());
        }
    }
    for target in &targets[1..] {
        assert_eq!(targets[0], *target);
    }
    assert_eq!(targets[0]["profile"], "analyst");
    assert_eq!(targets[0]["space"], "routed");
}

#[tokio::test]
async fn profile_environment_and_flag_timeouts_set_the_whole_call_deadline() {
    let server = MockServer::start().await;
    // Each request is below the one-second transport timeout. Their combined
    // 1.5 seconds prove the deadline wraps capabilities, spaces, and license.
    mount_info_routes(&server, Duration::from_millis(500)).await;
    let dir = tempfile::tempdir().expect("temporary directory");
    let config = config_for(dir.path(), "analyst", &server.uri(), None, 1, true);

    let (reply, output) = current_stack_info("elasticctl", &args_with_config(&config), &[]);
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(
        reply["result"]["structuredContent"]["error"]["code"],
        "deadline_exceeded"
    );

    let (reply, output) = current_stack_info(
        "elasticctl",
        &args_with_config(&config),
        &[("ELASTICCTL_TIMEOUT", "2")],
    );
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(
        reply["result"]["structuredContent"]["data"]["version"],
        "9.6.0"
    );

    let mut args = args_with_config(&config);
    args.splice(0..0, ["--timeout".to_string(), "2".to_string()]);
    let (reply, output) = current_stack_info(
        "elasticctl",
        &args,
        &[("ELASTICCTL_TIMEOUT", ARGUMENT_SENTINEL)],
    );
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(
        reply["result"]["structuredContent"]["data"]["version"],
        "9.6.0"
    );
}

#[cfg(unix)]
#[test]
fn sigterm_exits_with_open_stdin_after_a_flushed_protocol_response() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let config = config_for(
        dir.path(),
        "analyst",
        "https://kibana.example.test",
        None,
        30,
        true,
    );
    let mut child = spawn("elasticctl", &args_with_config(&config));
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut stdout = BufReader::new(stdout);
    write_json(&mut child, current_list_request(99));
    let reply = read_json_line(&mut stdout);
    assert_eq!(reply["id"], 99, "server entered its receive loop");

    let status = std::process::Command::new(OsStr::new("kill"))
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(5);
    let exit = loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("stop hung child");
            let _ = child.wait();
            panic!("MCP process did not exit within the five-second shutdown grace");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    assert!(exit.success(), "SIGTERM must be a clean exit: {exit}");
    assert!(
        child.stdin.is_some(),
        "the test must retain open stdin until exit"
    );
    let mut tail = Vec::new();
    stdout.read_to_end(&mut tail).expect("read final stdout");
    assert!(
        tail.is_empty(),
        "only complete frames may be emitted: {tail:?}"
    );
}

#[test]
fn mcp_serve_help_snapshot_and_command_tree_are_additive_and_read_only() {
    let help = output_after_eof(spawn(
        "elasticctl",
        &["mcp".to_string(), "serve".to_string(), "--help".to_string()],
    ));
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    let help = String::from_utf8(help.stdout)
        .expect("help is UTF-8")
        .replace("elasticctl.exe", "elasticctl");
    insta::assert_snapshot!("mcp_serve_help", help);

    let output = output_after_eof(spawn(
        "elasticctl",
        &["commands".to_string(), "--json".to_string()],
    ));
    assert!(output.status.success());
    let tree: Value = serde_json::from_slice(&output.stdout).expect("command tree JSON");
    let mcp = tree["commands"]
        .as_array()
        .expect("commands array")
        .iter()
        .find(|command| command["name"] == "mcp")
        .expect("mcp command tree entry");
    assert_eq!(mcp["mutates"], false);
    let serve = mcp["subcommands"]
        .as_array()
        .expect("mcp children")
        .iter()
        .find(|command| command["name"] == "serve")
        .expect("mcp serve command tree entry");
    assert_eq!(serve["mutates"], false);
}
