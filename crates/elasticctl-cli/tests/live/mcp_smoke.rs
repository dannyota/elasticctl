use super::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Stdio};
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

    let error = validate_catalog(&catalog).expect_err("additional catalog pages are rejected");

    assert_eq!(
        error,
        "MCP tools/list response included an unexpected continuation cursor."
    );
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

pub(super) fn run_contract(config: &Path, scratch: &Path, cleanup: &mut LiveCleanup) -> TestResult {
    let rule_id = unique_name("mcp-rule");
    let list_id = unique_name("mcp-exceptions");
    let item_id = unique_name("mcp-exception-item");
    cleanup.rule(rule_id.clone());
    cleanup.list(list_id.clone());
    cleanup.item(list_id.clone(), item_id.clone());

    (|| -> TestResult {
        let exceptions = scratch.join("mcp-exceptions.ndjson");
        std::fs::write(
            &exceptions,
            exception_bundle(
                &list_id,
                &item_id,
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
        let index = format!("{rule_id}-index");
        std::fs::write(
            &rule,
            query_rule(&rule_id, &index, "host.name: *", Some(&list_id)),
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

        let mut child = McpChild::spawn(config)?;
        let protocol_result = exercise_protocol(&mut child, &rule_id, &list_id, &item_id);
        let shutdown_result = child.shutdown();
        protocol_result?;
        shutdown_result
    })()
}

fn exercise_protocol(
    child: &mut McpChild,
    rule_id: &str,
    list_id: &str,
    item_id: &str,
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
    validate_catalog(&catalog)?;

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
    validate_stack_info(&info)
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
    fn spawn(config: &Path) -> TestResult<Self> {
        let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin!("elasticctl"));
        command
            .arg("--config")
            .arg(config)
            .args(["mcp", "serve"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
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
        "exceptions_get",
        "exceptions_list",
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

fn validate_catalog(catalog: &Value) -> TestResult {
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
    if names
        != [
            "alerts_get",
            "alerts_list",
            "cases_get",
            "cases_list",
            "exceptions_get",
            "exceptions_list",
            "rules_get",
            "rules_list",
            "rules_prebuilt_status",
            "stack_doctor",
            "stack_info",
        ]
    {
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
