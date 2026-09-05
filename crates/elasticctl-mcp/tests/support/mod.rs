use std::time::Duration;

use elasticctl_core::{Profile, Resolved, Source};
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream},
    task::JoinHandle,
};

use elasticctl_mcp::{ServerOptions, serve_io};

pub const EXPECTED_TOOL_NAMES: &[&str] = &["stack_doctor", "stack_info"];

pub struct Harness {
    input: Option<DuplexStream>,
    output: BufReader<DuplexStream>,
    task: JoinHandle<elasticctl_core::Result<()>>,
}

impl Harness {
    pub fn start(target: Resolved, options: ServerOptions) -> Self {
        let (input, server_input) = tokio::io::duplex(1_048_576);
        let (server_output, output) = tokio::io::duplex(1_048_576);
        let task = tokio::spawn(serve_io(target, options, server_input, server_output));
        Self {
            input: Some(input),
            output: BufReader::new(output),
            task,
        }
    }

    pub async fn send_json(&mut self, value: Value) {
        let mut frame = serde_json::to_vec(&value).expect("test JSON serializes");
        frame.push(b'\n');
        self.input
            .as_mut()
            .expect("input remains open")
            .write_all(&frame)
            .await
            .expect("test writes request");
    }

    pub async fn receive_json(&mut self) -> Value {
        let mut line = Vec::new();
        self.output
            .read_until(b'\n', &mut line)
            .await
            .expect("test reads response");
        serde_json::from_slice(&line).expect("server returns JSON")
    }

    pub fn close_input(&mut self) {
        self.input.take();
    }

    pub async fn join(self) -> elasticctl_core::Result<()> {
        self.task.await.expect("server task must not panic")
    }
}

pub fn target() -> Resolved {
    Resolved {
        name: "test".to_string(),
        source: Source::Profile,
        profile: Profile {
            kibana_url: "https://kibana.example.test/base".to_string(),
            es_url: Some("https://es.example.test/base".to_string()),
            api_key: None,
            username: None,
            password: None,
            space: "default".to_string(),
            verify: true,
            timeout_secs: 30,
        },
    }
}

pub fn current_metadata() -> Value {
    serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

pub fn options() -> ServerOptions {
    ServerOptions {
        call_timeout: Duration::from_secs(30),
        allow_query_tools: false,
    }
}

pub fn legacy_initialize(id: u64) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "0" },
        },
    })
}
