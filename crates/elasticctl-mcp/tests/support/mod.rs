use std::time::Duration;

use elasticctl_core::{Profile, Resolved, Source};
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream},
    task::JoinHandle,
};

use elasticctl_mcp::{ServerOptions, serve_io};

pub const EXPECTED_TOOL_NAMES: &[&str] = &[
    "alert_context",
    "alerts_get",
    "alerts_list",
    "cases_get",
    "cases_list",
    "dashboards_get",
    "dashboards_list",
    "data_views_default_get",
    "data_views_get",
    "data_views_list",
    "detection_coverage",
    "exceptions_get",
    "exceptions_list",
    "fleet_agent_policies_get",
    "fleet_agent_policies_list",
    "fleet_integration_policies_get",
    "fleet_integration_policies_list",
    "rule_health",
    "rule_readiness",
    "rules_get",
    "rules_list",
    "rules_prebuilt_status",
    "stack_doctor",
    "stack_info",
];

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
        allow_mutations: elasticctl_mcp::MutationClasses::default(),
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

#[allow(dead_code)]
pub const EXPECTED_RESOURCE_URIS: &[&str] = &[
    "elasticctl://stack/coverage/tactic",
    "elasticctl://stack/coverage/technique",
    "elasticctl://stack/doctor",
    "elasticctl://stack/info",
    "elasticctl://stack/prebuilt-rules/status",
];
#[allow(dead_code)]
pub const EXPECTED_TEMPLATE_URIS: &[&str] = &[
    "elasticctl://stack/alerts/{alert_id}",
    "elasticctl://stack/cases/{case_id}",
    "elasticctl://stack/exception-lists/{namespace_type}/{list_id}",
    "elasticctl://stack/rules/{rule_id}",
];
#[allow(dead_code)]
pub const EXPECTED_PROMPT_NAMES: &[&str] = &[
    "check_rule_readiness",
    "review_detection_coverage",
    "review_rule_health",
    "triage_alert",
];
#[allow(dead_code)]
pub async fn request(
    h: &mut Harness,
    current: bool,
    id: u64,
    method: &str,
    mut params: Value,
) -> Value {
    if current {
        params["_meta"] = current_metadata();
    }
    h.send_json(serde_json::json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}))
        .await;
    let reply = tokio::time::timeout(Duration::from_secs(5), h.receive_json())
        .await
        .expect("response deadline");
    assert_eq!(reply["id"], id);
    reply
}
#[allow(dead_code)]
pub async fn initialize(h: &mut Harness, current: bool) {
    if !current {
        h.send_json(legacy_initialize(1000)).await;
        assert_eq!(
            h.receive_json().await["result"]["capabilities"],
            serde_json::json!({"prompts":{},"resources":{},"tools":{}})
        );
    }
}
