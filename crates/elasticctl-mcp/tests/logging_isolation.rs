use std::{
    fmt::Write,
    sync::{Arc, Mutex},
};

use elasticctl_core::{Profile, Resolved, Source};
use elasticctl_mcp::{ServerOptions, serve_io};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    task::JoinHandle,
};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span,
};

#[derive(Clone)]
struct RecordingSubscriber {
    records: Arc<Mutex<Vec<String>>>,
}

impl Subscriber for RecordingSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attributes: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut record = format!(
            "target={};name={};",
            event.metadata().target(),
            event.metadata().name()
        );
        event.record(&mut FieldRecorder(&mut record));
        self.records
            .lock()
            .expect("record lock poisoned")
            .push(record);
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

struct FieldRecorder<'a>(&'a mut String);

impl Visit for FieldRecorder<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, "{}={value:?};", field.name());
    }
}

fn target() -> Resolved {
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

fn metadata(sentinel: &str) -> serde_json::Value {
    serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "credential-metadata": sentinel,
    })
}

async fn send(input: &mut tokio::io::DuplexStream, value: serde_json::Value) {
    let mut frame = serde_json::to_vec(&value).expect("test request serializes");
    frame.push(b'\n');
    input.write_all(&frame).await.expect("test sends request");
}

async fn receive(output: &mut BufReader<tokio::io::DuplexStream>) -> serde_json::Value {
    let mut line = Vec::new();
    output
        .read_until(b'\n', &mut line)
        .await
        .expect("test receives response");
    serde_json::from_slice(&line).expect("server response is JSON")
}

#[tokio::test]
async fn public_session_suppresses_sdk_events_without_changing_the_global_subscriber() {
    let records = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::set_global_default(RecordingSubscriber {
        records: Arc::clone(&records),
    })
    .expect("this executable installs one global subscriber");

    tracing::trace!(target: "elasticctl_mcp_control", phase = "before", "control event");
    let (mut input, server_input) = tokio::io::duplex(16_384);
    let (server_output, output) = tokio::io::duplex(16_384);
    let session: JoinHandle<elasticctl_core::Result<()>> = tokio::spawn(serve_io(
        target(),
        ServerOptions::default(),
        server_input,
        server_output,
    ));
    let mut output = BufReader::new(output);
    let sentinels = [
        "credential-list-sentinel",
        "credential-tool-sentinel",
        "credential-argument-sentinel",
        "credential-cancel-sentinel",
        "credential-invalid-sentinel",
    ];

    send(
        &mut input,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": { "_meta": metadata(sentinels[0]) },
        }),
    )
    .await;
    let listed = receive(&mut output).await;
    assert_eq!(listed["id"], 1);

    send(
        &mut input,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "_meta": metadata(sentinels[1]),
                "name": sentinels[1],
                "arguments": { "credential": sentinels[2] },
            },
        }),
    )
    .await;
    let unknown = receive(&mut output).await;
    assert_eq!(unknown["id"], 2);
    assert_eq!(unknown["error"]["message"], "Unknown MCP tool");

    send(
        &mut input,
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {
                "requestId": 2,
                "reason": sentinels[3],
                "_meta": metadata(sentinels[3]),
            },
        }),
    )
    .await;
    send(
        &mut input,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": true,
            "credential": sentinels[4],
        }),
    )
    .await;
    let invalid = receive(&mut output).await;
    assert_eq!(invalid["error"]["message"], "Invalid MCP request");

    input.shutdown().await.expect("test closes input");
    session
        .await
        .expect("session task does not panic")
        .expect("session shuts down cleanly");
    tracing::trace!(target: "elasticctl_mcp_control", phase = "after", "control event");

    let records = records.lock().expect("record lock poisoned");
    assert!(
        records
            .iter()
            .any(|record| record.contains("phase=\"before\""))
    );
    assert!(
        records
            .iter()
            .any(|record| record.contains("phase=\"after\""))
    );
    assert!(
        records
            .iter()
            .all(|record| !record.starts_with("target=rmcp"))
    );
    let wire = format!("{listed}{unknown}{invalid}");
    for sentinel in sentinels {
        assert!(records.iter().all(|record| !record.contains(sentinel)));
        assert!(!wire.contains(sentinel));
    }
}
