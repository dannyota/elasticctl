//! Bounded JSON-lines MCP transport.

use std::{marker::PhantomData, sync::Arc};

use rmcp::{
    RoleServer,
    model::{ErrorCode, ErrorData},
    service::{RxJsonRpcMessage, TxJsonRpcMessage},
    transport::{
        Transport,
        async_rw::{JsonRpcMessageCodec, JsonRpcMessageCodecError},
    },
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::Mutex,
    time::{self, Duration},
};
use tokio_util::{bytes::BytesMut, codec::Decoder, sync::CancellationToken};

pub const MAX_INPUT_LINE_BYTES: usize = 262_144;
pub const MAX_STRUCTURED_CONTENT_BYTES: usize = 262_144;
pub const MAX_OUTPUT_FRAME_BYTES: usize = 1_048_576;

/// A JSON-lines transport that bounds complete inbound and outbound frames.
///
/// It retains the SDK codec for message decoding. The frame scanner only
/// establishes the product byte bound before that codec sees a complete line.
pub struct BoundedIo<R, W> {
    read: BufReader<R>,
    line: Vec<u8>,
    decoder: JsonRpcMessageCodec<RxJsonRpcMessage<RoleServer>>,
    write: Arc<Mutex<Option<W>>>,
    cancellation: CancellationToken,
    _role: PhantomData<fn() -> RoleServer>,
}

impl<R, W> BoundedIo<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    #[cfg(test)]
    pub fn new(read: R, write: W) -> Self {
        Self::with_cancellation(read, write, CancellationToken::new())
    }

    pub fn with_cancellation(read: R, write: W, cancellation: CancellationToken) -> Self {
        Self {
            read: BufReader::new(read),
            line: Vec::with_capacity(MAX_INPUT_LINE_BYTES + 1),
            decoder: JsonRpcMessageCodec::new_with_max_length(MAX_INPUT_LINE_BYTES + 2),
            write: Arc::new(Mutex::new(Some(write))),
            cancellation,
            _role: PhantomData,
        }
    }

    /// Read exactly one delimited line while never adding more than the
    /// product payload cap plus its newline to `line`.
    async fn read_frame(&mut self) -> std::io::Result<bool> {
        loop {
            let available = self.read.fill_buf().await?;
            if available.is_empty() {
                return Ok(false);
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let consumed = newline.map_or(available.len(), |index| index + 1);
            let trailing_carriage_return = newline.is_some_and(|index| {
                (index > 0 && available[index - 1] == b'\r')
                    || (index == 0 && self.line.last() == Some(&b'\r'))
            });
            let payload_bytes = newline.unwrap_or(available.len());
            let new_payload_bytes = payload_bytes
                .saturating_sub(usize::from(trailing_carriage_return && payload_bytes > 0));
            let existing_payload_bytes = self
                .line
                .len()
                .saturating_sub(usize::from(trailing_carriage_return && payload_bytes == 0));
            let unterminated_trailing_carriage_return = newline.is_none()
                && self.line.len().saturating_add(available.len()) == MAX_INPUT_LINE_BYTES + 1
                && available.last() == Some(&b'\r');
            if existing_payload_bytes.saturating_add(new_payload_bytes) > MAX_INPUT_LINE_BYTES
                && !unterminated_trailing_carriage_return
            {
                eprintln!("MCP input frame exceeds the configured limit");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "MCP input frame exceeds the configured limit",
                ));
            }

            self.line.extend_from_slice(&available[..consumed]);
            self.read.consume(consumed);
            if newline.is_some() {
                return Ok(true);
            }
        }
    }

    fn sanitize_protocol_error(value: &mut serde_json::Value) {
        let Some(error) = value
            .get_mut("error")
            .and_then(serde_json::Value::as_object_mut)
        else {
            return;
        };
        let message = match error.get("code").and_then(serde_json::Value::as_i64) {
            Some(-32600 | -32602) => "Invalid MCP request",
            Some(-32601) => "Unknown MCP tool",
            Some(-32603) => "MCP server error",
            Some(-32700) => "Invalid JSON-RPC message",
            _ => "MCP protocol error",
        };
        error.insert(
            "message".to_string(),
            serde_json::Value::String(message.to_string()),
        );
        error.remove("data");
    }

    async fn send_protocol_error(&mut self) -> std::io::Result<()> {
        self.send(TxJsonRpcMessage::<RoleServer>::error(
            ErrorData::new(ErrorCode::INVALID_REQUEST, "Invalid request", None),
            None,
        ))
        .await
    }
}

impl<R, W> Transport<RoleServer> for BoundedIo<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    type Error = std::io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let write = Arc::clone(&self.write);
        let cancellation = self.cancellation.clone();
        async move {
            let send = async {
                let mut value = serde_json::to_value(item)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
                Self::sanitize_protocol_error(&mut value);
                let mut frame = serde_json::to_vec(&value)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
                if frame.len() > MAX_OUTPUT_FRAME_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "MCP output frame exceeds the configured limit",
                    ));
                }
                frame.push(b'\n');
                let mut writer = write.lock().await;
                let writer = writer.as_mut().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotConnected, "MCP transport is closed")
                })?;
                writer.write_all(&frame).await?;
                writer.flush().await
            };
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "MCP transport cancelled",
                )),
                result = send => result,
            }
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        loop {
            let cancellation = self.cancellation.clone();
            let frame = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return None,
                result = self.read_frame() => result,
            };
            match frame {
                Ok(true) => {}
                Ok(false) | Err(_) => {
                    self.cancellation.cancel();
                    return None;
                }
            }

            let parsed = {
                let mut bytes = BytesMut::from(self.line.as_slice());
                self.decoder.decode(&mut bytes)
            };
            self.line.clear();
            match parsed {
                Ok(Some(message)) => return Some(message),
                Ok(None) => continue,
                Err(JsonRpcMessageCodecError::Serde(error)) => match error.classify() {
                    serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {}
                    serde_json::error::Category::Data | serde_json::error::Category::Io => {
                        if self.send_protocol_error().await.is_err() {
                            return None;
                        }
                    }
                },
                Err(_) => return None,
            }
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.cancellation.cancel();
        let write = Arc::clone(&self.write);
        match time::timeout(Duration::from_secs(2), async move {
            let mut writer = write.lock().await;
            let Some(mut writer) = writer.take() else {
                return Ok(());
            };
            writer.shutdown().await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "MCP transport close timed out",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedIo, MAX_INPUT_LINE_BYTES, MAX_OUTPUT_FRAME_BYTES};
    use rmcp::{
        RoleServer,
        model::{CustomResult, ServerResult},
        service::TxJsonRpcMessage,
        transport::Transport,
    };
    use std::{
        io,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        time::{Duration, timeout},
    };
    use tokio_util::sync::CancellationToken;

    struct StalledWriter {
        write_started: Arc<AtomicBool>,
        shutdown_started: Arc<AtomicBool>,
    }

    impl StalledWriter {
        fn new() -> (Self, Arc<AtomicBool>, Arc<AtomicBool>) {
            let write_started = Arc::new(AtomicBool::new(false));
            let shutdown_started = Arc::new(AtomicBool::new(false));
            (
                Self {
                    write_started: Arc::clone(&write_started),
                    shutdown_started: Arc::clone(&shutdown_started),
                },
                write_started,
                shutdown_started,
            )
        }
    }

    impl tokio::io::AsyncWrite for StalledWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.write_started.store(true, Ordering::SeqCst);
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.write_started.store(true, Ordering::SeqCst);
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdown_started.store(true, Ordering::SeqCst);
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn accepts_an_input_payload_at_the_exact_limit() {
        let (mut writer, reader) = tokio::io::duplex(MAX_INPUT_LINE_BYTES + 2);
        let (_, output) = tokio::io::duplex(64);
        let mut frame = br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#.to_vec();
        frame.resize(MAX_INPUT_LINE_BYTES, b' ');
        frame.push(b'\n');
        writer.write_all(&frame).await.expect("test writes input");

        let mut transport = BoundedIo::new(reader, output);
        assert!(transport.receive().await.is_some());
    }

    #[tokio::test]
    async fn accepts_an_input_payload_at_the_exact_limit_with_crlf() {
        let (mut writer, reader) = tokio::io::duplex(MAX_INPUT_LINE_BYTES + 3);
        let (_, output) = tokio::io::duplex(64);
        let mut frame = br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#.to_vec();
        frame.resize(MAX_INPUT_LINE_BYTES, b' ');
        frame.extend_from_slice(b"\r\n");
        writer.write_all(&frame).await.expect("test writes input");

        let mut transport = BoundedIo::new(reader, output);
        assert!(transport.receive().await.is_some());
    }

    #[tokio::test]
    async fn rejects_an_unterminated_input_larger_than_the_limit() {
        let (mut writer, reader) = tokio::io::duplex(MAX_INPUT_LINE_BYTES + 2);
        let (_, output) = tokio::io::duplex(64);
        writer
            .write_all(&vec![b'x'; MAX_INPUT_LINE_BYTES + 1])
            .await
            .expect("test writes oversized input");
        let mut transport = BoundedIo::new(reader, output);
        assert!(
            timeout(Duration::from_millis(100), transport.receive())
                .await
                .expect("the byte cap rejects without waiting for EOF")
                .is_none()
        );
    }

    #[tokio::test]
    async fn rejects_a_terminated_input_payload_one_byte_over_the_limit() {
        let (mut writer, reader) = tokio::io::duplex(MAX_INPUT_LINE_BYTES + 3);
        let (_, output) = tokio::io::duplex(64);
        let mut frame = vec![b'x'; MAX_INPUT_LINE_BYTES + 1];
        frame.push(b'\n');
        writer
            .write_all(&frame)
            .await
            .expect("test writes oversized input");
        let mut transport = BoundedIo::new(reader, output);
        assert!(transport.receive().await.is_none());
    }

    #[tokio::test]
    async fn reports_well_formed_but_schema_invalid_input() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let (output, reader_output) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            let mut transport = BoundedIo::new(reader, output);
            transport.receive().await
        });
        writer
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":true}\n")
            .await
            .expect("test writes schema-invalid JSON");
        let mut reader_output = BufReader::new(reader_output);
        let mut response = Vec::new();
        timeout(
            Duration::from_millis(100),
            reader_output.read_until(b'\n', &mut response),
        )
        .await
        .expect("SDK parsing emits a protocol error")
        .expect("test reads error response");
        let response: serde_json::Value = serde_json::from_slice(&response).expect("JSON reply");
        assert_eq!(response["error"]["message"], "Invalid MCP request");
        writer.shutdown().await.expect("test closes input");
        task.abort();
    }

    #[tokio::test]
    async fn accepts_an_output_payload_at_the_exact_limit() {
        let (_, input) = tokio::io::duplex(64);
        let (output, mut reader) = tokio::io::duplex(MAX_OUTPUT_FRAME_BYTES + 2);
        let mut transport = BoundedIo::new(input, output);
        let mut low = 0usize;
        let mut high = MAX_OUTPUT_FRAME_BYTES;
        let mut matching = None;
        while low <= high {
            let middle = low + (high - low) / 2;
            let message = TxJsonRpcMessage::<RoleServer>::response(
                ServerResult::CustomResult(CustomResult(serde_json::json!("x".repeat(middle)))),
                rmcp::model::NumberOrString::Number(1),
            );
            let bytes = serde_json::to_vec(&message).expect("test message serializes");
            match bytes.len().cmp(&MAX_OUTPUT_FRAME_BYTES) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle - 1,
                std::cmp::Ordering::Equal => {
                    matching = Some(message);
                    break;
                }
            }
        }
        let message = matching.expect("test constructs an exact-limit frame");
        transport
            .send(message)
            .await
            .expect("exact frame is accepted");
        transport.close().await.expect("test closes output");
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .await
            .expect("test reads output");
        assert_eq!(bytes.len(), MAX_OUTPUT_FRAME_BYTES + 1);
        assert_eq!(bytes.last(), Some(&b'\n'));
    }

    #[tokio::test]
    async fn refuses_an_oversized_output_before_writing_any_bytes() {
        let (_, input) = tokio::io::duplex(64);
        let (output, mut reader) = tokio::io::duplex(MAX_OUTPUT_FRAME_BYTES + 2);
        let mut transport = BoundedIo::new(input, output);
        let message = TxJsonRpcMessage::<RoleServer>::response(
            ServerResult::CustomResult(CustomResult(serde_json::json!(
                "x".repeat(MAX_OUTPUT_FRAME_BYTES)
            ))),
            rmcp::model::NumberOrString::Number(1),
        );
        assert!(transport.send(message).await.is_err());
        transport.close().await.expect("test closes output");
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .await
            .expect("test reads output");
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn counts_escaped_bytes_when_rejecting_a_frame_before_any_write() {
        let (_, input) = tokio::io::duplex(64);
        let (output, mut reader) = tokio::io::duplex(MAX_OUTPUT_FRAME_BYTES + 2);
        let mut transport = BoundedIo::new(input, output);
        let message = TxJsonRpcMessage::<RoleServer>::response(
            ServerResult::CustomResult(CustomResult(serde_json::json!(
                "\"".repeat(MAX_OUTPUT_FRAME_BYTES / 2)
            ))),
            rmcp::model::NumberOrString::Number(1),
        );
        assert!(
            serde_json::to_vec(&message)
                .expect("test message serializes")
                .len()
                > MAX_OUTPUT_FRAME_BYTES
        );
        assert!(transport.send(message).await.is_err());
        transport.close().await.expect("test closes output");
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .await
            .expect("test reads output");
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn cancellation_drops_a_stalled_send_and_releases_the_writer_lock() {
        let (_, input) = tokio::io::duplex(64);
        let (writer, write_started, _) = StalledWriter::new();
        let cancellation = CancellationToken::new();
        let mut transport = BoundedIo::with_cancellation(input, writer, cancellation.clone());
        let message = TxJsonRpcMessage::<RoleServer>::response(
            ServerResult::CustomResult(CustomResult(serde_json::json!("response"))),
            rmcp::model::NumberOrString::Number(1),
        );
        let send = tokio::spawn(transport.send(message));
        timeout(Duration::from_millis(100), async {
            while !write_started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stalled write begins");

        cancellation.cancel();
        let error = timeout(Duration::from_millis(100), send)
            .await
            .expect("cancellation drops the stalled send")
            .expect("send task does not panic")
            .expect_err("cancelled send is interrupted");
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        let lock = timeout(Duration::from_millis(100), transport.write.lock())
            .await
            .expect("dropped send releases the writer lock");
        drop(lock);
    }

    #[tokio::test(start_paused = true)]
    async fn close_times_out_after_two_seconds_when_shutdown_stalls() {
        let (_, input) = tokio::io::duplex(64);
        let (writer, _, shutdown_started) = StalledWriter::new();
        let mut transport = BoundedIo::new(input, writer);
        let close = tokio::spawn(async move { transport.close().await });
        for _ in 0..10 {
            if shutdown_started.load(Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            shutdown_started.load(Ordering::SeqCst),
            "shutdown begins before its deadline"
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        let error = close
            .await
            .expect("close task does not panic")
            .expect_err("stalled shutdown hits the static timeout");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "MCP transport close timed out");
    }
}
