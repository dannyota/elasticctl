use std::{
    panic::{self, AssertUnwindSafe},
    sync::Arc,
    thread,
};

use elasticctl_core::{Error, ErrorKind, Resolved, Result};
use rmcp::{ServiceExt, transport::Transport as McpTransport};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::oneshot,
};
use tokio_util::sync::CancellationToken;

use super::{
    ServerOptions, ServerState, TargetContext,
    handler::McpServer,
    lifecycle::{
        CurrentLifecycleService, FirstPath, LegacyInitializationGate, ReplayTransport, first_path,
    },
    validate_target,
};
use crate::bounded_io::BoundedIo;

/// Serve MCP over process stdin and stdout.
pub async fn serve_stdio(target: Resolved, options: ServerOptions) -> Result<()> {
    let root = CancellationToken::new();
    let signal_root = root.clone();
    let signal = tokio::spawn(await_stdio_shutdown(signal_root));
    let result = serve_io_with_root(
        target,
        options,
        tokio::io::stdin(),
        tokio::io::stdout(),
        root,
    )
    .await;
    signal.abort();
    let _ = signal.await;
    result
}

#[cfg(unix)]
async fn await_stdio_shutdown(root: CancellationToken) {
    let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        root.cancelled().await;
        return;
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => root.cancel(),
        _ = terminate.recv() => root.cancel(),
        _ = root.cancelled() => {},
    }
}

#[cfg(not(unix))]
async fn await_stdio_shutdown(root: CancellationToken) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => root.cancel(),
        _ = root.cancelled() => {},
    }
}

/// Serve MCP over bounded newline-delimited JSON streams.
pub async fn serve_io<R, W>(
    target: Resolved,
    options: ServerOptions,
    input: R,
    output: W,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    serve_io_with_root(target, options, input, output, CancellationToken::new()).await
}

async fn serve_io_with_root<R, W>(
    target: Resolved,
    options: ServerOptions,
    input: R,
    output: W,
    root: CancellationToken,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let context = validate_target(&target, &options)?;
    let mut cancel_on_drop = CancelSessionOnDrop::new(root.clone());
    let (complete, waiting) = oneshot::channel();
    thread::Builder::new()
        .name("elasticctl-mcp".to_string())
        .spawn(move || {
            let result = panic::catch_unwind(AssertUnwindSafe(|| {
                tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::new(), || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_io()
                        .enable_time()
                        .build()
                        .map_err(|_| mcp_runtime_error("MCP session runtime could not start"))?;
                    let result = runtime
                        .block_on(serve_session(target, options, input, output, root, context));
                    runtime.shutdown_background();
                    result
                })
            }));
            let result = match result {
                Ok(result) => result,
                Err(_) => Err(mcp_runtime_error("MCP session thread failed")),
            };
            let _ = complete.send(result);
        })
        .map_err(|_| mcp_runtime_error("MCP session thread could not start"))?;
    let result = waiting
        .await
        .map_err(|_| mcp_runtime_error("MCP session completion channel closed"))?;
    cancel_on_drop.disarm();
    result
}

struct CancelSessionOnDrop {
    root: CancellationToken,
    armed: bool,
}

impl CancelSessionOnDrop {
    fn new(root: CancellationToken) -> Self {
        Self { root, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelSessionOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.root.cancel();
        }
    }
}

fn mcp_runtime_error(message: &'static str) -> Error {
    Error::new(ErrorKind::Error, message)
}

async fn serve_session<R, W>(
    target: Resolved,
    options: ServerOptions,
    input: R,
    output: W,
    root: CancellationToken,
    context: TargetContext,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut state = ServerState::new(
        context,
        target,
        options.call_timeout,
        options.allow_query_tools,
    );
    state.allow_mutations = options.allow_mutations;
    let state = Arc::new(state);
    let mut transport = BoundedIo::with_cancellation(input, output, root.clone());
    let Some(first) = transport.receive().await else {
        return Ok(());
    };
    let replay = ReplayTransport::new(first.clone(), transport, root.clone());
    match first_path(&first) {
        FirstPath::Current => {
            let running = rmcp::service::serve_directly_with_ct(
                CurrentLifecycleService::new(McpServer::new(state)),
                replay,
                None,
                root,
            );
            running
                .waiting()
                .await
                .map_err(|_| Error::new(ErrorKind::Error, "MCP server task failed"))?;
        }
        FirstPath::LegacyGate => {
            let running = LegacyInitializationGate::new(McpServer::new(state))
                .serve_with_ct(replay, root)
                .await
                .map_err(|_| Error::new(ErrorKind::Error, "MCP protocol startup failed"))?;
            running
                .waiting()
                .await
                .map_err(|_| Error::new(ErrorKind::Error, "MCP server task failed"))?;
        }
        FirstPath::SdkStartup => {
            let running = McpServer::new(state)
                .serve_with_ct(replay, root)
                .await
                .map_err(|_| Error::new(ErrorKind::Error, "MCP protocol startup failed"))?;
            running
                .waiting()
                .await
                .map_err(|_| Error::new(ErrorKind::Error, "MCP server task failed"))?;
        }
    }
    Ok(())
}
