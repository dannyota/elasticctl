use std::{
    borrow::Cow,
    panic::{self, AssertUnwindSafe},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use elasticctl_core::{Error, ErrorKind, Resolved, Result, Transport, TransportOptions};
use rmcp::{
    RoleServer, ServerHandler, Service, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, ClientJsonRpcMessage, ClientRequest, GetMeta,
        Implementation, ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult,
        ListToolsResult, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    service::{RequestContext, RxJsonRpcMessage},
    transport::Transport as McpTransport,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{
    sync::{Semaphore, oneshot},
    time,
};
use tokio_util::sync::CancellationToken;

use crate::{
    bounded_io::BoundedIo,
    catalog,
    error::{self, LocalError},
    result::{self, TargetContext},
    tools::{self, AdapterError, AdapterResult},
};

/// MCP runtime settings supplied by the caller after configuration resolution.
#[derive(Clone, Debug)]
pub struct ServerOptions {
    pub call_timeout: Duration,
    pub allow_query_tools: bool,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            call_timeout: Duration::from_secs(30),
            allow_query_tools: false,
        }
    }
}

/// Shared state passed to every vertical adapter.
pub struct ServerState {
    target: TargetContext,
    resolved: Resolved,
    transport: tokio::sync::OnceCell<Transport>,
    query_transport: tokio::sync::OnceCell<Transport>,
    allow_query_tools: bool,
    call_timeout: Duration,
    permits: Arc<Semaphore>,
}

impl ServerState {
    fn new(
        target: TargetContext,
        resolved: Resolved,
        call_timeout: Duration,
        allow_query_tools: bool,
    ) -> Self {
        Self {
            target,
            resolved,
            transport: tokio::sync::OnceCell::new(),
            query_transport: tokio::sync::OnceCell::new(),
            allow_query_tools,
            call_timeout,
            permits: Arc::new(Semaphore::new(4)),
        }
    }

    /// Lazily construct the one-attempt transport used only by query tools.
    pub async fn query_transport(&self) -> Result<&Transport> {
        self.query_transport
            .get_or_try_init(|| async {
                Transport::with_options(
                    &self.resolved.profile,
                    TransportOptions {
                        debug: false,
                        response_body_limit: Some(16_777_216),
                        disable_redirects: true,
                        disable_retries: true,
                    },
                )
            })
            .await
    }

    /// Lazily construct the restricted core transport shared by all adapters.
    pub async fn transport(&self) -> Result<&Transport> {
        self.transport
            .get_or_try_init(|| async {
                Transport::with_options(
                    &self.resolved.profile,
                    TransportOptions {
                        debug: false,
                        response_body_limit: Some(16_777_216),
                        disable_redirects: true,
                        disable_retries: false,
                    },
                )
            })
            .await
    }

    /// Return only the target identity safe for MCP output.
    pub fn target(&self) -> &TargetContext {
        &self.target
    }

    fn try_admit(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.permits.clone().try_acquire_owned().ok()
    }

    fn allows_query_tools(&self) -> bool {
        self.allow_query_tools
    }
}

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
    let state = Arc::new(ServerState::new(
        context,
        target,
        options.call_timeout,
        options.allow_query_tools,
    ));
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

/// Validate configuration that can be rejected before MCP startup or network I/O.
fn validate_target(target: &Resolved, options: &ServerOptions) -> Result<TargetContext> {
    let seconds = options.call_timeout.as_secs();
    if seconds == 0 || seconds > 120 || options.call_timeout.subsec_nanos() != 0 {
        return Err(Error::new(
            ErrorKind::Error,
            "MCP call timeout must be between 1 and 120 seconds",
        ));
    }
    validate_url("Kibana URL", &target.profile.kibana_url)?;
    validate_url(
        "Elasticsearch URL",
        target
            .profile
            .es_url
            .as_deref()
            .unwrap_or(&target.profile.kibana_url),
    )?;
    Ok(TargetContext {
        profile: target.name.clone(),
        host: target.profile.host(),
        space: target.profile.space.clone(),
    })
}

fn validate_url(field: &str, value: &str) -> Result<()> {
    let scheme_end = value.find("://").ok_or_else(|| {
        Error::new(
            ErrorKind::Error,
            format!("{field} must include an HTTP URL scheme"),
        )
    })?;
    let rest = &value[scheme_end + 3..];
    let doubled_scheme = rest
        .get(.."http://".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || rest
            .get(.."https://".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"));
    if rest.starts_with('/') || doubled_scheme {
        return Err(Error::new(
            ErrorKind::Error,
            format!("{field} must not contain a doubled URL scheme"),
        ));
    }
    let parsed = url::Url::parse(value)
        .map_err(|_| Error::new(ErrorKind::Error, format!("{field} must be a valid URL")))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(Error::new(
            ErrorKind::Error,
            format!("{field} must be an HTTP(S) URL with an authority and no query or fragment"),
        ));
    }
    Ok(())
}

/// Validate a selector or filter without changing caller-provided text.
#[allow(dead_code)] // Called by selector-bearing adapters added after the foundation runtime.
pub(crate) fn validate_text(field: &'static str, value: &str, max_bytes: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(Error::new(
            ErrorKind::Error,
            format!("{field} must contain non-whitespace text within {max_bytes} bytes"),
        ));
    }
    Ok(())
}

/// Validate a list page size.
#[allow(dead_code)] // Called by list adapters added after the foundation runtime.
pub(crate) fn validate_limit(value: usize) -> Result<()> {
    if !(1..=200).contains(&value) {
        return Err(Error::new(
            ErrorKind::Error,
            "limit must be between 1 and 200",
        ));
    }
    Ok(())
}

fn tool_failure_result(
    target: TargetContext,
    tool_error: crate::result::ToolError,
    request_id: &rmcp::model::NumberOrString,
) -> std::result::Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
    result::failure(target.clone(), tool_error, request_id)
        .or_else(|_| result::failure(target, error::local(LocalError::ResultTooLarge), request_id))
        .map_err(|_| rmcp::ErrorData::internal_error("MCP server error", None))
}

enum FirstPath {
    Current,
    LegacyGate,
    SdkStartup,
}

fn first_path(message: &RxJsonRpcMessage<RoleServer>) -> FirstPath {
    let ClientJsonRpcMessage::Request(request) = message else {
        return FirstPath::SdkStartup;
    };
    if matches!(request.request, ClientRequest::InitializeRequest(_)) {
        return FirstPath::SdkStartup;
    }
    let missing = request
        .request
        .get_meta()
        .missing_required_keys(&ProtocolVersion::V_2026_07_28);
    if missing.is_empty() {
        FirstPath::Current
    } else if matches!(request.request, ClientRequest::PingRequest(_)) {
        FirstPath::LegacyGate
    } else {
        FirstPath::SdkStartup
    }
}

struct ReplayTransport<T> {
    first: Option<RxJsonRpcMessage<RoleServer>>,
    inner: T,
    root: CancellationToken,
}

impl<T> ReplayTransport<T> {
    fn new(first: RxJsonRpcMessage<RoleServer>, inner: T, root: CancellationToken) -> Self {
        Self {
            first: Some(first),
            inner,
            root,
        }
    }
}

impl<T> McpTransport<RoleServer> for ReplayTransport<T>
where
    T: McpTransport<RoleServer>,
{
    type Error = T::Error;

    fn send(
        &mut self,
        item: rmcp::service::TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = std::result::Result<(), Self::Error>> + Send + 'static {
        self.inner.send(item)
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        if let Some(first) = self.first.take() {
            return Some(first);
        }
        let message = self.inner.receive().await;
        if message.is_none() {
            self.root.cancel();
            std::future::pending::<()>().await;
        }
        message
    }

    async fn close(&mut self) -> std::result::Result<(), Self::Error> {
        self.inner.close().await
    }
}

struct CurrentLifecycleService<S> {
    inner: S,
}

impl<S> CurrentLifecycleService<S> {
    fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> Service<RoleServer> for CurrentLifecycleService<S>
where
    S: Service<RoleServer>,
{
    async fn handle_request(
        &self,
        request: ClientRequest,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<rmcp::model::ServerResult, rmcp::ErrorData> {
        if matches!(request, ClientRequest::InitializeRequest(_)) {
            return Err(rmcp::ErrorData::invalid_request(
                "Initialize is unavailable after current startup",
                None,
            ));
        }
        let metadata = &context.meta;
        if !metadata
            .missing_required_keys(&ProtocolVersion::V_2026_07_28)
            .is_empty()
            || metadata.protocol_version() != Some(ProtocolVersion::V_2026_07_28)
        {
            return Err(rmcp::ErrorData::invalid_request(
                "Current MCP requests require valid current metadata",
                None,
            ));
        }
        self.inner.handle_request(request, context).await
    }

    async fn handle_notification(
        &self,
        notification: rmcp::model::ClientNotification,
        context: rmcp::service::NotificationContext<RoleServer>,
    ) -> std::result::Result<(), rmcp::ErrorData> {
        self.inner.handle_notification(notification, context).await
    }

    fn get_info(&self) -> ServerInfo {
        self.inner.get_info()
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        self.inner.supported_protocol_versions()
    }
}

enum LegacyState {
    AwaitingInitialize,
    Legacy,
    Rejected,
}

struct LegacyInitializationGate<S> {
    inner: S,
    state: Mutex<LegacyState>,
}

impl<S> LegacyInitializationGate<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            state: Mutex::new(LegacyState::AwaitingInitialize),
        }
    }
}

impl<S> Service<RoleServer> for LegacyInitializationGate<S>
where
    S: Service<RoleServer>,
{
    async fn handle_request(
        &self,
        request: ClientRequest,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<rmcp::model::ServerResult, rmcp::ErrorData> {
        let awaiting = matches!(
            *self.state.lock().expect("legacy gate lock poisoned"),
            LegacyState::AwaitingInitialize
        );
        if awaiting && !matches!(request, ClientRequest::InitializeRequest(_)) {
            *self.state.lock().expect("legacy gate lock poisoned") = LegacyState::Rejected;
            return Err(rmcp::ErrorData::invalid_request(
                "Initialize is required before legacy MCP requests",
                None,
            ));
        }
        if matches!(
            *self.state.lock().expect("legacy gate lock poisoned"),
            LegacyState::Rejected
        ) {
            return Err(rmcp::ErrorData::invalid_request(
                "Initialize is required before legacy MCP requests",
                None,
            ));
        }
        let result = self.inner.handle_request(request, context).await;
        if awaiting && result.is_ok() {
            *self.state.lock().expect("legacy gate lock poisoned") = LegacyState::Legacy;
        }
        result
    }

    async fn handle_notification(
        &self,
        notification: rmcp::model::ClientNotification,
        context: rmcp::service::NotificationContext<RoleServer>,
    ) -> std::result::Result<(), rmcp::ErrorData> {
        self.inner.handle_notification(notification, context).await
    }

    fn get_info(&self) -> ServerInfo {
        self.inner.get_info()
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        self.inner.supported_protocol_versions()
    }
}

struct McpServer {
    state: Arc<ServerState>,
}

#[cfg(test)]
struct TestControls {
    entered: std::sync::atomic::AtomicUsize,
    cancelled: std::sync::atomic::AtomicUsize,
    release: CancellationToken,
}

#[cfg(test)]
impl TestControls {
    fn new() -> Self {
        Self {
            entered: std::sync::atomic::AtomicUsize::new(0),
            cancelled: std::sync::atomic::AtomicUsize::new(0),
            release: CancellationToken::new(),
        }
    }
}

#[cfg(test)]
struct TestCallDrop(Arc<TestControls>);

#[cfg(test)]
impl Drop for TestCallDrop {
    fn drop(&mut self) {
        self.0
            .cancelled
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
fn test_controls() -> &'static Mutex<Option<Arc<TestControls>>> {
    static CONTROLS: std::sync::OnceLock<Mutex<Option<Arc<TestControls>>>> =
        std::sync::OnceLock::new();
    CONTROLS.get_or_init(|| Mutex::new(None))
}

impl McpServer {
    fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

enum DispatchTarget {
    Adapter(crate::catalog::ToolId, &'static dyn tools::ToolAdapter),
    #[cfg(test)]
    Synthetic(SyntheticTool),
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum SyntheticTool {
    Delay,
    Rows,
    OversizeRow,
    CpuDelay,
    InvalidArgument,
    RetryingCore,
}

fn dispatch_target(name: &str, allow_query_tools: bool) -> Option<DispatchTarget> {
    if let Some(tool) = crate::catalog::ToolId::parse(name) {
        if matches!(
            tool,
            crate::catalog::ToolId::SearchDsl | crate::catalog::ToolId::SearchEsql
        ) && !allow_query_tools
        {
            return None;
        }
        return tools::adapter_for(tool).map(|adapter| DispatchTarget::Adapter(tool, adapter));
    }
    #[cfg(test)]
    {
        Some(DispatchTarget::Synthetic(match name {
            "__test_delay" => SyntheticTool::Delay,
            "__test_rows" => SyntheticTool::Rows,
            "__test_oversize_row" => SyntheticTool::OversizeRow,
            "__test_cpu_delay" => SyntheticTool::CpuDelay,
            "__test_invalid_argument" => SyntheticTool::InvalidArgument,
            "__test_retrying_core" => SyntheticTool::RetryingCore,
            _ => return None,
        }))
    }
    #[cfg(not(test))]
    None
}

#[cfg(test)]
async fn synthetic_adapter(
    tool: SyntheticTool,
    state: &ServerState,
    cancellation: CancellationToken,
) -> std::result::Result<AdapterResult, AdapterError> {
    match tool {
        SyntheticTool::Delay => {
            let controls = test_controls()
                .lock()
                .expect("test controls lock poisoned")
                .clone()
                .ok_or(AdapterError::InvalidArgument)?;
            let _drop = TestCallDrop(Arc::clone(&controls));
            controls
                .entered
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::select! {
                _ = cancellation.cancelled() => Err(AdapterError::InvalidArgument),
                _ = controls.release.cancelled() => Ok(AdapterResult {
                    data: serde_json::json!({"synthetic": "complete"}),
                    page: None,
                    row_key: None,
                }),
            }
        }
        SyntheticTool::Rows => Ok(AdapterResult {
            data: serde_json::json!({ "rows": ["x".repeat(150_000), "x".repeat(150_000)] }),
            page: Some(crate::PageInfo {
                limit: 2,
                returned: 2,
                total: Some(2),
                has_more: Some(false),
                truncated: false,
            }),
            row_key: Some("rows"),
        }),
        SyntheticTool::OversizeRow => Ok(AdapterResult {
            data: serde_json::json!({ "rows": ["x".repeat(262_145)] }),
            page: Some(crate::PageInfo {
                limit: 1,
                returned: 1,
                total: Some(1),
                has_more: Some(false),
                truncated: false,
            }),
            row_key: Some("rows"),
        }),
        SyntheticTool::CpuDelay => {
            let until = std::time::Instant::now() + Duration::from_millis(1_100);
            while std::time::Instant::now() < until {
                std::hint::spin_loop();
            }
            Ok(AdapterResult {
                data: serde_json::json!({"synthetic": "late"}),
                page: None,
                row_key: None,
            })
        }
        SyntheticTool::InvalidArgument => Err(AdapterError::InvalidArgument),
        SyntheticTool::RetryingCore => {
            if let Some(controls) = test_controls()
                .lock()
                .expect("test controls lock poisoned")
                .clone()
            {
                controls
                    .entered
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            let transport = state.transport().await.map_err(AdapterError::Core)?;
            let value = transport.get("/retry").await.map_err(AdapterError::Core)?;
            Ok(AdapterResult {
                data: value,
                page: None,
                row_key: None,
            })
        }
    }
}

fn project_success(
    target: TargetContext,
    output: AdapterResult,
    request_id: &rmcp::model::NumberOrString,
) -> std::result::Result<CallToolResponse, Box<(TargetContext, crate::result::ToolError)>> {
    let AdapterResult {
        data,
        page,
        row_key,
    } = output;
    let result = match row_key {
        Some(row_key) => page.ok_or(LocalError::ResultTooLarge).and_then(|page| {
            result::success_with_truncated_rows(target.clone(), data, row_key, page, request_id)
        }),
        None => result::success(target.clone(), data, page, request_id),
    };
    result
        .map(Into::into)
        .map_err(|local| Box::new((target, error::local(local))))
}

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build());
        info.protocol_version = ProtocolVersion::V_2025_11_25;
        info.server_info = Implementation::new("elasticctl", env!("CARGO_PKG_VERSION"));
        info
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[ProtocolVersion::V_2026_07_28, ProtocolVersion::V_2025_11_25])
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<ListToolsResult, rmcp::ErrorData> {
        let _ = self.state.target();
        Ok(ListToolsResult {
            tools: catalog::definitions_for(self.state.allows_query_tools()),
            ..Default::default()
        })
    }

    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<ListResourcesResult, rmcp::ErrorData> {
        Err(unavailable_method_error())
    }

    async fn list_resource_templates(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<ListResourceTemplatesResult, rmcp::ErrorData> {
        Err(unavailable_method_error())
    }

    async fn list_prompts(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<ListPromptsResult, rmcp::ErrorData> {
        Err(unavailable_method_error())
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<CallToolResponse, rmcp::ErrorData> {
        let Some(dispatch) =
            dispatch_target(request.name.as_ref(), self.state.allows_query_tools())
        else {
            return Err(unknown_tool_error());
        };
        let Some(permit) = self.state.try_admit() else {
            return tool_failure_result(
                self.state.target().clone(),
                error::local(LocalError::Busy),
                &context.id,
            )
            .map(Into::into);
        };

        let cancellation = context.ct.clone();
        let target = self.state.target().clone();
        let request_id = context.id.clone();
        let state = Arc::clone(&self.state);
        let deadline = time::Instant::now() + self.state.call_timeout;
        let operation = async move {
            let _permit = permit;
            let outcome = match dispatch {
                DispatchTarget::Adapter(tool, adapter) => {
                    adapter
                        .call(
                            tool,
                            request.arguments.as_ref(),
                            &state,
                            cancellation.clone(),
                        )
                        .await
                }
                #[cfg(test)]
                DispatchTarget::Synthetic(tool) => {
                    synthetic_adapter(tool, &state, cancellation.clone()).await
                }
            };
            match outcome {
                Ok(output) => project_success(target.clone(), output, &request_id),
                Err(AdapterError::InvalidArgument) => Err(Box::new((
                    target,
                    error::local(LocalError::InvalidArgument),
                ))),
                Err(AdapterError::Core(core_error)) => {
                    Err(Box::new((target, error::core(&core_error))))
                }
            }
        };
        tokio::pin!(operation);
        tokio::select! {
            _ = context.ct.cancelled() => Err(rmcp::ErrorData::internal_error("MCP request cancelled", None)),
            outcome = time::timeout_at(deadline, &mut operation) => {
                if time::Instant::now() >= deadline {
                    tool_failure_result(
                        self.state.target().clone(),
                        error::local(LocalError::DeadlineExceeded),
                        &context.id,
                    ).map(Into::into)
                } else {
                    match outcome {
                        Ok(Ok(result)) => Ok(result),
                        Ok(Err(error)) => {
                            let (target, tool_error) = *error;
                            tool_failure_result(target, tool_error, &context.id).map(Into::into)
                        }
                        Err(_) => tool_failure_result(
                            self.state.target().clone(),
                            error::local(LocalError::DeadlineExceeded),
                            &context.id,
                        ).map(Into::into),
                    }
                }
            }
        }
    }
}

fn unknown_tool_error() -> rmcp::ErrorData {
    rmcp::ErrorData::new(
        rmcp::model::ErrorCode::METHOD_NOT_FOUND,
        "Unknown MCP tool",
        None,
    )
}

fn unavailable_method_error() -> rmcp::ErrorData {
    rmcp::ErrorData::new(
        rmcp::model::ErrorCode::METHOD_NOT_FOUND,
        "MCP method is unavailable",
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        ServerOptions, TestControls, test_controls, validate_limit, validate_target, validate_text,
    };
    use elasticctl_core::{Profile, Resolved, Source};
    use std::{
        io,
        pin::Pin,
        sync::{
            Arc, OnceLock,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        time::timeout,
    };

    fn resolved(kibana_url: &str, es_url: Option<&str>) -> Resolved {
        Resolved {
            name: "test".to_string(),
            source: Source::Profile,
            profile: Profile {
                kibana_url: kibana_url.to_string(),
                es_url: es_url.map(str::to_string),
                api_key: None,
                username: None,
                password: None,
                space: "default".to_string(),
                verify: true,
                timeout_secs: 30,
            },
        }
    }

    #[test]
    fn validates_text_without_normalizing_it() {
        assert!(validate_text("selector", "value", 1_024).is_ok());
        assert!(validate_text("selector", "   ", 1_024).is_err());
        assert!(validate_text("selector", &"a".repeat(1_025), 1_024).is_err());
        assert!(validate_text("selector", &"é".repeat(512), 1_024).is_ok());
        assert!(validate_text("selector", &"é".repeat(513), 1_024).is_err());
    }

    #[test]
    fn validates_list_limits_at_both_boundaries() {
        assert!(validate_limit(0).is_err());
        assert!(validate_limit(1).is_ok());
        assert!(validate_limit(200).is_ok());
        assert!(validate_limit(201).is_err());
    }

    #[test]
    fn rejects_doubled_schemes_in_both_resolved_urls() {
        let options = ServerOptions {
            call_timeout: Duration::from_secs(30),
            allow_query_tools: false,
        };
        assert!(
            validate_target(
                &resolved("https://https://kibana.example.test", None),
                &options
            )
            .is_err()
        );
        assert!(
            validate_target(
                &resolved(
                    "https://kibana.example.test",
                    Some("https://https://es.example.test"),
                ),
                &options,
            )
            .is_err()
        );
    }

    #[test]
    fn preserves_scheme_text_inside_a_valid_base_path() {
        let options = ServerOptions::default();
        assert!(
            validate_target(
                &resolved(
                    "https://kibana.example.test/proxy/https://upstream",
                    Some("https://es.example.test/proxy/http://upstream"),
                ),
                &options,
            )
            .is_ok()
        );
    }

    #[test]
    fn validates_each_resolved_url_and_timeout_boundary_before_startup() {
        let valid = "https://example.test/base";
        let options = ServerOptions::default();
        for invalid in [
            "ftp://example.test",
            "https:///missing-authority",
            "https://example.test/?query=1",
            "https://example.test/#fragment",
            "https://https://example.test",
        ] {
            assert!(
                validate_target(&resolved(invalid, Some(valid)), &options).is_err(),
                "Kibana URL unexpectedly accepted {invalid}"
            );
            assert!(
                validate_target(&resolved(valid, Some(invalid)), &options).is_err(),
                "Elasticsearch URL unexpectedly accepted {invalid}"
            );
        }
        for seconds in [0, 121] {
            assert!(
                validate_target(
                    &resolved(valid, Some(valid)),
                    &ServerOptions {
                        call_timeout: Duration::from_secs(seconds),
                        allow_query_tools: false,
                    },
                )
                .is_err()
            );
        }
        for seconds in [1, 120] {
            assert!(
                validate_target(
                    &resolved(valid, Some(valid)),
                    &ServerOptions {
                        call_timeout: Duration::from_secs(seconds),
                        allow_query_tools: false,
                    },
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn tool_failure_is_serialized_as_matching_structured_and_text_content() {
        let result = super::tool_failure_result(
            elasticctl_mcp_test_target(),
            crate::error::local(crate::error::LocalError::Busy),
            &rmcp::model::NumberOrString::Number(1),
        )
        .expect("test result serializes");
        assert_eq!(
            result
                .structured_content
                .as_ref()
                .expect("structured result"),
            &serde_json::from_str::<serde_json::Value>(
                serde_json::to_value(&result).expect("result serializes")["content"][0]["text"]
                    .as_str()
                    .expect("text content"),
            )
            .expect("text is JSON"),
        );
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn central_router_truncates_rows_and_returns_result_too_large() {
        let (mut input, server_input) = tokio::io::duplex(1_048_576);
        let (server_output, output) = tokio::io::duplex(1_048_576);
        let server = tokio::spawn(super::serve_io(
            resolved("https://kibana.example.test", None),
            ServerOptions::default(),
            server_input,
            server_output,
        ));
        let mut output = BufReader::new(output);
        send_current(
            &mut input,
            60,
            "tools/call",
            serde_json::json!({
                "_meta": current_meta(),
                "name": "__test_rows",
                "arguments": {},
            }),
        )
        .await;
        let mut line = Vec::new();
        timeout(Duration::from_secs(1), output.read_until(b'\n', &mut line))
            .await
            .expect("truncated response arrives")
            .expect("test reads truncated response");
        let truncated: serde_json::Value = serde_json::from_slice(&line).expect("response is JSON");
        assert_eq!(truncated["id"], 60);
        assert_eq!(
            truncated["result"]["structuredContent"]["data"]["rows"]
                .as_array()
                .expect("rows are an array")
                .len(),
            1
        );
        assert_eq!(
            truncated["result"]["structuredContent"]["page"]["truncated"],
            true
        );
        assert_eq!(
            truncated["result"]["structuredContent"]["page"]["has_more"],
            true
        );
        assert_eq!(truncated["result"]["resultType"], "complete");

        send_current(
            &mut input,
            61,
            "tools/call",
            serde_json::json!({
                "_meta": current_meta(),
                "name": "__test_invalid_argument",
                "arguments": { "credential": "credential-argument-sentinel" },
            }),
        )
        .await;
        line.clear();
        timeout(Duration::from_secs(1), output.read_until(b'\n', &mut line))
            .await
            .expect("safe argument failure arrives")
            .expect("test reads safe argument failure");
        let invalid: serde_json::Value = serde_json::from_slice(&line).expect("response is JSON");
        assert_eq!(invalid["id"], 61);
        assert_eq!(
            invalid["result"]["structuredContent"]["error"]["code"],
            "invalid_argument"
        );
        assert!(!invalid.to_string().contains("credential-argument-sentinel"));

        send_current(
            &mut input,
            63,
            "tools/call",
            serde_json::json!({
                "_meta": current_meta(),
                "name": "__test_oversize_row",
                "arguments": {},
            }),
        )
        .await;
        line.clear();
        timeout(Duration::from_secs(1), output.read_until(b'\n', &mut line))
            .await
            .expect("oversize failure arrives")
            .expect("test reads oversize failure");
        let too_large: serde_json::Value = serde_json::from_slice(&line).expect("response is JSON");
        assert_eq!(too_large["id"], 63);
        assert_eq!(
            too_large["result"]["structuredContent"]["error"]["code"],
            "result_too_large"
        );

        drop(input);
        timeout(Duration::from_secs(5), server)
            .await
            .expect("server shuts down within grace")
            .expect("server task does not panic")
            .expect("server returns cleanly");
    }

    #[tokio::test]
    async fn central_router_rejects_a_synchronous_result_that_finishes_after_deadline() {
        let (mut input, server_input) = tokio::io::duplex(16_384);
        let (server_output, output) = tokio::io::duplex(16_384);
        let server = tokio::spawn(super::serve_io(
            resolved("https://kibana.example.test", None),
            ServerOptions {
                call_timeout: Duration::from_secs(1),
                allow_query_tools: false,
            },
            server_input,
            server_output,
        ));
        let mut output = BufReader::new(output);
        send_current(
            &mut input,
            62,
            "tools/call",
            serde_json::json!({
                "_meta": current_meta(),
                "name": "__test_cpu_delay",
                "arguments": {},
            }),
        )
        .await;
        let mut line = Vec::new();
        timeout(Duration::from_secs(2), output.read_until(b'\n', &mut line))
            .await
            .expect("late result is converted to a deadline failure")
            .expect("test reads deadline failure");
        let response: serde_json::Value = serde_json::from_slice(&line).expect("response is JSON");
        assert_eq!(response["id"], 62);
        assert_eq!(
            response["result"]["structuredContent"]["error"]["code"],
            "deadline_exceeded"
        );
        drop(input);
        timeout(Duration::from_secs(5), server)
            .await
            .expect("server shuts down within grace")
            .expect("server task does not panic")
            .expect("server returns cleanly");
    }

    #[tokio::test]
    async fn central_deadline_stops_a_retrying_core_call() {
        let _serial = synthetic_test_lock().lock().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener binds");
        let address = listener.local_addr().expect("listener address");
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&requests);
        let responder = tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut socket, _) = listener.accept().await.expect("test accepts core request");
                let mut request = [0_u8; 4_096];
                let read = socket
                    .read(&mut request)
                    .await
                    .expect("test reads core request");
                assert!(read > 0, "core transport sends an HTTP request");
                observed.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    socket
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .await
                        .expect("test returns a retryable status");
                } else {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        });

        let (mut input, server_input) = tokio::io::duplex(16_384);
        let (server_output, output) = tokio::io::duplex(16_384);
        let mut retry_target = resolved(&format!("http://{address}"), None);
        retry_target.profile.api_key = Some("test-api-key".to_string());
        let server = tokio::spawn(super::serve_io(
            retry_target,
            ServerOptions {
                call_timeout: Duration::from_secs(1),
                allow_query_tools: false,
            },
            server_input,
            server_output,
        ));
        let mut output = BufReader::new(output);
        send_current(
            &mut input,
            64,
            "tools/call",
            serde_json::json!({
                "_meta": current_meta(),
                "name": "__test_retrying_core",
                "arguments": {},
            }),
        )
        .await;
        wait_for(&requests, 2).await;
        let mut line = Vec::new();
        timeout(Duration::from_secs(2), output.read_until(b'\n', &mut line))
            .await
            .expect("deadline failure arrives while the retry remains in flight")
            .expect("test reads deadline failure");
        let response: serde_json::Value = serde_json::from_slice(&line).expect("response is JSON");
        assert_eq!(response["id"], 64);
        assert_eq!(
            response["result"]["structuredContent"]["error"]["code"],
            "deadline_exceeded"
        );
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        drop(input);
        timeout(Duration::from_secs(5), server)
            .await
            .expect("server shuts down within grace")
            .expect("server task does not panic")
            .expect("server returns cleanly");
        responder.abort();
        assert!(
            responder.await.is_err(),
            "test responder is intentionally stopped"
        );
    }

    #[tokio::test]
    async fn discovery_does_not_construct_or_call_the_configured_core_transport() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener binds");
        let address = listener.local_addr().expect("listener address");
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&requests);
        let probe = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.expect("test accepts connection");
                observed.fetch_add(1, Ordering::SeqCst);
                socket.shutdown().await.expect("test closes connection");
            }
        });
        let (mut input, server_input) = tokio::io::duplex(8_192);
        let (server_output, output) = tokio::io::duplex(8_192);
        let mut discovery_target = resolved(&format!("http://{address}"), None);
        discovery_target.profile.api_key = Some("test-api-key".to_string());
        let server = tokio::spawn(super::serve_io(
            discovery_target,
            ServerOptions::default(),
            server_input,
            server_output,
        ));
        let mut output = BufReader::new(output);
        send_current(
            &mut input,
            65,
            "server/discover",
            serde_json::json!({ "_meta": current_meta() }),
        )
        .await;
        let mut line = Vec::new();
        timeout(Duration::from_secs(1), output.read_until(b'\n', &mut line))
            .await
            .expect("discovery response arrives")
            .expect("test reads discovery response");
        let response: serde_json::Value = serde_json::from_slice(&line).expect("response is JSON");
        assert_eq!(response["id"], 65);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        drop(input);
        timeout(Duration::from_secs(5), server)
            .await
            .expect("server shuts down within grace")
            .expect("server task does not panic")
            .expect("server returns cleanly");
        probe.abort();
        assert!(probe.await.is_err(), "test probe is intentionally stopped");
    }

    #[tokio::test]
    async fn bare_legacy_ping_blocks_a_current_synthetic_tool_before_handler_or_elastic_io() {
        let _serial = synthetic_test_lock().lock().await;
        let controls = Arc::new(TestControls::new());
        *test_controls().lock().expect("test controls lock poisoned") = Some(controls.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener binds");
        let address = listener.local_addr().expect("listener address");
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&requests);
        let probe = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.expect("test accepts connection");
                observed.fetch_add(1, Ordering::SeqCst);
                socket.shutdown().await.expect("test closes connection");
            }
        });

        let (mut input, server_input) = tokio::io::duplex(8_192);
        let (server_output, output) = tokio::io::duplex(8_192);
        let mut retry_target = resolved(&format!("http://{address}"), None);
        retry_target.profile.api_key = Some("test-api-key".to_string());
        let server = tokio::spawn(super::serve_io(
            retry_target,
            ServerOptions::default(),
            server_input,
            server_output,
        ));
        let mut output = BufReader::new(output);

        send_current(&mut input, 70, "ping", serde_json::json!({})).await;
        let mut line = Vec::new();
        timeout(Duration::from_secs(1), output.read_until(b'\n', &mut line))
            .await
            .expect("legacy ping response arrives")
            .expect("test reads legacy ping response");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&line).expect("response is JSON")["id"],
            70
        );

        send_current(
            &mut input,
            71,
            "tools/call",
            serde_json::json!({
                "_meta": current_meta(),
                "name": "__test_retrying_core",
                "arguments": {},
            }),
        )
        .await;
        line.clear();
        timeout(Duration::from_secs(1), output.read_until(b'\n', &mut line))
            .await
            .expect("legacy gate rejection arrives")
            .expect("test reads legacy gate rejection");
        let rejection: serde_json::Value = serde_json::from_slice(&line).expect("response is JSON");
        assert_eq!(rejection["id"], 71);
        assert_eq!(rejection["error"]["code"], -32600);
        assert_eq!(rejection["error"]["message"], "Invalid MCP request");
        assert!(rejection.get("result").is_none());
        assert_eq!(controls.entered.load(Ordering::SeqCst), 0);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(requests.load(Ordering::SeqCst), 0);

        drop(input);
        timeout(Duration::from_secs(5), server)
            .await
            .expect("server shuts down within grace")
            .expect("server task does not panic")
            .expect("server returns cleanly");
        probe.abort();
        assert!(probe.await.is_err(), "test probe is intentionally stopped");
        *test_controls().lock().expect("test controls lock poisoned") = None;
    }

    fn elasticctl_mcp_test_target() -> super::TargetContext {
        super::TargetContext {
            profile: "test".to_string(),
            host: "example.test".to_string(),
            space: "default".to_string(),
        }
    }

    fn synthetic_test_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    struct StalledWriter {
        write_started: Arc<AtomicBool>,
        shutdown_started: Arc<AtomicBool>,
    }

    struct DropWriter {
        inner: tokio::io::Sink,
        dropped: Arc<AtomicBool>,
    }

    impl DropWriter {
        fn new() -> (Self, Arc<AtomicBool>) {
            let dropped = Arc::new(AtomicBool::new(false));
            (
                Self {
                    inner: tokio::io::sink(),
                    dropped: Arc::clone(&dropped),
                },
                dropped,
            )
        }
    }

    impl Drop for DropWriter {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl tokio::io::AsyncWrite for DropWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buffer)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
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

    async fn send_current(
        input: &mut tokio::io::DuplexStream,
        id: i64,
        method: &str,
        params: serde_json::Value,
    ) {
        let mut frame = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .expect("test request serializes");
        frame.push(b'\n');
        input.write_all(&frame).await.expect("test writes request");
    }

    fn current_meta() -> serde_json::Value {
        serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        })
    }

    async fn wait_for(counter: &std::sync::atomic::AtomicUsize, expected: usize) {
        if timeout(Duration::from_secs(1), async {
            while counter.load(std::sync::atomic::Ordering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_err()
        {
            panic!(
                "synthetic handlers entered too slowly: expected {expected}, observed {}",
                counter.load(std::sync::atomic::Ordering::SeqCst)
            );
        }
    }

    #[tokio::test]
    async fn direct_first_call_admits_four_cancels_and_never_replies_after_cancellation() {
        let _serial = synthetic_test_lock().lock().await;
        let controls = Arc::new(TestControls::new());
        *test_controls().lock().expect("test controls lock poisoned") = Some(controls.clone());

        let (mut input, server_input) = tokio::io::duplex(32_768);
        let (server_output, output) = tokio::io::duplex(32_768);
        let server = tokio::spawn(super::serve_io(
            resolved("https://kibana.example.test", None),
            ServerOptions::default(),
            server_input,
            server_output,
        ));
        let mut output = BufReader::new(output);

        for id in 1..=4 {
            send_current(
                &mut input,
                id,
                "tools/call",
                serde_json::json!({
                    "_meta": current_meta(),
                    "name": "__test_delay",
                    "arguments": {},
                }),
            )
            .await;
        }
        wait_for(&controls.entered, 4).await;
        send_current(
            &mut input,
            5,
            "tools/call",
            serde_json::json!({
                "_meta": current_meta(),
                "name": "__test_delay",
                "arguments": {},
            }),
        )
        .await;
        let mut line = Vec::new();
        timeout(
            Duration::from_millis(250),
            output.read_until(b'\n', &mut line),
        )
        .await
        .expect("fifth call is rejected without queueing")
        .expect("test reads busy result");
        let busy: serde_json::Value = serde_json::from_slice(&line).expect("busy result is JSON");
        assert_eq!(busy["id"], 5);
        assert_eq!(busy["result"]["structuredContent"]["error"]["code"], "busy");
        assert_eq!(busy["result"]["isError"], true);

        let mut cancelled = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {
                "requestId": 1,
                "reason": "test",
                "_meta": current_meta(),
            },
        }))
        .expect("test notification serializes");
        cancelled.push(b'\n');
        input
            .write_all(&cancelled)
            .await
            .expect("test cancels first call");
        wait_for(&controls.cancelled, 1).await;

        send_current(
            &mut input,
            6,
            "tools/call",
            serde_json::json!({
                "_meta": current_meta(),
                "name": "__test_delay",
                "arguments": {},
            }),
        )
        .await;
        wait_for(&controls.entered, 5).await;
        controls.release.cancel();

        let mut ids = Vec::new();
        while ids.len() < 4 {
            let mut line = Vec::new();
            timeout(
                Duration::from_millis(250),
                output.read_until(b'\n', &mut line),
            )
            .await
            .expect("remaining calls complete")
            .expect("test reads completed result");
            let response: serde_json::Value =
                serde_json::from_slice(&line).expect("completed result is JSON");
            ids.push(response["id"].as_i64().expect("response has an id"));
        }
        ids.sort_unstable();
        assert_eq!(ids, vec![2, 3, 4, 6]);
        drop(input);
        timeout(Duration::from_secs(5), server)
            .await
            .expect("server shuts down within grace")
            .expect("server task does not panic")
            .expect("server returns cleanly");
        *test_controls().lock().expect("test controls lock poisoned") = None;
    }

    #[tokio::test]
    async fn direct_first_call_deadline_releases_its_permit() {
        let _serial = synthetic_test_lock().lock().await;
        let controls = Arc::new(TestControls::new());
        *test_controls().lock().expect("test controls lock poisoned") = Some(controls.clone());
        let (mut input, server_input) = tokio::io::duplex(8_192);
        let (server_output, output) = tokio::io::duplex(8_192);
        let server = tokio::spawn(super::serve_io(
            resolved("https://kibana.example.test", None),
            ServerOptions {
                call_timeout: Duration::from_secs(1),
                allow_query_tools: false,
            },
            server_input,
            server_output,
        ));
        let mut output = BufReader::new(output);
        send_current(
            &mut input,
            30,
            "tools/call",
            serde_json::json!({
                "_meta": current_meta(),
                "name": "__test_delay",
                "arguments": {},
            }),
        )
        .await;
        wait_for(&controls.entered, 1).await;
        let mut line = Vec::new();
        timeout(Duration::from_secs(2), output.read_until(b'\n', &mut line))
            .await
            .expect("deadline response arrives")
            .expect("test reads deadline response");
        let deadline: serde_json::Value = serde_json::from_slice(&line).expect("deadline is JSON");
        assert_eq!(deadline["id"], 30);
        assert_eq!(
            deadline["result"]["structuredContent"]["error"]["code"],
            "deadline_exceeded"
        );

        send_current(
            &mut input,
            31,
            "tools/call",
            serde_json::json!({
                "_meta": current_meta(),
                "name": "__test_delay",
                "arguments": {},
            }),
        )
        .await;
        wait_for(&controls.entered, 2).await;
        controls.release.cancel();
        let mut line = Vec::new();
        timeout(
            Duration::from_millis(250),
            output.read_until(b'\n', &mut line),
        )
        .await
        .expect("replacement call uses released permit")
        .expect("test reads replacement response");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&line).expect("response is JSON")["id"],
            31
        );
        drop(input);
        timeout(Duration::from_secs(5), server)
            .await
            .expect("server shuts down within grace")
            .expect("server task does not panic")
            .expect("server returns cleanly");
        *test_controls().lock().expect("test controls lock poisoned") = None;
    }

    #[tokio::test]
    async fn eof_cancels_a_blocked_direct_first_call_within_the_shutdown_grace() {
        let _serial = synthetic_test_lock().lock().await;
        let controls = Arc::new(TestControls::new());
        *test_controls().lock().expect("test controls lock poisoned") = Some(controls.clone());
        let (mut input, server_input) = tokio::io::duplex(8_192);
        let (server_output, _output) = tokio::io::duplex(8_192);
        let server = tokio::spawn(super::serve_io(
            resolved("https://kibana.example.test", None),
            ServerOptions::default(),
            server_input,
            server_output,
        ));
        send_current(
            &mut input,
            40,
            "tools/call",
            serde_json::json!({
                "_meta": current_meta(),
                "name": "__test_delay",
                "arguments": {},
            }),
        )
        .await;
        wait_for(&controls.entered, 1).await;
        drop(input);
        wait_for(&controls.cancelled, 1).await;
        timeout(Duration::from_secs(5), server)
            .await
            .expect("server shuts down within grace")
            .expect("server task does not panic")
            .expect("server returns cleanly");
        *test_controls().lock().expect("test controls lock poisoned") = None;
    }

    #[tokio::test]
    async fn dropping_the_public_future_cancels_and_releases_the_isolated_session() {
        let _serial = synthetic_test_lock().lock().await;
        let controls = Arc::new(TestControls::new());
        *test_controls().lock().expect("test controls lock poisoned") = Some(controls.clone());
        let (mut input, server_input) = tokio::io::duplex(8_192);
        let (writer, dropped) = DropWriter::new();
        let session = tokio::spawn(super::serve_io(
            resolved("https://kibana.example.test", None),
            ServerOptions::default(),
            server_input,
            writer,
        ));
        send_current(
            &mut input,
            45,
            "tools/call",
            serde_json::json!({
                "_meta": current_meta(),
                "name": "__test_delay",
                "arguments": {},
            }),
        )
        .await;
        wait_for(&controls.entered, 1).await;
        session.abort();
        assert!(
            session.await.is_err(),
            "caller task is intentionally aborted"
        );
        wait_for(&controls.cancelled, 1).await;
        timeout(Duration::from_secs(5), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("caller drop releases the isolated writer after cleanup");
        drop(input);
        *test_controls().lock().expect("test controls lock poisoned") = None;
    }

    #[tokio::test]
    async fn stalled_response_writer_cannot_extend_the_shutdown_grace() {
        let (mut input, server_input) = tokio::io::duplex(8_192);
        let (writer, write_started, shutdown_started) = StalledWriter::new();
        let server = tokio::spawn(super::serve_io(
            resolved("https://kibana.example.test", None),
            ServerOptions::default(),
            server_input,
            writer,
        ));
        send_current(
            &mut input,
            50,
            "tools/list",
            serde_json::json!({ "_meta": current_meta() }),
        )
        .await;
        timeout(Duration::from_secs(1), async {
            while !write_started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("server starts its stalled response write");
        drop(input);
        let _result = timeout(Duration::from_secs(5), server)
            .await
            .expect("stalled writer cannot exceed shutdown grace")
            .expect("server task does not panic");
        assert!(
            shutdown_started.load(Ordering::SeqCst),
            "the bounded close path owns stalled shutdown"
        );
    }
}
