use std::{borrow::Cow, sync::Mutex};

use rmcp::{
    RoleServer, Service,
    model::{ClientJsonRpcMessage, ClientRequest, GetMeta, ProtocolVersion, ServerConfig},
    service::{RequestContext, RxJsonRpcMessage},
    transport::Transport as McpTransport,
};
use tokio_util::sync::CancellationToken;

pub(super) enum FirstPath {
    Current,
    LegacyGate,
    SdkStartup,
}

pub(super) fn first_path(message: &RxJsonRpcMessage<RoleServer>) -> FirstPath {
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

pub(super) struct ReplayTransport<T> {
    first: Option<RxJsonRpcMessage<RoleServer>>,
    inner: T,
    root: CancellationToken,
}

impl<T> ReplayTransport<T> {
    pub(super) fn new(
        first: RxJsonRpcMessage<RoleServer>,
        inner: T,
        root: CancellationToken,
    ) -> Self {
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

pub(super) struct CurrentLifecycleService<S> {
    inner: S,
}

impl<S> CurrentLifecycleService<S> {
    pub(super) fn new(inner: S) -> Self {
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

    fn get_info(&self) -> ServerConfig {
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

pub(super) struct LegacyInitializationGate<S> {
    inner: S,
    state: Mutex<LegacyState>,
}

impl<S> LegacyInitializationGate<S> {
    pub(super) fn new(inner: S) -> Self {
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

    fn get_info(&self) -> ServerConfig {
        self.inner.get_info()
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        self.inner.supported_protocol_versions()
    }
}
