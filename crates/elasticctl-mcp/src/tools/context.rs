use rmcp::{
    RoleServer,
    model::{ClientCapabilities, ProtocolVersion},
    service::RequestContext,
};

/// Supported protocol revisions for adapter calls and audit records.
#[derive(Clone, Copy, Debug, Default)]
pub enum CallProtocol {
    Legacy,
    #[default]
    Current,
}
impl CallProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "2025-11-25",
            Self::Current => "2026-07-28",
        }
    }
}

/// Metadata from the session lifecycle for one tool call.
#[derive(Clone, Debug, Default)]
pub struct CallContext {
    pub form_elicitation: bool,
    pub protocol: CallProtocol,
}
impl CallContext {
    pub(crate) fn from_request(
        context: &RequestContext<RoleServer>,
    ) -> Result<Self, rmcp::ErrorData> {
        if let Some(info) = context.peer.peer_info()
            && context
                .meta
                .protocol_version()
                .is_some_and(|v| v != info.protocol_version)
        {
            return Err(rmcp::ErrorData::invalid_request(
                "MCP protocol does not match the session",
                None,
            ));
        }
        // The SDK stores negotiated initialize data in peer_info. Direct startup has none.
        let (version, capabilities) = if let Some(info) = context.peer.peer_info() {
            (
                Some(info.protocol_version.clone()),
                Some(info.capabilities.clone()),
            )
        } else {
            (
                context.meta.protocol_version(),
                context.meta.client_capabilities(),
            )
        };
        let protocol = match version {
            Some(v) if v == ProtocolVersion::V_2025_11_25 => CallProtocol::Legacy,
            Some(v) if v == ProtocolVersion::V_2026_07_28 => CallProtocol::Current,
            _ => {
                return Err(rmcp::ErrorData::invalid_request(
                    "Unsupported MCP protocol",
                    None,
                ));
            }
        };
        Ok(Self {
            protocol,
            form_elicitation: supports_form(capabilities),
        })
    }
}

fn supports_form(capabilities: Option<ClientCapabilities>) -> bool {
    capabilities
        .and_then(|c| c.elicitation)
        .is_some_and(|e| e.form.is_some() || e.url.is_none())
}
