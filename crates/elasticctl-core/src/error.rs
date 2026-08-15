//! Classify errors returned to the user.

use serde_json::{Value, json};

/// A stable error classification.
///
/// Its string values are part of the CLI's public API. Changing one requires a
/// minor version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Auth,
    Permission,
    NotFound,
    Conflict,
    Unsupported,
    Http,
    Connection,
    Timeout,
    Error,
}

impl ErrorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Permission => "permission",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Unsupported => "unsupported",
            Self::Http => "http",
            Self::Connection => "connection",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }

    pub fn from_status(status: u16) -> Self {
        match status {
            401 => Self::Auth,
            403 => Self::Permission,
            404 => Self::NotFound,
            409 => Self::Conflict,
            _ => Self::Http,
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct Error {
    pub kind: ErrorKind,
    pub http_status: Option<u16>,
    pub message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            http_status: None,
            message: message.into(),
        }
    }

    pub fn with_status(kind: ErrorKind, status: u16, message: impl Into<String>) -> Self {
        Self {
            kind,
            http_status: Some(status),
            message: message.into(),
        }
    }

    /// Classify an HTTP error response.
    ///
    /// Kibana returns `{"statusCode":..,"error":..,"message":..}`. The Elastic
    /// Cloud edge proxy returns `{"ok":false,"message":".."}`. The latter also
    /// appears when a project rename leaves a hostname unresolved. Elasticsearch
    /// returns `{"error":{"reason":"..","type":".."},"status":<int>}`.
    pub fn from_response_body(status: u16, body: &str) -> Self {
        let kind = ErrorKind::from_status(status);
        let message = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| {
                v.get("message")
                    .or_else(|| v.get("error").and_then(|e| e.get("reason")))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| {
                let trimmed = body.trim();
                if trimmed.is_empty() {
                    format!("HTTP {status}")
                } else {
                    format!("HTTP {status}: {trimmed}")
                }
            });
        Self {
            kind,
            http_status: Some(status),
            message,
        }
    }

    /// Return the JSON object written to stderr when a command fails.
    pub fn to_envelope(&self) -> Value {
        let mut inner = json!({ "kind": self.kind.as_str(), "message": self.message });
        if let Some(status) = self.http_status {
            inner["http_status"] = json!(status);
        }
        json!({ "error": inner })
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_maps_from_http_status() {
        assert_eq!(ErrorKind::from_status(401), ErrorKind::Auth);
        assert_eq!(ErrorKind::from_status(403), ErrorKind::Permission);
        assert_eq!(ErrorKind::from_status(404), ErrorKind::NotFound);
        assert_eq!(ErrorKind::from_status(409), ErrorKind::Conflict);
        assert_eq!(ErrorKind::from_status(500), ErrorKind::Http);
        assert_eq!(ErrorKind::from_status(418), ErrorKind::Http);
    }

    #[test]
    fn kind_str_values_are_the_documented_taxonomy() {
        assert_eq!(ErrorKind::Auth.as_str(), "auth");
        assert_eq!(ErrorKind::Permission.as_str(), "permission");
        assert_eq!(ErrorKind::NotFound.as_str(), "not_found");
        assert_eq!(ErrorKind::Conflict.as_str(), "conflict");
        assert_eq!(ErrorKind::Unsupported.as_str(), "unsupported");
        assert_eq!(ErrorKind::Http.as_str(), "http");
        assert_eq!(ErrorKind::Connection.as_str(), "connection");
        assert_eq!(ErrorKind::Timeout.as_str(), "timeout");
        assert_eq!(ErrorKind::Error.as_str(), "error");
    }

    // Kibana error envelope.
    #[test]
    fn parses_the_kibana_error_envelope() {
        let body = r#"{"statusCode":400,"error":"Bad Request","message":"rule_id already exists"}"#;
        let err = Error::from_response_body(400, body);
        assert_eq!(err.kind, ErrorKind::Http);
        assert_eq!(err.http_status, Some(400));
        assert_eq!(err.message, "rule_id already exists");
    }

    // Elastic Cloud edge-proxy error envelope.
    #[test]
    fn parses_the_cloud_edge_proxy_envelope() {
        let body = r#"{"ok":false,"message":"Unknown resource."}"#;
        let err = Error::from_response_body(404, body);
        assert_eq!(err.kind, ErrorKind::NotFound);
        assert_eq!(err.message, "Unknown resource.");
    }

    // Elasticsearch error envelope: {"error":{"reason":"..."},"status":<int>}.
    #[test]
    fn parses_the_elasticsearch_error_envelope() {
        let body = r#"{"error":{"root_cause":[{"type":"x_content_parse_exception","reason":"[1:68] [esql/query] unknown field [search_after]"}],"type":"x_content_parse_exception","reason":"[1:68] [esql/query] unknown field [search_after]"},"status":400}"#;
        let err = Error::from_response_body(400, body);
        assert_eq!(err.kind, ErrorKind::Http);
        assert_eq!(err.http_status, Some(400));
        assert_eq!(
            err.message,
            "[1:68] [esql/query] unknown field [search_after]"
        );
    }

    #[test]
    fn falls_back_to_the_raw_body_when_it_is_not_json() {
        let err = Error::from_response_body(502, "<html>bad gateway</html>");
        assert_eq!(err.kind, ErrorKind::Http);
        assert_eq!(err.http_status, Some(502));
        assert!(err.message.contains("bad gateway"));
    }

    #[test]
    fn falls_back_when_json_has_no_message_field() {
        let err = Error::from_response_body(500, r#"{"unexpected":true}"#);
        assert_eq!(err.kind, ErrorKind::Http);
        assert!(!err.message.is_empty());
    }

    #[test]
    fn envelope_is_the_documented_shape() {
        let err = Error::with_status(ErrorKind::Permission, 403, "nope");
        let env = err.to_envelope();
        assert_eq!(env["error"]["kind"], "permission");
        assert_eq!(env["error"]["http_status"], 403);
        assert_eq!(env["error"]["message"], "nope");
    }

    #[test]
    fn envelope_omits_http_status_when_absent() {
        let err = Error::new(ErrorKind::Connection, "dns failure");
        let env = err.to_envelope();
        assert_eq!(env["error"]["kind"], "connection");
        assert!(env["error"].get("http_status").is_none());
    }
}
