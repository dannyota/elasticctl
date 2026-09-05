//! Safe MCP-local error classifications.

use elasticctl_core::{Error, ErrorKind};

use crate::ToolError;

const INVALID_ARGUMENT_MESSAGE: &str = "The tool arguments are invalid.";
const BUSY_MESSAGE: &str = "Too many active tool calls are in progress.";
const DEADLINE_MESSAGE: &str = "The tool call exceeded its time limit.";
const RESULT_TOO_LARGE_MESSAGE: &str = "The tool result exceeds the configured size limit.";

/// Return a static local tool failure. No caller-provided values are included.
pub(crate) fn local(code: LocalError) -> ToolError {
    let (kind, code, message) = match code {
        LocalError::InvalidArgument => ("error", "invalid_argument", INVALID_ARGUMENT_MESSAGE),
        LocalError::Busy => ("error", "busy", BUSY_MESSAGE),
        LocalError::DeadlineExceeded => ("timeout", "deadline_exceeded", DEADLINE_MESSAGE),
        LocalError::ResultTooLarge => ("unsupported", "result_too_large", RESULT_TOO_LARGE_MESSAGE),
    };
    ToolError {
        kind: kind.to_string(),
        http_status: None,
        code: code.to_string(),
        message: message.to_string(),
    }
}

/// Map a core failure without exposing its remote or transport message.
pub(crate) fn core(error: &Error) -> ToolError {
    let message = match error.kind {
        ErrorKind::Auth => "The selected credential could not be authenticated.",
        ErrorKind::Permission => "The selected credential cannot read this data.",
        ErrorKind::NotFound => "The selected resource was not found.",
        ErrorKind::Conflict => "The selected resource conflicts with current state.",
        ErrorKind::Unsupported => "The selected deployment does not support this operation.",
        ErrorKind::Http => "The selected deployment returned an HTTP error.",
        ErrorKind::Connection => "The selected deployment could not be reached.",
        ErrorKind::Timeout => "The selected deployment did not respond before the timeout.",
        ErrorKind::Error => "The request could not be completed.",
    };
    ToolError {
        kind: error.kind.as_str().to_string(),
        http_status: error.http_status,
        code: format!("elastic_{}", error.kind.as_str()),
        message: message.to_string(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalError {
    InvalidArgument,
    Busy,
    DeadlineExceeded,
    ResultTooLarge,
}

#[cfg(test)]
mod tests {
    use super::{LocalError, core, local};
    use elasticctl_core::{Error, ErrorKind};

    #[test]
    fn core_errors_keep_only_the_classification_and_status() {
        let error = Error::with_status(
            ErrorKind::Permission,
            403,
            "credential-sentinel and remote body must not escape",
        );
        let mapped = core(&error);
        assert_eq!(mapped.kind, "permission");
        assert_eq!(mapped.http_status, Some(403));
        assert_eq!(mapped.code, "elastic_permission");
        assert_eq!(
            mapped.message,
            "The selected credential cannot read this data."
        );
        assert!(
            !serde_json::to_string(&mapped)
                .expect("mapped error serializes")
                .contains("credential-sentinel")
        );
    }

    #[test]
    fn local_error_codes_are_static_and_stable() {
        let cases = [
            (LocalError::InvalidArgument, "error", "invalid_argument"),
            (LocalError::Busy, "error", "busy"),
            (LocalError::DeadlineExceeded, "timeout", "deadline_exceeded"),
            (
                LocalError::ResultTooLarge,
                "unsupported",
                "result_too_large",
            ),
        ];
        for (kind, expected_kind, expected_code) in cases {
            let error = local(kind);
            assert_eq!(error.kind, expected_kind);
            assert_eq!(error.code, expected_code);
        }
    }

    #[test]
    fn every_core_error_kind_uses_a_static_code_and_message() {
        let cases = [
            ErrorKind::Auth,
            ErrorKind::Permission,
            ErrorKind::NotFound,
            ErrorKind::Conflict,
            ErrorKind::Unsupported,
            ErrorKind::Http,
            ErrorKind::Connection,
            ErrorKind::Timeout,
            ErrorKind::Error,
        ];
        for kind in cases {
            let mapped = core(&Error::new(kind, "credential-sentinel and remote detail"));
            assert_eq!(mapped.code, format!("elastic_{}", kind.as_str()));
            assert!(!mapped.message.contains("credential-sentinel"));
        }
    }
}
