//! MCP stdio startup boundary.
//!
//! This module owns the diagnostics emitted before the MCP runtime receives
//! stdout. They stay static because configuration and parser failures can
//! contain credentials, paths, URLs, or command-line values.

use crate::cli::GlobalArgs;
use crate::context::{Context, config_path};
use elasticctl_core::Config;
use serde_json::json;
use std::io::Write;
use std::time::Duration;

const INVALID_ARGUMENTS: &str = "Invalid MCP serve arguments.";
const FORBIDDEN_GLOBALS: &str =
    "MCP serve accepts only --config, --profile, --space, and --timeout.";
const CONFIGURATION_FAILED: &str = "MCP startup configuration could not be resolved.";
const INVALID_TIMEOUT: &str = "MCP timeout must be between 1 and 120 seconds.";
const SERVER_FAILED: &str = "MCP server failed.";
const INSECURE_PERMISSIONS: &str =
    "Config file permissions allow access by other users; set mode 0600.";
const INSECURE_TLS: &str = "TLS certificate verification is disabled for the MCP target.";

/// Emit the privacy-preserving parser error for an invocation classified as
/// the MCP command group.
pub fn exit_usage() -> ! {
    finish_error(2, "error", INVALID_ARGUMENTS)
}

/// Resolve the target and delegate MCP stdio without entering the CLI renderer.
pub async fn serve(global: &GlobalArgs) -> ! {
    if global.yes
        || global.out.is_some()
        || global.fields.is_some()
        || global.json
        || global.format.is_some()
        || global.debug
    {
        finish_error(2, "error", FORBIDDEN_GLOBALS);
    }

    let context = match Context::build(global) {
        Ok(context) => context,
        Err(error) => finish_error(1, error.kind.as_str(), CONFIGURATION_FAILED),
    };
    let timeout_secs = context.resolved.profile.timeout_secs;
    if !(1..=120).contains(&timeout_secs) {
        finish_error(1, "error", INVALID_TIMEOUT);
    }

    if Config::permission_warning(&config_path(global)).is_some() {
        emit_warning("insecure_config_permissions", INSECURE_PERMISSIONS);
    }
    if !context.resolved.profile.verify {
        emit_warning("insecure_tls_verification", INSECURE_TLS);
    }

    let result = elasticctl_mcp::serve_stdio(
        context.resolved,
        elasticctl_mcp::ServerOptions {
            call_timeout: Duration::from_secs(timeout_secs),
            allow_query_tools: false,
        },
    )
    .await;
    let code = match result {
        Ok(()) => 0,
        Err(error) => {
            emit_error(error.kind.as_str(), SERVER_FAILED);
            1
        }
    };
    flush_and_exit(code)
}

fn emit_error(kind: &'static str, message: &'static str) {
    eprintln!("{}", json!({"error": {"kind": kind, "message": message}}));
}

fn emit_warning(kind: &'static str, message: &'static str) {
    eprintln!("{}", json!({"warning": {"kind": kind, "message": message}}));
}

fn finish_error(code: i32, kind: &'static str, message: &'static str) -> ! {
    emit_error(kind, message);
    flush_and_exit(code)
}

fn flush_and_exit(code: i32) -> ! {
    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();
    std::process::exit(code)
}
