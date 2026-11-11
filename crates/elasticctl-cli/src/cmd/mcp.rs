//! MCP stdio startup boundary.
//!
//! This module owns the diagnostics emitted before the MCP runtime receives
//! stdout. They stay static because configuration and parser failures can
//! contain credentials, paths, URLs, or command-line values.

use crate::cli::GlobalArgs;
use crate::context::{Context, config_path};
use elasticctl_core::Config;
use elasticctl_mcp::MUTATION_TARGET_MESSAGE;
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
pub async fn serve(global: &GlobalArgs, allow_query_tools: bool, values: &[String]) -> ! {
    if global.yes
        || global.out.is_some()
        || global.fields.is_some()
        || global.json
        || global.format.is_some()
        || global.debug
    {
        finish_error(2, "error", FORBIDDEN_GLOBALS);
    }

    let allow_mutations = match elasticctl_mcp::MutationClasses::parse(values) {
        Ok(classes) => classes,
        Err(_) => exit_usage(),
    };

    let context = match Context::build(global) {
        Ok(context) => context,
        Err(error) => finish_error(1, error.kind.as_str(), CONFIGURATION_FAILED),
    };
    let timeout_secs = context.resolved.profile.timeout_secs;
    if !(1..=120).contains(&timeout_secs) {
        finish_error(1, "error", INVALID_TIMEOUT);
    }

    if !allow_mutations.is_empty() && context.resolved.profile.es_url.is_none() {
        finish_error(
            1,
            "error",
            "MCP mutation tools need an Elasticsearch URL. Set es_url in the profile or ELASTICCTL_ES_URL.",
        );
    }
    let options = elasticctl_mcp::ServerOptions {
        call_timeout: Duration::from_secs(timeout_secs),
        allow_query_tools,
        allow_mutations,
    };

    let validation = elasticctl_mcp::validate_startup(&context.resolved, &options);
    if validation
        .as_ref()
        .is_err_and(|error| error.message == MUTATION_TARGET_MESSAGE)
    {
        finish_error(1, "error", MUTATION_TARGET_MESSAGE);
    }

    if Config::permission_warning(&config_path(global)).is_some() {
        emit_warning("insecure_config_permissions", INSECURE_PERMISSIONS, None);
    }
    if !context.resolved.profile.verify {
        emit_warning("insecure_tls_verification", INSECURE_TLS, None);
    }

    // Validate before announcing mutations, so a failed start never claims
    // they are enabled. The output of a failed start is the same as before.
    if let Err(error) = validation {
        finish_error(1, error.kind.as_str(), SERVER_FAILED);
    }
    if !options.allow_mutations.is_empty() {
        emit_warning(
            "mutations_enabled",
            "MCP mutation tools are enabled.",
            Some(&options.allow_mutations.names()),
        );
    }

    let result = elasticctl_mcp::serve_stdio(context.resolved, options).await;
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

fn emit_warning(kind: &'static str, message: &'static str, classes: Option<&[&str]>) {
    let mut warning = json!({"kind": kind, "message": message});
    if let Some(classes) = classes {
        warning["classes"] = json!(classes);
    }
    eprintln!("{}", json!({"warning": warning}));
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
