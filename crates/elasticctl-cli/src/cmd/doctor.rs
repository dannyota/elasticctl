//! Checks the conditions required for rule operations. Independent checks run
//! after failures where prerequisites permit. A config or connectivity failure
//! skips dependent checks.
//!
//! `doctor` handles broken configuration, when it is most useful. Other
//! commands fail on `Context::build`; `doctor` reports the failure as
//! `config: fail`.
//!
//! Orchestration lives in `elasticctl_api::health`; this module resolves the
//! configuration checks — which read this machine's profile file, not the
//! stack — and prepends them to the stack checks.

use crate::cli::GlobalArgs;
use crate::context::{self, Context};
use elasticctl_api::health::{self, DoctorCheck, DoctorReport};
use elasticctl_core::{Config, Error, ErrorKind, Result};
use serde_json::Value;

fn check(name: &str, status: &str, message: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status: status.into(),
        detail: message.into(),
    }
}

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v)
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding report: {e}")))
}

pub async fn run(global: &GlobalArgs) -> Result<Value> {
    let mut checks = Vec::new();

    // Report the warning as a check so it does not compete with the report on
    // stderr.
    let path = context::config_path(global);
    if let Some(message) = Config::permission_warning(&path) {
        checks.push(check("config_permissions", "warn", message));
    }

    let ctx = match Context::build(global) {
        Ok(ctx) => match ctx.require_credential() {
            Ok(()) => {
                checks.push(check(
                    "config",
                    "ok",
                    format!("profile '{}'", ctx.resolved.name),
                ));
                Some(ctx)
            }
            Err(e) => {
                // Use the credential error because it names the profile and
                // remedy.
                checks.push(check("config", "fail", e.message));
                None
            }
        },
        Err(e) => {
            checks.push(check("config", "fail", e.message));
            None
        }
    };

    let Some(ctx) = ctx else {
        // No later check is meaningful without a resolved, credentialed target.
        return to_value(&DoctorReport { checks, ok: false });
    };

    // Configuration checks are a property of this machine, not of the stack,
    // so they precede the stack checks `health::doctor` reports.
    let mut report = match ctx.transport().await {
        Ok(t) => health::doctor(t).await?,
        // A failed transport construction is a connectivity failure, not an
        // abort: `doctor` keeps reporting.
        Err(e) => DoctorReport {
            checks: vec![check("connectivity", "fail", e.message)],
            ok: false,
        },
    };
    report.checks.splice(0..0, checks);
    report.ok = report.checks.iter().all(|c| c.status != "fail");
    to_value(&report)
}
