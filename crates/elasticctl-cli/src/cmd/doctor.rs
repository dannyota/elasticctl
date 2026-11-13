use crate::cli::GlobalArgs;
use crate::context::{self, Context};
use elasticctl_api::health::{self, DoctorReport, Status, check};
use elasticctl_core::{Config, Error, ErrorKind, Result};
use serde_json::Value;

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v)
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding report: {e}")))
}

pub async fn run(global: &GlobalArgs) -> Result<Value> {
    let mut checks = Vec::new();

    let path = context::config_path(global);
    if let Some(message) = Config::permission_warning(&path) {
        checks.push(check("config_permissions", Status::Warn, message));
    }

    let ctx = match Context::build(global) {
        Ok(ctx) => match ctx.require_credential() {
            Ok(()) => {
                checks.push(check(
                    "config",
                    Status::Ok,
                    format!("profile '{}'", ctx.resolved.name),
                ));
                Some(ctx)
            }
            Err(e) => {
                checks.push(check("config", Status::Fail, e.message));
                None
            }
        },
        Err(e) => {
            checks.push(check("config", Status::Fail, e.message));
            None
        }
    };

    let Some(ctx) = ctx else {
        return to_value(&DoctorReport::from_checks(checks));
    };

    let stack_checks = match ctx.transport().await {
        Ok(t) => health::doctor(t).await?.checks,
        Err(e) => vec![check("connectivity", Status::Fail, e.message)],
    };
    checks.extend(stack_checks);
    to_value(&DoctorReport::from_checks(checks))
}
