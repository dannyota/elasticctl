//! One pass over everything that has to be true before a rule operation can
//! work. Every check runs even after one fails, so the operator sees all the
//! problems at once.
//!
//! `doctor` must survive a broken configuration — that is exactly when an
//! operator reaches for it. Every other command fails fast on
//! `Context::build`; `doctor` builds its own context and turns a build
//! failure into a `config: fail` check instead of a bare error envelope.

use crate::cli::GlobalArgs;
use crate::context::Context;
use elasticctl_api::rules::{self, RuleFilter};
use elasticctl_core::Result;
use serde_json::{Value, json};

fn check(name: &str, status: &str, message: impl Into<String>) -> Value {
    json!({"check": name, "status": status, "message": message.into()})
}

pub async fn run(global: &GlobalArgs) -> Result<Value> {
    let mut checks = Vec::new();

    let ctx = match Context::build(global) {
        Ok(ctx) => {
            checks.push(check(
                "config",
                "ok",
                format!("profile '{}'", ctx.resolved.name),
            ));
            Some(ctx)
        }
        Err(e) => {
            checks.push(check("config", "fail", e.message));
            None
        }
    };

    let Some(ctx) = ctx else {
        // Nothing downstream is meaningful without a resolved target.
        return Ok(json!({"checks": checks, "ok": false}));
    };

    let caps = match ctx.capabilities().await {
        Ok(c) => {
            checks.push(check(
                "connectivity",
                "ok",
                ctx.resolved.profile.kibana_url.clone(),
            ));
            checks.push(check(
                "flavor",
                "ok",
                format!("{} {}", c.flavor.as_str(), c.version),
            ));
            Some(c)
        }
        Err(e) => {
            checks.push(check("connectivity", "fail", e.message));
            None
        }
    };

    if caps.is_some() {
        // Realm is the cheap, direct signal for whether rule mutation will
        // work. An organization key reads fine but cannot enable a rule.
        match identity(&ctx).await {
            Ok((username, realm)) => {
                checks.push(check("auth", "ok", format!("{username} via {realm}")));
                if realm == "_cloud_api_key" {
                    checks.push(check(
                        "key_scope",
                        "warn",
                        "Organization-level API key: reads and deletes work, but enabling a \
                         rule will fail. Create a project-scoped Elasticsearch API key in \
                         Kibana under Management > API keys.",
                    ));
                } else {
                    checks.push(check(
                        "key_scope",
                        "ok",
                        "project-scoped Elasticsearch API key",
                    ));
                }
            }
            Err(e) => checks.push(check("auth", "fail", e.message)),
        }

        match rules::find_page(&ctx.transport, &RuleFilter::default(), 1, 1).await {
            Ok((_, total)) => checks.push(check(
                "rules_access",
                "ok",
                format!("{total} rules visible"),
            )),
            Err(e) => checks.push(check("rules_access", "fail", e.message)),
        }
    }

    let ok = checks.iter().all(|c| c["status"] != "fail");
    Ok(json!({"checks": checks, "ok": ok}))
}

/// Username and authentication realm, read from Elasticsearch. Falls back to
/// the Kibana host when no separate ES URL is configured.
async fn identity(ctx: &Context) -> Result<(String, String)> {
    let body = ctx
        .transport
        .get_absolute_es("/_security/_authenticate")
        .await?;
    let username = body["username"].as_str().unwrap_or("unknown").to_string();
    let realm = body["authentication_realm"]["type"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    Ok((username, realm))
}
