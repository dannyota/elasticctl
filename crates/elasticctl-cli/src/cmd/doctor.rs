//! One pass over everything that has to be true before a rule operation can
//! work. Every check runs even after one fails, so the operator sees all the
//! problems at once.
//!
//! `doctor` must survive a broken configuration — that is exactly when an
//! operator reaches for it. Every other command fails fast on
//! `Context::build`; `doctor` builds its own context and turns a build
//! failure into a `config: fail` check instead of a bare error envelope.

use crate::cli::GlobalArgs;
use crate::context::{self, Context};
use elasticctl_api::rules::{self, RuleFilter};
use elasticctl_core::{Config, Result};
use serde_json::{Value, json};

fn check(name: &str, status: &str, message: impl Into<String>) -> Value {
    json!({"check": name, "status": status, "message": message.into()})
}

/// `_es_api_key` is the realm that can mint a rule API key on the caller's
/// behalf; `_cloud_api_key` cannot. Every other realm (basic auth, PKI,
/// SAML, ...) is unrelated to that specific failure mode, so it is reported
/// as fine — but by naming the realm, not by claiming it is an API key it
/// is not.
fn key_scope_check(realm: &str) -> Value {
    match realm {
        "_es_api_key" => check("key_scope", "ok", "project-scoped Elasticsearch API key"),
        "_cloud_api_key" => check(
            "key_scope",
            "warn",
            "Organization-level API key: reads and deletes work, but enabling a \
             rule will fail. Create a project-scoped Elasticsearch API key in \
             Kibana under Management > API keys.",
        ),
        other => check(
            "key_scope",
            "ok",
            format!("authenticated via the '{other}' realm, not an Elasticsearch API key"),
        ),
    }
}

pub async fn run(global: &GlobalArgs) -> Result<Value> {
    let mut checks = Vec::new();

    // A side-channel stderr warning would compete with doctor's own report;
    // fold the same signal into a check instead of calling the emitter every
    // other command uses.
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
                // The profile resolved but carries no credential — report
                // require_credential's message (names the profile and the
                // remedy), not a generic one.
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
        // Nothing downstream is meaningful without a resolved, credentialed target.
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
                checks.push(key_scope_check(&realm));
            }
            Err(e) => checks.push(check("auth", "fail", e.message)),
        }

        match ctx.transport().await {
            Ok(transport) => {
                match rules::find_page(transport, &RuleFilter::default(), 1, 1).await {
                    Ok((_, total)) => checks.push(check(
                        "rules_access",
                        "ok",
                        format!("{total} rules visible"),
                    )),
                    Err(e) => checks.push(check("rules_access", "fail", e.message)),
                }
            }
            // Unreachable in practice — `capabilities()` above already built
            // and cached the transport successfully — but handled rather
            // than unwrapped so this can never abort the report.
            Err(e) => checks.push(check("rules_access", "fail", e.message)),
        }
    }

    let ok = checks.iter().all(|c| c["status"] != "fail");
    Ok(json!({"checks": checks, "ok": ok}))
}

/// Username and authentication realm, read from Elasticsearch. Falls back to
/// the Kibana host when no separate ES URL is configured.
async fn identity(ctx: &Context) -> Result<(String, String)> {
    let transport = ctx.transport().await?;
    let body = transport
        .get_absolute_es("/_security/_authenticate")
        .await?;
    let username = body["username"].as_str().unwrap_or("unknown").to_string();
    let realm = body["authentication_realm"]["type"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    Ok((username, realm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_scope_check_reports_ok_for_a_project_scoped_es_api_key() {
        let c = key_scope_check("_es_api_key");
        assert_eq!(c["status"], "ok");
        assert!(c["message"].as_str().unwrap().contains("project-scoped"));
    }

    #[test]
    fn key_scope_check_warns_for_an_organization_cloud_api_key() {
        let c = key_scope_check("_cloud_api_key");
        assert_eq!(c["status"], "warn");
        assert!(
            c["message"]
                .as_str()
                .unwrap()
                .contains("Organization-level")
        );
    }

    #[test]
    fn key_scope_check_names_an_unrecognized_realm_rather_than_calling_it_an_api_key() {
        let c = key_scope_check("native");
        assert_eq!(c["status"], "ok");
        let msg = c["message"].as_str().unwrap();
        assert!(msg.contains("native"), "message must name the realm: {msg}");
        assert!(
            !msg.contains("project-scoped Elasticsearch API key"),
            "must not claim a non-API-key realm is a project-scoped API key: {msg}"
        );
    }

    #[test]
    fn key_scope_check_names_the_unknown_realm_from_a_parse_failure() {
        // `identity()` falls back to "unknown" when the server response
        // doesn't have the expected shape; that must not be misreported as
        // an API key either.
        let c = key_scope_check("unknown");
        assert_eq!(c["status"], "ok");
        assert!(c["message"].as_str().unwrap().contains("unknown"));
    }
}
