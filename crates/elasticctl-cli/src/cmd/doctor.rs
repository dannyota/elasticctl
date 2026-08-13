//! Checks the conditions required for rule operations. Independent checks run
//! after failures where prerequisites permit. A config or connectivity failure
//! skips dependent checks.
//!
//! `doctor` handles broken configuration, when it is most useful. Other
//! commands fail on `Context::build`; `doctor` reports the failure as
//! `config: fail`.

use crate::cli::GlobalArgs;
use crate::context::{self, Context};
use elasticctl_api::rules::{self, RuleFilter};
use elasticctl_core::{Config, Result};
use serde_json::{Value, json};

fn check(name: &str, status: &str, message: impl Into<String>) -> Value {
    json!({"check": name, "status": status, "message": message.into()})
}

/// `_es_api_key` can mint a rule API key for the caller; `_cloud_api_key`
/// cannot. Other realms are not API keys, so the result names the realm
/// without claiming otherwise.
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

/// Identities longer than this are truncated in output.
///
/// API keys authenticate as their key IDs. Truncate those IDs because
/// `config show` redacts them, while short usernames remain readable.
const MAX_IDENTITY_CHARS: usize = 12;

fn short_identity(value: &str) -> String {
    if value.chars().count() <= MAX_IDENTITY_CHARS {
        return value.to_string();
    }
    // By characters, not bytes: a byte slice can split a multibyte character
    // and panic.
    let head: String = value.chars().take(6).collect();
    format!("{head}...")
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
        // The realm determines whether rule mutations work. An organization
        // key can read rules but cannot enable them.
        match identity(&ctx).await {
            Ok((username, realm)) => {
                checks.push(check(
                    "auth",
                    "ok",
                    format!("{} via {realm}", short_identity(&username)),
                ));
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
            // `capabilities()` should already have cached the transport. Keep
            // this error path so a failed assumption does not abort the report.
            Err(e) => checks.push(check("rules_access", "fail", e.message)),
        }
    }

    let ok = checks.iter().all(|c| c["status"] != "fail");
    Ok(json!({"checks": checks, "ok": ok}))
}

/// Reads the username and authentication realm from Elasticsearch. Uses the
/// Kibana host when no ES URL is configured.
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
        // `identity()` returns "unknown" for an unexpected response. Do not
        // report that as an API key.
        let c = key_scope_check("unknown");
        assert_eq!(c["status"], "ok");
        assert!(c["message"].as_str().unwrap().contains("unknown"));
    }

    #[test]
    fn a_key_id_is_truncated_in_the_auth_check() {
        // An API key authenticates as its key ID. `config show` redacts that
        // identifier, so do not write it in full to stdout.
        let full = "2XTe9p8BLjNicQlhfc9W";
        let short = short_identity(full);
        assert_eq!(short, "2XTe9p...");
        assert!(
            !full.starts_with(&short),
            "sanity: the id must be shortened"
        );
    }

    #[test]
    fn a_human_username_is_left_readable() {
        // Keep common usernames readable.
        assert_eq!(short_identity("elastic"), "elastic");
        assert_eq!(short_identity("admin"), "admin");
        assert_eq!(short_identity("unknown"), "unknown");
    }

    #[test]
    fn truncation_never_splits_a_multibyte_character() {
        let s = short_identity("ααααααααααααααααα");
        assert!(s.ends_with("..."));
        assert_eq!(s.chars().count(), 9);
    }
}
