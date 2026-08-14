//! Health orchestration: `doctor` and `info`.
//!
//! `doctor` reads the stack and reports every check it can, so a broken
//! configuration surfaces as a failed check rather than an error envelope.
//! The checks that read the operator's local configuration live in `-cli`,
//! which has the `Context`; these functions take a `&Transport` and report
//! only what the stack says.

use crate::rules::{self, RuleFilter};
use elasticctl_core::capabilities::{probe_license_tier, probe_spaces};
use elasticctl_core::{Capabilities, Result, Transport};
use serde::Serialize;

/// One `doctor` check.
///
/// Field order is the serialized JSON key order and is contractual: the root
/// `Cargo.toml` enables `serde_json`'s `preserve_order`, so reordering these
/// fields would silently change rendered output.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DoctorCheck {
    #[serde(rename = "check")]
    pub name: String,
    /// `ok` passes, `warn` passes with a caution, `fail` fails the report.
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "message")]
    pub detail: String,
}

/// The report `doctor` renders.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
    pub ok: bool,
}

/// The stack-derived half of `info`'s report. The caller prepends the
/// profile fields (`elasticctl_version`, `profile`, `kibana_url`, `space`)
/// it alone can supply.
#[derive(Debug, Clone, PartialEq)]
pub struct InfoReport {
    pub version: String,
    pub flavor: String,
    pub license: Option<String>,
    pub spaces: Option<Vec<String>>,
}

fn check(name: &str, status: &str, message: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status: status.into(),
        detail: message.into(),
    }
}

/// `_es_api_key` can mint a rule API key for the caller; `_cloud_api_key`
/// cannot. Other realms are not API keys, so the result names the realm
/// without claiming otherwise.
fn key_scope_check(realm: &str) -> DoctorCheck {
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

/// Reads the username and authentication realm from Elasticsearch.
async fn identity(t: &Transport) -> Result<(String, String)> {
    let body = t.get_absolute_es("/_security/_authenticate").await?;
    let username = body["username"].as_str().unwrap_or("unknown").to_string();
    let realm = body["authentication_realm"]["type"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    Ok((username, realm))
}

/// Run the stack-reading checks.
///
/// The connectivity check gates the rest: without a capability probe there is
/// no flavor, no realm, and no rule access to report. Spec 7.2: the realm is
/// the signal for whether rule mutation will work — `_cloud_api_key` cannot
/// enable a rule, and an operator must learn that here rather than from a 400
/// in the middle of a push.
pub async fn doctor(t: &Transport) -> Result<DoctorReport> {
    let mut checks = Vec::new();

    let caps = Capabilities::probe(t, t.kibana_url()).await;
    match &caps {
        Ok(_) => checks.push(check("connectivity", "ok", t.kibana_url())),
        Err(e) => checks.push(check("connectivity", "fail", e.message.clone())),
    }

    if let Ok(c) = &caps {
        checks.push(check(
            "flavor",
            "ok",
            format!("{} {}", c.flavor.as_str(), c.version),
        ));

        match identity(t).await {
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

        match rules::find_page(t, &RuleFilter::default(), 1, 1).await {
            Ok((_, total)) => checks.push(check(
                "rules_access",
                "ok",
                format!("{total} rules visible"),
            )),
            Err(e) => checks.push(check("rules_access", "fail", e.message)),
        }
    }

    let ok = checks.iter().all(|c| c.status != "fail");
    Ok(DoctorReport { checks, ok })
}

/// Probe the stack values only `info` reports.
///
/// Spaces and license tier each cost a request, so they are not part of the
/// capability probe every command pays for. `None` means the value could not
/// be determined; Serverless has no license tier.
pub async fn info(t: &Transport) -> Result<InfoReport> {
    let caps = Capabilities::probe(t, t.kibana_url()).await?;
    let spaces = probe_spaces(t).await;
    let license = probe_license_tier(t, caps.flavor).await;

    Ok(InfoReport {
        version: caps.version,
        flavor: caps.flavor.as_str().to_string(),
        license,
        spaces,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_scope_check_reports_ok_for_a_project_scoped_es_api_key() {
        let c = key_scope_check("_es_api_key");
        assert_eq!(c.status, "ok");
        assert!(c.detail.contains("project-scoped"));
    }

    #[test]
    fn key_scope_check_warns_for_an_organization_cloud_api_key() {
        let c = key_scope_check("_cloud_api_key");
        assert_eq!(c.status, "warn");
        assert!(c.detail.contains("Organization-level"));
    }

    #[test]
    fn key_scope_check_names_an_unrecognized_realm_rather_than_calling_it_an_api_key() {
        let c = key_scope_check("native");
        assert_eq!(c.status, "ok");
        assert!(
            c.detail.contains("native"),
            "message must name the realm: {}",
            c.detail
        );
        assert!(
            !c.detail.contains("project-scoped Elasticsearch API key"),
            "must not claim a non-API-key realm is a project-scoped API key: {}",
            c.detail
        );
    }

    #[test]
    fn key_scope_check_names_the_unknown_realm_from_a_parse_failure() {
        // `identity()` returns "unknown" for an unexpected response. Do not
        // report that as an API key.
        let c = key_scope_check("unknown");
        assert_eq!(c.status, "ok");
        assert!(c.detail.contains("unknown"));
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

    #[test]
    fn doctor_check_serializes_to_the_rendered_key_names() {
        let c = check("config", "ok", "profile 'default'");
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["check"], "config");
        assert_eq!(v["status"], "ok");
        assert_eq!(v["message"], "profile 'default'");
        assert_eq!(
            v.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()),
            Some(vec![
                "check".to_string(),
                "status".to_string(),
                "message".to_string()
            ]),
            "key order is the rendered JSON order"
        );
    }
}
