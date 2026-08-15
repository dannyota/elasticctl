//! Health orchestration: `doctor` and `info`.
//!
//! `doctor` reads the stack and reports every check it can, so a broken
//! configuration surfaces as a failed check rather than an error envelope.
//! The checks that read the operator's local configuration live in `-cli`,
//! which has the `Context`; these functions take a `&Transport` and report
//! only what the stack says.

use crate::rules::{self, RuleFilter};
use elasticctl_core::capabilities::{probe_license_tier, probe_spaces};
use elasticctl_core::{Capabilities, Error, ErrorKind, Result, Transport};
use serde::Serialize;
use serde_json::Value;

/// The outcome of one `doctor` check.
///
/// Serialized lowercase (`ok`, `warn`, `fail`). `warn` passes the report but
/// carries a caution, so it is distinct from `ok` even though both leave
/// [`DoctorReport::ok`] true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

/// One `doctor` check.
///
/// Field order is the serialized JSON key order and is contractual: the root
/// `Cargo.toml` enables `serde_json`'s `preserve_order`, so reordering these
/// fields would silently change rendered output.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DoctorCheck {
    #[serde(rename = "check")]
    pub name: String,
    #[serde(rename = "status")]
    pub status: Status,
    #[serde(rename = "message")]
    pub detail: String,
}

/// The report `doctor` renders.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
    pub ok: bool,
}

impl DoctorReport {
    /// Build a report from its checks, deriving `ok` from them.
    ///
    /// This is the single place `ok` is derived, so a check with a misspelled
    /// status cannot silently report a broken stack as healthy.
    pub fn from_checks(checks: Vec<DoctorCheck>) -> DoctorReport {
        let ok = checks.iter().all(|c| c.status != Status::Fail);
        DoctorReport { checks, ok }
    }
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

/// Construct a check. Public so `-cli` builds its configuration checks with
/// the same shape as the stack checks.
pub fn check(name: &str, status: Status, message: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status,
        detail: message.into(),
    }
}

/// `_es_api_key` can mint a rule API key for the caller; `_cloud_api_key`
/// cannot. Other realms are not API keys, so the result names the realm
/// without claiming otherwise.
fn key_scope_check(realm: &str) -> DoctorCheck {
    match realm {
        "_es_api_key" => check(
            "key_scope",
            Status::Ok,
            "project-scoped Elasticsearch API key",
        ),
        "_cloud_api_key" => check(
            "key_scope",
            Status::Warn,
            "Organization-level API key: reads and deletes work, but enabling a \
             rule will fail. Create a project-scoped Elasticsearch API key in \
             Kibana under Management > API keys.",
        ),
        other => check(
            "key_scope",
            Status::Ok,
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
    decode_identity(&body)
}

/// Decode an `_authenticate` response, refusing a malformed success body.
///
/// A missing or mistyped `username` or `authentication_realm.type` must fail
/// the auth check rather than read as an "unknown" realm.
fn decode_identity(body: &Value) -> Result<(String, String)> {
    let username = body
        .get("username")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| identity_error("username", "must be a non-empty string"))?
        .to_string();
    let realm = body
        .get("authentication_realm")
        .and_then(|realm| realm.get("type"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| identity_error("authentication_realm.type", "must be a non-empty string"))?
        .to_string();
    Ok((username, realm))
}

fn identity_error(field: &str, detail: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorKind::Http,
        format!("decoding identity response field {field}: {detail}"),
    )
}

/// The value-list data streams (`/api/lists/index`) bootstrapping check.
///
/// A 404 is the absent case, not an error (spec 7.7): the route answering 404
/// is how it says the data streams do not exist, and an exception entry of
/// type `list` cannot work until they are created. Absence is a warning, not a
/// failure — a stack with no value-list-backed exceptions never needs them.
async fn value_list_index_check(t: &Transport) -> DoctorCheck {
    match crate::exceptions::value_lists_bootstrapped(t).await {
        Ok(true) => check(
            "value_list_index",
            Status::Ok,
            "value-list data streams are bootstrapped",
        ),
        Ok(false) => check(
            "value_list_index",
            Status::Warn,
            "value-list data streams are not bootstrapped; an exception entry of type \
             'list' cannot work until POST /api/lists/index runs",
        ),
        Err(e) => check("value_list_index", Status::Fail, e.message),
    }
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
        Ok(_) => checks.push(check("connectivity", Status::Ok, t.kibana_url())),
        Err(e) => checks.push(check("connectivity", Status::Fail, e.message.clone())),
    }

    if let Ok(c) = &caps {
        checks.push(check(
            "flavor",
            Status::Ok,
            format!("{} {}", c.flavor.as_str(), c.version),
        ));

        match identity(t).await {
            Ok((username, realm)) => {
                checks.push(check(
                    "auth",
                    Status::Ok,
                    format!("{} via {realm}", short_identity(&username)),
                ));
                checks.push(key_scope_check(&realm));
            }
            Err(e) => checks.push(check("auth", Status::Fail, e.message)),
        }

        match rules::find_page(t, &RuleFilter::default(), 1, 1).await {
            Ok((_, total)) => checks.push(check(
                "rules_access",
                Status::Ok,
                format!("{total} rules visible"),
            )),
            Err(e) => checks.push(check("rules_access", Status::Fail, e.message)),
        }

        checks.push(value_list_index_check(t).await);
    }

    Ok(DoctorReport::from_checks(checks))
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
    fn status_serializes_to_the_rendered_lowercase_strings() {
        assert_eq!(
            serde_json::to_value(Status::Ok).unwrap(),
            serde_json::json!("ok")
        );
        assert_eq!(
            serde_json::to_value(Status::Warn).unwrap(),
            serde_json::json!("warn")
        );
        assert_eq!(
            serde_json::to_value(Status::Fail).unwrap(),
            serde_json::json!("fail")
        );
    }

    #[test]
    fn key_scope_check_reports_ok_for_a_project_scoped_es_api_key() {
        let c = key_scope_check("_es_api_key");
        assert_eq!(c.status, Status::Ok);
        assert!(c.detail.contains("project-scoped"));
    }

    #[test]
    fn key_scope_check_warns_for_an_organization_cloud_api_key() {
        let c = key_scope_check("_cloud_api_key");
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("Organization-level"));
    }

    #[test]
    fn key_scope_check_names_an_unrecognized_realm_rather_than_calling_it_an_api_key() {
        let c = key_scope_check("native");
        assert_eq!(c.status, Status::Ok);
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
    fn key_scope_check_names_an_unclassifiable_realm() {
        // A realm string that is neither API-key type is reported by name, not
        // claimed as an API key.
        let c = key_scope_check("unknown");
        assert_eq!(c.status, Status::Ok);
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
        let c = check("config", Status::Ok, "profile 'default'");
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

    #[test]
    fn from_checks_derives_ok_from_the_checks() {
        assert!(
            DoctorReport::from_checks(vec![
                check("connectivity", Status::Ok, "ok"),
                check("key_scope", Status::Warn, "caution"),
            ])
            .ok,
            "a warning must not fail the report"
        );
        assert!(!DoctorReport::from_checks(vec![check("config", Status::Fail, "fail")]).ok);
    }
}
