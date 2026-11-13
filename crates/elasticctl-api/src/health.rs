use crate::rules::{self, RuleFilter};
use elasticctl_core::capabilities::{probe_license_tier, probe_spaces};
use elasticctl_core::{Capabilities, Error, ErrorKind, Result, Transport};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DoctorCheck {
    #[serde(rename = "check")]
    pub name: String,
    #[serde(rename = "status")]
    pub status: Status,
    #[serde(rename = "message")]
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
    pub ok: bool,
}

impl DoctorReport {
    pub fn from_checks(checks: Vec<DoctorCheck>) -> DoctorReport {
        let ok = checks.iter().all(|c| c.status != Status::Fail);
        DoctorReport { checks, ok }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InfoReport {
    pub version: String,
    pub flavor: String,
    pub license: Option<String>,
    pub spaces: Option<Vec<String>>,
}

pub fn check(name: &str, status: Status, message: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status,
        detail: message.into(),
    }
}

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
            "Organization-level API key: not supported. MCP planning refuses it, and \
             rule changes may fail on some deployments. Create a project- or \
             deployment-scoped Elasticsearch API key in Kibana under Management > API keys.",
        ),
        other => check(
            "key_scope",
            Status::Ok,
            format!("authenticated via the '{other}' realm, not an Elasticsearch API key"),
        ),
    }
}

const MAX_IDENTITY_CHARS: usize = 12;

fn short_identity(value: &str) -> String {
    if value.chars().count() <= MAX_IDENTITY_CHARS {
        return value.to_string();
    }
    let head: String = value.chars().take(6).collect();
    format!("{head}...")
}

async fn identity(t: &Transport) -> Result<(String, String)> {
    let body = t.get_absolute_es("/_security/_authenticate").await?;
    decode_identity(&body)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialIdentity {
    pub username: String,
    pub realm_type: String,
    pub api_key_id: Option<String>,
}

pub async fn credential_identity(t: &Transport) -> Result<CredentialIdentity> {
    let body = t.get_absolute_es("/_security/_authenticate").await?;
    let (username, realm_type) = decode_identity(&body)?;
    let api_key_id = match body.get("api_key") {
        None | Some(Value::Null) => None,
        Some(Value::Object(key)) => match key.get("id") {
            None => None,
            Some(id) => Some(
                id.as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| identity_error("api_key.id", "must be a non-empty string"))?
                    .to_string(),
            ),
        },
        Some(_) => return Err(identity_error("api_key", "must be an object")),
    };
    Ok(CredentialIdentity {
        username,
        realm_type,
        api_key_id,
    })
}

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
        assert_eq!(
            c.detail,
            "Organization-level API key: not supported. MCP planning refuses it, and rule changes may fail on some deployments. Create a project- or deployment-scoped Elasticsearch API key in Kibana under Management > API keys."
        );
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
        let c = key_scope_check("unknown");
        assert_eq!(c.status, Status::Ok);
        assert!(c.detail.contains("unknown"));
    }

    #[test]
    fn a_key_id_is_truncated_in_the_auth_check() {
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
