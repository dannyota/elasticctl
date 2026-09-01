//! Username-to-profile-uid resolution for alert (and, in 0.4.1, case)
//! assignment.
//!
//! The assignees routes take user profile uids, and a uid exists only after
//! its user has activated a profile by logging into Kibana at least once.
//! Resolution is flavor-dependent (triage spec section 7): Hosted and
//! self-managed use the public suggest API; Serverless answers 410 there, so
//! it uses the Security solution's own internal suggestion route — the one
//! the assignee picker in the UI calls.

use elasticctl_core::{Error, ErrorKind, Flavor, Result, Transport, urlencode};
use serde_json::{Value, json};

/// Prefix that bypasses resolution: `uid:<profile_uid>` is passed through.
/// The escape hatch, not the primary interface.
pub const UID_PREFIX: &str = "uid:";

pub const PUBLIC_SUGGEST_PATH: &str = "/_security/profile/_suggest";

pub fn internal_find_path(term: &str) -> String {
    format!(
        "/internal/detection_engine/users/_find?searchTerm={}",
        urlencode(term)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserProfile {
    pub uid: String,
    pub username: String,
    /// The public route reports `realm_name`; the internal one does not.
    pub realm: Option<String>,
}

fn decode_profile(entry: &Value, context: &str) -> Result<UserProfile> {
    let uid = entry
        .get("uid")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(ErrorKind::Http, format!("decoding {context} field `uid`")))?;
    let username = entry
        .pointer("/user/username")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                format!("decoding {context} field `user.username`"),
            )
        })?;
    Ok(UserProfile {
        uid: uid.to_string(),
        username: username.to_string(),
        realm: entry
            .pointer("/user/realm_name")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// Decode `POST /_security/profile/_suggest`: `{total, took, profiles: [...]}`.
pub fn decode_public(value: &Value) -> Result<Vec<UserProfile>> {
    value
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new(ErrorKind::Http, "decoding profile suggest field `profiles`"))?
        .iter()
        .map(|p| decode_profile(p, "profile suggest entry"))
        .collect()
}

/// Decode `GET /internal/detection_engine/users/_find`: a bare array.
pub fn decode_internal(value: &Value) -> Result<Vec<UserProfile>> {
    value
        .as_array()
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                "decoding users find response: expected an array",
            )
        })?
        .iter()
        .map(|p| decode_profile(p, "users find entry"))
        .collect()
}

/// A resolution route that is missing, withdrawn, or forbidden is a definite
/// refusal with a remedy, not an unclassified failure.
fn downgrade_unavailable(e: Error, flavor: Flavor) -> Error {
    let unavailable =
        matches!(e.http_status, Some(404) | Some(410)) || e.kind == ErrorKind::Permission;
    if unavailable {
        Error::new(
            ErrorKind::Unsupported,
            format!(
                "profile suggestion is unavailable on {} ({}); pass uid:<profile_uid> to bypass resolution",
                flavor.as_str(),
                e.message
            ),
        )
    } else {
        e
    }
}

/// Suggest activated profiles matching `name`, on the route this flavor
/// serves.
pub async fn suggest(t: &Transport, flavor: Flavor, name: &str) -> Result<Vec<UserProfile>> {
    match flavor {
        Flavor::Serverless => {
            let body = t
                .get_internal(&internal_find_path(name))
                .await
                .map_err(|e| downgrade_unavailable(e, flavor))?;
            decode_internal(&body)
        }
        Flavor::ElasticCloudHosted | Flavor::SelfManaged => {
            let body = t
                .post_absolute_es(PUBLIC_SUGGEST_PATH, &json!({ "name": name, "size": 10 }))
                .await
                .map_err(|e| downgrade_unavailable(e, flavor))?;
            decode_public(&body)
        }
    }
}

/// Match the suggestion list exactly on `user.username`, mirroring rule-name
/// resolution: never a prefix, never a silent first pick.
pub fn pick_exact(candidates: &[UserProfile], username: &str) -> Result<String> {
    let matches: Vec<&UserProfile> = candidates
        .iter()
        .filter(|p| p.username == username)
        .collect();
    match matches.as_slice() {
        [] => Err(Error::new(
            ErrorKind::NotFound,
            format!(
                "no user profile for '{username}': the user must have logged into Kibana at least \
                 once to activate a profile, and an API-key identity never has one"
            ),
        )),
        [one] => Ok(one.uid.clone()),
        many => {
            let listed: Vec<String> = many
                .iter()
                .map(|p| {
                    format!(
                        "{} ({})",
                        p.username,
                        p.realm.as_deref().unwrap_or("unknown realm")
                    )
                })
                .collect();
            Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "username '{username}' is ambiguous across realms: {}",
                    listed.join(", ")
                ),
            ))
        }
    }
}

/// Resolve an assignee argument to a profile uid. `uid:<uid>` bypasses
/// resolution entirely; anything else is a username resolved per flavor.
pub async fn resolve_assignee(t: &Transport, input: &str) -> Result<String> {
    if let Some(uid) = input.strip_prefix(UID_PREFIX) {
        if uid.is_empty() {
            return Err(Error::new(
                ErrorKind::Error,
                "empty profile uid after 'uid:'",
            ));
        }
        return Ok(uid.to_string());
    }
    let flavor = t.capabilities().await?.flavor;
    let candidates = suggest(t, flavor, input).await?;
    pick_exact(&candidates, input)
}
