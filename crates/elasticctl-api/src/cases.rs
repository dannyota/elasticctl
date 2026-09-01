//! Cases: typed wrappers over the `/api/cases` family.
//!
//! Case identity on mutation is `id` plus the fetched `version` — the API is
//! optimistic-concurrency and a stale version answers 409 (triage spec
//! sections 3 and 10). Cases are collaboration records: there is no mirror,
//! no reconciliation, and deletion is a real verb (unlike alerts).

use elasticctl_core::{Error, ErrorKind, Result, Transport, urlencode};
use serde_json::{Map, Value, json};

pub const FIND_PATH: &str = "/api/cases/_find";
pub const CASES_PATH: &str = "/api/cases";
pub const OWNER: &str = "securitySolution";

pub fn case_path(id: &str) -> String {
    format!("/api/cases/{}", urlencode(id))
}

pub fn comments_path(id: &str) -> String {
    format!("/api/cases/{}/comments", urlencode(id))
}

/// `DELETE /api/cases?ids=["a","b"]` — the ids parameter is a JSON array in
/// the query string.
pub fn delete_path(ids: &[String]) -> Result<String> {
    let encoded = serde_json::to_string(ids)
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding case ids: {e}")))?;
    Ok(format!("{CASES_PATH}?ids={}", urlencode(&encoded)))
}

/// The case status vocabulary. Cases legitimately use `in-progress` (it is a
/// filter value); the transition verbs target only `open` and `closed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseStatus {
    Open,
    InProgress,
    Closed,
}

impl CaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CaseStatus::Open => "open",
            CaseStatus::InProgress => "in-progress",
            CaseStatus::Closed => "closed",
        }
    }

    /// The verb a preview banner uses. `InProgress` is a filter value, not a
    /// transition target, so it has no verb.
    pub fn verb(self) -> &'static str {
        match self {
            CaseStatus::Open => "Open",
            CaseStatus::InProgress => "Mark in progress",
            CaseStatus::Closed => "Close",
        }
    }

    pub fn parse(s: &str) -> Result<CaseStatus> {
        match s {
            "open" => Ok(CaseStatus::Open),
            "in-progress" => Ok(CaseStatus::InProgress),
            "closed" => Ok(CaseStatus::Closed),
            other => Err(Error::new(
                ErrorKind::Error,
                format!("unknown case status '{other}': expected open, in-progress, or closed"),
            )),
        }
    }
}

/// A case as the API returns it. The four identity/workflow fields are
/// required (fail-closed); everything else is optional or flattened into
/// `extra` so the full server object survives a round trip to render.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Case {
    pub id: String,
    pub version: String,
    pub title: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub assignees: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(
        default,
        rename = "totalComment",
        skip_serializing_if = "Option::is_none"
    )]
    pub total_comment: Option<u64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

pub fn decode_case(value: &Value) -> Result<Case> {
    serde_json::from_value(value.clone())
        .map_err(|e| Error::new(ErrorKind::Http, format!("decoding case: {e}")))
}

/// Decode `GET /api/cases/_find`: `{cases, page, per_page, total, ...}`.
pub fn decode_find(value: &Value) -> Result<(Vec<Case>, u64)> {
    let cases = value
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new(ErrorKind::Http, "decoding cases find field `cases`"))?
        .iter()
        .map(decode_case)
        .collect::<Result<Vec<_>>>()?;
    let total = value
        .get("total")
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::new(ErrorKind::Http, "decoding cases find field `total`"))?;
    Ok((cases, total))
}

/// One find page; the caller builds the query string (`cases_ops::find_query`).
pub async fn find_page(t: &Transport, query_string: &str) -> Result<(Vec<Case>, u64)> {
    decode_find(&t.get(&format!("{FIND_PATH}?{query_string}")).await?)
}

pub async fn get(t: &Transport, id: &str) -> Result<Case> {
    decode_case(&t.get(&case_path(id)).await?)
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewCase {
    pub title: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub severity: Option<String>,
    /// Resolved profile uids (the caller resolves usernames first).
    pub assignee_uids: Vec<String>,
}

/// Create a case. The API requires a non-empty description; when the
/// operator gave none, or gave an empty or whitespace-only one, the title
/// stands in — `Some("")` must fall back exactly like `None`, or it defeats
/// the fallback and earns a server 400 on minimum length. `connector` and
/// `settings` are required by the route; elasticctl pins the no-op connector
/// and leaves alert-status syncing off — alert transitions stay explicit CLI
/// actions.
pub async fn create(t: &Transport, new: &NewCase) -> Result<Case> {
    let description = new
        .description
        .as_deref()
        .filter(|d| !d.trim().is_empty())
        .unwrap_or(&new.title);
    let assignees: Vec<Value> = new
        .assignee_uids
        .iter()
        .map(|u| json!({"uid": u}))
        .collect();
    let mut body = json!({
        "title": new.title,
        "description": description,
        "tags": new.tags,
        "assignees": assignees,
        "connector": {"id": "none", "name": "none", "type": ".none", "fields": null},
        "settings": {"syncAlerts": false},
        "owner": OWNER,
    });
    if let Some(severity) = &new.severity {
        body["severity"] = json!(severity);
    }
    decode_case(&t.post(CASES_PATH, Some(&body)).await?)
}

/// Bulk status update: `PATCH /api/cases` with `{cases: [{id, version,
/// status}]}`. The response is the array of updated cases.
pub async fn patch_status(
    t: &Transport,
    updates: &[(String, String, CaseStatus)],
) -> Result<Vec<Case>> {
    let cases: Vec<Value> = updates
        .iter()
        .map(|(id, version, status)| json!({"id": id, "version": version, "status": status.as_str()}))
        .collect();
    let body = json!({ "cases": cases });
    let response = t.patch(CASES_PATH, &body).await?;
    response
        .as_array()
        .ok_or_else(|| Error::new(ErrorKind::Http, "decoding cases update: expected an array"))?
        .iter()
        .map(decode_case)
        .collect()
}

/// Delete cases permanently. 204 with an empty body on success.
pub async fn delete(t: &Transport, ids: &[String]) -> Result<()> {
    t.delete(&delete_path(ids)?).await?;
    Ok(())
}

/// Add a user comment; the response is the updated case.
pub async fn add_comment(t: &Transport, case_id: &str, comment: &str) -> Result<Case> {
    let body = json!({"type": "user", "comment": comment, "owner": OWNER});
    decode_case(&t.post(&comments_path(case_id), Some(&body)).await?)
}

/// Attach alerts as one comment of type `alert`. All alerts in one call share
/// a rule (the API takes one `rule` object per comment); the caller groups by
/// rule. `alert_ids` and `indices` are parallel arrays.
pub async fn attach_alerts(
    t: &Transport,
    case_id: &str,
    alert_ids: &[String],
    indices: &[String],
    rule_id: &str,
    rule_name: &str,
) -> Result<Case> {
    let body = json!({
        "type": "alert",
        "alertId": alert_ids,
        "index": indices,
        "rule": {"id": rule_id, "name": rule_name},
        "owner": OWNER,
    });
    decode_case(&t.post(&comments_path(case_id), Some(&body)).await?)
}
