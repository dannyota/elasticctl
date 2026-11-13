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

pub fn delete_path(ids: &[String]) -> Result<String> {
    let encoded = serde_json::to_string(ids)
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding case ids: {e}")))?;
    Ok(format!("{CASES_PATH}?ids={}", urlencode(&encoded)))
}

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
    pub assignee_uids: Vec<String>,
}

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

pub async fn delete(t: &Transport, ids: &[String]) -> Result<()> {
    t.delete(&delete_path(ids)?).await?;
    Ok(())
}

pub async fn add_comment(t: &Transport, case_id: &str, comment: &str) -> Result<Case> {
    crate::compose::require_path_segment(case_id)?;
    let body = json!({"type": "user", "comment": comment, "owner": OWNER});
    decode_case(&t.post(&comments_path(case_id), Some(&body)).await?)
}

pub async fn attach_alerts(
    t: &Transport,
    case_id: &str,
    alert_ids: &[String],
    indices: &[String],
    rule_id: &str,
    rule_name: &str,
) -> Result<Case> {
    crate::compose::require_path_segment(case_id)?;
    let body = json!({
        "type": "alert",
        "alertId": alert_ids,
        "index": indices,
        "rule": {"id": rule_id, "name": rule_name},
        "owner": OWNER,
    });
    decode_case(&t.post(&comments_path(case_id), Some(&body)).await?)
}

#[derive(Debug)]
pub struct CaseRef {
    pub id: String,
    pub title: Option<String>,
}
pub async fn by_alert(t: &Transport, alert_id: &str) -> Result<Vec<CaseRef>> {
    if !crate::compose::is_path_segment(alert_id) {
        return Err(Error::new(ErrorKind::Error, "invalid alert id"));
    }
    let body = t
        .get(&format!("/api/cases/alerts/{}", urlencode(alert_id)))
        .await?;
    let invalid = || Error::new(ErrorKind::Http, "invalid cases by alert response");
    body.as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|row| {
            let id = row
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| crate::compose::is_path_segment(id))
                .ok_or_else(invalid)?
                .to_owned();
            let title = row
                .get("title")
                .map(|v| v.as_str().map(str::to_owned).ok_or_else(invalid))
                .transpose()?;
            Ok(CaseRef { id, title })
        })
        .collect()
}
