use super::*;
use crate::observe::{Observed, Preconditions};

pub(super) fn case_state(case: &Case, with_version: bool) -> Value {
    let mut state = serde_json::Map::new();
    state.insert("status".into(), Value::String(case.status.clone()));
    state.insert("title".into(), Value::String(case.title.clone()));
    if with_version {
        state.insert("version".into(), Value::String(case.version.clone()));
        state.insert("sync_alerts".into(), sync_alerts(case));
    }
    Value::Object(state)
}

fn sync_alerts(case: &Case) -> Value {
    case.extra
        .get("settings")
        .and_then(|s| s.get("syncAlerts"))
        .filter(|value| value.is_boolean())
        .cloned()
        .unwrap_or(Value::Null)
}

pub async fn plan_status_observed(
    t: &Transport,
    ids: &[String],
    target: CaseStatus,
) -> Result<(StatusPlan, Preconditions)> {
    let resolved = resolve_case_values(t, ids).await?;
    let seen = Preconditions(
        resolved
            .iter()
            .map(|case| Observed {
                object: "case",
                id: case.id.clone(),
                state: Some(case_state(case, true)),
            })
            .collect(),
    );
    let mut updates = Vec::new();
    let mut details = Vec::new();
    for case in &resolved {
        if case.status == target.as_str() {
            details.push(format!(
                "{}  {}  already {}",
                case.id, case.title, case.status
            ));
        } else {
            details.push(format!(
                "{}  {}  {} -> {}",
                case.id,
                case.title,
                case.status,
                target.as_str()
            ));
            updates.push((case.id.clone(), case.version.clone(), target));
        }
    }
    Ok((
        StatusPlan {
            preview_action: format!(
                "{} {} {}",
                target.verb(),
                resolved.len(),
                case_noun(resolved.len())
            ),
            target,
            updates,
            resolved: resolved.len(),
            preview_details: details,
        },
        seen,
    ))
}

pub async fn plan_comment_observed(
    t: &Transport,
    case_id: &str,
    message: &str,
) -> Result<(CommentPlan, Preconditions)> {
    if message.trim().is_empty() {
        return Err(Error::new(ErrorKind::Error, "pass a non-empty --message"));
    }
    let case = cases::get(t, case_id).await?;
    let seen = Preconditions(vec![Observed {
        object: "case",
        id: case.id.clone(),
        state: Some(case_state(&case, false)),
    }]);
    Ok((
        CommentPlan {
            preview_action: format!("Comment on case '{}'", case.title),
            preview_details: vec![message.to_string()],
            case_id: case.id,
            message: message.to_string(),
        },
        seen,
    ))
}
