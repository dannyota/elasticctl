use crate::diagnostics::recording_error;
use crate::recorder::markers::{
    ALERT_MARKER_TAG, ALERT_PROBE_INDEX, ALERT_RULE_ID, CASE_TAG, CASE_TITLE, ITEM_ID, LIST_ID,
    MARKER_TAGS, NAMESPACE_TYPE, RULE_ID, SCRATCH_MARKER,
};
use crate::recorder::preview::{PREVIEW_PROBE_INDEX, SEARCH_MARKER, SEARCH_PROBE_INDEX};
use elasticctl_core::urlencode;
use serde_json::Value;

fn has_marker_tags(value: &Value) -> bool {
    let tags = value.get("tags").and_then(Value::as_array);
    MARKER_TAGS.iter().all(|tag| {
        tags.is_some_and(|tags| tags.iter().any(|candidate| candidate.as_str() == Some(tag)))
    })
}

pub(crate) fn owns_rule(value: &Value) -> bool {
    value.get("rule_id").and_then(Value::as_str) == Some(RULE_ID) && has_marker_tags(value)
}

pub(crate) fn owns_list(value: &Value) -> bool {
    value.get("list_id").and_then(Value::as_str) == Some(LIST_ID)
        && value
            .get("namespace_type")
            .and_then(Value::as_str)
            .unwrap_or("single")
            == NAMESPACE_TYPE
        && has_marker_tags(value)
}

pub(crate) fn owns_item(value: &Value) -> bool {
    value.get("item_id").and_then(Value::as_str) == Some(ITEM_ID)
        && value.get("list_id").and_then(Value::as_str) == Some(LIST_ID)
        && value
            .get("namespace_type")
            .and_then(Value::as_str)
            .unwrap_or("single")
            == NAMESPACE_TYPE
        && has_marker_tags(value)
}

pub(crate) fn owns_scratch_index(value: &Value) -> bool {
    value["_source"][SCRATCH_MARKER].as_bool() == Some(true)
}

pub(crate) fn owns_search_index(value: &Value) -> bool {
    value["_source"]["marker"].as_str() == Some(SEARCH_MARKER)
}

pub(crate) fn owns_alert_rule(value: &Value) -> bool {
    value.get("rule_id").and_then(Value::as_str) == Some(ALERT_RULE_ID)
        && value
            .get("tags")
            .and_then(Value::as_array)
            .is_some_and(|tags| {
                tags.iter()
                    .any(|tag| tag.as_str() == Some(ALERT_MARKER_TAG))
            })
}

pub(crate) fn owns_alert_index(value: &Value) -> bool {
    value["_source"]["marker"].as_str() == Some(ALERT_MARKER_TAG)
}

pub(crate) fn owns_case(value: &Value) -> bool {
    value.get("title").and_then(Value::as_str) == Some(CASE_TITLE)
        && value
            .get("tags")
            .and_then(Value::as_array)
            .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(CASE_TAG)))
}

pub(crate) async fn require_absent_rule(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    match t
        .get(&format!("/api/detection_engine/rules?rule_id={RULE_ID}"))
        .await
    {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: rule {RULE_ID} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) async fn require_absent_list(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    match t
        .get(&format!(
            "/api/exception_lists?list_id={}&namespace_type={NAMESPACE_TYPE}",
            urlencode(LIST_ID)
        ))
        .await
    {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: exception list {LIST_ID} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) async fn require_absent_item(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    match t
        .get(&format!(
            "/api/exception_lists/items?item_id={}&namespace_type={NAMESPACE_TYPE}",
            urlencode(ITEM_ID)
        ))
        .await
    {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: exception item {ITEM_ID} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) async fn require_absent_scratch_index(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    match t.get_absolute_es(&format!("/{PREVIEW_PROBE_INDEX}")).await {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: scratch index {PREVIEW_PROBE_INDEX} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) async fn require_absent_search_index(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    match t.get_absolute_es(&format!("/{SEARCH_PROBE_INDEX}")).await {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: scratch index {SEARCH_PROBE_INDEX} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) async fn require_absent_alert_rule(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    match t
        .get(&format!(
            "/api/detection_engine/rules?rule_id={ALERT_RULE_ID}"
        ))
        .await
    {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: rule {ALERT_RULE_ID} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) async fn require_absent_alert_index(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    match t.get_absolute_es(&format!("/{ALERT_PROBE_INDEX}")).await {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: scratch index {ALERT_PROBE_INDEX} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::markers::{ALERT_MARKER_TAG, ALERT_RULE_ID};
    use serde_json::json;

    #[test]
    fn owns_alert_rule_checks_id_and_marker_tag() {
        assert!(owns_alert_rule(&json!({
            "rule_id": ALERT_RULE_ID,
            "tags": [ALERT_MARKER_TAG]
        })));
        assert!(!owns_alert_rule(
            &json!({"rule_id": ALERT_RULE_ID, "tags": []})
        ));
        assert!(!owns_alert_rule(
            &json!({"rule_id": "other", "tags": [ALERT_MARKER_TAG]})
        ));
    }

    #[test]
    fn owns_alert_index_checks_the_marker_field() {
        assert!(owns_alert_index(
            &json!({"_source": {"marker": ALERT_MARKER_TAG}})
        ));
        assert!(!owns_alert_index(&json!({"_source": {"marker": "other"}})));
    }
}
