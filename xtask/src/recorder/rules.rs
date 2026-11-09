//! Rules helpers.

use crate::diagnostics::recording_error;
use crate::recorder::markers::{ITEM_ID, LIST_ID, MARKER_TAGS, NAMESPACE_TYPE, RULE_ID};
use crate::recorder::ownership::{
    owns_item, owns_list, owns_rule, require_absent_item, require_absent_list, require_absent_rule,
};
use crate::recorder::session::RecordingSession;
use serde_json::{Value, json};

pub(crate) async fn create_marked_list(
    session: &mut RecordingSession<'_>,
) -> elasticctl_core::Result<Value> {
    require_absent_list(session.transport).await?;
    let body = json!({
        "list_id": LIST_ID,
        "namespace_type": NAMESPACE_TYPE,
        "name": "elasticctl sample exceptions",
        "description": "Recorded by cargo xtask record. Safe to delete.",
        "type": "detection",
        "tags": MARKER_TAGS,
    });
    let created = session
        .transport
        .post("/api/exception_lists", Some(&body))
        .await?;
    if !owns_list(&created) {
        return Err(recording_error(
            "exception list create response did not prove the fixed marker identity",
        ));
    }
    session.ownership.list = true;
    Ok(created)
}

pub(crate) async fn create_marked_item(
    session: &mut RecordingSession<'_>,
) -> elasticctl_core::Result<Value> {
    require_absent_item(session.transport).await?;
    let body = json!({
        "item_id": ITEM_ID,
        "list_id": LIST_ID,
        "namespace_type": NAMESPACE_TYPE,
        "name": "elasticctl sample exception item",
        "description": "Recorded by cargo xtask record. Safe to delete.",
        "type": "simple",
        "entries": [{
            "field": "process.name",
            "operator": "included",
            "type": "match",
            "value": "elasticctl-sample.exe",
        }],
        "tags": MARKER_TAGS,
    });
    let created = session
        .transport
        .post("/api/exception_lists/items", Some(&body))
        .await?;
    if !owns_item(&created) {
        return Err(recording_error(
            "exception item create response did not prove the fixed marker identity",
        ));
    }
    session.ownership.item = true;
    Ok(created)
}

pub(crate) async fn create_marked_rule(
    session: &mut RecordingSession<'_>,
    list_server_id: &str,
) -> elasticctl_core::Result<(Value, Value)> {
    require_absent_rule(session.transport).await?;
    let body = json!({
        "rule_id": RULE_ID,
        "name": "elasticctl fixture probe",
        "description": "Recorded by cargo xtask record. Safe to delete.",
        "type": "query",
        "language": "kuery",
        "query": "*:*",
        "index": ["logs-*"],
        "severity": "low",
        "risk_score": 21,
        "enabled": false,
        "from": "now-6m",
        "interval": "5m",
        "tags": MARKER_TAGS,
        "exceptions_list": [{
            "id": list_server_id,
            "list_id": LIST_ID,
            "namespace_type": NAMESPACE_TYPE,
            "type": "detection",
        }],
    });
    let created = session
        .transport
        .post("/api/detection_engine/rules", Some(&body))
        .await?;
    if !owns_rule(&created) {
        return Err(recording_error(
            "rule create response did not prove the fixed marker identity",
        ));
    }
    session.ownership.rule = true;
    Ok((body, created))
}
