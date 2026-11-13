use super::{
    CONTAIN, EXCEPTION, LIST, Session,
    steps::{add_item, create_list, require_status, settle, step_error},
};
use crate::diagnostics::recording_error;
use elasticctl_core::{Result, urlencode};
use serde_json::json;

pub(super) async fn reference_reads(session: &mut Session<'_>) -> Result<()> {
    let filter = "exception-list.attributes.list_id:elasticctl-live-vl-*";
    let path = format!(
        "/api/exception_lists/_find?namespace_type=single&per_page=10&page=1&filter={}",
        urlencode(filter)
    );
    let (status, body) = session
        .t
        .get_response(&path)
        .await
        .map_err(|e| step_error("exception_lists_find", 200, e))?;
    require_status("exception_lists_find", status, 200)?;
    if body["total"] != 1
        || !body["data"]
            .as_array()
            .is_some_and(|rows| rows.len() == 1 && rows[0]["list_id"] == EXCEPTION)
    {
        return Err(recording_error(
            "exception_lists_find: expected one marker container",
        ));
    }
    session.evidence.exchange(
        "exception_lists_find",
        json!({"namespace_type":"single", "per_page":10, "page":1, "filter":filter}),
        body,
    );
    let path = format!(
        "/api/exception_lists/items/_find?list_id={}&namespace_type=single&per_page=10&page=1",
        urlencode(EXCEPTION)
    );
    let (status, body) = session
        .t
        .get_response(&path)
        .await
        .map_err(|e| step_error("exception_items_find", 200, e))?;
    require_status("exception_items_find", status, 200)?;
    let valid = body["data"].as_array().is_some_and(|rows| {
        rows.len() == 1
            && rows[0]["entries"].as_array().is_some_and(|entries| {
                entries.len() == 2
                    && entries
                        .iter()
                        .zip([("source.ip", "included"), ("destination.ip", "excluded")])
                        .all(|(entry, (field, operator))| {
                            entry["type"] == "list"
                                && entry["list"]["id"] == LIST
                                && entry["list"]["type"] == "ip_range"
                                && entry["field"] == field
                                && entry["operator"] == operator
                        })
            })
    });
    if body["total"] != 1 || !valid {
        return Err(recording_error(
            "exception_items_find: expected two list entries",
        ));
    }
    session.evidence.exchange(
        "exception_items_find",
        json!({"list_id": EXCEPTION, "namespace_type":"single", "per_page":10, "page":1}),
        body,
    );
    Ok(())
}

pub(super) async fn containment(session: &mut Session<'_>) -> Result<()> {
    create_list(session, CONTAIN, "contain_create")
        .await
        .map_err(|e| step_error("contain_create", 200, e))?;
    for (index, value) in ["10.0.0.0/8", "10.0.0.5/32"].iter().enumerate() {
        add_item(session, CONTAIN, index, value)
            .await
            .map_err(|e| step_error(&format!("contain_add_item_{index}"), 200, e))?;
    }
    contain_export(session, "contain_export", &["10.0.0.0/8", "10.0.0.5/32"]).await?;
    let path = format!(
        "/api/lists/items?id={}",
        urlencode(&format!("{CONTAIN}-item-1"))
    );
    session.attempted_deletes.insert(path.clone());
    session.pending_imports.insert(CONTAIN.to_string(), Some(1));
    let result = session.t.delete_once_response(&path).await;
    let status = result
        .as_ref()
        .map(|(status, _)| *status)
        .ok()
        .or_else(|| result.as_ref().err().and_then(|e| e.http_status));
    session.clear_refused_import(CONTAIN, status);
    let (status, body) = result.map_err(|e| step_error("contain_delete_id", 200, e))?;
    require_status("contain_delete_id", status, 200)?;
    session.evidence.response("contain_delete_id", body);
    settle(session, CONTAIN, 1)
        .await
        .map_err(|e| step_error("contain_delete_id", 200, e))?;
    session.pending_imports.remove(CONTAIN);
    contain_export(session, "contain_export_after", &["10.0.0.0/8"]).await
}

async fn contain_export(
    session: &mut Session<'_>,
    step: &'static str,
    expected: &[&str],
) -> Result<()> {
    let body = session
        .t
        .post_text(&format!("/api/lists/items/_export?list_id={CONTAIN}"), None)
        .await
        .map_err(|e| step_error(step, 200, e))?;
    let mut lines: Vec<_> = body.lines().filter(|line| !line.is_empty()).collect();
    lines.sort_unstable();
    if lines != expected {
        return Err(recording_error(format!("{step}: unexpected export values")));
    }
    session.evidence.response(step, json!(body));
    Ok(())
}
