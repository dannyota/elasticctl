//! Requests are sent once for writes and retained only after cleanup succeeds.

use super::{ABSENT, EXCEPTION, ITEM, LIST, MARKER, RANGES, Session, Timing, cleanup, inventory};
use crate::diagnostics::recording_error;
use crate::scrub::scrub_status;
use elasticctl_core::{Result, Transport, urlencode};
use serde_json::{Value, json};
use tokio::time::{Instant, sleep, timeout};

pub(super) async fn record(session: &mut Session<'_>, flavor: Option<String>) -> Result<()> {
    let mut status = session.t.get("/api/status").await?;
    session.evidence.version = status["version"]["number"]
        .as_str()
        .ok_or_else(|| recording_error("status version is missing"))?
        .to_string();
    session.evidence.flavor = flavor.unwrap_or_else(|| {
        status["version"]["build_flavor"]
            .as_str()
            .unwrap_or("unknown")
            .to_string()
    });
    scrub_status(&mut status);
    session.evidence.response("status", status);
    match session.t.get("/api/lists/index").await {
        Ok(body) => session.evidence.response("index_before", body),
        Err(error) if error.http_status == Some(404) => {
            session.before_absent = true;
            session.evidence.refusal("index_before", error);
        }
        Err(error) => return Err(error),
    }
    inventory::require_clear(session.t, session.before_absent).await?;
    session.baseline_checked = true;
    initialize(session).await?;
    container(session).await?;
    values(session).await?;
    references(session).await?;
    create_list(session, RANGES, "spellings_create").await?;
    refusals(session).await?;
    for (index, value) in [
        "2001:DB8:0:0::1",
        "10.0.0.7/24",
        "10.0.0.1-2001:db8::1",
        "2001:db8::/32",
    ]
    .iter()
    .enumerate()
    {
        add_item(session, RANGES, index, value).await?;
    }
    let body = session
        .t
        .post_text(&format!("/api/lists/items/_export?list_id={RANGES}"), None)
        .await?;
    session.evidence.response("export_spellings", json!(body));
    Ok(())
}

async fn initialize(session: &mut Session<'_>) -> Result<()> {
    session.init_attempted = true;
    let request = json!({"flows": ["create-list-indices"]});
    match session
        .t
        .post_once("/api/security_solution/initialize", Some(&request))
        .await
    {
        Ok(body) => session.evidence.exchange("initialize", request, body),
        Err(error)
            if session.evidence.flavor == "traditional"
                && matches!(error.http_status, Some(404 | 405 | 501)) =>
        {
            session.evidence.refusal("initialize_unavailable", error);
            let body = session.t.post_once("/api/lists/index", None).await?;
            session.evidence.response("initialize_fallback", body);
        }
        Err(error) => return Err(error),
    }
    let after = session.t.get("/api/lists/index").await?;
    if after["list_index"] != true || after["list_item_index"] != true {
        return Err(recording_error("list indices are not ready after init"));
    }
    session.evidence.response("index_after", after);
    Ok(())
}

async fn create_list(
    session: &mut Session<'_>,
    id: &'static str,
    name: &'static str,
) -> Result<Value> {
    session.lists.push(id);
    session.pending_creates.insert(id.to_string());
    let request = json!({"id": id, "name": id, "description": MARKER, "type": "ip_range",
        "meta": {"marker": MARKER, "recorder_nonce": session.nonce}});
    let result = session.t.post_once("/api/lists", Some(&request)).await;
    if result
        .as_ref()
        .is_err_and(|e| matches!(e.http_status, Some(400..=499)))
    {
        session.pending_creates.remove(id);
    }
    if result.as_ref().is_err_and(|e| e.http_status == Some(409)) {
        session.lists.retain(|owned| *owned != id);
        session.pending_creates.remove(id);
    }
    let body = result?;
    session.evidence.exchange(name, request, body);
    let current = session.t.get(&format!("/api/lists?id={id}")).await?;
    if !cleanup::owns(session, &current, id, false, false) {
        return Err(recording_error(
            "created list does not prove session ownership",
        ));
    }
    session.pending_creates.remove(id);
    Ok(current)
}

async fn container(session: &mut Session<'_>) -> Result<()> {
    let current = create_list(session, LIST, "container_create").await?;
    session.evidence.response("container_read", current.clone());
    let version = current["_version"]
        .as_str()
        .ok_or_else(|| recording_error("container has no version"))?;
    let request = json!({"id": LIST, "name": "elasticctl-live-vl-updated", "_version": version});
    let body = session.t.patch_once("/api/lists", &request).await?;
    session
        .evidence
        .exchange("container_patch", request.clone(), body);
    let updated = session.t.get(&format!("/api/lists?id={LIST}")).await?;
    if updated["_version"] == current["_version"] {
        return Err(recording_error("PATCH did not change the version"));
    }
    let (status, body) = session
        .t
        .patch_once_response("/api/lists", &request)
        .await?;
    if (200..300).contains(&status) {
        return Err(recording_error("stale PATCH unexpectedly succeeded"));
    }
    require_status(Some(status), 409)?;
    session
        .evidence
        .http_response("container_patch_stale", status, body);
    let request = json!({"id": LIST, "name": "elasticctl-live-vl-updated", "description": MARKER,
        "type": "keyword", "_version": updated["_version"],
        "meta": {"marker": MARKER, "recorder_nonce": session.nonce}});
    let body = session.t.put_once("/api/lists", &request).await?;
    if body["type"] != "ip_range" {
        return Err(recording_error("PUT did not preserve the container type"));
    }
    session
        .evidence
        .exchange("container_put_type_ignored", request, body);
    session.t.get(&format!("/api/lists?id={LIST}")).await?;
    Ok(())
}

async fn add_item(session: &mut Session<'_>, list: &str, index: usize, value: &str) -> Result<()> {
    let id = format!("{list}-item-{index}");
    session.items.push(id.clone());
    let request = json!({"id": id, "list_id": list, "value": value});
    session.pending_imports.insert(list.to_string());
    session
        .t
        .post_once("/api/lists/items", Some(&request))
        .await?;
    settle(session.t, list, index as u64 + 1, session.timing).await?;
    session.pending_imports.remove(list);
    Ok(())
}

async fn values(session: &mut Session<'_>) -> Result<()> {
    for (index, value) in ["10.0.0.5", "10.0.0.5", "10.0.0.6/32", "10.0.0.7/32"]
        .iter()
        .enumerate()
    {
        add_item(session, LIST, index, value).await?;
    }
    let first = session
        .t
        .get(&format!(
            "/api/lists/items/_find?list_id={LIST}&per_page=2&page=1"
        ))
        .await?;
    let cursor = first["cursor"]
        .as_str()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| recording_error("first item page has no cursor"))?
        .to_string();
    if inventory::total(&first)? != 4 || inventory::data(&first)?.len() != 2 {
        return Err(recording_error(
            "first item page did not contain two of four items",
        ));
    }
    session.evidence.exchange(
        "items_find_first",
        json!({"list_id": LIST, "per_page": 2, "page": 1}),
        first,
    );
    let second = session
        .t
        .get(&format!(
            "/api/lists/items/_find?list_id={LIST}&per_page=2&page=2&cursor={}",
            urlencode(&cursor)
        ))
        .await?;
    if inventory::data(&second)?.len() != 2 {
        return Err(recording_error(
            "second item page did not contain two items",
        ));
    }
    session.evidence.exchange(
        "items_find_next",
        json!({"list_id": LIST, "per_page": 2, "page": 2, "cursor": cursor}),
        second,
    );
    let export = session
        .t
        .post_text(&format!("/api/lists/items/_export?list_id={LIST}"), None)
        .await?;
    if export.lines().filter(|v| *v == "10.0.0.5-10.0.0.5").count() != 2 {
        return Err(recording_error(
            "export did not retain both duplicate dash values",
        ));
    }
    session.evidence.response("items_export", json!(export));
    session.pending_imports.insert(LIST.to_string());
    let imported = session
        .t
        .post_multipart_once_named(
            &format!("/api/lists/items/_import?list_id={LIST}&refresh=wait_for"),
            "elasticctl-live-vl.txt",
            "text/plain",
            "10.0.0.8/32\n10.0.0.9/32\n",
        )
        .await?;
    session.evidence.response("items_import", imported);
    let settled = settle(session.t, LIST, 6, session.timing).await?;
    session.evidence.response("items_import_settled", settled);
    session.pending_imports.remove(LIST);
    let delete_path = format!(
        "/api/lists/items?list_id={LIST}&value={}",
        urlencode("10.0.0.5-10.0.0.5")
    );
    session.attempted_deletes.insert(delete_path.clone());
    session.pending_imports.insert(LIST.to_string());
    let (status, body) = session.t.delete_once_response(&delete_path).await?;
    require_status(Some(status), 200)?;
    if body.as_array().is_none_or(|items| items.len() != 2) {
        return Err(recording_error(
            "delete by value did not return both duplicate items",
        ));
    }
    session.evidence.response("items_delete_value", body);
    settle(session.t, LIST, 4, session.timing).await?;
    session.pending_imports.remove(LIST);
    Ok(())
}

async fn references(session: &mut Session<'_>) -> Result<()> {
    session.exception = true;
    session.pending_creates.insert(EXCEPTION.to_string());
    let request = json!({"list_id": EXCEPTION, "name": EXCEPTION, "description": MARKER,
        "type": "detection", "namespace_type": "single", "tags": [MARKER, session.nonce]});
    let result = session
        .t
        .post_once("/api/exception_lists", Some(&request))
        .await;
    if result
        .as_ref()
        .is_err_and(|e| matches!(e.http_status, Some(400..=499)))
    {
        session.pending_creates.remove(EXCEPTION);
    }
    if result.as_ref().is_err_and(|e| e.http_status == Some(409)) {
        session.exception = false;
        session.pending_creates.remove(EXCEPTION);
    }
    let body = result?;
    session.evidence.exchange("exception_create", request, body);
    let current = session.t.get(&cleanup::exception_path(false)).await?;
    if !cleanup::owns(session, &current, EXCEPTION, true, false) {
        return Err(recording_error(
            "exception container does not prove session ownership",
        ));
    }
    session.pending_creates.remove(EXCEPTION);
    session.exception_item = true;
    session.pending_creates.insert(ITEM.to_string());
    let request = json!({"item_id": ITEM, "list_id": EXCEPTION, "name": ITEM, "description": MARKER,
        "type": "simple", "namespace_type": "single", "tags": [MARKER, session.nonce],
        "entries": [{"type": "list", "list": {"id": LIST, "type": "ip_range"}, "field": "source.ip", "operator": "included"}]});
    let result = session
        .t
        .post_once("/api/exception_lists/items", Some(&request))
        .await;
    if result
        .as_ref()
        .is_err_and(|e| matches!(e.http_status, Some(400..=499)))
    {
        session.pending_creates.remove(ITEM);
    }
    if result.as_ref().is_err_and(|e| e.http_status == Some(409)) {
        session.exception_item = false;
        session.pending_creates.remove(ITEM);
    }
    let body = result?;
    session
        .evidence
        .exchange("exception_item_create", request, body);
    let current = session.t.get(&cleanup::exception_path(true)).await?;
    if !cleanup::owns(session, &current, ITEM, true, true) {
        return Err(recording_error(
            "exception item does not prove session ownership",
        ));
    }
    session.pending_creates.remove(ITEM);
    let delete_path = format!("/api/lists?id={LIST}");
    session.attempted_deletes.insert(delete_path.clone());
    let (status, body) = session.t.delete_once_response(&delete_path).await?;
    require_status(Some(status), 409)?;
    // A confirmed refusal permits the later delete after removing the reference.
    session.attempted_deletes.remove(&delete_path);
    if !body["references"].is_array() || body["references"].as_array().is_some_and(Vec::is_empty) {
        return Err(recording_error("referenced delete has no references body"));
    }
    session
        .evidence
        .response("container_delete_referenced", body);
    cleanup::delete_owned(session, &cleanup::exception_path(true), ITEM, true, true).await?;
    session.exception_item = false;
    let body = cleanup::delete_owned(
        session,
        &format!("/api/lists?id={LIST}"),
        LIST,
        false,
        false,
    )
    .await?
    .ok_or_else(|| recording_error("container disappeared before its recorded delete"))?;
    session.lists.retain(|id| *id != LIST);
    session.evidence.response("container_delete", body);
    cleanup::delete_owned(
        session,
        &cleanup::exception_path(false),
        EXCEPTION,
        true,
        false,
    )
    .await?;
    session.exception = false;
    Ok(())
}

async fn refusals(session: &mut Session<'_>) -> Result<()> {
    for (name, list, filename, content, expected) in [
        (
            "import_too_large",
            RANGES,
            "elasticctl-live-vl.txt",
            "x".repeat(9_000_001),
            413,
        ),
        (
            "import_wrong_extension",
            RANGES,
            "elasticctl-live-vl.json",
            "10.0.0.1/32\n".to_string(),
            415,
        ),
        (
            "import_absent_list",
            ABSENT,
            "elasticctl-live-vl.txt",
            "10.0.0.1/32\n".to_string(),
            409,
        ),
    ] {
        if !session.lists.contains(&list) {
            session.lists.push(list);
        }
        session.pending_imports.insert(list.to_string());
        let (status, body) = session
            .t
            .post_multipart_once_named_response(
                &format!("/api/lists/items/_import?list_id={list}&refresh=wait_for"),
                filename,
                "text/plain",
                &content,
            )
            .await?;
        if (400..500).contains(&status) {
            session.pending_imports.remove(list);
        }
        if (200..300).contains(&status) {
            return Err(recording_error("import refusal unexpectedly succeeded"));
        }
        require_status(Some(status), expected)?;
        session.evidence.http_response(name, status, body);
    }
    Ok(())
}

fn require_status(actual: Option<u16>, expected: u16) -> Result<()> {
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(recording_error(format!(
            "expected HTTP {expected}, received {actual:?}"
        )))
    }
}

/// Require the known count on two consecutive reads. An unchanged old total is not settled.
pub(super) async fn settle(
    t: &Transport,
    list: &str,
    expected: u64,
    timing: Timing,
) -> Result<Value> {
    let work = async {
        let deadline = Instant::now() + timing.budget;
        let mut matched = false;
        loop {
            let body = t
                .get(&format!(
                    "/api/lists/items/_find?list_id={}&per_page=1&page=1",
                    urlencode(list)
                ))
                .await?;
            let matches = inventory::total(&body)? == expected;
            if matches && matched {
                return Ok(body);
            }
            matched = matches;
            if Instant::now() >= deadline {
                return Err(recording_error("item settle timed out"));
            }
            sleep(timing.interval).await;
        }
    };
    timeout(timing.budget, work)
        .await
        .map_err(|_| recording_error("item settle timed out"))?
}
