use super::{
    ABSENT, EXCEPTION, ITEM, LIST, MARKER, RANGES, Session, cleanup, definite_refusal, inventory,
};
use crate::diagnostics::recording_error;
use crate::scrub::scrub_status;
use elasticctl_core::{Result, urlencode};
use serde_json::{Value, json};
use tokio::time::{Instant, sleep, timeout};

pub(super) async fn record(session: &mut Session<'_>, flavor: Option<String>) -> Result<()> {
    let mut status = session.get("/api/status").await?;
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
    let (status, body) = session.t.get_response("/api/lists/index").await?;
    match status {
        200..=299 => session.evidence.http_response("index_before", status, body),
        404 => {
            session.before_absent = true;
            session.evidence.http_response("index_before", status, body);
        }
        _ => {
            return Err(elasticctl_core::Error::from_response_body(
                status,
                &body.to_string(),
            ));
        }
    }
    inventory::require_clear(session).await?;
    session.baseline_checked = true;
    initialize(session).await?;
    container(session).await?;
    values(session).await?;
    create_list(session, RANGES, "spellings_create").await?;
    lists_find(session).await?;
    references(session).await?;
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
    let (status, body) = session
        .t
        .post_once_response("/api/security_solution/initialize", Some(&request))
        .await?;
    match status {
        200..=299 => session.evidence.exchange("initialize", request, body),
        404 | 405 if session.evidence.flavor == "traditional" => {
            session
                .evidence
                .http_response("initialize_unavailable", status, body);
            let body = session.t.post_once("/api/lists/index", None).await?;
            session.evidence.response("initialize_fallback", body);
        }
        _ => {
            return Err(elasticctl_core::Error::from_response_body(
                status,
                &body.to_string(),
            ));
        }
    }
    let after = session.get("/api/lists/index").await?;
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
        .is_err_and(|e| definite_refusal(e.http_status))
    {
        session.pending_creates.remove(id);
    }
    if result.as_ref().is_err_and(|e| e.http_status == Some(409)) {
        session.lists.retain(|owned| *owned != id);
        session.pending_creates.remove(id);
    }
    let body = result?;
    session.evidence.exchange(name, request, body);
    let current = session.get(&format!("/api/lists?id={id}")).await?;
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
    let updated = session.get(&format!("/api/lists?id={LIST}")).await?;
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
    require_status("container_patch_stale", status, 409)?;
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
    session.get(&format!("/api/lists?id={LIST}")).await?;
    Ok(())
}

async fn add_item(session: &mut Session<'_>, list: &str, index: usize, value: &str) -> Result<()> {
    let id = format!("{list}-item-{index}");
    session.items.push(id.clone());
    let request = json!({"id": id, "list_id": list, "value": value});
    session
        .pending_imports
        .insert(list.to_string(), Some(index as u64 + 1));
    let result = session
        .t
        .post_once("/api/lists/items", Some(&request))
        .await;
    session.clear_refused_import(list, result.as_ref().err().and_then(|e| e.http_status));
    let body = result?;
    session.evidence.observe(&body);
    settle(session, list, index as u64 + 1).await?;
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
        first.clone(),
    );
    let second = session
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
        second.clone(),
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
    let items = inventory::data(&first)?
        .iter()
        .chain(inventory::data(&second)?);
    let mut page_values = Vec::new();
    let mut duplicate_ids = Vec::new();
    for item in items {
        let value = item["value"]
            .as_str()
            .ok_or_else(|| recording_error("items_export: page item has no value"))?;
        page_values.push(value);
        if value == "10.0.0.5-10.0.0.5" {
            duplicate_ids.push(
                item["id"]
                    .as_str()
                    .ok_or_else(|| recording_error("items_delete_id: duplicate has no id"))?,
            );
        }
    }
    let mut exported_values: Vec<_> = export.lines().filter(|line| !line.is_empty()).collect();
    page_values.sort_unstable();
    exported_values.sort_unstable();
    if page_values != exported_values {
        return Err(recording_error(
            "items_export: item pages do not match export",
        ));
    }
    duplicate_ids.sort_unstable();
    let expected_ids = [format!("{LIST}-item-0"), format!("{LIST}-item-1")];
    if duplicate_ids != expected_ids {
        return Err(recording_error(
            "items_delete_id: unexpected duplicate item ids",
        ));
    }
    session.evidence.response("items_export", json!(export));
    session.pending_imports.insert(LIST.to_string(), Some(6));
    let result = session
        .t
        .post_multipart_once_named(
            &format!("/api/lists/items/_import?list_id={LIST}&refresh=wait_for"),
            "elasticctl-live-vl.txt",
            "text/plain",
            "10.0.0.8/32\n10.0.0.9/32\n",
        )
        .await;
    session.clear_refused_import(LIST, result.as_ref().err().and_then(|e| e.http_status));
    session.evidence.response("items_import", result?);
    let settled = settle(session, LIST, 6).await?;
    session.evidence.response("items_import_settled", settled);
    session.pending_imports.remove(LIST);
    for (index, id) in expected_ids.iter().enumerate() {
        let delete_path = format!("/api/lists/items?id={}", urlencode(id));
        session.attempted_deletes.insert(delete_path.clone());
        let expected = 5 - index as u64;
        session
            .pending_imports
            .insert(LIST.to_string(), Some(expected));
        let result = session.t.delete_once_response(&delete_path).await;
        let status = result
            .as_ref()
            .map(|(status, _)| *status)
            .ok()
            .or_else(|| result.as_ref().err().and_then(|e| e.http_status));
        session.clear_refused_import(LIST, status);
        let (status, body) = result.map_err(|error| step_error("items_delete_id", 200, error))?;
        require_status("items_delete_id", status, 200)?;
        if index == 0 {
            session.evidence.response("items_delete_id", body);
        }
        settle(session, LIST, expected).await?;
        session.pending_imports.remove(LIST);
    }
    let path = format!("/api/lists/items?id={}", urlencode(&expected_ids[0]));
    let (status, body) = session
        .t
        .delete_once_response(&path)
        .await
        .map_err(|error| step_error("items_delete_id_absent", 404, error))?;
    require_status("items_delete_id_absent", status, 404)?;
    session
        .evidence
        .http_response("items_delete_id_absent", status, body);
    Ok(())
}

async fn lists_find(session: &mut Session<'_>) -> Result<()> {
    let filter = "name:elasticctl-live-vl-*";
    let path = format!(
        "/api/lists/_find?per_page=1&page=1&filter={}",
        urlencode(filter)
    );
    let (status, first) = session
        .t
        .get_response(&path)
        .await
        .map_err(|error| step_error("lists_find_first", 200, error))?;
    require_status("lists_find_first", status, 200)?;
    let rows = first["data"]
        .as_array()
        .filter(|rows| rows.len() == 1)
        .ok_or_else(|| recording_error("lists_find_first: expected one row"))?;
    if first["total"].as_u64() != Some(2) {
        return Err(recording_error("lists_find_first: expected total 2"));
    }
    let first_id = rows[0]["id"]
        .as_str()
        .ok_or_else(|| recording_error("lists_find_first: row has no id"))?
        .to_string();
    let cursor = first["cursor"]
        .as_str()
        .filter(|cursor| !cursor.is_empty())
        .ok_or_else(|| recording_error("lists_find_first: missing cursor"))?
        .to_string();
    session.evidence.exchange(
        "lists_find_first",
        json!({"per_page": 1, "page": 1, "filter": filter}),
        first,
    );
    let path = format!(
        "/api/lists/_find?per_page=1&page=2&filter={}&cursor={}",
        urlencode(filter),
        urlencode(&cursor)
    );
    let (status, second) = session
        .t
        .get_response(&path)
        .await
        .map_err(|error| step_error("lists_find_next", 200, error))?;
    require_status("lists_find_next", status, 200)?;
    let rows = second["data"]
        .as_array()
        .filter(|rows| rows.len() == 1)
        .ok_or_else(|| recording_error("lists_find_next: expected one row"))?;
    let second_id = rows[0]["id"]
        .as_str()
        .ok_or_else(|| recording_error("lists_find_next: row has no id"))?;
    if !((first_id == LIST && second_id == RANGES) || (first_id == RANGES && second_id == LIST)) {
        return Err(recording_error("lists_find_next: unexpected list ids"));
    }
    session.evidence.exchange(
        "lists_find_next",
        json!({"per_page": 1, "page": 2, "filter": filter, "cursor": cursor}),
        second,
    );
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
        .is_err_and(|e| definite_refusal(e.http_status))
    {
        session.pending_creates.remove(EXCEPTION);
    }
    if result.as_ref().is_err_and(|e| e.http_status == Some(409)) {
        session.exception = false;
        session.pending_creates.remove(EXCEPTION);
    }
    let body = result?;
    session.evidence.exchange("exception_create", request, body);
    let current = session.get(&cleanup::exception_path(false)).await?;
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
        .is_err_and(|e| definite_refusal(e.http_status))
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
    let current = session.get(&cleanup::exception_path(true)).await?;
    if !cleanup::owns(session, &current, ITEM, true, true) {
        return Err(recording_error(
            "exception item does not prove session ownership",
        ));
    }
    session.pending_creates.remove(ITEM);
    let delete_path = format!("/api/lists?id={LIST}");
    session.attempted_deletes.insert(delete_path.clone());
    let (status, body) = session.t.delete_once_response(&delete_path).await?;
    require_status("container_delete_referenced", status, 409)?;
    session.attempted_deletes.remove(&delete_path);
    if body
        .pointer("/message/error/references")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
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
        session.pending_imports.insert(list.to_string(), None);
        let (status, body) = session
            .t
            .post_multipart_once_named_response(
                &format!("/api/lists/items/_import?list_id={list}&refresh=wait_for"),
                filename,
                "text/plain",
                &content,
            )
            .await?;
        if definite_refusal(Some(status)) {
            session.pending_imports.remove(list);
        }
        if (200..300).contains(&status) {
            return Err(recording_error("import refusal unexpectedly succeeded"));
        }
        require_status(name, status, expected)?;
        session.evidence.http_response(name, status, body);
    }
    Ok(())
}

fn require_status(step: &str, actual: u16, expected: u16) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(recording_error(format!(
            "{step}: expected HTTP {expected}, received {actual}"
        )))
    }
}

pub(super) async fn settle(session: &mut Session<'_>, list: &str, expected: u64) -> Result<Value> {
    let timing = session.timing;
    let work = async {
        let deadline = Instant::now() + timing.budget;
        let mut matched = false;
        loop {
            let body = session
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

fn step_error(
    step: &str,
    expected: u16,
    mut error: elasticctl_core::Error,
) -> elasticctl_core::Error {
    error.kind = elasticctl_core::ErrorKind::Error;
    error.message = match error.http_status {
        Some(status) => format!("{step}: expected HTTP {expected}, received {status}"),
        None => format!("{step}: request failed"),
    };
    error
}
