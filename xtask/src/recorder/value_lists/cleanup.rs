//! Exact-id cleanup runs before any fixture is published.

use super::{EXCEPTION, ITEM, MARKER, Session, inventory};
use crate::diagnostics::{recording_error, safe_recording_error_summary};
use elasticctl_core::{Result, urlencode};
use serde_json::Value;

pub(super) fn exception_path(item: bool) -> String {
    if item {
        format!("/api/exception_lists/items?item_id={ITEM}&namespace_type=single")
    } else {
        format!("/api/exception_lists?list_id={EXCEPTION}&namespace_type=single")
    }
}

pub(super) fn owns(
    session: &Session<'_>,
    body: &Value,
    id: &str,
    exception: bool,
    item: bool,
) -> bool {
    if exception {
        body["list_id"].as_str() == Some(EXCEPTION)
            && (!item || body["item_id"].as_str() == Some(ITEM))
            && body["namespace_type"].as_str() == Some("single")
            && body["tags"].as_array().is_some_and(|tags| {
                tags.iter().any(|tag| tag.as_str() == Some(MARKER))
                    && tags.iter().any(|tag| tag.as_str() == Some(&session.nonce))
            })
    } else {
        body["id"].as_str() == Some(id)
            && body["meta"]["marker"].as_str() == Some(MARKER)
            && body["meta"]["recorder_nonce"].as_str() == Some(&session.nonce)
    }
}

pub(super) async fn delete_owned(
    session: &Session<'_>,
    path: &str,
    id: &str,
    exception: bool,
    item: bool,
) -> Result<Option<Value>> {
    let read = async {
        loop {
            match session.t.get(path).await {
                Err(error)
                    if error.http_status == Some(404) && session.pending_creates.contains(id) =>
                {
                    tokio::time::sleep(session.timing.interval).await;
                }
                result => return result,
            }
        }
    };
    let found = if session.pending_creates.contains(id) {
        tokio::time::timeout(session.timing.budget, read)
            .await
            .map_err(|_| {
                recording_error(format!("cleanup could not resolve pending create for {id}"))
            })?
    } else {
        read.await
    };
    match found {
        Err(error) if error.http_status == Some(404) => return Ok(None),
        Err(error) => return Err(error),
        Ok(body) if !owns(session, &body, id, exception, item) => {
            return Err(recording_error(format!(
                "refusing cleanup: ownership changed for {id}"
            )));
        }
        Ok(_) => {}
    }
    let (status, body) = session.t.delete_once_response(path).await?;
    if status != 200 && status != 404 {
        return Err(recording_error(format!(
            "cleanup delete of {id} returned HTTP {status}"
        )));
    }
    match session.t.get(path).await {
        Err(error) if error.http_status == Some(404) => Ok((status == 200).then_some(body)),
        Err(error) => Err(error),
        Ok(_) => Err(recording_error(format!(
            "cleanup verification still found {id}"
        ))),
    }
}

pub(super) async fn finish(session: &mut Session<'_>) -> Result<()> {
    if !session.baseline_checked {
        return Ok(());
    }
    let mut failures = Vec::new();
    if session.pending_import {
        // Accepted imports can continue writing after the HTTP answer is lost.
        tokio::time::sleep(session.timing.budget).await;
    }
    if session.exception_item {
        match delete_owned(session, &exception_path(true), ITEM, true, true).await {
            Ok(_) => session.exception_item = false,
            Err(error) => failures.push(failure(ITEM, error)),
        }
    }
    if session.exception && !session.exception_item {
        match delete_owned(session, &exception_path(false), EXCEPTION, true, false).await {
            Ok(_) => session.exception = false,
            Err(error) => failures.push(failure(EXCEPTION, error)),
        }
    }
    // A surviving reference blocks its value list. Other owned lists can still be cleaned.
    for id in session.lists.clone().into_iter().rev() {
        if id == super::LIST && session.exception_item {
            continue;
        }
        match delete_owned(
            session,
            &format!("/api/lists?id={}", urlencode(id)),
            id,
            false,
            false,
        )
        .await
        {
            Ok(_) => session.lists.retain(|owned| *owned != id),
            Err(error) => failures.push(failure(id, error)),
        }
    }
    if let Err(error) = inventory::require_clear(session.t, session.before_absent).await {
        failures.push(failure("marker audit", error));
    }
    if failures.is_empty()
        && session.lists.is_empty()
        && !session.exception
        && !session.exception_item
    {
        session.items.clear();
        session.pending_creates.clear();
        restore(session).await?;
    } else {
        return Err(recording_error(format!(
            "cleanup failed: {}",
            failures.join("; ")
        )));
    }
    Ok(())
}

pub(super) async fn restore(session: &mut Session<'_>) -> Result<()> {
    if !session.before_absent || session.evidence.flavor == "traditional" || !session.init_attempted
    {
        return Ok(());
    }
    let body = session.t.get("/api/lists/_find?per_page=1").await?;
    if inventory::total(&body)? != 0 {
        return Ok(());
    }
    let (status, body) = session.t.delete_once_response("/api/lists/index").await?;
    if status != 200 {
        return Err(recording_error(format!(
            "index restore returned HTTP {status}"
        )));
    }
    session.evidence.response("index_delete", body);
    match session.t.get("/api/lists/index").await {
        Err(error) if error.http_status == Some(404) => {
            session.evidence.refusal("index_restored", error);
            Ok(())
        }
        Err(error) => Err(error),
        Ok(_) => Err(recording_error("index restore did not return 404")),
    }
}

fn failure(id: &str, error: elasticctl_core::Error) -> String {
    let message = if error.kind == elasticctl_core::ErrorKind::Error {
        error.message.as_str()
    } else {
        "endpoint failed"
    };
    format!("{id}: {message} ({})", safe_recording_error_summary(&error))
}
