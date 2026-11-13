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
    session: &mut Session<'_>,
    path: &str,
    id: &str,
    exception: bool,
    item: bool,
) -> Result<Option<Value>> {
    if session.attempted_deletes.contains(path) {
        wait_deleted(session, path, id).await?;
        return Ok(None);
    }
    let budget = session.timing.budget;
    let pending = session.pending_creates.contains(id);
    let read = async {
        loop {
            match session.get(path).await {
                Err(error)
                    if error.http_status == Some(404) && session.pending_creates.contains(id) =>
                {
                    tokio::time::sleep(session.timing.interval).await;
                }
                result => return result,
            }
        }
    };
    let found = if pending {
        tokio::time::timeout(budget, read).await.map_err(|_| {
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
    // Record before sending so a lost answer or cancellation cannot cause a resend.
    session.attempted_deletes.insert(path.to_string());
    let answer = session.t.delete_once_response(path).await;
    if let Ok((_, body)) = &answer {
        session.evidence.observe(body);
    }
    wait_deleted(session, path, id).await?;
    Ok(answer
        .ok()
        .and_then(|(status, body)| (status == 200).then_some(body)))
}

async fn wait_deleted(session: &mut Session<'_>, path: &str, id: &str) -> Result<()> {
    let budget = session.timing.budget;
    let reads = async {
        loop {
            if session
                .get(path)
                .await
                .is_err_and(|error| error.http_status == Some(404))
            {
                return;
            }
            tokio::time::sleep(session.timing.interval).await;
        }
    };
    tokio::time::timeout(budget, reads).await.map_err(|_| {
        recording_error(format!(
            "cleanup verification still found {id} or could not prove its absence"
        ))
    })
}

pub(super) async fn finish(session: &mut Session<'_>) -> Result<()> {
    if !session.baseline_checked {
        return Ok(());
    }
    let mut failures = Vec::new();
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
        if session.pending_imports.contains_key(id) {
            if let Err(error) = settle_import(session, id).await {
                failures.push(failure(id, error));
                continue;
            }
            session.pending_imports.remove(id);
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
    if let Err(error) = inventory::require_clear(session).await {
        failures.push(failure("marker audit", error));
    }
    if failures.is_empty()
        && session.pending_imports.is_empty()
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

async fn settle_import(session: &mut Session<'_>, id: &str) -> Result<()> {
    let unresolved = || {
        recording_error(format!(
            "pending import for {id} is unresolved; remove it by exact id after the import settles"
        ))
    };
    let expected = session
        .pending_imports
        .get(id)
        .copied()
        .flatten()
        .ok_or_else(unresolved)?;
    super::steps::settle(session, id, expected)
        .await
        .map(|_| ())
        .map_err(|_| unresolved())
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
    if !session.attempted_deletes.insert("/api/lists/index".into()) {
        return wait_deleted(session, "/api/lists/index", "value-list indices").await;
    }
    let (status, body) = session.t.delete_once_response("/api/lists/index").await?;
    if status != 200 {
        return Err(recording_error(format!(
            "index restore returned HTTP {status}"
        )));
    }
    session.evidence.response("index_delete", body);
    let (status, body) = session.t.get_response("/api/lists/index").await?;
    match status {
        404 => {
            session
                .evidence
                .http_response("index_restored", status, body);
            Ok(())
        }
        200..=299 => Err(recording_error("index restore did not return 404")),
        _ => Err(elasticctl_core::Error::from_response_body(
            status,
            &body.to_string(),
        )),
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
