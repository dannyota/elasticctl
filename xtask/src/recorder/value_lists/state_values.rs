use super::{CONTAIN, DASH, IP, LIST, RANGES, Session, cleanup, inventory, steps};
use crate::diagnostics::recording_error;
use elasticctl_core::{Result, urlencode};
use serde_json::{Value, json};

pub(super) async fn read(
    session: &mut Session<'_>,
    name: &'static str,
    path: &str,
    expected: u16,
) -> Result<Value> {
    let (status, body) = session
        .t
        .get_response(path)
        .await
        .map_err(|e| steps::step_error(name, expected, e))?;
    steps::require_status(name, status, expected)?;
    session
        .evidence
        .exchange(name, json!({"path": path}), body.clone());
    if status != 200 {
        session.evidence.fixtures.last_mut().unwrap().document["http_status"] = json!(status);
    }
    Ok(body)
}

pub(super) async fn export(
    session: &mut Session<'_>,
    list: &str,
    name: &'static str,
    expected: &[&str],
) -> Result<()> {
    let path = format!("/api/lists/items/_export?list_id={}", urlencode(list));
    let text = session
        .t
        .post_text(&path, None)
        .await
        .map_err(|e| steps::step_error(name, 200, e))?;
    let mut lines: Vec<_> = text.lines().filter(|s| !s.is_empty()).collect();
    lines.sort_unstable();
    let mut want = expected.to_vec();
    want.sort_unstable();
    if lines != want {
        return Err(recording_error(format!("{name}: export multiset differs")));
    }
    session.evidence.response(name, json!(text));
    Ok(())
}

pub(super) async fn page(
    session: &mut Session<'_>,
    list: &str,
    name: &'static str,
    expected: &[&str],
) -> Result<Value> {
    let body = read(
        session,
        name,
        &format!("/api/lists/items/_find?list_id={list}&page=1&per_page=1000"),
        200,
    )
    .await?;
    let mut values: Vec<_> = inventory::data(&body)?
        .iter()
        .map(|row| row["value"].as_str().unwrap_or(""))
        .collect();
    values.sort_unstable();
    let mut want = expected.to_vec();
    want.sort_unstable();
    if inventory::total(&body)? != expected.len() as u64 || values != want {
        return Err(recording_error(format!("{name}: item multiset differs")));
    }
    Ok(body)
}

pub(super) async fn add(
    session: &mut Session<'_>,
    list: &str,
    suffix: &str,
    value: &str,
    expected: u64,
) -> Result<()> {
    let id = format!("{list}-item-{suffix}");
    session.items.push(id.clone());
    session.pending_imports.insert(list.into(), Some(expected));
    let result = session
        .t
        .post_once(
            "/api/lists/items",
            Some(&json!({"id": id, "list_id": list, "value": value})),
        )
        .await;
    session.clear_refused_import(list, result.as_ref().err().and_then(|e| e.http_status));
    session
        .evidence
        .observe(&result.map_err(|e| steps::step_error(suffix, 200, e))?);
    steps::settle(session, list, expected)
        .await
        .map_err(|e| steps::step_error(suffix, 200, e))?;
    session.pending_imports.remove(list);
    Ok(())
}

pub(super) async fn remove_value(
    session: &mut Session<'_>,
    list: &str,
    value: &str,
    expected: u64,
) -> Result<()> {
    let body = session
        .get(&format!(
            "/api/lists/items/_find?list_id={list}&page=1&per_page=1000"
        ))
        .await?;
    let item = inventory::data(&body)?
        .iter()
        .find(|r| r["value"] == value)
        .ok_or_else(|| {
            recording_error(format!("remove value: {list} has no matching stored item"))
        })?;
    let id = item["id"]
        .as_str()
        .ok_or_else(|| recording_error("remove value: stored item id missing"))?;
    let path = format!("/api/lists/items?id={}", urlencode(id));
    if !session.attempted_deletes.insert(path.clone()) {
        return Err(recording_error("remove value: delete already attempted"));
    }
    session.pending_imports.insert(list.into(), Some(expected));
    let result = session.t.delete_once(&path).await;
    session.clear_refused_import(list, result.as_ref().err().and_then(|e| e.http_status));
    session
        .evidence
        .observe(&result.map_err(|e| steps::step_error("remove_value", 200, e))?);
    steps::settle(session, list, expected)
        .await
        .map_err(|e| steps::step_error("remove_value", 200, e))?;
    session.pending_imports.remove(list);
    Ok(())
}

pub(super) async fn delete_list(session: &mut Session<'_>, id: &'static str) -> Result<()> {
    if session.pending_imports.contains_key(id)
        || session.exception_item
        || session
            .objects
            .values()
            .any(|o| matches!(o, super::objects::Object::Item { .. }))
    {
        return Err(recording_error(format!(
            "delete list: {id} has pending writes or references"
        )));
    }
    cleanup::delete_owned(session, &format!("/api/lists?id={id}"), id, false, false).await?;
    session.lists.retain(|owned| *owned != id);
    session.pending_creates.remove(id);
    Ok(())
}

pub(super) async fn prepare(session: &mut Session<'_>) -> Result<()> {
    steps::create_list(session, LIST, "state_container_v").await?;
    for (i, value) in ["10.0.0.5", "10.0.0.5", "10.0.0.6/32", "10.0.0.7/32"]
        .iter()
        .enumerate()
    {
        add(session, LIST, &format!("state-{i}"), value, i as u64 + 1).await?;
    }
    remove_value(session, CONTAIN, "10.0.0.6/32", 1).await?;
    add(session, CONTAIN, "state", "10.0.0.5/32", 2).await?;
    add(
        session,
        RANGES,
        "lowercase",
        "2001:db8:0:0::1-2001:db8:0:0::1",
        5,
    )
    .await?;
    export(
        session,
        RANGES,
        "export_s_two_spellings",
        &[
            "2001:DB8:0:0::1-2001:DB8:0:0::1",
            "10.0.0.7/24",
            "10.0.0.1-2001:db8::1",
            "2001:db8::/32",
            "2001:db8:0:0::1-2001:db8:0:0::1",
        ],
    )
    .await?;
    steps::create_typed_list(session, IP, "ip", "state_container_p").await?;
    add(session, IP, "upper", "2001:DB8::1", 1).await?;
    add(session, IP, "lower", "2001:db8::1", 2).await?;
    read(
        session,
        "container_p_ip",
        &format!("/api/lists?id={IP}"),
        200,
    )
    .await?;
    export(
        session,
        IP,
        "export_p_spellings",
        &["2001:DB8::1", "2001:db8::1"],
    )
    .await
}

pub(super) async fn dash(session: &mut Session<'_>) -> Result<()> {
    steps::create_list(session, DASH, "dash_create").await?;
    let values: Vec<_> = (1..=199)
        .map(|n| format!("10.0.0.{n}-10.0.0.{n}"))
        .collect();
    let content = format!("{}\n", values.join("\n"));
    session.pending_imports.insert(DASH.into(), Some(199));
    let result = session
        .t
        .post_multipart_once_named(
            &format!("/api/lists/items/_import?list_id={DASH}&refresh=wait_for"),
            "elasticctl-live-vl.txt",
            "text/plain",
            &content,
        )
        .await;
    session.clear_refused_import(DASH, result.as_ref().err().and_then(|e| e.http_status));
    session
        .evidence
        .observe(&result.map_err(|e| steps::step_error("dash_import", 200, e))?);
    steps::settle(session, DASH, 199)
        .await
        .map_err(|e| steps::step_error("dash_import", 200, e))?;
    session.pending_imports.remove(DASH);
    add(session, DASH, "duplicate", "10.0.0.1-10.0.0.1", 200).await?;
    let mut expected: Vec<_> = values.iter().map(String::as_str).collect();
    expected.push("10.0.0.1-10.0.0.1");
    export(session, DASH, "export_dash_200", &expected).await?;
    add(session, DASH, "last", "10.0.0.200-10.0.0.200", 201).await?;
    expected.push("10.0.0.200-10.0.0.200");
    export(session, DASH, "export_dash_201", &expected).await?;
    delete_list(session, DASH).await
}
