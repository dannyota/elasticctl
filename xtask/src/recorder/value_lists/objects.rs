use super::{MARKER, Session, cleanup, definite_refusal};
use crate::diagnostics::recording_error;
use elasticctl_core::{Result, urlencode};
use serde_json::{Value, json};

#[derive(Clone)]
pub(super) enum Object {
    Rule,
    Container {
        namespace: &'static str,
    },
    Item {
        list: &'static str,
        namespace: &'static str,
    },
}

impl Object {
    pub(super) fn path(&self, id: &str) -> String {
        let id = urlencode(id);
        match self {
            Self::Rule => format!("/api/detection_engine/rules?rule_id={id}"),
            Self::Container { namespace } => {
                format!("/api/exception_lists?list_id={id}&namespace_type={namespace}")
            }
            Self::Item { namespace, .. } => {
                format!("/api/exception_lists/items?item_id={id}&namespace_type={namespace}")
            }
        }
    }

    pub(super) fn owns(&self, session: &Session<'_>, body: &Value, id: &str) -> bool {
        let identity = match self {
            Self::Rule => body["rule_id"] == id && body["enabled"] == false,
            Self::Container { namespace } => {
                body["list_id"] == id && body["namespace_type"] == *namespace
            }
            Self::Item { list, namespace } => {
                body["item_id"] == id
                    && body["list_id"] == *list
                    && body["namespace_type"] == *namespace
            }
        };
        identity
            && body["tags"].as_array().is_some_and(|tags| {
                tags.iter().any(|t| t == MARKER) && tags.iter().any(|t| t == &session.nonce)
            })
    }
}

pub(super) async fn create(
    session: &mut Session<'_>,
    id: &str,
    object: Object,
    request: Value,
    name: Option<&'static str>,
) -> Result<Value> {
    if !id.starts_with(super::PREFIX) || !object.owns(session, &request, id) {
        return Err(recording_error(format!(
            "{id}: refusing unowned or enabled object create"
        )));
    }
    let path = object.path(id);
    let endpoint = path.split('?').next().unwrap();
    session.objects.insert(id.into(), object.clone());
    session.pending_creates.insert(id.into());
    session.attempted_deletes.remove(&path);
    let result = session.t.post_once(endpoint, Some(&request)).await;
    if result
        .as_ref()
        .is_err_and(|e| definite_refusal(e.http_status))
    {
        session.pending_creates.remove(id);
    }
    if result.as_ref().is_err_and(|e| e.http_status == Some(409)) {
        session.objects.remove(id);
    }
    let body = result.map_err(|e| super::steps::step_error(name.unwrap_or(id), 200, e))?;
    if let Some(name) = name {
        session.evidence.exchange(name, request, body);
    } else {
        session.evidence.observe(&body);
    }
    let current = session
        .get(&path)
        .await
        .map_err(|e| super::steps::step_error(id, 200, e))?;
    if !object.owns(session, &current, id) {
        return Err(recording_error(format!(
            "{id}: created object does not prove session ownership"
        )));
    }
    session.pending_creates.remove(id);
    Ok(current)
}

pub(super) async fn delete(session: &mut Session<'_>, id: &str) -> Result<()> {
    let Some(object) = session.objects.get(id).cloned() else {
        return Ok(());
    };
    cleanup::delete_owned(session, &object.path(id), id, false, false)
        .await
        .map_err(|e| {
            if e.kind == elasticctl_core::ErrorKind::Error {
                e
            } else {
                super::steps::step_error(id, 404, e)
            }
        })?;
    session.objects.remove(id);
    session.pending_creates.remove(id);
    Ok(())
}

pub(super) async fn clear_items(session: &mut Session<'_>) -> Result<()> {
    let ids: Vec<_> = session
        .objects
        .iter()
        .filter(|(_, o)| matches!(o, Object::Item { .. }))
        .map(|(id, _)| id.clone())
        .collect();
    for id in ids {
        delete(session, &id).await?;
    }
    Ok(())
}

pub(super) async fn item(
    session: &mut Session<'_>,
    suffix: &str,
    list: &'static str,
    namespace: &'static str,
    entries: Value,
) -> Result<()> {
    for entry in entries
        .as_array()
        .ok_or_else(|| recording_error("exception item entries are invalid"))?
    {
        let id = entry["list"]["id"]
            .as_str()
            .ok_or_else(|| recording_error("exception item list id is missing"))?;
        let body = session
            .get(&format!(
                "/api/lists/items/_find?list_id={}&page=1&per_page=1000",
                urlencode(id)
            ))
            .await?;
        let count = super::inventory::total(&body)?;
        if count == 0 || super::inventory::data(&body)?.len() as u64 != count {
            return Err(recording_error(format!(
                "{suffix}: referenced list {id} is empty or incomplete"
            )));
        }
        let dashes = super::inventory::data(&body)?
            .iter()
            .filter(|row| row["value"].as_str().is_some_and(|s| s.contains('-')))
            .count();
        if dashes > 200 {
            return Err(recording_error(format!(
                "{suffix}: referenced list {id} exceeds 200 dash entries"
            )));
        }
        let container = session
            .get(&format!("/api/lists?id={}", urlencode(id)))
            .await?;
        if !cleanup::owns(session, &container, id, false, false)
            || container["type"] != entry["list"]["type"]
        {
            return Err(recording_error(format!(
                "{suffix}: referenced list {id} ownership or type changed"
            )));
        }
    }
    let id = format!("elasticctl-live-vl-{suffix}");
    let request = json!({"item_id": id, "list_id": list, "name": id, "description": MARKER,
        "type": "simple", "namespace_type": namespace, "tags": [MARKER, session.nonce], "entries": entries});
    create(
        session,
        &id,
        Object::Item { list, namespace },
        request,
        None,
    )
    .await?;
    Ok(())
}

pub(super) fn entry(id: &str, kind: &str, field: &str, operator: &str) -> Value {
    json!({"type": "list", "list": {"id": id, "type": kind}, "field": field, "operator": operator})
}
