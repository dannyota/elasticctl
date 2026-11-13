use super::{
    Action, Evidence, InstalledReference, ListOutcome, Outcome, RemoteList, Sent, bootstrap_state,
    decode_remote_container, read_container, read_list, require_bootstrapped, scan_references,
};
use super::{
    apply::{record, same_read},
    reads::{read_unchanged_list, required_string, response_error},
};
use crate::model::ListKey;
use elasticctl_core::{Error, ErrorKind, Result, Transport, urlencode};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InitOutcome {
    AlreadyBootstrapped,
    Bootstrapped,
}

pub async fn apply_init(t: &Transport) -> Result<InitOutcome> {
    if bootstrap_state(t).await?.ready() {
        return Ok(InitOutcome::AlreadyBootstrapped);
    }
    let (status, body) = t
        .post_once_response(
            "/api/security_solution/initialize",
            Some(&json!({"flows": ["create-list-indices"]})),
        )
        .await?;
    if status >= 400 {
        return Err(response_error(status, &body));
    }
    let flow = body
        .pointer("/flows/create-list-indices/status")
        .and_then(Value::as_str);
    if flow != Some("ready") {
        return Err(Error::with_status(
            ErrorKind::Http,
            status,
            format!(
                "create-list-indices flow status is {}; expected ready",
                flow.unwrap_or("unreadable")
            ),
        ));
    }
    if !bootstrap_state(t).await?.ready() {
        return Err(Error::new(
            ErrorKind::Http,
            "create-list-indices flow is ready but both list streams do not exist",
        ));
    }
    Ok(InitOutcome::Bootstrapped)
}

#[derive(Clone, Debug, Serialize)]
pub struct DeletePlan {
    pub before: Vec<RemoteList>,
    pub installed: Vec<InstalledReference>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeleteReference {
    pub container: ListKey,
    pub item_id: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeleteOutcome {
    pub result: ListOutcome,
    pub references: Vec<DeleteReference>,
}

pub async fn plan_delete(t: &Transport, ids: &[String]) -> Result<DeletePlan> {
    require_bootstrapped(t).await?;
    let ids: std::collections::BTreeSet<_> = ids.iter().collect();
    let mut before = Vec::new();
    for id in ids {
        let list = read_list(t, id)
            .await?
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("value list {id} not found")))?;
        before.push(list);
    }
    let installed = scan_references(t).await?;
    Ok(DeletePlan { before, installed })
}

pub async fn apply_delete(t: &Transport, plan: &DeletePlan) -> Vec<DeleteOutcome> {
    let mut outcomes: Vec<_> = plan
        .before
        .iter()
        .map(|before| {
            let c = &before.container.container;
            let mut entry = Evidence::new(Action::NotReached, &c.id, &c.name);
            entry.values = None;
            entry.planned_adds = Some(0);
            entry.planned_removes = Some(before.stored.set().len());
            DeleteOutcome {
                result: ListOutcome {
                    id: c.id.clone(),
                    outcome: Outcome::NotReached,
                    evidence: vec![entry],
                    error: None,
                },
                references: Vec::new(),
            }
        })
        .collect();
    if outcomes.is_empty() {
        return outcomes;
    }
    if let Err((index, error)) = delete_preflight(t, plan).await {
        outcomes[index].result.finish(Outcome::Failed, Some(error));
        return outcomes;
    }
    for (index, before) in plan.before.iter().enumerate() {
        outcomes[index] = delete_one(t, before).await;
        if outcomes[index].result.outcome != Outcome::Applied {
            break;
        }
    }
    outcomes
}

async fn delete_preflight(
    t: &Transport,
    plan: &DeletePlan,
) -> std::result::Result<(), (usize, Error)> {
    require_bootstrapped(t).await.map_err(|e| (0, e))?;
    for (index, before) in plan.before.iter().enumerate() {
        let read = read_unchanged_list(t, &before.container.container.id, Some(before))
            .await
            .map_err(|e| (index, e))?;
        if !same_read(&Some(before.clone()), &read) {
            return Err((
                index,
                Error::new(
                    ErrorKind::Conflict,
                    "value list changed since delete preview; re-run",
                ),
            ));
        }
    }
    let references = scan_references(t).await.map_err(|e| (0, e))?;
    let selected: std::collections::BTreeSet<_> = plan
        .before
        .iter()
        .map(|r| &r.container.container.id)
        .collect();
    let relevant = |refs: &[InstalledReference]| {
        refs.iter()
            .filter(|r| selected.contains(&r.list_id))
            .cloned()
            .collect::<Vec<_>>()
    };
    if relevant(&plan.installed) != relevant(&references) {
        return Err((
            0,
            Error::new(
                ErrorKind::Conflict,
                "installed references changed since delete preview; re-run",
            ),
        ));
    }
    Ok(())
}

pub(super) async fn delete_one(t: &Transport, before: &RemoteList) -> DeleteOutcome {
    let c = &before.container.container;
    let mut entry = Evidence::new(Action::DeleteValueList, &c.id, &c.name);
    let response = t
        .delete_once_response(&format!("/api/lists?id={}", urlencode(&c.id)))
        .await;
    let references = match &response {
        Ok((409, body)) => delete_references(body),
        _ => Vec::new(),
    };
    let sent = record(response, &mut entry, false, |body| {
        decode_remote_container(body)?;
        Ok(())
    });
    let mut result = ListOutcome {
        id: c.id.clone(),
        outcome: Outcome::NotReached,
        evidence: vec![entry],
        error: None,
    };
    match sent {
        Err(mut error) => {
            for reference in &references {
                error.message.push_str(&format!(
                    "; {} ({}) item {}",
                    reference.container.list_id,
                    reference.container.namespace_type,
                    reference.item_id
                ));
            }
            result.finish(Outcome::Failed, Some(error));
        }
        Ok(Sent::Uncertain) => {
            let mut read = Evidence::new(Action::ReadBack, &c.id, &c.name);
            read.of = Some(super::ReadOf::Container);
            read.values = None;
            read.sent = None;
            match read_container(t, &c.id).await {
                Ok(None) => {
                    result.evidence[0].phase_verified = true;
                    result.finish(Outcome::Applied, None);
                }
                observed => {
                    read.observed = Some(observed.is_ok());
                    match observed {
                        Ok(Some(_)) => read.mismatched = Some(vec!["id".into()]),
                        Err(error) => read.read_error = Some(error.into()),
                        Ok(None) => unreachable!(),
                    }
                    result.evidence.push(read);
                    result.finish(
                        Outcome::Unknown,
                        Some(Error::new(
                            ErrorKind::Http,
                            "value-list delete outcome is unknown",
                        )),
                    );
                }
            }
        }
        Ok(_) => {
            result.evidence[0].phase_verified = true;
            result.finish(Outcome::Applied, None);
        }
    }
    DeleteOutcome { result, references }
}

fn delete_references(body: &Value) -> Vec<DeleteReference> {
    body.pointer("/message/error/references")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|reference| {
            let item = reference.get("exception_item")?;
            let decode = || -> Result<DeleteReference> {
                Ok(DeleteReference {
                    container: ListKey {
                        list_id: required_string(item, "list_id")?.into(),
                        namespace_type: required_string(item, "namespace_type")?.into(),
                    },
                    item_id: required_string(item, "item_id")?.into(),
                })
            };
            decode().ok()
        })
        .collect()
}
