use super::{
    Action, Clock, ContainerAction, Evidence, ListOutcome, ListPlan, Outcome, PhaseOrder,
    RemoteList, Sent, StoredValues, ValueSet, decode_remote_container, pack_imports, plan_list,
    require_bootstrapped, scan_references,
};
use super::{
    plan::{container_mismatches, stored_equal},
    read_back::{Expected, settle},
    reads::{find_cursor, malformed, read_unchanged_list, required_string, response_error},
};
use elasticctl_core::{Error, ErrorKind, Result, Transport, urlencode};
use serde_json::{Value, json};
use std::time::Duration;

pub async fn apply_plans<C: Clock>(
    t: &Transport,
    plans: &[ListPlan],
    clock: &C,
) -> Vec<ListOutcome> {
    let mut outcomes: Vec<_> = plans.iter().map(ListOutcome::not_reached).collect();
    if plans.is_empty() {
        return outcomes;
    }
    let checked = preflight(t, plans).await;
    match checked {
        Err((index, error)) => {
            outcomes[index] =
                pending(&plans[index]).unwrap_or_else(|_| ListOutcome::not_reached(&plans[index]));
            outcomes[index].finish(Outcome::Failed, Some(error));
        }
        Ok(checked) => {
            let mut last_export_end = None;
            for (index, plan) in checked.iter().enumerate() {
                outcomes[index] = apply_one(t, plan, clock, 1000, &mut last_export_end).await;
                if outcomes[index].outcome != Outcome::Applied {
                    break;
                }
            }
        }
    }
    outcomes
}

async fn preflight(
    t: &Transport,
    plans: &[ListPlan],
) -> std::result::Result<Vec<ListPlan>, (usize, Error)> {
    let mut validated = Vec::new();
    for (index, plan) in plans.iter().enumerate() {
        validated.push(
            plan_list(
                plan.local.clone(),
                plan.before.clone(),
                &plan.installed,
                &plan.desired,
            )
            .map_err(|e| (index, e))?,
        );
    }
    check_dependency_cone(&validated)?;
    require_bootstrapped(t).await.map_err(|e| (0, e))?;
    let mut reads = Vec::new();
    for (index, plan) in plans.iter().enumerate() {
        reads.push(
            read_unchanged_list(t, &plan.local.container.id, plan.before.as_ref())
                .await
                .map_err(|e| (index, e))?,
        );
    }
    let references = scan_references(t).await.map_err(|e| (0, e))?;
    let mut checked = Vec::new();
    for (index, (plan, read)) in plans.iter().zip(reads).enumerate() {
        let installed: Vec<_> = references
            .iter()
            .filter(|r| r.list_id == plan.local.container.id)
            .cloned()
            .collect();
        if !same_read(&plan.before, &read) || installed != plan.installed {
            return Err((
                index,
                Error::new(
                    ErrorKind::Conflict,
                    format!(
                        "value list {} or its installed references changed since preview; re-run",
                        plan.local.container.id
                    ),
                ),
            ));
        }
        checked.push(
            plan_list(plan.local.clone(), read, &installed, &plan.desired)
                .map_err(|e| (index, e))?,
        );
    }
    Ok(checked)
}

fn check_dependency_cone(plans: &[ListPlan]) -> std::result::Result<(), (usize, Error)> {
    let mut items = std::collections::BTreeMap::new();
    for (index, plan) in plans.iter().enumerate() {
        if plan.adds.is_empty() && plan.removes.is_empty() {
            continue;
        }
        for reference in &plan.installed {
            let lists = items
                .entry((&reference.container, &reference.item_id))
                .or_insert_with(std::collections::BTreeMap::new);
            lists.insert(&reference.list_id, index);
        }
    }
    for ((container, item_id), lists) in items {
        if lists.len() > 1 {
            let index = *lists.values().min().expect("multiple changed lists");
            return Err((
                index,
                Error::new(
                    ErrorKind::Conflict,
                    format!(
                        "{} ({}) item {} references lists whose values change together: {}; use separate runs",
                        container.list_id,
                        container.namespace_type,
                        item_id,
                        lists
                            .keys()
                            .map(|id| id.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                ),
            ));
        }
    }
    Ok(())
}

pub(super) fn same_read(a: &Option<RemoteList>, b: &Option<RemoteList>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.container.container.id == b.container.container.id
                && a.container.container.list_type == b.container.container.list_type
                && a.container.version == b.container.version
                && stored_equal(&a.stored, &b.stored)
        }
        _ => false,
    }
}

struct Request {
    action: Action,
    values: Vec<String>,
    body: String,
}
fn requests(plan: &ListPlan) -> Result<Vec<Request>> {
    let mut requests = Vec::new();
    match plan.container_action {
        ContainerAction::Create => requests.push(Request {
            action: Action::CreateValueList,
            values: Vec::new(),
            body: String::new(),
        }),
        ContainerAction::Update => requests.push(Request {
            action: Action::UpdateValueList,
            values: Vec::new(),
            body: String::new(),
        }),
        ContainerAction::None => {}
    }
    let adds = pack_imports(&plan.adds)?
        .into_iter()
        .map(|body| Request {
            action: Action::AddValues,
            values: body.split_terminator('\n').map(str::to_owned).collect(),
            body,
        })
        .collect::<Vec<_>>();
    let mut copies: Vec<_> = plan
        .before
        .as_ref()
        .map(|r| {
            r.stored
                .values
                .iter()
                .filter(|v| plan.removes.contains(*v))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    copies.sort();
    let removes = copies
        .into_iter()
        .map(|value| Request {
            action: Action::RemoveValues,
            values: vec![value],
            body: String::new(),
        })
        .collect::<Vec<_>>();
    match plan.order {
        PhaseOrder::AddsFirst => {
            requests.extend(adds);
            requests.extend(removes);
        }
        PhaseOrder::RemovesFirst => {
            requests.extend(removes);
            requests.extend(adds);
        }
    }
    Ok(requests)
}

fn pending(plan: &ListPlan) -> Result<ListOutcome> {
    let requests = requests(plan)?;
    let evidence = requests
        .iter()
        .map(|request| {
            let mut entry = Evidence::new(
                request.action,
                &plan.local.container.id,
                &plan.local.container.name,
            );
            entry.values = Some(request.values.clone());
            entry
        })
        .collect();
    Ok(ListOutcome {
        id: plan.local.container.id.clone(),
        outcome: Outcome::NotReached,
        evidence,
        error: None,
    })
}

pub(super) async fn apply_one<C: Clock>(
    t: &Transport,
    plan: &ListPlan,
    clock: &C,
    per_page: u32,
    last_export_end: &mut Option<Duration>,
) -> ListOutcome {
    let mut result = ListOutcome {
        id: plan.local.container.id.clone(),
        outcome: Outcome::NotReached,
        evidence: Vec::new(),
        error: None,
    };
    let mut requests = match requests(plan) {
        Ok(requests) => requests,
        Err(error) => {
            result.finish(Outcome::Failed, Some(error));
            return result;
        }
    };
    result = pending(plan).expect("requests already checked");
    let mut stored = plan
        .before
        .as_ref()
        .map(|r| r.stored.clone())
        .unwrap_or_default();
    let run = Execution {
        t,
        plan,
        clock,
        per_page,
        last_export_end,
    }
    .execute(&mut requests, &mut result.evidence, &mut stored)
    .await;
    match run {
        Ok(()) => result.finish(Outcome::Applied, None),
        Err(Stop::Failed(error)) => result.finish(Outcome::Failed, Some(error)),
        Err(Stop::Unknown(read)) => {
            result.evidence.push(*read);
            result.finish(
                Outcome::Unknown,
                Some(Error::new(
                    ErrorKind::Http,
                    "value-list outcome is unknown; wait, run diff, and review before retrying",
                )),
            );
        }
    }
    result
}

enum Stop {
    Failed(Error),
    Unknown(Box<Evidence>),
}
impl From<Error> for Stop {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

struct Execution<'a, C> {
    t: &'a Transport,
    plan: &'a ListPlan,
    clock: &'a C,
    per_page: u32,
    last_export_end: &'a mut Option<Duration>,
}

impl<C: Clock> Execution<'_, C> {
    async fn execute(
        &mut self,
        requests: &mut Vec<Request>,
        evidence: &mut Vec<Evidence>,
        stored: &mut StoredValues,
    ) -> std::result::Result<(), Stop> {
        let Self {
            t,
            plan,
            clock,
            per_page,
            last_export_end,
        } = self;
        let c = &plan.local.container;
        let mut index = 0;
        if plan.container_action != ContainerAction::None {
            let mut payload = json!({"id":c.id, "name":c.name, "description":c.description});
            if let Some(meta) = &c.meta {
                payload["meta"] = json!(meta);
            }
            let response = if plan.container_action == ContainerAction::Create {
                payload["type"] = json!(c.list_type);
                t.post_once_response("/api/lists", Some(&payload)).await
            } else {
                payload["_version"] = json!(
                    plan.before
                        .as_ref()
                        .ok_or_else(|| malformed("update lacks apply-time container"))?
                        .container
                        .version
                );
                t.patch_once_response("/api/lists", &payload).await
            };
            let sent = record(response, &mut evidence[0], false, |body| {
                let observed = decode_remote_container(body)?;
                if !container_mismatches(c, &observed.container).is_empty() {
                    return Err(malformed("container write response differs from plan"));
                }
                Ok(())
            })?;
            if sent == Sent::Uncertain {
                let read = settle(t, c, Expected::Container, *clock, last_export_end).await;
                if !read.verified {
                    return Err(Stop::Unknown(Box::new(read.evidence)));
                }
            }
            evidence[0].phase_verified = true;
            index = 1;
        }
        while index < requests.len() {
            let action = requests[index].action;
            let mut end = requests[index..]
                .iter()
                .position(|request| request.action != action)
                .map_or(requests.len(), |offset| index + offset);
            let expected: ValueSet = if action == Action::AddValues {
                stored.set().union(&plan.adds).cloned().collect()
            } else {
                stored.set().difference(&plan.removes).cloned().collect()
            };
            let items = if action == Action::RemoveValues {
                Some(remove_items(t, plan, stored, *per_page).await?)
            } else {
                None
            };
            if let Some(items) = &items {
                requests.splice(
                    index..end,
                    items.iter().map(|(_, value)| Request {
                        action: Action::RemoveValues,
                        values: vec![value.clone()],
                        body: String::new(),
                    }),
                );
                evidence.splice(
                    index..end,
                    items.iter().map(|(_, value)| {
                        let mut entry = Evidence::new(Action::RemoveValues, &c.id, &c.name);
                        entry.values = Some(vec![value.clone()]);
                        entry
                    }),
                );
                end = index + items.len();
            }
            for offset in index..end {
                let response = if let Some(items) = &items {
                    t.delete_once_response(&format!(
                        "/api/lists/items?id={}",
                        urlencode(&items[offset - index].0)
                    ))
                    .await
                } else {
                    t.post_multipart_once_named_response(
                        &format!("/api/lists/items/_import?list_id={}", urlencode(&c.id)),
                        &format!("{}.txt", plan.local.stem),
                        "text/plain",
                        &requests[offset].body,
                    )
                    .await
                };
                let sent = record(response, &mut evidence[offset], items.is_some(), |body| {
                    if items.is_some() {
                        required_string(body, "id")?;
                        required_string(body, "value")?;
                    } else {
                        decode_remote_container(body)?;
                    }
                    Ok(())
                })?;
                if sent == Sent::Uncertain {
                    break;
                }
            }
            let read = settle(t, c, Expected::Values(&expected), *clock, last_export_end).await;
            if !read.verified {
                return Err(Stop::Unknown(Box::new(read.evidence)));
            }
            *stored = read
                .stored
                .ok_or_else(|| malformed("verified values read has no stored values"))?;
            for entry in &mut evidence[index..end] {
                entry.phase_verified = true;
            }
            index = end;
        }
        Ok(())
    }
}

pub(super) fn record(
    response: Result<(u16, Value)>,
    evidence: &mut Evidence,
    item_delete: bool,
    decode: impl FnOnce(&Value) -> Result<()>,
) -> Result<Sent> {
    match response {
        Ok((status, body)) => {
            evidence.status = Some(status);
            if status >= 400 {
                evidence.sent = Some(Sent::Refused);
                if status == 404 && item_delete {
                    return Ok(Sent::Refused);
                }
                return Err(response_error(status, &body));
            }
            if decode(&body).is_err() {
                evidence.sent = Some(Sent::Uncertain);
                return Ok(Sent::Uncertain);
            }
            evidence.sent = Some(Sent::Accepted);
            Ok(Sent::Accepted)
        }
        Err(error)
            if error
                .http_status
                .is_some_and(|status| (400..500).contains(&status)) =>
        {
            evidence.status = error.http_status;
            evidence.sent = Some(Sent::Refused);
            if item_delete && error.http_status == Some(404) {
                return Ok(Sent::Refused);
            }
            Err(error)
        }
        Err(error) => {
            evidence.status = error.http_status;
            evidence.sent = Some(Sent::Uncertain);
            Ok(Sent::Uncertain)
        }
    }
}

async fn remove_items(
    t: &Transport,
    plan: &ListPlan,
    stored: &StoredValues,
    per_page: u32,
) -> Result<Vec<(String, String)>> {
    let path = format!(
        "/api/lists/items/_find?list_id={}",
        urlencode(&plan.local.container.id)
    );
    let mut seen = std::collections::BTreeSet::new();
    let mut items = Vec::new();
    for item in find_cursor(t, &path, per_page).await? {
        let id = required_string(&item, "id")?;
        let value = required_string(&item, "value")?;
        if required_string(&item, "list_id")? != plan.local.container.id
            || required_string(&item, "type")? != plan.local.container.list_type.to_string()
            || !seen.insert(id.to_owned())
        {
            return Err(malformed("invalid value-list item _find identity"));
        }
        items.push((id.to_owned(), value.to_owned()));
    }
    if !stored_equal(
        &StoredValues::new(items.iter().map(|(_, value)| value.clone()).collect()),
        stored,
    ) {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "value list {} item _find differs from the last export; re-run",
                plan.local.container.id
            ),
        ));
    }
    items.retain(|(_, value)| plan.removes.contains(value));
    items.sort_by(|a, b| (&a.1, &a.0).cmp(&(&b.1, &b.0)));
    Ok(items)
}
