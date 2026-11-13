use super::*;

pub(super) fn definite_refusal(status: Option<u16>) -> bool {
    status.is_some_and(|s| (400..500).contains(&s) && s != 408)
}

pub(super) async fn baseline(t: &Transport, lease: &mut Lease) -> StepResult {
    let before = checked_step(api::bootstrap_state(t).await)?;
    require(before.ready() || (!before.list_index && !before.list_item_index))?;
    lease.before = Some(before);
    audit_lists(t, lease).await?;
    cleanup::audit_items(t, lease).await
}

pub(super) async fn audit_lists(t: &Transport, lease: &Lease) -> StepResult {
    match api::find_containers(t, None, 100).await {
        Ok(lists) => require(
            lists
                .iter()
                .all(|l| !l.container.id.starts_with(LIVE_PREFIX)),
        ),
        Err(e) if e.http_status == Some(404) && lease.before.is_some_and(|b| !b.ready()) => Ok(()),
        Err(_) => Err(StepError::Failed),
    }
}

pub(super) async fn initialize(t: &Transport, lease: &mut Lease) -> StepResult {
    lease.check_interrupt()?;
    let before = lease.before.ok_or(StepError::Failed)?;
    if before.ready() {
        return Ok(());
    }
    lease.init_pending = true;
    let result = api::apply_init(t).await;
    lease.restore_streams = result
        .as_ref()
        .is_ok_and(|o| *o == api::InitOutcome::Bootstrapped);
    if result.is_ok()
        || result
            .as_ref()
            .is_err_and(|e| definite_refusal(e.http_status))
    {
        lease.init_pending = false;
    }
    checked_step(result).map(|_| ())
}

pub(super) async fn create(
    t: &Transport,
    lease: &mut Lease,
    kind: Kind,
    id: String,
    request: Value,
) -> StepResult<Value> {
    lease.check_interrupt()?;
    require(id.starts_with(PREFIX))?;
    let mut object = Object::new(kind, id.clone());
    require(object.owns(&request, &lease.nonce))?;
    object.pending = true;
    lease.objects.push(object);
    let result = t.post_once(kind.endpoint(), Some(&request)).await;
    let index = lease.objects.len() - 1;
    if result
        .as_ref()
        .is_err_and(|e| definite_refusal(e.http_status))
    {
        lease.objects[index].pending = false;
    }
    if result.as_ref().is_err_and(|e| e.http_status == Some(409)) {
        lease.objects.remove(index);
    }
    let response = checked_step(result)?;
    require(lease.objects[index].owns(&response, &lease.nonce))?;
    let observed = checked_step(t.get(&lease.objects[index].path()).await)?;
    require(lease.objects[index].owns(&observed, &lease.nonce))?;
    lease.objects[index].pending = false;
    Ok(response)
}

async fn list(
    t: &Transport,
    lease: &mut Lease,
    id: String,
    kind: api::ValueListType,
    values: Vec<String>,
) -> StepResult {
    create(
        t,
        lease,
        Kind::List,
        id.clone(),
        json!({
            "id": id, "name": id, "type": kind, "description": LIVE_TAG,
            "meta": {"marker": LIVE_TAG, "recorder_nonce": lease.nonce}
        }),
    )
    .await?;
    lease.check_interrupt()?;
    let object = lease.objects.last_mut().ok_or(StepError::Failed)?;
    object.import = Some((kind.clone(), values.clone()));
    let text = values.iter().map(|v| format!("{v}\n")).collect::<String>();
    let result = t
        .post_multipart_once_named(
            &format!("/api/lists/items/_import?list_id={}", urlencode(&id)),
            "values.txt",
            "text/plain",
            &text,
        )
        .await;
    if result
        .as_ref()
        .is_err_and(|e| definite_refusal(e.http_status))
    {
        lease.objects.last_mut().ok_or(StepError::Failed)?.import = None;
    }
    checked_step(result)?;
    cleanup::settle_import(
        t,
        lease.objects.last_mut().ok_or(StepError::Failed)?,
        lease.budget,
        lease.interval,
    )
    .await?;
    let remote = checked_step(api::read_list(t, &id).await)?.ok_or(StepError::Failed)?;
    require(
        remote.container.container.list_type == kind
            && !remote.stored.values.is_empty()
            && remote.stored.values.iter().collect::<BTreeSet<_>>() == values.iter().collect(),
    )
}

pub(super) async fn index(t: &Transport, lease: &mut Lease, id: String) -> StepResult {
    lease.check_interrupt()?;
    lease.index = Some(Index {
        id: id.clone(),
        pending: true,
        delete_sent: false,
        pending_event: None,
    });
    let result = t.put_absolute_es_once(&format!("/{id}"), &json!({"mappings": {
        "_meta": {"marker": LIVE_TAG, "nonce": lease.nonce},
        "properties": {"@timestamp":{"type":"date"}, "source.ip":{"type":"ip"}, "event.action":{"type":"keyword"}, "event.code":{"type":"keyword"}}
    }})).await;
    if result
        .as_ref()
        .is_err_and(|e| definite_refusal(e.http_status))
    {
        lease.index = None;
    }
    checked_step(result)?;
    lease.index.as_mut().ok_or(StepError::Failed)?.pending = false;
    for (number, ip, action) in [
        (1, "192.0.2.5", "stay"),
        (2, "198.51.100.5", "stay"),
        (3, "203.0.113.1", "allow"),
        (4, "203.0.113.2", "block"),
        (5, "203.0.113.3", "stay"),
        (6, "10.0.0.5", "stay"),
    ] {
        lease.check_interrupt()?;
        let event_id = format!("{id}-{number}");
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StepError::Failed)?
            .as_millis() as u64;
        let event = json!({"@timestamp":timestamp, "source":{"ip":ip}, "event":{"action":action,"code":number.to_string()}});
        write_event(t, lease, &id, event_id, event).await?;
    }
    Ok(())
}

pub(super) async fn write_event(
    t: &Transport,
    lease: &mut Lease,
    id: &str,
    event_id: String,
    event: Value,
) -> StepResult {
    lease.check_interrupt()?;
    require(id.starts_with(PREFIX) && event_id.starts_with(PREFIX))?;
    require(lease.index.as_ref().is_some_and(|index| index.id == id))?;
    lease.index.as_mut().ok_or(StepError::Failed)?.pending_event =
        Some((event_id.clone(), event.clone()));
    let result = t
        .put_absolute_es_once(&format!("/{id}/_doc/{event_id}?refresh=true"), &event)
        .await;
    if result
        .as_ref()
        .is_err_and(|e| definite_refusal(e.http_status))
    {
        lease.index.as_mut().ok_or(StepError::Failed)?.pending_event = None;
    }
    checked_step(result)?;
    lease.index.as_mut().ok_or(StepError::Failed)?.pending_event = None;
    Ok(())
}

pub(super) async fn objects(t: &Transport, lease: &mut Lease) -> StepResult {
    let base = format!("{PREFIX}{}", lease.nonce);
    let index_id = format!("{base}-events");
    index(t, lease, index_id.clone()).await?;
    let ip = format!("{base}-ip");
    let keyword = format!("{base}-keyword");
    list(
        t,
        lease,
        ip.clone(),
        api::ValueListType::IpRange,
        vec!["10.0.0.0/8".into(), "192.0.2.0/24".into()],
    )
    .await?;
    list(
        t,
        lease,
        keyword.clone(),
        api::ValueListType::Keyword,
        vec!["allow".into(), "stay".into()],
    )
    .await?;
    let container = format!("{base}-exceptions");
    let exception = create(
        t,
        lease,
        Kind::Exception,
        container.clone(),
        json!({
            "list_id":container, "name":container, "description":LIVE_TAG,
            "type":"detection", "namespace_type":"single", "tags":[LIVE_TAG, lease.nonce]
        }),
    )
    .await?;
    for (suffix, list_id, kind, field, operator) in [
        ("included", ip, "ip_range", "source.ip", "included"),
        ("excluded", keyword, "keyword", "event.action", "excluded"),
    ] {
        let item = format!("{base}-{suffix}");
        create(t, lease, Kind::Item, item.clone(), json!({
            "item_id":item, "list_id":container, "name":item, "description":LIVE_TAG,
            "type":"simple", "namespace_type":"single", "tags":[LIVE_TAG, lease.nonce],
            "entries":[{"type":"list", "list":{"id":list_id,"type":kind}, "field":field,"operator":operator}]
        })).await?;
    }
    let rule_id = format!("{base}-rule");
    let mut rule: Value = serde_json::from_str(&query_rule(&rule_id, &index_id, "*:*", None))
        .map_err(|_| StepError::Failed)?;
    rule["tags"] = json!([LIVE_TAG, lease.nonce]);
    rule["exceptions_list"] = json!([{"id":exception["id"],"list_id":container,"type":"detection","namespace_type":"single"}]);
    create(t, lease, Kind::Rule, rule_id, rule).await?;
    Ok(())
}
