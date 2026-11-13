use super::*;

async fn wait<T>(
    budget: Duration,
    interval: Duration,
    mut read: impl AsyncFnMut() -> StepResult<T>,
) -> StepResult<T> {
    checked_timeout(budget, async {
        loop {
            if let Ok(value) = read().await {
                return Ok(value);
            }
            tokio::time::sleep(interval).await;
        }
    })
    .await
}

async fn checked_timeout<T>(
    budget: Duration,
    future: impl std::future::Future<Output = StepResult<T>>,
) -> StepResult<T> {
    tokio::time::timeout(budget, future)
        .await
        .map_err(|_| StepError::Failed)?
}

async fn absent(t: &Transport, path: &str, budget: Duration, interval: Duration) -> StepResult {
    wait(budget, interval, async || {
        let (status, _) = checked_step(t.get_response(path).await)?;
        require(status == 404)
    })
    .await
}

pub(super) async fn settle_import(
    t: &Transport,
    object: &mut Object,
    budget: Duration,
    interval: Duration,
) -> StepResult {
    if let Some((kind, values)) = &object.import {
        wait(budget, interval, async || {
            let stored = checked_step(api::export_values(t, &object.id, kind).await)?;
            require(
                stored.values.len() == values.len()
                    && stored.values.iter().collect::<BTreeSet<_>>() == values.iter().collect(),
            )
        })
        .await?;
        object.import = None;
    }
    Ok(())
}

async fn delete(
    t: &Transport,
    object: &mut Object,
    nonce: &str,
    budget: Duration,
    interval: Duration,
) -> StepResult {
    require(object.id.starts_with(PREFIX))?;
    let path = object.path();
    if object.delete_sent {
        return absent(t, &path, budget, interval).await;
    }
    let read = async || {
        let (status, body) = checked_step(t.get_response(&path).await)?;
        if status == 404 && !object.pending {
            return Ok(None);
        }
        require(status == 200 && object.owns(&body, nonce))?;
        Ok(Some(body))
    };
    let found = if object.pending {
        wait(budget, interval, read).await?
    } else {
        read().await?
    };
    if found.is_none() {
        require(object.import.is_none())?;
        return Ok(());
    }
    object.pending = false;
    settle_import(t, object, budget, interval).await?;
    object.delete_sent = true;
    let _ = t.delete_once_response(&path).await;
    absent(t, &path, budget, interval).await
}

pub(super) async fn audit_items(t: &Transport, lease: &Lease) -> StepResult {
    require(t.has_es_url())?;
    let path = format!(
        "/.items-{}/_search?size=100&track_total_hits=true&q={}",
        urlencode(t.space()),
        urlencode(&format!("list_id:{PREFIX}*"))
    );
    let result = t.get_absolute_es(&path).await;
    if result.as_ref().is_err_and(|e| e.http_status == Some(404))
        && lease.before.is_some_and(|b| !b.ready())
    {
        return Ok(());
    }
    let body = checked_step(result)?;
    require(
        body["timed_out"] == false
            && body["_shards"]["failed"] == 0
            && body["hits"]["total"]["relation"] == "eq"
            && body["hits"]["total"]["value"] == 0
            && body["hits"]["hits"].as_array().is_some_and(Vec::is_empty),
    )
}

async fn restore(t: &Transport, lease: &mut Lease) -> StepResult {
    if !lease.restore_streams {
        return Ok(());
    }
    if lease.stream_delete_sent {
        return absent(t, "/api/lists/index", lease.budget, lease.interval).await;
    }
    let state = checked_step(api::bootstrap_state(t).await)?;
    if !state.list_index && !state.list_item_index {
        return Ok(());
    }
    require(state.ready())?;
    let body = checked_step(t.get("/api/lists/_find?per_page=1").await)?;
    let total = body["total"].as_u64().ok_or(StepError::Failed)?;
    if total != 0 {
        return Ok(());
    }
    require(body["data"].as_array().is_some_and(Vec::is_empty))?;
    lease.stream_delete_sent = true;
    let _ = t.delete_once_response("/api/lists/index").await;
    absent(t, "/api/lists/index", lease.budget, lease.interval).await
}

async fn index(t: &Transport, lease: &mut Lease) -> StepResult {
    let Some(index) = lease.index.as_mut() else {
        return Ok(());
    };
    require(index.id.starts_with(PREFIX))?;
    let path = format!("/{}", index.id);
    if !index.delete_sent {
        let read = async || match t.get_absolute_es(&format!("{path}/_mapping")).await {
            Err(e) if e.http_status == Some(404) && !index.pending => Ok(false),
            result => {
                let body = checked_step(result)?;
                require(
                    body[&index.id]["mappings"]["_meta"]
                        == json!({"marker":LIVE_TAG,"nonce":lease.nonce}),
                )?;
                Ok(true)
            }
        };
        let found = if index.pending {
            wait(lease.budget, lease.interval, read).await?
        } else {
            read().await?
        };
        if !found {
            require(index.pending_event.is_none())?;
            lease.index = None;
            return Ok(());
        }
        if let Some((id, event)) = &index.pending_event {
            wait(lease.budget, lease.interval, async || {
                let body = checked_step(t.get_absolute_es(&format!("{path}/_doc/{id}")).await)?;
                require(body["_source"] == *event)
            })
            .await?;
            index.pending_event = None;
        }
    }
    delete_index(t, index, lease.budget, lease.interval).await?;
    lease.index = None;
    Ok(())
}

pub(super) async fn delete_index(
    t: &Transport,
    index: &mut Index,
    budget: Duration,
    interval: Duration,
) -> StepResult {
    require(index.id.starts_with(PREFIX) && index.pending_event.is_none())?;
    let path = format!("/{}", index.id);
    if !index.delete_sent {
        index.delete_sent = true;
        let _ = t.delete_absolute_es_once(&path).await;
    }
    wait(budget, interval, async || {
        require(
            t.get_absolute_es(&path)
                .await
                .is_err_and(|e| e.http_status == Some(404)),
        )
    })
    .await
}

pub(super) async fn finish(t: &Transport, lease: &mut Lease) -> StepResult {
    let mut failed = lease.init_pending || lease.state_push_pending;
    if lease.init_pending {
        eprintln!("value-list init ownership is unresolved; refusing stream deletion");
    }
    if lease.state_push_pending {
        eprintln!("state push has unresolved writes; refusing list and stream deletion");
    }
    lease.objects.sort_by_key(|o| o.kind);
    for kind in [Kind::Rule, Kind::Item, Kind::Exception, Kind::List] {
        if kind == Kind::List && lease.state_push_pending {
            break;
        }
        if lease.objects.iter().any(|o| o.kind < kind) {
            failed = true;
            break;
        }
        let mut remaining = Vec::new();
        for mut object in std::mem::take(&mut lease.objects) {
            if object.kind != kind
                || delete(t, &mut object, &lease.nonce, lease.budget, lease.interval)
                    .await
                    .is_err()
            {
                if object.kind == kind {
                    failed = true;
                }
                remaining.push(object);
            }
        }
        lease.objects = remaining;
    }
    if index(t, lease).await.is_err() {
        failed = true;
    }
    if wait(lease.budget, lease.interval, async || {
        audit_items(t, lease).await
    })
    .await
    .is_err()
    {
        failed = true;
    }
    if !failed && lease.objects.is_empty() && !lease.init_pending {
        restore(t, lease).await?;
    }
    require(!failed)
}
