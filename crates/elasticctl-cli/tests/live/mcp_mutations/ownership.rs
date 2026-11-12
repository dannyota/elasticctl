use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
pub(super) struct Registry {
    pub rules: BTreeSet<String>,
    pub pending_rules: BTreeSet<String>,
    pub pending_cases: BTreeSet<String>,
    pub cases: BTreeMap<String, String>,
    pub indices: BTreeSet<String>,
    pub alerts: BTreeMap<String, String>,
    pub lab: Option<lab_identity::Lease>,
}

pub(super) fn exact_targets(actual: &[String], expected: &[String]) -> TestResult {
    let a: BTreeSet<_> = actual.iter().collect();
    let b: BTreeSet<_> = expected.iter().collect();
    require(a == b && a.len() == actual.len() && b.len() == expected.len())
}
pub(super) fn verify_view(content: &Value, rule: &str) -> TestResult {
    let p = &content["data"]["plan"];
    require(p["targets"] == json!([rule]) && p["operation"]["rule_ids"] == json!([rule]))
}
pub(super) async fn create_rule(
    t: &Transport,
    registry: &mut Registry,
    id: &str,
    index: &str,
) -> TestResult {
    check_cancelled()?;
    let (p, _) = safe(elasticctl_api::rules_ops::plan_create(t, rule_body(id, index)?).await)?;
    exact_targets(&p.preview.targets, &[id.into()])?;
    safe(elasticctl_api::rules_ops::apply_create(t, &p).await)?;
    owned_rule(t, id).await?;
    // The locally generated id is also the unique ownership token in tags.
    registry.rules.insert(id.into());
    Ok(())
}
pub(super) async fn create_case(
    t: &Transport,
    registry: &mut Registry,
    token: &str,
) -> TestResult<String> {
    check_cancelled()?;
    marker(token)?;
    let p = safe(
        elasticctl_api::cases_ops::plan_create(
            t,
            token,
            Some(LIVE_TAG.into()),
            vec![LIVE_TAG.into(), token.into()],
            Some("low".into()),
            &[],
        )
        .await,
    )?;
    let created = safe(elasticctl_api::cases_ops::apply_create(t, &p).await)?;
    let id = created["id"].as_str().ok_or("contract")?.to_owned();
    register_case(t, registry, &id, token).await?;
    Ok(id)
}
pub(super) async fn register_case(
    t: &Transport,
    registry: &mut Registry,
    id: &str,
    token: &str,
) -> TestResult {
    marker(token)?;
    let c = safe(elasticctl_api::cases::get(t, id).await)?;
    require(
        c.id == id
            && c.title == token
            && c.tags.contains(&LIVE_TAG.into())
            && c.tags.contains(&token.into()),
    )?;
    registry.cases.insert(id.into(), token.into());
    registry.pending_cases.remove(token);
    Ok(())
}
pub(super) async fn create_index(
    t: &Transport,
    registry: &mut Registry,
    index: &str,
) -> TestResult {
    marker(index)?;
    check_cancelled()?;
    safe(
        t.put_absolute_es_once(
            &format!("/{index}"),
            &json!({"mappings":{"_meta":{"marker":LIVE_TAG,"token":index}}}),
        )
        .await,
    )?;
    verify_index(t, index).await?;
    registry.indices.insert(index.into());
    Ok(())
}
async fn verify_index(t: &Transport, index: &str) -> TestResult {
    let v = safe(t.get_absolute_es(&format!("/{index}/_mapping")).await)?;
    require(v[index]["mappings"]["_meta"] == json!({"marker":LIVE_TAG,"token":index}))
}
pub(super) fn verify_alert(source: &Value, rule: &str) -> TestResult {
    require(
        source["kibana.alert.rule.rule_id"] == rule
            && source["kibana.alert.rule.tags"]
                .as_array()
                .is_some_and(|tags| tags.contains(&json!(LIVE_TAG)) && tags.contains(&json!(rule))),
    )
}
pub(super) fn cleanup_transport(profile: &Profile) -> TestResult<Transport> {
    safe(Transport::with_options(
        profile,
        elasticctl_core::transport::TransportOptions {
            disable_retries: true,
            disable_redirects: true,
            disable_connection_pool: true,
            ..Default::default()
        },
    ))
}
pub(super) async fn clean(t: &Transport, registry: &Registry) -> TestResult {
    let mut resolved = Registry {
        rules: registry.rules.clone(),
        cases: registry.cases.clone(),
        indices: registry.indices.clone(),
        alerts: registry.alerts.clone(),
        ..Default::default()
    };
    for id in &registry.pending_rules {
        marker(id)?;
        match elasticctl_api::rules::get(t, id).await {
            Ok(_) => {
                owned_rule(t, id).await?;
                resolved.rules.insert(id.clone());
            }
            Err(e) if e.kind == ErrorKind::NotFound => {}
            Err(_) => return Err("cleanup_failed".into()),
        }
    }
    for token in &registry.pending_cases {
        marker(token)?;
        let filter = elasticctl_api::cases_ops::CaseFilter {
            tag: Some(token.clone()),
            ..Default::default()
        };
        let mut seen = BTreeSet::new();
        for page in 1.. {
            let query = elasticctl_api::cases_ops::find_query(&filter, page, 100);
            let (batch, total) = safe(elasticctl_api::cases::find_page(t, &query).await)?;
            require(!batch.is_empty() || seen.len() as u64 == total)?;
            for candidate in batch {
                require(seen.insert(candidate.id.clone()))?;
                register_case(t, &mut resolved, &candidate.id, token).await?;
            }
            if seen.len() as u64 == total {
                break;
            }
            require((seen.len() as u64) < total)?;
        }
    }
    clean_registered(t, &resolved).await?;
    if let Some(lease) = &registry.lab {
        lab_identity::clean(lease).await?;
    }
    Ok(())
}
async fn clean_registered(t: &Transport, registry: &Registry) -> TestResult {
    // Every ? stops the trace. No retry or Drop path sends another mutation.
    for rule in &registry.rules {
        match elasticctl_api::rules::get(t, rule).await {
            Ok(_) => {
                owned_rule(t, rule).await?;
                toggle(t, registry, rule, false).await?;
            }
            Err(e) if e.kind == ErrorKind::NotFound => continue,
            Err(_) => return Err("cleanup_failed".into()),
        }
    }
    let mut alerts = registry.alerts.clone();
    for rule in &registry.rules {
        let hits = safe(elasticctl_api::alerts::search_all(t,
            &json!({"bool":{"filter":[{"term":{"kibana.alert.rule.rule_id":rule}},{"term":{"kibana.alert.workflow_status":"open"}}]}}),
            &elasticctl_api::alerts_ops::default_sort(), None).await)?;
        for hit in hits {
            verify_alert(&hit.source, rule)?;
            alerts.insert(hit.id, rule.clone());
        }
    }
    for (id, rule) in &alerts {
        let hit = safe(elasticctl_api::alerts_ops::get_one(t, id).await)?;
        require(hit.id == *id && registry.rules.contains(rule))?;
        verify_alert(&hit.source, rule)?;
        let outcome = safe(
            elasticctl_api::alerts::status_by_ids(
                t,
                std::slice::from_ref(id),
                elasticctl_api::alerts::AlertStatus::Closed,
                None,
            )
            .await,
        )?;
        require(
            outcome.failures.is_empty()
                && outcome.version_conflicts == 0
                && outcome.total == 1
                && outcome.updated.checked_add(outcome.noops) == Some(1),
        )?;
        let closed = safe(elasticctl_api::alerts_ops::get_one(t, id).await)?;
        require(closed.id == *id && closed.source["kibana.alert.workflow_status"] == "closed")?;
        verify_alert(&closed.source, rule)?;
    }
    for (id, token) in &registry.cases {
        let c = safe(elasticctl_api::cases::get(t, id).await)?;
        require(
            c.id == *id
                && c.title == *token
                && c.tags.contains(&LIVE_TAG.into())
                && c.tags.contains(token),
        )?;
        safe(elasticctl_api::cases::delete(t, std::slice::from_ref(id)).await)?;
    }
    for id in &registry.rules {
        match elasticctl_api::rules::get(t, id).await {
            Ok(_) => {
                require(owned_rule(t, id).await?.as_map().get("enabled") == Some(&json!(false)))?;
                safe(elasticctl_api::rules::delete(t, id).await)?;
            }
            Err(e) if e.kind == ErrorKind::NotFound => {}
            Err(_) => return Err("cleanup_failed".into()),
        }
    }
    for index in &registry.indices {
        verify_index(t, index).await?;
        safe(t.delete_absolute_es_once(&format!("/{index}")).await)?;
    }
    if let Some(lease) = &registry.lab {
        lab_identity::clean(lease).await?;
    }
    Ok(())
}
pub(super) async fn baseline(t: &Transport) -> TestResult {
    let v = safe(t.get("/api/detection_engine/rules/_find?per_page=1&filter=alert.attributes.tags%3A%22elasticctl-live-marker%22").await)?;
    require(v["total"].as_u64() == Some(0))
}
pub(super) fn orchestrate(
    rt: &tokio::runtime::Runtime,
    t: &Transport,
    cleanup: &Transport,
    registry: &mut Registry,
    mut shared_baseline: impl FnMut() -> TestResult,
    body: impl FnOnce(&mut Registry) -> TestResult,
) -> TestResult {
    // SIGKILL cannot be cleaned. The next guarded baseline refuses marker
    // leftovers before creating anything. Pending creates require marker reads.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(baseline(t))
            .map_err(|_| "baseline_failed".to_string())?;
        shared_baseline().map_err(|_| "baseline_failed".to_string())?;
        body(registry)
    }));
    CANCELLATION.with(|flag| {
        flag.borrow_mut().take();
    });
    rt.block_on(clean(cleanup, registry))
        .map_err(|_| "cleanup_failed".to_string())?;
    if matches!(&result, Ok(Err(e)) if e == "baseline_failed") {
        return Err("baseline_failed".into());
    }
    rt.block_on(baseline(t))
        .map_err(|_| "baseline_failed".to_string())?;
    shared_baseline().map_err(|_| "baseline_failed".to_string())?;
    match result {
        Ok(Ok(())) => Ok(()),
        _ => Err("contract".into()),
    }
}
thread_local! { pub(super) static CANCELLATION: std::cell::RefCell<Option<Arc<AtomicBool>>> = const { std::cell::RefCell::new(None) }; }
pub(super) fn check_cancelled() -> TestResult {
    require(!CANCELLATION.with(|f| {
        f.borrow()
            .as_ref()
            .is_some_and(|f| f.load(Ordering::SeqCst))
    }))
}
type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync>;
pub(super) struct Signals {
    task: tokio::task::JoinHandle<()>,
    hook: Option<PanicHook>,
}
impl Signals {
    pub fn install(rt: &tokio::runtime::Runtime) -> TestResult<Self> {
        let flag = Arc::new(AtomicBool::new(false));
        CANCELLATION.with(|f| *f.borrow_mut() = Some(flag.clone()));
        let _enter = rt.enter();
        #[cfg(unix)]
        let task = {
            use tokio::signal::unix::{SignalKind, signal};
            let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| "contract")?;
            let mut terminate = signal(SignalKind::terminate()).map_err(|_| "contract")?;
            tokio::spawn(async move {
                tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
                flag.store(true, Ordering::SeqCst);
            })
        };
        #[cfg(not(unix))]
        let task = tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            flag.store(true, Ordering::SeqCst);
        });
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| eprintln!("contract")));
        Ok(Self {
            task,
            hook: Some(hook),
        })
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(hook) = self.hook.take() {
            std::panic::set_hook(hook);
        }
    }
}
