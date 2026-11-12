use super::*;
use elasticctl_api::{alerts_ops, cases};

impl<C: Child> Session<C> {
    pub(super) fn check_change(
        &self,
        content: &Value,
        targets: &[String],
        operation: &Value,
    ) -> TestResult {
        require(targets.iter().all(|id| self.owned.contains(id)))?;
        let p = &content["data"]["plan"];
        require(p["targets"] == json!(targets) && p["operation"] == *operation)
    }
    pub(super) fn change(
        &mut self,
        tool: &str,
        args: Value,
        owner: &str,
        targets: Vec<String>,
        operation: Value,
    ) -> TestResult<Value> {
        require(self.owned.contains(owner))?;
        let f = self.call(tool, args)?;
        let content = frames::content(f, self.path)?;
        self.check_change(&content, &targets, &operation)?;
        let id = frames::plan_id(&content)?;
        self.plans.insert(id.clone(), owner.into());
        self.checks.insert(id.clone(), (targets, operation));
        let result = self.apply(&id, true)?;
        frames::applied(&result, false)?;
        require(
            result["data"]["outcome"]["complete"] == true
                && result["data"]["outcome"]["failed"] == 0,
        )?;
        Ok(result)
    }
}

// Both offline and live checks use these inputs and exact expected views.
pub(super) fn change_view(tool: &str, args: &Value, version: Option<&str>) -> (Vec<String>, Value) {
    let strings = |key: &str| {
        args[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };
    match tool {
        "alerts_set_tags_plan" => (strings("alert_ids"), args.clone()),
        "alerts_set_status_plan" => {
            let mut operation = args.clone();
            operation["reason"] = args.get("reason").cloned().unwrap_or(Value::Null);
            (strings("alert_ids"), operation)
        }
        "cases_create_plan" => {
            let mut operation = args.clone();
            operation["sync_alerts"] = json!(false);
            (vec![], operation)
        }
        "cases_comment_plan" => (
            vec![args["id"].as_str().unwrap().into()],
            json!({"case_id":args["id"],"message":args["message"]}),
        ),
        "cases_set_status_plan" => (
            strings("ids"),
            json!({"status":args["status"],"updates":[{"id":args["ids"][0],"version":version.unwrap()}],"resolved":1}),
        ),
        "rules_create_plan" => (
            vec![args["rule"]["rule_id"].as_str().unwrap().into()],
            args.clone(),
        ),
        _ => unreachable!(),
    }
}
impl<C: Child> Session<C> {
    pub(super) fn extension_change(
        &mut self,
        tool: &str,
        args: Value,
        owner: &str,
        version: Option<&str>,
    ) -> TestResult<Value> {
        let (targets, operation) = change_view(tool, &args, version);
        self.change(tool, args, owner, targets, operation)
    }
}

async fn alert(
    t: &Transport,
    registry: &Registry,
    id: &str,
) -> TestResult<elasticctl_api::alerts::AlertHit> {
    let rule = registry.alerts.get(id).ok_or("contract")?;
    require(registry.rules.contains(rule))?;
    let h = safe(alerts_ops::get_one(t, id).await)?;
    require(h.id == id)?;
    verify_alert(&h.source, rule)?;
    Ok(h)
}
async fn case(t: &Transport, registry: &Registry, id: &str) -> TestResult<cases::Case> {
    let token = registry.cases.get(id).ok_or("contract")?;
    let c = safe(cases::get(t, id).await)?;
    require(
        c.id == id
            && c.title == *token
            && c.tags.contains(&LIVE_TAG.into())
            && c.tags.contains(token),
    )?;
    Ok(c)
}
async fn prepare_alerts(
    t: &Transport,
    registry: &mut Registry,
    rule: &str,
    index: &str,
) -> TestResult<Vec<String>> {
    create_index(t, registry, index).await?;
    for n in 0..2 {
        check_cancelled()?;
        require(registry.indices.contains(index))?;
        safe(
            t.post_absolute_es(
                &format!("/{index}/_doc/{n}?refresh=wait_for"),
                &json!({"@timestamp":current_rfc3339(),"marker":LIVE_TAG,"seq":n}),
            )
            .await,
        )?;
    }
    toggle(t, registry, rule, true).await?;
    let mut ids = Vec::new();
    for _ in 0..TRIAGE_POLL_ATTEMPTS {
        check_cancelled()?;
        let hits = safe(elasticctl_api::alerts::search(t, &json!({"query":open_marker_rule_alerts_query(rule),"size":10,"_source":true,"track_total_hits":true})).await)?.hits;
        for h in hits {
            let read = safe(alerts_ops::get_one(t, &h.id).await)?;
            require(read.id == h.id)?;
            verify_alert(&read.source, rule)?;
            registry.alerts.insert(h.id.clone(), rule.into());
            if !ids.contains(&h.id) {
                ids.push(h.id);
            }
        }
        if ids.len() >= 2 {
            break;
        }
        tokio::time::sleep(TRIAGE_POLL_INTERVAL).await;
    }
    toggle(t, registry, rule, false).await?;
    require(ids.len() >= 2)?;
    Ok(ids)
}

pub(super) fn run<C: Child>(
    s: &mut Session<C>,
    rt: &tokio::runtime::Runtime,
    t: &Transport,
    registry: &mut Registry,
    rule: &str,
    index: &str,
) -> TestResult {
    let ids = rt.block_on(prepare_alerts(t, registry, rule, index))?;
    s.owned.extend(registry.alerts.keys().cloned());
    let id = &ids[0];
    let tag = unique_name("mutation-tag");
    let before = rt.block_on(alert(t, registry, id))?;
    require(
        !before.source["kibana.alert.workflow_tags"]
            .as_array()
            .is_some_and(|v| v.contains(&json!(tag))),
    )?;
    for add in [true, false] {
        let before = rt.block_on(alert(t, registry, id))?;
        let (adds, removes) = if add {
            (vec![tag.clone()], vec![])
        } else {
            (vec![], vec![tag.clone()])
        };
        let args = json!({"alert_ids":[id],"add":adds,"remove":removes});
        s.extension_change("alerts_set_tags_plan", args, id, None)?;
        let after = rt.block_on(alert(t, registry, id))?;
        let mut expected = before.source["kibana.alert.workflow_tags"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        expected.retain(|v| *v != json!(tag));
        if add {
            expected.push(json!(tag));
        }
        let mut actual = after.source["kibana.alert.workflow_tags"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        expected.sort_by_key(Value::to_string);
        actual.sort_by_key(Value::to_string);
        require(
            actual == expected
                && after.source["kibana.alert.workflow_status"]
                    == before.source["kibana.alert.workflow_status"],
        )?;
    }
    for status in ["acknowledged", "open", "closed"] {
        rt.block_on(alert(t, registry, id))?;
        s.extension_change(
            "alerts_set_status_plan",
            json!({"alert_ids":[id],"status":status}),
            id,
            None,
        )?;
        require(
            rt.block_on(alert(t, registry, id))?.source["kibana.alert.workflow_status"] == status,
        )?;
    }
    let token = unique_name("mutation-created-case");
    marker(&token)?;
    s.owned.insert(token.clone());
    let case_id = create_mcp_case(s, rt, t, registry, &token)?;
    s.owned.insert(case_id.clone());
    let c = rt.block_on(case(t, registry, &case_id))?;
    require(
        c.status == "open"
            && c.description.as_deref() == Some(LIVE_TAG)
            && c.severity.as_deref() == Some("low")
            && c.extra["settings"]["syncAlerts"] == false,
    )?;
    s.extension_change(
        "cases_comment_plan",
        json!({"id":case_id,"message":LIVE_TAG}),
        &case_id,
        None,
    )?;
    let after = rt.block_on(case(t, registry, &case_id))?;
    require(after.total_comment == c.total_comment.unwrap_or(0).checked_add(1))?;
    let raw = rt.block_on(safe_case_read(t, &case_id))?;
    require(raw["comments"].as_array().is_some_and(|v| {
        v.iter()
            .any(|v| v["comment"] == LIVE_TAG && v["type"] == "user")
    }))?;
    for status in ["closed", "open"] {
        let before = rt.block_on(case(t, registry, &case_id))?;
        s.extension_change(
            "cases_set_status_plan",
            json!({"ids":[case_id],"status":status}),
            &case_id,
            Some(&before.version),
        )?;
        require(rt.block_on(case(t, registry, &case_id))?.status == status)?;
    }
    let new_rule = unique_name("mutation-created-rule");
    marker(&new_rule)?;
    s.owned.insert(new_rule.clone());
    let body = rule_body(&new_rule, index)?;
    let (result, created) = create_mcp_rule(s, rt, t, registry, &new_rule, &body)?;
    let canonical = rule_state(&created);
    let expected = rule_state(&body);
    require(
        !created.enabled()
            && expected
                .as_map()
                .iter()
                .all(|(key, value)| canonical.as_map().get(key) == Some(value)),
    )?;
    require(result["data"]["outcome"]["created"]["rule_id"] == new_rule)?;
    refusal(s, rt, t, registry, &ids[1])
}
async fn safe_case_read(t: &Transport, id: &str) -> TestResult<Value> {
    safe(t.get(&cases::case_path(id)).await)
}

pub(super) fn refusal<C: Child>(
    s: &mut Session<C>,
    rt: &tokio::runtime::Runtime,
    t: &Transport,
    registry: &mut Registry,
    alert_id: &str,
) -> TestResult {
    let token = unique_name("mutation-sync-case");
    marker(&token)?;
    let id = rt.block_on(create_refusal_case(t, registry, &token))?;
    let h = rt.block_on(alert(t, registry, alert_id))?;
    require(h.source["kibana.alert.workflow_status"] == "open")?;
    let rule = registry.alerts.get(alert_id).ok_or("contract")?;
    rt.block_on(owned_rule(t, rule))?;
    rt.block_on(async {
        case(t, registry, &id).await?;
        check_cancelled()?;
        safe(
            cases::attach_alerts(
                t,
                &id,
                &[alert_id.into()],
                &[h.index.clone().ok_or("contract")?],
                h.source["kibana.alert.rule.uuid"]
                    .as_str()
                    .ok_or("contract")?,
                h.source["kibana.alert.rule.name"]
                    .as_str()
                    .ok_or("contract")?,
            )
            .await,
        )?;
        Ok::<_, String>(())
    })?;
    s.owned.insert(id.clone());
    let before = rt.block_on(case(t, registry, &id))?;
    require(before.extra["settings"]["syncAlerts"] == true && before.extra["totalAlerts"] == 1)?;
    let alert_before = rt.block_on(alert(t, registry, alert_id))?;
    let f = s.call(
        "cases_set_status_plan",
        json!({"ids":[id],"status":"closed"}),
    )?;
    frames::code(&frames::content(f, s.path)?, "case_sync_alerts")?;
    require(
        rt.block_on(case(t, registry, &id))? == before
            && rt.block_on(alert(t, registry, alert_id))?.source == alert_before.source,
    )
}

pub(super) fn create_mcp_case<C: Child>(
    s: &mut Session<C>,
    rt: &tokio::runtime::Runtime,
    t: &Transport,
    registry: &mut Registry,
    token: &str,
) -> TestResult<String> {
    marker(token)?;
    registry.pending_cases.insert(token.into());
    let args =
        json!({"title":token,"description":LIVE_TAG,"tags":[LIVE_TAG,token],"severity":"low"});
    let result = s.extension_change("cases_create_plan", args, token, None)?;
    let case_id = result["data"]["outcome"]["created"]["case_id"]
        .as_str()
        .ok_or("contract")?
        .to_owned();
    rt.block_on(register_case(t, registry, &case_id, token))?;
    Ok(case_id)
}
pub(super) fn create_mcp_rule<C: Child>(
    s: &mut Session<C>,
    rt: &tokio::runtime::Runtime,
    t: &Transport,
    registry: &mut Registry,
    id: &str,
    body: &elasticctl_api::model::Rule,
) -> TestResult<(Value, elasticctl_api::model::Rule)> {
    marker(id)?;
    registry.pending_rules.insert(id.into());
    let result = s.extension_change("rules_create_plan", json!({"rule":body}), id, None)?;
    let created = rt.block_on(owned_rule(t, id))?;
    registry.rules.insert(id.into());
    registry.pending_rules.remove(id);
    Ok((result, created))
}
pub(super) async fn create_refusal_case(
    t: &Transport,
    registry: &mut Registry,
    token: &str,
) -> TestResult<String> {
    marker(token)?;
    registry.pending_cases.insert(token.into());
    check_cancelled()?;
    let raw = safe(t.post_once(cases::CASES_PATH, Some(&json!({"title":token,"description":LIVE_TAG,"tags":[LIVE_TAG,token],"owner":cases::OWNER,"connector":{"id":"none","name":"none","type":".none","fields":null},"settings":{"syncAlerts":true}}))).await)?;
    let id = raw["id"].as_str().ok_or("contract")?.to_owned();
    register_case(t, registry, &id, token).await?;
    Ok(id)
}
