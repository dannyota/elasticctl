use super::*;
use elasticctl_api::{alerts, alerts_ops, cases, cases_ops, health, normalize, rules, rules_ops};
use std::time::Instant;

fn report(label: &'static str, class: &'static str, start: Instant) {
    println!("{label} {class} {}s", start.elapsed().as_secs());
}
pub(super) fn run(
    rt: &tokio::runtime::Runtime,
    t: &Transport,
    profile: &Profile,
    id: &str,
    index: &str,
    cleanup: &mut Registry,
) -> TestResult {
    rt.block_on(async {
        let start = Instant::now();
        let identity = safe(health::credential_identity(t).await)?;
        require(!identity.username.is_empty() && !identity.realm_type.is_empty())?;
        report(
            "M1",
            if identity.api_key_id.is_some() {
                "api_key"
            } else {
                "basic"
            },
            start,
        );
        create_index(t, cleanup, index).await?;
        for n in 0..2 {
            check_cancelled()?;
            require(cleanup.indices.contains(index))?;
            safe(
                t.post_absolute_es(
                    &format!("/{index}/_doc/{n}?refresh=wait_for"),
                    &json!({"@timestamp":current_rfc3339(),"marker":LIVE_TAG,"seq":n}),
                )
                .await,
            )?;
        }
        let start = Instant::now();
        toggle(t, cleanup, id, true).await?;
        let before = normalize::canonical(&owned_rule(t, id).await?);
        tokio::time::sleep(Duration::from_secs(60)).await;
        require(before == normalize::canonical(&owned_rule(t, id).await?))?;
        report("M2", "equal", start);
        let start = Instant::now();
        toggle(t, cleanup, id, false).await?;
        toggle(t, cleanup, id, true).await?;
        let gone = unique_name("mutation-deleted");
        marker(&gone)?;
        create_rule(t, cleanup, &gone, index).await?;
        check_cancelled()?;
        require(cleanup.rules.contains(&gone))?;
        safe(rules::delete(t, &gone).await)?;
        let plan = safe(rules_ops::plan_set_enabled(t, &[id.into()], false).await)?;
        exact_targets(&plan.targets, &[id.into()])?;
        let mut missing = plan;
        missing.targets.push(gone);
        check_cancelled()?;
        let outcome = safe(rules_ops::apply_set_enabled(t, &missing, false).await)?;
        require(outcome.total == 1 && outcome.failed == 0 && outcome.succeeded == 1)?;
        report("M3", "missing_excluded", start);
        let start = Instant::now();
        toggle(t, cleanup, id, true).await?;
        let mut hits = Vec::new();
        for _ in 0..TRIAGE_POLL_ATTEMPTS {
            hits = safe(
                alerts::search(
                    t,
                    &json!({"query":open_marker_rule_alerts_query(id),
                "size":10,"_source":true,"track_total_hits":true}),
                )
                .await,
            )?
            .hits;
            if hits.len() >= 2 {
                break;
            }
            tokio::time::sleep(TRIAGE_POLL_INTERVAL).await;
        }
        require(hits.len() >= 2)?;
        for hit in &hits {
            require(hit.source["kibana.alert.rule.rule_id"] == id)?;
        }
        for hit in &hits {
            let read = safe(alerts_ops::get_one(t, &hit.id).await)?;
            require(cleanup.rules.contains(id))?;
            verify_alert(&read.source, id)?;
            cleanup.alerts.insert(hit.id.clone(), id.into());
        }
        let ids: Vec<_> = hits.iter().map(|h| h.id.clone()).collect();
        let p = safe(
            alerts_ops::plan_status_by_ids(t, &ids, alerts::AlertStatus::Acknowledged, None).await,
        )?;
        exact_targets(&p.targets, &ids)?;
        check_cancelled()?;
        let o = safe(alerts_ops::apply_status_by_ids(t, &p).await)?;
        require(o.failed == 0)?;
        for alert in &ids {
            let h = safe(alerts_ops::get_one(t, alert).await)?;
            require(h.source["kibana.alert.workflow_status"] == "acknowledged")?;
        }
        let p = safe(alerts_ops::plan_tags(t, &ids, vec![LIVE_TAG.into()], vec![]).await)?;
        exact_targets(&p.targets, &ids)?;
        check_cancelled()?;
        safe(alerts_ops::apply_tags(t, &p).await)?;
        for alert in &ids {
            let h = safe(alerts_ops::get_one(t, alert).await)?;
            require(
                h.source["kibana.alert.workflow_tags"]
                    .as_array()
                    .is_some_and(|v| v.contains(&json!(LIVE_TAG))),
            )?;
        }
        report("M4", "visible", start);
        let title = unique_name("mutation-case");
        marker(&title)?;
        let case_id = create_case(t, cleanup, &title).await?;
        let case = safe(cases::get(t, &case_id).await)?;
        require(case.title == title && case.tags.contains(&LIVE_TAG.to_owned()))?;
        let start = Instant::now();
        let p = safe(cases_ops::plan_comment(t, &case_id, LIVE_TAG).await)?;
        require(p.case_id == case_id && cleanup.cases.contains_key(&case_id))?;
        check_cancelled()?;
        safe(cases_ops::apply_comment(t, &p).await)?;
        let after = safe(cases::get(t, &case_id).await)?;
        report(
            "M5",
            if case.version == after.version {
                "version_kept"
            } else {
                "version_changed"
            },
            start,
        );
        let start = Instant::now();
        check_cancelled()?;
        require(cleanup.cases.contains_key(&case_id))?;
        safe(
            cases::patch_status(
                t,
                &[(
                    case_id.clone(),
                    after.version.clone(),
                    cases::CaseStatus::Closed,
                )],
            )
            .await,
        )?;
        check_cancelled()?;
        let error = cases::patch_status(t, &[(case_id, after.version, cases::CaseStatus::Open)])
            .await
            .err()
            .ok_or("stale case accepted")?;
        require(error.http_status == Some(409))?;
        report("M6", "conflict", start);
        toggle(t, cleanup, id, false).await?;
        let start = Instant::now();
        check_cancelled()?;
        require(cleanup.rules.contains(id))?;
        let error = rules::create(t, &rule_body(id, index)?)
            .await
            .err()
            .ok_or("duplicate rule accepted")?;
        require(error.http_status == Some(409) && !owned_rule(t, id).await?.enabled())?;
        report("M7", "conflict_disabled_create", start);
        let mut ids = vec![id.to_owned()];
        for _ in 1..20 {
            let next = unique_name("mutation-timing");
            marker(&next)?;
            create_rule(t, cleanup, &next, index).await?;
            ids.push(next);
        }
        let start = Instant::now();
        let (p, seen) = safe(rules_ops::plan_set_enabled_observed(t, &ids, false).await)?;
        report("M8_plan", "complete", start);
        let start = Instant::now();
        let check = safe(rules_ops::observe_rules(t, &ids).await)?;
        require(seen == check)?;
        report("M8_check", "equal", start);
        let start = Instant::now();
        exact_targets(&p.targets, &ids)?;
        check_cancelled()?;
        let outcome = safe(rules_ops::apply_set_enabled(t, &p, false).await)?;
        require(outcome.failed == 0 && outcome.total == 20)?;
        for id in &ids {
            require(!owned_rule(t, id).await?.enabled())?;
        }
        report("M8_apply", "complete", start);
        if let Ok(key) = std::env::var("ELASTICCTL_ORG_API_KEY") {
            let start = Instant::now();
            let mut org = profile.clone();
            org.api_key = Some(key);
            org.username = None;
            org.password = None;
            let org = safe(Transport::new(&org))?;
            // Start from a disabled rule, so an enable is a real change and not a skip.
            toggle(t, cleanup, id, false).await?;
            let plan = safe(rules_ops::plan_set_enabled(t, &[id.into()], true).await)?;
            exact_targets(&plan.targets, &[id.into()])?;
            check_cancelled()?;
            match rules_ops::apply_set_enabled(&org, &plan, true).await {
                Err(e) => report(
                    "M9",
                    if e.http_status == Some(403) {
                        "forbidden"
                    } else {
                        "error"
                    },
                    start,
                ),
                Ok(o) => {
                    let enabled = owned_rule(t, id).await?.enabled();
                    report(
                        "M9",
                        match (o.succeeded, o.failed, o.skipped, enabled) {
                            (1, 0, 0, true) => "enabled",
                            (_, f, _, false) if f > 0 => "failed",
                            (0, 0, s, false) if s > 0 => "skipped",
                            _ => "inconclusive",
                        },
                        start,
                    )
                }
            }
            owned_rule(t, id).await?;
        } else {
            println!("M9 skipped");
        }
        lab::measure(t, profile, id, index, cleanup).await
    })
}
#[path = "lab.rs"]
pub(super) mod lab;
