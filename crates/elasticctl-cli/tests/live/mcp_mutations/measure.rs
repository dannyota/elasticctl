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
    cleanup: &mut LiveCleanup,
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
        cleanup.index(index.to_owned());
        cleanup.alert_rule(id.to_owned());
        for n in 0..2 {
            safe(
                t.post_absolute_es(
                    &format!("/{index}/_doc?refresh=wait_for"),
                    &json!({"@timestamp":current_rfc3339(),"marker":LIVE_TAG,"seq":n}),
                )
                .await,
            )?;
        }
        let start = Instant::now();
        toggle(t, id, true).await?;
        let before = normalize::canonical(&owned_rule(t, id).await?);
        tokio::time::sleep(Duration::from_secs(60)).await;
        require(before == normalize::canonical(&owned_rule(t, id).await?))?;
        report("M2", "equal", start);
        let start = Instant::now();
        toggle(t, id, false).await?;
        toggle(t, id, true).await?;
        let gone = unique_name("mutation-deleted");
        marker(&gone)?;
        cleanup.rule(gone.clone());
        safe(rules::create(t, &rule_body(&gone, index)?).await)?;
        owned_rule(t, &gone).await?;
        safe(rules::delete(t, &gone).await)?;
        let plan = safe(rules_ops::plan_set_enabled(t, &[id.into()], false).await)?;
        let mut missing = plan;
        missing.targets.push(gone);
        let outcome = safe(rules_ops::apply_set_enabled(t, &missing, false).await)?;
        require(outcome.total == 1 && outcome.failed == 0 && outcome.succeeded == 1)?;
        report("M3", "missing_excluded", start);
        let start = Instant::now();
        toggle(t, id, true).await?;
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
        let ids: Vec<_> = hits.iter().map(|h| h.id.clone()).collect();
        let p = safe(
            alerts_ops::plan_status_by_ids(t, &ids, alerts::AlertStatus::Acknowledged, None).await,
        )?;
        let o = safe(alerts_ops::apply_status_by_ids(t, &p).await)?;
        require(o.failed == 0)?;
        for alert in &ids {
            let h = safe(alerts_ops::get_one(t, alert).await)?;
            require(h.source["kibana.alert.workflow_status"] == "acknowledged")?;
        }
        let p = safe(alerts_ops::plan_tags(t, &ids, vec![LIVE_TAG.into()], vec![]).await)?;
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
        cleanup.case_scope(title.clone(), LIVE_TAG);
        let p = safe(
            cases_ops::plan_create(
                t,
                &title,
                Some(LIVE_TAG.into()),
                vec![LIVE_TAG.into()],
                Some("low".into()),
                &[],
            )
            .await,
        )?;
        let created = safe(cases_ops::apply_create(t, &p).await)?;
        let case_id = created["id"]
            .as_str()
            .ok_or("missing case identity")?
            .to_owned();
        cleanup.case(case_id.clone());
        let case = safe(cases::get(t, &case_id).await)?;
        require(case.title == title && case.tags.contains(&LIVE_TAG.to_owned()))?;
        let start = Instant::now();
        let p = safe(cases_ops::plan_comment(t, &case_id, LIVE_TAG).await)?;
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
        let error = cases::patch_status(t, &[(case_id, after.version, cases::CaseStatus::Open)])
            .await
            .err()
            .ok_or("stale case accepted")?;
        require(error.http_status == Some(409))?;
        report("M6", "conflict", start);
        toggle(t, id, false).await?;
        let start = Instant::now();
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
            cleanup.rule(next.clone());
            let (p, _) = safe(rules_ops::plan_create(t, rule_body(&next, index)?).await)?;
            safe(rules_ops::apply_create(t, &p).await)?;
            require(!owned_rule(t, &next).await?.enabled())?;
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
            let plan = safe(rules_ops::plan_set_enabled(t, &[id.into()], true).await)?;
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
                Ok(o) => report(
                    "M9",
                    if o.failed > 0 { "failed" } else { "succeeded" },
                    start,
                ),
            }
            owned_rule(t, id).await?;
        } else {
            println!("M9 skipped");
        }
        lab::measure(t, profile, id, index, cleanup).await
    })
}
#[path = "lab.rs"]
mod lab;
