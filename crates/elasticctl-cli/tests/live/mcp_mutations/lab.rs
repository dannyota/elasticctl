use super::*;

pub(super) async fn measure(
    t: &Transport,
    profile: &Profile,
    id: &str,
    index: &str,
    cleanup: &mut LiveCleanup,
) -> TestResult {
    let is_lab = [
        "http://localhost:",
        "http://127.0.0.1:",
        "https://localhost:",
        "https://127.0.0.1:",
    ]
    .iter()
    .any(|p| profile.kibana_url.starts_with(p));
    if !is_lab {
        println!("M13 skipped");
        return Ok(());
    }
    let start = Instant::now();
    // A lab basic credential proves the absent api_key branch separately.
    let mut basic = profile.clone();
    basic.api_key = None;
    basic.username = std::env::var("ELASTICCTL_USERNAME").ok();
    basic.password = std::env::var("ELASTICCTL_PASSWORD").ok();
    require(basic.username.is_some() && basic.password.is_some())?;
    let basic = safe(Transport::new(&basic))?;
    require(
        safe(health::credential_identity(&basic).await)?
            .api_key_id
            .is_none(),
    )?;
    report("M1_lab_basic", "basic", start);
    let name = unique_name("mutation-credential");
    marker(&name)?;
    let key = safe(
        basic
            .post_absolute_es(
                "/_security/api_key",
                &json!({"name":name,"expiration":"15m"}),
            )
            .await,
    )?;
    let key_id = key["id"].as_str().ok_or("missing credential identity")?;
    let run = async {
        let mut other = profile.clone();
        other.api_key = Some(
            key["encoded"]
                .as_str()
                .ok_or("missing credential")?
                .to_owned(),
        );
        other.username = None;
        other.password = None;
        let other = safe(Transport::new(&other))?;
        require(
            safe(health::credential_identity(&other).await)?
                .api_key_id
                .is_some(),
        )?;
        let rule_id = unique_name("mutation-owner");
        marker(&rule_id)?;
        cleanup.rule(rule_id.clone());
        let created = safe(rules::create(&other, &rule_body(&rule_id, index)?).await)?;
        let saved = created.as_map()["id"]
            .as_str()
            .ok_or("missing saved identity")?;
        let path = format!("/api/alerting/rule/{saved}");
        let before = safe(t.get(&path).await)?;
        owned_rule(t, &rule_id).await?;
        toggle(t, &rule_id, true).await?;
        let enabled = safe(t.get(&path).await)?;
        toggle(t, &rule_id, false).await?;
        let disabled = safe(t.get(&path).await)?;
        for body in [&before, &enabled, &disabled] {
            require(body["api_key_owner"].is_string())?;
        }
        report(
            "M13_enable",
            if before["api_key_owner"] == enabled["api_key_owner"] {
                "owner_kept"
            } else {
                "owner_changed"
            },
            start,
        );
        report(
            "M13_disable",
            if enabled["api_key_owner"] == disabled["api_key_owner"] {
                "owner_kept"
            } else {
                "owner_changed"
            },
            start,
        );
        owned_rule(t, id).await?;
        Ok(())
    }
    .await;
    let revoke = safe(
        basic
            .delete_absolute_es_json("/_security/api_key", &json!({"ids":[key_id]}))
            .await,
    );
    revoke?;
    run
}
