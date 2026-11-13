use super::*;

pub(in crate::mcp_mutations) fn lab_target(opt_in: bool, profile: &Profile) -> bool {
    fn loopback(url: &str) -> bool {
        let Some(rest) = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
        else {
            return false;
        };
        let authority = rest.split('/').next().unwrap_or("");
        if authority.contains('@') {
            return false;
        }
        authority == "localhost"
            || authority.starts_with("localhost:")
            || authority == "127.0.0.1"
            || authority.starts_with("127.0.0.1:")
            || authority == "[::1]"
            || authority.starts_with("[::1]:")
    }
    opt_in && loopback(&profile.kibana_url) && profile.es_url.as_deref().is_some_and(loopback)
}
pub(in crate::mcp_mutations) async fn fingerprint(profile: &Profile, opt_in: bool) -> TestResult {
    require(lab_target(opt_in, profile))?;
    let options = || elasticctl_core::transport::TransportOptions {
        disable_retries: true,
        disable_redirects: true,
        ..Default::default()
    };
    let kibana = safe(Transport::with_options(profile, options()))?;
    let mut es_profile = profile.clone();
    es_profile.kibana_url = profile.es_url.clone().ok_or("contract")?;
    es_profile.space = "default".into();
    let es = safe(Transport::with_options(&es_profile, options()))?;
    let root = safe(es.get_with_headers("/").await)?;
    let nodes = safe(es.get_with_headers("/_nodes/_local/settings").await)?;
    let status = safe(kibana.get_with_headers("/api/status").await)?;
    for response in [&root, &nodes, &status] {
        require(
            response.header("x-found-handling-cluster").is_none()
                && response.header("x-found-handling-instance").is_none(),
        )?;
    }
    require(
        root.body["cluster_name"] == "docker-cluster"
            && nodes.body["cluster_name"] == "docker-cluster",
    )?;
    let local = nodes.body["nodes"].as_object().ok_or("contract")?;
    require(
        local.len() == 1
            && local.values().all(|n| {
                n.pointer("/settings/discovery/type")
                    .and_then(Value::as_str)
                    == Some("single-node")
            }),
    )?;
    require(status.body["version"]["build_flavor"] == "traditional")?;
    let uuid = root.body["cluster_uuid"]
        .as_str()
        .filter(|v| !v.is_empty() && *v != "_na_")
        .ok_or("contract")?;
    let through_kibana = safe(kibana.get("/api/stats?extended=true").await)?;
    require(through_kibana["cluster_uuid"] == uuid)
}
pub(super) async fn measure(
    t: &Transport,
    profile: &Profile,
    id: &str,
    index: &str,
    cleanup: &mut Registry,
) -> TestResult {
    if !lab_target(
        std::env::var("ELASTICCTL_MUTATION_LAB").as_deref() == Ok("1"),
        profile,
    ) {
        println!("M13 skipped");
        return Ok(());
    }
    let start = Instant::now();
    let mut basic_profile = profile.clone();
    basic_profile.api_key = None;
    basic_profile.username = std::env::var("ELASTICCTL_USERNAME").ok();
    basic_profile.password = std::env::var("ELASTICCTL_PASSWORD").ok();
    if basic_profile.username.is_none() || basic_profile.password.is_none() {
        report("M13", "inconclusive", start);
        return Ok(());
    }
    measure_with_basic(t, &basic_profile, index, cleanup, true).await?;
    owned_rule(t, id).await?;
    Ok(())
}
pub(in crate::mcp_mutations) async fn measure_with_basic(
    t: &Transport,
    basic_profile: &Profile,
    index: &str,
    cleanup: &mut Registry,
    opt_in: bool,
) -> TestResult {
    if fingerprint(basic_profile, opt_in).await.is_err() {
        println!("M13 skipped");
        return Ok(());
    }
    let start = Instant::now();
    let Ok(basic) = Transport::new(basic_profile) else {
        report("M13", "inconclusive", start);
        return Ok(());
    };
    let Ok(elastic_owner) = health::credential_identity(&basic).await else {
        report("M13", "inconclusive", start);
        return Ok(());
    };
    if elastic_owner.username != "elastic" || elastic_owner.api_key_id.is_some() {
        report("M13", "inconclusive", start);
        return Ok(());
    }
    let Ok((other, other_owner)) = lab_identity::provision(basic_profile, true, cleanup).await
    else {
        report("M13", "inconclusive", start);
        return Ok(());
    };
    let probe_id = unique_name("mutation-owner-probe");
    create_rule(&other, cleanup, &probe_id, index).await?;
    toggle(&other, cleanup, &probe_id, true).await?;
    let rule_id = unique_name("mutation-owner");
    create_rule(&basic, cleanup, &rule_id, index).await?;
    toggle(&basic, cleanup, &rule_id, true).await?;
    async fn owner(t: &Transport, id: &str) -> TestResult<(String, Value)> {
        let rule = owned_rule(t, id).await?;
        let saved = rule.as_map()["id"].as_str().ok_or("contract")?;
        let path = format!("/api/alerting/rule/{saved}");
        let value = safe(t.get(&path).await)?;
        Ok((path, value))
    }
    let (_, probe) = owner(t, &probe_id).await?;
    let (path, before) = owner(t, &rule_id).await?;
    if probe["api_key_owner"] != other_owner || before["api_key_owner"] != "elastic" {
        report("M13", "inconclusive", start);
        return Ok(());
    }
    toggle(&other, cleanup, &rule_id, false).await?;
    let disabled = safe(t.get(&path).await)?;
    toggle(&other, cleanup, &rule_id, true).await?;
    let enabled = safe(t.get(&path).await)?;
    let class = |from: &Value, to: &Value| {
        if to["api_key_owner"] == from["api_key_owner"] {
            "owner_kept"
        } else if to["api_key_owner"] == other_owner {
            "owner_changed"
        } else if to["api_key_owner"].is_null() {
            "owner_cleared"
        } else {
            "inconclusive"
        }
    };
    report("M13_disable", class(&before, &disabled), start);
    report("M13_enable", class(&disabled, &enabled), start);
    Ok(())
}
