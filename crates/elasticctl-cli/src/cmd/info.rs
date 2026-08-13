use crate::context::Context;
use elasticctl_core::Result;
use elasticctl_core::capabilities::{probe_license_tier, probe_spaces};
use serde_json::{Value, json};

pub async fn run(ctx: &Context) -> Result<Value> {
    // Check the credential first so a missing one names the profile instead
    // of returning Transport's generic error.
    ctx.require_credential()?;
    let caps = ctx.capabilities().await?;
    let transport = ctx.transport().await?;

    // Only `info` reports these values, so probing them here avoids two
    // requests for every other capability caller. `None` renders as null
    // because the value is unknown.
    let spaces = probe_spaces(transport).await;
    let license_tier = probe_license_tier(transport, caps.flavor).await;

    Ok(json!({
        "elasticctl_version": env!("CARGO_PKG_VERSION"),
        "profile": ctx.resolved.name,
        "kibana_url": ctx.resolved.profile.kibana_url,
        "space": ctx.resolved.profile.space,
        "spaces": spaces,
        "flavor": caps.flavor.as_str(),
        "stack_version": caps.version,
        "license_tier": license_tier,
    }))
}
