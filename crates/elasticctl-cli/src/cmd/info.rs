use crate::context::Context;
use elasticctl_core::Result;
use elasticctl_core::capabilities::{probe_license_tier, probe_spaces};
use serde_json::{Value, json};

pub async fn run(ctx: &Context) -> Result<Value> {
    // A live connection is required below; check the credential first so a
    // missing one produces its profile-naming message, not the generic one
    // `Transport::new` would give.
    ctx.require_credential()?;
    let caps = ctx.capabilities().await?;
    let transport = ctx.transport().await?;

    // Probed here rather than in `Capabilities`, because `info` is the only
    // command that reports them and every other caller of the capability probe
    // would otherwise pay two round trips for fields it never prints. Either
    // may come back `None`, which reports as null: unknown is the honest
    // answer, and a hardcoded value that happens to be right on one flavor is
    // what this replaces.
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
