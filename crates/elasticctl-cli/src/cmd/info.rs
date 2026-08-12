use crate::context::Context;
use elasticctl_core::Result;
use serde_json::{Value, json};

pub async fn run(ctx: &Context) -> Result<Value> {
    // A live connection is required below; check the credential first so a
    // missing one produces its profile-naming message, not the generic one
    // `Transport::new` would give.
    ctx.require_credential()?;
    let caps = ctx.capabilities().await?;
    Ok(json!({
        "elasticctl_version": env!("CARGO_PKG_VERSION"),
        "profile": ctx.resolved.name,
        "kibana_url": ctx.resolved.profile.kibana_url,
        "space": ctx.resolved.profile.space,
        "flavor": caps.flavor.as_str(),
        "stack_version": caps.version,
        "license_tier": caps.license_tier,
    }))
}
