use crate::context::Context;
use elasticctl_core::Result;
use serde_json::{Value, json};

pub async fn run(ctx: &Context) -> Result<Value> {
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
