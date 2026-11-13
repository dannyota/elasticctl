use crate::context::Context;
use elasticctl_api::health;
use elasticctl_core::Result;
use serde_json::{Value, json};

pub async fn run(ctx: &Context) -> Result<Value> {
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    let report = health::info(t).await?;

    Ok(json!({
        "elasticctl_version": env!("CARGO_PKG_VERSION"),
        "profile": ctx.resolved.name,
        "kibana_url": ctx.resolved.profile.kibana_url,
        "space": ctx.resolved.profile.space,
        "spaces": report.spaces,
        "flavor": report.flavor,
        "stack_version": report.version,
        "license_tier": report.license,
    }))
}
