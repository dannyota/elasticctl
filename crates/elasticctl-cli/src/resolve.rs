//! Resolve a user-facing selector to a stable rule ID.
//!
//! `elasticctl_api::selection` provides shared resolution for every command.
//! This module adapts the CLI's `Context` to the API's `Transport`.

use crate::context::Context;
use elasticctl_api::selection;
use elasticctl_core::Result;

pub(crate) use elasticctl_api::selection::UNREADABLE_RULE_ID;

/// Resolve a rule ID or display name against the stack.
pub async fn to_rule_id(ctx: &Context, selector: &str) -> Result<String> {
    let transport = ctx.transport().await?;
    selection::to_rule_id(transport, selector).await
}
