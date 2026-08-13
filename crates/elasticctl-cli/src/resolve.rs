//! Turning a user-facing selector into the stable rule_id.
//!
//! The resolution itself lives in `elasticctl_api::selection`, so that every
//! command answering "which rules?" — export, delete, enable, and the state
//! commands — answers it the same way. What stays here is the `Context` shim:
//! `-api` takes a `Transport`, and the CLI holds a `Context`.

use crate::context::Context;
use elasticctl_api::selection;
use elasticctl_core::Result;

pub(crate) use elasticctl_api::selection::UNREADABLE_RULE_ID;

/// A selector is a rule_id or a display name, resolved against the stack.
pub async fn to_rule_id(ctx: &Context, selector: &str) -> Result<String> {
    let transport = ctx.transport().await?;
    selection::to_rule_id(transport, selector).await
}
