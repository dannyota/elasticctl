//! Forms and answers on the client confirmation channel.
use super::audit::Answer;
use rmcp::model::{ElicitRequestParams, ElicitResult, ElicitationAction, ElicitationSchema};
use serde_json::Value;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
pub(crate) const LEGACY_CONFIRM_WAIT: Duration = Duration::from_secs(240);
static WAITING: AtomicBool = AtomicBool::new(false);
pub(crate) struct LegacyWait;
impl LegacyWait {
    pub(crate) fn take() -> Option<Self> {
        WAITING
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| Self)
    }
}
impl Drop for LegacyWait {
    fn drop(&mut self) {
        WAITING.store(false, Ordering::SeqCst);
    }
}
pub(crate) fn form(message: String) -> ElicitRequestParams {
    ElicitRequestParams::FormElicitationParams {
        meta: None,
        message,
        requested_schema: ElicitationSchema::builder()
            .required_bool_property("apply", |b| {
                b.title("Apply this change")
                    .description("True applies the change shown above. False keeps the dry run.")
                    .with_default(false)
            })
            .build()
            .expect("static form schema"),
    }
}
pub(crate) fn answer(value: Option<&Value>) -> Answer {
    let result = value.and_then(|v| serde_json::from_value::<ElicitResult>(v.clone()).ok());
    match result {
        Some(r) if r.action == ElicitationAction::Decline => Answer::Declined,
        Some(r)
            if r.action == ElicitationAction::Accept
                && r.content.as_ref().and_then(|v| v.get("apply")) == Some(&Value::Bool(true)) =>
        {
            Answer::Confirmed
        }
        _ => Answer::NotConfirmed,
    }
}
#[cfg(test)]
pub(crate) mod tests {
    // Legacy confirmation has one process-wide slot.
    pub(crate) static LEGACY_SESSION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[test]
    fn production_wait_is_240_seconds() {
        assert_eq!(super::LEGACY_CONFIRM_WAIT.as_secs(), 240);
    }
}
