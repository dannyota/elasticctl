pub(crate) mod apply;
pub(crate) mod audit;
pub(crate) mod confirm;
pub(crate) mod consent;
pub(crate) mod hash;
pub(crate) mod kind;
pub(crate) mod store;
pub(crate) mod view;

#[allow(dead_code)]
pub(crate) const MAX_OPEN_PLANS: usize = 8;
#[allow(dead_code)]
pub(crate) const MAX_FINAL_RECORDS: usize = 32;
#[allow(dead_code)]
pub(crate) const PLAN_LIFE_SECS: u64 = 900;
#[allow(dead_code)]
pub(crate) const MAX_OBJECTS_PER_PLAN: usize = 20;
#[allow(dead_code)]
pub(crate) const MAX_PLAN_BODY_BYTES: usize = 262_144;
#[allow(dead_code)]
pub(crate) const MAX_CONSENT_TEXT_BYTES: usize = 8_192;
#[allow(dead_code)]
pub(crate) const MAX_PROMPTS_PER_PLAN: u8 = 3;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlanError {
    NotFound,
    Expired,
    Stale,
    Declined,
    Discarded,
    NotOpen,
    TooLarge,
    TooManyPlans,
    NotConfirmed,
    ConfirmationUnavailable,
    ConfirmationPending,
    ConfirmationTimeout,
    CredentialUnsuitable,
    CaseSyncAlerts,
    ApplyPending,
    ApplyOutcomeUnknown(elasticctl_core::ErrorKind),
    InvalidArgument,
    Randomness,
}
#[allow(dead_code)]
impl PlanError {
    pub(crate) fn tool_error(self) -> crate::ToolError {
        let (code, kind, message) = match self {
            Self::NotFound => (
                "plan_not_found",
                "not_found",
                "No plan with that id in this process.",
            ),
            Self::Expired => ("plan_expired", "conflict", "The plan's life ended."),
            Self::Stale => (
                "plan_stale",
                "conflict",
                "The target changed after the plan was made.",
            ),
            Self::Declined => (
                "plan_declined",
                "permission",
                "The plan was declined and closed.",
            ),
            Self::Discarded => ("plan_discarded", "conflict", "The plan was discarded."),
            Self::NotOpen => ("plan_not_open", "conflict", "The plan is not open."),
            Self::TooLarge => (
                "plan_too_large",
                "unsupported",
                "The plan or its consent text exceeds a limit.",
            ),
            Self::TooManyPlans => (
                "too_many_plans",
                "error",
                "Eight plans are open or applying.",
            ),
            Self::NotConfirmed => (
                "not_confirmed",
                "permission",
                "The form was not accepted with apply: true.",
            ),
            Self::ConfirmationUnavailable => (
                "confirmation_unavailable",
                "unsupported",
                "The client cannot show a form.",
            ),
            Self::ConfirmationPending => (
                "confirmation_pending",
                "error",
                "Another confirmation is waiting.",
            ),
            Self::ConfirmationTimeout => (
                "confirmation_timeout",
                "timeout",
                "No confirmation answer arrived in time.",
            ),
            Self::CredentialUnsuitable => (
                "credential_unsuitable",
                "permission",
                "The credential's realm cannot perform this kind.",
            ),
            Self::CaseSyncAlerts => (
                "case_sync_alerts",
                "unsupported",
                "The case syncAlerts setting must be false.",
            ),
            Self::ApplyPending => (
                "apply_pending",
                "timeout",
                "The write was sent and its answer is pending.",
            ),
            Self::ApplyOutcomeUnknown(kind) => (
                "apply_outcome_unknown",
                kind.as_str(),
                "The write was sent and its result is unknown.",
            ),
            Self::InvalidArgument => (
                "invalid_argument",
                "error",
                "The tool arguments are invalid.",
            ),
            Self::Randomness => ("elastic_error", "error", "OS randomness is unavailable."),
        };
        crate::ToolError {
            kind: kind.into(),
            http_status: None,
            code: code.into(),
            message: message.into(),
        }
    }
}
