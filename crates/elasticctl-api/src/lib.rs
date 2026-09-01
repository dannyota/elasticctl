#![forbid(unsafe_code)]

pub mod alerts;
pub mod codec;
pub mod diff;
pub mod exceptions;
pub mod health;
pub mod model;
pub mod normalize;
pub mod ops;
pub mod prebuilt;
pub mod report;
pub mod rules;
pub mod rules_ops;
pub mod search;
pub mod selection;
pub mod state;

pub use alerts::{AlertHit, AlertPage, AlertStatus, Conflicts, SignalsOutcome};
pub use codec::Format;
pub use diff::{Change, Drift, FieldChange};
pub use exceptions::{ListDetail, ListFilter, ListReport};
pub use health::{DoctorCheck, DoctorReport, InfoReport, Status};
pub use model::{
    COMMENT_VOLATILE_FIELDS, ExceptionItem, ExceptionList, ExceptionRef, ExportSummary,
    ITEM_VOLATILE_FIELDS, LIST_VOLATILE_FIELDS, ListKey, Rule, VOLATILE_FIELDS, exception_refs,
    server_defaults,
};
pub use normalize::{canonical, comparable, sort_rules};
pub use ops::{DeleteOutcome, ExportOutcome, ImportPlan, ImportReport, MutationPlan};
pub use prebuilt::{PrebuiltInstallOutcome, PrebuiltStatus};
pub use report::{ChangeReport, ReportEntry};
pub use rules::{BulkAction, BulkOutcome, RuleFilter, RuleSource};
pub use rules_ops::{PreviewReport, RuleListReport, SetEnabledOutcome, ValidateReport};
pub use state::{
    DanglingPointer, DiffReport, ExceptionDrift, ListChange, PullReport, PushPlan, PushReport,
};
