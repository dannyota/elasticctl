#![forbid(unsafe_code)]

pub mod codec;
pub mod diff;
pub mod exceptions;
pub mod health;
pub mod model;
pub mod normalize;
pub mod ops;
pub mod report;
pub mod rules;
pub mod rules_ops;
pub mod selection;
pub mod state;

pub use codec::Format;
pub use diff::{Change, Drift, FieldChange};
pub use exceptions::ListFilter;
pub use health::{DoctorCheck, DoctorReport, InfoReport, Status};
pub use model::{
    COMMENT_VOLATILE_FIELDS, ExceptionItem, ExceptionList, ExceptionRef, ExportSummary,
    ITEM_VOLATILE_FIELDS, LIST_VOLATILE_FIELDS, ListKey, Rule, VOLATILE_FIELDS, exception_refs,
    server_defaults,
};
pub use normalize::{canonical, comparable, sort_rules};
pub use ops::{ExportOutcome, MutationPlan};
pub use report::{ChangeReport, ReportEntry};
pub use rules::{BulkAction, BulkOutcome, RuleFilter};
pub use rules_ops::{
    DeleteOutcome, ImportPlan, ImportReport, PreviewReport, RuleListReport, SetEnabledOutcome,
    ValidateReport,
};
pub use state::{DiffReport, PullReport, PushPlan, PushReport};
