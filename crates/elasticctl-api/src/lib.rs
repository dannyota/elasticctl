#![forbid(unsafe_code)]

pub mod codec;
pub mod diff;
pub mod model;
pub mod normalize;
pub mod report;
pub mod rules;
pub mod selection;

pub use codec::Format;
pub use diff::{Change, Drift, FieldChange};
pub use model::{ExportSummary, Rule, VOLATILE_FIELDS, server_defaults};
pub use normalize::{canonical, comparable, sort_rules};
pub use report::{ChangeReport, ReportEntry};
pub use rules::{BulkAction, BulkOutcome, RuleFilter};
