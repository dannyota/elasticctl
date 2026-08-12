#![forbid(unsafe_code)]

pub mod codec;
pub mod diff;
pub mod model;
pub mod normalize;
pub mod rules;

pub use codec::Format;
pub use diff::{Change, Drift, FieldChange};
pub use model::{ExportSummary, Rule, VOLATILE_FIELDS, server_defaults};
pub use normalize::{canonical, comparable, sort_rules};
pub use rules::{BulkAction, BulkOutcome, RuleFilter};
