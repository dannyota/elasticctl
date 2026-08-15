//! Report types shared across command verticals.
//!
//! A type lives here because more than one vertical consumes it; per-command
//! outcome shapes deliberately do not. Field order is the serialized JSON key
//! order and is contractual: the root `Cargo.toml` enables `serde_json`'s
//! `preserve_order`, so reordering these fields would silently change rendered
//! output.

use elasticctl_core::{Error, ErrorKind, Result};
use serde::Serialize;
use serde_json::{Value, json};

/// What a guarded mutation will do, shown in the guard banner.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MutationPlan {
    pub preview_action: String,
    pub preview_details: Vec<String>,
    /// Object identities the plan will act on: `rule_id` values in the rules
    /// vertical; `list_id` and `item_id` values in the exceptions vertical.
    pub targets: Vec<String>,
}

/// A file-producing export: the encoded body and its counts.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportOutcome {
    pub body: String,
    pub exported: u64,
    pub missing: Vec<Value>,
}

/// The report a `delete` apply renders. Shared by the rules and exceptions
/// verticals: each reports the same applied/deleted/failed/total shape, only
/// the per-object entries differ (`rule_id` versus `list_id`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeleteOutcome {
    pub applied: bool,
    pub deleted: Vec<Value>,
    pub failed: Vec<Value>,
    pub total: usize,
}

/// What `plan_import` computed and `apply_import` uploads. Shared by the rules
/// and exceptions verticals: the plan, the re-encoded NDJSON, the in-file
/// object count, and the objects `--skip-existing` removed.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportPlan {
    pub preview: MutationPlan,
    /// The file re-encoded as NDJSON, resolved once at plan time so the apply
    /// never re-reads the file after the guard.
    pub ndjson: String,
    /// Every object in the file, before `--skip-existing`.
    pub total: usize,
    /// Objects the server already has, with `--skip-existing`.
    pub skipped: Vec<Value>,
}

/// The upload half of an import, before the caller adds the plan's totals.
/// Shared by the rules and exceptions verticals: both normalize Kibana's
/// import response to a succeeded count and an errors array.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportReport {
    pub succeeded: Value,
    pub failed: Value,
}

/// Decode an import response into a normalized report, refusing a malformed
/// success body.
///
/// `context` names the vertical for the error message ("rules" or
/// "exceptions"). A missing or mistyped `success_count` or `errors` must fail
/// rather than read as "nothing was imported".
pub(crate) fn decode_import_report(body: &Value, context: &str) -> Result<ImportReport> {
    let map = body
        .as_object()
        .ok_or_else(|| import_error(context, "response", "must be a JSON object"))?;
    let success_count = map
        .get("success_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| import_error(context, "success_count", "must be an unsigned integer"))?;
    let errors = map
        .get("errors")
        .and_then(Value::as_array)
        .ok_or_else(|| import_error(context, "errors", "must be an array"))?;
    Ok(ImportReport {
        succeeded: json!(success_count),
        failed: Value::Array(errors.clone()),
    })
}

fn import_error(context: &str, field: &str, detail: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorKind::Http,
        format!("decoding {context} import response field {field}: {detail}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use elasticctl_core::ErrorKind;
    use serde_json::json;

    #[test]
    fn import_report_rejects_missing_or_wrongly_typed_fields() {
        for body in [
            json!({}),
            json!({"success_count": "1", "errors": []}),
            json!({"success_count": 1}),
            json!({"success_count": 1, "errors": "not-an-array"}),
        ] {
            let error = decode_import_report(&body, "rules").unwrap_err();
            assert_eq!(error.kind, ErrorKind::Http);
        }
    }

    #[test]
    fn import_report_accepts_a_valid_response() {
        let report = decode_import_report(
            &json!({"success_count": 2, "errors": [{"message": "x"}]}),
            "rules",
        )
        .unwrap();
        assert_eq!(report.succeeded, json!(2));
        assert_eq!(report.failed, json!([{"message": "x"}]));
    }
}
