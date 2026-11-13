use elasticctl_core::{Error, ErrorKind, Result};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MutationPlan {
    pub preview_action: String,
    pub preview_details: Vec<String>,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportOutcome {
    pub body: String,
    pub exported: u64,
    pub missing: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeleteOutcome {
    pub applied: bool,
    pub deleted: Vec<Value>,
    pub failed: Vec<Value>,
    pub total: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImportPlan {
    pub preview: MutationPlan,
    pub ndjson: String,
    pub total: usize,
    pub skipped: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportReport {
    pub succeeded: Value,
    pub failed: Value,
}

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
            json!({"success_count": -1, "errors": []}),
            json!({"success_count": 1.5, "errors": []}),
            json!({"success_count": null, "errors": []}),
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
