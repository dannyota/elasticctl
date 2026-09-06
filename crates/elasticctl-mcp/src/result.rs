//! Shared structured tool result envelopes.

use rmcp::schemars::{self, JsonSchema};
use rmcp::{
    RoleServer,
    model::{CallToolResult, NumberOrString, ServerResult},
    service::TxJsonRpcMessage,
};
use serde::Serialize;

use crate::{
    bounded_io::{MAX_OUTPUT_FRAME_BYTES, MAX_STRUCTURED_CONTENT_BYTES},
    error::LocalError,
};

/// Target identity that may safely appear in MCP results.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct TargetContext {
    pub profile: String,
    pub host: String,
    pub space: String,
}

/// Paging metadata shared by list tools.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct PageInfo {
    pub limit: usize,
    pub returned: usize,
    pub total: Option<u64>,
    pub has_more: Option<bool>,
    pub truncated: bool,
}

/// A successful tool envelope.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ToolSuccess<T: JsonSchema> {
    pub target: TargetContext,
    pub data: T,
    pub page: Option<PageInfo>,
}

/// A caller-safe, classified tool error.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ToolError {
    pub kind: String,
    pub http_status: Option<u16>,
    pub code: String,
    pub message: String,
}

/// A failed tool envelope.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ToolFailure {
    pub target: TargetContext,
    pub error: ToolError,
}

/// Build a success result with identical structured and text representations.
pub(crate) fn success(
    target: TargetContext,
    data: serde_json::Value,
    page: Option<PageInfo>,
    request_id: &NumberOrString,
) -> std::result::Result<CallToolResult, LocalError> {
    result(
        serde_json::json!({ "target": target, "data": data, "page": page }),
        false,
        request_id,
    )
}

/// Build a caller-safe tool error result.
pub(crate) fn failure(
    target: TargetContext,
    error: ToolError,
    request_id: &NumberOrString,
) -> std::result::Result<CallToolResult, LocalError> {
    result(
        serde_json::json!({ "target": target, "error": error }),
        true,
        request_id,
    )
}

/// Build a list result, removing complete trailing rows until both copies of
/// the envelope fit. Callers keep their schema-specific rows under `row_key`.
#[allow(dead_code)] // List adapters call this once the foundation catalog gains rows.
pub(crate) fn success_with_truncated_rows(
    target: TargetContext,
    mut data: serde_json::Value,
    row_key: &str,
    mut page: PageInfo,
    request_id: &NumberOrString,
) -> std::result::Result<CallToolResult, LocalError> {
    let rows = std::mem::take(
        data.get_mut(row_key)
            .and_then(serde_json::Value::as_array_mut)
            .ok_or(LocalError::ResultTooLarge)?,
    );
    let row_count = rows.len();
    if row_count == 0 {
        page.returned = 0;
        if page.truncated {
            page.has_more = Some(true);
        }
        return success(target, data, Some(page), request_id);
    }
    if page.truncated {
        page.has_more = Some(true);
    }

    let mut low = 1;
    let mut high = row_count;
    let mut fitting = None;
    while low <= high {
        let middle = low + (high - low) / 2;
        *data
            .get_mut(row_key)
            .expect("row key was validated before truncation") =
            serde_json::Value::Array(rows[..middle].to_vec());
        let mut candidate_page = page.clone();
        candidate_page.returned = middle;
        if middle < row_count {
            candidate_page.truncated = true;
            candidate_page.has_more = Some(true);
        }
        match success(
            target.clone(),
            data.clone(),
            Some(candidate_page),
            request_id,
        ) {
            Ok(result) => {
                fitting = Some(result);
                low = middle + 1;
            }
            Err(_) => high = middle - 1,
        }
    }
    fitting.ok_or(LocalError::ResultTooLarge)
}

fn result(
    value: serde_json::Value,
    is_error: bool,
    request_id: &NumberOrString,
) -> std::result::Result<CallToolResult, LocalError> {
    let text = serde_json::to_string(&value).map_err(|_| LocalError::ResultTooLarge)?;
    if text.len() > MAX_STRUCTURED_CONTENT_BYTES {
        return Err(LocalError::ResultTooLarge);
    }
    let mut result = if is_error {
        CallToolResult::structured_error(value)
    } else {
        CallToolResult::structured(value)
    };
    result.is_error = Some(is_error);
    let frame = TxJsonRpcMessage::<RoleServer>::response(
        ServerResult::CallToolResult(result.clone()),
        request_id.clone(),
    );
    if serde_json::to_vec(&frame)
        .map_err(|_| LocalError::ResultTooLarge)?
        .len()
        > MAX_OUTPUT_FRAME_BYTES
    {
        return Err(LocalError::ResultTooLarge);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{PageInfo, TargetContext, success, success_with_truncated_rows};
    use crate::error::LocalError;
    use rmcp::model::NumberOrString;

    #[test]
    fn rejects_a_structured_result_before_it_can_overrun_the_frame() {
        let result = success(
            TargetContext {
                profile: "test".to_string(),
                host: "example.test".to_string(),
                space: "default".to_string(),
            },
            serde_json::json!({ "value": "x".repeat(262_145) }),
            None,
            &NumberOrString::Number(1),
        );
        assert_eq!(result, Err(LocalError::ResultTooLarge));
    }

    #[test]
    fn list_results_drop_only_complete_rows_to_fit_the_structured_limit() {
        let result = success_with_truncated_rows(
            TargetContext {
                profile: "test".to_string(),
                host: "example.test".to_string(),
                space: "default".to_string(),
            },
            serde_json::json!({ "rows": ["x".repeat(150_000), "x".repeat(150_000)] }),
            "rows",
            PageInfo {
                limit: 2,
                returned: 2,
                total: Some(2),
                has_more: Some(false),
                truncated: false,
            },
            &NumberOrString::Number(1),
        )
        .expect("one complete row fits");
        let structured = result.structured_content.expect("structured result");
        assert_eq!(
            structured["data"]["rows"]
                .as_array()
                .expect("rows array")
                .len(),
            1
        );
        assert_eq!(structured["page"]["returned"], 1);
        assert_eq!(structured["page"]["truncated"], true);
        assert_eq!(structured["page"]["has_more"], true);
    }

    #[test]
    fn list_with_no_fitting_row_returns_result_too_large() {
        let result = success_with_truncated_rows(
            TargetContext {
                profile: "test".to_string(),
                host: "example.test".to_string(),
                space: "default".to_string(),
            },
            serde_json::json!({ "rows": ["x".repeat(262_145)] }),
            "rows",
            PageInfo {
                limit: 1,
                returned: 1,
                total: Some(1),
                has_more: Some(false),
                truncated: false,
            },
            &NumberOrString::Number(1),
        );
        assert_eq!(result, Err(LocalError::ResultTooLarge));
    }
}
