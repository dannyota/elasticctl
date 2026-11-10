use super::*;
pub(super) fn definition() -> Tool {
    Tool::new(
        "rule_readiness",
        "Read-only composition report.",
        serde_json::json!({"type":"object","properties":{},"additionalProperties":false})
            .as_object()
            .unwrap()
            .clone(),
    )
    // Every catalog entry declares an object output schema; the tool's own
    // schema replaces this one when the tool is implemented.
    .with_raw_output_schema(std::sync::Arc::new(
        serde_json::json!({"type":"object"})
            .as_object()
            .unwrap()
            .clone(),
    ))
    .with_annotations(
        ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(true),
    )
}
pub(super) async fn call(
    arguments: Option<&JsonObject>,
    _state: &ServerState,
    _cancellation: CancellationToken,
) -> Result<AdapterResult, AdapterError> {
    // The input schema is a closed empty object.
    if arguments.is_some_and(|arguments| !arguments.is_empty()) {
        return Err(AdapterError::InvalidArgument);
    }
    Err(AdapterError::Core(Error::new(
        ErrorKind::Unsupported,
        "not implemented",
    )))
}
