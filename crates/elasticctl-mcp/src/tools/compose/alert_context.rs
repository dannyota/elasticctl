use super::*;
pub(super) fn definition() -> Tool {
    placeholder_definition("alert_context")
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
