use super::*;

pub(super) fn capabilities(form: bool) -> Value {
    if form {
        json!({"elicitation":{"form":{}}})
    } else {
        json!({})
    }
}
pub(super) fn request(
    path: McpProtocolPath,
    id: u64,
    name: &str,
    args: Value,
    form: bool,
) -> Value {
    let mut params = json!({"name":name,"arguments":args});
    if matches!(path, McpProtocolPath::Current) {
        params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":capabilities(form)});
    }
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
}
pub(super) fn schema() -> Value {
    json!({"type":"object","properties":{"apply":{"type":"boolean","title":"Apply this change",
        "description":"True applies the change shown above. False keeps the dry run.","default":false}},"required":["apply"]})
}
pub(super) fn form(params: &Value) -> TestResult {
    require(
        params["mode"] == "form"
            && params["message"].is_string()
            && params["requestedSchema"] == schema(),
    )
}
pub(super) fn answer(question: &Value, accept: bool) -> TestResult<Value> {
    let r = &question["result"];
    require(
        r["resultType"] == "input_required"
            && r.get("structuredContent").is_none()
            && r["inputRequests"]["confirm"]["method"] == "elicitation/create",
    )?;
    form(&r["inputRequests"]["confirm"]["params"])?;
    let state = r["requestState"]
        .as_str()
        .ok_or("missing confirmation state")?;
    Ok(json!({"inputResponses":{"confirm":answer_content(accept)},"requestState":state}))
}
fn answer_content(accept: bool) -> Value {
    json!({"action":if accept {"accept"} else {"decline"},"content":{"apply":accept}})
}
pub(super) fn legacy_answer(id: Value, accept: bool) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":answer_content(accept)})
}
pub(super) fn content(mut frame: Value, path: McpProtocolPath) -> TestResult<Value> {
    mcp_smoke::normalize_protocol_result(&mut frame, path)?;
    require(frame.get("error").is_none())?;
    let content = frame
        .pointer("/result/structuredContent")
        .cloned()
        .ok_or("missing tool content")?;
    let text = frame
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .ok_or("missing tool text")?;
    let decoded: Value = serde_json::from_str(text).map_err(|_| "invalid tool text")?;
    require(decoded == content)?;
    Ok(content)
}
pub(super) fn plan_id(content: &Value) -> TestResult<String> {
    content
        .pointer("/data/plan/plan_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or("missing plan".into())
}
pub(super) fn code(content: &Value, expected: &str) -> TestResult {
    require(content.pointer("/error/code").and_then(Value::as_str) == Some(expected))
}
pub(super) fn applied(content: &Value, replayed: bool) -> TestResult {
    require(
        content.pointer("/data/plan/state") == Some(&json!("applied"))
            && content.pointer("/data/replayed") == Some(&json!(replayed)),
    )
}
