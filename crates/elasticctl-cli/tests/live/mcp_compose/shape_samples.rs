use serde_json::{Value, json};

pub(crate) fn error(kind: &str, status: Option<u16>, message: &str) -> Value {
    json!({"kind": kind, "http_status": status, "code": format!("elastic_{kind}"), "message": message})
}

pub(crate) fn not_found() -> Value {
    error(
        "not_found",
        Some(404),
        "The selected resource was not found.",
    )
}

pub(crate) fn alert(id: &str, rule_id: &str, rule_name: &str) -> Value {
    json!({"id": id, "index": ".internal.alerts-security.alerts-default-000001", "source": {
        "@timestamp": "2026-11-10T03:00:00.000Z",
        "kibana.alert.rule.rule_id": rule_id,
        "kibana.alert.rule.name": rule_name,
        "kibana.alert.severity": "low",
        "kibana.alert.risk_score": 21,
        "kibana.alert.workflow_status": "open",
    }})
}

pub(crate) fn rule(rule_id: &str, name: &str, enabled: bool, lists: &[&str]) -> Value {
    json!({
        "rule_id": rule_id, "name": name, "type": "query", "enabled": enabled,
        "severity": "low", "risk_score": 21, "tags": ["elasticctl-live-marker"],
        "language": "kuery", "query": "marker: *", "index": ["elasticctl-live-index"],
        "from": "now-10m", "interval": "1m",
        "exceptions_list": lists.iter().map(|id| json!({"list_id": id, "namespace_type": "single", "type": "detection"})).collect::<Vec<_>>(),
        "execution": {"status": "succeeded", "date": "2026-11-10T03:00:00.000Z", "status_order": 0,
            "message": "Rule execution completed successfully", "message_truncated": false,
            "metrics": {"total_search_duration_ms": 12}},
    })
}

pub(crate) fn list_row(list_id: &str, items: u64) -> Value {
    json!({"list_id": list_id, "namespace_type": "single", "type": "detection", "status": "ok",
        "name": format!("{list_id} exception list"), "list_type": "detection", "item_count": items})
}

pub(crate) fn missing_list_row(list_id: &str) -> Value {
    json!({"list_id": list_id, "namespace_type": "single", "type": "detection",
        "status": "unavailable", "error": not_found()})
}

pub(crate) fn case_row(id: &str, title: &str) -> Value {
    json!({"id": id, "title": title, "status": "ok", "case": {
        "id": id, "title": title, "status": "open", "severity": "low",
        "tags": ["elasticctl-live-marker"], "description": "MCP smoke case",
        "created_at": "now", "updated_at": "now", "totalComment": 0,
    }})
}

pub(crate) fn activity(total: u64, recent: Option<Vec<Value>>) -> Value {
    let mut value = json!({"window": "24h", "total": total,
        "by_status": {"open": total, "acknowledged": 0, "closed": 0, "other": 0}});
    if let Some(recent) = recent {
        value["recent"] = Value::Array(recent);
    }
    value
}

pub(crate) fn ok(value: Value) -> Value {
    json!({"status": "ok", "value": value})
}

pub(crate) fn envelope(data: Value, page: Value) -> Value {
    json!({"target": {"profile": "default", "host": "kibana.example.test", "space": "default"},
        "data": data, "page": page})
}

pub(crate) fn coverage_page(limit: u64, returned: usize, total: u64) -> Value {
    let truncated = (returned as u64) < total;
    json!({"limit": limit, "returned": returned, "total": total,
        "has_more": truncated, "truncated": truncated})
}
