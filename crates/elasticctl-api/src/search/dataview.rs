//! Kibana data-view resolution and the default alerts index.

use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::Value;

/// Match a `GET /api/data_views` body to one data view by `id` or `name`
/// (exact), returning its `title` (the comma-separated index pattern).
pub fn resolve_title(body: &Value, name: &str) -> Result<String> {
    let views = body
        .get("data_view")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                "decoding data views response field `data_view`",
            )
        })?;
    let matches: Vec<&Value> = views
        .iter()
        .filter(|v| {
            v.get("id").and_then(Value::as_str) == Some(name)
                || v.get("name").and_then(Value::as_str) == Some(name)
        })
        .collect();
    match matches.as_slice() {
        [] => Err(Error::new(
            ErrorKind::NotFound,
            format!("no data view with id or name '{name}'"),
        )),
        [one] => one
            .get("title")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error::new(ErrorKind::Http, "decoding data view field `title`")),
        _ => Err(Error::new(
            ErrorKind::Conflict,
            format!("data view '{name}' is ambiguous"),
        )),
    }
}

/// Resolve a data view over the wire.
pub async fn resolve(t: &Transport, name: &str) -> Result<String> {
    let body = t.get("/api/data_views").await?;
    resolve_title(&body, name)
}

/// The space's default alerts index, from `GET /api/detection_engine/index`.
pub async fn default_alerts_index(t: &Transport) -> Result<String> {
    let body = t.get("/api/detection_engine/index").await?;
    body.get("name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Http,
                "decoding detection engine index field `name`",
            )
        })
}
