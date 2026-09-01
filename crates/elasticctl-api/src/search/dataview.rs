//! Kibana data-view resolution and the default alerts index.

use crate::data_views_ops;
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
    let view = data_views_ops::select_by_id_or_name(
        views,
        name,
        |view| view.get("id").and_then(Value::as_str),
        |view| view.get("name").and_then(Value::as_str),
    )?;
    view.get("title")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::new(ErrorKind::Http, "decoding data view field `title`"))
}

/// Resolve a data view over the wire.
pub async fn resolve(t: &Transport, name: &str) -> Result<String> {
    Ok(data_views_ops::resolve(t, name).await?.title)
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
