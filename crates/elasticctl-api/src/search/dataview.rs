//! Kibana data-view resolution and the default alerts index.

use crate::data_views_ops;
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::Value;

/// Match a `GET /api/data_views` body to one data view by `id` or `name`
/// (exact), returning its `title` (the comma-separated index pattern).
pub fn resolve_title(body: &Value, name: &str) -> Result<String> {
    Ok(data_views_ops::resolve_from_body(body, name)?.title)
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
