use crate::data_views_ops;
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::Value;

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

pub async fn resolve(t: &Transport, name: &str) -> Result<String> {
    let body = t.get("/api/data_views").await?;
    resolve_title(&body, name)
}

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
