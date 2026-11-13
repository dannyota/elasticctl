use elasticctl_core::{Error, ErrorKind, Result, Transport, urlencode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Container, StoredValues, ValueListType, canonical_value};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootstrapState {
    pub list_index: bool,
    pub list_item_index: bool,
}

impl BootstrapState {
    pub fn ready(self) -> bool {
        self.list_index && self.list_item_index
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RemoteContainer {
    pub container: Container,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RemoteList {
    pub container: RemoteContainer,
    pub stored: StoredValues,
}

pub(super) fn malformed(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Http, message)
}

pub(super) fn required_string<'a>(body: &'a Value, field: &str) -> Result<&'a str> {
    body.get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            malformed(format!(
                "invalid value-list response field {field}: expected a non-empty string"
            ))
        })
}

pub(super) fn response_error(status: u16, body: &Value) -> Error {
    Error::from_response_body(status, body.as_str().unwrap_or(&body.to_string()))
}

pub async fn bootstrap_state(t: &Transport) -> Result<BootstrapState> {
    let (status, body) = t.get_response("/api/lists/index").await?;
    if status == 404 {
        return Ok(BootstrapState::default());
    }
    if status >= 400 {
        return Err(response_error(status, &body));
    }
    for field in ["list_index", "list_item_index"] {
        if !body.get(field).is_some_and(Value::is_boolean) {
            return Err(malformed(format!(
                "invalid value-list index response field {field}: expected a boolean"
            )));
        }
    }
    serde_json::from_value(body)
        .map_err(|e| malformed(format!("invalid value-list index response: {e}")))
}

pub async fn require_bootstrapped(t: &Transport) -> Result<()> {
    if !bootstrap_state(t).await?.ready() {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "value-list streams are not bootstrapped; run elasticctl value-lists init",
        ));
    }
    Ok(())
}

pub fn decode_remote_container(body: &Value) -> Result<RemoteContainer> {
    let container = Container {
        id: required_string(body, "id")?.into(),
        list_type: required_string(body, "type")?.to_owned().into(),
        name: body
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("invalid value-list name"))?
            .into(),
        description: body
            .get("description")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("invalid value-list description"))?
            .into(),
        meta: match body.get("meta") {
            Some(Value::Object(meta)) => Some(meta.clone()),
            None => None,
            Some(_) => return Err(malformed("invalid value-list meta: expected an object")),
        },
    };
    Ok(RemoteContainer {
        container,
        version: required_string(body, "_version")?.into(),
    })
}

async fn fetch_container(t: &Transport, id: &str) -> Result<Option<RemoteContainer>> {
    let (status, body) = t
        .get_response(&format!("/api/lists?id={}", urlencode(id)))
        .await?;
    if status == 404 {
        return Ok(None);
    }
    if status >= 400 {
        return Err(response_error(status, &body));
    }
    Ok(Some(decode_remote_container(&body)?))
}

pub async fn read_container(t: &Transport, id: &str) -> Result<Option<RemoteContainer>> {
    let Some(remote) = fetch_container(t, id).await? else {
        return Ok(None);
    };
    if remote.container.id != id {
        return Err(malformed(format!(
            "requested value list {id:?}, received {:?}",
            remote.container.id
        )));
    }
    Ok(Some(remote))
}

pub fn decode_export(kind: &ValueListType, text: &str) -> Result<StoredValues> {
    kind.require_supported()?;
    let mut values = Vec::new();
    for (index, value) in text.split_terminator('\n').enumerate() {
        if value.is_empty()
            || value.chars().any(char::is_control)
            || value.trim_matches([' ', '\t']) != value
        {
            return Err(malformed(format!(
                "invalid value-list export line {}",
                index + 1
            )));
        }
        canonical_value(kind, value).map_err(|e| {
            malformed(format!(
                "invalid value-list export line {}: {}",
                index + 1,
                e.message
            ))
        })?;
        values.push(value.to_owned());
    }
    Ok(StoredValues::new(values))
}

pub async fn export_values(t: &Transport, id: &str, kind: &ValueListType) -> Result<StoredValues> {
    let text = t
        .post_text(
            &format!("/api/lists/items/_export?list_id={}", urlencode(id)),
            None,
        )
        .await?;
    decode_export(kind, &text)
}

pub async fn read_list(t: &Transport, id: &str) -> Result<Option<RemoteList>> {
    let Some(container) = read_container(t, id).await? else {
        return Ok(None);
    };
    let stored = export_values(t, id, &container.container.list_type).await?;
    Ok(Some(RemoteList { container, stored }))
}

pub(super) async fn find_cursor(t: &Transport, base: &str, per_page: u32) -> Result<Vec<Value>> {
    if per_page == 0 {
        return Err(super::invalid("per_page must be positive"));
    }
    let mut out = Vec::new();
    let mut page = 1u64;
    let mut cursor: Option<String> = None;
    let mut expected_total = None;
    loop {
        let separator = if base.contains('?') { '&' } else { '?' };
        let mut path = format!("{base}{separator}page={page}&per_page={per_page}");
        if let Some(cursor) = &cursor {
            path.push_str(&format!("&cursor={}", urlencode(cursor)));
        }
        let body = t.get(&path).await?;
        let total = body
            .get("total")
            .and_then(Value::as_u64)
            .ok_or_else(|| malformed("invalid value-list _find total"))?;
        if expected_total.is_some_and(|expected| expected != total) {
            return Err(malformed("value-list _find total changed during read"));
        }
        expected_total = Some(total);
        let data = body
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("invalid value-list _find data"))?;
        if body.get("page").and_then(Value::as_u64) != Some(page)
            || body.get("per_page").and_then(Value::as_u64) != Some(u64::from(per_page))
            || data.len() > per_page as usize
            || out.len() as u64 + data.len() as u64 > total
        {
            return Err(malformed("invalid value-list _find page"));
        }
        let empty = data.is_empty();
        out.extend(data.iter().cloned());
        if out.len() as u64 == total {
            return Ok(out);
        }
        if empty {
            return Err(malformed("refusing partial value-list _find read"));
        }
        cursor = Some(required_string(&body, "cursor")?.into());
        page += 1;
    }
}

pub async fn find_containers(
    t: &Transport,
    filter: Option<&str>,
    per_page: u32,
) -> Result<Vec<RemoteContainer>> {
    let mut path = "/api/lists/_find".to_owned();
    if let Some(filter) = filter {
        path.push_str(&format!("?filter={}", urlencode(filter)));
    }
    let mut containers: Vec<_> = find_cursor(t, &path, per_page)
        .await?
        .iter()
        .map(decode_remote_container)
        .collect::<Result<_>>()?;
    containers.sort_by(|a, b| a.container.id.cmp(&b.container.id));
    if containers
        .windows(2)
        .any(|pair| pair[0].container.id == pair[1].container.id)
    {
        return Err(malformed("duplicate container in value-list _find"));
    }
    Ok(containers)
}

pub(super) fn check_preview_container(
    id: &str,
    expected: Option<&RemoteContainer>,
    observed: Option<&RemoteContainer>,
) -> Result<()> {
    let unchanged = match (expected, observed) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.container.id == b.container.id
                && a.container.list_type == b.container.list_type
                && a.version == b.version
        }
        _ => false,
    };
    if !unchanged {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!("value list {id} container changed since preview; re-run"),
        ));
    }
    Ok(())
}

pub(super) async fn read_unchanged_list(
    t: &Transport,
    id: &str,
    before: Option<&RemoteList>,
) -> Result<Option<RemoteList>> {
    let container = fetch_container(t, id).await?;
    check_preview_container(id, before.map(|r| &r.container), container.as_ref())?;
    let Some(container) = container else {
        return Ok(None);
    };
    let stored = export_values(t, id, &container.container.list_type).await?;
    Ok(Some(RemoteList { container, stored }))
}
