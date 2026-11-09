//! Value list references and availability checks.

use elasticctl_core::{Error, ErrorKind, Result, Transport, urlencode};
use serde_json::Value;

/// A stable value-list identity referenced by an exception item.
///
/// Unlike exception containers, a value list has no namespace in the public
/// lookup API. Its caller-supplied `id` is therefore the whole identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ValueListRef {
    pub id: String,
}
/// Whether the value-list data streams (`.lists-default`, `.items-default`)
/// are bootstrapped.
///
/// `GET /api/lists/index` answers 404 when they are not, so a 404 is the
/// absent case rather than an error (spec 7.7). Only a status outside the
/// success range other than 404 is returned as an error. `pub(crate)` because
/// it is shared by `doctor` and the push preview, not part of the public API.
pub(crate) async fn value_lists_bootstrapped(t: &Transport) -> Result<bool> {
    match t.get("/api/lists/index").await {
        Ok(body) => {
            let object = body.as_object();
            let list_index = object
                .and_then(|value| value.get("list_index"))
                .and_then(Value::as_bool)
                .ok_or_else(|| value_list_index_field_error("list_index"))?;
            let list_item_index = object
                .and_then(|value| value.get("list_item_index"))
                .and_then(Value::as_bool)
                .ok_or_else(|| value_list_index_field_error("list_item_index"))?;
            Ok(list_index && list_item_index)
        }
        Err(e) if e.kind == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn value_list_index_field_error(field: &str) -> Error {
    Error::new(
        ErrorKind::Http,
        format!("invalid value-list index response field {field}: expected a boolean"),
    )
}

/// Whether a value list with caller-supplied stable `id` exists.
///
/// The public route's successful response shape is server-owned and may grow,
/// so the status alone is the contract. Only the measured 404 means absence.
pub(crate) async fn value_list_exists(t: &Transport, id: &str) -> Result<bool> {
    match t.get(&format!("/api/lists?id={}", urlencode(id))).await {
        Ok(_) => Ok(true),
        Err(e) if e.kind == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elasticctl_core::Profile;
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn transport(server: &MockServer) -> Transport {
        Transport::new(&Profile {
            kibana_url: server.uri(),
            es_url: None,
            api_key: Some("essu_test".into()),
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 5,
        })
        .unwrap()
    }

    /// A successful lookup confirms the requested stable value-list id exists,
    /// even when the server returns extra document fields.
    #[tokio::test]
    async fn value_list_lookup_accepts_any_successful_response_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/lists"))
            .and(query_param("id", "ip-allowlist"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "ip-allowlist", "extra": {"server": "owned"}
            })))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            value_list_exists(&transport(&server), "ip-allowlist")
                .await
                .unwrap()
        );
    }

    /// The measured 404 is the only absence signal; it must not be conflated
    /// with authentication, validation, rate-limit, or server errors.
    #[tokio::test]
    async fn value_list_lookup_treats_only_not_found_as_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/lists"))
            .and(query_param("id", "missing"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "message": "value list is absent"
            })))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            !value_list_exists(&transport(&server), "missing")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn value_list_lookup_propagates_classified_errors_after_transport_retries() {
        for (status, kind, expected_requests) in [
            (400, ErrorKind::Http, 1),
            (403, ErrorKind::Permission, 1),
            (429, ErrorKind::Http, 3),
            (500, ErrorKind::Http, 3),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/lists"))
                .and(query_param("id", "broken"))
                .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                    "message": format!("HTTP {status}")
                })))
                .expect(expected_requests)
                .mount(&server)
                .await;

            let err = value_list_exists(&transport(&server), "broken")
                .await
                .unwrap_err();
            assert_eq!(err.kind, kind, "HTTP {status}");
            assert_eq!(err.http_status, Some(status), "HTTP {status}");
        }
    }
}
