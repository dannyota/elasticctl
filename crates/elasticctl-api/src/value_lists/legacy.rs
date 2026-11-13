use elasticctl_core::{ErrorKind, Result, Transport, urlencode};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ValueListRef {
    pub id: String,
}
pub(crate) async fn value_lists_bootstrapped(t: &Transport) -> Result<bool> {
    Ok(super::bootstrap_state(t).await?.ready())
}

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
