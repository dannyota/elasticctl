use super::{API_VERSION, CAPTURED_HEADERS, Responded, Transport, parse_response_json};
use crate::error::{Error, ErrorKind, Result};
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

impl Transport {
    /// Read a response body without retrying an operation that may have
    /// completed after its headers were received.
    async fn response_text(
        &self,
        method: &Method,
        url: &str,
        mut response: Response,
    ) -> Result<String> {
        if let Some(limit) = self.response_body_limit {
            if response
                .content_length()
                .is_some_and(|length| usize::try_from(length).map_or(true, |length| length > limit))
            {
                return Err(Self::response_limit_error());
            }

            let mut bytes = Vec::new();
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) => {
                        let length = bytes
                            .len()
                            .checked_add(chunk.len())
                            .ok_or_else(Self::response_limit_error)?;
                        if length > limit {
                            return Err(Self::response_limit_error());
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    Ok(None) => return Ok(String::from_utf8_lossy(&bytes).into_owned()),
                    Err(e) if e.is_timeout() => {
                        self.debug_failure(method, url, "timeout");
                        return Err(Error::new(
                            ErrorKind::Timeout,
                            format!("request timed out while reading response body: {e}"),
                        ));
                    }
                    Err(e) => {
                        self.debug_failure(method, url, "connection error");
                        return Err(Error::new(
                            ErrorKind::Connection,
                            format!("request failed while reading response body: {e}"),
                        ));
                    }
                }
            }
        }

        match response.text().await {
            Ok(text) => Ok(text),
            Err(e) if e.is_timeout() => {
                self.debug_failure(method, url, "timeout");
                Err(Error::new(
                    ErrorKind::Timeout,
                    format!("request timed out while reading response body: {e}"),
                ))
            }
            Err(e) => {
                self.debug_failure(method, url, "connection error");
                Err(Error::new(
                    ErrorKind::Connection,
                    format!("request failed while reading response body: {e}"),
                ))
            }
        }
    }

    fn response_limit_error() -> Error {
        Error::new(
            ErrorKind::Unsupported,
            "response body exceeds configured byte limit",
        )
    }

    async fn send_retrying<F>(
        &self,
        method: Method,
        url: &str,
        attempt_limit: u32,
        build: F,
    ) -> Result<Response>
    where
        F: FnMut() -> Result<reqwest::RequestBuilder>,
    {
        self.send_retrying_with_client_errors(method, url, attempt_limit, false, build)
            .await
    }

    async fn send_retrying_with_client_errors<F>(
        &self,
        method: Method,
        url: &str,
        attempt_limit: u32,
        return_client_errors: bool,
        mut build: F,
    ) -> Result<Response>
    where
        F: FnMut() -> Result<reqwest::RequestBuilder>,
    {
        let mut attempt = 0;

        loop {
            attempt += 1;
            let req = build()?;

            self.debug_request(&method, url, attempt);
            let result = req.send().await;

            let response = match result {
                Ok(r) => r,
                Err(e) if e.is_timeout() => {
                    self.debug_failure(&method, url, "timeout");
                    return Err(Error::new(
                        ErrorKind::Timeout,
                        format!("request timed out: {e}"),
                    ));
                }
                Err(e) => {
                    self.debug_failure(&method, url, "connection error");
                    return Err(Error::new(
                        ErrorKind::Connection,
                        format!("request failed: {e}"),
                    ));
                }
            };

            let status = response.status();
            self.debug_log(&method, url, status.as_u16(), attempt);
            if status.is_success() || (return_client_errors && status.is_client_error()) {
                return Ok(response);
            }

            // Retry transient failures only. Retrying a 4xx repeats the same
            // caller error.
            let transient = status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
            if transient && attempt < attempt_limit {
                // A configured limit applies to error bodies too. Read the
                // body before deciding to retry so an over-limit response is
                // rejected rather than replayed.
                if self.response_body_limit.is_some() {
                    self.response_text(&method, url, response).await?;
                }
                let backoff = Duration::from_millis(200 * 2u64.pow(attempt - 1));
                tokio::time::sleep(backoff).await;
                continue;
            }

            let code = status.as_u16();
            let text = self.response_text(&method, url, response).await?;
            return Err(Error::from_response_body(code, &text));
        }
    }

    async fn send(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Response> {
        self.send_with_attempt_limit(method, path, body, self.attempt_limit)
            .await
    }

    async fn send_with_attempt_limit(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        attempt_limit: u32,
    ) -> Result<Response> {
        self.send_with_client_attempt_limit(&self.client, method, path, body, attempt_limit)
            .await
    }

    async fn send_with_client_attempt_limit(
        &self,
        client: &Client,
        method: Method,
        path: &str,
        body: Option<&Value>,
        attempt_limit: u32,
    ) -> Result<Response> {
        self.send_with_client_options(client, method, path, body, attempt_limit, false)
            .await
    }

    /// As [`Self::send_with_client_attempt_limit`]; with `return_client_errors`
    /// a 4xx answer is returned as a response instead of an error.
    async fn send_with_client_options(
        &self,
        client: &Client,
        method: Method,
        path: &str,
        body: Option<&Value>,
        attempt_limit: u32,
        return_client_errors: bool,
    ) -> Result<Response> {
        let url = self.url(path)?;
        let request_method = method.clone();
        self.send_retrying_with_client_errors(
            method,
            &url,
            attempt_limit,
            return_client_errors,
            || {
                let mut req = client
                    .request(request_method.clone(), &url)
                    .header("Authorization", &self.auth_header)
                    .header("elastic-api-version", API_VERSION);

                // Kibana rejects any state-changing request without this header.
                if request_method != Method::GET {
                    req = req.header("kbn-xsrf", "true");
                }
                if let Some(b) = body {
                    req = req.json(b);
                }

                Ok(req)
            },
        )
        .await
    }

    async fn send_json(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        self.send_json_with_attempt_limit(method, path, body, self.attempt_limit)
            .await
    }

    async fn send_json_with_attempt_limit(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        attempt_limit: u32,
    ) -> Result<Value> {
        let url = self.url(path)?;
        let response = self
            .send_with_attempt_limit(method.clone(), path, body, attempt_limit)
            .await?;
        let text = self.response_text(&method, &url, response).await?;
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        parse_response_json(&text)
    }

    async fn send_json_once(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value> {
        let url = self.url(path)?;
        let response = self
            .send_with_client_attempt_limit(&self.one_shot_client, method.clone(), path, body, 1)
            .await?;
        let text = self.response_text(&method, &url, response).await?;
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        parse_response_json(&text)
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        self.send_json(Method::GET, path, None).await
    }

    /// GET and retain the status and JSON body for 2xx and 4xx.
    pub async fn get_response(&self, path: &str) -> Result<(u16, Value)> {
        let method = Method::GET;
        let url = self.url(path)?;
        let response = self
            .send_with_client_options(
                &self.client,
                method.clone(),
                path,
                None,
                self.attempt_limit,
                true,
            )
            .await?;
        self.status_and_body(&method, &url, response).await
    }

    /// GET a Kibana *internal* route. Internal routes sit outside the public
    /// API's versioning contract: Kibana requires `x-elastic-internal-origin`
    /// on them (without it the route family answers 400 "exists but is not
    /// available"), and `elastic-api-version: 2023-10-31` names a public-API
    /// version internal routes do not serve, so it is omitted.
    pub async fn get_internal(&self, path: &str) -> Result<Value> {
        let method = Method::GET;
        let url = self.url(path)?;
        let response = self
            .send_retrying(method.clone(), &url, self.attempt_limit, || {
                Ok(self
                    .client
                    .request(Method::GET, &url)
                    .header("Authorization", &self.auth_header)
                    .header("x-elastic-internal-origin", "Kibana"))
            })
            .await?;

        // Convert the response exactly as `get` does: the same
        // response_text/parse_response_json path `send_json` uses after its
        // send, with the same `Error::from_response_body` classification
        // already applied inside `send_retrying`.
        let text = self.response_text(&method, &url, response).await?;
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        parse_response_json(&text)
    }

    /// POST a Kibana *internal* route with a JSON body. Mirrors
    /// `get_internal`'s reasoning (same `x-elastic-internal-origin`
    /// requirement, `elastic-api-version` still omitted), plus `kbn-xsrf`:
    /// Kibana rejects any state-changing request without it, same as every
    /// other non-GET call `send` makes.
    ///
    /// Its only caller today is xtask's profile-activation login
    /// (`POST /internal/security/login`) — not reachable from
    /// `elasticctl-api` or `elasticctl-cli`.
    pub async fn post_internal(&self, path: &str, body: &Value) -> Result<Value> {
        let method = Method::POST;
        let url = self.url(path)?;
        let response = self
            .send_retrying(method.clone(), &url, self.attempt_limit, || {
                Ok(self
                    .client
                    .request(Method::POST, &url)
                    .header("Authorization", &self.auth_header)
                    .header("kbn-xsrf", "true")
                    .header("x-elastic-internal-origin", "Kibana")
                    .json(body))
            })
            .await?;

        let text = self.response_text(&method, &url, response).await?;
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        parse_response_json(&text)
    }

    /// GET a body with its captured headers.
    ///
    /// This is separate from `get` because only the capability probe needs
    /// headers.
    pub async fn get_with_headers(&self, path: &str) -> Result<Responded> {
        let method = Method::GET;
        let url = self.url(path)?;
        let response = self.send(method.clone(), path, None).await?;

        let mut headers = BTreeMap::new();
        for name in CAPTURED_HEADERS {
            if let Some(value) = response.headers().get(name)
                && let Ok(text) = value.to_str()
            {
                headers.insert(name.to_string(), text.to_string());
            }
        }

        let text = self.response_text(&method, &url, response).await?;
        let body = if text.trim().is_empty() {
            Value::Null
        } else {
            parse_response_json(&text)?
        };

        Ok(Responded { body, headers })
    }

    pub async fn post(&self, path: &str, body: Option<&Value>) -> Result<Value> {
        self.send_json(Method::POST, path, body).await
    }

    /// Send a JSON POST exactly once.
    ///
    /// This is for mutations whose endpoint does not provide an idempotency
    /// key. It disables redirects, connection pooling, and protocol-level
    /// retries. It otherwise uses the same request construction, response
    /// parsing, timeout handling, and error classification as [`Self::post`].
    pub async fn post_once(&self, path: &str, body: Option<&Value>) -> Result<Value> {
        self.send_json_once(Method::POST, path, body).await
    }

    /// POST exactly once and retain the status and JSON body for 2xx and 4xx.
    pub async fn post_once_response(
        &self,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(u16, Value)> {
        let method = Method::POST;
        let url = self.url(path)?;
        let response = self
            .send_with_client_options(&self.one_shot_client, method.clone(), path, body, 1, true)
            .await?;
        self.status_and_body(&method, &url, response).await
    }

    pub async fn put(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_json(Method::PUT, path, Some(body)).await
    }

    /// Send a JSON PUT exactly once.
    ///
    /// This is for mutations whose endpoint does not provide an idempotency
    /// key. It disables redirects, connection pooling, and protocol-level
    /// retries. It otherwise uses the same request construction, response
    /// parsing, timeout handling, and error classification as [`Self::put`].
    pub async fn put_once(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_json_once(Method::PUT, path, Some(body)).await
    }

    pub async fn patch(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_json(Method::PATCH, path, Some(body)).await
    }

    /// Send a JSON PATCH exactly once, using the one-shot client of [`Self::put_once`].
    pub async fn patch_once(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_json_once(Method::PATCH, path, Some(body)).await
    }

    /// Send a JSON PATCH exactly once and retain the status and JSON body for
    /// 2xx and 4xx, as [`Self::delete_once_response`] does.
    pub async fn patch_once_response(&self, path: &str, body: &Value) -> Result<(u16, Value)> {
        let method = Method::PATCH;
        let url = self.url(path)?;
        let response = self
            .send_with_client_options(
                &self.one_shot_client,
                method.clone(),
                path,
                Some(body),
                1,
                true,
            )
            .await?;
        self.status_and_body(&method, &url, response).await
    }

    /// The status and the JSON body of a response; an empty body is null.
    async fn status_and_body(
        &self,
        method: &Method,
        url: &str,
        response: Response,
    ) -> Result<(u16, Value)> {
        let status = response.status().as_u16();
        let text = self.response_text(method, url, response).await?;
        let body = if text.trim().is_empty() {
            Value::Null
        } else {
            parse_response_json(&text)?
        };
        Ok((status, body))
    }

    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.send_json(Method::DELETE, path, None).await
    }

    /// Send a JSON DELETE exactly once.
    ///
    /// This is for mutations whose endpoint does not provide an idempotency
    /// key. It disables redirects, connection pooling, and protocol-level
    /// retries. It otherwise uses the same request construction, response
    /// parsing, timeout handling, and error classification as [`Self::delete`].
    pub async fn delete_once(&self, path: &str) -> Result<Value> {
        self.send_json_once(Method::DELETE, path, None).await
    }

    /// Send DELETE exactly once and retain the status and JSON body for 2xx and 4xx.
    ///
    /// Empty bodies decode as null. Other statuses and request or decode failures
    /// use the same errors as [`Self::delete_once`].
    pub async fn delete_once_response(&self, path: &str) -> Result<(u16, Value)> {
        let method = Method::DELETE;
        let url = self.url(path)?;
        let response = self
            .send_retrying_with_client_errors(method.clone(), &url, 1, true, || {
                Ok(self
                    .one_shot_client
                    .delete(&url)
                    .header("Authorization", &self.auth_header)
                    .header("elastic-api-version", API_VERSION)
                    .header("kbn-xsrf", "true"))
            })
            .await?;
        self.status_and_body(&method, &url, response).await
    }

    /// GET Elasticsearch without a Kibana space prefix.
    ///
    /// Cloud deployments use a different Elasticsearch host.
    pub async fn get_absolute_es(&self, path: &str) -> Result<Value> {
        self.send_absolute_es(Method::GET, path, None).await
    }

    /// POST JSON to Elasticsearch without a Kibana space prefix or `kbn-xsrf`
    /// header.
    pub async fn post_absolute_es(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_absolute_es(Method::POST, path, Some(body)).await
    }

    /// PUT JSON to Elasticsearch exactly once.
    ///
    /// This is for a write whose outcome must not be blurred by a retry, such
    /// as an index create whose answer decides who owns the index. It uses
    /// the one-shot client of [`Self::put_once`] and otherwise the request
    /// construction, response parsing, and error classification of
    /// [`Self::post_absolute_es`].
    pub async fn put_absolute_es_once(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_absolute_es_with(&self.one_shot_client, Method::PUT, path, Some(body), 1)
            .await
    }

    /// POST to Elasticsearch exactly once, with a JSON body or none. A route
    /// such as `_refresh` rejects any body. See
    /// [`Self::put_absolute_es_once`].
    pub async fn post_absolute_es_once(&self, path: &str, body: Option<&Value>) -> Result<Value> {
        self.send_absolute_es_with(&self.one_shot_client, Method::POST, path, body, 1)
            .await
    }

    /// DELETE from Elasticsearch.
    ///
    /// The fixture recorder uses this to remove its scratch index.
    pub async fn delete_absolute_es(&self, path: &str) -> Result<Value> {
        self.send_absolute_es(Method::DELETE, path, None).await
    }

    /// DELETE from Elasticsearch exactly once. See
    /// [`Self::put_absolute_es_once`].
    pub async fn delete_absolute_es_once(&self, path: &str) -> Result<Value> {
        self.send_absolute_es_with(&self.one_shot_client, Method::DELETE, path, None, 1)
            .await
    }

    /// DELETE from Elasticsearch with a JSON body. The PIT close needs one;
    /// the plain `delete_absolute_es` sends no body.
    pub async fn delete_absolute_es_json(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_absolute_es(Method::DELETE, path, Some(body))
            .await
    }

    async fn send_absolute_es(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value> {
        self.send_absolute_es_with(&self.client, method, path, body, self.attempt_limit)
            .await
    }

    async fn send_absolute_es_with(
        &self,
        client: &Client,
        method: Method,
        path: &str,
        body: Option<&Value>,
        attempt_limit: u32,
    ) -> Result<Value> {
        let url = self.es_url(path)?;
        let request_method = method.clone();
        let response = self
            .send_retrying(method.clone(), &url, attempt_limit, || {
                let mut req = client
                    .request(request_method.clone(), &url)
                    .header("Authorization", &self.auth_header);
                if let Some(b) = body {
                    req = req.json(b);
                }
                Ok(req)
            })
            .await?;

        let text = self.response_text(&method, &url, response).await?;
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        parse_response_json(&text)
    }

    /// POST and return the raw body for NDJSON endpoints.
    pub async fn post_text(&self, path: &str, body: Option<&Value>) -> Result<String> {
        let method = Method::POST;
        let url = self.url(path)?;
        let response = self.send(method.clone(), path, body).await?;
        self.response_text(&method, &url, response).await
    }

    /// Upload a multipart NDJSON file for Kibana rule import.
    pub async fn post_multipart_ndjson(&self, path: &str, ndjson: &str) -> Result<Value> {
        self.post_multipart_ndjson_named(path, "rules.ndjson", ndjson)
            .await
    }

    /// Upload one multipart file exactly once, using the one-shot client of [`Self::post_once`].
    pub async fn post_multipart_once_named(
        &self,
        path: &str,
        filename: &str,
        content_type: &str,
        body: &str,
    ) -> Result<Value> {
        let method = Method::POST;
        let url = self.url(path)?;
        let response = self
            .send_multipart_once(&url, filename, content_type, body, false)
            .await?;
        let text = self.response_text(&method, &url, response).await?;
        parse_response_json(&text)
    }

    /// Upload one multipart file exactly once and retain the status and JSON
    /// body for 2xx and 4xx, as [`Self::delete_once_response`] does.
    pub async fn post_multipart_once_named_response(
        &self,
        path: &str,
        filename: &str,
        content_type: &str,
        body: &str,
    ) -> Result<(u16, Value)> {
        let method = Method::POST;
        let url = self.url(path)?;
        let response = self
            .send_multipart_once(&url, filename, content_type, body, true)
            .await?;
        self.status_and_body(&method, &url, response).await
    }

    async fn send_multipart_once(
        &self,
        url: &str,
        filename: &str,
        content_type: &str,
        body: &str,
        return_client_errors: bool,
    ) -> Result<Response> {
        self.send_retrying_with_client_errors(Method::POST, url, 1, return_client_errors, || {
            let part = reqwest::multipart::Part::text(body.to_string())
                .file_name(filename.to_string())
                .mime_str(content_type)
                .map_err(|e| Error::new(ErrorKind::Error, format!("building upload: {e}")))?;
            let form = reqwest::multipart::Form::new().part("file", part);

            Ok(self
                .one_shot_client
                .post(url)
                .header("Authorization", &self.auth_header)
                .header("elastic-api-version", API_VERSION)
                .header("kbn-xsrf", "true")
                .multipart(form))
        })
        .await
    }

    /// Upload a multipart NDJSON file for Kibana import with the requested filename.
    pub async fn post_multipart_ndjson_named(
        &self,
        path: &str,
        filename: &str,
        ndjson: &str,
    ) -> Result<Value> {
        let method = Method::POST;
        let url = self.url(path)?;
        let response = self
            .send_retrying(method.clone(), &url, self.attempt_limit, || {
                // Retryable HTTP responses deliberately replay this POST. Part and Form are
                // recreated here because reqwest consumes multipart bodies while sending.
                let part = reqwest::multipart::Part::text(ndjson.to_string())
                    .file_name(filename.to_string())
                    .mime_str("application/octet-stream")
                    .map_err(|e| Error::new(ErrorKind::Error, format!("building upload: {e}")))?;
                let form = reqwest::multipart::Form::new().part("file", part);

                Ok(self
                    .client
                    .post(&url)
                    .header("Authorization", &self.auth_header)
                    .header("elastic-api-version", API_VERSION)
                    .header("kbn-xsrf", "true")
                    .multipart(form))
            })
            .await?;

        let text = self.response_text(&method, &url, response).await?;
        parse_response_json(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Profile;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn transport(server: &MockServer) -> Transport {
        Transport::new(&Profile {
            kibana_url: server.uri(),
            es_url: None,
            api_key: Some("test".into()),
            username: None,
            password: None,
            space: "security".into(),
            verify: true,
            timeout_secs: 1,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn get_response_returns_client_error_body() {
        let server = MockServer::start().await;
        let body = serde_json::json!({"statusCode": 404, "message": "list indices missing"});
        Mock::given(method("GET"))
            .and(path("/s/security/api/lists/index"))
            .and(header("Authorization", "ApiKey test"))
            .and(header("elastic-api-version", "2023-10-31"))
            .respond_with(ResponseTemplate::new(404).set_body_json(&body))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            transport(&server)
                .get_response("/api/lists/index")
                .await
                .unwrap(),
            (404, body)
        );
    }

    #[tokio::test]
    async fn post_once_response_returns_client_error_body() {
        let server = MockServer::start().await;
        let request = serde_json::json!({"flows": ["create-list-indices"]});
        let body = serde_json::json!({"statusCode": 404, "message": "flow unavailable"});
        Mock::given(method("POST"))
            .and(path("/s/security/api/security_solution/initialize"))
            .and(header("kbn-xsrf", "true"))
            .and(header("Authorization", "ApiKey test"))
            .and(header("elastic-api-version", "2023-10-31"))
            .and(body_json(&request))
            .respond_with(ResponseTemplate::new(404).set_body_json(&body))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            transport(&server)
                .post_once_response("/api/security_solution/initialize", Some(&request))
                .await
                .unwrap(),
            (404, body)
        );
    }

    #[tokio::test]
    async fn post_once_response_never_replays_server_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/s/security/api/lists/index"))
            .respond_with(
                ResponseTemplate::new(503)
                    .set_body_json(serde_json::json!({"message": "unavailable"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let error = transport(&server)
            .post_once_response("/api/lists/index", None)
            .await
            .unwrap_err();
        assert_eq!(error.http_status, Some(503));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
