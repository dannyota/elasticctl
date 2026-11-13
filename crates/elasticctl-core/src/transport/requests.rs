use super::{API_VERSION, CAPTURED_HEADERS, Responded, Transport, parse_response_json};
use crate::error::{Error, ErrorKind, Result};
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

impl Transport {
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
            if status.is_success()
                || (return_client_errors
                    && status.is_client_error()
                    && (status != StatusCode::TOO_MANY_REQUESTS || attempt >= attempt_limit))
            {
                return Ok(response);
            }

            let transient = status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
            if transient && attempt < attempt_limit {
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

        let text = self.response_text(&method, &url, response).await?;
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        parse_response_json(&text)
    }

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

    pub async fn post_once(&self, path: &str, body: Option<&Value>) -> Result<Value> {
        self.send_json_once(Method::POST, path, body).await
    }

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

    pub async fn put_once(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_json_once(Method::PUT, path, Some(body)).await
    }

    pub async fn patch(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_json(Method::PATCH, path, Some(body)).await
    }

    pub async fn patch_once(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_json_once(Method::PATCH, path, Some(body)).await
    }

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

    async fn status_and_body(
        &self,
        method: &Method,
        url: &str,
        response: Response,
    ) -> Result<(u16, Value)> {
        let status = response.status().as_u16();
        let text = self
            .response_text(method, url, response)
            .await
            .map_err(|error| {
                if (400..500).contains(&status) {
                    Error::with_status(ErrorKind::from_status(status), status, error.message)
                } else {
                    error
                }
            })?;
        let body = if (400..500).contains(&status) {
            parse_response_json(&text).unwrap_or_else(|_| Value::String(text))
        } else if text.trim().is_empty() {
            Value::Null
        } else {
            parse_response_json(&text)?
        };
        Ok((status, body))
    }

    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.send_json(Method::DELETE, path, None).await
    }

    pub async fn delete_once(&self, path: &str) -> Result<Value> {
        self.send_json_once(Method::DELETE, path, None).await
    }

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

    pub async fn get_absolute_es(&self, path: &str) -> Result<Value> {
        self.send_absolute_es(Method::GET, path, None).await
    }

    pub async fn post_absolute_es(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_absolute_es(Method::POST, path, Some(body)).await
    }

    pub async fn put_absolute_es_once(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_absolute_es_with(&self.one_shot_client, Method::PUT, path, Some(body), 1)
            .await
    }

    pub async fn post_absolute_es_once(&self, path: &str, body: Option<&Value>) -> Result<Value> {
        self.send_absolute_es_with(&self.one_shot_client, Method::POST, path, body, 1)
            .await
    }

    pub async fn delete_absolute_es(&self, path: &str) -> Result<Value> {
        self.send_absolute_es(Method::DELETE, path, None).await
    }

    pub async fn delete_absolute_es_once(&self, path: &str) -> Result<Value> {
        self.send_absolute_es_with(&self.one_shot_client, Method::DELETE, path, None, 1)
            .await
    }

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

    pub async fn post_text(&self, path: &str, body: Option<&Value>) -> Result<String> {
        let method = Method::POST;
        let url = self.url(path)?;
        let response = self.send(method.clone(), path, body).await?;
        self.response_text(&method, &url, response).await
    }

    pub async fn post_text_once(&self, path: &str, body: Option<&Value>) -> Result<String> {
        let method = Method::POST;
        let url = self.url(path)?;
        let response = self
            .send_with_client_attempt_limit(&self.one_shot_client, method.clone(), path, body, 1)
            .await?;
        self.response_text(&method, &url, response).await
    }

    pub async fn post_multipart_ndjson(&self, path: &str, ndjson: &str) -> Result<Value> {
        self.post_multipart_ndjson_named(path, "rules.ndjson", ndjson)
            .await
    }

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
    async fn get_response_retries_429_then_returns_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/s/security/api/lists/index"))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_json(serde_json::json!({"message": "rate limited"})),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        let body = serde_json::json!({"list_index": true, "list_item_index": true});
        Mock::given(method("GET"))
            .and(path("/s/security/api/lists/index"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            transport(&server)
                .get_response("/api/lists/index")
                .await
                .unwrap(),
            (200, body)
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn get_response_retries_429_then_returns_last_body() {
        let server = MockServer::start().await;
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        Mock::given(method("GET"))
            .and(path("/s/security/api/lists/index"))
            .respond_with(move |_: &wiremock::Request| {
                let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                ResponseTemplate::new(429).set_body_json(
                    serde_json::json!({"message": "rate limited", "attempt": attempt}),
                )
            })
            .expect(3)
            .mount(&server)
            .await;
        assert_eq!(
            transport(&server)
                .get_response("/api/lists/index")
                .await
                .unwrap(),
            (
                429,
                serde_json::json!({"message": "rate limited", "attempt": 3})
            )
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn post_once_response_returns_429_without_replaying() {
        let server = MockServer::start().await;
        let body = serde_json::json!({"message": "rate limited"});
        Mock::given(method("POST"))
            .and(path("/s/security/api/lists/index"))
            .respond_with(ResponseTemplate::new(429).set_body_json(&body))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            transport(&server)
                .post_once_response("/api/lists/index", None)
                .await
                .unwrap(),
            (429, body)
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
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
