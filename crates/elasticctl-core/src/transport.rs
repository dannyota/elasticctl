//! The HTTP layer. Owns URL construction, required headers, retry, and the
//! translation of any non-success response into a classified `Error`.

use crate::auth::Credential;
use crate::config::Profile;
use crate::error::{Error, ErrorKind, Result};
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::Value;
use std::time::Duration;

/// The versioned public API contract this client is written against.
const API_VERSION: &str = "2023-10-31";
const MAX_ATTEMPTS: u32 = 3;

pub struct Transport {
    client: Client,
    base: String,
    /// Elasticsearch lives at a different host from Kibana on Cloud
    /// deployments. Falls back to the Kibana host when no separate URL is set,
    /// which is the usual self-managed single-host case.
    #[expect(dead_code)]
    es_base: String,
    space: String,
    auth_header: String,
}

impl Transport {
    pub fn new(profile: &Profile) -> Result<Transport> {
        let credential = Credential::from_profile(profile)?;
        let client = Client::builder()
            .timeout(Duration::from_secs(profile.timeout_secs))
            .danger_accept_invalid_certs(!profile.verify)
            .build()
            .map_err(|e| Error::new(ErrorKind::Connection, format!("building HTTP client: {e}")))?;

        let base = profile.kibana_url.trim_end_matches('/').to_string();
        let es_base = profile
            .es_url
            .as_deref()
            .unwrap_or(&profile.kibana_url)
            .trim_end_matches('/')
            .to_string();

        Ok(Transport {
            client,
            base,
            es_base,
            space: profile.space.clone(),
            auth_header: credential.header_value(),
        })
    }

    /// Kibana serves the default space at the bare path and every other space
    /// under `/s/<name>`. Prefixing the default space also works, but keeping
    /// URLs bare makes recorded fixtures and `--debug` output easier to read.
    pub fn space_path(space: &str, path: &str) -> String {
        if space.is_empty() || space == "default" {
            path.to_string()
        } else {
            format!("/s/{space}{path}")
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, Self::space_path(&self.space, path))
    }

    async fn send(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Response> {
        let url = self.url(path);
        let mut attempt = 0;

        loop {
            attempt += 1;
            let mut req = self
                .client
                .request(method.clone(), &url)
                .header("Authorization", &self.auth_header)
                .header("elastic-api-version", API_VERSION);

            // Kibana rejects any state-changing request without this header.
            if method != Method::GET {
                req = req.header("kbn-xsrf", "true");
            }
            if let Some(b) = body {
                req = req.json(b);
            }

            let result = req.send().await;

            let response = match result {
                Ok(r) => r,
                Err(e) if e.is_timeout() => {
                    return Err(Error::new(
                        ErrorKind::Timeout,
                        format!("request timed out: {e}"),
                    ));
                }
                Err(e) => {
                    return Err(Error::new(
                        ErrorKind::Connection,
                        format!("request failed: {e}"),
                    ));
                }
            };

            let status = response.status();
            if status.is_success() {
                return Ok(response);
            }

            // Retry only transient failures. A 4xx is the caller's problem and
            // retrying it just multiplies the same error.
            let transient = status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
            if transient && attempt < MAX_ATTEMPTS {
                let backoff = Duration::from_millis(200 * 2u64.pow(attempt - 1));
                tokio::time::sleep(backoff).await;
                continue;
            }

            let code = status.as_u16();
            let text = response.text().await.unwrap_or_default();
            return Err(Error::from_response_body(code, &text));
        }
    }

    async fn send_json(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let response = self.send(method, path, body).await?;
        let text = response
            .text()
            .await
            .map_err(|e| Error::new(ErrorKind::Http, format!("reading response body: {e}")))?;
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text)
            .map_err(|e| Error::new(ErrorKind::Http, format!("parsing response JSON: {e}")))
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        self.send_json(Method::GET, path, None).await
    }

    pub async fn post(&self, path: &str, body: Option<&Value>) -> Result<Value> {
        self.send_json(Method::POST, path, body).await
    }

    pub async fn put(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_json(Method::PUT, path, Some(body)).await
    }

    pub async fn patch(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_json(Method::PATCH, path, Some(body)).await
    }

    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.send_json(Method::DELETE, path, None).await
    }

    /// Raw body, for endpoints that return NDJSON rather than a JSON document.
    pub async fn post_text(&self, path: &str, body: Option<&Value>) -> Result<String> {
        let response = self.send(Method::POST, path, body).await?;
        response
            .text()
            .await
            .map_err(|e| Error::new(ErrorKind::Http, format!("reading response body: {e}")))
    }

    /// Kibana's rule import takes a multipart file upload, not a JSON body.
    pub async fn post_multipart_ndjson(&self, path: &str, ndjson: &str) -> Result<Value> {
        let url = self.url(path);
        let part = reqwest::multipart::Part::text(ndjson.to_string())
            .file_name("rules.ndjson")
            .mime_str("application/octet-stream")
            .map_err(|e| Error::new(ErrorKind::Error, format!("building upload: {e}")))?;
        let form = reqwest::multipart::Form::new().part("file", part);

        let response = self
            .client
            .post(&url)
            .header("Authorization", &self.auth_header)
            .header("elastic-api-version", API_VERSION)
            .header("kbn-xsrf", "true")
            .multipart(form)
            .send()
            .await
            .map_err(|e| Error::new(ErrorKind::Connection, format!("upload failed: {e}")))?;

        let status = response.status().as_u16();
        let text = response
            .text()
            .await
            .map_err(|e| Error::new(ErrorKind::Http, format!("reading response body: {e}")))?;
        if !(200..300).contains(&status) {
            return Err(Error::from_response_body(status, &text));
        }
        serde_json::from_str(&text)
            .map_err(|e| Error::new(ErrorKind::Http, format!("parsing response JSON: {e}")))
    }
}
