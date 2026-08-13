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

/// Percent-encode a query-string value. Only the characters that actually
/// break a URL are escaped, so recorded fixtures and `--debug` lines stay
/// readable.
///
/// Lives here rather than beside the endpoint wrappers because both the API
/// client and the fixture recorder build URLs, and two copies of an encoder is
/// two chances to encode a scoped filter differently from the request it is
/// meant to reproduce.
pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub struct Transport {
    client: Client,
    base: String,
    /// Elasticsearch lives at a different host from Kibana on Cloud
    /// deployments. Falls back to the Kibana host when no separate URL is set,
    /// which is the usual self-managed single-host case.
    es_base: String,
    space: String,
    auth_header: String,
    debug: bool,
}

impl Transport {
    pub fn new(profile: &Profile) -> Result<Transport> {
        Self::with_debug(profile, false)
    }

    /// Build a transport with HTTP request logging enabled or disabled. Kept
    /// as a separate constructor so `debug` is a plain `bool` here — the CLI's
    /// `clap` types never cross into `-core`.
    pub fn with_debug(profile: &Profile, debug: bool) -> Result<Transport> {
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
            debug,
        })
    }

    /// One stderr line per request/response event. Method, URL, and status
    /// only — never the `Authorization` header, never a body, never a
    /// query-string credential.
    fn debug_log(&self, method: &Method, url: &str, status: u16, attempt: u32) {
        if !self.debug {
            return;
        }
        if attempt > 1 {
            eprintln!(
                "[debug] {} {url} -> {status} (attempt {attempt})",
                method.as_str()
            );
        } else {
            eprintln!("[debug] {} {url} -> {status}", method.as_str());
        }
    }

    /// Logged before the request goes out. Without it, a request that never
    /// returns — the case `--debug` exists for — produces no output at all.
    fn debug_request(&self, method: &Method, url: &str, attempt: u32) {
        if !self.debug {
            return;
        }
        if attempt > 1 {
            eprintln!("[debug] -> {} {url} (attempt {attempt})", method.as_str());
        } else {
            eprintln!("[debug] -> {} {url}", method.as_str());
        }
    }

    /// Logged on an outcome that never produced a status: a timeout or a
    /// connection failure. Same shape as the response line, so one log format
    /// covers every outcome.
    fn debug_failure(&self, method: &Method, url: &str, what: &str) {
        if !self.debug {
            return;
        }
        eprintln!("[debug] {} {url} -> {what}", method.as_str());
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

            self.debug_request(&method, &url, attempt);
            let result = req.send().await;

            let response = match result {
                Ok(r) => r,
                Err(e) if e.is_timeout() => {
                    self.debug_failure(&method, &url, "timeout");
                    return Err(Error::new(
                        ErrorKind::Timeout,
                        format!("request timed out: {e}"),
                    ));
                }
                Err(e) => {
                    self.debug_failure(&method, &url, "connection error");
                    return Err(Error::new(
                        ErrorKind::Connection,
                        format!("request failed: {e}"),
                    ));
                }
            };

            let status = response.status();
            self.debug_log(&method, &url, status.as_u16(), attempt);
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

    /// Elasticsearch lives at a different host from Kibana on Cloud
    /// deployments, so ES calls do not go through the space-prefixed path.
    pub async fn get_absolute_es(&self, path: &str) -> Result<Value> {
        let url = format!("{}{}", self.es_base, path);
        self.debug_request(&Method::GET, &url, 1);
        let response = self
            .client
            .get(&url)
            .header("Authorization", &self.auth_header)
            .send()
            .await
            .map_err(|e| {
                self.debug_failure(&Method::GET, &url, "connection error");
                Error::new(ErrorKind::Connection, format!("request failed: {e}"))
            })?;
        let status = response.status().as_u16();
        self.debug_log(&Method::GET, &url, status, 1);
        let text = response.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(Error::from_response_body(status, &text));
        }
        serde_json::from_str(&text)
            .map_err(|e| Error::new(ErrorKind::Http, format!("parsing response JSON: {e}")))
    }

    /// POST a JSON body to Elasticsearch. Separate from `post` because
    /// Elasticsearch lives at a different host from Kibana on Cloud
    /// deployments and takes no space prefix and no `kbn-xsrf` header.
    pub async fn post_absolute_es(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_absolute_es(Method::POST, path, Some(body)).await
    }

    /// DELETE against Elasticsearch. Used by the fixture recorder to remove
    /// the scratch index it creates; a recording session must leave the stack
    /// exactly as it found it.
    pub async fn delete_absolute_es(&self, path: &str) -> Result<Value> {
        self.send_absolute_es(Method::DELETE, path, None).await
    }

    async fn send_absolute_es(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value> {
        let url = format!("{}{}", self.es_base, path);
        let mut req = self
            .client
            .request(method.clone(), &url)
            .header("Authorization", &self.auth_header);
        if let Some(b) = body {
            req = req.json(b);
        }

        self.debug_request(&method, &url, 1);
        let response = req.send().await.map_err(|e| {
            self.debug_failure(&method, &url, "connection error");
            Error::new(ErrorKind::Connection, format!("request failed: {e}"))
        })?;

        let status = response.status().as_u16();
        self.debug_log(&method, &url, status, 1);
        let text = response.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(Error::from_response_body(status, &text));
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text)
            .map_err(|e| Error::new(ErrorKind::Http, format!("parsing response JSON: {e}")))
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

        self.debug_request(&Method::POST, &url, 1);
        let response = self
            .client
            .post(&url)
            .header("Authorization", &self.auth_header)
            .header("elastic-api-version", API_VERSION)
            .header("kbn-xsrf", "true")
            .multipart(form)
            .send()
            .await
            .map_err(|e| {
                self.debug_failure(&Method::POST, &url, "connection error");
                Error::new(ErrorKind::Connection, format!("upload failed: {e}"))
            })?;

        let status = response.status().as_u16();
        self.debug_log(&Method::POST, &url, status, 1);
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
