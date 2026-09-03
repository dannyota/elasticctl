//! HTTP transport, including URL construction, headers, retries, and error
//! classification.

use crate::auth::Credential;
use crate::capabilities::{Capabilities, Feature};
use crate::config::Profile;
use crate::error::{Error, ErrorKind, Result};
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;
use tokio::sync::OnceCell;

/// Version of the public API this client targets.
const API_VERSION: &str = "2023-10-31";
const MAX_ATTEMPTS: u32 = 3;

/// Response headers retained past the transport boundary.
///
/// These headers are allowlisted because recorded fixtures are public.
/// Capturing all headers could record cookies, rate-limit counters, or future
/// proxy headers that do not belong in the repository.
///
/// The capability probe reads `x-found-handling-cluster`. The other two show
/// which Cloud headers the recorded response contained.
const CAPTURED_HEADERS: [&str; 3] = [
    "x-found-handling-cluster",
    "x-found-handling-instance",
    "x-elastic-product",
];

/// Parse a JSON response without letting serde_json coerce an out-of-range
/// integer literal into an imprecise floating-point number.
fn parse_response_json(text: &str) -> Result<Value> {
    validate_json_integer_ranges(text)?;
    serde_json::from_str(text)
        .map_err(|e| Error::new(ErrorKind::Http, format!("parsing response JSON: {e}")))
}

/// Reject positive integer lexemes above `u64::MAX` and negative integer
/// lexemes below `i64::MIN`. Numbers with a decimal point or exponent remain
/// floating-point JSON values, even when their magnitude is greater than
/// `u64::MAX`.
fn validate_json_integer_ranges(text: &str) -> Result<()> {
    let bytes = text.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'"' {
            index += 1;
            while index < bytes.len() {
                match bytes[index] {
                    b'\\' => index += 2,
                    b'"' => {
                        index += 1;
                        break;
                    }
                    _ => index += 1,
                }
            }
            continue;
        }

        if bytes[index] != b'-' && !bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }

        let start = index;
        if bytes[index] == b'-' {
            index += 1;
        }
        if index == bytes.len() || !bytes[index].is_ascii_digit() {
            index = start + 1;
            continue;
        }

        if bytes[index] == b'0' {
            index += 1;
        } else {
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
        }

        let mut is_integer = true;
        if bytes.get(index) == Some(&b'.') {
            is_integer = false;
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
        }
        if matches!(bytes.get(index), Some(b'e' | b'E')) {
            is_integer = false;
            index += 1;
            if matches!(bytes.get(index), Some(b'+' | b'-')) {
                index += 1;
            }
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
        }

        if is_integer {
            let number = &text[start..index];
            let in_range = if bytes[start] == b'-' {
                number.parse::<i64>().is_ok()
            } else {
                number.parse::<u64>().is_ok()
            };
            if !in_range {
                return Err(Error::new(
                    ErrorKind::Http,
                    format!(
                        "parsing response JSON: integer {number} is outside supported integer range"
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// A response body and its captured headers.
///
/// Hosted and self-managed stacks return the same `/api/status` body. An
/// edge-proxy header distinguishes them.
#[derive(Debug, Clone)]
pub struct Responded {
    pub body: Value,
    pub headers: BTreeMap<String, String>,
}

impl Responded {
    /// Look up a header case-insensitively.
    ///
    /// The Elastic proxy varies the casing of `x-found-handling-cluster` by
    /// endpoint.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(|s| &**s)
    }
}

/// Percent-encode a query value while leaving URL-safe characters unchanged.
///
/// The API client and fixture recorder share this encoder so they produce the
/// same scoped-filter URL.
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
    /// The Kibana URL exactly as configured, before trailing-slash
    /// normalization. `doctor` reports it as the connectivity target and the
    /// capability probe uses it for hostname-based flavor detection.
    kibana_url: String,
    /// Elasticsearch host. Cloud deployments use a different host from
    /// Kibana; otherwise this uses the Kibana host.
    es_base: String,
    /// Whether the profile configured an explicit `es_url`. `es_base` falls
    /// back to the Kibana host either way, so a caller that needs to know
    /// whether that fallback happened (e.g. to name a likely cause in an
    /// error message) reads this instead of comparing hosts.
    has_es_url: bool,
    space: String,
    auth_header: String,
    debug: bool,
    capabilities: OnceCell<Capabilities>,
}

impl Transport {
    pub fn new(profile: &Profile) -> Result<Transport> {
        Self::with_debug(profile, false)
    }

    /// Build a transport with HTTP request logging enabled or disabled.
    ///
    /// Keeping `debug` as a `bool` prevents CLI `clap` types entering `-core`.
    pub fn with_debug(profile: &Profile, debug: bool) -> Result<Transport> {
        // Scrub URL userinfo before deriving any base URL or logging, so a
        // credential embedded in a URL never reaches a request or debug line.
        let mut profile = profile.clone();
        profile.strip_userinfo();
        let credential = Credential::from_profile(&profile)?;
        let client = Client::builder()
            .timeout(Duration::from_secs(profile.timeout_secs))
            .danger_accept_invalid_certs(!profile.verify)
            .build()
            .map_err(|e| Error::new(ErrorKind::Connection, format!("building HTTP client: {e}")))?;

        let base = profile.kibana_url.trim_end_matches('/').to_string();
        let kibana_url = profile.kibana_url.clone();
        let has_es_url = profile.es_url.is_some();
        let es_base = profile
            .es_url
            .as_deref()
            .unwrap_or(&profile.kibana_url)
            .trim_end_matches('/')
            .to_string();

        Ok(Transport {
            client,
            base,
            kibana_url,
            es_base,
            has_es_url,
            space: profile.space.clone(),
            auth_header: credential.header_value(),
            debug,
            capabilities: OnceCell::new(),
        })
    }

    /// Log one request or response line to stderr.
    ///
    /// Logs include the method, complete URL, and status. They exclude
    /// authorization headers and bodies. Callers must not put credentials in
    /// query strings.
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

    /// Log the request before sending it so timeouts produce debug output.
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

    /// Log a timeout or connection failure in the response-line format.
    fn debug_failure(&self, method: &Method, url: &str, what: &str) {
        if !self.debug {
            return;
        }
        let _ = writeln!(
            std::io::stderr(),
            "[debug] {} {url} -> {what}",
            method.as_str()
        );
    }

    /// Prefix non-default spaces with `/s/<name>`.
    ///
    /// Kibana serves the default space at the bare path.
    pub fn space_path(space: &str, path: &str) -> String {
        if space.is_empty() || space == "default" {
            path.to_string()
        } else {
            format!("/s/{space}{path}")
        }
    }

    /// The Kibana URL this transport targets, exactly as configured.
    pub fn kibana_url(&self) -> &str {
        &self.kibana_url
    }

    /// The Kibana space this transport targets, exactly as the profile
    /// resolved it. Fleet normalization compares `space_ids` against it.
    pub fn space(&self) -> &str {
        &self.space
    }

    /// Whether the profile configured an explicit `es_url`. When it did not,
    /// every `*_absolute_es` call silently falls back to the Kibana host —
    /// callers that need to distinguish "no Elasticsearch host configured"
    /// from "the real Elasticsearch host answered" read this.
    pub fn has_es_url(&self) -> bool {
        self.has_es_url
    }

    /// Probe deployment capabilities once for this transport.
    pub async fn capabilities(&self) -> Result<&Capabilities> {
        self.capabilities
            .get_or_try_init(|| Capabilities::probe(self, self.kibana_url()))
            .await
    }

    /// Refuse an unverified feature before its public route is called.
    pub async fn require_feature(&self, feature: Feature) -> Result<()> {
        self.capabilities().await?.require_feature(feature)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, Self::space_path(&self.space, path))
    }

    /// Read a response body without retrying an operation that may have
    /// completed after its headers were received.
    async fn response_text(
        &self,
        method: &Method,
        url: &str,
        response: Response,
    ) -> Result<String> {
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

    async fn send_retrying<F>(
        &self,
        method: Method,
        url: &str,
        attempt_limit: u32,
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
            if status.is_success() {
                return Ok(response);
            }

            // Retry transient failures only. Retrying a 4xx repeats the same
            // caller error.
            let transient = status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
            if transient && attempt < attempt_limit {
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
        self.send_with_attempt_limit(method, path, body, MAX_ATTEMPTS)
            .await
    }

    async fn send_with_attempt_limit(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        attempt_limit: u32,
    ) -> Result<Response> {
        let url = self.url(path);
        let request_method = method.clone();
        self.send_retrying(method, &url, attempt_limit, || {
            let mut req = self
                .client
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
        })
        .await
    }

    async fn send_json(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        self.send_json_with_attempt_limit(method, path, body, MAX_ATTEMPTS)
            .await
    }

    async fn send_json_with_attempt_limit(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        attempt_limit: u32,
    ) -> Result<Value> {
        let url = self.url(path);
        let response = self
            .send_with_attempt_limit(method.clone(), path, body, attempt_limit)
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

    /// GET a Kibana *internal* route. Internal routes sit outside the public
    /// API's versioning contract: Kibana requires `x-elastic-internal-origin`
    /// on them (without it the route family answers 400 "exists but is not
    /// available"), and `elastic-api-version: 2023-10-31` names a public-API
    /// version internal routes do not serve, so it is omitted.
    pub async fn get_internal(&self, path: &str) -> Result<Value> {
        let method = Method::GET;
        let url = self.url(path);
        let response = self
            .send_retrying(method.clone(), &url, MAX_ATTEMPTS, || {
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
        let url = self.url(path);
        let response = self
            .send_retrying(method.clone(), &url, MAX_ATTEMPTS, || {
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
        let url = self.url(path);
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

    pub async fn put(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_json(Method::PUT, path, Some(body)).await
    }

    /// Send a JSON PUT exactly once.
    ///
    /// This is for mutations whose endpoint does not provide an idempotency
    /// key. It otherwise uses the same request construction, response parsing,
    /// timeout handling, and error classification as [`Self::put`].
    pub async fn put_once(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_json_with_attempt_limit(Method::PUT, path, Some(body), 1)
            .await
    }

    pub async fn patch(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_json(Method::PATCH, path, Some(body)).await
    }

    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.send_json(Method::DELETE, path, None).await
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

    /// DELETE from Elasticsearch.
    ///
    /// The fixture recorder uses this to remove its scratch index.
    pub async fn delete_absolute_es(&self, path: &str) -> Result<Value> {
        self.send_absolute_es(Method::DELETE, path, None).await
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
        let url = format!("{}{}", self.es_base, path);
        let request_method = method.clone();
        let response = self
            .send_retrying(method.clone(), &url, MAX_ATTEMPTS, || {
                let mut req = self
                    .client
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
        let url = self.url(path);
        let response = self.send(method.clone(), path, body).await?;
        self.response_text(&method, &url, response).await
    }

    /// Upload a multipart NDJSON file for Kibana rule import.
    pub async fn post_multipart_ndjson(&self, path: &str, ndjson: &str) -> Result<Value> {
        self.post_multipart_ndjson_named(path, "rules.ndjson", ndjson)
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
        let url = self.url(path);
        let response = self
            .send_retrying(method.clone(), &url, MAX_ATTEMPTS, || {
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
