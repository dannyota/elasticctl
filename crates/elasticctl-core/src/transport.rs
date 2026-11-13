use crate::auth::Credential;
use crate::capabilities::{Capabilities, Feature};
use crate::config::Profile;
use crate::error::{Error, ErrorKind, Result};
use reqwest::{Client, Method};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;
use tokio::sync::OnceCell;

mod requests;

const API_VERSION: &str = "2023-10-31";
const MAX_ATTEMPTS: u32 = 3;

#[derive(Clone, Debug, Default)]
pub struct TransportOptions {
    pub debug: bool,
    pub response_body_limit: Option<usize>,
    pub disable_redirects: bool,
    pub disable_retries: bool,
    pub disable_connection_pool: bool,
}

const CAPTURED_HEADERS: [&str; 3] = [
    "x-found-handling-cluster",
    "x-found-handling-instance",
    "x-elastic-product",
];

fn parse_response_json(text: &str) -> Result<Value> {
    validate_json_integer_ranges(text)?;
    serde_json::from_str(text)
        .map_err(|e| Error::new(ErrorKind::Http, format!("parsing response JSON: {e}")))
}

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

#[derive(Debug, Clone)]
pub struct Responded {
    pub body: Value,
    pub headers: BTreeMap<String, String>,
}

impl Responded {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(|s| &**s)
    }
}

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
    one_shot_client: Client,
    base: String,
    kibana_url: String,
    es_base: String,
    has_es_url: bool,
    space: String,
    auth_header: String,
    debug: bool,
    response_body_limit: Option<usize>,
    attempt_limit: u32,
    capabilities: OnceCell<Capabilities>,
}

impl Transport {
    fn client_builder(profile: &Profile) -> reqwest::ClientBuilder {
        Client::builder()
            .timeout(Duration::from_secs(profile.timeout_secs))
            .danger_accept_invalid_certs(!profile.verify)
    }

    pub fn new(profile: &Profile) -> Result<Transport> {
        Self::with_options(profile, TransportOptions::default())
    }

    pub fn with_debug(profile: &Profile, debug: bool) -> Result<Transport> {
        Self::with_options(
            profile,
            TransportOptions {
                debug,
                ..Default::default()
            },
        )
    }

    pub fn with_options(profile: &Profile, options: TransportOptions) -> Result<Transport> {
        crate::config::validate_space(&profile.space)?;
        let mut profile = profile.clone();
        profile.strip_userinfo();
        let credential = Credential::from_profile(&profile)?;
        let mut client_builder = Self::client_builder(&profile);
        if options.disable_redirects {
            client_builder = client_builder.redirect(reqwest::redirect::Policy::none());
        }
        if options.disable_retries {
            client_builder = client_builder.retry(reqwest::retry::never());
        }
        if options.disable_connection_pool {
            client_builder = client_builder.pool_max_idle_per_host(0);
        }
        let client = client_builder
            .build()
            .map_err(|e| Error::new(ErrorKind::Connection, format!("building HTTP client: {e}")))?;
        let one_shot_client = Self::client_builder(&profile)
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .retry(reqwest::retry::never())
            .build()
            .map_err(|e| {
                Error::new(
                    ErrorKind::Connection,
                    format!("building one-shot HTTP client: {e}"),
                )
            })?;

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
            one_shot_client,
            base,
            kibana_url,
            es_base,
            has_es_url,
            space: profile.space.clone(),
            auth_header: credential.header_value(),
            debug: options.debug,
            response_body_limit: options.response_body_limit,
            attempt_limit: if options.disable_retries {
                1
            } else {
                MAX_ATTEMPTS
            },
            capabilities: OnceCell::new(),
        })
    }

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

    pub fn space_path(space: &str, path: &str) -> String {
        if space.is_empty() || space == "default" {
            path.to_string()
        } else {
            format!("/s/{space}{path}")
        }
    }

    pub fn kibana_url(&self) -> &str {
        &self.kibana_url
    }

    pub fn space(&self) -> &str {
        &self.space
    }

    pub fn has_es_url(&self) -> bool {
        self.has_es_url
    }

    pub async fn capabilities(&self) -> Result<&Capabilities> {
        self.capabilities
            .get_or_try_init(|| Capabilities::probe(self, self.kibana_url()))
            .await
    }

    pub async fn require_feature(&self, feature: Feature) -> Result<()> {
        self.capabilities().await?.require_feature(feature)
    }

    fn url(&self, path: &str) -> Result<String> {
        let path = origin_relative(path)?;
        Ok(format!(
            "{}{}",
            self.base,
            Self::space_path(&self.space, path)
        ))
    }

    fn es_url(&self, path: &str) -> Result<String> {
        Ok(format!("{}{}", self.es_base, origin_relative(path)?))
    }
}

fn origin_relative(path: &str) -> Result<&str> {
    if path.starts_with('/') {
        Ok(path)
    } else {
        Err(Error::new(
            ErrorKind::Error,
            "request path must start with /",
        ))
    }
}
