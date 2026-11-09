//! Authority matching and URL scrubbing.

use serde_json::Value;

/// Extract a recording authority without URL userinfo.
///
/// The transport removes userinfo before issuing a request. This helper uses
/// the same final-`@` rule while preparing the fixture host scrubber, so a
/// credential cannot survive in a recorded URL value.
fn recording_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    (!host.is_empty()).then(|| host.to_string())
}

/// Return the recording stack's bare hostnames.
///
/// Read them from the environment because every write path needs them and each
/// run talks to one stack.
pub(crate) fn recording_hosts() -> Vec<String> {
    [
        "ELASTICCTL_KIBANA_URL",
        "ELASTICCTL_ES_URL",
        "ELASTICCTL_INGEST_URL",
    ]
    .iter()
    .filter_map(|k| std::env::var(k).ok())
    .filter_map(|url| recording_host(&url))
    .collect()
}

fn is_authority_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'[' | b']')
}

fn authority_token_end(bytes: &[u8], start: usize) -> usize {
    let mut index = start;
    let mut in_ipv6 = false;
    while index < bytes.len() {
        match bytes[index] {
            b'[' => in_ipv6 = true,
            b']' if in_ipv6 => in_ipv6 = false,
            byte if !in_ipv6
                && (byte.is_ascii_whitespace()
                    || matches!(
                        byte,
                        b'/' | b'?'
                            | b'#'
                            | b','
                            | b';'
                            | b'\''
                            | b'"'
                            | b'('
                            | b')'
                            | b'<'
                            | b'>'
                            | b'['
                            | b']'
                    )) =>
            {
                break;
            }
            _ => {}
        }
        index += 1;
    }
    index
}

fn replace_bounded_authority(value: &str, authority: &str) -> String {
    if authority.is_empty() {
        return value.to_string();
    }

    let bytes = value.as_bytes();
    let authority = authority.as_bytes();
    let mut scrubbed = String::with_capacity(value.len());
    let mut copied_end = 0;
    let mut index = 0;

    while index + authority.len() <= bytes.len() {
        let before_is_safe =
            index == 0 || (!is_authority_char(bytes[index - 1]) && bytes[index - 1] != b'@');
        let end = index + authority.len();
        let after_is_safe =
            end == bytes.len() || (!is_authority_char(bytes[end]) && bytes[end] != b'@');

        if before_is_safe && after_is_safe && bytes[index..end].eq_ignore_ascii_case(authority) {
            scrubbed.push_str(&value[copied_end..index]);
            scrubbed.push_str("REDACTED.example.invalid");
            copied_end = end;
            index = end;
        } else {
            index += 1;
        }
    }

    scrubbed.push_str(&value[copied_end..]);
    scrubbed
}

fn default_port_host(authority: &str, default_port: u16) -> Option<&str> {
    authority.rsplit_once(':').and_then(|(host, port)| {
        (!host.is_empty() && port.parse::<u16>().ok() == Some(default_port)).then_some(host)
    })
}

/// Remove userinfo from a URL authority without changing its path or query.
///
/// Fixture values can contain the configured host with credentials that were
/// never part of the transport URL. Removing only the host would leave those
/// credentials in the public fixture.
fn strip_url_userinfo(value: &str) -> String {
    let mut scrubbed = String::with_capacity(value.len());
    let mut remaining = value;

    while let Some(scheme_end) = remaining.find("://") {
        let authority_start = scheme_end + 3;
        scrubbed.push_str(&remaining[..authority_start]);
        remaining = &remaining[authority_start..];

        let authority_end = authority_token_end(remaining.as_bytes(), 0);
        let (authority, tail) = remaining.split_at(authority_end);
        scrubbed.push_str(
            authority
                .rfind('@')
                .map_or(authority, |index| &authority[index + 1..]),
        );
        remaining = tail;
    }
    scrubbed.push_str(remaining);
    scrubbed
}

/// Replace the configured authority in every absolute URL.
///
/// URL hostnames compare case-insensitively. A configured
/// `https://host:443` can also appear in a response as `https://host/...`, and
/// `http://host:80` likewise loses `:80`. Do not derive a bare-host match for
/// non-default ports: `host:9243` and `host` can identify different
/// deployments.
fn scrub_recording_authority_urls(value: &str, configured_authority: &str) -> String {
    let mut scrubbed = String::new();
    let mut remaining = value;

    while let Some(scheme_end) = remaining.find("://") {
        let authority_start = scheme_end + 3;
        let scheme = remaining[..scheme_end]
            .rsplit(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .next()
            .unwrap_or("");
        scrubbed.push_str(&remaining[..authority_start]);
        remaining = &remaining[authority_start..];

        let authority_end = authority_token_end(remaining.as_bytes(), 0);
        let (authority, tail) = remaining.split_at(authority_end);
        let default_port = if scheme.eq_ignore_ascii_case("https") {
            Some(443)
        } else if scheme.eq_ignore_ascii_case("http") {
            Some(80)
        } else {
            None
        };
        let normalized_default = default_port.and_then(|port| {
            default_port_host(configured_authority, port).map(|configured_host| {
                authority.eq_ignore_ascii_case(configured_host)
                    || default_port_host(authority, port)
                        .is_some_and(|host| host.eq_ignore_ascii_case(configured_host))
            })
        });

        if authority.eq_ignore_ascii_case(configured_authority) || normalized_default == Some(true)
        {
            scrubbed.push_str("REDACTED.example.invalid");
        } else {
            scrubbed.push_str(authority);
        }
        remaining = tail;
    }
    scrubbed.push_str(remaining);
    scrubbed
}

/// Replace the recording stack's hostname wherever it appears in a value.
///
/// `is_sensitive` checks keys, but an alert document stores the project URL in
/// `kibana.alert.url`, where identity is in the *value*. Sweep every recorded
/// string and keep the path so the document shape remains intact.
pub(crate) fn scrub_hosts(v: &mut Value, hosts: &[String]) {
    match v {
        Value::String(s) => {
            *s = strip_url_userinfo(s);
            for h in hosts {
                *s = replace_bounded_authority(s, h);
                *s = scrub_recording_authority_urls(s, h);
            }
        }
        Value::Object(m) => m.values_mut().for_each(|x| scrub_hosts(x, hosts)),
        Value::Array(a) => a.iter_mut().for_each(|x| scrub_hosts(x, hosts)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    #[test]
    fn recording_host_removes_userinfo_and_keeps_the_authority() {
        assert_eq!(
            recording_host("https://alice:secret@cluster.example:9243/s/default?x=1#fragment"),
            Some("cluster.example:9243".to_string())
        );
        assert_eq!(
            recording_host(
                "https://user:pa@ss@host.example:443/path@not-userinfo?x=@query#@fragment"
            ),
            Some("host.example:443".to_string())
        );
        assert_eq!(
            recording_host("https://plain.example:5601/path?x=1#fragment"),
            Some("plain.example:5601".to_string())
        );
    }

    #[test]
    fn host_scrub_removes_url_userinfo_before_replacing_the_host() {
        let mut value = json!({
            "url": "https://alice:secret@cluster.example:9243/app/rules?x=1#detail"
        });

        scrub_hosts(&mut value, &["cluster.example:9243".to_string()]);

        assert_eq!(
            value["url"],
            "https://REDACTED.example.invalid/app/rules?x=1#detail"
        );
    }

    #[test]
    fn host_scrub_removes_userinfo_from_each_url_in_a_string() {
        let mut value = json!({
            "urls": "https://alice:secret@cluster.example:9243 https://bob:hidden@cluster.example:9243/b"
        });

        scrub_hosts(&mut value, &["cluster.example:9243".to_string()]);

        assert_eq!(
            value["urls"],
            "https://REDACTED.example.invalid https://REDACTED.example.invalid/b"
        );
    }

    #[test]
    fn host_scrub_matches_a_normalized_default_port_url() {
        let mut value = json!({"url": "https://internal.example/app/rules"});

        scrub_hosts(&mut value, &["internal.example:443".to_string()]);

        assert_eq!(value["url"], "https://REDACTED.example.invalid/app/rules");
    }

    #[test]
    fn host_scrub_matches_a_case_normalized_default_port_url() {
        let mut value = json!({"url": "https://internal.example/app/rules"});

        scrub_hosts(&mut value, &["INTERNAL.example:443".to_string()]);

        assert_eq!(value["url"], "https://REDACTED.example.invalid/app/rules");
    }

    #[test]
    fn host_scrub_matches_zero_padded_default_ports() {
        let mut value = json!({
            "https": "https://internal.example/app/rules",
            "http": "http://internal.example/app/rules"
        });

        scrub_hosts(
            &mut value,
            &[
                "internal.example:0443".to_string(),
                "internal.example:0080".to_string(),
            ],
        );

        assert_eq!(value["https"], "https://REDACTED.example.invalid/app/rules");
        assert_eq!(value["http"], "http://REDACTED.example.invalid/app/rules");
    }

    #[test]
    fn host_scrub_matches_a_normalized_http_default_port_url() {
        let mut value = json!({"url": "http://internal.example/app/rules"});

        scrub_hosts(&mut value, &["internal.example:80".to_string()]);

        assert_eq!(value["url"], "http://REDACTED.example.invalid/app/rules");
    }

    #[test]
    fn host_scrub_does_not_normalize_a_nondefault_port() {
        let mut value = json!({"url": "https://internal.example/app/rules"});

        scrub_hosts(&mut value, &["internal.example:9243".to_string()]);

        assert_eq!(value["url"], "https://internal.example/app/rules");
    }

    #[test]
    fn host_scrub_leaves_plain_at_sign_text_unchanged() {
        let mut value = json!({"note": "contact ops@example.com before recording"});

        scrub_hosts(&mut value, &["cluster.example:9243".to_string()]);

        assert_eq!(value["note"], "contact ops@example.com before recording");
    }

    #[cfg(test)]
    #[test]
    fn scrub_hosts_handles_authority_boundaries() {
        // This fails if a configured authority is matched case-sensitively,
        // extends into an adjacent authority character, or does not recognize
        // punctuation-delimited default-port URL authorities.
        let cases = [
            (
                "comma-delimited HTTPS canonical default port",
                "https://internal.example:443,",
                "internal.example:443",
                "https://REDACTED.example.invalid,",
            ),
            (
                "comma-delimited HTTPS default port",
                "https://internal.example:0443,",
                "internal.example:443",
                "https://REDACTED.example.invalid,",
            ),
            (
                "semicolon-delimited HTTP canonical default port",
                "http://internal.example:80;",
                "internal.example:80",
                "http://REDACTED.example.invalid;",
            ),
            (
                "semicolon-delimited HTTP default port",
                "http://internal.example:0080;",
                "internal.example:80",
                "http://REDACTED.example.invalid;",
            ),
            (
                "single-quoted authority",
                "https://internal.example:0443'",
                "internal.example:443",
                "https://REDACTED.example.invalid'",
            ),
            (
                "double-quoted authority",
                "http://internal.example:0080\"",
                "internal.example:80",
                "http://REDACTED.example.invalid\"",
            ),
            (
                "parenthesized authority",
                "https://internal.example:0443)",
                "internal.example:443",
                "https://REDACTED.example.invalid)",
            ),
            (
                "angle-bracketed authority",
                "http://internal.example:0080>",
                "internal.example:80",
                "http://REDACTED.example.invalid>",
            ),
            (
                "square-bracketed authority",
                "https://internal.example:0443]",
                "internal.example:443",
                "https://REDACTED.example.invalid]",
            ),
            (
                "whitespace-separated authorities",
                "https://cluster.example:9243 https://cluster.example:9243/b",
                "cluster.example:9243",
                "https://REDACTED.example.invalid https://REDACTED.example.invalid/b",
            ),
            (
                "mixed-case authority",
                "https://CLUSTER.ExAmPlE:9243/app",
                "cluster.example:9243",
                "https://REDACTED.example.invalid/app",
            ),
            (
                "userinfo authority",
                "https://alice:secret@cluster.example:9243/app",
                "cluster.example:9243",
                "https://REDACTED.example.invalid/app",
            ),
            (
                "bracketed IPv6 authority",
                "https://[2001:DB8::1]:0443/app",
                "[2001:db8::1]:443",
                "https://REDACTED.example.invalid/app",
            ),
            (
                "exact authority in plain text",
                "Connect to CLUSTER.example:9243 now",
                "cluster.example:9243",
                "Connect to REDACTED.example.invalid now",
            ),
            (
                "longer hostname remains visible",
                "https://cluster.example:9243.evil/app",
                "cluster.example:9243",
                "https://cluster.example:9243.evil/app",
            ),
            (
                "prefixed hostname remains visible",
                "https://evilcluster.example:9243/app",
                "cluster.example:9243",
                "https://evilcluster.example:9243/app",
            ),
            (
                "bare nondefault host remains visible",
                "https://cluster.example/app",
                "cluster.example:9243",
                "https://cluster.example/app",
            ),
            (
                "bare HTTPS default host is redacted",
                "https://internal.example/app",
                "internal.example:443",
                "https://REDACTED.example.invalid/app",
            ),
            (
                "bare HTTP default host is redacted",
                "http://internal.example/app",
                "internal.example:80",
                "http://REDACTED.example.invalid/app",
            ),
            (
                "plain at-sign text remains visible",
                "contact ops@example.com before recording",
                "example.com",
                "contact ops@example.com before recording",
            ),
            (
                "plain authority followed by at-sign remains visible",
                "example.com@ops.invalid",
                "example.com",
                "example.com@ops.invalid",
            ),
            (
                "configured default authority does not scrub plain email text",
                "ops@example.com",
                "example.com:443",
                "ops@example.com",
            ),
            (
                "configured default authority does not scrub trailing at-sign text",
                "example.com@ops.invalid",
                "example.com:443",
                "example.com@ops.invalid",
            ),
        ];

        for (name, input, host, expected) in cases {
            let mut value = json!(input);
            scrub_hosts(&mut value, &[host.to_string()]);
            assert_eq!(value, json!(expected), "{name}");
        }
    }
}
