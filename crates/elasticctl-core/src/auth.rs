//! Credential selection and the Authorization header.

use crate::config::Profile;
use crate::error::{Error, ErrorKind, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// An Elastic API key. Already base64 of `id:key`, so it is sent verbatim.
    ApiKey(String),
    Basic {
        username: String,
        password: String,
    },
}

impl Credential {
    /// API key wins when both are present: it is the documented default and
    /// the one that works across all three deployment flavors.
    pub fn from_profile(p: &Profile) -> Result<Credential> {
        if let Some(key) = &p.api_key
            && !key.trim().is_empty()
        {
            return Ok(Credential::ApiKey(key.clone()));
        }
        match (&p.username, &p.password) {
            (Some(u), Some(pw)) => Ok(Credential::Basic {
                username: u.clone(),
                password: pw.clone(),
            }),
            _ => Err(Error::new(
                ErrorKind::Auth,
                "No credential configured. Set api_key, or both username and password.",
            )),
        }
    }

    pub fn header_value(&self) -> String {
        match self {
            Credential::ApiKey(k) => format!("ApiKey {k}"),
            Credential::Basic { username, password } => {
                format!(
                    "Basic {}",
                    STANDARD.encode(format!("{username}:{password}"))
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Profile {
        Profile {
            kibana_url: "https://kb.example.com".into(),
            es_url: None,
            api_key: None,
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 30,
        }
    }

    #[test]
    fn api_key_is_sent_verbatim_because_elastic_keys_are_already_encoded() {
        let c = Credential::ApiKey("essu_abc123".into());
        assert_eq!(c.header_value(), "ApiKey essu_abc123");
    }

    #[test]
    fn basic_auth_is_base64_encoded() {
        let c = Credential::Basic {
            username: "elastic".into(),
            password: "changeme".into(),
        };
        // base64("elastic:changeme")
        assert_eq!(c.header_value(), "Basic ZWxhc3RpYzpjaGFuZ2VtZQ==");
    }

    #[test]
    fn api_key_wins_when_both_credentials_are_configured() {
        let mut p = profile();
        p.api_key = Some("essu_abc".into());
        p.username = Some("elastic".into());
        p.password = Some("changeme".into());
        assert!(matches!(
            Credential::from_profile(&p).unwrap(),
            Credential::ApiKey(_)
        ));
    }

    #[test]
    fn a_profile_with_no_credential_is_an_auth_error() {
        let err = Credential::from_profile(&profile()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Auth);
    }

    #[test]
    fn a_username_without_a_password_is_an_auth_error() {
        let mut p = profile();
        p.username = Some("elastic".into());
        assert_eq!(
            Credential::from_profile(&p).unwrap_err().kind,
            ErrorKind::Auth
        );
    }
}
