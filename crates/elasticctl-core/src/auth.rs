//! Credential selection and `Authorization` header construction.

use crate::config::Profile;
use crate::error::{Error, ErrorKind, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

#[derive(Clone, PartialEq, Eq)]
pub enum Credential {
    /// An Elastic API key, already Base64-encoded as `id:key`.
    ApiKey(String),
    Basic {
        username: String,
        password: String,
    },
}

impl std::fmt::Debug for Credential {
    /// Redacts keys and passwords. Derived `Debug` could expose them in logs
    /// or panic messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credential::ApiKey(_) => f.write_str("Credential::ApiKey(***)"),
            Credential::Basic { username, .. } => {
                write!(
                    f,
                    "Credential::Basic {{ username: {username:?}, password: *** }}"
                )
            }
        }
    }
}

impl Credential {
    /// Prefer an API key when both credential types are configured. It is the
    /// documented default and works on all deployment flavors.
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

    /// Whether the profile has a usable credential. Reuse credential selection
    /// so this rule does not diverge from `from_profile`.
    pub fn is_configured(profile: &Profile) -> bool {
        Self::from_profile(profile).is_ok()
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
        // Base64 of "elastic:changeme".
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

    #[test]
    fn is_configured_true_for_a_valid_api_key() {
        let mut p = profile();
        p.api_key = Some("essu_abc".into());
        assert!(Credential::is_configured(&p));
    }

    #[test]
    fn is_configured_false_for_an_empty_api_key_with_no_basic_auth() {
        let mut p = profile();
        p.api_key = Some("".into());
        assert!(!Credential::is_configured(&p));
    }

    #[test]
    fn is_configured_false_for_a_username_without_a_password() {
        let mut p = profile();
        p.username = Some("elastic".into());
        assert!(!Credential::is_configured(&p));
    }

    #[test]
    fn debug_redacts_api_key_material() {
        let c = Credential::ApiKey("essu_secret".into());
        let debug_str = format!("{:?}", c);
        assert!(!debug_str.contains("essu_secret"));
        assert!(debug_str.contains("***"));
    }

    #[test]
    fn debug_redacts_password_but_shows_username() {
        let c = Credential::Basic {
            username: "elastic".into(),
            password: "changeme".into(),
        };
        let debug_str = format!("{:?}", c);
        assert!(!debug_str.contains("changeme"));
        assert!(debug_str.contains("elastic"));
        assert!(debug_str.contains("***"));
    }
}
