//! Profiles, their on-disk form, and the resolution order
//! flags -> environment -> profile -> defaults.

use crate::error::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const REDACTED: &str = "***";

/// Fields that decide *which instance, as whom*. Overriding one of these
/// changes the provenance reported in the guard banner; overriding a
/// non-identity field (timeout, space) does not.
fn is_identity_override(ov: &Overrides) -> bool {
    ov.kibana_url.is_some() || ov.api_key.is_some()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub kibana_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub es_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default = "default_space")]
    pub space: String,
    #[serde(default = "default_verify")]
    pub verify: bool,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_space() -> String {
    "default".to_string()
}
fn default_verify() -> bool {
    true
}
fn default_timeout() -> u64 {
    30
}

impl Profile {
    /// A copy safe to print. Every secret becomes `***`; absent stays absent,
    /// so redacted output never implies a credential that is not configured.
    pub fn redacted(&self) -> Profile {
        Profile {
            api_key: self.api_key.as_ref().map(|_| REDACTED.to_string()),
            password: self.password.as_ref().map(|_| REDACTED.to_string()),
            ..self.clone()
        }
    }

    /// Host portion of the Kibana URL, for banners. Falls back to the whole
    /// string when it will not parse, so a banner never silently loses its target.
    pub fn host(&self) -> String {
        self.kibana_url
            .split("://")
            .nth(1)
            .unwrap_or(&self.kibana_url)
            .trim_end_matches('/')
            .to_string()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub current: String,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Profile,
    Env,
    Flags,
}

#[derive(Debug, Clone)]
pub struct Resolved {
    pub profile: Profile,
    pub name: String,
    pub source: Source,
}

impl Resolved {
    pub fn banner(&self) -> String {
        format!(
            "profile: {} @ {}, space: {}",
            self.name,
            self.profile.host(),
            self.profile.space
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub kibana_url: Option<String>,
    pub api_key: Option<String>,
    pub space: Option<String>,
    pub timeout_secs: Option<u64>,
}

impl Overrides {
    /// Read `ELASTICCTL_*` environment variables into an override set.
    pub fn from_env() -> Overrides {
        Overrides {
            kibana_url: std::env::var("ELASTICCTL_KIBANA_URL").ok(),
            api_key: std::env::var("ELASTICCTL_API_KEY").ok(),
            space: std::env::var("ELASTICCTL_SPACE").ok(),
            timeout_secs: std::env::var("ELASTICCTL_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok()),
        }
    }

    /// `self` wins over `lower`. Used to layer flags on top of environment.
    pub fn merge_over(self, lower: Overrides) -> Overrides {
        Overrides {
            kibana_url: self.kibana_url.or(lower.kibana_url),
            api_key: self.api_key.or(lower.api_key),
            space: self.space.or(lower.space),
            timeout_secs: self.timeout_secs.or(lower.timeout_secs),
        }
    }
}

impl Config {
    pub fn default_path() -> PathBuf {
        directories::UserDirs::new()
            .map(|d| d.home_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".elasticctl")
            .join("config.toml")
    }

    /// A missing file is an empty config, not an error — `config init` has to
    /// work on a machine that has never run elasticctl.
    pub fn load(path: &Path) -> Result<Config> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let body = fs::read_to_string(path).map_err(|e| {
            Error::new(ErrorKind::Error, format!("reading {}: {e}", path.display()))
        })?;
        toml::from_str(&body)
            .map_err(|e| Error::new(ErrorKind::Error, format!("parsing {}: {e}", path.display())))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                Error::new(
                    ErrorKind::Error,
                    format!("creating {}: {e}", parent.display()),
                )
            })?;
        }
        let body = toml::to_string_pretty(self)
            .map_err(|e| Error::new(ErrorKind::Error, format!("serializing config: {e}")))?;
        fs::write(path, body).map_err(|e| {
            Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
        })?;
        Self::restrict_permissions(path)
    }

    #[cfg(unix)]
    fn restrict_permissions(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::new(ErrorKind::Error, format!("chmod {}: {e}", path.display())))
    }

    #[cfg(not(unix))]
    fn restrict_permissions(_path: &Path) -> Result<()> {
        Ok(())
    }

    /// Resolve the effective profile and report where it came from.
    pub fn resolve(&self, name: Option<&str>, ov: &Overrides) -> Result<Resolved> {
        let wanted = name.unwrap_or(if self.current.is_empty() {
            "default"
        } else {
            &self.current
        });
        let mut profile = self.profiles.get(wanted).cloned().ok_or_else(|| {
            Error::new(ErrorKind::NotFound, format!("Profile '{wanted}' not found"))
        })?;

        if let Some(v) = &ov.kibana_url {
            profile.kibana_url = v.clone();
        }
        if let Some(v) = &ov.api_key {
            profile.api_key = Some(v.clone());
        }
        if let Some(v) = &ov.space {
            profile.space = v.clone();
        }
        if let Some(v) = ov.timeout_secs {
            profile.timeout_secs = v;
        }

        let source = if is_identity_override(ov) {
            Source::Flags
        } else {
            Source::Profile
        };
        Ok(Resolved {
            profile,
            name: wanted.to_string(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sample() -> Config {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "default".to_string(),
            Profile {
                kibana_url: "https://kb.example.com".into(),
                es_url: Some("https://es.example.com".into()),
                api_key: Some("essu_SECRET".into()),
                username: None,
                password: None,
                space: "default".into(),
                verify: true,
                timeout_secs: 30,
            },
        );
        profiles.insert(
            "prod".to_string(),
            Profile {
                kibana_url: "https://prod.example.com".into(),
                ..profiles["default"].clone()
            },
        );
        Config {
            current: "default".into(),
            profiles,
        }
    }

    #[test]
    fn round_trips_through_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sample().save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.current, "default");
        assert_eq!(loaded.profiles.len(), 2);
        assert_eq!(
            loaded.profiles["prod"].kibana_url,
            "https://prod.example.com"
        );
    }

    #[test]
    fn save_enforces_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sample().save(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config must not be readable by group or other");
    }

    #[test]
    fn load_of_a_missing_file_is_an_empty_config_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::load(&dir.path().join("absent.toml")).unwrap();
        assert!(cfg.profiles.is_empty());
    }

    #[test]
    fn resolving_an_unknown_profile_is_a_not_found_error() {
        let err = sample()
            .resolve(Some("nope"), &Overrides::default())
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::NotFound);
        assert!(err.message.contains("nope"));
    }

    #[test]
    fn resolve_defaults_to_the_current_profile() {
        let r = sample().resolve(None, &Overrides::default()).unwrap();
        assert_eq!(r.name, "default");
        assert_eq!(r.source, Source::Profile);
        assert_eq!(r.profile.kibana_url, "https://kb.example.com");
    }

    #[test]
    fn flags_override_the_profile_and_change_the_reported_source() {
        let ov = Overrides {
            kibana_url: Some("https://override.example.com".into()),
            ..Default::default()
        };
        let r = sample().resolve(None, &ov).unwrap();
        assert_eq!(r.profile.kibana_url, "https://override.example.com");
        assert_eq!(
            r.source,
            Source::Flags,
            "an identity override changes provenance"
        );
    }

    #[test]
    fn a_non_identity_override_does_not_change_the_source() {
        let ov = Overrides {
            timeout_secs: Some(90),
            ..Default::default()
        };
        let r = sample().resolve(None, &ov).unwrap();
        assert_eq!(r.profile.timeout_secs, 90);
        assert_eq!(
            r.source,
            Source::Profile,
            "timeout is not an identity field"
        );
    }

    #[test]
    fn redacted_hides_every_secret_field() {
        let p = sample().profiles["default"].redacted();
        assert_eq!(p.api_key.as_deref(), Some("***"));
        assert_eq!(
            p.kibana_url, "https://kb.example.com",
            "non-secrets stay visible"
        );
    }

    #[test]
    fn redacted_leaves_absent_secrets_absent() {
        let mut p = sample().profiles["default"].clone();
        p.api_key = None;
        assert_eq!(p.redacted().api_key, None);
    }

    #[test]
    fn banner_names_profile_host_and_space() {
        let r = sample()
            .resolve(Some("prod"), &Overrides::default())
            .unwrap();
        let b = r.banner();
        assert!(b.contains("prod"), "banner must name the profile: {b}");
        assert!(
            b.contains("prod.example.com"),
            "banner must name the host: {b}"
        );
        assert!(b.contains("default"), "banner must name the space: {b}");
    }

    #[test]
    fn a_saved_config_never_contains_a_plaintext_key_in_a_world_readable_file() {
        // Guards the pairing of the two properties, not either alone.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sample().save(&path).unwrap();
        let body = fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("essu_SECRET"),
            "the real key is stored, not redacted on disk"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
