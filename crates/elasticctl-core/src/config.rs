//! Profiles, their on-disk form, and the resolution order
//! flags -> environment -> profile -> defaults.

use crate::error::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
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
        // Find the last occurrence of "://" to handle doubled schemes correctly
        if let Some(pos) = self.kibana_url.rfind("://") {
            let after_scheme = &self.kibana_url[pos + 3..];
            // Strip any path/query portion after the first /
            let host_part = after_scheme.split('/').next().unwrap_or("");
            // If we got something, return it; otherwise fall back to original
            if !host_part.is_empty() {
                return host_part.to_string();
            }
        }
        // Fall back to original if parsing fails or result is empty
        self.kibana_url.clone()
    }

    /// Drop any `user:password@` prefix from `kibana_url` and `es_url`.
    ///
    /// Credentials belong in `api_key` or `username`/`password`. The transport
    /// has never read them from a URL, so nothing that authenticated stops
    /// authenticating — but a URL carrying userinfo would print in the guard
    /// banner, in `config show`, and in every `--debug` line, which is exactly
    /// the class this closes.
    pub fn strip_userinfo(&mut self) {
        self.kibana_url = strip_userinfo(&self.kibana_url);
        self.es_url = self.es_url.as_deref().map(strip_userinfo);
    }
}

/// Remove userinfo from a URL's authority, leaving everything else byte for
/// byte. Only the authority is examined: a path or query may legitimately
/// contain `@`.
fn strip_userinfo(url: &str) -> String {
    let (scheme, rest) = match url.find("://") {
        Some(i) => url.split_at(i + 3),
        None => ("", url),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    match authority.rfind('@') {
        Some(i) => format!("{scheme}{}{tail}", &authority[i + 1..]),
        None => url.to_string(),
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

    /// A structured description of the file's insecure permissions, or
    /// `None` when it is absent or already owner-only.
    ///
    /// Returns rather than prints: a core library must not decide whether or
    /// how a warning reaches the user — that belongs to whichever caller
    /// controls the output channel (and, for the CLI, whether `--json` is in
    /// play).
    #[cfg(unix)]
    pub fn permission_warning(path: &Path) -> Option<String> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path).ok()?;
        let mode = metadata.permissions().mode();
        // Group or other bits set.
        if mode & 0o077 != 0 {
            Some(format!(
                "config file {} is readable by group or other (mode {:o}); should be 0600",
                path.display(),
                mode & 0o777
            ))
        } else {
            None
        }
    }

    #[cfg(not(unix))]
    pub fn permission_warning(_path: &Path) -> Option<String> {
        None
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
        Self::write_config_file(path, &body)?;
        // Also restrict permissions afterward in case an existing file had looser permissions
        Self::restrict_permissions(path)
    }

    #[cfg(unix)]
    fn write_config_file(path: &Path, body: &str) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
            })?;
        f.write_all(body.as_bytes())
            .map_err(|e| Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display())))
    }

    #[cfg(not(unix))]
    fn write_config_file(path: &Path, body: &str) -> Result<()> {
        fs::write(path, body)
            .map_err(|e| Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display())))
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

        // After the overrides, not before: a userinfo URL can arrive from the
        // file, the environment, or a flag, and this is the one point all
        // three have already passed through.
        profile.strip_userinfo();

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
                username: Some("user".into()),
                password: Some("pass_SECRET".into()),
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
        assert_eq!(
            p.api_key.as_deref(),
            Some("***"),
            "api_key must be redacted"
        );
        assert_eq!(
            p.password.as_deref(),
            Some("***"),
            "password must be redacted"
        );
        assert_eq!(
            p.kibana_url, "https://kb.example.com",
            "non-secrets stay visible"
        );
    }

    #[test]
    fn redacted_leaves_absent_secrets_absent() {
        let mut p = sample().profiles["default"].clone();
        p.api_key = None;
        p.password = None;
        let redacted = p.redacted();
        assert_eq!(redacted.api_key, None, "absent api_key stays absent");
        assert_eq!(redacted.password, None, "absent password stays absent");
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

    #[test]
    fn newly_created_file_is_mode_0600_not_umask_default() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new_config.toml");
        // Ensure file does not exist
        assert!(!path.exists());
        sample().save(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "newly created config must be 0600 immediately, not umask default"
        );
    }

    #[test]
    fn host_parses_normal_https_url() {
        let p = Profile {
            kibana_url: "https://kb.example.com".into(),
            ..Profile {
                kibana_url: "".into(),
                es_url: None,
                api_key: None,
                username: None,
                password: None,
                space: "default".into(),
                verify: true,
                timeout_secs: 30,
            }
        };
        assert_eq!(p.host(), "kb.example.com");
    }

    #[test]
    fn host_strips_path_from_url() {
        let p = Profile {
            kibana_url: "https://kb.example.com/api/spaces".into(),
            ..Profile {
                kibana_url: "".into(),
                es_url: None,
                api_key: None,
                username: None,
                password: None,
                space: "default".into(),
                verify: true,
                timeout_secs: 30,
            }
        };
        assert_eq!(p.host(), "kb.example.com");
    }

    #[test]
    fn host_handles_doubled_scheme() {
        let p = Profile {
            kibana_url: "https://https://kb.example.com".into(),
            ..Profile {
                kibana_url: "".into(),
                es_url: None,
                api_key: None,
                username: None,
                password: None,
                space: "default".into(),
                verify: true,
                timeout_secs: 30,
            }
        };
        assert_eq!(
            p.host(),
            "kb.example.com",
            "must extract host after last :// to avoid reporting wrong scheme as host"
        );
    }

    #[test]
    fn host_handles_bare_hostname() {
        let p = Profile {
            kibana_url: "kb.example.com".into(),
            ..Profile {
                kibana_url: "".into(),
                es_url: None,
                api_key: None,
                username: None,
                password: None,
                space: "default".into(),
                verify: true,
                timeout_secs: 30,
            }
        };
        assert_eq!(p.host(), "kb.example.com", "must fall back to original");
    }

    #[test]
    fn host_handles_empty_string() {
        let p = Profile {
            kibana_url: "".into(),
            es_url: None,
            api_key: None,
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 30,
        };
        assert_eq!(p.host(), "", "empty falls back to original");
    }

    #[test]
    fn load_succeeds_on_a_permissive_file_and_prints_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sample().save(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        // `load` never prints — that decision belongs to the caller, via
        // `permission_warning` below.
        let cfg = Config::load(&path).unwrap();
        assert!(
            !cfg.profiles.is_empty(),
            "load must succeed regardless of file permissions"
        );
    }

    #[test]
    fn permission_warning_flags_a_group_or_other_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sample().save(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let warning = Config::permission_warning(&path).expect("0644 must warn");
        assert!(warning.contains("644"), "{warning}");
    }

    #[test]
    fn permission_warning_is_none_for_an_owner_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sample().save(&path).unwrap(); // `Config::save` already enforces 0600.
        assert!(Config::permission_warning(&path).is_none());
    }

    #[test]
    fn permission_warning_is_none_for_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Config::permission_warning(&dir.path().join("absent.toml")).is_none());
    }

    fn with_urls(kibana: &str, es: Option<&str>) -> Config {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "default".to_string(),
            Profile {
                kibana_url: kibana.into(),
                es_url: es.map(String::from),
                api_key: Some("essu_SECRET".into()),
                username: None,
                password: None,
                space: "default".into(),
                verify: true,
                timeout_secs: 30,
            },
        );
        Config {
            current: "default".into(),
            profiles,
        }
    }

    #[test]
    fn resolve_strips_userinfo_from_both_urls() {
        let r = with_urls(
            "https://user:pass@kb.example.com",
            Some("https://user:pass@es.example.com:9243/"),
        )
        .resolve(None, &Overrides::default())
        .unwrap();
        assert_eq!(r.profile.kibana_url, "https://kb.example.com");
        assert_eq!(
            r.profile.es_url.as_deref(),
            Some("https://es.example.com:9243/")
        );
    }

    #[test]
    fn resolve_strips_userinfo_supplied_by_an_override() {
        // Flags and environment reach the profile after it is loaded, so the
        // strip has to sit downstream of them, not at load.
        let ov = Overrides {
            kibana_url: Some("https://user:pass@override.example.com".into()),
            ..Default::default()
        };
        let r = with_urls("https://kb.example.com", None)
            .resolve(None, &ov)
            .unwrap();
        assert_eq!(r.profile.kibana_url, "https://override.example.com");
    }

    #[test]
    fn the_banner_never_shows_userinfo() {
        // The banner is the one thing an operator reads before approving a
        // mutation. It must not be where a password first appears.
        let r = with_urls("https://user:hunter2@prod.example.com", None)
            .resolve(None, &Overrides::default())
            .unwrap();
        let b = r.banner();
        assert!(!b.contains("hunter2"), "{b}");
        // The banner's only `@` is the documented separator between profile
        // name and host; a leaked `user:pass@` would add a second.
        assert_eq!(b.matches('@').count(), 1, "{b}");
        assert!(b.contains("prod.example.com"), "{b}");
    }

    #[test]
    fn a_url_without_userinfo_is_left_exactly_as_written() {
        for url in [
            "https://kb.example.com",
            "https://kb.example.com:5601/base/path?q=1",
            "http://localhost:5601",
            "kb.example.com",
            "",
        ] {
            let mut p = with_urls(url, None).profiles["default"].clone();
            p.strip_userinfo();
            assert_eq!(
                p.kibana_url, url,
                "unchanged input must stay byte-identical"
            );
        }
    }

    #[test]
    fn an_at_sign_outside_the_authority_is_not_treated_as_userinfo() {
        // A path or query may legitimately contain '@'; only the authority
        // carries userinfo.
        let mut p =
            with_urls("https://kb.example.com/a@b?user=x@y", None).profiles["default"].clone();
        p.strip_userinfo();
        assert_eq!(p.kibana_url, "https://kb.example.com/a@b?user=x@y");
    }
}
