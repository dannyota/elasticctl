//! Profiles, their on-disk form, and resolution order.
//!
//! Flags override environment variables, which override profiles and defaults.

use crate::error::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const REDACTED: &str = "***";

/// Whether overrides change the target deployment or credential.
///
/// Only these overrides change the guard banner's reported source. Timeout and
/// space overrides do not.
fn is_identity_override(ov: &Overrides) -> bool {
    ov.kibana_url.is_some() || ov.es_url.is_some() || ov.api_key.is_some()
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
    /// Return a copy safe to print.
    ///
    /// Secrets become `***`; absent values remain absent.
    pub fn redacted(&self) -> Profile {
        Profile {
            api_key: self.api_key.as_ref().map(|_| REDACTED.to_string()),
            password: self.password.as_ref().map(|_| REDACTED.to_string()),
            ..self.clone()
        }
    }

    /// Return the Kibana URL host for banners.
    ///
    /// Return the original URL when no host can be parsed.
    pub fn host(&self) -> String {
        // Use the last scheme separator to handle doubled schemes.
        if let Some(pos) = self.kibana_url.rfind("://") {
            let after_scheme = &self.kibana_url[pos + 3..];
            // Drop the path and query after the first slash.
            let host_part = after_scheme.split('/').next().unwrap_or("");
            // Use the parsed host when present.
            if !host_part.is_empty() {
                return host_part.to_string();
            }
        }
        // Preserve the original URL when parsing finds no host.
        self.kibana_url.clone()
    }

    /// Remove userinfo from `kibana_url` and `es_url`.
    ///
    /// Credentials use `api_key` or `username` and `password`; the transport
    /// never reads URL userinfo. Removing it prevents credentials appearing in
    /// the guard banner, `config show`, or `--debug` output.
    pub fn strip_userinfo(&mut self) {
        self.kibana_url = strip_userinfo(&self.kibana_url);
        self.es_url = self.es_url.as_deref().map(strip_userinfo);
    }
}

/// Remove userinfo from a URL authority without changing other bytes.
///
/// Paths and queries may legitimately contain `@`.
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
    pub es_url: Option<String>,
    pub api_key: Option<String>,
    pub space: Option<String>,
    pub timeout_secs: Option<u64>,
}

impl Overrides {
    /// Read `ELASTICCTL_*` environment variables as overrides.
    ///
    /// `es_url` and `kibana_url` are identity overrides. Cloud deployments use
    /// distinct endpoints; inheriting one from a saved profile could target two
    /// deployments and send the overridden credential to the wrong host.
    pub fn from_env() -> Overrides {
        Overrides {
            kibana_url: std::env::var("ELASTICCTL_KIBANA_URL").ok(),
            es_url: std::env::var("ELASTICCTL_ES_URL").ok(),
            api_key: std::env::var("ELASTICCTL_API_KEY").ok(),
            space: std::env::var("ELASTICCTL_SPACE").ok(),
            timeout_secs: std::env::var("ELASTICCTL_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok()),
        }
    }

    /// Merge overrides, preferring `self` over `lower`.
    pub fn merge_over(self, lower: Overrides) -> Overrides {
        Overrides {
            kibana_url: self.kibana_url.or(lower.kibana_url),
            es_url: self.es_url.or(lower.es_url),
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

    /// Treat a missing file as an empty config so `config init` works on a new
    /// machine.
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

    /// Describe insecure file permissions, or return `None` for absent or
    /// owner-only files.
    ///
    /// The caller decides whether and how to display this warning, including
    /// for CLI `--json` output.
    #[cfg(unix)]
    pub fn permission_warning(path: &Path) -> Option<String> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path).ok()?;
        let mode = metadata.permissions().mode();
        // Group or other permission bits are set.
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
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|e| {
            Error::new(
                ErrorKind::Error,
                format!("creating {}: {e}", parent.display()),
            )
        })?;
        let body = toml::to_string_pretty(self)
            .map_err(|e| Error::new(ErrorKind::Error, format!("serializing config: {e}")))?;

        // Write to a same-directory temporary file, then rename it over the
        // destination. This replaces the file atomically instead of truncating
        // it in place, so an existing loose-permission file or a symlink is
        // never written through.
        let mut pending = tempfile::Builder::new()
            .prefix(".elasticctl-config-")
            .tempfile_in(parent)
            .map_err(|e| {
                Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            pending
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
                })?;
        }
        use std::io::Write;
        pending
            .write_all(body.as_bytes())
            .map_err(|e| Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display())))?;
        pending
            .as_file()
            .sync_all()
            .map_err(|e| Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display())))?;
        pending
            .persist(path)
            .map_err(|e| Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display())))?;
        #[cfg(unix)]
        fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|e| Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display())))?;
        Ok(())
    }

    /// Resolve the effective profile and its source.
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
        // Do not combine an overridden Kibana URL with a profile Elasticsearch
        // URL: they can target separate deployments. Without an `es_url`
        // override, fall back to the Kibana host instead of sending credentials
        // to the profile's Elasticsearch host.
        if let Some(v) = &ov.es_url {
            profile.es_url = Some(v.clone());
        } else if ov.kibana_url.is_some() {
            profile.es_url = None;
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

        // Strip userinfo after applying file, environment, and flag values.
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

    #[cfg(unix)]
    #[test]
    fn save_atomically_replaces_a_permissive_existing_file() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "old\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let old_inode = fs::metadata(&path).unwrap().ino();

        sample().save(&path).unwrap();

        let metadata = fs::metadata(&path).unwrap();
        assert_ne!(metadata.ino(), old_inode, "save must replace, not truncate");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(Config::load(&path).unwrap().current, "default");
    }

    #[cfg(unix)]
    #[test]
    fn save_replaces_a_symlink_without_writing_its_target() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.toml");
        let path = dir.path().join("config.toml");
        fs::write(&target, "do not replace\n").unwrap();
        symlink(&target, &path).unwrap();

        sample().save(&path).unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "do not replace\n");
        assert!(!fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
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

    /// Verify that `ELASTICCTL_ES_URL` overrides the profile. This prevents a
    /// Kibana override and inherited `es_url` from targeting two deployments.
    #[test]
    fn an_es_url_override_is_applied() {
        let r = sample()
            .resolve(
                None,
                &Overrides {
                    es_url: Some("https://other-es.example.com".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            r.profile.es_url.as_deref(),
            Some("https://other-es.example.com")
        );
    }

    /// A Kibana-only override must clear the profile's Elasticsearch host.
    /// Otherwise credentials could be sent to an unselected deployment.
    #[test]
    fn overriding_only_the_kibana_url_clears_the_profiles_es_url() {
        let r = sample()
            .resolve(
                None,
                &Overrides {
                    kibana_url: Some("https://other-kb.example.com".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            r.profile.es_url, None,
            "an inherited es_url would point at the profile's stack, not the overridden one"
        );
    }

    #[test]
    fn an_es_url_override_counts_as_an_identity_override() {
        let r = sample()
            .resolve(
                None,
                &Overrides {
                    es_url: Some("https://other-es.example.com".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            r.source,
            Source::Flags,
            "changing which stack is addressed is an identity change"
        );
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
        // Check key storage and file permissions together.
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
        // Verify the file is newly created.
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
        // `load` does not print; callers use `permission_warning` instead.
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
        // Strip userinfo after flags and environment overrides are applied.
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
        // The approval banner must not expose a password.
        let r = with_urls("https://user:hunter2@prod.example.com", None)
            .resolve(None, &Overrides::default())
            .unwrap();
        let b = r.banner();
        assert!(!b.contains("hunter2"), "{b}");
        // The banner uses one `@` between profile name and host.
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
        // Only the authority carries userinfo; paths and queries may contain `@`.
        let mut p =
            with_urls("https://kb.example.com/a@b?user=x@y", None).profiles["default"].clone();
        p.strip_userinfo();
        assert_eq!(p.kibana_url, "https://kb.example.com/a@b?user=x@y");
    }
}
