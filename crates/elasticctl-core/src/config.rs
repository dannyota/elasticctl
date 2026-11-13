use crate::error::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn validate_space(space: &str) -> Result<()> {
    if space.is_empty() {
        return Ok(());
    }
    if !space
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
    {
        return Err(Error::new(ErrorKind::Error, "invalid space id"));
    }
    Ok(())
}

const REDACTED: &str = "***";

fn is_identity_override(ov: &Overrides) -> bool {
    ov.kibana_url.is_some() || ov.es_url.is_some() || ov.api_key.is_some()
}

fn checked_env(name: &str) -> Result<Option<String>> {
    match std::env::var_os(name) {
        None => Ok(None),
        Some(value) => value.into_string().map(Some).map_err(|_| {
            Error::new(
                ErrorKind::Error,
                format!("{name} contains invalid Unicode; set it to valid UTF-8"),
            )
        }),
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Profile")
            .field("kibana_url", &strip_userinfo(&self.kibana_url))
            .field("es_url", &self.es_url.as_deref().map(strip_userinfo))
            .field("api_key", &self.api_key.as_ref().map(|_| REDACTED))
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| REDACTED))
            .field("space", &self.space)
            .field("verify", &self.verify)
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

impl Profile {
    pub fn redacted(&self) -> Profile {
        let mut scrubbed = self.clone();
        scrubbed.strip_userinfo();
        Profile {
            api_key: self.api_key.as_ref().map(|_| REDACTED.to_string()),
            password: self.password.as_ref().map(|_| REDACTED.to_string()),
            ..scrubbed
        }
    }

    pub fn host(&self) -> String {
        let url = strip_userinfo(&self.kibana_url);
        if let Some(pos) = scheme_anchor(&url) {
            let after_scheme = &url[pos..];
            let host_part = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
            if !host_part.is_empty() {
                return host_part.to_string();
            }
        }
        url
    }

    pub fn strip_userinfo(&mut self) {
        self.kibana_url = strip_userinfo(&self.kibana_url);
        self.es_url = self.es_url.as_deref().map(strip_userinfo);
    }
}

pub(crate) fn scheme_anchor(url: &str) -> Option<usize> {
    let first = url.find("://")?;
    let after = &url[first + 3..];
    let Some(delim) = after.find(['/', '?', '#']) else {
        return Some(first + 3);
    };
    if delim >= 1
        && after.as_bytes()[delim - 1] == b':'
        && after.get(delim..delim + 2) == Some("//")
    {
        Some(first + 3 + delim + 2)
    } else {
        Some(first + 3)
    }
}

fn strip_userinfo(url: &str) -> String {
    let Some(scheme_end) = scheme_anchor(url) else {
        return url.to_string();
    };
    let (scheme, rest) = url.split_at(scheme_end);
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

    pub fn try_from_env() -> Result<Overrides> {
        Self::try_from_env_with_flags(&Overrides::default())
    }

    pub fn try_from_env_with_flags(flags: &Overrides) -> Result<Overrides> {
        let timeout = if flags.timeout_secs.is_some() {
            std::env::var("ELASTICCTL_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
        } else {
            match checked_env("ELASTICCTL_TIMEOUT")? {
                None => None,
                Some(value) => Some(value.parse::<u64>().map_err(|error| {
                    Error::new(
                        ErrorKind::Error,
                        format!("ELASTICCTL_TIMEOUT must be an unsigned integer: {error}"),
                    )
                })?),
            }
        };
        let space = if flags.space.is_some() {
            std::env::var("ELASTICCTL_SPACE").ok()
        } else {
            checked_env("ELASTICCTL_SPACE")?
        };
        Ok(Overrides {
            kibana_url: checked_env("ELASTICCTL_KIBANA_URL")?,
            es_url: checked_env("ELASTICCTL_ES_URL")?,
            api_key: checked_env("ELASTICCTL_API_KEY")?,
            space,
            timeout_secs: timeout,
        })
    }

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

    #[cfg(unix)]
    pub fn permission_warning(path: &Path) -> Option<String> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path).ok()?;
        let mode = metadata.permissions().mode();
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
        let mut scrubbed = self.clone();
        for profile in scrubbed.profiles.values_mut() {
            profile.strip_userinfo();
        }
        let body = toml::to_string_pretty(&scrubbed)
            .map_err(|e| Error::new(ErrorKind::Error, format!("serializing config: {e}")))?;

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
        pending.write_all(body.as_bytes()).map_err(|e| {
            Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
        })?;
        pending.as_file().sync_all().map_err(|e| {
            Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
        })?;
        pending.persist(path).map_err(|e| {
            Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
        })?;
        #[cfg(target_os = "linux")]
        fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|e| {
                Error::new(ErrorKind::Error, format!("writing {}: {e}", path.display()))
            })?;
        Ok(())
    }

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

        validate_space(&profile.space)?;

        let source = if is_identity_override(ov) {
            Source::Flags
        } else {
            Source::Profile
        };

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

    #[test]
    fn invalid_spaces_are_refused_during_resolution() {
        for space in [
            ".", "..", "a/b", "a?b", "%2e%2e", "UPPER", "a b", "é", "a\\b",
        ] {
            let mut config = sample();
            config.profiles.get_mut("default").unwrap().space = space.into();
            for overrides in [
                Overrides::default(),
                Overrides {
                    space: Some(space.into()),
                    ..Default::default()
                },
            ] {
                let error = config.resolve(None, &overrides).unwrap_err();
                assert_eq!(error.kind, ErrorKind::Error);
                assert_eq!(error.message, "invalid space id");
            }
        }
    }

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
        assert!(
            !fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn save_never_writes_userinfo_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = with_urls(
            "https://user:pass@kb.example.com",
            Some("https://user:pass@es.example.com"),
        );
        cfg.save(&path).unwrap();
        let body = fs::read_to_string(&path).unwrap();
        assert!(!body.contains("user:pass"), "{body}");
        assert!(!body.contains("user:"), "{body}");
        assert!(body.contains("https://kb.example.com"), "{body}");
        assert!(body.contains("https://es.example.com"), "{body}");
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
    fn redacted_strips_userinfo_from_both_urls() {
        let mut p = sample().profiles["default"].clone();
        p.kibana_url = "https://user:pass@kb.example.com".into();
        p.es_url = Some("https://user:pass@es.example.com".into());
        let r = p.redacted();
        assert_eq!(r.kibana_url, "https://kb.example.com");
        assert_eq!(r.es_url.as_deref(), Some("https://es.example.com"));
        assert_eq!(r.api_key.as_deref(), Some("***"), "secrets still redact");
    }

    #[test]
    fn debug_never_prints_a_secret_or_userinfo() {
        let profile = with_urls(
            "https://user:pass@kb.example.com",
            Some("https://user:pass@es.example.com"),
        )
        .profiles["default"]
            .clone();
        let out = format!("{profile:?}");
        assert!(!out.contains("essu_SECRET"), "api key leaked: {out}");
        assert!(!out.contains("user:pass"), "userinfo leaked: {out}");
        assert!(!out.contains("pass@"), "userinfo leaked: {out}");
        assert!(out.contains("kb.example.com"), "host missing: {out}");
        assert!(out.contains("es.example.com"), "host missing: {out}");
    }

    #[test]
    fn debug_marks_the_api_key_present_but_redacted() {
        let profile = with_urls("https://kb.example.com", None).profiles["default"].clone();
        let out = format!("{profile:?}");
        assert!(
            out.contains("Some(\"***\")"),
            "api key must show present-but-redacted: {out}"
        );
        assert!(!out.contains("essu_SECRET"), "api key leaked: {out}");
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
        assert_eq!(p.host(), "kb.example.com");
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
    fn host_never_shows_userinfo() {
        let p = with_urls("https://user:pass@kb.example.com", None).profiles["default"].clone();
        assert_eq!(p.host(), "kb.example.com");
    }

    #[test]
    fn load_succeeds_on_a_permissive_file_and_prints_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sample().save(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
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
        sample().save(&path).unwrap();
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
        let r = with_urls("https://user:hunter2@prod.example.com", None)
            .resolve(None, &Overrides::default())
            .unwrap();
        let b = r.banner();
        assert!(!b.contains("hunter2"), "{b}");
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
        let mut p =
            with_urls("https://kb.example.com/a@b?user=x@y", None).profiles["default"].clone();
        p.strip_userinfo();
        assert_eq!(p.kibana_url, "https://kb.example.com/a@b?user=x@y");
    }

    #[test]
    fn a_query_string_scheme_without_userinfo_is_left_exactly_as_written() {
        let mut p =
            with_urls("https://kb.example.com/?next=https://idp", None).profiles["default"].clone();
        p.strip_userinfo();
        assert_eq!(p.kibana_url, "https://kb.example.com/?next=https://idp");
    }

    #[test]
    fn userinfo_is_stripped_when_a_query_contains_a_scheme() {
        let mut p = with_urls("https://user:pass@kb.example.com/?next=https://idp", None).profiles
            ["default"]
            .clone();
        p.strip_userinfo();
        assert_eq!(p.kibana_url, "https://kb.example.com/?next=https://idp");
    }

    #[test]
    fn host_uses_the_authority_when_a_query_contains_a_scheme() {
        let p = with_urls("https://user:pass@kb.example.com/?next=https://idp", None)
            .profiles["default"]
            .clone();
        assert_eq!(p.host(), "kb.example.com");
    }

    #[test]
    fn a_doubled_scheme_with_userinfo_is_stripped() {
        let mut p =
            with_urls("https://https://user:pass@kb.example.com", None).profiles["default"].clone();
        p.strip_userinfo();
        assert_eq!(p.kibana_url, "https://https://kb.example.com");
        assert_eq!(p.host(), "kb.example.com");
    }

    #[test]
    fn a_doubled_scheme_with_userinfo_and_a_query_scheme_strips_the_userinfo() {
        let mut p = with_urls(
            "https://https://user:pass@kb.example.com/?next=https://idp",
            None,
        )
        .profiles["default"]
            .clone();
        p.strip_userinfo();
        assert_eq!(
            p.kibana_url,
            "https://https://kb.example.com/?next=https://idp"
        );
    }

    #[test]
    fn an_empty_port_does_not_defeat_userinfo_stripping() {
        let mut p =
            with_urls("https://user:pass@host:/path?next=https://idp", None).profiles["default"]
                .clone();
        p.strip_userinfo();
        assert_eq!(p.kibana_url, "https://host:/path?next=https://idp");
    }

    #[test]
    fn percent_encoded_userinfo_scrubs_to_the_host() {
        assert_eq!(
            strip_userinfo("https://user%40x:pass@kb.example.com"),
            "https://kb.example.com"
        );
    }

    #[test]
    fn percent_encoded_path_and_query_without_userinfo_are_left_byte_identical() {
        let url = "https://kb.example.com/%2Fpath?next=%3F";
        assert_eq!(strip_userinfo(url), url);
    }
}
