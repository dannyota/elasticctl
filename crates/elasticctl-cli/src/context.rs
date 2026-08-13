//! Resolves configuration once and holds the transport for a command run.

use crate::cli::GlobalArgs;
use elasticctl_core::{
    Capabilities, Config, Credential, Error, ErrorKind, Overrides, Resolved, Result, Transport,
};
use tokio::sync::OnceCell;

/// The effective config path: `--config` if given, else the platform
/// default. Shared so every caller that needs to reason about the config
/// file — not just the ones that build a full `Context` — resolves it the
/// same way.
pub fn config_path(global: &GlobalArgs) -> std::path::PathBuf {
    global.config.clone().unwrap_or_else(Config::default_path)
}

pub struct Context {
    pub resolved: Resolved,
    pub global: GlobalArgs,
    transport: OnceCell<Transport>,
    caps: OnceCell<Capabilities>,
}

impl Context {
    /// Loads and resolves configuration only — no network types, no
    /// credential requirement. A command that only needs profile/space
    /// resolution (e.g. a future `rules validate`, which never contacts a
    /// server) can use a `Context` without a credential ever needing to
    /// exist; `transport()`/`capabilities()` are where that requirement
    /// actually bites.
    pub fn build(global: &GlobalArgs) -> Result<Context> {
        let path = config_path(global);
        let config = Config::load(&path)?;

        // Flags beat environment, environment beats the profile.
        let flags = Overrides {
            space: global.space.clone(),
            timeout_secs: global.timeout,
            ..Default::default()
        };
        let overrides = flags.merge_over(Overrides::from_env());

        let resolved = config.resolve(global.profile.as_deref(), &overrides)?;

        Ok(Context {
            resolved,
            global: global.clone(),
            transport: OnceCell::new(),
            caps: OnceCell::new(),
        })
    }

    /// Built once per run, on first use — the same lazy shape as
    /// `capabilities()`. This is where a missing credential actually fails
    /// (via `Transport::new`/`Credential::from_profile`), with a generic
    /// message. Call `require_credential()` first in any command that needs
    /// a live connection, so the operator sees its better message — naming
    /// the profile and the remedy — instead.
    pub async fn transport(&self) -> Result<&Transport> {
        self.transport
            .get_or_try_init(|| async {
                Transport::with_debug(&self.resolved.profile, self.global.debug)
            })
            .await
    }

    /// Probed once per run, on first use. A command that never needs the
    /// flavor never pays for the round trip.
    pub async fn capabilities(&self) -> Result<&Capabilities> {
        let transport = self.transport().await?;
        self.caps
            .get_or_try_init(|| async {
                Capabilities::probe(transport, &self.resolved.profile.kibana_url).await
            })
            .await
    }

    /// Fail early with a clear message when a profile carries no credential.
    ///
    /// Delegates the actual check to `Credential::is_configured` — the same
    /// test `Transport::new` applies via `Credential::from_profile` — so
    /// there is one definition of "has a credential", not two that can
    /// drift apart.
    pub fn require_credential(&self) -> Result<()> {
        if !Credential::is_configured(&self.resolved.profile) {
            return Err(Error::new(
                ErrorKind::Auth,
                format!(
                    "Profile '{}' has no credential. Run: elasticctl config init --profile {}",
                    self.resolved.name, self.resolved.name
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elasticctl_core::{Profile, Source};

    fn profile_with(
        api_key: Option<&str>,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Profile {
        Profile {
            kibana_url: "https://kb.example.com".into(),
            es_url: None,
            api_key: api_key.map(String::from),
            username: username.map(String::from),
            password: password.map(String::from),
            space: "default".into(),
            verify: true,
            timeout_secs: 30,
        }
    }

    fn context_with(profile: Profile) -> Context {
        Context {
            resolved: Resolved {
                profile,
                name: "test".into(),
                source: Source::Profile,
            },
            global: GlobalArgs::default(),
            transport: OnceCell::new(),
            caps: OnceCell::new(),
        }
    }

    #[test]
    fn require_credential_rejects_an_empty_api_key() {
        let ctx = context_with(profile_with(Some(""), None, None));
        let err = ctx.require_credential().unwrap_err();
        assert_eq!(err.kind, ErrorKind::Auth);
        assert!(err.message.contains("test"), "{}", err.message);
    }

    #[test]
    fn require_credential_rejects_a_username_without_a_password() {
        let ctx = context_with(profile_with(None, Some("elastic"), None));
        assert_eq!(ctx.require_credential().unwrap_err().kind, ErrorKind::Auth);
    }

    #[test]
    fn require_credential_accepts_a_configured_api_key() {
        let ctx = context_with(profile_with(Some("essu_abc"), None, None));
        assert!(ctx.require_credential().is_ok());
    }

    #[tokio::test]
    async fn build_succeeds_for_a_profile_with_no_credential() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
current = "nocreds"

[profiles.nocreds]
kibana_url = "https://kb.example.com"
space = "default"
verify = true
timeout_secs = 30
"#,
        )
        .unwrap();

        let global = GlobalArgs {
            config: Some(path),
            ..GlobalArgs::default()
        };
        let ctx = Context::build(&global).expect(
            "Context::build must succeed without a credential — that requirement belongs to \
             transport()/require_credential(), not to loading and resolving config",
        );
        assert!(ctx.require_credential().is_err());
    }
}
