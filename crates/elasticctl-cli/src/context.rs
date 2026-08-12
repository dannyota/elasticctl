//! Resolves configuration once and holds the transport for a command run.

use crate::cli::GlobalArgs;
use elasticctl_core::{
    Capabilities, Config, Credential, Error, ErrorKind, Overrides, Resolved, Result, Transport,
};
use tokio::sync::OnceCell;

// Not yet constructed by any command — wired in as commands adopt it in
// later tasks. (Exercised directly by this module's tests in the meantime,
// so `#[allow]` rather than `#[expect]`: the lint only fires in a plain
// build, never in a test build.)
#[allow(dead_code)]
pub struct Context {
    pub resolved: Resolved,
    pub transport: Transport,
    pub global: GlobalArgs,
    caps: OnceCell<Capabilities>,
}

impl Context {
    #[expect(dead_code)]
    pub fn build(global: &GlobalArgs) -> Result<Context> {
        let path = global.config.clone().unwrap_or_else(Config::default_path);
        let config = Config::load(&path)?;

        // Flags beat environment, environment beats the profile.
        let flags = Overrides {
            space: global.space.clone(),
            timeout_secs: global.timeout,
            ..Default::default()
        };
        let overrides = flags.merge_over(Overrides::from_env());

        let resolved = config.resolve(global.profile.as_deref(), &overrides)?;
        let transport = Transport::new(&resolved.profile)?;

        Ok(Context {
            resolved,
            transport,
            global: global.clone(),
            caps: OnceCell::new(),
        })
    }

    /// Probed once per run, on first use. A command that never needs the
    /// flavor never pays for the round trip.
    #[expect(dead_code)]
    pub async fn capabilities(&self) -> Result<&Capabilities> {
        self.caps
            .get_or_try_init(|| async {
                Capabilities::probe(&self.transport, &self.resolved.profile.kibana_url).await
            })
            .await
    }

    /// Fail early with a clear message when a profile carries no credential.
    ///
    /// Delegates the actual check to `Credential::is_configured` — the same
    /// test `Transport::new` already applies via `Credential::from_profile` —
    /// so there is one definition of "has a credential", not two that can
    /// drift apart.
    #[allow(dead_code)]
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

    /// `require_credential` only reads `resolved.profile`, so the `transport`
    /// field can carry any validly-constructed `Transport` — its own profile
    /// need not match the one under test.
    fn context_with(profile: Profile) -> Context {
        let dummy = profile_with(Some("valid-key"), None, None);
        let transport = Transport::new(&dummy).unwrap();
        Context {
            resolved: Resolved {
                profile,
                name: "test".into(),
                source: Source::Profile,
            },
            transport,
            global: GlobalArgs::default(),
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
}
