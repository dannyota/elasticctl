//! Resolves configuration once and holds the transport for a command run.

use crate::cli::GlobalArgs;
use elasticctl_core::{
    Capabilities, Config, Error, ErrorKind, Overrides, Resolved, Result, Transport,
};
use tokio::sync::OnceCell;

// Not yet constructed by any command — wired in as commands adopt it in
// later tasks.
#[expect(dead_code)]
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
    #[expect(dead_code)]
    pub fn require_credential(&self) -> Result<()> {
        if self.resolved.profile.api_key.is_none() && self.resolved.profile.username.is_none() {
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
