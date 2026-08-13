//! Profile management. `show` and `list` always redact.

use crate::cli::GlobalArgs;
use crate::context::{self, Context};
use elasticctl_core::{Config, Error, ErrorKind, Overrides, Profile, Result};
use serde_json::{Value, json};

pub fn list(global: &GlobalArgs) -> Result<Value> {
    let path = context::config_path(global);
    let config = Config::load(&path)?;
    let rows: Vec<Value> = config
        .profiles
        .iter()
        .map(|(name, p)| {
            json!({
                "name": name,
                "current": *name == config.current,
                "kibana_url": p.kibana_url,
                "space": p.space,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

pub fn show(global: &GlobalArgs) -> Result<Value> {
    let path = context::config_path(global);
    let config = Config::load(&path)?;
    let resolved = config.resolve(global.profile.as_deref(), &Overrides::default())?;
    // Redaction happens here, once, so no caller can forget it.
    serde_json::to_value(resolved.profile.redacted())
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding profile: {e}")))
}

pub fn init(global: &GlobalArgs, name: Option<&str>, from_env: bool) -> Result<Value> {
    let path = context::config_path(global);
    let mut config = Config::load(&path)?;
    let name = name.unwrap_or("default").to_string();

    let env = Overrides::from_env();
    if !from_env {
        return Err(Error::new(
            ErrorKind::Error,
            "Interactive init is not available yet. Set ELASTICCTL_KIBANA_URL and \
             ELASTICCTL_API_KEY, then run: elasticctl config init --from-env",
        ));
    }

    let kibana_url = env
        .kibana_url
        .ok_or_else(|| Error::new(ErrorKind::Error, "ELASTICCTL_KIBANA_URL is not set"))?;

    let profile = Profile {
        kibana_url,
        es_url: std::env::var("ELASTICCTL_ES_URL").ok(),
        api_key: env.api_key,
        username: None,
        password: None,
        space: env.space.unwrap_or_else(|| "default".into()),
        verify: true,
        timeout_secs: env.timeout_secs.unwrap_or(30),
    };

    // `resolve` strips on read; stripping here as well means a credential in
    // ELASTICCTL_KIBANA_URL never reaches disk in the first place.
    let mut profile = profile;
    profile.strip_userinfo();
    config.profiles.insert(name.clone(), profile);
    if config.current.is_empty() {
        config.current = name.clone();
    }
    config.save(&path)?;

    Ok(json!({"profile": name, "path": path.display().to_string(), "written": true}))
}

pub async fn test(ctx: &Context) -> Result<Value> {
    ctx.require_credential()?;
    let caps = ctx.capabilities().await?;
    Ok(json!({
        "profile": ctx.resolved.name,
        "kibana_url": ctx.resolved.profile.kibana_url,
        "reachable": true,
        "flavor": caps.flavor.as_str(),
        "version": caps.version,
    }))
}
