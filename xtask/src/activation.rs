//! Kibana user-profile activation.
//!
//! `POST /internal/security/login` is the only call that activates a
//! profile: a raw Elasticsearch API key, or an HTTP Basic call to an
//! ordinary Kibana route, does not (design spec
//! `elasticctl-triage-design.md` section 10, measured 2026-09-01 on the
//! traditional lab). The triage conformance contract needs one activated
//! profile to exercise its assign/unassign step. Serverless and Hosted
//! already carry one from the operator's own SSO login; the self-managed
//! lab boots headless, with no browser session ever logging in, so the
//! traditional matrix leg calls this once at boot (`conformance_matrix.rs`,
//! `run_traditional_boot_and_leg`).

use elasticctl_core::{Profile, Result, Transport};
use serde_json::json;

/// Log in as `username`/`password` against `kibana_url`, activating that
/// user's profile.
///
/// Idempotent from the caller's perspective: logging in again when a
/// profile is already active changes nothing a later `profiles::suggest` or
/// `users_find` observes.
pub(crate) async fn activate_profile(
    kibana_url: &str,
    username: &str,
    password: &str,
) -> Result<()> {
    let mut profile = Profile {
        kibana_url: kibana_url.to_string(),
        es_url: None,
        api_key: None,
        username: Some(username.to_string()),
        password: Some(password.to_string()),
        space: "default".to_string(),
        verify: true,
        timeout_secs: 30,
    };
    profile.strip_userinfo();
    let transport = Transport::new(&profile)?;
    transport
        .post_internal(
            "/internal/security/login",
            &json!({
                "providerType": "basic",
                "providerName": "basic",
                "currentURL": "/",
                "params": {"username": username, "password": password},
            }),
        )
        .await?;
    Ok(())
}
