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

use elasticctl_core::{Error, ErrorKind, Profile, Result, Transport};
use serde_json::json;

/// Log in as `username`/`password` against `kibana_url`, activating that
/// user's profile, then verify the activation actually took: a 200 from the
/// login route does not by itself prove a profile now exists to assign to,
/// the same reasoning `conformance_matrix.rs::install_prebuilt_rules`
/// applies to its own `200` response (a successful-looking response can
/// still mean nothing happened). Reading `users_find` back and requiring a
/// non-empty list is the exact check the recorder already makes after
/// activation (`xtask/src/main.rs`'s `users_find` block) — doing it here
/// means a silent activation failure surfaces at this `lab-activate` step,
/// not ~20 minutes later misattributed as a `triage` contract failure
/// ("no activated user profile is available for assignment").
///
/// Idempotent from the caller's perspective: logging in again when a
/// profile is already active changes nothing `users_find` observes.
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

    let users_body = transport
        .get_internal(&elasticctl_api::profiles::internal_find_path(""))
        .await?;
    let profiles = elasticctl_api::profiles::decode_internal(&users_body)?;
    if profiles.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "profile activation login succeeded but users_find still reports no activated \
             profiles",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn activate_profile_succeeds_when_login_and_users_find_both_report_a_profile() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/internal/security/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"username": "elastic"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/internal/detection_engine/users/_find"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"uid": "u_1", "user": {"username": "elastic"}, "data": {}, "enabled": true}
            ])))
            .mount(&server)
            .await;

        activate_profile(&server.uri(), "elastic", "elasticctl-lab")
            .await
            .expect("activation with a non-empty users_find must succeed");
    }

    /// A login `200` does not by itself prove a profile now exists —
    /// `users_find` still reporting empty must be a named activation error,
    /// not a silent success that only surfaces later as a `triage` contract
    /// failure.
    #[tokio::test]
    async fn activate_profile_errors_when_login_succeeds_but_no_profile_is_activated() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/internal/security/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"username": "elastic"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/internal/detection_engine/users/_find"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let error = activate_profile(&server.uri(), "elastic", "elasticctl-lab")
            .await
            .expect_err("an empty users_find after a 200 login must be an error");
        assert!(
            error.message.contains("activat"),
            "error must name activation as the cause: {}",
            error.message
        );
    }
}
