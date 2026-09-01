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
//! `run_traditional_boot_and_leg`). The Hosted leg calls it too when
//! `ELASTICCTL_ECH_USERNAME` and `ELASTICCTL_ECH_PASSWORD` are both set
//! (`run_ech_leg`), which is why the login provider's name is discovered
//! rather than assumed: Hosted names it `cloud-basic`, the lab `basic`.

use elasticctl_core::{Error, ErrorKind, Profile, Result, Transport};
use serde_json::json;

/// Resolve the name Kibana gives its HTTP Basic login provider.
///
/// `POST /internal/security/login` takes a provider's *configured name*, not
/// its type, and answers `401 Unauthorized` for a name the deployment does
/// not configure — indistinguishable from a wrong password. A self-managed
/// stack names the provider `basic`; an Elastic Cloud Hosted deployment
/// names it `cloud-basic` (measured 2026-09-01: `basic` answers 401 there
/// and `cloud-basic` answers 200, with the same credentials). Reading the
/// name off `GET /internal/security/login_state` keeps that a runtime probe
/// rather than a per-flavor branch, so a deployment that renames or adds a
/// basic provider still activates.
///
/// `selector.enabled` is deliberately ignored: the lab reports it `false`
/// while still listing the provider, and it only controls whether Kibana
/// draws a chooser.
async fn basic_provider_name(transport: &Transport) -> Result<String> {
    let state = transport
        .get_internal("/internal/security/login_state")
        .await?;
    state["selector"]["providers"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|provider| provider["type"] == "basic" && provider["usesLoginForm"] == true)
        .and_then(|provider| provider["name"].as_str())
        .map(str::to_string)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                "login_state advertises no HTTP Basic login provider, so no profile can be \
                 activated by logging in",
            )
        })
}

/// Log in as `username`/`password` against `kibana_url` through whichever
/// HTTP Basic provider that deployment advertises (see
/// `basic_provider_name`), activating that user's profile, then verify the
/// activation actually took: a 200 from the
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
    let provider_name = basic_provider_name(&transport).await?;
    transport
        .post_internal(
            "/internal/security/login",
            &json!({
                "providerType": "basic",
                "providerName": provider_name,
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
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Mount a `login_state` answering with one basic provider under
    /// `name`, the shape both a self-managed stack (`basic`) and an Elastic
    /// Cloud Hosted deployment (`cloud-basic`) return.
    async fn mount_login_state(server: &MockServer, name: &str) {
        Mock::given(method("GET"))
            .and(path("/internal/security/login_state"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "allowLogin": true,
                "layout": "form",
                "selector": {
                    "enabled": false,
                    "providers": [
                        {"type": "basic", "name": name, "usesLoginForm": true}
                    ]
                }
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn activate_profile_succeeds_when_login_and_users_find_both_report_a_profile() {
        let server = MockServer::start().await;
        mount_login_state(&server, "basic").await;
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
        mount_login_state(&server, "basic").await;
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

    /// The login body must carry the provider name the deployment actually
    /// advertises. Hosted calls its basic provider `cloud-basic` and answers
    /// 401 for `basic`, so a hardcoded name fails the Hosted leg with an
    /// error indistinguishable from a wrong password. The login mock here
    /// only matches `cloud-basic`; a regression to a fixed `basic` leaves it
    /// unmatched and fails the test.
    #[tokio::test]
    async fn activate_profile_logs_in_through_the_advertised_provider_name() {
        let server = MockServer::start().await;
        mount_login_state(&server, "cloud-basic").await;
        Mock::given(method("POST"))
            .and(path("/internal/security/login"))
            .and(body_partial_json(json!({"providerName": "cloud-basic"})))
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
            .expect("activation must use the provider name login_state advertises");
    }

    /// A deployment with no HTTP Basic provider cannot be activated by
    /// logging in at all; that must be a named error at this step rather
    /// than a 401 that reads like a bad password.
    #[tokio::test]
    async fn activate_profile_errors_when_no_basic_provider_is_advertised() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/internal/security/login_state"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "allowLogin": true,
                "selector": {
                    "enabled": true,
                    "providers": [
                        {"type": "saml", "name": "cloud-saml-kibana", "usesLoginForm": false}
                    ]
                }
            })))
            .mount(&server)
            .await;

        let error = activate_profile(&server.uri(), "elastic", "elasticctl-lab")
            .await
            .expect_err("a stack with no basic provider must fail at provider resolution");
        assert!(
            error.message.contains("Basic login provider"),
            "error must name the missing basic provider: {}",
            error.message
        );
    }
}
