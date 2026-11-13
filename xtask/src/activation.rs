use elasticctl_core::{Error, ErrorKind, Profile, Result, Transport};
use serde_json::json;

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

        activate_profile(&server.uri(), "elastic", "test-password")
            .await
            .expect("activation with a non-empty users_find must succeed");
    }

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

        let error = activate_profile(&server.uri(), "elastic", "test-password")
            .await
            .expect_err("an empty users_find after a 200 login must be an error");
        assert!(
            error.message.contains("activat"),
            "error must name activation as the cause: {}",
            error.message
        );
    }

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

        activate_profile(&server.uri(), "elastic", "test-password")
            .await
            .expect("activation must use the provider name login_state advertises");
    }

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

        let error = activate_profile(&server.uri(), "elastic", "test-password")
            .await
            .expect_err("a stack with no basic provider must fail at provider resolution");
        assert!(
            error.message.contains("Basic login provider"),
            "error must name the missing basic provider: {}",
            error.message
        );
    }
}
