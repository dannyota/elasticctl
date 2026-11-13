use crate::activation;
use crate::diagnostics::{recording_error, safe_recording_transport_error};

pub(crate) fn transport_from_env(default_timeout_secs: u64) -> elasticctl_core::Transport {
    let timeout_secs = std::env::var("ELASTICCTL_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_timeout_secs);
    let mut profile = elasticctl_core::Profile {
        kibana_url: std::env::var("ELASTICCTL_KIBANA_URL").expect("ELASTICCTL_KIBANA_URL"),
        es_url: std::env::var("ELASTICCTL_ES_URL").ok(),
        api_key: Some(std::env::var("ELASTICCTL_API_KEY").expect("ELASTICCTL_API_KEY")),
        username: None,
        password: None,
        space: std::env::var("ELASTICCTL_SPACE").unwrap_or_else(|_| "default".into()),
        verify: true,
        timeout_secs,
    };
    profile.strip_userinfo();
    elasticctl_core::Transport::new(&profile).expect("transport")
}

struct TraditionalRecorderLogin<'a> {
    username: &'a str,
    password: &'a str,
}

fn traditional_recorder_login_inputs<'a>(
    flavor: Option<&str>,
    username: Option<&'a str>,
    password: Option<&'a str>,
) -> elasticctl_core::Result<Option<TraditionalRecorderLogin<'a>>> {
    if flavor != Some("traditional") {
        return Ok(None);
    }
    let username = username
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            recording_error("ELASTICCTL_USERNAME is required for traditional fixture recording")
        })?;
    let password = password
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            recording_error("ELASTICCTL_PASSWORD is required for traditional fixture recording")
        })?;
    Ok(Some(TraditionalRecorderLogin { username, password }))
}

pub(crate) async fn activate_traditional_recorder_profile() -> elasticctl_core::Result<()> {
    let flavor = std::env::var("ELASTICCTL_FIXTURE_FLAVOR").ok();
    let username = std::env::var("ELASTICCTL_USERNAME").ok();
    let password = std::env::var("ELASTICCTL_PASSWORD").ok();
    let login = traditional_recorder_login_inputs(
        flavor.as_deref(),
        username.as_deref(),
        password.as_deref(),
    )?;
    let Some(login) = login else {
        return Ok(());
    };
    let kibana_url = std::env::var("ELASTICCTL_KIBANA_URL").map_err(|_| {
        recording_error("ELASTICCTL_KIBANA_URL is required for traditional fixture recording")
    })?;
    activation::activate_profile(&kibana_url, login.username, login.password)
        .await
        .map_err(|error| {
            safe_recording_transport_error("traditional profile activation failed", error)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traditional_recorder_activation_requires_generic_login_inputs_only_for_exact_flavor() {
        let login = traditional_recorder_login_inputs(
            Some("traditional"),
            Some("fixture-user"),
            Some("fixture-password"),
        )
        .expect("traditional login inputs");
        assert_eq!(
            login.map(|login| (login.username, login.password)),
            Some(("fixture-user", "fixture-password"))
        );

        for (username, password, expected) in [
            (None, Some("fixture-password"), "ELASTICCTL_USERNAME"),
            (Some("fixture-user"), None, "ELASTICCTL_PASSWORD"),
            (
                Some(" \t "),
                Some("fixture-password"),
                "ELASTICCTL_USERNAME",
            ),
            (Some("fixture-user"), Some("\n "), "ELASTICCTL_PASSWORD"),
        ] {
            let error =
                match traditional_recorder_login_inputs(Some("traditional"), username, password) {
                    Err(error) => error,
                    Ok(_) => panic!("a traditional recorder must require both login inputs"),
                };
            assert_eq!(
                error.message,
                format!("{expected} is required for traditional fixture recording")
            );
        }

        for flavor in [None, Some("serverless"), Some("ech"), Some("Traditional")] {
            assert!(
                traditional_recorder_login_inputs(flavor, None, None)
                    .expect("nontraditional flavor needs no login")
                    .is_none()
            );
        }
    }
}
