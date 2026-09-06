use elasticctl_core::{ErrorKind, Profile, Transport, TransportOptions};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn profile_for(server: &MockServer) -> Profile {
    profile_for_url(server.uri())
}

fn profile_for_url(kibana_url: String) -> Profile {
    Profile {
        kibana_url,
        es_url: None,
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    }
}

fn limited_transport(profile: &Profile, limit: usize) -> Transport {
    Transport::with_options(
        profile,
        TransportOptions {
            response_body_limit: Some(limit),
            ..Default::default()
        },
    )
    .expect("transport options are valid")
}

fn assert_limit_error(error: elasticctl_core::Error) {
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(error.message, "response body exceeds configured byte limit");
}

async fn raw_response_server(response: String) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind raw responder");
    let url = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept request");
        let mut request = [0; 4096];
        let _ = stream.read(&mut request).await;
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write raw response");
        let _ = stream.shutdown().await;
    });
    url
}

#[tokio::test]
async fn response_limit_accepts_bodies_below_or_at_the_boundary() {
    for (path_name, body, limit) in [
        ("/below", r#"{"v":"123456"}"#, 16_usize),
        ("/at", r#"{"v":"12345678"}"#, 16_usize),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(path_name))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;

        let transport = limited_transport(&profile_for(&server), limit);
        assert_eq!(
            transport.get(path_name).await.unwrap()["v"],
            body[6..body.len() - 2]
        );
    }
}

#[tokio::test]
async fn response_limit_rejects_a_declared_success_body_above_the_boundary() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/above"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"v":"123456789"}"#))
        .expect(1)
        .mount(&server)
        .await;

    let error = limited_transport(&profile_for(&server), 16)
        .get("/above")
        .await
        .expect_err("a declared body above the limit must be rejected");
    assert_limit_error(error);
}

#[tokio::test]
async fn response_limit_counts_an_unknown_length_chunked_body() {
    let url = raw_response_server(
        concat!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n",
            "8\r\n{\"v\":\"12\r\n",
            "9\r\n3456789\"}\r\n",
            "0\r\n\r\n"
        )
        .to_string(),
    )
    .await;

    let error = limited_transport(&profile_for_url(url), 16)
        .get("/chunked")
        .await
        .expect_err("an unknown-length body above the limit must be rejected");
    assert_limit_error(error);
}

#[tokio::test]
async fn response_limit_rejects_an_oversized_error_body_without_retrying() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/error"))
        .respond_with(ResponseTemplate::new(503).set_body_string(r#"{"message":"123456789"}"#))
        .expect(1)
        .mount(&server)
        .await;

    let error = limited_transport(&profile_for(&server), 16)
        .get("/error")
        .await
        .expect_err("an oversized error body must be rejected before a retry");
    assert_limit_error(error);
}

#[tokio::test]
async fn incomplete_body_is_classified_as_a_connection_error() {
    let url = raw_response_server(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"v\":\"short\"}".into(),
    )
    .await;

    let error = limited_transport(&profile_for_url(url), 16)
        .get("/truncated")
        .await
        .expect_err("a body that ends before its declared length must fail");
    assert_eq!(error.kind, ErrorKind::Connection);
}

#[tokio::test]
async fn disabled_redirects_do_not_follow_a_redirect_to_another_authority() {
    let source = MockServer::start().await;
    let destination = MockServer::start().await;
    let replacement = format!("{}/target", destination.uri());
    Mock::given(method("GET"))
        .and(path("/source"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", replacement))
        .expect(1)
        .mount(&source)
        .await;
    Mock::given(method("GET"))
        .and(path("/target"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(0)
        .mount(&destination)
        .await;

    let transport = Transport::with_options(
        &profile_for(&source),
        TransportOptions {
            disable_redirects: true,
            ..Default::default()
        },
    )
    .unwrap();
    let error = transport
        .get("/source")
        .await
        .expect_err("redirect suppression must return the source response");
    assert_eq!(error.kind, ErrorKind::Http);
    assert_eq!(error.http_status, Some(307));
}

#[tokio::test]
async fn existing_constructors_keep_unlimited_bodies_and_redirects() {
    let source = MockServer::start().await;
    let destination = MockServer::start().await;
    let replacement = format!("{}/target", destination.uri());
    Mock::given(method("GET"))
        .and(path("/source"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", replacement))
        .expect(2)
        .mount(&source)
        .await;
    Mock::given(method("GET"))
        .and(path("/target"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(2)
        .mount(&destination)
        .await;

    for transport in [
        Transport::new(&profile_for(&source)).unwrap(),
        Transport::with_debug(&profile_for(&source), true).unwrap(),
    ] {
        assert_eq!(transport.get("/source").await.unwrap()["ok"], true);
    }
}

#[tokio::test]
async fn disabled_retries_send_one_kibana_or_absolute_es_post() {
    for status in [429, 503] {
        for absolute_es in [false, true] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/retry"))
                .respond_with(
                    ResponseTemplate::new(status).set_body_json(json!({"message": "retry"})),
                )
                .expect(1)
                .mount(&server)
                .await;

            let mut profile = profile_for(&server);
            if absolute_es {
                profile.es_url = Some(server.uri());
            }
            let transport = Transport::with_options(
                &profile,
                TransportOptions {
                    disable_retries: true,
                    ..Default::default()
                },
            )
            .unwrap();
            let result = if absolute_es {
                transport.post_absolute_es("/retry", &json!({})).await
            } else {
                transport.post("/retry", Some(&json!({}))).await
            };
            assert_eq!(result.unwrap_err().http_status, Some(status));
        }
    }
}

#[tokio::test]
async fn existing_constructor_retries_transient_kibana_and_absolute_es_posts_three_times() {
    for status in [429, 503] {
        for absolute_es in [false, true] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/retry"))
                .respond_with(
                    ResponseTemplate::new(status).set_body_json(json!({"message": "retry"})),
                )
                .expect(3)
                .mount(&server)
                .await;

            let mut profile = profile_for(&server);
            if absolute_es {
                profile.es_url = Some(server.uri());
            }
            let transport = Transport::new(&profile).unwrap();
            let result = if absolute_es {
                transport.post_absolute_es("/retry", &json!({})).await
            } else {
                transport.post("/retry", Some(&json!({}))).await
            };
            assert_eq!(result.unwrap_err().http_status, Some(status));
        }
    }
}
