use elasticctl_core::{Error, ErrorKind, Profile, Transport, TransportOptions};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Clone, Copy, Debug)]
enum Operation {
    Patch,
    Multipart,
    DeleteResponse,
    PatchResponse,
    MultipartResponse,
}

const OPERATIONS: [Operation; 5] = [
    Operation::Patch,
    Operation::Multipart,
    Operation::DeleteResponse,
    Operation::PatchResponse,
    Operation::MultipartResponse,
];

impl Operation {
    fn method(self) -> &'static str {
        match self {
            Self::Patch | Self::PatchResponse => "PATCH",
            Self::Multipart | Self::MultipartResponse => "POST",
            Self::DeleteResponse => "DELETE",
        }
    }

    async fn send(self, transport: &Transport, path: &str) -> elasticctl_core::Result<Value> {
        match self {
            Self::Patch => {
                transport
                    .patch_once(path, &json!({"name": "updated"}))
                    .await
            }
            Self::Multipart => {
                transport
                    .post_multipart_once_named(path, "values.txt", "text/plain", "alpha\nβeta\n")
                    .await
            }
            Self::DeleteResponse => transport
                .delete_once_response(path)
                .await
                .map(|(_, body)| body),
            Self::PatchResponse => transport
                .patch_once_response(path, &json!({"name": "updated"}))
                .await
                .map(|(_, body)| body),
            Self::MultipartResponse => transport
                .post_multipart_once_named_response(
                    path,
                    "values.txt",
                    "text/plain",
                    "alpha\nβeta\n",
                )
                .await
                .map(|(_, body)| body),
        }
    }
}

fn profile(url: String) -> Profile {
    Profile {
        kibana_url: url,
        es_url: None,
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "security".into(),
        verify: true,
        timeout_secs: 1,
    }
}

fn mutation_mock(operation: Operation) -> wiremock::MockBuilder {
    Mock::given(method(operation.method()))
        .and(path("/s/security/api/lists"))
        .and(header("Authorization", "ApiKey essu_test"))
        .and(header("kbn-xsrf", "true"))
        .and(header("elastic-api-version", "2023-10-31"))
}

#[tokio::test]
async fn patch_once_preserves_json_headers_and_space() {
    let server = MockServer::start().await;
    mutation_mock(Operation::Patch)
        .and(body_json(json!({"name": "updated"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "updated"})))
        .expect(1)
        .mount(&server)
        .await;

    let transport = Transport::new(&profile(server.uri())).unwrap();
    assert_eq!(
        Operation::Patch
            .send(&transport, "/api/lists")
            .await
            .unwrap(),
        json!({"name": "updated"})
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn multipart_once_sends_exactly_one_named_file_with_the_requested_type_and_bytes() {
    let server = MockServer::start().await;
    mutation_mock(Operation::Multipart)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(1)
        .mount(&server)
        .await;

    let transport = Transport::new(&profile(server.uri())).unwrap();
    assert_eq!(
        Operation::Multipart
            .send(&transport, "/api/lists")
            .await
            .unwrap(),
        json!({"ok": true})
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let content_type = requests[0].headers["content-type"].to_str().unwrap();
    let boundary = content_type
        .strip_prefix("multipart/form-data; boundary=")
        .unwrap();
    let expected = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"values.txt\"\r\nContent-Type: text/plain\r\n\r\nalpha\nβeta\n\r\n--{boundary}--\r\n"
    );
    assert_eq!(requests[0].body, expected.as_bytes());
}

#[tokio::test]
async fn delete_once_response_preserves_success_and_client_error_statuses_and_json() {
    for (status, body) in [
        (
            409,
            json!({"references": [{"list_id": "exceptions", "item_id": "item"}]}),
        ),
        (200, json!([{"id": "value-1"}, {"id": "value-2"}])),
        (404, json!({"statusCode": 404, "message": "not found"})),
        (401, json!({"message": "unauthorized"})),
        (403, json!({"message": "forbidden"})),
        (429, json!({"message": "rate limited"})),
    ] {
        let server = MockServer::start().await;
        mutation_mock(Operation::DeleteResponse)
            .and(query_param("id", "example"))
            .respond_with(ResponseTemplate::new(status).set_body_json(&body))
            .expect(1)
            .mount(&server)
            .await;

        let transport = Transport::new(&profile(server.uri())).unwrap();
        assert_eq!(
            transport
                .delete_once_response("/api/lists?id=example")
                .await
                .unwrap(),
            (status, body)
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].body.is_empty());
    }
}

#[tokio::test]
async fn patch_and_upload_responses_preserve_success_and_client_error_bodies() {
    for operation in [Operation::PatchResponse, Operation::MultipartResponse] {
        for (status, body) in [
            (200, json!({"id": "list", "_version": "WzEsMV0="})),
            (
                409,
                json!({"statusCode": 409, "message": "version conflict"}),
            ),
            (
                413,
                json!({"statusCode": 413, "message": "Payload content length greater than maximum allowed: 9000000"}),
            ),
            (
                415,
                json!({"statusCode": 415, "message": "File must be one of the following types: [.csv, .txt]"}),
            ),
            (429, json!({"message": "rate limited"})),
        ] {
            let server = MockServer::start().await;
            mutation_mock(operation)
                .respond_with(ResponseTemplate::new(status).set_body_json(&body))
                .expect(1)
                .mount(&server)
                .await;

            let transport = Transport::new(&profile(server.uri())).unwrap();
            let answer = match operation {
                Operation::PatchResponse => transport
                    .patch_once_response("/api/lists", &json!({"name": "updated"}))
                    .await
                    .unwrap(),
                _ => transport
                    .post_multipart_once_named_response(
                        "/api/lists",
                        "values.txt",
                        "text/plain",
                        "alpha\n",
                    )
                    .await
                    .unwrap(),
            };
            assert_eq!(answer, (status, body), "{operation:?} {status}");
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }
}

#[tokio::test]
async fn delete_once_response_decodes_empty_bodies_as_null() {
    for status in [204, 404] {
        let server = MockServer::start().await;
        mutation_mock(Operation::DeleteResponse)
            .respond_with(ResponseTemplate::new(status))
            .expect(1)
            .mount(&server)
            .await;

        let transport = Transport::new(&profile(server.uri())).unwrap();
        assert_eq!(
            transport.delete_once_response("/api/lists").await.unwrap(),
            (status, Value::Null)
        );
    }
}

#[tokio::test]
async fn send_once_calls_return_shared_503_errors_without_replaying() {
    for operation in OPERATIONS {
        let server = MockServer::start().await;
        mutation_mock(operation)
            .respond_with(
                ResponseTemplate::new(503).set_body_string(r#"{"message":"unavailable"}"#),
            )
            .expect(1)
            .mount(&server)
            .await;

        let transport = Transport::new(&profile(server.uri())).unwrap();
        let error = operation.send(&transport, "/api/lists").await.unwrap_err();
        let expected = Error::from_response_body(503, r#"{"message":"unavailable"}"#);
        assert_eq!(error.kind, expected.kind, "{operation:?}");
        assert_eq!(error.http_status, expected.http_status, "{operation:?}");
        assert_eq!(error.message, expected.message, "{operation:?}");
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "{operation:?}"
        );
    }
}

#[tokio::test]
async fn patch_and_upload_return_shared_429_errors_without_replaying() {
    for operation in [Operation::Patch, Operation::Multipart] {
        let server = MockServer::start().await;
        mutation_mock(operation)
            .respond_with(
                ResponseTemplate::new(429).set_body_string(r#"{"message":"rate limited"}"#),
            )
            .expect(1)
            .mount(&server)
            .await;

        let transport = Transport::new(&profile(server.uri())).unwrap();
        let error = operation.send(&transport, "/api/lists").await.unwrap_err();
        let expected = Error::from_response_body(429, r#"{"message":"rate limited"}"#);
        assert_eq!(error.kind, expected.kind, "{operation:?}");
        assert_eq!(error.http_status, expected.http_status, "{operation:?}");
        assert_eq!(error.message, expected.message, "{operation:?}");
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "{operation:?}"
        );
    }
}

#[tokio::test]
async fn send_once_calls_return_shared_timeout_errors_without_replaying() {
    for operation in OPERATIONS {
        let server = MockServer::start().await;
        mutation_mock(operation)
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"ok": true}))
                    .set_delay(Duration::from_millis(1_200)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let transport = Transport::new(&profile(server.uri())).unwrap();
        let error = operation.send(&transport, "/api/lists").await.unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout, "{operation:?}");
        assert_eq!(error.http_status, None, "{operation:?}");
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "{operation:?}"
        );
    }
}

struct ResetServer {
    url: String,
    requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl ResetServer {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(stream.read_u8().await.unwrap());
                }
                let head = String::from_utf8(head).unwrap();
                let length = head
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, length)| length.trim().parse::<usize>().unwrap())
                    .unwrap_or(0);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                stream.set_zero_linger().unwrap();
                drop(stream);
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }
}

impl Drop for ResetServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn send_once_calls_return_shared_connection_errors_without_replaying_a_reset() {
    for operation in OPERATIONS {
        let server = ResetServer::start().await;
        let transport = Transport::new(&profile(server.url.clone())).unwrap();
        let error = operation.send(&transport, "/api/lists").await.unwrap_err();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(error.kind, ErrorKind::Connection, "{operation:?}");
        assert_eq!(error.http_status, None, "{operation:?}");
        assert_eq!(server.requests.load(Ordering::SeqCst), 1, "{operation:?}");
    }
}

#[tokio::test]
async fn send_once_calls_reject_undecodable_bodies_without_replaying() {
    for (operation, status) in OPERATIONS
        .into_iter()
        .map(|operation| (operation, 200))
        .chain([
            (Operation::DeleteResponse, 409),
            (Operation::DeleteResponse, 404),
            (Operation::PatchResponse, 409),
            (Operation::MultipartResponse, 413),
        ])
    {
        let server = MockServer::start().await;
        mutation_mock(operation)
            .respond_with(ResponseTemplate::new(status).set_body_string("not JSON"))
            .expect(1)
            .mount(&server)
            .await;

        let transport = Transport::new(&profile(server.uri())).unwrap();
        let error = operation.send(&transport, "/api/lists").await.unwrap_err();
        assert_eq!(error.kind, ErrorKind::Http, "{operation:?} {status}");
        assert_eq!(error.http_status, None, "{operation:?} {status}");
        assert!(error.message.starts_with("parsing response JSON:"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn send_once_calls_never_follow_redirects() {
    for operation in OPERATIONS {
        for status in [307, 308] {
            let server = MockServer::start().await;
            mutation_mock(operation)
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("location", format!("{}/replacement", server.uri())),
                )
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(path("/replacement"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
                .expect(0)
                .mount(&server)
                .await;

            let transport = Transport::new(&profile(server.uri())).unwrap();
            let error = operation.send(&transport, "/api/lists").await.unwrap_err();
            assert_eq!(error.kind, ErrorKind::Http, "{operation:?} {status}");
            assert_eq!(error.http_status, Some(status), "{operation:?} {status}");
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }
}

#[tokio::test]
async fn send_once_calls_preserve_response_body_limits() {
    for (operation, status) in OPERATIONS
        .into_iter()
        .map(|operation| (operation, 200))
        .chain([(Operation::DeleteResponse, 409)])
    {
        let server = MockServer::start().await;
        mutation_mock(operation)
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({"large": "body"})))
            .expect(1)
            .mount(&server)
            .await;

        let transport = Transport::with_options(
            &profile(server.uri()),
            TransportOptions {
                response_body_limit: Some(4),
                ..Default::default()
            },
        )
        .unwrap();
        let error = operation.send(&transport, "/api/lists").await.unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unsupported, "{operation:?} {status}");
        assert_eq!(error.http_status, None);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
