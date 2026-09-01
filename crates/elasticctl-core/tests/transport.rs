use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::json;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::fd::FromRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct WithoutHeader(&'static str);

impl wiremock::Match for WithoutHeader {
    fn matches(&self, request: &wiremock::Request) -> bool {
        !request.headers.contains_key(self.0)
    }
}

#[cfg(unix)]
const STDERR_FILENO: i32 = 2;
#[cfg(unix)]
static STDERR_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(unix)]
unsafe extern "C" {
    fn close(fd: i32) -> i32;
    fn dup(fd: i32) -> i32;
    fn dup2(oldfd: i32, newfd: i32) -> i32;
    fn pipe(fds: *mut i32) -> i32;
}

#[cfg(unix)]
struct StderrCapture {
    original_fd: i32,
    read_fd: i32,
}

#[cfg(unix)]
impl StderrCapture {
    fn start() -> Self {
        let mut fds = [0; 2];
        // The test redirects only the process stderr and restores it before
        // asserting. A shared lock prevents another test from writing there.
        unsafe {
            assert_eq!(pipe(fds.as_mut_ptr()), 0);
            let original_fd = dup(STDERR_FILENO);
            assert!(original_fd >= 0);
            assert_eq!(dup2(fds[1], STDERR_FILENO), STDERR_FILENO);
            assert_eq!(close(fds[1]), 0);
            Self {
                original_fd,
                read_fd: fds[0],
            }
        }
    }

    fn finish(mut self) -> String {
        unsafe {
            assert_eq!(dup2(self.original_fd, STDERR_FILENO), STDERR_FILENO);
            assert_eq!(close(self.original_fd), 0);
        }
        self.original_fd = -1;

        let mut output = String::new();
        let mut reader = unsafe { File::from_raw_fd(self.read_fd) };
        self.read_fd = -1;
        reader.read_to_string(&mut output).unwrap();
        output
    }
}

#[cfg(unix)]
impl Drop for StderrCapture {
    fn drop(&mut self) {
        unsafe {
            if self.original_fd >= 0 {
                let _ = dup2(self.original_fd, STDERR_FILENO);
                let _ = close(self.original_fd);
            }
            if self.read_fd >= 0 {
                let _ = close(self.read_fd);
            }
        }
    }
}

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

fn absolute_es_profile_for(server: &MockServer) -> Profile {
    let mut profile = profile_for(server);
    profile.kibana_url = "https://kibana.invalid".into();
    profile.es_url = Some(server.uri());
    profile.space = "security".into();
    profile
}

fn one_second_timeout_profile_for(server: &MockServer) -> Profile {
    let mut profile = profile_for(server);
    profile.timeout_secs = 1;
    profile
}

async fn headers_then_delayed_body_server()
-> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let request_count = Arc::clone(&requests);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        request_count.fetch_add(1, Ordering::SeqCst);

        let mut request = [0; 1_024];
        tokio::io::AsyncReadExt::read(&mut stream, &mut request)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        tokio::io::AsyncWriteExt::flush(&mut stream).await.unwrap();

        tokio::time::sleep(Duration::from_millis(1_200)).await;
        let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, b"{\"ok\":true}").await;

        if let Ok(Ok((_stream, _))) =
            tokio::time::timeout(Duration::from_millis(250), listener.accept()).await
        {
            request_count.fetch_add(1, Ordering::SeqCst);
        }
    });

    (url, requests, server)
}

#[test]
fn space_path_prefixes_only_non_default_spaces() {
    // Kibana serves the default space at the bare path.
    assert_eq!(Transport::space_path("default", "/api/x"), "/api/x");
    assert_eq!(Transport::space_path("soc", "/api/x"), "/s/soc/api/x");
}

#[tokio::test]
async fn get_sends_the_authorization_and_version_headers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/thing"))
        .and(header("authorization", "ApiKey essu_test"))
        .and(header("elastic-api-version", "2023-10-31"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    assert_eq!(t.get("/api/thing").await.unwrap()["ok"], true);
}

#[tokio::test]
async fn get_internal_sends_the_internal_origin_header_and_no_api_version() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/internal/detection_engine/users/_find"))
        .and(header("x-elastic-internal-origin", "Kibana"))
        .and(WithoutHeader("elastic-api-version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"uid": "u_1"}])))
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    let body = t
        .get_internal("/internal/detection_engine/users/_find?searchTerm=")
        .await
        .expect("internal GET");
    assert_eq!(body[0]["uid"], json!("u_1"));
}

#[tokio::test]
async fn post_internal_sends_the_internal_origin_and_xsrf_headers_and_no_api_version() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/internal/security/login"))
        .and(header("x-elastic-internal-origin", "Kibana"))
        .and(header("kbn-xsrf", "true"))
        .and(WithoutHeader("elastic-api-version"))
        .and(body_partial_json(json!({"providerType": "basic"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    let body = t
        .post_internal(
            "/internal/security/login",
            &json!({"providerType": "basic"}),
        )
        .await
        .expect("internal POST");
    assert_eq!(body["ok"], true);
}

#[tokio::test]
async fn out_of_range_json_integer_is_a_transport_http_parse_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/overflow"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("{\"total\":18446744073709551616}"),
        )
        .mount(&server)
        .await;

    let err = Transport::new(&profile_for(&server))
        .unwrap()
        .get("/api/overflow")
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Http, "{err}");
    assert!(err.message.contains("parsing response JSON"), "{err}");
}

#[tokio::test]
async fn signed_json_integers_remain_valid_transport_responses() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/signed-integers"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{\"offset\":-1,\"zero\":-0}"))
        .mount(&server)
        .await;

    let body = Transport::new(&profile_for(&server))
        .unwrap()
        .get("/api/signed-integers")
        .await
        .unwrap();
    assert_eq!(body["offset"].as_i64(), Some(-1));
    assert_eq!(body["zero"].as_f64(), Some(-0.0));
}

#[tokio::test]
async fn integer_below_i64_min_is_a_transport_http_parse_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/underflow"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("{\"offset\":-9223372036854775809}"),
        )
        .mount(&server)
        .await;

    let err = Transport::new(&profile_for(&server))
        .unwrap()
        .get("/api/underflow")
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Http, "{err}");
    assert!(err.message.contains("parsing response JSON"), "{err}");
}

#[tokio::test]
async fn a_large_json_float_remains_a_valid_transport_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/large-float"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{\"ratio\":1e100}"))
        .mount(&server)
        .await;

    let body = Transport::new(&profile_for(&server))
        .unwrap()
        .get("/api/large-float")
        .await
        .unwrap();
    assert!(body["ratio"].is_f64());
}

#[tokio::test]
async fn non_get_requests_carry_the_xsrf_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/thing"))
        .and(header("kbn-xsrf", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"created": true})))
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    assert_eq!(
        t.post("/api/thing", Some(&json!({}))).await.unwrap()["created"],
        true
    );
}

#[tokio::test]
async fn a_404_becomes_a_not_found_error_carrying_the_server_message() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(
            json!({"statusCode": 404, "error": "Not Found", "message": "rule not found"}),
        ))
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    let err = t.get("/api/missing").await.unwrap_err();
    assert_eq!(err.kind, elasticctl_core::ErrorKind::NotFound);
    assert_eq!(err.message, "rule not found");
}

#[tokio::test]
async fn the_cloud_edge_proxy_envelope_is_classified_too() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/gone"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"ok": false, "message": "Unknown resource."})),
        )
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    let err = t.get("/api/gone").await.unwrap_err();
    assert_eq!(err.kind, elasticctl_core::ErrorKind::NotFound);
    assert_eq!(err.message, "Unknown resource.");
}

#[tokio::test]
async fn a_429_is_retried_and_then_succeeds() {
    let server = MockServer::start().await;
    // wiremock serves mounted mocks in order with `up_to_n_times`.
    Mock::given(method("GET"))
        .and(path("/api/flaky"))
        .respond_with(ResponseTemplate::new(429))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/flaky"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    assert_eq!(t.get("/api/flaky").await.unwrap()["ok"], true);
}

#[tokio::test]
async fn a_400_is_never_retried() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/bad"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"message": "bad input"})))
        .expect(1) // exactly one call proves no retry happened
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    assert!(t.get("/api/bad").await.is_err());
    // MockServer verifies `expect(1)` on drop.
}

#[test]
fn urlencode_escapes_what_breaks_a_url_and_leaves_the_rest() {
    // Escape only query-breaking characters to keep recorded fixtures readable.
    assert_eq!(elasticctl_core::urlencode("a-b_c.d~e"), "a-b_c.d~e");
    assert_eq!(elasticctl_core::urlencode("a b"), "a%20b");
    assert_eq!(elasticctl_core::urlencode("x\"y"), "x%22y");
    assert_eq!(
        elasticctl_core::urlencode("alert.attributes.params.ruleId: \"a/b\""),
        "alert.attributes.params.ruleId%3A%20%22a%2Fb%22"
    );
}

#[cfg_attr(not(unix), ignore = "stderr capture uses Unix file descriptors")]
#[tokio::test]
async fn debug_output_never_shows_url_userinfo() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/scrub"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;

    // Insert dummy userinfo after the scheme, before the host.
    let uri = server.uri();
    let with_userinfo = uri.replacen("://", "://dummyuser:dummypass@", 1);
    let t = Transport::with_debug(&profile_for_url(with_userinfo), true).unwrap();
    #[cfg(unix)]
    let _stderr_guard = STDERR_LOCK.lock().await;
    #[cfg(unix)]
    let capture = StderrCapture::start();

    let body = t.get("/api/scrub").await.unwrap();
    assert_eq!(body["ok"], true);

    #[cfg(unix)]
    let debug = capture.finish();
    #[cfg(unix)]
    {
        assert!(!debug.contains("dummyuser"), "debug output: {debug}");
        assert!(!debug.contains("dummypass"), "debug output: {debug}");
    }
}

#[tokio::test]
async fn post_absolute_es_sends_the_body_to_the_es_host() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/index/_search"))
        .and(header("authorization", "ApiKey essu_test"))
        .and(body_partial_json(json!({"size": 1})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"hits": {"total": {"value": 3}}})),
        )
        .mount(&server)
        .await;

    let mut profile = profile_for(&server);
    // Cloud deployments use a different Elasticsearch host from Kibana.
    profile.es_url = Some(server.uri());
    profile.kibana_url = "https://kibana.invalid".into();
    let t = Transport::new(&profile).unwrap();

    let body = t
        .post_absolute_es("/index/_search", &json!({"size": 1}))
        .await
        .unwrap();
    assert_eq!(body["hits"]["total"]["value"], 3);
}

#[tokio::test]
async fn post_absolute_es_classifies_an_error_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/index/_search"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "no access"})))
        .mount(&server)
        .await;
    let mut profile = profile_for(&server);
    profile.es_url = Some(server.uri());
    let t = Transport::new(&profile).unwrap();

    let err = t
        .post_absolute_es("/index/_search", &json!({}))
        .await
        .unwrap_err();
    assert_eq!(err.kind, elasticctl_core::ErrorKind::Permission);
    assert_eq!(err.message, "no access");
}

#[tokio::test]
async fn absolute_es_retries_a_429_once_without_kibana_headers_or_space_prefix() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/index/_search"))
        .respond_with(ResponseTemplate::new(429))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/index/_search"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"hits": {"total": {"value": 2}}})),
        )
        .mount(&server)
        .await;

    let t = Transport::new(&absolute_es_profile_for(&server)).unwrap();
    let body = t
        .post_absolute_es("/index/_search", &json!({"size": 2}))
        .await
        .unwrap();

    assert_eq!(body["hits"]["total"]["value"], 2);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert_eq!(request.url.path(), "/index/_search");
        assert_eq!(
            request.headers.get("authorization").unwrap(),
            "ApiKey essu_test"
        );
        assert!(request.headers.get("elastic-api-version").is_none());
        assert!(request.headers.get("kbn-xsrf").is_none());
        assert_eq!(
            request.body_json::<serde_json::Value>().unwrap(),
            json!({"size": 2})
        );
    }
}

#[cfg_attr(not(unix), ignore = "stderr capture uses Unix file descriptors")]
#[tokio::test]
async fn an_absolute_es_timeout_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_cluster/health"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(1_100))
                .set_body_json(json!({"status": "green"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut profile = one_second_timeout_profile_for(&server);
    profile.es_url = Some(server.uri());
    let t = Transport::with_debug(&profile, true).unwrap();
    #[cfg(unix)]
    let _stderr_guard = STDERR_LOCK.lock().await;
    #[cfg(unix)]
    let capture = StderrCapture::start();
    let err = t.get_absolute_es("/_cluster/health").await.unwrap_err();
    #[cfg(unix)]
    let debug = capture.finish();

    assert_eq!(err.kind, elasticctl_core::ErrorKind::Timeout);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    #[cfg(unix)]
    assert!(
        debug.trim_end().ends_with("timeout"),
        "debug output: {debug}"
    );
}

#[tokio::test]
async fn a_delayed_response_body_is_a_timeout_without_a_retry() {
    let (url, requests, server) = headers_then_delayed_body_server().await;
    let mut profile = profile_for_url(url);
    profile.timeout_secs = 1;
    let t = Transport::with_debug(&profile, true).unwrap();
    #[cfg(unix)]
    let _stderr_guard = STDERR_LOCK.lock().await;
    #[cfg(unix)]
    let capture = StderrCapture::start();

    let err = t.get("/api/delayed-body").await.unwrap_err();

    #[cfg(unix)]
    let debug = capture.finish();
    server.await.unwrap();

    assert_eq!(err.kind, elasticctl_core::ErrorKind::Timeout);
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    #[cfg(unix)]
    assert!(
        debug.trim_end().ends_with("timeout"),
        "debug output: {debug}"
    );
}

#[tokio::test]
async fn a_400_from_absolute_es_is_never_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/index/_search"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"message": "bad input"})))
        .expect(1)
        .mount(&server)
        .await;

    let t = Transport::new(&absolute_es_profile_for(&server)).unwrap();
    assert!(
        t.post_absolute_es("/index/_search", &json!({"size": 0}))
            .await
            .is_err()
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn delete_absolute_es_targets_the_es_host() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/scratch-index"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .mount(&server)
        .await;
    let mut profile = profile_for(&server);
    profile.es_url = Some(server.uri());
    let t = Transport::new(&profile).unwrap();

    assert_eq!(
        t.delete_absolute_es("/scratch-index").await.unwrap()["acknowledged"],
        true
    );
}

#[tokio::test]
async fn post_text_returns_the_raw_body_for_ndjson_export() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/export"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("{\"rule_id\":\"a\"}\n{\"exported_count\":1}\n"),
        )
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    let body = t.post_text("/api/export", None).await.unwrap();
    assert_eq!(body.lines().count(), 2);
}

#[tokio::test]
async fn multipart_retries_a_503_with_the_same_file_and_kibana_headers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
        .mount(&server)
        .await;

    let ndjson = "{\"rule_id\":\"retry-rule\"}\n";
    let t = Transport::new(&profile_for(&server)).unwrap();
    assert_eq!(
        t.post_multipart_ndjson("/api/detection_engine/rules/_import", ndjson)
            .await
            .unwrap()["success"],
        true
    );

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests {
        let body = String::from_utf8(request.body).unwrap();
        assert!(body.contains("filename=\"rules.ndjson\""));
        assert!(body.contains(ndjson));
        assert_eq!(
            request.headers.get("authorization").unwrap(),
            "ApiKey essu_test"
        );
        assert_eq!(
            request.headers.get("elastic-api-version").unwrap(),
            "2023-10-31"
        );
        assert_eq!(request.headers.get("kbn-xsrf").unwrap(), "true");
    }
}

#[tokio::test]
async fn a_multipart_timeout_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(1_100))
                .set_body_json(json!({"success": true})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let t = Transport::new(&one_second_timeout_profile_for(&server)).unwrap();
    let err = t
        .post_multipart_ndjson(
            "/api/detection_engine/rules/_import",
            "{\"rule_id\":\"timeout-rule\"}\n",
        )
        .await
        .unwrap_err();

    assert_eq!(err.kind, elasticctl_core::ErrorKind::Timeout);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_400_from_multipart_is_never_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"message": "bad input"})))
        .expect(1)
        .mount(&server)
        .await;

    let t = Transport::new(&profile_for(&server)).unwrap();
    assert!(
        t.post_multipart_ndjson(
            "/api/detection_engine/rules/_import",
            "{\"rule_id\":\"bad-rule\"}\n",
        )
        .await
        .is_err()
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
