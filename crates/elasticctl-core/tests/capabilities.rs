use elasticctl_core::{Capabilities, ErrorKind, Feature, Flavor, Profile, Transport};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn profile_for(uri: &str) -> Profile {
    Profile {
        kibana_url: uri.to_string(),
        es_url: None,
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    }
}

async fn server_reporting(build_flavor: &str, number: &str) -> MockServer {
    server_reporting_with_headers(build_flavor, number, &[]).await
}

/// Start a status server with response headers for offline Cloud edge tests.
async fn server_reporting_with_headers(
    build_flavor: &str,
    number: &str,
    headers: &[(&str, &str)],
) -> MockServer {
    let server = MockServer::start().await;
    let mut response = ResponseTemplate::new(200).set_body_json(json!({
        "name": "kb",
        "version": {"number": number, "build_flavor": build_flavor},
        "status": {"overall": {"level": "available"}}
    }));
    for (name, value) in headers {
        response = response.insert_header(*name, *value);
    }
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(response)
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn serverless_is_detected_from_build_flavor() {
    let server = server_reporting("serverless", "9.6.0").await;
    let p = profile_for(&server.uri());
    let t = Transport::new(&p).unwrap();
    let caps = Capabilities::probe(&t, &p.kibana_url).await.unwrap();
    assert_eq!(caps.flavor, Flavor::Serverless);
    assert_eq!(caps.version, "9.6.0");
}

#[tokio::test]
async fn a_traditional_build_flavor_on_a_private_host_is_self_managed() {
    // A real 9.5.1 stack reports this value; see
    // tests/fixtures/traditional-9.5.1/status.json. No stack reports
    // "default" here.
    let server = server_reporting("traditional", "9.5.1").await;
    let p = profile_for(&server.uri()); // wiremock binds to 127.0.0.1.
    let t = Transport::new(&p).unwrap();
    let caps = Capabilities::probe(&t, &p.kibana_url).await.unwrap();
    assert_eq!(caps.flavor, Flavor::SelfManaged);
    assert_eq!(caps.version, "9.5.1");
}

#[tokio::test]
async fn a_default_build_flavor_on_an_elastic_cloud_host_is_ech() {
    let server = server_reporting("default", "9.5.1").await;
    let t = Transport::new(&profile_for(&server.uri())).unwrap();
    // Transport calls wiremock; classification alone reads this URL.
    let caps = Capabilities::probe(&t, "https://abc.kb.us-east-1.aws.found.io")
        .await
        .unwrap();
    assert_eq!(caps.flavor, Flavor::ElasticCloudHosted);
}

#[tokio::test]
async fn a_missing_build_flavor_falls_back_to_self_managed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "8.15.0"}
        })))
        .mount(&server)
        .await;
    let p = profile_for(&server.uri());
    let t = Transport::new(&p).unwrap();
    let caps = Capabilities::probe(&t, &p.kibana_url).await.unwrap();
    assert_eq!(caps.flavor, Flavor::SelfManaged);
}

/// Hosted and self-managed stacks can report the same `build_flavor`. With no
/// Cloud suffix, the edge header must distinguish them; see
/// `tests/fixtures/ech-9.5.1/status.json`.
#[tokio::test]
async fn the_cloud_edge_header_makes_a_traditional_stack_ech() {
    let server = server_reporting_with_headers(
        "traditional",
        "9.5.1",
        &[("x-found-handling-cluster", "REDACTED")],
    )
    .await;
    let p = profile_for(&server.uri()); // wiremock uses 127.0.0.1, without a Cloud suffix.
    let t = Transport::new(&p).unwrap();
    let caps = Capabilities::probe(&t, &p.kibana_url).await.unwrap();
    assert_eq!(caps.flavor, Flavor::ElasticCloudHosted);
    assert_eq!(caps.version, "9.5.1");
}

/// Serverless sends the same edge header as Hosted. It must be checked after
/// `build_flavor`, or Serverless projects would be classified as Hosted.
#[tokio::test]
async fn serverless_wins_over_the_edge_header() {
    let server = server_reporting_with_headers(
        "serverless",
        "9.6.0",
        &[("x-found-handling-cluster", "REDACTED")],
    )
    .await;
    let p = profile_for(&server.uri());
    let t = Transport::new(&p).unwrap();
    let caps = Capabilities::probe(&t, &p.kibana_url).await.unwrap();
    assert_eq!(caps.flavor, Flavor::Serverless);
}

/// HTTP header names are case-insensitive. The proxy uses different casing on
/// Kibana and Elasticsearch endpoints.
#[tokio::test]
async fn the_edge_header_is_matched_regardless_of_casing() {
    let server = server_reporting_with_headers(
        "traditional",
        "9.5.1",
        &[("X-Found-Handling-Cluster", "REDACTED")],
    )
    .await;
    let p = profile_for(&server.uri());
    let t = Transport::new(&p).unwrap();
    let caps = Capabilities::probe(&t, &p.kibana_url).await.unwrap();
    assert_eq!(caps.flavor, Flavor::ElasticCloudHosted);
}

/// Classify recorded responses rather than mocks built from the same
/// assumptions.
///
/// Each fixture directory names the expected flavor, and `status.json` is the
/// input. A re-recorded response shape fails here first.
///
/// Every set records headers. Requiring the `headers` key proves that an
/// absent `x-found-handling-cluster` is absent, not unrecorded. In
/// `traditional-9.5.1`, the header is absent while other stack headers remain
/// present.
#[test]
fn every_recorded_status_classifies_as_the_flavor_it_came_from() {
    use elasticctl_core::Capabilities;
    use std::path::Path;

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut checked = 0;

    for entry in std::fs::read_dir(&root).expect("fixtures root") {
        let dir = entry.expect("entry").path();
        let status = dir.join("status.json");
        if !status.is_file() {
            continue;
        }

        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        let expected = match name.split('-').next().unwrap() {
            "serverless" => Flavor::Serverless,
            "traditional" => Flavor::SelfManaged,
            "ech" => Flavor::ElasticCloudHosted,
            other => panic!("fixture set {other} has no expected flavor"),
        };

        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&status).expect("read status"))
                .expect("status fixture is JSON");
        let headers = doc
            .get("headers")
            .unwrap_or_else(|| panic!("fixture set {name} records no headers; re-record it"));
        let cloud_edge = headers.get("x-found-handling-cluster").is_some();

        // No Cloud suffix: only the body and header determine the flavor.
        let caps = Capabilities::classify(&doc["response"], cloud_edge, "https://kibana.internal");
        assert_eq!(caps.flavor, expected, "fixture set {name}");
        checked += 1;
    }

    assert!(
        checked >= 3,
        "expected all three flavors, checked {checked}"
    );
}

#[tokio::test]
async fn a_failed_probe_surfaces_the_classified_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "unauthorized"})))
        .mount(&server)
        .await;
    let p = profile_for(&server.uri());
    let t = Transport::new(&p).unwrap();
    let err = Capabilities::probe(&t, &p.kibana_url).await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Auth);
}

#[test]
fn require_names_the_flavor_in_the_unsupported_error() {
    let caps = Capabilities {
        flavor: Flavor::Serverless,
        version: "9.6.0".into(),
    };
    let err = caps.require("machine learning rules", false).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Unsupported);
    assert!(
        err.message.contains("serverless"),
        "message must name the flavor: {}",
        err.message
    );
    assert!(err.message.contains("machine learning rules"));
}

#[test]
fn require_passes_when_the_feature_is_supported() {
    let caps = Capabilities {
        flavor: Flavor::SelfManaged,
        version: "9.5.1".into(),
    };
    assert!(caps.require("anything", true).is_ok());
}

#[test]
fn verified_features_reject_a_stack_below_9_5_1() {
    let caps = Capabilities {
        flavor: Flavor::SelfManaged,
        version: "9.5.0".into(),
    };

    let error = caps.require_feature(Feature::ExceptionLists).unwrap_err();

    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert!(
        error.message.contains("exception lists"),
        "{}",
        error.message
    );
    assert!(
        error.message.contains("self-managed 9.5.0"),
        "{}",
        error.message
    );
    assert!(error.message.contains("9.5.1"), "{}", error.message);
}

#[test]
fn verified_features_accept_9_5_1_and_newer() {
    for version in ["9.5.1", "9.6.0", "10.0.0"] {
        let caps = Capabilities {
            flavor: Flavor::Serverless,
            version: version.into(),
        };
        for feature in [
            Feature::ExceptionLists,
            Feature::PrebuiltRules,
            Feature::RuleSourceScoping,
        ] {
            caps.require_feature(feature).unwrap();
        }
    }
}

#[test]
fn an_unreadable_feature_version_is_unsupported() {
    let caps = Capabilities {
        flavor: Flavor::ElasticCloudHosted,
        version: "unknown".into(),
    };

    let error = caps.require_feature(Feature::PrebuiltRules).unwrap_err();

    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert!(
        error.message.contains("elastic-cloud-hosted unknown"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn transport_caches_one_status_probe() {
    let server = server_reporting("traditional", "9.5.1").await;
    let transport = Transport::new(&profile_for(&server.uri())).unwrap();

    transport.capabilities().await.unwrap();
    transport.capabilities().await.unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/api/status")
            .count(),
        1
    );
}

#[tokio::test]
async fn ech_suffix_in_subdomain_is_detected() {
    let server = server_reporting("default", "9.5.1").await;
    let t = Transport::new(&profile_for(&server.uri())).unwrap();
    let caps = Capabilities::probe(&t, "https://abc.kb.us-east-1.aws.found.io")
        .await
        .unwrap();
    assert_eq!(caps.flavor, Flavor::ElasticCloudHosted);
}

#[tokio::test]
async fn ech_suffix_with_port_is_detected() {
    let server = server_reporting("default", "9.5.1").await;
    let t = Transport::new(&profile_for(&server.uri())).unwrap();
    let caps = Capabilities::probe(&t, "https://abc.kb.us-east-1.aws.found.io:9243")
        .await
        .unwrap();
    assert_eq!(caps.flavor, Flavor::ElasticCloudHosted);
}

#[tokio::test]
async fn ech_suffix_as_bare_host_is_detected() {
    let server = server_reporting("default", "9.5.1").await;
    let t = Transport::new(&profile_for(&server.uri())).unwrap();
    let caps = Capabilities::probe(&t, "https://found.io").await.unwrap();
    assert_eq!(caps.flavor, Flavor::ElasticCloudHosted);
}

#[tokio::test]
async fn ech_suffix_in_path_is_not_misclassified() {
    let server = server_reporting("default", "9.5.1").await;
    let t = Transport::new(&profile_for(&server.uri())).unwrap();
    let caps = Capabilities::probe(&t, "https://kibana.example.com/login?ref=found.io")
        .await
        .unwrap();
    assert_eq!(caps.flavor, Flavor::SelfManaged);
}

#[tokio::test]
async fn ech_suffix_in_internal_host_is_not_misclassified() {
    let server = server_reporting("default", "9.5.1").await;
    let t = Transport::new(&profile_for(&server.uri())).unwrap();
    let caps = Capabilities::probe(&t, "https://kibana.found.io.internal.corp")
        .await
        .unwrap();
    assert_eq!(caps.flavor, Flavor::SelfManaged);
}

#[tokio::test]
async fn lookalike_domain_is_not_misclassified() {
    let server = server_reporting("default", "9.5.1").await;
    let t = Transport::new(&profile_for(&server.uri())).unwrap();
    let caps = Capabilities::probe(&t, "https://notfound.io")
        .await
        .unwrap();
    assert_eq!(caps.flavor, Flavor::SelfManaged);
}

#[tokio::test]
async fn probe_spaces_returns_the_ids() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/spaces/space"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "default", "name": "Default"},
            {"id": "soc", "name": "SOC"}
        ])))
        .mount(&server)
        .await;
    let t = Transport::new(&profile_for(&server.uri())).unwrap();

    assert_eq!(
        elasticctl_core::capabilities::probe_spaces(&t).await,
        Some(vec!["default".to_string(), "soc".to_string()])
    );
}

/// An unavailable probe returns no list. `info` prints null rather than a
/// configured space, which is not a probe result.
#[tokio::test]
async fn probe_spaces_returns_none_when_the_probe_fails() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/spaces/space"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "nope"})))
        .mount(&server)
        .await;
    let t = Transport::new(&profile_for(&server.uri())).unwrap();

    assert_eq!(elasticctl_core::capabilities::probe_spaces(&t).await, None);
}

#[tokio::test]
async fn probe_license_tier_reads_the_license_type() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_license"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "license": {"status": "active", "type": "trial"}
        })))
        .mount(&server)
        .await;
    let t = Transport::new(&profile_for(&server.uri())).unwrap();

    assert_eq!(
        elasticctl_core::capabilities::probe_license_tier(&t, Flavor::SelfManaged).await,
        Some("trial".to_string())
    );
}

/// Serverless uses project tiers, so it does not call the license endpoint.
#[tokio::test]
async fn probe_license_tier_does_not_call_the_endpoint_on_serverless() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_license"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"license": {"type": "trial"}})),
        )
        .expect(0)
        .mount(&server)
        .await;
    let t = Transport::new(&profile_for(&server.uri())).unwrap();

    assert_eq!(
        elasticctl_core::capabilities::probe_license_tier(&t, Flavor::Serverless).await,
        None
    );
}
