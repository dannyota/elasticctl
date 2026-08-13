use elasticctl_core::{Capabilities, ErrorKind, Flavor, Profile, Transport};
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
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "kb",
            "version": {"number": number, "build_flavor": build_flavor},
            "status": {"overall": {"level": "available"}}
        })))
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
    // The literal a real 9.5.1 stack sends, recorded in
    // tests/fixtures/traditional-9.5.1/status.json. "default" was a
    // stand-in that no stack has ever reported.
    let server = server_reporting("traditional", "9.5.1").await;
    let p = profile_for(&server.uri()); // wiremock binds 127.0.0.1
    let t = Transport::new(&p).unwrap();
    let caps = Capabilities::probe(&t, &p.kibana_url).await.unwrap();
    assert_eq!(caps.flavor, Flavor::SelfManaged);
    assert_eq!(caps.version, "9.5.1");
}

#[tokio::test]
async fn a_default_build_flavor_on_an_elastic_cloud_host_is_ech() {
    let server = server_reporting("default", "9.5.1").await;
    let t = Transport::new(&profile_for(&server.uri())).unwrap();
    // The transport still talks to wiremock; only classification reads the URL.
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
        spaces: true,
        license_tier: None,
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
        spaces: true,
        license_tier: Some("platinum".into()),
    };
    assert!(caps.require("anything", true).is_ok());
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
