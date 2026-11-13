use super::*;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const FLAVORS: [&str; 3] = ["serverless-9.7.0", "ech-9.5.6", "traditional-9.5.1"];

fn fixture(flavor: &str, name: &str) -> Value {
    let file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(flavor)
        .join("value_lists")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(file).unwrap().replace(
        "elasticctl-fixture-value-list-id-",
        "elasticctl-live-vl-fixture-",
    );
    serde_json::from_str(&text).unwrap()
}

fn transport(server: &MockServer) -> Transport {
    Transport::with_options(
        &Profile {
            kibana_url: server.uri(),
            es_url: Some(server.uri()),
            api_key: Some("synthetic".into()),
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 1,
        },
        elasticctl_core::TransportOptions {
            disable_retries: true,
            disable_redirects: true,
            ..Default::default()
        },
    )
    .unwrap()
}

async fn mount(
    server: &MockServer,
    verb: &str,
    endpoint: &str,
    query: Option<(&str, &str)>,
    body: &Value,
    status: u16,
    count: u64,
) {
    let mut mock = Mock::given(method(verb)).and(path(endpoint));
    if let Some((key, value)) = query {
        mock = mock.and(query_param(key, value));
    }
    mock.respond_with(ResponseTemplate::new(status).set_body_json(body))
        .up_to_n_times(count)
        .expect(count)
        .mount(server)
        .await;
}

fn lease() -> Lease {
    let mut lease = Lease::new("REDACTED".into());
    lease.budget = Duration::from_millis(50);
    lease.interval = Duration::from_millis(1);
    lease
}

#[test]
fn four_failure_paths_emit_the_controller_class_lines() {
    for (failure, expected) in [
        (Failure::Contract, "elasticctl-conformance-class:contract"),
        (Failure::Cleanup, "elasticctl-conformance-class:cleanup"),
        (
            Failure::InitialBaseline,
            "elasticctl-conformance-class:harness",
        ),
        (
            Failure::FinalBaseline,
            "elasticctl-conformance-class:cleanup",
        ),
    ] {
        assert_eq!(conformance_marker(failure.class()), expected);
    }
    assert_eq!(
        classify(Ok(()), Err(StepError::NotWired(3)), Err(()), Err(())),
        Err(Failure::Cleanup)
    );
    assert_eq!(
        classify(Ok(()), Err(StepError::NotWired(3)), Ok(()), Err(())),
        Err(Failure::FinalBaseline)
    );
    assert_eq!(
        classify(Ok(()), Err(StepError::NotWired(3)), Ok(()), Ok(())),
        Err(Failure::Contract)
    );
}

#[test]
fn state_preview_and_refusal_steps_are_explicitly_not_wired() {
    for (number, step) in [
        (3, state_pull as fn() -> StepResult),
        (4, state_push),
        (5, preview),
        (6, refusals),
    ] {
        assert_eq!(step(), Err(StepError::NotWired(number)));
    }
}

async fn registered_objects(
    server: &MockServer,
    flavor: &str,
    lease: &mut Lease,
    through: usize,
) -> Vec<String> {
    let mut order = Vec::new();
    for (kind, name, absent) in [
        (Kind::List, "contain_create", "container_missing_c"),
        (Kind::List, "state_container_v", "container_missing_v"),
        (
            Kind::Exception,
            "exception_create",
            "cleanup_exception_absent",
        ),
        (
            Kind::Item,
            "exception_item_create",
            "cleanup_exception_item_absent",
        ),
        (Kind::Rule, "state_rule_r", "cleanup_rule_absent"),
    ]
    .into_iter()
    .take(through)
    {
        let recorded = fixture(flavor, name);
        let object = Object::new(
            kind,
            recorded["response"][kind.key()].as_str().unwrap().into(),
        );
        let endpoint = kind.endpoint();
        let query = Some((kind.key(), object.id.as_str()));
        mount(
            server,
            "GET",
            endpoint,
            query,
            &recorded["response"],
            200,
            1,
        )
        .await;
        mount(
            server,
            "DELETE",
            endpoint,
            query,
            &recorded["response"],
            200,
            1,
        )
        .await;
        mount(
            server,
            "GET",
            endpoint,
            query,
            &fixture(flavor, absent)["response"],
            404,
            1,
        )
        .await;
        order.push(object.path());
        lease.objects.push(object);
    }
    if through >= 4 {
        let body = fixture(flavor, "state_items_excluded")["response"]["data"][0].clone();
        let object = Object::new(Kind::Item, body["item_id"].as_str().unwrap().into());
        let query = Some(("item_id", object.id.as_str()));
        mount(server, "GET", Kind::Item.endpoint(), query, &body, 200, 1).await;
        mount(
            server,
            "DELETE",
            Kind::Item.endpoint(),
            query,
            &body,
            200,
            1,
        )
        .await;
        mount(
            server,
            "GET",
            Kind::Item.endpoint(),
            query,
            &fixture(flavor, "cleanup_exception_item_absent")["response"],
            404,
            1,
        )
        .await;
        order.push(object.path());
        lease.objects.push(object);
    }
    order.sort_by_key(|p| {
        if p.starts_with("/api/detection_engine") {
            0
        } else if p.starts_with("/api/exception_lists/items?") {
            1
        } else if p.starts_with("/api/exception_lists?") {
            2
        } else {
            3
        }
    });
    order
}

async fn audit(server: &MockServer, flavor: &str) {
    mount(
        server,
        "GET",
        "/.items-default/_search",
        Some(("q", "list_id:elasticctl-live-vl-*")),
        &fixture(flavor, "cleanup_items_audit")["response"],
        200,
        1,
    )
    .await;
}

#[tokio::test]
async fn cleanup_from_object_failures_and_steps_three_through_seven_uses_exact_ids_and_confirms_404()
 {
    for flavor in FLAVORS {
        for step in 0..=8 {
            let server = MockServer::start().await;
            let mut lease = lease();
            let expected = registered_objects(&server, flavor, &mut lease, step.min(5)).await;
            audit(&server, flavor).await;
            cleanup::finish(&transport(&server), &mut lease)
                .await
                .unwrap();
            let requests = server.received_requests().await.unwrap();
            let deletes: Vec<_> = requests
                .iter()
                .filter(|r| r.method == "DELETE")
                .map(|r| format!("{}?{}", r.url.path(), r.url.query().unwrap()))
                .collect();
            assert_eq!(deletes, expected);
            for request in requests.iter().filter(|r| r.method == "DELETE") {
                let pairs: Vec<_> = request.url.query_pairs().collect();
                assert!(pairs.iter().any(|(_, id)| id.starts_with(PREFIX)));
                assert!(pairs.iter().all(|(key, _)| {
                    ["id", "rule_id", "item_id", "list_id", "namespace_type"]
                        .contains(&key.as_ref())
                }));
            }
            assert!(lease.objects.is_empty());
        }
    }
}

#[tokio::test]
async fn streams_are_restored_only_when_bootstrapped_here_and_no_list_remains() {
    for flavor in FLAVORS {
        for (bootstrapped, remaining) in [(false, false), (true, true), (true, false)] {
            let server = MockServer::start().await;
            let mut lease = lease();
            lease.restore_streams = bootstrapped;
            audit(&server, flavor).await;
            if bootstrapped {
                mount(
                    &server,
                    "GET",
                    "/api/lists/index",
                    None,
                    &fixture(flavor, "index_after")["response"],
                    200,
                    1,
                )
                .await;
                mount(
                    &server,
                    "GET",
                    "/api/lists/_find",
                    Some(("per_page", "1")),
                    &fixture(
                        flavor,
                        if remaining {
                            "cleanup_lists_nonempty"
                        } else {
                            "cleanup_lists_empty"
                        },
                    )["response"],
                    200,
                    1,
                )
                .await;
                if !remaining {
                    mount(
                        &server,
                        "DELETE",
                        "/api/lists/index",
                        None,
                        &fixture(flavor, "index_delete")["response"],
                        200,
                        1,
                    )
                    .await;
                    mount(
                        &server,
                        "GET",
                        "/api/lists/index",
                        None,
                        &fixture(flavor, "index_restored")["response"],
                        404,
                        1,
                    )
                    .await;
                }
            }
            cleanup::finish(&transport(&server), &mut lease)
                .await
                .unwrap();
            let requests = server.received_requests().await.unwrap();
            assert_eq!(
                requests.iter().filter(|r| r.method == "DELETE").count(),
                usize::from(bootstrapped && !remaining)
            );
        }
    }
}

#[path = "faults.rs"]
mod faults;

#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;

#[path = "classification_tests.rs"]
mod classification_tests;
