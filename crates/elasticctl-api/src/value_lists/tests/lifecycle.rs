use super::super::*;
use super::apply::FastClock;
use super::plan::{pair, remote};
use super::reads::{FLAVORS, fixture, response, transport};
use super::requests::{assert_plan_writes, assert_request};
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer};

#[tokio::test]
async fn init_already_ready_never_writes() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/lists/index"))
            .respond_with(response(&fixture(flavor, "index_after"), 200))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            apply_init(&transport(&server)).await.unwrap(),
            InitOutcome::AlreadyBootstrapped
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn init_runs_only_the_named_flow_and_verifies_both_streams() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/lists/index"))
            .respond_with(response(&fixture(flavor, "index_before"), 404))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/lists/index"))
            .respond_with(response(&fixture(flavor, "index_after"), 200))
            .expect(1)
            .mount(&server)
            .await;
        let flow = fixture(flavor, "initialize");
        Mock::given(method("POST"))
            .and(path("/api/security_solution/initialize"))
            .and(body_json(&flow["request"]))
            .respond_with(response(&flow, 200))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            apply_init(&transport(&server)).await.unwrap(),
            InitOutcome::Bootstrapped
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method, "GET");
        assert_request(
            &requests[1],
            "POST",
            "/api/security_solution/initialize",
            &[],
        );
        assert_eq!(
            requests[1].body_json::<serde_json::Value>().unwrap(),
            flow["request"]
        );
        assert_eq!(requests[2].method, "GET");
        assert!(requests.iter().all(|r| r.url.query().is_none()));
    }
}

#[tokio::test]
async fn init_non_ready_flow_derived_from_recorded_initialize_is_an_http_error() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/lists/index"))
        .respond_with(response(&fixture(flavor, "index_before"), 404))
        .expect(1)
        .mount(&server)
        .await;
    let mut flow = fixture(flavor, "initialize");
    flow["response"]["flows"]["create-list-indices"]["status"] = serde_json::json!("failed");
    Mock::given(method("POST"))
        .and(path("/api/security_solution/initialize"))
        .and(body_json(&flow["request"]))
        .respond_with(response(&flow, 200))
        .expect(1)
        .mount(&server)
        .await;
    let error = apply_init(&transport(&server)).await.unwrap_err();
    assert_eq!(error.kind, elasticctl_core::ErrorKind::Http);
    assert!(error.message.contains("failed"));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_request(
        &requests[1],
        "POST",
        "/api/security_solution/initialize",
        &[],
    );
    assert_eq!(
        requests[1].body_json::<serde_json::Value>().unwrap(),
        flow["request"]
    );
}

#[tokio::test]
async fn referenced_delete_reports_nested_reference_names_and_sends_no_flags() {
    for flavor in FLAVORS {
        let before = remote(flavor);
        let local = pair(&before);
        let server = MockServer::start().await;
        let f = fixture(flavor, "container_delete_referenced");
        Mock::given(method("DELETE"))
            .and(path("/api/lists"))
            .and(query_param("id", &local.container.id))
            .respond_with(response(&f, 409))
            .expect(1)
            .mount(&server)
            .await;
        let result = super::super::lifecycle::delete_one(&transport(&server), &before).await;
        let requests = server.received_requests().await.unwrap();
        assert_request(
            &requests[0],
            "DELETE",
            "/api/lists",
            &[("id", &before.container.container.id)],
        );
        assert!(requests[0].body.is_empty());
        assert_eq!(result.result.outcome, Outcome::Failed);
        assert_eq!(result.result.error.as_ref().unwrap().kind, "conflict");
        let expected = &f["response"]["message"]["error"]["references"][0]["exception_item"];
        assert_eq!(
            result.references[0].container.list_id,
            expected["list_id"].as_str().unwrap()
        );
        assert_eq!(
            result.references[0].container.namespace_type,
            expected["namespace_type"].as_str().unwrap()
        );
        assert_eq!(
            result.references[0].item_id,
            expected["item_id"].as_str().unwrap()
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url.query_pairs().count(), 1);
        assert!(requests[0].body.is_empty());
    }
}

#[tokio::test]
async fn uncertain_patch_settles_from_matching_container_then_continues() {
    for flavor in FLAVORS {
        let before = remote(flavor);
        let mut local = pair(&before);
        local.container.name = fixture(flavor, "container_patch")["response"]["name"]
            .as_str()
            .unwrap()
            .into();
        let plan = plan_list(local, Some(before), &[], &[]).unwrap();
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/api/lists"))
            .respond_with(response(&fixture(flavor, "container_patch"), 503))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/lists"))
            .and(query_param("id", &plan.local.container.id))
            .respond_with(response(&fixture(flavor, "container_patch"), 200))
            .expect(1)
            .mount(&server)
            .await;
        let result = super::super::apply::apply_one(
            &transport(&server),
            &plan,
            &FastClock::default(),
            2,
            &mut None,
        )
        .await;
        assert_plan_writes(&server, flavor, &plan).await;
        assert_eq!(result.outcome, Outcome::Applied);
        assert_eq!(result.evidence[0].sent, Some(Sent::Uncertain));
        assert!(result.evidence[0].phase_verified);
    }
}

#[tokio::test]
async fn create_sends_the_local_container_once_and_uncertainty_settles_both_ways() {
    for flavor in FLAVORS {
        for (status, matching) in [(200, true), (503, true), (503, false)] {
            let before = remote(flavor);
            let plan = plan_list(pair(&before), None, &[], &[]).unwrap();
            let server = MockServer::start().await;
            let create = fixture(flavor, "container_create");
            Mock::given(method("POST"))
                .and(path("/api/lists"))
                .and(body_json(&create["request"]))
                .respond_with(response(&create, status))
                .expect(1)
                .mount(&server)
                .await;
            if status == 503 {
                Mock::given(method("GET"))
                    .and(path("/api/lists"))
                    .and(query_param("id", &plan.local.container.id))
                    .respond_with(response(
                        &fixture(
                            flavor,
                            if matching {
                                "container_read"
                            } else {
                                "container_patch"
                            },
                        ),
                        200,
                    ))
                    .mount(&server)
                    .await;
            }
            if matching {
                Mock::given(method("POST"))
                    .and(path("/api/lists/items/_import"))
                    .respond_with(response(&fixture(flavor, "items_import"), 200))
                    .expect(1)
                    .mount(&server)
                    .await;
                super::apply::export_mock(&server, flavor, "items_export", 200).await;
            }
            let result = super::super::apply::apply_one(
                &transport(&server),
                &plan,
                &FastClock::default(),
                2,
                &mut None,
            )
            .await;
            assert_plan_writes(&server, flavor, &plan).await;
            assert_eq!(
                result.outcome,
                if matching {
                    Outcome::Applied
                } else {
                    Outcome::Unknown
                }
            );
            assert_eq!(
                result.evidence[0].sent,
                Some(if status == 200 {
                    Sent::Accepted
                } else {
                    Sent::Uncertain
                })
            );
            if !matching {
                let read = result.evidence.last().unwrap();
                assert_eq!(read.of, Some(ReadOf::Container));
                assert_eq!(read.observed, Some(true));
                assert_eq!(read.mismatched, Some(vec!["name".into()]));
                assert!(
                    server
                        .received_requests()
                        .await
                        .unwrap()
                        .iter()
                        .all(|r| !r.url.path().ends_with("_import"))
                );
            }
        }
    }
}

#[tokio::test]
async fn uncertain_patch_with_nonmatching_container_is_unknown_and_sends_no_import() {
    let flavor = FLAVORS[0];
    let before = remote(flavor);
    let mut local = pair(&before);
    local.container.name = fixture(flavor, "container_patch")["response"]["name"]
        .as_str()
        .unwrap()
        .into();
    local.values.insert("192.0.2.0/24".into());
    let plan = plan_list(local, Some(before), &[], &[]).unwrap();
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/lists"))
        .respond_with(response(&fixture(flavor, "container_patch"), 503))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/lists"))
        .respond_with(response(&fixture(flavor, "container_read"), 200))
        .mount(&server)
        .await;
    let result = super::super::apply::apply_one(
        &transport(&server),
        &plan,
        &FastClock::default(),
        2,
        &mut None,
    )
    .await;
    assert_plan_writes(&server, flavor, &plan).await;
    assert_eq!(result.outcome, Outcome::Unknown);
    assert_eq!(result.evidence[1].sent, Some(Sent::NotSent));
    assert_eq!(
        result.evidence.last().unwrap().mismatched,
        Some(vec!["name".into()])
    );
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| !r.url.path().ends_with("_import"))
    );
}

#[tokio::test]
async fn uncertain_container_delete_is_applied_only_when_the_following_read_is_404() {
    for absent in [true, false] {
        let flavor = FLAVORS[0];
        let before = remote(flavor);
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/lists"))
            .respond_with(response(&fixture(flavor, "container_delete"), 503))
            .expect(1)
            .mount(&server)
            .await;
        let (operation, status) = if absent {
            ("items_delete_id_absent", 404)
        } else {
            ("container_read", 200)
        };
        Mock::given(method("GET"))
            .and(path("/api/lists"))
            .and(query_param("id", &before.container.container.id))
            .respond_with(response(&fixture(flavor, operation), status))
            .expect(1)
            .mount(&server)
            .await;
        let result = super::super::lifecycle::delete_one(&transport(&server), &before).await;
        let requests = server.received_requests().await.unwrap();
        assert_request(
            &requests[0],
            "DELETE",
            "/api/lists",
            &[("id", &before.container.container.id)],
        );
        assert!(requests[0].body.is_empty());
        assert_eq!(
            result.result.outcome,
            if absent {
                Outcome::Applied
            } else {
                Outcome::Unknown
            }
        );
        assert_eq!(result.result.evidence[0].sent, Some(Sent::Uncertain));
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
}
