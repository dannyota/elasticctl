use super::super::round_trip::{RoundTrip, multiset, verify_alerts};
use super::*;

fn root_fixture(flavor: &str, operation: &str) -> Value {
    let flavor = if flavor == "ech-9.5.6" {
        "ech-9.5.2"
    } else {
        flavor
    };
    let file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(flavor)
        .join(format!("{operation}.json"));
    serde_json::from_slice::<Value>(&std::fs::read(file).unwrap()).unwrap()["response"].clone()
}

#[test]
fn export_comparison_preserves_duplicate_counts_but_ignores_order() {
    let values = vec!["a".into(), "b".into(), "a".into()];
    assert_eq!(
        multiset(values.clone()),
        multiset(vec!["a".into(), "a".into(), "b".into()])
    );
    assert_ne!(multiset(values), multiset(vec!["a".into(), "b".into()]));
}

#[test]
fn alert_check_uses_recorded_event_codes_and_rejects_the_wrong_events_at_the_same_count() {
    let hits = elasticctl_api::rules::decode_preview_hits_checked(&root_fixture(
        FLAVORS[2],
        "rules_preview_hits",
    ))
    .unwrap();
    let report = serde_json::to_value(elasticctl_api::rules_ops::PreviewReport {
        rule: "synthetic".into(),
        preview_id: Some("synthetic".into()),
        invocations: 1,
        hits: Some(hits.total),
        errors: vec![],
        warnings: vec![],
        hits_error: None,
        sample: hits.sample,
    })
    .unwrap();
    assert_eq!(verify_alerts(&report, &["1"]), Ok(()));
    assert_eq!(verify_alerts(&report, &["2"]), Err(StepError::Failed));
}

pub(super) fn case<'a>(
    dir: &'a tempfile::TempDir,
    config: &'a Path,
    flavor: &str,
) -> RoundTrip<'a> {
    RoundTrip {
        config,
        dir: dir.path().join("mirror"),
        key: None,
        rule: fixture(flavor, "state_rule_r")["response"]["rule_id"]
            .as_str()
            .unwrap()
            .into(),
        ip: fixture(flavor, "state_container_v")["response"]["id"]
            .as_str()
            .unwrap()
            .into(),
        keyword: fixture(flavor, "state_container_c")["response"]["id"]
            .as_str()
            .unwrap()
            .into(),
    }
}

async fn current(server: &MockServer, flavor: &str) -> Lease {
    let mut lease = lease();
    for (kind, name) in [
        (Kind::List, "state_container_c"),
        (Kind::List, "state_container_v"),
        (Kind::Exception, "exception_create"),
        (Kind::Item, "exception_item_create"),
        (Kind::Rule, "state_rule_r"),
    ] {
        let body = fixture(flavor, name)["response"].clone();
        let id = body[kind.key()].as_str().unwrap();
        Mock::given(method("GET"))
            .and(path(kind.endpoint()))
            .and(query_param(kind.key(), id))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(server)
            .await;
        lease.objects.push(Object::new(kind, id.into()));
    }
    for (endpoint, operation) in [
        ("/api/status", "status"),
        ("/api/lists/index", "index_after"),
        ("/api/detection_engine/rules/_find", "state_rules_selected"),
        ("/api/exception_lists/items/_find", "exception_items_find"),
    ] {
        Mock::given(method("GET"))
            .and(path(endpoint))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(&fixture(flavor, operation)["response"]),
            )
            .mount(server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/_find"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&fixture(flavor, "exception_lists_find_agnostic")["response"]),
        )
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_export"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                fixture(flavor, "items_export")["response"]
                    .as_str()
                    .unwrap(),
            ),
        )
        .mount(server)
        .await;
    lease
}

fn local_mirror(run: &RoundTrip<'_>, flavor: &str) {
    std::fs::create_dir_all(run.dir.join("rules")).unwrap();
    std::fs::create_dir_all(run.dir.join("exceptions")).unwrap();
    std::fs::create_dir_all(run.dir.join("value-lists")).unwrap();
    let rule = elasticctl_api::model::Rule::from_value(
        fixture(flavor, "state_rule_r")["response"].clone(),
    )
    .unwrap();
    std::fs::write(
        run.dir.join("rules").join(format!("{}.ndjson", run.rule)),
        serde_json::to_vec(&elasticctl_api::normalize::canonical(&rule).into_value()).unwrap(),
    )
    .unwrap();
    let mut container = fixture(flavor, "exception_create")["response"].clone();
    container["items"] = fixture(flavor, "exception_items_find")["response"]["data"].clone();
    let id = container["list_id"].as_str().unwrap();
    std::fs::write(
        run.dir.join("exceptions").join(format!("{id}.ndjson")),
        serde_json::to_vec(&container).unwrap(),
    )
    .unwrap();
    for operation in ["state_container_v", "state_container_c"] {
        let remote = api::decode_remote_container(&fixture(flavor, operation)["response"]).unwrap();
        let root = run.values_path(&remote.container.id);
        std::fs::write(
            root.with_extension("yaml"),
            api::encode_container(&remote.container).unwrap(),
        )
        .unwrap();
        std::fs::write(
            root,
            fixture(flavor, "items_export")["response"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    }
}

async fn clean_after_failure(
    server: &MockServer,
    flavor: &str,
    lease: &mut Lease,
    result: StepResult,
    step: u8,
) {
    assert_eq!(result, Err(StepError::Step(step)));
    server.reset().await;
    for object in &lease.objects {
        let (operation, absent) = match object.kind {
            Kind::Rule => ("state_rule_r", "cleanup_rule_absent"),
            Kind::Item => ("exception_item_create", "cleanup_exception_item_absent"),
            Kind::Exception => ("exception_create", "cleanup_exception_absent"),
            Kind::List if object.id == fixture(flavor, "state_container_c")["response"]["id"] => {
                ("state_container_c", "container_missing_c")
            }
            Kind::List => ("state_container_v", "container_missing_v"),
        };
        let query = Some((object.kind.key(), object.id.as_str()));
        mount(
            server,
            "GET",
            object.kind.endpoint(),
            query,
            &fixture(flavor, operation)["response"],
            200,
            1,
        )
        .await;
        mount(
            server,
            "DELETE",
            object.kind.endpoint(),
            query,
            &fixture(flavor, operation)["response"],
            200,
            1,
        )
        .await;
        mount(
            server,
            "GET",
            object.kind.endpoint(),
            query,
            &fixture(flavor, absent)["response"],
            404,
            1,
        )
        .await;
    }
    audit(server, flavor).await;
    let cleanup = cleanup::finish(&transport(server), lease).await;
    assert!(cleanup.is_ok());
    assert!(lease.objects.is_empty());
    let payload =
        std::panic::catch_unwind(|| run_classified(|| classify(Ok(()), result, Ok(()), Ok(()))))
            .unwrap_err();
    assert_eq!(
        panic_payload_text(payload).lines().next(),
        Some("elasticctl-conformance-class:contract")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_cli_verifies_pairs_and_failure_class_then_cleans_exact_ids() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        let mut lease = current(&server, flavor).await;
        let dir = tempfile::tempdir().unwrap();
        let config = mcp_smoke::mcp_subprocess_config(dir.path(), &server.uri());
        let run = case(&dir, &config, flavor);
        let result = at_step(3, run.pull(&lease).await);
        let mirror = elasticctl_api::state::read_mirror(&run.dir).unwrap();
        assert_eq!(mirror.value_lists.len(), 1);
        assert_eq!(mirror.value_lists[0].container.id, run.ip);
        let requests = server.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .all(|r| r.method == "GET" || r.url.path() == "/api/lists/items/_export")
        );
        assert!(
            requests
                .iter()
                .filter(|r| r.url.path() == "/api/detection_engine/rules/_find")
                .all(|r| r
                    .url
                    .query_pairs()
                    .any(|(k, v)| k == "filter" && v.contains(&run.rule)))
        );
        clean_after_failure(&server, flavor, &mut lease, result, 3).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn injected_push_preflight_fault_is_classified_and_cleanup_removes_every_object() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    let mut lease = current(&server, flavor).await;
    let dir = tempfile::tempdir().unwrap();
    let config = mcp_smoke::mcp_subprocess_config(dir.path(), &server.uri());
    let run = case(&dir, &config, flavor);
    local_mirror(&run, flavor);
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(&fixture(flavor, "status")["response"]),
        )
        .with_priority(1)
        .mount(&server)
        .await;
    let result = at_step(4, run.push(&transport(&server), &mut lease).await);
    assert!(!lease.state_push_pending);
    assert!(
        std::fs::read_to_string(run.values_path(&run.ip))
            .unwrap()
            .contains("198.51.100.5\n")
    );
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == "GET" || r.url.path() == "/api/lists/items/_export")
    );
    clean_after_failure(&server, flavor, &mut lease, result, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preview_without_identity_is_classified_and_cleaned_for_both_phases() {
    for after in [false, true] {
        let flavor = FLAVORS[2];
        let server = MockServer::start().await;
        let mut lease = current(&server, flavor).await;
        let dir = tempfile::tempdir().unwrap();
        let config = mcp_smoke::mcp_subprocess_config(dir.path(), &server.uri());
        let run = case(&dir, &config, flavor);
        Mock::given(method("POST"))
            .and(path("/api/detection_engine/rules/preview"))
            .and(wiremock::matchers::body_partial_json(
                json!({"enabled":false,"invocationCount":1}),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(root_fixture(flavor, "rules_preview")),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/.preview.alerts-security.alerts-default/_search"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(root_fixture(flavor, "rules_preview_hits")),
            )
            .mount(&server)
            .await;
        let result = at_step(5, run.preview(&transport(&server), &lease, after).await);
        let requests = server.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .any(|r| r.url.path() == "/api/detection_engine/rules/preview")
        );
        clean_after_failure(&server, flavor, &mut lease, result, 5).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_and_type_refusals_are_read_only_and_restore_local_files() {
    for refusal in [
        super::super::refusals::Refusal::Missing,
        super::super::refusals::Refusal::TypeMismatch,
    ] {
        let flavor = FLAVORS[0];
        let server = MockServer::start().await;
        let lease = current(&server, flavor).await;
        let dir = tempfile::tempdir().unwrap();
        let config = mcp_smoke::mcp_subprocess_config(dir.path(), &server.uri());
        let run = case(&dir, &config, flavor);
        local_mirror(&run, flavor);
        let before = elasticctl_api::state::read_mirror(&run.dir).unwrap();
        assert_eq!(
            super::super::refusals::one(&transport(&server), &lease, &run, refusal).await,
            Ok(())
        );
        let after = elasticctl_api::state::read_mirror(&run.dir).unwrap();
        assert_eq!(before.value_lists, after.value_lists);
        assert_eq!(before.items, after.items);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method == "GET" || r.url.path() == "/api/lists/items/_export")
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn injected_refusal_preflight_fault_is_classified_and_cleanup_removes_every_object() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    let mut lease = current(&server, flavor).await;
    let dir = tempfile::tempdir().unwrap();
    let config = mcp_smoke::mcp_subprocess_config(dir.path(), &server.uri());
    let run = case(&dir, &config, flavor);
    local_mirror(&run, flavor);
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(&fixture(flavor, "status")["response"]),
        )
        .with_priority(1)
        .mount(&server)
        .await;
    let result = at_step(
        6,
        super::super::refusals::run(&transport(&server), &lease, &run).await,
    );
    clean_after_failure(&server, flavor, &mut lease, result, 6).await;
}

#[test]
fn dash_refusal_has_no_transport_and_never_references_or_writes_its_candidate() {
    assert_eq!(super::super::refusals::dash_refusal("synthetic"), Ok(()));
}

#[tokio::test]
async fn push_evidence_is_generated_by_the_api_and_unverified_writes_keep_cleanup_blocked() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    let lease = current(&server, flavor).await;
    Mock::given(method("PATCH"))
        .and(path("/api/lists"))
        .respond_with(
            ResponseTemplate::new(409)
                .set_body_json(&fixture(flavor, "container_patch_stale")["response"]),
        )
        .expect(1)
        .mount(&server)
        .await;
    let t = transport(&server);
    let mut plans = Vec::new();
    let mut ids = Vec::new();
    for name in ["state_container_v", "state_container_c"] {
        let container = api::decode_remote_container(&fixture(flavor, name)["response"]).unwrap();
        let stored = api::decode_export(
            &container.container.list_type,
            fixture(flavor, "items_export")["response"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let mut local = api::LocalPair {
            stem: api::file_stem(&container.container.id),
            container: container.container.clone(),
            values: stored.set(),
        };
        local.container.name.push_str(" changed");
        ids.push(local.container.id.clone());
        plans.push(
            api::plan_list(local, Some(api::RemoteList { container, stored }), &[], &[]).unwrap(),
        );
    }
    let outcomes = api::apply_plans(&t, &plans, &api::SystemClock::default()).await;
    let original = outcomes
        .iter()
        .flat_map(|outcome| outcome.evidence.iter().cloned())
        .collect::<Vec<_>>();
    let report = |evidence: Vec<api::Evidence>| {
        serde_json::to_value(elasticctl_api::report::ChangeReport {
            profile: "synthetic".into(),
            host: "example.invalid".into(),
            space: "default".into(),
            applied: true,
            entries: evidence
                .into_iter()
                .map(elasticctl_api::report::ReportEntry::from)
                .collect(),
        })
        .unwrap()
    };
    let mut known = super::lease();
    known.state_push_pending = true;
    super::super::round_trip::settle_push_report(
        &report(original.clone()),
        &mut known,
        [&ids[0], &ids[1]],
    )
    .unwrap();
    assert!(!known.state_push_pending);
    for (sent, status) in [
        (api::Sent::Accepted, 200),
        (api::Sent::Refused, 408),
        (api::Sent::Refused, 503),
        (api::Sent::Uncertain, 200),
    ] {
        let mut evidence = original.clone();
        evidence[0].sent = Some(sent);
        evidence[0].status = Some(status);
        evidence[0].phase_verified = false;
        let mut unknown = super::lease();
        unknown.state_push_pending = true;
        assert!(
            super::super::round_trip::settle_push_report(
                &report(evidence),
                &mut unknown,
                [&ids[0], &ids[1]]
            )
            .is_err()
        );
        assert!(unknown.state_push_pending);
    }
    assert!(!lease.state_push_pending);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_new_step_stops_before_a_child_when_interrupted() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    let mut lease = current(&server, flavor).await;
    let dir = tempfile::tempdir().unwrap();
    let config = mcp_smoke::mcp_subprocess_config(dir.path(), &server.uri());
    let run = case(&dir, &config, flavor);
    lease.cancelled.store(true, Ordering::SeqCst);
    assert_eq!(run.pull(&lease).await, Err(StepError::Interrupted));
    assert_eq!(
        run.push(&transport(&server), &mut lease).await,
        Err(StepError::Interrupted)
    );
    assert_eq!(
        run.preview(&transport(&server), &lease, false).await,
        Err(StepError::Interrupted)
    );
    assert_eq!(
        super::super::refusals::run(&transport(&server), &lease, &run).await,
        Err(StepError::Interrupted)
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn unresolved_child_push_retains_lists_and_streams_while_removing_known_parents() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    let mut lease = super::lease();
    for (kind, operation, absent) in [
        (Kind::Rule, "state_rule_r", "cleanup_rule_absent"),
        (
            Kind::Item,
            "exception_item_create",
            "cleanup_exception_item_absent",
        ),
        (
            Kind::Exception,
            "exception_create",
            "cleanup_exception_absent",
        ),
    ] {
        let body = fixture(flavor, operation)["response"].clone();
        let id = body[kind.key()].as_str().unwrap();
        let query = Some((kind.key(), id));
        mount(&server, "GET", kind.endpoint(), query, &body, 200, 1).await;
        mount(&server, "DELETE", kind.endpoint(), query, &body, 200, 1).await;
        mount(
            &server,
            "GET",
            kind.endpoint(),
            query,
            &fixture(flavor, absent)["response"],
            404,
            1,
        )
        .await;
        lease.objects.push(Object::new(kind, id.into()));
    }
    lease
        .objects
        .push(Object::new(Kind::List, format!("{PREFIX}pending-child")));
    lease.state_push_pending = true;
    lease.restore_streams = true;
    audit(&server, flavor).await;
    assert!(
        cleanup::finish(&transport(&server), &mut lease)
            .await
            .is_err()
    );
    assert_eq!(lease.objects.len(), 1);
    assert_eq!(lease.objects[0].kind, Kind::List);
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.url.path() != "/api/lists" && r.url.path() != "/api/lists/index")
    );
}
