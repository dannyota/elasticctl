use super::*;

#[tokio::test]
async fn injected_create_fault_at_each_write_is_registered_once_and_cleaned_after_an_early_404() {
    for flavor in FLAVORS {
        for (kind, name, absent) in [
            (Kind::List, "contain_create", "container_missing_c"),
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
        ] {
            let server = MockServer::start().await;
            let recorded = fixture(flavor, name);
            let id = recorded["response"][kind.key()].as_str().unwrap();
            let missing = fixture(flavor, absent);
            mount(
                &server,
                "POST",
                kind.endpoint(),
                None,
                &recorded["response"],
                500,
                1,
            )
            .await;
            mount(
                &server,
                "GET",
                kind.endpoint(),
                Some((kind.key(), id)),
                &missing["response"],
                404,
                1,
            )
            .await;
            mount(
                &server,
                "GET",
                kind.endpoint(),
                Some((kind.key(), id)),
                &recorded["response"],
                200,
                1,
            )
            .await;
            mount(
                &server,
                "DELETE",
                kind.endpoint(),
                Some((kind.key(), id)),
                &recorded["response"],
                200,
                1,
            )
            .await;
            mount(
                &server,
                "GET",
                kind.endpoint(),
                Some((kind.key(), id)),
                &missing["response"],
                404,
                1,
            )
            .await;
            audit(&server, flavor).await;
            let mut lease = lease();
            let t = transport(&server);
            assert_eq!(
                setup::create(&t, &mut lease, kind, id.into(), recorded["request"].clone()).await,
                Err(StepError::Failed)
            );
            assert!(lease.objects[0].pending);
            cleanup::finish(&t, &mut lease).await.unwrap();
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.iter().filter(|r| r.method == "POST").count(), 1);
            assert_eq!(requests.iter().filter(|r| r.method == "DELETE").count(), 1);
            assert_eq!(
                requests[0].body_json::<Value>().unwrap(),
                recorded["request"]
            );
        }
    }
}

#[tokio::test]
async fn pending_create_without_proven_ownership_blocks_dependent_deletes_and_stream_restore() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    let mut lease = lease();
    let recorded = fixture(flavor, "state_rule_r");
    let id = recorded["response"]["rule_id"].as_str().unwrap();
    let mut rule = Object::new(Kind::Rule, id.into());
    rule.pending = true;
    lease.objects.push(rule);
    lease
        .objects
        .push(Object::new(Kind::Exception, format!("{PREFIX}blocked")));
    lease.restore_streams = true;
    Mock::given(method("GET"))
        .and(path(Kind::Rule.endpoint()))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(fixture(flavor, "cleanup_rule_absent")["response"].clone()),
        )
        .mount(&server)
        .await;
    audit(&server, flavor).await;
    assert_eq!(
        cleanup::finish(&transport(&server), &mut lease).await,
        Err(StepError::Failed)
    );
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
    assert_eq!(lease.objects.len(), 2);
}

#[tokio::test]
async fn a_create_409_never_registers_the_existing_object_for_deletion() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    let recorded = fixture(flavor, "contain_create");
    mount(
        &server,
        "POST",
        Kind::List.endpoint(),
        None,
        &fixture(flavor, "container_delete_referenced")["response"],
        409,
        1,
    )
    .await;
    audit(&server, flavor).await;
    let mut lease = lease();
    assert!(
        setup::create(
            &transport(&server),
            &mut lease,
            Kind::List,
            recorded["request"]["id"].as_str().unwrap().into(),
            recorded["request"].clone()
        )
        .await
        .is_err()
    );
    assert!(lease.objects.is_empty());
    cleanup::finish(&transport(&server), &mut lease)
        .await
        .unwrap();
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method != "DELETE")
    );
}

#[tokio::test]
async fn no_404_confirmation_keeps_the_rule_registered_and_blocks_parent_deletion() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    let recorded = fixture(flavor, "state_rule_r");
    let id = recorded["response"]["rule_id"].as_str().unwrap();
    Mock::given(method("GET"))
        .and(path(Kind::Rule.endpoint()))
        .and(query_param("rule_id", id))
        .respond_with(ResponseTemplate::new(200).set_body_json(recorded["response"].clone()))
        .mount(&server)
        .await;
    mount(
        &server,
        "DELETE",
        Kind::Rule.endpoint(),
        Some(("rule_id", id)),
        &recorded["response"],
        200,
        1,
    )
    .await;
    let mut lease = lease();
    lease.objects.push(Object::new(Kind::Rule, id.into()));
    lease
        .objects
        .push(Object::new(Kind::Exception, format!("{PREFIX}blocked")));
    audit(&server, flavor).await;
    assert!(
        cleanup::finish(&transport(&server), &mut lease)
            .await
            .is_err()
    );
    assert_eq!(lease.objects.len(), 2);
    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "DELETE")
            .count(),
        1
    );
}

#[tokio::test]
async fn injected_audit_fault_retries_inside_budget_before_restore() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    mount(
        &server,
        "GET",
        "/.items-default/_search",
        None,
        &fixture(flavor, "cleanup_items_audit")["response"],
        500,
        1,
    )
    .await;
    audit(&server, flavor).await;
    cleanup::finish(&transport(&server), &mut lease())
        .await
        .unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn injected_audit_timeout_blocks_stream_deletion() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.items-default/_search"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(fixture(flavor, "cleanup_items_audit")["response"].clone())
                .set_delay(Duration::from_secs(1)),
        )
        .mount(&server)
        .await;
    let mut lease = lease();
    lease.restore_streams = true;
    let started = std::time::Instant::now();
    assert!(
        cleanup::finish(&transport(&server), &mut lease)
            .await
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.url.path() == "/.items-default/_search")
    );
}

#[tokio::test]
async fn interrupt_refuses_new_writes_and_still_cleans_every_registered_object() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    let mut lease = lease();
    registered_objects(&server, flavor, &mut lease, 5).await;
    lease.cancelled.store(true, Ordering::SeqCst);
    let recorded = fixture(flavor, "contain_create");
    assert_eq!(
        setup::create(
            &transport(&server),
            &mut lease,
            Kind::List,
            recorded["request"]["id"].as_str().unwrap().into(),
            recorded["request"].clone()
        )
        .await,
        Err(StepError::Interrupted)
    );
    audit(&server, flavor).await;
    cleanup::finish(&transport(&server), &mut lease)
        .await
        .unwrap();
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method != "POST")
    );
}

#[tokio::test]
async fn bootstrap_uses_recorded_before_and_init_is_one_shot() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        for (name, status) in [
            ("index_before", 404),
            ("index_before", 404),
            ("index_after", 200),
        ] {
            mount(
                &server,
                "GET",
                "/api/lists/index",
                None,
                &fixture(flavor, name)["response"],
                status,
                1,
            )
            .await;
        }
        let flow = fixture(flavor, "initialize");
        mount(
            &server,
            "POST",
            "/api/security_solution/initialize",
            None,
            &flow["response"],
            200,
            1,
        )
        .await;
        let mut lease = lease();
        let t = transport(&server);
        lease.before = Some(api::bootstrap_state(&t).await.unwrap());
        setup::initialize(&t, &mut lease).await.unwrap();
        assert!(lease.restore_streams && !lease.init_pending);
        let requests = server.received_requests().await.unwrap();
        let writes: Vec<_> = requests.iter().filter(|r| r.method == "POST").collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].body_json::<Value>().unwrap(), flow["request"]);
    }
}

#[tokio::test]
async fn existing_streams_skip_initialize() {
    let server = MockServer::start().await;
    let mut lease = lease();
    lease.before = Some(api::BootstrapState {
        list_index: true,
        list_item_index: true,
    });
    setup::initialize(&transport(&server), &mut lease)
        .await
        .unwrap();
    assert!(!lease.restore_streams);
    assert!(server.received_requests().await.unwrap().is_empty());
}
