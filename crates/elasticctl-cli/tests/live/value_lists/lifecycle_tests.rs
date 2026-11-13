use super::*;

#[tokio::test]
async fn pending_import_settles_from_recorded_export_before_list_delete() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        let mut lease = lease();
        registered_objects(&server, flavor, &mut lease, 1).await;
        let export = fixture(flavor, "contain_export");
        let values = export["response"]
            .as_str()
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        lease.objects[0].import = Some((api::ValueListType::IpRange, values));
        Mock::given(method("POST"))
            .and(path("/api/lists/items/_export"))
            .and(query_param("list_id", &lease.objects[0].id))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(export["response"].as_str().unwrap()),
            )
            .expect(1)
            .mount(&server)
            .await;
        audit(&server, flavor).await;
        cleanup::finish(&transport(&server), &mut lease)
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests[1].url.path(), "/api/lists/items/_export");
        assert_eq!(requests[2].method, "DELETE");
        assert!(requests.iter().all(|r| !r.url.path().ends_with("_import")));
    }
}

#[tokio::test]
async fn unresolved_import_blocks_list_and_stream_delete() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    let recorded = fixture(flavor, "contain_create");
    let id = recorded["response"]["id"].as_str().unwrap();
    mount(
        &server,
        "GET",
        "/api/lists",
        Some(("id", id)),
        &recorded["response"],
        200,
        1,
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_export"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                fixture(flavor, "export_empty")["response"]
                    .as_str()
                    .unwrap(),
            ),
        )
        .mount(&server)
        .await;
    let mut lease = lease();
    let mut object = Object::new(Kind::List, id.into());
    object.import = Some((api::ValueListType::IpRange, vec!["10.0.0.0/8".into()]));
    lease.objects.push(object);
    lease.restore_streams = true;
    audit(&server, flavor).await;
    assert!(
        cleanup::finish(&transport(&server), &mut lease)
            .await
            .is_err()
    );
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
async fn initial_absent_stream_baseline_is_read_only() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        for endpoint in [
            "/api/lists/index",
            "/api/lists/_find",
            "/.items-default/_search",
        ] {
            mount(
                &server,
                "GET",
                endpoint,
                None,
                &fixture(flavor, "index_before")["response"],
                404,
                1,
            )
            .await;
        }
        let mut lease = lease();
        setup::baseline(&transport(&server), &mut lease)
            .await
            .unwrap();
        assert_eq!(lease.before, Some(api::BootstrapState::default()));
        assert!(!lease.restore_streams);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method == "GET")
        );
    }
}

#[tokio::test]
async fn a_missing_list_cannot_clear_a_pending_import_or_authorize_stream_deletion() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    mount(
        &server,
        "GET",
        "/api/lists",
        None,
        &fixture(flavor, "container_missing_c")["response"],
        404,
        1,
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_export"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(fixture(flavor, "container_missing_c")["response"].clone()),
        )
        .mount(&server)
        .await;
    audit(&server, flavor).await;
    let mut lease = lease();
    let mut object = Object::new(Kind::List, format!("{PREFIX}pending-import"));
    object.import = Some((api::ValueListType::IpRange, vec!["10.0.0.0/8".into()]));
    lease.objects.push(object);
    assert!(
        cleanup::finish(&transport(&server), &mut lease)
            .await
            .is_err()
    );
    assert_eq!(lease.objects.len(), 1);
    assert!(lease.objects[0].import.is_some());
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
async fn a_missing_marker_index_cannot_clear_a_pending_document_write() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    let id = format!("{PREFIX}pending-events");
    mount(
        &server,
        "GET",
        &format!("/{id}/_mapping"),
        None,
        &fixture(flavor, "index_before")["response"],
        404,
        1,
    )
    .await;
    audit(&server, flavor).await;
    let mut lease = lease();
    lease.index = Some(Index {
        id: id.clone(),
        pending: false,
        delete_sent: false,
        pending_event: Some((
            format!("{id}-event"),
            fixture(flavor, "state_rule_r")["request"].clone(),
        )),
    });
    assert!(
        cleanup::finish(&transport(&server), &mut lease)
            .await
            .is_err()
    );
    assert!(lease.index.as_ref().unwrap().pending_event.is_some());
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
async fn verified_marker_index_deletion_is_once_by_exact_id_and_confirms_404() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        let id = format!("{PREFIX}verified-events");
        mount(
            &server,
            "DELETE",
            &format!("/{id}"),
            None,
            &fixture(flavor, "index_delete")["response"],
            200,
            1,
        )
        .await;
        mount(
            &server,
            "GET",
            &format!("/{id}"),
            None,
            &fixture(flavor, "index_before")["response"],
            404,
            2,
        )
        .await;
        let mut index = Index {
            id: id.clone(),
            pending: false,
            delete_sent: false,
            pending_event: None,
        };
        let t = transport(&server);
        cleanup::delete_index(
            &t,
            &mut index,
            Duration::from_millis(50),
            Duration::from_millis(1),
        )
        .await
        .unwrap();
        cleanup::delete_index(
            &t,
            &mut index,
            Duration::from_millis(50),
            Duration::from_millis(1),
        )
        .await
        .unwrap();
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method, "DELETE");
        assert!(
            requests
                .iter()
                .all(|r| r.url.path() == format!("/{id}") && r.url.query().is_none())
        );
    }
}

#[tokio::test]
async fn injected_index_create_fault_retains_the_pending_index_and_never_repeats_the_write() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    let id = format!("{PREFIX}uncertain-index");
    mount(
        &server,
        "PUT",
        &format!("/{id}"),
        None,
        &fixture(flavor, "index_delete")["response"],
        500,
        1,
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("/{id}/_mapping")))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(fixture(flavor, "index_before")["response"].clone()),
        )
        .mount(&server)
        .await;
    let mut lease = lease();
    let t = transport(&server);
    assert!(setup::index(&t, &mut lease, id).await.is_err());
    assert!(lease.index.as_ref().unwrap().pending);
    audit(&server, flavor).await;
    assert!(cleanup::finish(&t, &mut lease).await.is_err());
    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "PUT")
            .count(),
        1
    );
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
async fn injected_event_write_fault_retains_the_document_and_blocks_a_missing_parent_cleanup() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    let id = format!("{PREFIX}uncertain-event");
    let event_id = format!("{id}-1");
    mount(
        &server,
        "PUT",
        &format!("/{id}/_doc/{event_id}"),
        None,
        &fixture(flavor, "index_delete")["response"],
        500,
        1,
    )
    .await;
    mount(
        &server,
        "GET",
        &format!("/{id}/_mapping"),
        None,
        &fixture(flavor, "index_before")["response"],
        404,
        1,
    )
    .await;
    let mut lease = lease();
    lease.index = Some(Index {
        id: id.clone(),
        pending: false,
        delete_sent: false,
        pending_event: None,
    });
    let t = transport(&server);
    assert!(
        setup::write_event(
            &t,
            &mut lease,
            &id,
            event_id,
            fixture(flavor, "state_rule_r")["request"].clone()
        )
        .await
        .is_err()
    );
    assert!(lease.index.as_ref().unwrap().pending_event.is_some());
    audit(&server, flavor).await;
    assert!(cleanup::finish(&t, &mut lease).await.is_err());
    assert!(lease.index.as_ref().unwrap().pending_event.is_some());
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.iter().filter(|r| r.method == "PUT").count(), 1);
    assert!(requests.iter().all(|r| r.method != "DELETE"));
}
