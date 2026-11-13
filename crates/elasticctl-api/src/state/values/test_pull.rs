use super::*;

#[tokio::test]
async fn pull_reads_the_full_selected_list_preserving_spellings_and_warning_on_duplicates() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        mount(&server, flavor, "GET", "/api/lists", "container_read", 200).await;
        mount(
            &server,
            flavor,
            "POST",
            "/api/lists/items/_export",
            "items_export",
            200,
        )
        .await;
        let expected = pair(flavor);
        let (pairs, warnings) = pull_lists(&transport(&server), &[item(&expected.container.id)])
            .await
            .unwrap();
        assert_eq!(pairs, [expected]);
        assert!(
            warnings
                .iter()
                .any(|w| w.kind == vl::WarningKind::Duplicates)
        );
        no_writes(&server).await;
    }
}

#[tokio::test]
async fn pull_collects_missing_and_mismatched_lists_with_every_referencing_item() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    let present = pair(flavor).container.id;
    Mock::given(method("GET"))
        .and(path("/api/lists"))
        .and(query_param("id", &present))
        .respond_with(response(flavor, "container_read", 200))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/lists"))
        .and(query_param("id", "missing"))
        .respond_with(response(flavor, "items_delete_id_absent", 404))
        .mount(&server)
        .await;
    let mut mismatch = item(&present);
    mismatch.as_map_mut()["entries"][0]["list"]["type"] = json!("keyword");
    let error = pull_lists(&transport(&server), &[mismatch, item("missing")])
        .await
        .unwrap_err();
    for text in [
        present.as_str(),
        "missing",
        "item",
        "fix the stack or narrow the pull",
    ] {
        assert!(error.message.contains(text), "{}", error.message);
    }
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
}

#[tokio::test]
async fn reread_stops_when_a_referenced_container_disappears_before_exception_writes() {
    let server = MockServer::start().await;
    let flavor = FLAVORS[0];
    let local = pair(flavor);
    let list = vl::plan_list(local, Some(remote(flavor)), &[], &[]).unwrap();
    mount(
        &server,
        flavor,
        "GET",
        "/api/lists",
        "items_delete_id_absent",
        404,
    )
    .await;
    let error = reread(
        &transport(&server),
        &ValuePlan {
            plans: vec![list],
            drift: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Conflict);
    no_writes(&server).await;
}

#[tokio::test]
async fn reread_refuses_a_changed_container_id_as_conflict() {
    let server = MockServer::start().await;
    let flavor = FLAVORS[0];
    let planned = vl::plan_list(pair(flavor), Some(remote(flavor)), &[], &[]).unwrap();
    mount(&server, flavor, "GET", "/api/lists", "contain_create", 200).await;
    let error = reread(
        &transport(&server),
        &ValuePlan {
            plans: vec![planned],
            drift: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Conflict);
    no_writes(&server).await;
}
