use super::*;

#[tokio::test]
async fn selected_stack_only_reference_without_a_value_root_keeps_legacy_output() {
    for flavor in FLAVORS {
        for pushing in [false, true] {
            let server = MockServer::start().await;
            base(&server, flavor).await;
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
            let result = run(
                &transport(&server),
                &[],
                &[list()],
                &[item(&pair(flavor).container.id)],
                &[rule()],
                pushing,
            )
            .await
            .unwrap();
            assert!(
                result.drift.is_none(),
                "{flavor}, pushing={pushing}: {:?}",
                result.drift
            );
            assert_eq!(result.plans.len(), 1);
            let report = crate::state::reports::DiffReport {
                clean: result.drift.as_ref().is_none_or(ValueListDrift::is_clean),
                local: 1,
                remote: 1,
                changes: vec![],
                exceptions: crate::state::reports::ExceptionDrift {
                    local: 1,
                    remote: 1,
                    changes: vec![crate::state::reports::ListChange::Unchanged {
                        list_id: "exceptions".into(),
                    }],
                    dangling: vec![],
                },
                value_lists: result.drift,
                out_of_scope: 0,
                selected: None,
                local_total: None,
            };
            assert_eq!(
                serde_json::to_string(&report).unwrap(),
                r#"{"clean":true,"local":1,"remote":1,"changes":[],"exceptions":{"local":1,"remote":1,"changes":[{"change":"unchanged","list_id":"exceptions"}],"dangling":[]}}"#
            );
            no_writes(&server).await;
        }
    }
}

#[tokio::test]
async fn selected_set_uses_only_active_local_containers_and_reports_other_pairs() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        base(&server, flavor).await;
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
        let selected = pair(flavor);
        let mut other = selected.clone();
        other.container.id = "unselected".into();
        other.stem = "unselected".into();
        let items = [item(&selected.container.id), item("unselected")];
        let result = run(
            &transport(&server),
            &[selected.clone(), other],
            &[list()],
            &items[..1],
            &[rule()],
            true,
        )
        .await
        .unwrap();
        assert_eq!(result.plans.len(), 1);
        assert_eq!(result.plans[0].local.container.id, selected.container.id);
        let drift = result.drift.unwrap();
        assert_eq!(drift.unreferenced, ["unselected"]);
        assert!(drift.is_clean());
        assert!(drift.warnings.iter().any(|w| w.kind == "duplicates"));
        let requests = server.received_requests().await.unwrap();
        let lookups: Vec<_> = requests
            .iter()
            .filter(|r| r.url.path() == "/api/lists")
            .collect();
        assert_eq!(lookups.len(), 1);
        assert_eq!(
            lookups[0].url.query(),
            Some(format!("id={}", selected.container.id).as_str())
        );
        no_writes(&server).await;
    }
}

#[tokio::test]
async fn no_selected_reference_leaves_unreferenced_pairs_unread_and_clean() {
    let server = MockServer::start().await;
    let result = run(
        &transport(&server),
        &[pair(FLAVORS[0])],
        &[],
        &[],
        &[],
        true,
    )
    .await
    .unwrap();
    assert!(result.plans.is_empty());
    assert!(result.drift.unwrap().is_clean());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn diff_lists_every_value_and_container_field_change() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        base(&server, flavor).await;
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
        let mut local = pair(flavor);
        local.container.name = "Changed".into();
        local.values.remove("10.0.0.6/32");
        local.values.insert("10.0.0.9/32".into());
        let drift = run(
            &transport(&server),
            &[local.clone()],
            &[list()],
            &[item(&local.container.id)],
            &[rule()],
            false,
        )
        .await
        .unwrap()
        .drift
        .unwrap();
        assert!(!drift.is_clean());
        assert_eq!(drift.changes[0].change, "changed");
        assert_eq!(drift.changes[0].adds, ["10.0.0.9/32"]);
        assert_eq!(drift.changes[0].removes, ["10.0.0.6/32"]);
        assert_eq!(drift.changes[0].fields[0].field, "name");
    }
}

#[tokio::test]
async fn missing_source_is_not_found_for_push_and_dirty_for_diff() {
    for pushing in [false, true] {
        let server = MockServer::start().await;
        base(&server, FLAVORS[0]).await;
        mount(
            &server,
            FLAVORS[0],
            "GET",
            "/api/lists",
            "items_delete_id_absent",
            404,
        )
        .await;
        let result = run(
            &transport(&server),
            &[],
            &[list()],
            &[item("missing")],
            &[rule()],
            pushing,
        )
        .await;
        if pushing {
            let error = result.unwrap_err();
            assert_eq!(error.kind, ErrorKind::NotFound);
            assert!(error.message.contains("missing") && error.message.contains("item"));
        } else {
            let drift = result.unwrap().drift.unwrap();
            assert!(!drift.is_clean());
            assert_eq!(drift.refused[0].kind, "not_found");
        }
        no_writes(&server).await;
    }
}

#[tokio::test]
async fn unchanged_stack_only_reference_checks_the_entry_type() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        base(&server, flavor).await;
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
        let mut reference = item(&pair(flavor).container.id);
        reference.as_map_mut()["entries"][0]["list"]["type"] = json!("keyword");
        let error = run(
            &transport(&server),
            &[],
            &[list()],
            &[reference],
            &[rule()],
            true,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        assert!(error.message.contains("keyword") && error.message.contains("ip_range"));
        no_writes(&server).await;
    }
}

#[tokio::test]
async fn retained_reference_without_a_value_root_keeps_legacy_diff_shape_when_safe() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        base(&server, flavor).await;
        mount(
            &server,
            flavor,
            "GET",
            "/api/exception_lists",
            "exception_create",
            200,
        )
        .await;
        mount(
            &server,
            flavor,
            "GET",
            "/api/exception_lists/items/_find",
            "exception_items_find",
            200,
        )
        .await;
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
        let mut local = rule();
        local.as_map_mut()["exceptions_list"][0]["list_id"] =
            fixture(flavor, "exception_create")["response"]["list_id"].clone();
        let result = run(&transport(&server), &[], &[], &[], &[local], false)
            .await
            .unwrap();
        assert!(result.drift.is_none());
        assert_eq!(result.plans.len(), 1);
        no_writes(&server).await;
    }
}

#[tokio::test]
async fn full_and_scoped_local_selections_drive_the_same_reads_checks_and_plans() {
    let flavor = FLAVORS[0];
    for scoped in [false, true] {
        let server = MockServer::start().await;
        base(&server, flavor).await;
        let first = pair(flavor);
        let container = vl::decode_remote_container(&fixture(flavor, "contain_create")["response"])
            .unwrap()
            .container;
        let values = vl::decode_export(
            &container.list_type,
            fixture(flavor, "contain_export")["response"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .set();
        let second = LocalPair {
            stem: vl::file_stem(&container.id),
            container,
            values,
        };
        for (local, operation, export) in [
            (&first, "container_read", "items_export"),
            (&second, "contain_create", "contain_export"),
        ] {
            Mock::given(method("GET"))
                .and(path("/api/lists"))
                .and(query_param("id", &local.container.id))
                .respond_with(response(flavor, operation, 200))
                .expect(if scoped && operation == "contain_create" {
                    0
                } else {
                    1
                })
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/api/lists/items/_export"))
                .and(query_param("list_id", &local.container.id))
                .respond_with(response(flavor, export, 200))
                .expect(if scoped && operation == "contain_create" {
                    0
                } else {
                    1
                })
                .mount(&server)
                .await;
        }
        let mut second_list = list();
        second_list
            .as_map_mut()
            .insert("list_id".into(), json!("other"));
        let mut second_item = item(&second.container.id);
        second_item
            .as_map_mut()
            .insert("list_id".into(), json!("other"));
        let mut second_rule = rule();
        second_rule
            .as_map_mut()
            .insert("rule_id".into(), json!("other"));
        second_rule.as_map_mut()["exceptions_list"][0]["list_id"] = json!("other");
        let rules = if scoped {
            vec![rule()]
        } else {
            vec![rule(), second_rule]
        };
        let result = run(
            &transport(&server),
            &[first.clone(), second.clone()],
            &[list(), second_list],
            &[item(&first.container.id), second_item],
            &rules,
            true,
        )
        .await
        .unwrap();
        assert_eq!(result.plans.len(), if scoped { 1 } else { 2 });
        let drift = result.drift.unwrap();
        assert_eq!(
            drift.unreferenced,
            if scoped {
                vec![second.container.id]
            } else {
                vec![]
            }
        );
        no_writes(&server).await;
    }
}

#[test]
fn case_insensitive_collision_detection_reports_every_colliding_pair() {
    let collisions = vl::stem_collisions([("one", "same"), ("two", "SAME"), ("three", "Same")]);
    assert_eq!(collisions.len(), 3);
}

#[tokio::test]
async fn unchanged_selected_items_still_refuse_empty_and_excess_dash_local_targets() {
    let flavor = FLAVORS[0];
    for empty in [true, false] {
        let server = MockServer::start().await;
        base(&server, flavor).await;
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
        let mut local = pair(flavor);
        local.values = if empty {
            Default::default()
        } else {
            (1..=201)
                .map(|n| format!("10.0.{n}.1-10.0.{n}.2"))
                .collect()
        };
        let error = run(
            &transport(&server),
            &[local.clone()],
            &[list()],
            &[item(&local.container.id)],
            &[rule()],
            true,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unsupported);
        assert!(
            error
                .message
                .contains(if empty { "empty" } else { "stored dash values" }),
            "{}",
            error.message
        );
        no_writes(&server).await;
    }
}

#[tokio::test]
async fn an_unselected_local_pair_cannot_supply_a_missing_retained_reference() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    base(&server, flavor).await;
    mount(
        &server,
        flavor,
        "GET",
        "/api/exception_lists",
        "exception_create",
        200,
    )
    .await;
    mount(
        &server,
        flavor,
        "GET",
        "/api/exception_lists/items/_find",
        "exception_items_find",
        200,
    )
    .await;
    mount(
        &server,
        flavor,
        "GET",
        "/api/lists",
        "items_delete_id_absent",
        404,
    )
    .await;
    let mut local = rule();
    local.as_map_mut()["exceptions_list"][0]["list_id"] =
        fixture(flavor, "exception_create")["response"]["list_id"].clone();
    let error = run(
        &transport(&server),
        &[pair(flavor)],
        &[],
        &[],
        &[local],
        true,
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::NotFound);
    assert!(error.message.contains(&pair(flavor).container.id));
    no_writes(&server).await;
}

#[tokio::test]
async fn items_reconciled_while_a_rule_drops_its_binding_still_check_value_list_sources() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    base(&server, flavor).await;
    mount(
        &server,
        flavor,
        "GET",
        "/api/lists",
        "items_delete_id_absent",
        404,
    )
    .await;
    let mut detached = rule();
    detached.as_map_mut().remove("exceptions_list");
    let result = plan(
        &transport(&server),
        Inputs {
            pairs: &[],
            has_root: false,
            lists: &[list()],
            items: &[item("missing")],
            local: &[detached],
            remote: &[rule()],
            exception_plan: &exceptions(),
        },
        true,
    )
    .await;
    let error = result.unwrap_err();
    assert_eq!(error.kind, ErrorKind::NotFound);
    assert!(error.message.contains("missing"));
    no_writes(&server).await;
}
