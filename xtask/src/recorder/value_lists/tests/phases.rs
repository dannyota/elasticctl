use super::*;

#[tokio::test]
async fn failure_at_every_new_phase_cleans_exact_ids_in_dependency_order() {
    for (phase, verb, route, key, value, occurrence) in [
        ("missing_v", "GET", "/api/lists", "id", LIST, 1),
        (
            "export_empty",
            "POST",
            "/api/lists/items/_export",
            "list_id",
            CONTAIN,
            1,
        ),
        (
            "repeated",
            "GET",
            "/api/exception_lists/items/_find",
            "per_page",
            "10000",
            1,
        ),
        ("restore_v", "POST", "/api/lists", "id", LIST, 2),
        (
            "spelling_pair",
            "POST",
            "/api/lists/items",
            "id",
            "elasticctl-live-vl-spellings-item-lowercase",
            1,
        ),
        ("ip_create", "POST", "/api/lists", "id", IP, 1),
        (
            "ip_values",
            "POST",
            "/api/lists/items",
            "id",
            "elasticctl-live-vl-ip-item-lower",
            1,
        ),
        (
            "outside_create",
            "POST",
            "/api/exception_lists",
            "list_id",
            OUTSIDE,
            1,
        ),
        (
            "included",
            "POST",
            "/api/exception_lists/items",
            "item_id",
            "elasticctl-live-vl-included",
            1,
        ),
        (
            "coreferenced",
            "POST",
            "/api/exception_lists/items",
            "item_id",
            "elasticctl-live-vl-coreferenced",
            1,
        ),
        (
            "rule_r",
            "POST",
            "/api/detection_engine/rules",
            "rule_id",
            RULE,
            1,
        ),
        (
            "rule_q",
            "POST",
            "/api/detection_engine/rules",
            "rule_id",
            OTHER_RULE,
            1,
        ),
        (
            "rules_full",
            "GET",
            "/api/detection_engine/rules/_find",
            "per_page",
            "10000",
            1,
        ),
        (
            "scan_single",
            "GET",
            "/api/exception_lists/_find",
            "namespace_type",
            "single",
            3,
        ),
        (
            "scan_agnostic",
            "GET",
            "/api/exception_lists/_find",
            "namespace_type",
            "agnostic",
            3,
        ),
        (
            "excluded",
            "POST",
            "/api/exception_lists/items",
            "item_id",
            "elasticctl-live-vl-excluded",
            1,
        ),
        (
            "union",
            "POST",
            "/api/lists/items",
            "id",
            "elasticctl-live-vl-contain-item-union",
            1,
        ),
        (
            "mixed",
            "POST",
            "/api/exception_lists/items",
            "item_id",
            "elasticctl-live-vl-mixed-included",
            1,
        ),
        (
            "independent",
            "POST",
            "/api/exception_lists/items",
            "item_id",
            "elasticctl-live-vl-independent-s",
            1,
        ),
        ("dash_create", "POST", "/api/lists", "id", DASH, 1),
        (
            "dash_import",
            "POST",
            "/api/lists/items/_import",
            "list_id",
            DASH,
            1,
        ),
        (
            "dash_200",
            "POST",
            "/api/lists/items/_export",
            "list_id",
            DASH,
            1,
        ),
        (
            "dash_201",
            "POST",
            "/api/lists/items",
            "id",
            "elasticctl-live-vl-dash-item-last",
            1,
        ),
        ("keyword_swap", "POST", "/api/lists", "id", CONTAIN, 2),
        ("long_swap", "POST", "/api/lists", "id", RANGES, 2),
        ("text_create", "POST", "/api/lists", "id", TEXT, 1),
        (
            "cli_lists",
            "GET",
            "/api/lists/_find",
            "per_page",
            "1000",
            1,
        ),
        (
            "cleanup_nonempty",
            "GET",
            "/api/lists/_find",
            "filter",
            "name:elasticctl-live-vl-*",
            4,
        ),
        (
            "cleanup_empty",
            "GET",
            "/api/lists/_find",
            "filter",
            "name:elasticctl-live-vl-*",
            5,
        ),
        (
            "cleanup_audit",
            "GET",
            "/.items-default/_search",
            "size",
            "100",
            3,
        ),
    ] {
        let (server, state) = stack(Stack::default()).await;
        let matched = Arc::new(Mutex::new(0));
        let counter = matched.clone();
        let fake = state.clone();
        Mock::given(method(verb))
            .and(path(route))
            .and(move |r: &Request| {
                let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap_or_default();
                r.url.query_pairs().any(|(k, v)| k == key && v == value) || body[key] == value
            })
            .respond_with(move |r: &Request| {
                let mut n = counter.lock().unwrap();
                *n += 1;
                let result = fake.lock().unwrap().answer(r);
                if *n == occurrence {
                    response(
                        if verb == "GET" || route.ends_with("/_export") {
                            400
                        } else {
                            503
                        },
                        json!({"message":"private-body"}),
                    )
                } else {
                    result
                }
            })
            .with_priority(1)
            .mount(&server)
            .await;
        let t = transport(&server);
        let mut session = Session::new(
            &t,
            Timing {
                budget: Duration::from_secs(1),
                ..fast()
            },
        );
        let result = run(
            &mut session,
            Some("traditional".into()),
            std::future::pending::<()>,
        )
        .await;
        assert!(
            *matched.lock().unwrap() >= occurrence,
            "{phase}: failure not reached"
        );
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{phase}: unexpectedly succeeded"));
        assert!(
            !error.message.contains("value-list endpoint failed"),
            "{phase}: {}",
            error.message
        );
        assert!(
            !error.message.contains("private-body"),
            "{phase}: leaked body"
        );
        {
            let state = state.lock().unwrap();
            assert!(
                state.rules.is_empty()
                    && state.containers.is_empty()
                    && state.exception_items.is_empty()
                    && state.lists.is_empty()
                    && state.exception.is_none()
                    && state.item.is_none(),
                "{phase}: {}",
                error.message
            );
            assert!(!state.bootstrapped, "{phase}: {}", error.message);
        }
        let requests = server.received_requests().await.unwrap();
        let mut paths = std::collections::BTreeSet::new();
        for r in requests.iter().filter(|r| r.method == "DELETE") {
            assert!(!r.url.query_pairs().any(|(k, _)| k == "value"), "{phase}");
            let target = format!("{}?{}", r.url.path(), r.url.query().unwrap_or(""));
            if r.url.path() != "/api/lists/items" && r.url.path() != "/api/lists" {
                assert!(paths.insert(target), "{phase}: replayed delete");
            }
            assert!(
                r.url.path() == "/api/lists/index"
                    || r.url.query_pairs().any(|(k, v)| matches!(
                        k.as_ref(),
                        "id" | "rule_id" | "list_id" | "item_id"
                    ) && (v.starts_with(PREFIX)
                        || v == "server-import-3")),
                "{phase}"
            );
        }
        if let Some(last_rule) = requests
            .iter()
            .rposition(|r| r.method == "DELETE" && r.url.path() == "/api/detection_engine/rules")
        {
            let cleanup_containers = requests
                .iter()
                .enumerate()
                .filter(|(_, r)| r.method == "DELETE" && r.url.path() == "/api/exception_lists");
            assert!(
                cleanup_containers.into_iter().all(|(i, _)| i > last_rule),
                "{phase}: deleted container before rule"
            );
        }
    }
}
