use super::support::*;
use elasticctl_api::{state, value_lists as vl};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn mount_removes(
    s: &Stack,
    id: &str,
    page: &str,
    target: &BTreeSet<String>,
    response: &str,
) -> BTreeSet<String> {
    s.route(
        "GET",
        "/api/lists/items/_find",
        &[("list_id", id), ("page", "1"), ("per_page", "1000")],
        &[(page, 200)],
    );
    let ids: BTreeSet<_> = s
        .data(page)
        .iter()
        .filter(|i| !target.contains(&string(i, "value")))
        .map(|i| string(i, "id"))
        .collect();
    for item in &ids {
        s.route(
            "DELETE",
            "/api/lists/items",
            &[("id", item)],
            &[(response, 200)],
        );
    }
    ids
}

fn assert_import(request: &wiremock::Request, id: &str, values: &BTreeSet<String>) {
    assert_eq!(request.method, "POST");
    assert_eq!(request.url.path(), "/api/lists/items/_import");
    assert_eq!(
        request.url.query_pairs().collect::<Vec<_>>(),
        [("list_id".into(), id.into())]
    );
    let content_type = request.headers["content-type"].to_str().unwrap();
    let boundary = content_type
        .strip_prefix("multipart/form-data; boundary=")
        .unwrap();
    let body = String::from_utf8(request.body.clone()).unwrap();
    assert_eq!(
        body,
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{id}.txt\"\r\nContent-Type: text/plain\r\n\r\n{}\r\n--{boundary}--\r\n",
            values.iter().map(|v| format!("{v}\n")).collect::<String>()
        )
    );
}

#[tokio::test]
async fn remove_phases_delete_every_stored_copy_by_id_before_any_exception_write() {
    for flavor in FLAVORS {
        let s = Stack::new(flavor, "state_items_independent", "state_items_empty").await;
        let dir = tempfile::tempdir().unwrap();
        s.pull(dir.path(), false).await.unwrap();
        let mut expected_ids = BTreeSet::new();
        let mut removed_values = Vec::new();
        for (container, before, after, page, response) in [
            (
                "contain_create",
                "contain_export",
                "contain_export_after",
                "items_c_1000",
                "contain_delete_id",
            ),
            (
                "container_read",
                "items_export",
                "items_export_after_delete",
                "items_v_1000",
                "items_delete_id",
            ),
        ] {
            let id = s.id(container, "id");
            let target = s.values(after);
            removed_values.extend(
                s.body(before)
                    .as_str()
                    .unwrap()
                    .lines()
                    .filter(|v| !target.contains(*v))
                    .map(str::to_owned),
            );
            write_values(dir.path(), &id, &target);
            expected_ids.extend(mount_removes(&s, &id, page, &target, response));
        }
        let e = s.id("exception_create", "list_id");
        edit(dir.path(), "exceptions", &e, |list| {
            list["name"] = json!(format!("{}-updated", string(list, "name")))
        });
        s.route(
            "PUT",
            "/api/exception_lists",
            &[],
            &[("exception_create", 200)],
        );
        let plan = s.plan(dir.path(), false).await.unwrap();
        s.exports(
            &s.id("contain_create", "id"),
            &["contain_export", "contain_export_after"],
        );
        s.exports(
            &s.id("container_read", "id"),
            &["items_export", "items_export_after_delete"],
        );
        let changed: Vec<_> = plan
            .value_lists
            .iter()
            .filter(|p| !p.removes.is_empty())
            .map(|p| p.local.container.id.clone())
            .collect();
        let start = s.requests().await.len();
        let applied = state::apply_push(&s.t, plan).await.unwrap();
        assert!(
            applied
                .value_list_outcomes
                .iter()
                .all(|o| o.outcome == vl::Outcome::Applied),
            "{:?}",
            applied.value_list_outcomes
        );
        assert_eq!(applied.summary.value_lists_updated, changed.len());
        assert_eq!(applied.summary.values_removed, removed_values.len());
        let requests = s.requests().await;
        let writes: Vec<_> = requests[start..]
            .iter()
            .filter(|r| r.method != "GET" && r.url.path() != EXPORT)
            .collect();
        let deleted: BTreeSet<_> = writes
            .iter()
            .filter(|r| r.method == "DELETE")
            .map(|r| {
                r.url
                    .query_pairs()
                    .find(|(k, _)| k == "id")
                    .unwrap()
                    .1
                    .into_owned()
            })
            .collect();
        assert_eq!(deleted, expected_ids);
        assert_eq!(
            writes.iter().filter(|r| r.method == "DELETE").count(),
            expected_ids.len()
        );
        let put = writes.last().unwrap();
        assert_eq!(put.method, "PUT");
        assert_eq!(put.url.path(), "/api/exception_lists");
        assert_eq!(put.url.query(), None);
        let mut expected = writable(s.body("exception_create"), false);
        expected["name"] = json!(format!("{}-updated", string(&expected, "name")));
        assert_eq!(put.body_json::<Value>().unwrap(), expected);
        assert!(
            writes[..writes.len() - 1]
                .iter()
                .all(|r| r.method == "DELETE")
        );
        let evidence: Vec<_> = applied
            .report
            .entries
            .iter()
            .filter(|e| e.action == "remove_values")
            .collect();
        assert_eq!(evidence.len(), removed_values.len());
        let mut actual: Vec<_> = evidence
            .iter()
            .flat_map(|e| e.value_list.as_ref().unwrap().values.clone().unwrap())
            .collect();
        actual.sort();
        removed_values.sort();
        assert_eq!(actual, removed_values);
        assert!(
            evidence
                .iter()
                .all(|e| e.applied && e.value_list.as_ref().unwrap().phase_verified)
        );
        let reported_order: Vec<_> =
            evidence
                .iter()
                .map(|e| e.rule_id.clone())
                .fold(Vec::new(), |mut ids, id| {
                    if ids.last() != Some(&id) {
                        ids.push(id);
                    }
                    ids
                });
        assert_eq!(reported_order, changed);
    }
}

#[tokio::test]
async fn replacement_phases_follow_installed_operators_and_never_empty_a_singleton() {
    for flavor in FLAVORS {
        for (items, before, intermediate, page, order) in [
            (
                "state_items_included",
                "contain_export",
                "contain_export_after",
                "items_c_1000",
                vl::PhaseOrder::RemovesFirst,
            ),
            (
                "state_items_excluded",
                "contain_export",
                "export_c_union",
                "items_c_union_1000",
                vl::PhaseOrder::AddsFirst,
            ),
            (
                "state_items_mixed",
                "contain_export",
                "export_c_union",
                "items_c_union_1000",
                vl::PhaseOrder::AddsFirst,
            ),
            (
                "state_items_included",
                "contain_export_single",
                "export_c_union",
                "items_c_union_1000",
                vl::PhaseOrder::AddsFirst,
            ),
        ] {
            let s = Stack::new(flavor, items, "state_items_empty").await;
            let c = s.id("contain_create", "id");
            s.exports(&c, &[before]);
            let dir = tempfile::tempdir().unwrap();
            s.pull(dir.path(), false).await.unwrap();
            let target = s.values("contain_export_imported");
            write_values(dir.path(), &c, &target);
            let plan = s.plan(dir.path(), false).await.unwrap();
            assert_eq!(
                plan.value_lists
                    .iter()
                    .find(|p| p.local.container.id == c)
                    .unwrap()
                    .order,
                order
            );
            s.exports(&c, &[before, intermediate, "contain_export_imported"]);
            let expected_ids = mount_removes(&s, &c, page, &target, "contain_delete_id");
            s.route(
                "POST",
                "/api/lists/items/_import",
                &[("list_id", &c)],
                &[("contain_import", 200)],
            );
            let start = s.requests().await.len();
            let applied = state::apply_push(&s.t, plan).await.unwrap();
            assert!(
                applied
                    .value_list_outcomes
                    .iter()
                    .all(|o| o.outcome == vl::Outcome::Applied)
            );
            let requests = s.requests().await;
            let writes: Vec<_> = requests[start..]
                .iter()
                .filter(|r| r.method != "GET" && r.url.path() != EXPORT)
                .collect();
            assert_eq!(writes.len(), expected_ids.len() + 1);
            assert_eq!(
                writes.first().unwrap().method,
                if order == vl::PhaseOrder::AddsFirst {
                    "POST"
                } else {
                    "DELETE"
                }
            );
            let adds = target.difference(&s.values(before)).cloned().collect();
            assert_import(
                writes
                    .iter()
                    .find(|r| r.url.path() == "/api/lists/items/_import")
                    .unwrap(),
                &c,
                &adds,
            );
            assert_eq!(
                applied.summary.values_added,
                target.difference(&s.values(before)).count()
            );
            assert_eq!(
                applied.summary.values_removed,
                s.values(before).difference(&target).count()
            );
        }
    }
}

#[tokio::test]
async fn retained_dependencies_are_checked_without_writing_drifted_pairs_in_full_and_scoped_pushes()
{
    for flavor in FLAVORS {
        for scoped in [false, true] {
            let s = Stack::new(flavor, "state_items_included", "state_items_coreferenced").await;
            let dir = tempfile::tempdir().unwrap();
            s.pull(dir.path(), false).await.unwrap();
            let (container, items) = if scoped {
                s.rules("state_rules_selected", true);
                ("exception_create", "state_items_included")
            } else {
                ("state_outside_get", "state_items_coreferenced")
            };
            std::fs::remove_file(
                dir.path()
                    .join("exceptions")
                    .join(format!("{}.yaml", s.id(container, "list_id"))),
            )
            .unwrap();
            let c = s.id("contain_create", "id");
            let retained: BTreeSet<_> = s
                .data(items)
                .iter()
                .flat_map(|i| i["entries"].as_array().unwrap())
                .map(|e| string(&e["list"], "id"))
                .filter(|id| scoped || id != &c)
                .collect();
            assert!(!retained.is_empty());
            let mirror = state::read_mirror(dir.path()).unwrap();
            let unreferenced: BTreeSet<_> = mirror
                .value_lists
                .iter()
                .filter(|p| scoped || retained.contains(&p.container.id))
                .map(|p| p.container.id.clone())
                .collect();
            for pair in &mirror.value_lists {
                if unreferenced.contains(&pair.container.id) {
                    let mut drifted = pair.values.clone();
                    drifted.pop_first().unwrap();
                    assert_ne!(drifted, pair.values);
                    write_values(dir.path(), &pair.container.id, &drifted);
                    edit(dir.path(), "value-lists", &pair.container.id, |container| {
                        container["description"] =
                            json!(format!("{}-local-drift", string(container, "description")))
                    });
                }
            }
            if !scoped {
                write_values(dir.path(), &c, &s.values("contain_export_after"));
            }
            let plan = s.plan(dir.path(), scoped).await.unwrap();
            assert_eq!(
                plan.value_list_drift
                    .as_ref()
                    .unwrap()
                    .unreferenced
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>(),
                unreferenced
            );
            assert_eq!(
                plan.value_lists
                    .iter()
                    .filter(|p| retained.contains(&p.local.container.id))
                    .map(|p| p.local.container.id.clone())
                    .collect::<BTreeSet<_>>(),
                retained
            );
            for p in &plan.value_lists {
                if retained.contains(&p.local.container.id) {
                    assert!(p.adds.is_empty() && p.removes.is_empty());
                    assert_eq!(p.container_action, vl::ContainerAction::None);
                    let remote = p.before.as_ref().unwrap();
                    assert_eq!(p.local.values, remote.stored.set());
                    assert_eq!(p.local.container, remote.container.container);
                }
            }
            let expected = if scoped {
                BTreeSet::new()
            } else {
                s.exports(&c, &["contain_export", "contain_export_after"]);
                mount_removes(
                    &s,
                    &c,
                    "items_c_1000",
                    &s.values("contain_export_after"),
                    "contain_delete_id",
                )
            };
            let start = s.requests().await.len();
            let applied = state::apply_push(&s.t, plan).await.unwrap();
            assert_eq!(applied.summary.value_lists_updated, usize::from(!scoped));
            assert!(
                applied
                    .value_list_outcomes
                    .iter()
                    .all(|o| o.outcome == vl::Outcome::Applied)
            );
            assert!(
                applied
                    .report
                    .entries
                    .iter()
                    .all(|e| !unreferenced.contains(&e.rule_id))
            );
            let requests = s.requests().await;
            let writes: Vec<_> = requests[start..]
                .iter()
                .filter(|r| r.method != "GET" && r.url.path() != EXPORT)
                .collect();
            assert_eq!(writes.len(), expected.len());
            assert!(writes.iter().all(|r| r.method == "DELETE"));
            assert_eq!(
                writes
                    .iter()
                    .map(|r| {
                        assert_eq!(r.url.path(), "/api/lists/items");
                        r.url
                            .query_pairs()
                            .find(|(k, _)| k == "id")
                            .unwrap()
                            .1
                            .into_owned()
                    })
                    .collect::<BTreeSet<_>>(),
                expected
            );
            for id in retained {
                assert!(
                    requests[start..]
                        .iter()
                        .any(|r| r.url.path() == "/api/lists"
                            && r.url.query_pairs().any(|(k, v)| k == "id" && v == id))
                );
            }
        }
    }
}

#[tokio::test]
async fn item_page_disagreeing_with_the_last_export_refuses_before_any_delete() {
    for flavor in FLAVORS {
        let s = Stack::new(flavor, "state_items_included", "state_items_empty").await;
        let dir = tempfile::tempdir().unwrap();
        s.pull(dir.path(), false).await.unwrap();
        let c = s.id("contain_create", "id");
        write_values(dir.path(), &c, &s.values("contain_export_after"));
        let plan = s.plan(dir.path(), false).await.unwrap();
        s.route(
            "GET",
            "/api/lists/items/_find",
            &[("list_id", &c), ("page", "1"), ("per_page", "1000")],
            &[("items_c_union_1000", 200)],
        );
        let applied = state::apply_push(&s.t, plan).await.unwrap();
        let outcome = applied
            .value_list_outcomes
            .iter()
            .find(|o| o.id == c)
            .unwrap();
        assert_eq!(outcome.outcome, vl::Outcome::Failed);
        assert_eq!(outcome.error.as_ref().unwrap().kind, "conflict");
        assert!(
            outcome
                .error
                .as_ref()
                .unwrap()
                .message
                .contains("item _find differs from the last export")
        );
        assert_eq!(applied.summary.values_removed, 0);
        assert!(
            outcome
                .evidence
                .iter()
                .all(|e| e.sent == Some(vl::Sent::NotSent))
        );
        s.no_writes().await;
    }
}

#[tokio::test]
async fn empty_referenced_remote_list_can_be_repaired_with_verified_first_values() {
    for flavor in FLAVORS {
        let s = Stack::new(flavor, "state_items_included", "state_items_empty").await;
        let dir = tempfile::tempdir().unwrap();
        s.pull(dir.path(), false).await.unwrap();
        let c = s.id("contain_create", "id");
        s.exports(&c, &["export_empty"]);
        let plan = s.plan(dir.path(), false).await.unwrap();
        s.exports(&c, &["export_empty", "contain_export"]);
        s.route(
            "POST",
            "/api/lists/items/_import",
            &[("list_id", &c)],
            &[("contain_import", 200)],
        );
        let start = s.requests().await.len();
        let applied = state::apply_push(&s.t, plan).await.unwrap();
        assert!(
            applied
                .value_list_outcomes
                .iter()
                .all(|o| o.outcome == vl::Outcome::Applied)
        );
        assert_eq!(
            applied.summary.values_added,
            s.values("contain_export").len()
        );
        let requests = s.requests().await;
        let writes: Vec<_> = requests[start..]
            .iter()
            .filter(|r| r.method != "GET" && r.url.path() != EXPORT)
            .collect();
        assert_eq!(writes.len(), 1);
        assert_import(writes[0], &c, &s.values("contain_export"));
    }
}

#[tokio::test]
async fn first_creation_verifies_values_before_exception_container_item_and_rule_writes() {
    for flavor in FLAVORS {
        let s = Stack::new(flavor, "state_items_repeated_10000", "state_items_empty").await;
        s.rules("state_rules_selected", true);
        let dir = tempfile::tempdir().unwrap();
        s.pull(dir.path(), true).await.unwrap();
        let v = s.id("container_read", "id");
        let e = s.id("exception_create", "list_id");
        s.rules("state_rules_empty", false);
        for ns in ["single", "agnostic"] {
            s.route(
                "GET",
                "/api/exception_lists/_find",
                &[("page", "1"), ("per_page", "10000"), ("namespace_type", ns)],
                &[("exception_lists_find_agnostic", 200)],
            );
        }
        s.route(
            "GET",
            "/api/exception_lists",
            &[("list_id", &e), ("namespace_type", "single")],
            &[("cleanup_exception_absent", 404)],
        );
        s.container(&v, &[("container_missing_v", 404)]);
        let plan = s.plan(dir.path(), false).await.unwrap();
        assert_eq!(plan.value_lists.len(), 1);
        s.container(
            &v,
            &[("container_missing_v", 404), ("container_create", 200)],
        );
        s.route("POST", "/api/lists", &[], &[("container_create", 200)]);
        s.route(
            "POST",
            "/api/lists/items/_import",
            &[("list_id", &v)],
            &[("items_import", 200)],
        );
        s.exports(&v, &["items_export"]);
        s.route(
            "POST",
            "/api/exception_lists",
            &[],
            &[("exception_create", 200)],
        );
        s.route(
            "POST",
            "/api/exception_lists/items",
            &[],
            &[("exception_item_create", 200)],
        );
        s.route("POST", RULES, &[], &[("state_rule_r", 200)]);
        let start = s.requests().await.len();
        let applied = state::apply_push(&s.t, plan).await.unwrap();
        assert_eq!(applied.summary.value_lists_created, 1);
        assert_eq!(applied.summary.values_added, s.values("items_export").len());
        assert_eq!(applied.summary.lists_created, 1);
        assert_eq!(
            applied.summary.items_created,
            s.data("state_items_repeated_10000").len()
        );
        assert_eq!(
            applied.summary.created,
            s.data("state_rules_selected").len()
        );
        let requests = s.requests().await;
        let writes: Vec<_> = requests[start..]
            .iter()
            .filter(|r| r.method != "GET" && r.url.path() != EXPORT)
            .collect();
        let mut expected_paths = vec![
            "/api/lists",
            "/api/lists/items/_import",
            "/api/exception_lists",
        ];
        expected_paths.extend(std::iter::repeat_n(
            "/api/exception_lists/items",
            s.data("state_items_repeated_10000").len(),
        ));
        expected_paths.extend(std::iter::repeat_n(
            RULES,
            s.data("state_rules_selected").len(),
        ));
        assert_eq!(
            writes.iter().map(|r| r.url.path()).collect::<Vec<_>>(),
            expected_paths
        );
        let body = s.body("container_create");
        assert_eq!(
            writes[0].body_json::<Value>().unwrap(),
            json!({"id":body["id"],"name":body["name"],"description":body["description"],"type":body["type"],"meta":body["meta"]})
        );
        assert_import(writes[1], &v, &s.values("items_export"));
        assert_eq!(
            writes[2].body_json::<Value>().unwrap(),
            writable(s.body("exception_create"), false)
        );
        let expected_items: BTreeMap<_, _> = s
            .data("state_items_repeated_10000")
            .into_iter()
            .map(|i| (string(&i, "item_id"), writable(i, true)))
            .collect();
        let sent_items: BTreeMap<_, _> = writes
            .iter()
            .filter(|r| r.url.path() == "/api/exception_lists/items")
            .map(|r| {
                let item = r.body_json::<Value>().unwrap();
                (string(&item, "item_id"), item)
            })
            .collect();
        assert_eq!(sent_items, expected_items);
        let binding = writes.last().unwrap().body_json::<Value>().unwrap();
        let mut expected_rule = s.body("state_rule_r");
        for field in [
            "id",
            "created_at",
            "created_by",
            "updated_at",
            "updated_by",
            "revision",
            "version",
            "execution_summary",
        ] {
            expected_rule.as_object_mut().unwrap().remove(field);
        }
        assert_eq!(binding, expected_rule);
        assert!(
            binding["exceptions_list"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["id"] == s.body("exception_create")["id"])
        );
        let first_exception = requests[start..]
            .iter()
            .position(|r| r.method == "POST" && r.url.path() == "/api/exception_lists")
            .unwrap();
        assert!(
            requests[start..start + first_exception]
                .iter()
                .any(|r| r.url.path() == EXPORT)
        );
        let actions: Vec<_> = applied
            .report
            .entries
            .iter()
            .map(|e| e.action.as_str())
            .collect();
        let mut expected_actions = vec!["create_value_list", "add_values", "create_list"];
        expected_actions.extend(std::iter::repeat_n("create_item", expected_items.len()));
        expected_actions.extend(std::iter::repeat_n(
            "create",
            s.data("state_rules_selected").len(),
        ));
        assert_eq!(actions, expected_actions);
    }
}

async fn stop_after_list_fault(flavor: &str, status: u16) {
    let s = Stack::new(flavor, "state_items_independent", "state_items_empty").await;
    let dir = tempfile::tempdir().unwrap();
    s.pull(dir.path(), false).await.unwrap();
    let mut lists: Vec<_> = ["contain_create", "container_read", "spellings_create"]
        .into_iter()
        .map(|container| (s.id(container, "id"), container))
        .collect();
    lists.sort_by(|a, b| a.0.cmp(&b.0));
    let (first, first_container) = &lists[0];
    let (middle_id, middle_container) = &lists[1];
    let (last, _) = &lists[2];
    let first_values = s.values("contain_export_after");
    assert!(!first_values.is_empty());
    s.exports(first, &["export_empty"]);
    write_values(dir.path(), first, &first_values);
    edit(dir.path(), "value-lists", middle_id, |container| {
        container["description"] = json!("synthetic change refused")
    });
    edit(dir.path(), "value-lists", last, |container| {
        container["description"] = json!("synthetic change not reached")
    });
    edit(
        dir.path(),
        "exceptions",
        &s.id("exception_create", "list_id"),
        |list| list["name"] = json!("synthetic change not reached"),
    );
    edit(
        dir.path(),
        "rules",
        &s.id("state_rule_r", "rule_id"),
        |rule| rule["description"] = json!("synthetic change not reached"),
    );
    let plan = s.plan(dir.path(), false).await.unwrap();
    assert_eq!(
        plan.value_lists
            .iter()
            .map(|p| p.local.container.id.clone())
            .collect::<Vec<_>>(),
        lists.iter().map(|r| r.0.clone()).collect::<Vec<_>>()
    );
    let first_plan = plan
        .value_lists
        .iter()
        .find(|p| p.local.container.id == *first)
        .unwrap();
    assert_eq!(first_plan.adds, first_values);
    assert!(first_plan.removes.is_empty());
    s.exports(first, &["export_empty", "contain_export_after"]);
    s.route(
        "POST",
        "/api/lists/items/_import",
        &[("list_id", first)],
        &[(first_container, 200)],
    );
    s.route(
        "PATCH",
        "/api/lists",
        &[],
        &[("container_patch_stale", status)],
    );
    let start = s.requests().await.len();
    let applied = state::apply_push(&s.t, plan).await.unwrap();
    let middle = if status == 503 {
        vl::Outcome::Unknown
    } else {
        vl::Outcome::Failed
    };
    assert_eq!(
        applied
            .value_list_outcomes
            .iter()
            .map(|o| o.outcome)
            .collect::<Vec<_>>(),
        [vl::Outcome::Applied, middle, vl::Outcome::NotReached]
    );
    assert_eq!(applied.summary.value_lists_updated, 1);
    assert_eq!(applied.summary.values_added, first_values.len());
    assert_eq!(
        applied.summary.value_lists_unknown,
        usize::from(status == 503)
    );
    assert_eq!(applied.summary.value_lists_not_reached, 1);
    assert_eq!(applied.summary.values_removed, 0);
    let report = serde_json::to_value(&applied.report).unwrap();
    let entries = report["entries"].as_array().unwrap();
    let successful: Vec<_> = entries.iter().filter(|e| e["rule_id"] == *first).collect();
    assert_eq!(successful.len(), 1);
    assert_eq!(successful[0]["action"], "add_values");
    assert_eq!(successful[0]["values"], json!(first_values));
    assert_eq!(successful[0]["sent"], "accepted");
    assert_eq!(successful[0]["phase_verified"], true);
    assert_eq!(successful[0]["outcome"], "applied");
    assert_eq!(entries.first().unwrap(), successful[0]);
    let failed = entries
        .iter()
        .find(|e| e["action"] == "update_value_list")
        .unwrap();
    assert_eq!(
        failed["sent"],
        if status == 503 {
            "uncertain"
        } else {
            "refused"
        }
    );
    assert_eq!(
        failed["outcome"],
        if status == 503 { "unknown" } else { "failed" }
    );
    assert!(!failed["phase_verified"].as_bool().unwrap());
    let later = entries
        .iter()
        .find(|e| e["action"] == "not_reached")
        .unwrap();
    assert_eq!(later["rule_id"], *last);
    if status == 503 {
        let read = entries.iter().find(|e| e["action"] == "read_back").unwrap();
        assert_eq!(read["of"], "container");
        assert_eq!(read["observed"], true);
        assert_eq!(read["mismatched"], json!(["description"]));
    }
    let requests = s.requests().await;
    let writes: Vec<_> = requests[start..]
        .iter()
        .filter(|r| r.method != "GET" && r.url.path() != EXPORT)
        .collect();
    assert_eq!(writes.len(), 2);
    assert_import(writes[0], first, &first_values);
    assert_eq!(writes[1].method, "PATCH");
    assert_eq!(writes.iter().filter(|r| r.method == "PATCH").count(), 1);
    assert!(
        writes
            .iter()
            .all(|r| r.url.path().starts_with("/api/lists"))
    );
    let patch = writes
        .iter()
        .find(|r| r.method == "PATCH")
        .unwrap()
        .body_json::<Value>()
        .unwrap();
    let before = s.body(middle_container);
    assert_eq!(
        patch,
        json!({"id":before["id"],"name":before["name"],"description":"synthetic change refused","meta":before["meta"],"_version":before["_version"]})
    );
}

#[tokio::test]
async fn failed_list_stops_later_lists_exceptions_and_rules_with_a_complete_report() {
    for flavor in FLAVORS {
        stop_after_list_fault(flavor, 409).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn injected_5xx_patch_with_nonmatching_readback_is_unknown_and_stops_later_writes() {
    let mut tasks = tokio::task::JoinSet::new();
    for flavor in FLAVORS {
        tasks.spawn(async move {
            stop_after_list_fault(flavor, 503).await;
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
}
