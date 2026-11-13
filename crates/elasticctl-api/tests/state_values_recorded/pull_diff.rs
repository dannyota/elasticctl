use super::support::*;
use elasticctl_api::{state, value_lists as vl};
use elasticctl_core::ErrorKind;
use serde_json::json;
use std::collections::BTreeSet;

#[tokio::test]
async fn full_and_scoped_pull_follow_graph_closure_and_preserve_recorded_spellings() {
    for flavor in FLAVORS {
        for scoped in [false, true] {
            let s = Stack::new(flavor, "state_items_included", "state_items_coreferenced").await;
            if scoped {
                s.rules("state_rules_selected", true);
            }
            let dir = tempfile::tempdir().unwrap();
            let report = s.pull(dir.path(), scoped).await.unwrap();
            let rules = s.data(if scoped {
                "state_rules_selected"
            } else {
                "state_rules_full"
            });
            let containers: BTreeSet<_> = rules
                .iter()
                .flat_map(|r| r["exceptions_list"].as_array().unwrap())
                .map(|r| string(r, "list_id"))
                .collect();
            let items: Vec<_> = ["state_items_included", "state_items_coreferenced"]
                .into_iter()
                .flat_map(|op| s.data(op))
                .filter(|i| containers.contains(&string(i, "list_id")))
                .collect();
            let selected: BTreeSet<_> = items
                .iter()
                .flat_map(|i| i["entries"].as_array().unwrap())
                .map(|e| string(&e["list"], "id"))
                .collect();
            assert_eq!(report.pulled, rules.len());
            assert_eq!(report.exception_lists, containers.len());
            assert_eq!(report.exception_items, items.len());
            assert_eq!(report.value_lists, selected.len());
            let mirror = state::read_mirror(dir.path()).unwrap();
            assert_eq!(
                mirror
                    .rules
                    .iter()
                    .map(|r| r.rule_id().unwrap().to_owned())
                    .collect::<BTreeSet<_>>(),
                rules.iter().map(|r| string(r, "rule_id")).collect()
            );
            assert_eq!(
                mirror
                    .value_lists
                    .iter()
                    .map(|p| p.container.id.clone())
                    .collect::<BTreeSet<_>>(),
                selected
            );
            for (container, export) in [
                ("contain_create", "contain_export"),
                ("spellings_create", "export_s_two_spellings"),
                ("container_p_ip", "export_p_spellings"),
            ] {
                let id = s.id(container, "id");
                if selected.contains(&id) {
                    let pair = mirror
                        .value_lists
                        .iter()
                        .find(|p| p.container.id == id)
                        .unwrap();
                    assert_eq!(pair.values, s.values(export));
                    assert_eq!(
                        std::fs::read_to_string(value_path(dir.path(), &id)).unwrap(),
                        s.values(export)
                            .iter()
                            .map(|v| format!("{v}\n"))
                            .collect::<String>()
                    );
                    assert_eq!(
                        serde_json::to_value(&pair.container).unwrap()["type"],
                        s.body(container)["type"]
                    );
                    assert!(
                        vl::validate_path(&value_path(dir.path(), &id))
                            .unwrap()
                            .valid
                    );
                }
            }
            let requests = s.requests().await;
            assert_eq!(
                requests.iter().filter(|r| r.url.path() == EXPORT).count(),
                selected.len()
            );
            for id in &selected {
                assert_eq!(
                    requests
                        .iter()
                        .filter(|r| r.url.path() == EXPORT
                            && r.url.query_pairs().any(|(k, v)| k == "list_id" && v == *id))
                        .count(),
                    1
                );
            }
            s.no_writes().await;
            let diff = s.diff(dir.path(), scoped).await;
            assert!(diff.clean, "{diff:?}");
            assert_eq!(
                diff.value_lists.as_ref().unwrap().changes.len(),
                selected.len()
            );
            let plan = s.plan(dir.path(), scoped).await.unwrap();
            assert!(
                plan.value_lists
                    .iter()
                    .all(|p| p.adds.is_empty() && p.removes.is_empty())
            );
            let applied = state::apply_push(&s.t, plan).await.unwrap();
            assert!(
                applied
                    .value_list_outcomes
                    .iter()
                    .all(|o| o.outcome == vl::Outcome::Applied)
            );
            assert!(applied.report.entries.is_empty());
            s.no_writes().await;
        }
    }
}

#[tokio::test]
async fn doctor_uses_recorded_bootstrap_states_and_the_exact_initialization_message() {
    use elasticctl_api::health::{self, Status};
    for flavor in FLAVORS {
        for (index, status, expected_status, message) in [
            (
                "index_before",
                404,
                Status::Warn,
                "value-list data streams are not bootstrapped; an exception entry of type 'list' cannot work until elasticctl value-lists init runs POST /api/security_solution/initialize with the create-list-indices flow",
            ),
            (
                "index_after",
                200,
                Status::Ok,
                "value-list data streams are bootstrapped",
            ),
        ] {
            let s = Stack::new(flavor, "state_items_empty", "state_items_empty").await;
            s.route(
                "GET",
                "/_security/_authenticate",
                &[],
                &[("authenticate", 200)],
            );
            s.route(
                "GET",
                &format!("{RULES}/_find"),
                &[("page", "1"), ("per_page", "1")],
                &[("rules_find", 200)],
            );
            s.route("GET", "/api/lists/index", &[], &[(index, status)]);
            let report = health::doctor(&s.t).await.unwrap();
            let check = report
                .checks
                .iter()
                .find(|c| c.name == "value_list_index")
                .unwrap();
            assert_eq!(check.status, expected_status);
            assert_eq!(check.detail, message);
            assert!(report.ok);
            assert_eq!(
                s.requests()
                    .await
                    .iter()
                    .filter(|r| r.url.path() == "/api/lists/index")
                    .count(),
                1
            );
            s.no_writes().await;
        }
    }
}

#[tokio::test]
async fn pull_d23_aggregates_missing_wrong_type_and_unsupported_lists_without_changing_mirror() {
    for flavor in FLAVORS {
        for missing in [true, false] {
            let s = Stack::new(flavor, "state_items_included", "state_items_coreferenced").await;
            let dir = tempfile::tempdir().unwrap();
            s.pull(dir.path(), false).await.unwrap();
            let c = s.id("contain_create", "id");
            edit(
                dir.path(),
                "rules",
                &s.id("state_rule_r", "rule_id"),
                |rule| rule["description"] = json!("local rule preserved after refusal"),
            );
            edit(
                dir.path(),
                "exceptions",
                &s.id("exception_create", "list_id"),
                |list| list["description"] = json!("local exception preserved after refusal"),
            );
            write_values(dir.path(), &c, &s.values("contain_export_after"));
            let before = snapshot(dir.path());
            let spelling = s.id("spellings_create", "id");
            s.container(
                &c,
                &[(
                    if missing {
                        "container_missing_c"
                    } else {
                        "container_c_keyword"
                    },
                    if missing { 404 } else { 200 },
                )],
            );
            s.container(&spelling, &[("container_s_unsupported", 200)]);
            let start = s.requests().await.len();
            let error = s.pull(dir.path(), false).await.unwrap_err();
            assert_eq!(error.kind, ErrorKind::Conflict);
            for id in [&c, &spelling] {
                assert!(error.message.contains(id), "{error}");
                for item in ["state_items_included", "state_items_coreferenced"]
                    .into_iter()
                    .flat_map(|op| s.data(op))
                    .filter(|i| {
                        i["entries"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|e| e["list"]["id"] == *id)
                    })
                {
                    assert!(error.message.contains(&string(&item, "item_id")), "{error}");
                }
            }
            assert!(error.message.contains(if missing {
                "missing"
            } else {
                "differs from entry type"
            }));
            assert!(error.message.contains("unsupported type"));
            assert!(error.message.contains("fix the stack or narrow the pull"));
            assert_eq!(snapshot(dir.path()), before);
            assert!(
                s.requests().await[start..]
                    .iter()
                    .all(|r| r.method == "GET")
            );
        }
    }
}

#[tokio::test]
async fn diff_reports_only_value_drift_and_unreferenced_pairs_without_rule_or_exception_drift() {
    for flavor in FLAVORS {
        let s = Stack::new(flavor, "state_items_included", "state_items_coreferenced").await;
        let dir = tempfile::tempdir().unwrap();
        s.pull(dir.path(), false).await.unwrap();
        let c = s.id("contain_create", "id");
        write_values(dir.path(), &c, &s.values("contain_export_imported"));
        let mut unreferenced = BTreeSet::new();
        for operation in ["container_read", "state_container_t"] {
            let id = s.id(operation, "id");
            let body = s.body(operation);
            let container = json!({"id":body["id"],"type":body["type"],"name":body["name"],"description":body["description"],"meta":body["meta"]});
            std::fs::write(
                dir.path().join("value-lists").join(format!("{id}.yaml")),
                serde_yaml_ng::to_string(&container).unwrap(),
            )
            .unwrap();
            write_values(
                dir.path(),
                &id,
                &if operation == "container_read" {
                    s.values("items_export")
                } else {
                    [string(&body, "name")].into_iter().collect()
                },
            );
            unreferenced.insert(id);
        }
        let diff = s.diff(dir.path(), false).await;
        assert!(!diff.clean);
        assert!(diff.exceptions.is_clean());
        assert!(
            diff.changes
                .iter()
                .all(|c| matches!(c, elasticctl_api::diff::Change::Unchanged { .. }))
        );
        let block = diff.value_lists.as_ref().unwrap();
        assert_eq!(
            block.unreferenced.iter().cloned().collect::<BTreeSet<_>>(),
            unreferenced
        );
        assert!(block.refused.is_empty());
        let change = block.changes.iter().find(|change| change.id == c).unwrap();
        assert_eq!(change.change, "changed");
        assert!(change.fields.is_empty());
        assert_eq!(
            change.adds,
            s.values("contain_export_imported")
                .difference(&s.values("contain_export"))
                .cloned()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            change.removes,
            s.values("contain_export")
                .difference(&s.values("contain_export_imported"))
                .cloned()
                .collect::<Vec<_>>()
        );
        assert!(serde_json::to_value(&diff).unwrap()["value_lists"].is_object());
        write_values(dir.path(), &c, &s.values("contain_export"));
        assert!(s.diff(dir.path(), false).await.clean);
        s.rules("state_rules_selected", true);
        let scoped = s.diff(dir.path(), true).await;
        assert!(scoped.clean);
        let expected: BTreeSet<_> = state::read_mirror(dir.path())
            .unwrap()
            .value_lists
            .iter()
            .map(|p| p.container.id.clone())
            .filter(|id| id != &c)
            .collect();
        assert_eq!(
            scoped
                .value_lists
                .unwrap()
                .unreferenced
                .into_iter()
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert!(s.requests().await.iter().all(|r| {
            r.url.path() != "/api/lists"
                || !r
                    .url
                    .query_pairs()
                    .any(|(k, v)| k == "id" && unreferenced.contains(v.as_ref()))
        }));
        s.no_writes().await;
    }
}

#[tokio::test]
async fn diff_distinguishes_local_only_remote_only_and_container_fields_and_keeps_legacy_shape() {
    for flavor in FLAVORS {
        let s = Stack::new(flavor, "state_items_independent", "state_items_empty").await;
        let dir = tempfile::tempdir().unwrap();
        s.pull(dir.path(), false).await.unwrap();
        let c = s.id("contain_create", "id");
        let v = s.id("container_read", "id");
        let spelling = s.id("spellings_create", "id");
        s.container(&v, &[("container_missing_v", 404)]);
        std::fs::remove_file(value_path(dir.path(), &spelling)).unwrap();
        std::fs::remove_file(value_path(dir.path(), &spelling).with_extension("yaml")).unwrap();
        let description = s.body("container_patch")["name"].clone();
        edit(dir.path(), "value-lists", &c, |container| {
            container["description"] = description.clone()
        });
        let diff = s.diff(dir.path(), false).await;
        assert!(!diff.clean);
        assert!(diff.exceptions.is_clean());
        let block = diff.value_lists.unwrap();
        for (id, expected) in [
            (&v, "local_only"),
            (&spelling, "remote_only"),
            (&c, "changed"),
        ] {
            assert_eq!(
                block
                    .changes
                    .iter()
                    .find(|change| change.id == *id)
                    .unwrap()
                    .change,
                expected
            );
        }
        let change = block.changes.iter().find(|change| change.id == c).unwrap();
        assert_eq!(change.fields.len(), 1);
        assert_eq!(change.fields[0].field, "description");
        assert_eq!(
            change.fields[0].before,
            s.body("contain_create")["description"]
        );
        assert_eq!(change.fields[0].after, description);
        assert!(change.adds.is_empty() && change.removes.is_empty());
        assert!(
            block
                .refused
                .iter()
                .any(|refusal| refusal.id == v && refusal.kind == "unsupported")
        );
        s.container(&v, &[("container_read", 200)]);
        std::fs::remove_dir_all(dir.path().join("value-lists")).unwrap();
        let legacy = s.diff(dir.path(), false).await;
        assert!(legacy.clean, "{legacy:?}");
        assert!(legacy.value_lists.is_none());
        assert!(
            serde_json::to_value(legacy)
                .unwrap()
                .get("value_lists")
                .is_none()
        );
        s.no_writes().await;
    }
}
