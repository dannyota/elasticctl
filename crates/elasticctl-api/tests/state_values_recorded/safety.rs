use super::support::*;
use elasticctl_api::state;
use elasticctl_core::ErrorKind;
use serde_json::{Value, json};

#[tokio::test]
async fn unchanged_retained_and_stack_only_references_refuse_d4_d12_and_empty_remote_sources() {
    for flavor in FLAVORS {
        for source in ["unchanged", "retained", "stack_only", "legacy"] {
            for fault in ["missing", "wrong_type", "empty", "dash"] {
                let s = Stack::new(flavor, "state_items_included", "state_items_empty").await;
                let dir = tempfile::tempdir().unwrap();
                s.pull(dir.path(), false).await.unwrap();
                let c = s.id("contain_create", "id");
                if source == "retained" {
                    std::fs::remove_file(
                        dir.path()
                            .join("exceptions")
                            .join(format!("{}.yaml", s.id("exception_create", "list_id"))),
                    )
                    .unwrap();
                }
                if source != "unchanged" || fault == "missing" || fault == "wrong_type" {
                    std::fs::remove_file(value_path(dir.path(), &c)).unwrap();
                    std::fs::remove_file(value_path(dir.path(), &c).with_extension("yaml"))
                        .unwrap();
                }
                if source == "legacy" {
                    std::fs::remove_dir_all(dir.path().join("value-lists")).unwrap();
                }
                let (kind, text) = match fault {
                    "missing" => {
                        s.container(&c, &[("container_missing_c", 404)]);
                        (ErrorKind::NotFound, "no local or stack source")
                    }
                    "wrong_type" => {
                        s.container(&c, &[("container_c_keyword", 200)]);
                        (ErrorKind::Conflict, "source type keyword")
                    }
                    "empty" => {
                        s.exports(&c, &["export_empty"]);
                        if source == "unchanged" {
                            write_values(dir.path(), &c, &s.values("export_empty"));
                        }
                        (ErrorKind::Unsupported, "empty")
                    }
                    "dash" => {
                        s.exports(&c, &["export_dash_201"]);
                        if source == "unchanged" {
                            write_values(dir.path(), &c, &s.values("export_dash_201"));
                        }
                        (ErrorKind::Unsupported, "200")
                    }
                    _ => unreachable!(),
                };
                let error = s.plan(dir.path(), false).await.unwrap_err();
                assert_eq!(error.kind, kind, "{flavor} {source} {fault}: {error}");
                if matches!(fault, "missing" | "wrong_type") {
                    assert!(error.message.contains(&c), "{error}");
                }
                assert!(error.message.contains(text), "{error}");
                let diff = s.diff(dir.path(), false).await;
                assert!(!diff.clean);
                assert!(diff.value_lists.unwrap().refused.iter().any(|i| i.id == c));
                s.no_writes().await;
            }
        }
    }
}

#[tokio::test]
async fn first_creation_refuses_a_rule_detaching_from_the_container_receiving_first_references() {
    for flavor in FLAVORS {
        let s = Stack::new(flavor, "state_items_repeated_10000", "state_items_empty").await;
        let dir = tempfile::tempdir().unwrap();
        s.pull(dir.path(), false).await.unwrap();
        s.items("single", &["state_items_empty"]);
        let v = s.id("container_read", "id");
        s.container(&v, &[("container_missing_v", 404)]);
        let e = s.id("exception_create", "list_id");
        edit(
            dir.path(),
            "rules",
            &s.id("state_rule_r", "rule_id"),
            |rule| {
                rule["exceptions_list"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|r| r["list_id"] != e)
            },
        );
        let error = s.plan(dir.path(), false).await.unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        assert!(error.message.contains(&v));
        assert!(error.message.contains("binding"));
        s.no_writes().await;
    }
}

#[tokio::test]
async fn injected_scan_read_and_decode_faults_refuse_state_planning_without_writes() {
    for flavor in FLAVORS {
        for decode in [false, true] {
            let s = Stack::new(flavor, "state_items_included", "state_items_coreferenced").await;
            let dir = tempfile::tempdir().unwrap();
            s.pull(dir.path(), false).await.unwrap();
            s.rules("state_rules_selected", true);
            let start = s.requests().await.len();
            if decode {
                s.items("agnostic", &["export_p_spellings"]);
            } else {
                let o = s.id("state_outside_get", "list_id");
                s.route(
                    "GET",
                    "/api/exception_lists",
                    &[("list_id", &o), ("namespace_type", "agnostic")],
                    &[("state_outside_get", 503)],
                );
            }
            assert!(s.plan(dir.path(), true).await.is_err());
            assert!(s.requests().await[start..].iter().any(|r| {
                r.url.path() == "/api/exception_lists/_find"
                    && r.url
                        .query_pairs()
                        .any(|(k, v)| k == "namespace_type" && v == "agnostic")
            }));
            s.no_writes().await;
        }
    }
}

#[tokio::test]
async fn installed_reference_drift_between_plan_and_apply_stops_before_all_writes() {
    for flavor in FLAVORS {
        let s = Stack::new(flavor, "state_items_included", "state_items_empty").await;
        let dir = tempfile::tempdir().unwrap();
        s.pull(dir.path(), false).await.unwrap();
        let c = s.id("contain_create", "id");
        write_values(dir.path(), &c, &s.values("contain_export_after"));
        let plan = s.plan(dir.path(), false).await.unwrap();
        s.items("single", &["state_items_excluded"]);
        let applied = state::apply_push(&s.t, plan).await.unwrap();
        let failed = applied
            .value_list_outcomes
            .iter()
            .find(|o| o.id == c)
            .unwrap();
        assert_eq!(failed.outcome, elasticctl_api::value_lists::Outcome::Failed);
        assert_eq!(failed.error.as_ref().unwrap().kind, "conflict");
        assert!(
            failed
                .error
                .as_ref()
                .unwrap()
                .message
                .contains("references changed since preview")
        );
        s.no_writes().await;
    }
}

#[tokio::test]
async fn dash_projection_counts_stored_duplicates_and_allows_a_repair_below_the_limit() {
    for flavor in FLAVORS {
        let s = Stack::new(flavor, "state_items_included", "state_items_empty").await;
        let dir = tempfile::tempdir().unwrap();
        s.pull(dir.path(), false).await.unwrap();
        let c = s.id("contain_create", "id");
        s.exports(&c, &["export_dash_200"]);
        let stored: Vec<_> = s
            .body("export_dash_200")
            .as_str()
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        let mut desired = s.values("export_dash_200");
        write_values(dir.path(), &c, &desired);
        assert!(
            s.plan(dir.path(), false)
                .await
                .unwrap()
                .value_lists
                .iter()
                .all(|p| p.adds.is_empty() && p.removes.is_empty())
        );
        let single = desired
            .iter()
            .find(|v| stored.iter().filter(|copy| *copy == *v).count() == 1)
            .unwrap()
            .clone();
        desired.remove(&single);
        let next = s
            .values("export_dash_201")
            .difference(&s.values("export_dash_200"))
            .next()
            .unwrap()
            .clone();
        let address = next.split('-').next().unwrap();
        let mut octets: Vec<u8> = address.split('.').map(|v| v.parse().unwrap()).collect();
        *octets.last_mut().unwrap() += 1;
        let second = octets
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(".");
        desired.insert(next);
        desired.insert(format!("{second}-{second}"));
        write_values(dir.path(), &c, &desired);
        let error = s.plan(dir.path(), false).await.unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unsupported);
        assert!(
            error.message.contains(&(stored.len() + 1).to_string()),
            "{error}"
        );
        s.exports(&c, &["export_dash_201"]);
        write_values(dir.path(), &c, &s.values("export_dash_200"));
        let repair = s.plan(dir.path(), false).await.unwrap();
        assert!(
            repair
                .value_lists
                .iter()
                .any(|p| p.local.container.id == c && !p.removes.is_empty())
        );
        s.no_writes().await;
    }
}

fn reference_name(item: &Value, entry: &Value) -> String {
    let operator = match entry["operator"].as_str().unwrap() {
        "included" => "Included",
        "excluded" => "Excluded",
        _ => unreachable!(),
    };
    format!(
        "{} ({}) item {} field {} {operator}",
        string(item, "list_id"),
        string(item, "namespace_type"),
        string(item, "item_id"),
        string(entry, "field")
    )
}

#[tokio::test]
async fn d4_refuses_an_entry_type_change_before_dependency_cone_validation() {
    for flavor in FLAVORS {
        let s = Stack::new(flavor, "state_items_mixed", "state_items_coreferenced").await;
        let dir = tempfile::tempdir().unwrap();
        s.pull(dir.path(), false).await.unwrap();
        let c = s.id("contain_create", "id");
        write_values(dir.path(), &c, &s.values("contain_export_after"));
        let wrong_type = s.body("container_c_keyword")["type"].clone();
        let item = s
            .data("state_items_mixed")
            .into_iter()
            .find(|i| {
                i["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e["list"]["id"] == c && e["operator"] == "included")
            })
            .unwrap();
        let entry = item["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["list"]["id"] == c && e["operator"] == "included")
            .unwrap();
        edit(
            dir.path(),
            "exceptions",
            &s.id("exception_create", "list_id"),
            |list| {
                let changed = list["items"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|i| i["item_id"] == item["item_id"])
                    .unwrap();
                let entry = changed["entries"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|e| e["list"]["id"] == c && e["operator"] == "included")
                    .unwrap();
                entry["list"]["type"] = wrong_type.clone();
            },
        );
        let error = s.plan(dir.path(), false).await.unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        assert_eq!(
            error.message,
            format!(
                "value list {c} named by {} has entry type {}, source type {}",
                reference_name(&item, entry),
                wrong_type.as_str().unwrap(),
                s.id("contain_create", "type")
            )
        );
        s.no_writes().await;
    }
}

#[tokio::test]
async fn dependency_cone_refuses_reference_item_companion_and_shared_rule_changes() {
    for flavor in FLAVORS {
        for change in [
            "added",
            "removed",
            "replaced",
            "field",
            "operator",
            "other_entry",
            "companion",
            "duplicate",
            "binding",
        ] {
            let s = Stack::new(
                flavor,
                if change == "duplicate" {
                    "state_items_repeated_10000"
                } else {
                    "state_items_mixed"
                },
                "state_items_coreferenced",
            )
            .await;
            let dir = tempfile::tempdir().unwrap();
            s.pull(dir.path(), false).await.unwrap();
            let c = s.id(
                if change == "duplicate" {
                    "container_read"
                } else {
                    "contain_create"
                },
                "id",
            );
            write_values(
                dir.path(),
                &c,
                &s.values(if change == "duplicate" {
                    "items_export_after_delete"
                } else {
                    "contain_export_after"
                }),
            );
            let e = s.id("exception_create", "list_id");
            let p = s.id("container_p_ip", "id");
            if change == "binding" {
                edit(dir.path(), "rules", &s.id("state_rule_q", "rule_id"), |r| {
                    r["exceptions_list"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|r| r["list_id"] != e)
                });
            } else if change == "companion" {
                let spelling = s.id("spellings_create", "id");
                let mut values = s.values("export_s_two_spellings");
                values.remove(s.values("export_s_two_spellings").first().unwrap());
                write_values(dir.path(), &spelling, &values);
            } else if change != "duplicate" {
                edit(dir.path(), "exceptions", &e, |list| {
                    let items = list["items"].as_array_mut().unwrap();
                    let item = items
                        .iter_mut()
                        .find(|i| {
                            i["entries"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .any(|e| e["list"]["id"] == c && e["operator"] == "included")
                        })
                        .unwrap();
                    match change {
                        "added" => {
                            let mut added = item.clone();
                            added["item_id"] = json!(format!("{}-added",string(item,"item_id")));
                            items.push(added);
                        }
                        "removed" => { let id = string(item,"item_id"); items.retain(|i| i["item_id"] != id); }
                        "other_entry" => item["entries"].as_array_mut().unwrap().push(json!({"type":"match","field":"host.name","operator":"included","value":"synthetic"})),
                        _ => {
                            let entry = item["entries"].as_array_mut().unwrap().iter_mut().find(|e| e["list"]["id"] == c).unwrap();
                            match change {
                                "replaced" => entry["list"] = json!({"id":p,"type":"ip"}),
                                "field" => entry["field"] = json!("destination.ip"),
                                "operator" => entry["operator"] = json!("excluded"),
                                _ => unreachable!(),
                            }
                        }
                    }
                });
            }
            let reason = match change {
                "added" | "removed" | "replaced" | "field" | "operator" => format!(
                    "value list {c} changes values while its reference entries change; use separate runs"
                ),
                "other_entry" => {
                    let item = s
                        .data("state_items_mixed")
                        .into_iter()
                        .find(|i| {
                            i["entries"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .any(|e| e["list"]["id"] == c && e["operator"] == "included")
                        })
                        .unwrap();
                    let entry = item["entries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|e| e["list"]["id"] == c && e["operator"] == "included")
                        .unwrap();
                    format!(
                        "value list {c} changes values while referencing item {} changes; use separate runs",
                        reference_name(&item, entry)
                    )
                }
                "companion" => {
                    let spelling = s.id("spellings_create", "id");
                    let (first, other) = if c < spelling {
                        (&c, &spelling)
                    } else {
                        (&spelling, &c)
                    };
                    let item = s
                        .data("state_items_coreferenced")
                        .into_iter()
                        .find(|i| {
                            let entries = i["entries"].as_array().unwrap();
                            entries.iter().any(|e| e["list"]["id"] == c)
                                && entries.iter().any(|e| e["list"]["id"] == spelling)
                        })
                        .unwrap();
                    format!(
                        "value list {first} changes values while list {other} in referencing item {} also changes values; use separate runs",
                        string(&item, "item_id")
                    )
                }
                "duplicate" => {
                    let mut references: Vec<_> = s
                        .data("state_items_repeated_10000")
                        .iter()
                        .flat_map(|item| {
                            item["entries"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .filter(|e| e["list"]["id"] == c)
                                .map(|entry| {
                                    (
                                        (
                                            string(item, "list_id"),
                                            string(item, "namespace_type"),
                                            string(item, "item_id"),
                                        ),
                                        string(entry, "field"),
                                        string(entry, "operator"),
                                        reference_name(item, entry),
                                    )
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect();
                    references.sort();
                    let mut seen = std::collections::BTreeSet::new();
                    let duplicate = references.iter().find(|r| !seen.insert(&r.0)).unwrap();
                    format!("list {c} is referenced more than once by {}", duplicate.3)
                }
                "binding" => format!(
                    "value list {c} changes values while rule {} changes a binding to a referencing container; use separate runs",
                    s.id("state_rule_q", "rule_id")
                ),
                _ => unreachable!(),
            };
            let error = s.plan(dir.path(), false).await.unwrap_err();
            assert_eq!(error.kind, ErrorKind::Conflict, "{change}: {error}");
            assert_eq!(error.message, reason, "{change}");
            s.no_writes().await;
        }
    }
}

#[tokio::test]
async fn installed_missing_list_cannot_be_created_and_referenced_values_cannot_be_emptied() {
    for flavor in FLAVORS {
        let s = Stack::new(flavor, "state_items_included", "state_items_empty").await;
        let dir = tempfile::tempdir().unwrap();
        s.pull(dir.path(), false).await.unwrap();
        let c = s.id("contain_create", "id");
        s.container(&c, &[("container_missing_c", 404)]);
        let error = s.plan(dir.path(), false).await.unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unsupported);
        assert!(error.message.contains("installed reference"), "{error}");
        s.container(&c, &[("contain_create", 200)]);
        write_values(dir.path(), &c, &s.values("export_empty"));
        let error = s.plan(dir.path(), false).await.unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unsupported);
        assert!(error.message.contains("empty"));
        s.no_writes().await;
    }
}

#[tokio::test]
async fn final_container_type_reread_stops_before_exception_item_writes() {
    for flavor in FLAVORS {
        let s = Stack::new(flavor, "state_items_included", "state_items_empty").await;
        let dir = tempfile::tempdir().unwrap();
        s.pull(dir.path(), false).await.unwrap();
        let c = s.id("contain_create", "id");
        edit(
            dir.path(),
            "exceptions",
            &s.id("exception_create", "list_id"),
            |list| {
                for item in list["items"].as_array_mut().unwrap() {
                    item["name"] = json!(format!("{}-updated", string(item, "name")));
                }
            },
        );
        let plan = s.plan(dir.path(), false).await.unwrap();
        s.container(&c, &[("contain_create", 200), ("container_c_keyword", 200)]);
        let applied = state::apply_push(&s.t, plan).await.unwrap();
        let check = applied
            .report
            .entries
            .iter()
            .find(|e| e.action == "check_value_lists")
            .unwrap();
        assert!(
            check
                .error
                .as_ref()
                .unwrap()
                .contains("type changed since preview")
        );
        assert_eq!(applied.summary.failed, 1);
        assert_eq!(applied.summary.items_updated, 0);
        s.no_writes().await;
    }
}
