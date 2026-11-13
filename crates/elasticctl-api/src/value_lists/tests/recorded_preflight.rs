use super::super::*;
use super::apply::FastClock;
use super::plan::{pair, remote};
use super::reads::{FLAVORS, fixture, transport};
use super::recorded::{Script, remote_from, values};
use crate::model::{ExceptionItem, ListKey};
use wiremock::MockServer;

fn recorded_references(flavor: &str) -> Vec<InstalledReference> {
    let body = fixture(flavor, "exception_items_find")["response"]["data"][0].clone();
    let key = ListKey {
        list_id: body["list_id"].as_str().unwrap().into(),
        namespace_type: body["namespace_type"].as_str().unwrap().into(),
    };
    let mut references = item_references(&key, &ExceptionItem::from_value(body).unwrap()).unwrap();
    super::super::scan::sort_references(&mut references);
    references
}

#[tokio::test]
async fn complete_scan_reads_both_namespaces_unfiltered_and_keeps_outside_consumers() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        let mut script = Script::new(flavor);
        script.scan(true, true);
        script.mount(&server).await;
        let references = scan_references(&transport(&server)).await.unwrap();
        script.check(&server, false).await;
        assert_eq!(references, recorded_references(flavor));
        assert_eq!(references.len(), 2);
        assert!(
            references
                .iter()
                .any(|r| r.operator == ReferenceOperator::Included)
        );
        assert!(
            references
                .iter()
                .any(|r| r.operator == ReferenceOperator::Excluded)
        );
    }
}

#[tokio::test]
async fn public_noop_import_previews_and_applies_after_both_namespace_scans() {
    for flavor in FLAVORS {
        let before = remote(flavor);
        let mut script = Script::new(flavor);
        script.index();
        script.read(&before, "container_read", "items_export");
        script.scan(true, true);
        script.index();
        script.read(&before, "container_read", "items_export");
        script.scan(true, false);
        let server = MockServer::start().await;
        script.mount(&server).await;
        let t = transport(&server);
        let plan = plan_import(&t, pair(&before), true).await.unwrap();
        assert_eq!(plan.installed, recorded_references(flavor));
        assert!(plan.adds.is_empty() && plan.removes.is_empty());
        let results = apply_plans(&t, &[plan], &FastClock::default()).await;
        script.check(&server, false).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].outcome, Outcome::Applied);
        assert!(results[0].evidence.is_empty());
    }
}

#[tokio::test]
async fn public_add_only_reconciliation_scans_outside_references_and_verifies_values() {
    for flavor in FLAVORS {
        let before = remote_from(flavor, "contain_create", "contain_export_after");
        let mut local = pair(&before);
        local.values = values(flavor, "contain_export_imported");
        let expected = plan_list(local.clone(), Some(before.clone()), &[], &[]).unwrap();
        let id = &local.container.id;
        let mut script = Script::new(flavor);
        for preview in [true, false] {
            script.index();
            script.read(&before, "contain_create", "contain_export_after");
            script.scan(true, preview);
        }
        script.import(&expected, "contain_import", 200);
        script.export(id, "contain_export_imported");
        let server = MockServer::start().await;
        script.mount(&server).await;
        let t = transport(&server);
        let plan = plan_import(&t, local, true).await.unwrap();
        assert!(plan.installed.is_empty());
        assert_eq!(plan.order, PhaseOrder::RemovesFirst);
        let results = apply_plans(&t, &[plan], &FastClock::default()).await;
        script.check(&server, false).await;
        assert_eq!(results[0].outcome, Outcome::Applied);
        assert_eq!(results[0].evidence.len(), 1);
        assert!(results[0].evidence.iter().all(|e| e.phase_verified));
    }
}

#[tokio::test]
async fn installed_reference_addition_or_removal_since_public_preview_stops_import_and_delete() {
    for flavor in FLAVORS {
        for preview_populated in [false, true] {
            for deleting in [false, true] {
                let before = remote(flavor);
                let mut local = pair(&before);
                local.container.name = fixture(flavor, "container_patch")["response"]["name"]
                    .as_str()
                    .unwrap()
                    .into();
                let mut script = Script::new(flavor);
                for preview in [true, false] {
                    script.index();
                    script.read(&before, "container_read", "items_export");
                    script.scan(
                        if preview {
                            preview_populated
                        } else {
                            !preview_populated
                        },
                        preview,
                    );
                }
                let server = MockServer::start().await;
                script.mount(&server).await;
                let t = transport(&server);
                let result = if deleting {
                    let plan = plan_delete(&t, std::slice::from_ref(&local.container.id))
                        .await
                        .unwrap();
                    apply_delete(&t, &plan).await.remove(0).result
                } else {
                    let plan = plan_import(&t, local, true).await.unwrap();
                    apply_plans(&t, &[plan], &FastClock::default())
                        .await
                        .remove(0)
                };
                script.check(&server, false).await;
                assert_eq!(result.outcome, Outcome::Failed);
                assert_eq!(result.error.as_ref().unwrap().kind, "conflict");
                assert!(
                    result
                        .error
                        .as_ref()
                        .unwrap()
                        .message
                        .contains("references changed")
                );
                assert!(
                    result
                        .evidence
                        .iter()
                        .all(|e| e.sent == Some(Sent::NotSent))
                );
            }
        }
    }
}

#[tokio::test]
async fn stored_value_drift_since_public_preview_stops_import_and_delete_before_writes() {
    for flavor in FLAVORS {
        for deleting in [false, true] {
            let before = remote(flavor);
            let mut script = Script::new(flavor);
            script.index();
            script.read(&before, "container_read", "items_export");
            script.scan(true, true);
            script.index();
            script.read(&before, "container_read", "items_export_after_delete");
            if !deleting {
                script.scan(true, false);
            }
            let server = MockServer::start().await;
            script.mount(&server).await;
            let t = transport(&server);
            let result = if deleting {
                let plan = plan_delete(&t, std::slice::from_ref(&before.container.container.id))
                    .await
                    .unwrap();
                apply_delete(&t, &plan).await.remove(0).result
            } else {
                let plan = plan_import(&t, pair(&before), true).await.unwrap();
                apply_plans(&t, &[plan], &FastClock::default())
                    .await
                    .remove(0)
            };
            script.check(&server, false).await;
            assert_eq!(result.outcome, Outcome::Failed);
            assert_eq!(result.error.unwrap().kind, "conflict");
            assert!(
                result
                    .evidence
                    .iter()
                    .all(|e| e.sent == Some(Sent::NotSent))
            );
        }
    }
}

#[tokio::test]
async fn a_complete_scan_blocks_public_value_changes_with_a_repeated_installed_reference() {
    for flavor in FLAVORS {
        let before = remote(flavor);
        let mut local = pair(&before);
        local.values = values(flavor, "items_export_after_delete");
        let mut script = Script::new(flavor);
        script.index();
        script.read(&before, "container_read", "items_export");
        script.scan(true, true);
        let server = MockServer::start().await;
        script.mount(&server).await;
        let error = plan_import(&transport(&server), local, true)
            .await
            .unwrap_err();
        script.check(&server, false).await;
        assert_eq!(error.kind, elasticctl_core::ErrorKind::Conflict);
        assert!(error.message.contains("referenced more than once"));
    }
}

#[tokio::test]
async fn public_apply_stops_after_failed_or_unknown_list_and_keeps_later_writes_unsent() {
    for flavor in FLAVORS {
        for status in [409, 503] {
            let first = remote_from(flavor, "contain_create", "contain_export_after");
            let second = remote(flavor);
            let third = remote_from(flavor, "spellings_create", "export_spellings");
            let mut first_local = pair(&first);
            first_local.values = values(flavor, "contain_export_imported");
            let mut second_local = pair(&second);
            second_local.container.name = fixture(flavor, "container_patch")["response"]["name"]
                .as_str()
                .unwrap()
                .into();
            let mut third_local = pair(&third);
            third_local.container.name = "not-reached".into();
            let plans = [
                plan_list(first_local, Some(first.clone()), &[], &[]).unwrap(),
                plan_list(
                    second_local,
                    Some(second.clone()),
                    &recorded_references(flavor),
                    &[],
                )
                .unwrap(),
                plan_list(third_local, Some(third.clone()), &[], &[]).unwrap(),
            ];
            let mut script = Script::new(flavor);
            script.index();
            script.read(&first, "contain_create", "contain_export_after");
            script.read(&second, "container_read", "items_export");
            script.read(&third, "spellings_create", "export_spellings");
            script.scan(true, true);
            script.import(&plans[0], "contain_import", 200);
            script.export(&plans[0].local.container.id, "contain_export_imported");
            script.patch(&plans[1], status);
            if status == 503 {
                script.empty(
                    "GET",
                    "/api/lists",
                    &[("id", &plans[1].local.container.id)],
                    "container_read",
                    200,
                );
            }
            let server = MockServer::start().await;
            script.mount(&server).await;
            let results = apply_plans(&transport(&server), &plans, &FastClock::default()).await;
            script.check(&server, status == 503).await;
            assert_eq!(
                results.iter().map(|r| r.outcome).collect::<Vec<_>>(),
                [
                    Outcome::Applied,
                    if status == 409 {
                        Outcome::Failed
                    } else {
                        Outcome::Unknown
                    },
                    Outcome::NotReached
                ]
            );
            assert!(results[0].evidence.iter().all(|e| e.phase_verified));
            assert_eq!(
                results[1].evidence[0].sent,
                Some(if status == 409 {
                    Sent::Refused
                } else {
                    Sent::Uncertain
                })
            );
            assert!(!results[2].evidence.is_empty());
            assert!(
                results[2]
                    .evidence
                    .iter()
                    .all(|e| e.sent == Some(Sent::NotSent))
            );
        }
    }
}

#[tokio::test]
async fn public_delete_preflight_scans_both_namespaces_and_reports_references_without_flags() {
    for flavor in FLAVORS {
        let before = remote(flavor);
        let mut script = Script::new(flavor);
        for preview in [true, false] {
            script.index();
            script.read(&before, "container_read", "items_export");
            script.scan(true, preview);
        }
        script.empty(
            "DELETE",
            "/api/lists",
            &[("id", &before.container.container.id)],
            "container_delete_referenced",
            409,
        );
        let server = MockServer::start().await;
        script.mount(&server).await;
        let t = transport(&server);
        let plan = plan_delete(&t, std::slice::from_ref(&before.container.container.id))
            .await
            .unwrap();
        assert_eq!(plan.installed, recorded_references(flavor));
        let results = apply_delete(&t, &plan).await;
        script.check(&server, false).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].result.outcome, Outcome::Failed);
        assert_eq!(results[0].result.error.as_ref().unwrap().kind, "conflict");
        assert!(!results[0].references.is_empty());
    }
}

#[tokio::test]
async fn drift_on_a_later_list_blocks_every_write_in_the_batch() {
    for flavor in FLAVORS {
        for reference_drift in [false, true] {
            let first = remote_from(flavor, "contain_create", "contain_export_after");
            let second = remote(flavor);
            let mut first_local = pair(&first);
            first_local.values = values(flavor, "contain_export_imported");
            let mut second_local = pair(&second);
            second_local.container.name = "planned-update".into();
            let installed = if reference_drift {
                vec![]
            } else {
                recorded_references(flavor)
            };
            let plans = [
                plan_list(first_local, Some(first.clone()), &[], &[]).unwrap(),
                plan_list(second_local, Some(second.clone()), &installed, &[]).unwrap(),
            ];
            let mut script = Script::new(flavor);
            script.index();
            script.read(&first, "contain_create", "contain_export_after");
            script.read(
                &second,
                "container_read",
                if reference_drift {
                    "items_export"
                } else {
                    "items_export_after_delete"
                },
            );
            script.scan(true, true);
            let server = MockServer::start().await;
            script.mount(&server).await;
            let results = apply_plans(&transport(&server), &plans, &FastClock::default()).await;
            script.check(&server, false).await;
            assert_eq!(
                results.iter().map(|r| r.outcome).collect::<Vec<_>>(),
                [Outcome::NotReached, Outcome::Failed]
            );
            assert_eq!(results[1].error.as_ref().unwrap().kind, "conflict");
            assert!(
                results
                    .iter()
                    .flat_map(|r| &r.evidence)
                    .all(|e| e.sent == Some(Sent::NotSent))
            );
        }
    }
}

#[tokio::test]
async fn uncertain_import_read_back_controls_whether_the_next_list_is_written() {
    for flavor in FLAVORS {
        for matching in [false, true] {
            let first = remote_from(flavor, "contain_create", "contain_export_after");
            let second = remote(flavor);
            let mut first_local = pair(&first);
            first_local.values = values(flavor, "contain_export_imported");
            let mut second_local = pair(&second);
            second_local.container.name = fixture(flavor, "container_patch")["response"]["name"]
                .as_str()
                .unwrap()
                .into();
            let plans = [
                plan_list(first_local, Some(first.clone()), &[], &[]).unwrap(),
                plan_list(
                    second_local,
                    Some(second.clone()),
                    &recorded_references(flavor),
                    &[],
                )
                .unwrap(),
            ];
            let mut script = Script::new(flavor);
            script.index();
            script.read(&first, "contain_create", "contain_export_after");
            script.read(&second, "container_read", "items_export");
            script.scan(true, true);
            script.import(&plans[0], "contain_import", 503);
            script.export(&first.container.container.id, "contain_export_after");
            if matching {
                script.export(&first.container.container.id, "contain_export_imported");
                script.patch(&plans[1], 200);
            }
            let server = MockServer::start().await;
            script.mount(&server).await;
            let results = apply_plans(&transport(&server), &plans, &FastClock::default()).await;
            script.check(&server, !matching).await;
            assert_eq!(
                results.iter().map(|r| r.outcome).collect::<Vec<_>>(),
                if matching {
                    [Outcome::Applied, Outcome::Applied]
                } else {
                    [Outcome::Unknown, Outcome::NotReached]
                }
            );
            assert_eq!(results[0].evidence[0].sent, Some(Sent::Uncertain));
            assert_eq!(results[0].evidence[0].phase_verified, matching);
            if matching {
                assert!(results[1].evidence[0].phase_verified);
            } else {
                assert_eq!(results[0].evidence.last().unwrap().missing, Some(1));
                assert!(
                    results[1]
                        .evidence
                        .iter()
                        .all(|e| e.sent == Some(Sent::NotSent))
                );
            }
        }
    }
}
