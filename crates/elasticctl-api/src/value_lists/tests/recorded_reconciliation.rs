use super::super::*;
use super::apply::FastClock;
use super::plan::{pair, reference, remote};
use super::reads::{FLAVORS, fixture, transport};
use super::recorded::{Script, remote_from, values};
use wiremock::MockServer;

fn containment(flavor: &str) -> RemoteList {
    remote_from(flavor, "contain_create", "contain_export")
}

fn delete_target(script: &mut Script<'_>, flavor: &str, status: u16) {
    let deleted = fixture(flavor, "contain_delete_id");
    script.empty(
        "DELETE",
        "/api/lists/items",
        &[("id", deleted["response"]["id"].as_str().unwrap())],
        if status == 404 {
            "items_delete_id_absent"
        } else {
            "contain_delete_id"
        },
        status,
    );
}

#[tokio::test]
async fn containment_deletion_removes_only_the_32_by_id_and_404_still_verifies() {
    for flavor in FLAVORS {
        for status in [200, 404] {
            let before = containment(flavor);
            let mut local = pair(&before);
            local.values = values(flavor, "contain_export_after");
            let plan = plan_list(local, Some(before), &[], &[]).unwrap();
            assert_eq!(plan.removes, ["10.0.0.5/32".into()].into());
            assert!(plan.adds.is_empty());
            let id = &plan.local.container.id;
            let mut script = Script::new(flavor);
            script.items(id, "contain_items_find", "2");
            delete_target(&mut script, flavor, status);
            script.export(id, "contain_export");
            script.export(id, "contain_export_after");
            let server = MockServer::start().await;
            script.mount(&server).await;
            let result = super::super::apply::apply_one(
                &transport(&server),
                &plan,
                &FastClock::default(),
                2,
                &mut None,
            )
            .await;
            script.check(&server, false).await;
            assert_eq!(result.outcome, Outcome::Applied);
            assert_eq!(result.evidence.len(), 1);
            assert_eq!(result.evidence[0].status, Some(status));
            assert_eq!(
                result.evidence[0].sent,
                Some(if status == 404 {
                    Sent::Refused
                } else {
                    Sent::Accepted
                })
            );
            assert!(result.evidence[0].phase_verified);
            assert_eq!(
                values(flavor, "contain_export_after"),
                ["10.0.0.0/8".into()].into()
            );
        }
    }
}

#[tokio::test]
async fn remove_only_deletes_every_duplicate_by_id_and_verifies_the_recorded_multiset() {
    for flavor in FLAVORS {
        for first_status in [200, 404] {
            let before = remote(flavor);
            let mut local = pair(&before);
            local.values = values(flavor, "items_export_after_delete");
            let plan = plan_list(local, Some(before), &[], &[]).unwrap();
            assert_eq!(plan.removes, ["10.0.0.5-10.0.0.5".into()].into());
            let mut script = Script::new(flavor);
            let id = &plan.local.container.id;
            script.items(id, "items_find_first", "2");
            let first = fixture(flavor, "items_find_first");
            let cursor = first["response"]["cursor"].as_str().unwrap();
            script.empty(
                "GET",
                "/api/lists/items/_find",
                &[
                    ("list_id", id),
                    ("page", "2"),
                    ("per_page", "2"),
                    ("cursor", cursor),
                ],
                "items_find_next",
                200,
            );
            let mut ids = Vec::new();
            for operation in ["items_find_first", "items_find_next"] {
                for item in fixture(flavor, operation)["response"]["data"]
                    .as_array()
                    .unwrap()
                {
                    if plan.removes.contains(item["value"].as_str().unwrap()) {
                        ids.push(item["id"].as_str().unwrap().to_owned());
                    }
                }
            }
            ids.sort();
            assert_eq!(ids.len(), 2);
            for (index, id) in ids.iter().enumerate() {
                let status = if index == 0 { first_status } else { 200 };
                script.empty(
                    "DELETE",
                    "/api/lists/items",
                    &[("id", id)],
                    if status == 404 {
                        "items_delete_id_absent"
                    } else {
                        "items_delete_id"
                    },
                    status,
                );
            }
            script.export(id, "items_export_after_delete");
            let server = MockServer::start().await;
            script.mount(&server).await;
            let result = super::super::apply::apply_one(
                &transport(&server),
                &plan,
                &FastClock::default(),
                2,
                &mut None,
            )
            .await;
            script.check(&server, false).await;
            assert_eq!(result.outcome, Outcome::Applied);
            assert_eq!(result.evidence.len(), 2);
            assert!(
                result
                    .evidence
                    .iter()
                    .all(|e| e.action == Action::RemoveValues && e.phase_verified)
            );
            assert_eq!(result.evidence[0].status, Some(first_status));
            assert_eq!(result.evidence[1].sent, Some(Sent::Accepted));
        }
    }
}

#[tokio::test]
async fn removes_first_reconciliation_verifies_removal_before_import_and_final_values() {
    for flavor in FLAVORS {
        for referenced in [false, true] {
            let before = containment(flavor);
            let mut local = pair(&before);
            local.values = values(flavor, "contain_export_imported");
            let references = if referenced {
                vec![reference(&local.container.id, ReferenceOperator::Included)]
            } else {
                vec![]
            };
            let plan = plan_list(local, Some(before), &references, &[]).unwrap();
            assert_eq!(plan.order, PhaseOrder::RemovesFirst);
            assert_eq!(plan.adds, ["10.0.0.6/32".into()].into());
            assert_eq!(plan.removes, ["10.0.0.5/32".into()].into());
            let mut script = Script::new(flavor);
            let id = &plan.local.container.id;
            script.items(id, "contain_items_find", "2");
            delete_target(&mut script, flavor, 200);
            script.export(id, "contain_export_after");
            script.import(&plan, "contain_import", 200);
            script.export(id, "contain_export_imported");
            let server = MockServer::start().await;
            script.mount(&server).await;
            let result = super::super::apply::apply_one(
                &transport(&server),
                &plan,
                &FastClock::default(),
                2,
                &mut None,
            )
            .await;
            script.check(&server, false).await;
            assert_eq!(result.outcome, Outcome::Applied);
            assert_eq!(
                result.evidence.iter().map(|e| e.action).collect::<Vec<_>>(),
                [Action::RemoveValues, Action::AddValues]
            );
            assert!(
                result
                    .evidence
                    .iter()
                    .all(|e| e.sent == Some(Sent::Accepted) && e.phase_verified)
            );
        }
    }
}

#[tokio::test]
async fn singleton_replacement_adds_first_and_never_empties_for_every_reference_order() {
    for flavor in FLAVORS {
        for operators in [
            vec![ReferenceOperator::Included],
            vec![ReferenceOperator::Excluded],
            vec![ReferenceOperator::Included, ReferenceOperator::Excluded],
            vec![],
        ] {
            let before = remote_from(flavor, "contain_create", "contain_export_single");
            let mut local = pair(&before);
            local.values = values(flavor, "contain_export_after");
            let references: Vec<_> = operators
                .iter()
                .enumerate()
                .map(|(i, operator)| {
                    let mut r = reference(&local.container.id, *operator);
                    r.item_id = format!("consumer-{i}");
                    r
                })
                .collect();
            let plan = plan_list(local, Some(before), &references, &[]).unwrap();
            assert_eq!(plan.order, PhaseOrder::AddsFirst);
            assert_eq!(plan.adds, ["10.0.0.0/8".into()].into());
            assert_eq!(plan.removes, ["10.0.0.5/32".into()].into());
            let mut script = Script::new(flavor);
            let id = &plan.local.container.id;
            script.import(&plan, "contain_import", 200);
            script.export(id, "contain_export");
            script.items(id, "contain_items_find", "2");
            delete_target(&mut script, flavor, 200);
            script.export(id, "contain_export_after");
            let server = MockServer::start().await;
            script.mount(&server).await;
            let result = super::super::apply::apply_one(
                &transport(&server),
                &plan,
                &FastClock::default(),
                2,
                &mut None,
            )
            .await;
            script.check(&server, false).await;
            assert_eq!(result.outcome, Outcome::Applied);
            assert_eq!(
                result.evidence.iter().map(|e| e.action).collect::<Vec<_>>(),
                [Action::AddValues, Action::RemoveValues]
            );
            assert!(result.evidence.iter().all(|e| e.phase_verified));
            let intermediate = values(flavor, "contain_export");
            assert!(
                plan.before
                    .as_ref()
                    .unwrap()
                    .stored
                    .set()
                    .is_subset(&intermediate)
            );
            assert!(plan.local.values.is_subset(&intermediate));
            assert!(!intermediate.is_empty());
        }
    }
}

#[tokio::test]
async fn uncertain_item_delete_settles_both_ways_and_only_a_match_allows_the_add_phase() {
    for flavor in FLAVORS {
        for matching in [true, false] {
            let before = containment(flavor);
            let mut local = pair(&before);
            local.values = values(flavor, "contain_export_imported");
            let plan = plan_list(local, Some(before), &[], &[]).unwrap();
            assert_eq!(plan.order, PhaseOrder::RemovesFirst);
            let mut script = Script::new(flavor);
            let id = &plan.local.container.id;
            script.items(id, "contain_items_find", "2");
            delete_target(&mut script, flavor, 503);
            script.export(
                id,
                if matching {
                    "contain_export_after"
                } else {
                    "contain_export"
                },
            );
            if matching {
                script.import(&plan, "contain_import", 200);
                script.export(id, "contain_export_imported");
            }
            let server = MockServer::start().await;
            script.mount(&server).await;
            let result = super::super::apply::apply_one(
                &transport(&server),
                &plan,
                &FastClock::default(),
                2,
                &mut None,
            )
            .await;
            script.check(&server, !matching).await;
            assert_eq!(
                result.outcome,
                if matching {
                    Outcome::Applied
                } else {
                    Outcome::Unknown
                }
            );
            assert_eq!(result.evidence[0].sent, Some(Sent::Uncertain));
            assert_eq!(result.evidence[0].phase_verified, matching);
            assert_eq!(
                result.evidence[1].sent,
                Some(if matching {
                    Sent::Accepted
                } else {
                    Sent::NotSent
                })
            );
            if !matching {
                let read = result.evidence.last().unwrap();
                assert_eq!(read.observed, Some(true));
                assert_eq!(read.missing, Some(0));
                assert_eq!(read.extra, Some(1));
            }
        }
    }
}
