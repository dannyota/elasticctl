use super::super::*;
use super::apply::FastClock;
use super::plan::{pair, remote};
use super::reads::{FLAVORS, fixture, response, transport};
use crate::model::{ExceptionItem, ListKey};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer};

#[tokio::test]
async fn co_referenced_value_changes_refuse_the_batch_before_any_request() {
    for flavor in FLAVORS {
        let body = fixture(flavor, "exception_items_find")["response"]["data"][0].clone();
        let key = ListKey {
            list_id: body["list_id"].as_str().unwrap().into(),
            namespace_type: body["namespace_type"].as_str().unwrap().into(),
        };
        let item = ExceptionItem::from_value(body).unwrap();
        let mut references = item_references(&key, &item).unwrap();
        assert_eq!(references[0].field, "source.ip");
        assert_eq!(references[1].field, "destination.ip");
        references[1].list_id.push_str("-destination");
        let mut plans = Vec::new();
        for reference in &references {
            let mut before = remote(flavor);
            before.container.container.id.clone_from(&reference.list_id);
            let mut local = pair(&before);
            local.values.insert("192.0.2.0/24".into());
            plans.push(plan_list(local, Some(before), &references, &[]).unwrap());
        }
        let server = MockServer::start().await;
        let results = apply_plans(&transport(&server), &plans, &FastClock::default()).await;
        assert_eq!(results[0].outcome, Outcome::Failed);
        let error = results[0].error.as_ref().unwrap();
        assert_eq!(error.kind, "conflict");
        assert!(error.message.contains(&references[0].item_id));
        assert!(error.message.contains(&key.list_id));
        assert!(error.message.contains(&key.namespace_type));
        for reference in &references {
            assert!(error.message.contains(&reference.list_id));
        }
        assert_eq!(results[1].outcome, Outcome::NotReached);
        assert!(
            results
                .iter()
                .flat_map(|r| &r.evidence)
                .all(|e| e.sent == Some(Sent::NotSent))
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn apply_and_delete_container_drift_conflicts_before_exporting_values() {
    for flavor in FLAVORS {
        for drift in ["id", "type", "version", "absence"] {
            for deleting in [false, true] {
                let mut before = remote(flavor);
                match drift {
                    "id" => before.container.container.id.push_str("-preview"),
                    "type" => before.container.container.list_type = ValueListType::Keyword,
                    "version" => before.container.version.push('!'),
                    "absence" => (),
                    _ => unreachable!(),
                }
                let server = MockServer::start().await;
                Mock::given(method("GET"))
                    .and(path("/api/lists/index"))
                    .respond_with(response(&fixture(flavor, "index_after"), 200))
                    .expect(1)
                    .mount(&server)
                    .await;
                Mock::given(method("GET"))
                    .and(path("/api/lists"))
                    .and(query_param("id", &before.container.container.id))
                    .respond_with(response(
                        &fixture(flavor, "container_read"),
                        if drift == "absence" { 404 } else { 200 },
                    ))
                    .expect(1)
                    .mount(&server)
                    .await;
                let result = if deleting {
                    apply_delete(
                        &transport(&server),
                        &DeletePlan {
                            before: vec![before],
                            installed: vec![],
                        },
                    )
                    .await
                    .remove(0)
                    .result
                } else {
                    let plan = plan_list(pair(&before), Some(before), &[], &[]).unwrap();
                    apply_plans(&transport(&server), &[plan], &FastClock::default())
                        .await
                        .remove(0)
                };
                assert_eq!(
                    result.outcome,
                    Outcome::Failed,
                    "{flavor} {drift} delete={deleting}"
                );
                assert_eq!(
                    result.error.unwrap().kind,
                    "conflict",
                    "{flavor} {drift} delete={deleting}"
                );
                let requests = server.received_requests().await.unwrap();
                assert_eq!(requests.len(), 2);
                assert!(
                    requests
                        .iter()
                        .all(|r| r.method == "GET" && r.body.is_empty())
                );
                assert_eq!(requests[0].url.query(), None);
                assert_eq!(requests[1].url.query_pairs().count(), 1);
            }
        }
    }
}

#[tokio::test]
async fn noop_apply_sends_no_write_or_read_back() {
    for flavor in FLAVORS {
        let before = remote(flavor);
        let plan = plan_list(pair(&before), Some(before), &[], &[]).unwrap();
        let server = MockServer::start().await;
        let result = super::super::apply::apply_one(
            &transport(&server),
            &plan,
            &FastClock::default(),
            2,
            &mut None,
        )
        .await;
        assert_eq!(result.outcome, Outcome::Applied);
        assert!(result.evidence.is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}

#[test]
fn unsupported_recreated_container_is_a_preview_conflict() {
    for flavor in FLAVORS {
        let before = remote(flavor);
        for field in ["id", "type", "version"] {
            let mut observed = before.container.clone();
            match field {
                "id" => observed.container.id.push_str("-recreated"),
                "type" => {
                    observed.container.list_type = ValueListType::Unsupported("integer".into())
                }
                "version" => observed.version.push('!'),
                _ => unreachable!(),
            }
            let error = super::super::reads::check_preview_container(
                &before.container.container.id,
                Some(&before.container),
                Some(&observed),
            )
            .unwrap_err();
            assert_eq!(error.kind, elasticctl_core::ErrorKind::Conflict, "{field}");
        }
    }
}

#[tokio::test]
async fn dependency_check_allows_unchanged_values_and_distinct_consumers() {
    let flavor = FLAVORS[0];
    for difference in ["unchanged", "item", "namespace", "container"] {
        let mut plans = Vec::new();
        for index in 0..2 {
            let mut before = remote(flavor);
            before.container.container.id.push_str(&format!("-{index}"));
            let mut local = pair(&before);
            if index == 0 || difference != "unchanged" {
                local.values.insert("192.0.2.0/24".into());
            } else {
                local.container.name.push_str(" changed");
            }
            let mut consumer =
                super::plan::reference(&local.container.id, ReferenceOperator::Included);
            if index == 1 {
                match difference {
                    "item" => consumer.item_id.push_str("-other"),
                    "namespace" => consumer.container.namespace_type = "single".into(),
                    "container" => consumer.container.list_id.push_str("-other"),
                    _ => (),
                }
            }
            plans.push(plan_list(local, Some(before), &[consumer], &[]).unwrap());
        }
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/lists/index"))
            .respond_with(response(&fixture(flavor, "index_before"), 404))
            .expect(1)
            .mount(&server)
            .await;
        let results = apply_plans(&transport(&server), &plans, &FastClock::default()).await;
        assert_eq!(
            results[0].error.as_ref().unwrap().kind,
            "unsupported",
            "{difference}"
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        super::requests::assert_request(&requests[0], "GET", "/api/lists/index", &[]);
        assert!(requests[0].body.is_empty());
    }
}
