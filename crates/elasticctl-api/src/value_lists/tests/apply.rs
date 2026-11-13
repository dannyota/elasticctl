use super::super::*;
use super::plan::{pair, remote};
use super::reads::{FLAVORS, fixture, response, transport};
use super::requests::assert_plan_writes;
use std::{future::Future, pin::Pin, sync::Mutex, time::Duration};
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer};

#[derive(Default)]
pub(super) struct FastClock(Mutex<Duration>);
impl Clock for FastClock {
    fn now(&self) -> Duration {
        *self.0.lock().unwrap()
    }
    fn pause(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            *self.0.lock().unwrap() += duration;
        })
    }
}

pub(super) async fn export_mock(server: &MockServer, flavor: &str, operation: &str, status: u16) {
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_export"))
        .respond_with(response(&fixture(flavor, operation), status))
        .mount(server)
        .await;
}

#[tokio::test]
async fn accepted_import_is_verified_and_not_replayed_when_export_never_matches() {
    let flavor = FLAVORS[0];
    let before = remote(flavor);
    let mut local = pair(&before);
    local.values.insert("192.0.2.0/24".into());
    let plan = plan_list(local, Some(before), &[], &[]).unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_import"))
        .and(query_param("list_id", &plan.local.container.id))
        .respond_with(response(&fixture(flavor, "items_import"), 200))
        .expect(1)
        .mount(&server)
        .await;
    export_mock(&server, flavor, "items_export", 200).await;
    let result = super::super::apply::apply_one(
        &transport(&server),
        &plan,
        &FastClock::default(),
        2,
        &mut None,
    )
    .await;
    assert_plan_writes(&server, flavor, &plan).await;
    assert_eq!(result.outcome, Outcome::Unknown);
    let read = result.evidence.last().unwrap();
    assert_eq!(read.of, Some(ReadOf::Values));
    assert_eq!(read.observed, Some(true));
    assert_eq!(read.missing, Some(1));
    assert_eq!(read.extra, Some(0));
    let requests = server.received_requests().await.unwrap();
    let import = requests
        .iter()
        .find(|r| r.url.path().ends_with("_import"))
        .unwrap();
    let content_type = import.headers["content-type"].to_str().unwrap();
    let boundary = content_type
        .strip_prefix("multipart/form-data; boundary=")
        .unwrap();
    assert_eq!(
        String::from_utf8(import.body.clone()).unwrap(),
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}.txt\"\r\nContent-Type: text/plain\r\n\r\n192.0.2.0/24\n\r\n--{boundary}--\r\n",
            plan.local.stem
        )
    );
    assert!(requests.iter().all(|r| r.url.query_pairs().count() == 1));
}

#[tokio::test]
async fn uncertain_import_keeps_observed_false_if_every_export_fails() {
    let flavor = FLAVORS[0];
    let before = remote(flavor);
    let mut local = pair(&before);
    local.values.insert("192.0.2.0/24".into());
    let plan = plan_list(local, Some(before), &[], &[]).unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_import"))
        .respond_with(response(&fixture(flavor, "items_import"), 503))
        .expect(1)
        .mount(&server)
        .await;
    export_mock(&server, flavor, "import_absent_list", 409).await;
    let result = super::super::apply::apply_one(
        &transport(&server),
        &plan,
        &FastClock::default(),
        2,
        &mut None,
    )
    .await;
    assert_plan_writes(&server, flavor, &plan).await;
    assert_eq!(result.outcome, Outcome::Unknown);
    assert_eq!(result.evidence[0].sent, Some(Sent::Uncertain));
    let read = result.evidence.last().unwrap();
    assert_eq!(read.observed, Some(false));
    assert_eq!(read.missing, None);
    assert_eq!(read.extra, None);
    assert_eq!(read.read_error.as_ref().unwrap().status, Some(409));
}

#[tokio::test]
async fn patch_uses_apply_version_and_409_stops_without_read_back() {
    let flavor = FLAVORS[0];
    let before = remote(flavor);
    let mut local = pair(&before);
    local.container.name = fixture(flavor, "container_patch")["response"]["name"]
        .as_str()
        .unwrap()
        .into();
    local.container.meta = None;
    let plan = plan_list(local.clone(), Some(before.clone()), &[], &[]).unwrap();
    let server = MockServer::start().await;
    Mock::given(method("PATCH")).and(path("/api/lists"))
        .and(body_json(serde_json::json!({"id": local.container.id, "name": local.container.name, "description": local.container.description, "_version": before.container.version})))
        .respond_with(response(&fixture(flavor, "container_patch_stale"), 409)).expect(1).mount(&server).await;
    let result = super::super::apply::apply_one(
        &transport(&server),
        &plan,
        &FastClock::default(),
        2,
        &mut None,
    )
    .await;
    assert_plan_writes(&server, flavor, &plan).await;
    assert_eq!(result.outcome, Outcome::Failed);
    assert_eq!(result.error.unwrap().kind, "conflict");
    assert_eq!(result.evidence[0].status, Some(409));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn removal_enumeration_must_equal_last_export_before_any_delete() {
    let flavor = FLAVORS[0];
    let mut before = remote(flavor);
    before.stored.values.pop();
    let mut local = pair(&before);
    local.values.pop_first();
    let plan = plan_list(local, Some(before), &[], &[]).unwrap();
    let server = MockServer::start().await;
    for operation in ["items_find_first", "items_find_next"] {
        let f = fixture(flavor, operation);
        let mut mock = Mock::given(method("GET")).and(path("/api/lists/items/_find"));
        for (key, value) in f["request"].as_object().unwrap() {
            mock = mock.and(query_param(
                key,
                value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string()),
            ));
        }
        mock.respond_with(response(&f, 200))
            .expect(1)
            .mount(&server)
            .await;
    }
    let result = super::super::apply::apply_one(
        &transport(&server),
        &plan,
        &FastClock::default(),
        2,
        &mut None,
    )
    .await;
    assert_plan_writes(&server, flavor, &plan).await;
    assert_eq!(result.outcome, Outcome::Failed);
    assert_eq!(result.error.unwrap().kind, "conflict");
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
async fn uncertain_import_matching_export_verifies_without_resending() {
    for flavor in FLAVORS {
        let mut before = remote(flavor);
        let local = pair(&before);
        before.stored = StoredValues::default();
        let plan = plan_list(local, Some(before), &[], &[]).unwrap();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/lists/items/_import"))
            .respond_with(response(&fixture(flavor, "items_import"), 503))
            .expect(1)
            .mount(&server)
            .await;
        export_mock(&server, flavor, "items_export", 200).await;
        let result = super::super::apply::apply_one(
            &transport(&server),
            &plan,
            &FastClock::default(),
            2,
            &mut None,
        )
        .await;
        assert_plan_writes(&server, flavor, &plan).await;
        assert_eq!(result.outcome, Outcome::Applied);
        assert_eq!(result.evidence[0].sent, Some(Sent::Uncertain));
        assert!(result.evidence[0].phase_verified);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn write_refusals_are_definite_at_create_patch_import_and_item_delete() {
    let flavor = FLAVORS[0];
    for action in [
        Action::CreateValueList,
        Action::UpdateValueList,
        Action::AddValues,
        Action::RemoveValues,
    ] {
        for (operation, status) in [
            ("container_patch_stale", 409),
            ("import_too_large", 413),
            ("import_wrong_extension", 415),
        ] {
            let before = remote(flavor);
            let mut local = pair(&before);
            let before = match action {
                Action::CreateValueList => None,
                Action::UpdateValueList => {
                    local.container.name.push_str(" changed");
                    Some(before)
                }
                Action::AddValues => {
                    local.values.insert("192.0.2.0/24".into());
                    Some(before)
                }
                Action::RemoveValues => {
                    local.values.pop_first();
                    Some(before)
                }
                _ => unreachable!(),
            };
            let plan = plan_list(local, before, &[], &[]).unwrap();
            let server = MockServer::start().await;
            let (verb, route) = match action {
                Action::CreateValueList => ("POST", "/api/lists"),
                Action::UpdateValueList => ("PATCH", "/api/lists"),
                Action::AddValues => ("POST", "/api/lists/items/_import"),
                Action::RemoveValues => {
                    mount_items(&server, flavor).await;
                    ("DELETE", "/api/lists/items")
                }
                _ => unreachable!(),
            };
            Mock::given(method(verb))
                .and(path(route))
                .respond_with(response(&fixture(flavor, operation), status))
                .expect(1)
                .mount(&server)
                .await;
            let result = super::super::apply::apply_one(
                &transport(&server),
                &plan,
                &FastClock::default(),
                2,
                &mut None,
            )
            .await;
            assert_plan_writes(&server, flavor, &plan).await;
            assert_eq!(result.outcome, Outcome::Failed, "{action:?} {status}");
            let sent = result
                .evidence
                .iter()
                .filter(|e| e.sent != Some(Sent::NotSent))
                .collect::<Vec<_>>();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].status, Some(status));
            assert_eq!(sent[0].sent, Some(Sent::Refused));
            assert!(
                server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .all(|r| !r.url.path().ends_with("_export"))
            );
        }
    }
}

pub(super) async fn mount_items(server: &MockServer, flavor: &str) {
    for operation in ["items_find_first", "items_find_next"] {
        let f = fixture(flavor, operation);
        let mut mock = Mock::given(method("GET")).and(path("/api/lists/items/_find"));
        for (key, value) in f["request"].as_object().unwrap() {
            mock = mock.and(query_param(
                key,
                value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string()),
            ));
        }
        mock.respond_with(response(&f, 200))
            .expect(1)
            .mount(server)
            .await;
    }
}

#[tokio::test]
async fn removal_deletes_every_stored_copy_by_id_and_404_continues() {
    for flavor in FLAVORS {
        let before = remote(flavor);
        let mut local = pair(&before);
        let deleted = fixture(flavor, "items_delete_id");
        let value = deleted["response"]["value"].as_str().unwrap();
        local.values.remove(value);
        let plan = plan_list(local, Some(before), &[], &[]).unwrap();
        let server = MockServer::start().await;
        mount_items(&server, flavor).await;
        let mut ids = Vec::new();
        for operation in ["items_find_first", "items_find_next"] {
            for item in fixture(flavor, operation)["response"]["data"]
                .as_array()
                .unwrap()
            {
                if item["value"] == value {
                    ids.push(item["id"].as_str().unwrap().to_owned());
                }
            }
        }
        ids.sort();
        for (index, id) in ids.iter().enumerate() {
            let (op, status) = if index == 0 {
                ("items_delete_id_absent", 404)
            } else {
                ("items_delete_id", 200)
            };
            Mock::given(method("DELETE"))
                .and(path("/api/lists/items"))
                .and(query_param("id", id))
                .respond_with(response(&fixture(flavor, op), status))
                .expect(1)
                .mount(&server)
                .await;
        }
        export_mock(&server, flavor, "items_export", 200).await;
        let result = super::super::apply::apply_one(
            &transport(&server),
            &plan,
            &FastClock::default(),
            2,
            &mut None,
        )
        .await;
        assert_plan_writes(&server, flavor, &plan).await;
        assert_eq!(result.outcome, Outcome::Unknown);
        assert_eq!(
            result
                .evidence
                .iter()
                .filter(|e| e.action == Action::RemoveValues && e.sent != Some(Sent::NotSent))
                .count(),
            ids.len()
        );
        let requests = server.received_requests().await.unwrap();
        let deletes: Vec<_> = requests.iter().filter(|r| r.method == "DELETE").collect();
        assert_eq!(deletes.len(), ids.len());
        for request in deletes {
            assert_eq!(request.url.query_pairs().count(), 1);
            assert_eq!(request.url.query_pairs().next().unwrap().0, "id");
            assert!(request.body.is_empty());
        }
    }
}

#[tokio::test]
async fn unknown_keeps_last_completed_counts_beside_a_later_read_error() {
    let flavor = FLAVORS[0];
    let before = remote(flavor);
    let mut local = pair(&before);
    local.values.insert("192.0.2.0/24".into());
    let plan = plan_list(local, Some(before), &[], &[]).unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_import"))
        .respond_with(response(&fixture(flavor, "items_import"), 503))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_export"))
        .respond_with(response(&fixture(flavor, "items_export"), 200))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    export_mock(&server, flavor, "import_absent_list", 409).await;
    let result = super::super::apply::apply_one(
        &transport(&server),
        &plan,
        &FastClock::default(),
        2,
        &mut None,
    )
    .await;
    assert_plan_writes(&server, flavor, &plan).await;
    let read = result.evidence.last().unwrap();
    assert_eq!(read.observed, Some(true));
    assert_eq!(read.missing, Some(1));
    assert_eq!(read.extra, Some(0));
    assert_eq!(read.read_error.as_ref().unwrap().status, Some(409));
}

#[tokio::test]
async fn uncertain_item_delete_never_sends_the_rest_of_the_phase_or_the_add_phase() {
    let flavor = FLAVORS[0];
    let before = remote(flavor);
    let mut local = pair(&before);
    let value = fixture(flavor, "items_delete_id")["response"]["value"]
        .as_str()
        .unwrap()
        .to_owned();
    local.values.remove(&value);
    local.values.insert("192.0.2.0/24".into());
    let plan = plan_list(local, Some(before), &[], &[]).unwrap();
    assert_eq!(plan.order, PhaseOrder::RemovesFirst);
    let server = MockServer::start().await;
    mount_items(&server, flavor).await;
    Mock::given(method("DELETE"))
        .and(path("/api/lists/items"))
        .respond_with(response(&fixture(flavor, "items_delete_id"), 503))
        .expect(1)
        .mount(&server)
        .await;
    export_mock(&server, flavor, "items_export", 200).await;
    let result = super::super::apply::apply_one(
        &transport(&server),
        &plan,
        &FastClock::default(),
        2,
        &mut None,
    )
    .await;
    assert_plan_writes(&server, flavor, &plan).await;
    assert_eq!(result.outcome, Outcome::Unknown);
    assert_eq!(result.evidence[0].sent, Some(Sent::Uncertain));
    assert!(
        result
            .evidence
            .iter()
            .skip(1)
            .filter(|e| e.action != Action::ReadBack)
            .all(|e| e.sent == Some(Sent::NotSent))
    );
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| !r.url.path().ends_with("_import"))
    );
}

#[tokio::test]
async fn failed_preflight_returns_unsent_evidence_for_each_planned_request() {
    let flavor = FLAVORS[0];
    let before = remote(flavor);
    let mut local = pair(&before);
    local.values.insert("192.0.2.0/24".into());
    let plan = plan_list(local, Some(before), &[], &[]).unwrap();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/lists/index"))
        .respond_with(response(&fixture(flavor, "index_before"), 404))
        .expect(1)
        .mount(&server)
        .await;
    let results = apply_plans(&transport(&server), &[plan], &FastClock::default()).await;
    assert_eq!(results[0].outcome, Outcome::Failed);
    assert_eq!(results[0].evidence.len(), 1);
    assert_eq!(results[0].evidence[0].sent, Some(Sent::NotSent));
    assert_eq!(results[0].evidence[0].action, Action::AddValues);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn adds_first_removal_uses_the_verified_exports_copy_count_and_evidence() {
    let flavor = FLAVORS[0];
    for copies_before in [1, 3] {
        let mut before = remote(flavor);
        let original = before.stored.clone();
        let removed = fixture(flavor, "items_delete_id")["response"]["value"]
            .as_str()
            .unwrap()
            .to_owned();
        let added = ["items_find_first", "items_find_next"]
            .into_iter()
            .flat_map(|name| {
                fixture(flavor, name)["response"]["data"]
                    .as_array()
                    .unwrap()
                    .clone()
            })
            .find(|v| v["value"] != removed)
            .unwrap()["value"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut local = pair(&before);
        local.values.remove(&removed);
        before
            .stored
            .values
            .retain(|v| v != &removed && v != &added);
        before
            .stored
            .values
            .extend(std::iter::repeat_n(removed.clone(), copies_before));
        let reference = super::plan::reference(&local.container.id, ReferenceOperator::Excluded);
        let plan = plan_list(local, Some(before), &[reference], &[]).unwrap();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/lists/items/_import"))
            .respond_with(response(&fixture(flavor, "items_import"), 200))
            .expect(1)
            .mount(&server)
            .await;
        mount_items(&server, flavor).await;
        Mock::given(method("DELETE"))
            .and(path("/api/lists/items"))
            .respond_with(response(&fixture(flavor, "items_delete_id"), 200))
            .expect(2)
            .mount(&server)
            .await;
        export_mock(&server, flavor, "items_export", 200).await;
        let result = super::super::apply::apply_one(
            &transport(&server),
            &plan,
            &FastClock::default(),
            2,
            &mut None,
        )
        .await;
        assert_plan_writes(&server, flavor, &plan).await;
        assert_eq!(result.outcome, Outcome::Unknown);
        let removals: Vec<_> = result
            .evidence
            .iter()
            .filter(|e| e.action == Action::RemoveValues)
            .collect();
        assert_eq!(
            removals.len(),
            original.values.iter().filter(|v| **v == removed).count()
        );
        assert!(
            removals
                .iter()
                .all(|e| e.values == Some(vec![removed.clone()]) && e.sent == Some(Sent::Accepted))
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.iter().filter(|r| r.method == "DELETE").count(), 2);
    }
}

#[test]
fn an_item_delete_404_stays_exempt_when_its_body_cannot_be_read() {
    let mut evidence = Evidence::new(Action::RemoveValues, "synthetic", "synthetic");
    let result = super::super::apply::record(
        Err(elasticctl_core::Error::with_status(
            elasticctl_core::ErrorKind::NotFound,
            404,
            "truncated body",
        )),
        &mut evidence,
        true,
        |_| panic!("a refusal body is not decoded"),
    );
    assert_eq!(result.unwrap(), Sent::Refused);
    assert_eq!(evidence.sent, Some(Sent::Refused));
    assert_eq!(evidence.status, Some(404));
}

#[test]
fn preview_drift_compares_container_identity_version_type_and_stored_multiplicity() {
    let original = remote(FLAVORS[0]);
    for field in ["id", "type", "version", "values"] {
        let mut changed = original.clone();
        match field {
            "id" => changed.container.container.id.push_str("-changed"),
            "type" => changed.container.container.list_type = ValueListType::Keyword,
            "version" => changed.container.version.push('!'),
            "values" => changed.stored.values.push(changed.stored.values[0].clone()),
            _ => unreachable!(),
        }
        assert!(
            !super::super::apply::same_read(&Some(original.clone()), &Some(changed)),
            "{field}"
        );
    }
    let mut reordered = original.clone();
    reordered.stored.values.reverse();
    assert!(super::super::apply::same_read(
        &Some(original),
        &Some(reordered)
    ));
}
