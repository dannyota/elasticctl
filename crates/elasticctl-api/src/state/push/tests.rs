use super::*;
use crate::value_lists::{
    self as vl, Action, ContainerAction, Evidence, ListOutcome, Outcome, Sent,
};
use serde_json::json;

fn list(id: &str, action: ContainerAction) -> vl::ListPlan {
    vl::ListPlan {
        local: vl::LocalPair {
            stem: id.into(),
            container: vl::Container {
                id: id.into(),
                list_type: vl::ValueListType::Keyword,
                name: id.into(),
                description: "Synthetic".into(),
                meta: None,
            },
            values: ["target".into()].into(),
        },
        before: None,
        installed: vec![],
        desired: vec![],
        container_action: action,
        adds: ["target".into()].into(),
        removes: Default::default(),
        order: vl::PhaseOrder::AddsFirst,
        order_reason: "Synthetic".into(),
        warnings: vec![],
    }
}

fn evidence(
    id: &str,
    action: Action,
    outcome: Outcome,
    sent: Sent,
    count: usize,
    verified: bool,
) -> Evidence {
    Evidence {
        action,
        rule_id: id.into(),
        name: id.into(),
        values: Some((0..count).map(|n| format!("value-{n:05}")).collect()),
        sent: Some(sent),
        status: None,
        phase_verified: verified,
        outcome,
        of: None,
        observed: None,
        missing: None,
        extra: None,
        mismatched: None,
        read_error: None,
        planned_adds: None,
        planned_removes: None,
    }
}

fn push(plans: Vec<vl::ListPlan>, outcomes: Vec<ListOutcome>) -> PushPlan {
    let report = ChangeReport {
        profile: "test".into(),
        host: "example.invalid".into(),
        space: "default".into(),
        applied: true,
        entries: outcomes
            .iter()
            .flat_map(|o| o.evidence.iter().cloned())
            .map(ReportEntry::from)
            .collect(),
    };
    let summary = push_summary(&report, None, None, 0, ExceptionCounts::default());
    PushPlan {
        preview_action: String::new(),
        preview_details: vec![],
        report,
        summary,
        desired: BTreeMap::new(),
        list_ops: vec![],
        item_ops: vec![],
        value_lists: plans.clone(),
        value_list_outcomes: outcomes,
        value_list_drift: None,
        values: super::super::values::ValuePlan { plans, drift: None },
    }
}

#[test]
fn summary_matches_section_7_5_partial_apply_and_evidence_order() {
    let plans = vec![
        list("a", ContainerAction::None),
        list("b", ContainerAction::None),
        list("c", ContainerAction::None),
    ];
    let mut read = evidence(
        "b",
        Action::ReadBack,
        Outcome::Unknown,
        Sent::NotSent,
        0,
        false,
    );
    read.values = None;
    read.sent = None;
    read.of = Some(vl::ReadOf::Values);
    read.observed = Some(false);
    read.read_error = Some(vl::Failure {
        kind: "timeout".into(),
        status: None,
        message: "Injected".into(),
    });
    let mut not_reached = evidence(
        "c",
        Action::NotReached,
        Outcome::NotReached,
        Sent::NotSent,
        0,
        false,
    );
    not_reached.values = None;
    not_reached.planned_adds = Some(1);
    not_reached.planned_removes = Some(0);
    let outcomes = vec![
        ListOutcome {
            id: "a".into(),
            outcome: Outcome::Applied,
            error: None,
            evidence: vec![
                evidence(
                    "a",
                    Action::RemoveValues,
                    Outcome::Applied,
                    Sent::Accepted,
                    3,
                    true,
                ),
                evidence(
                    "a",
                    Action::AddValues,
                    Outcome::Applied,
                    Sent::Accepted,
                    1200,
                    true,
                ),
            ],
        },
        ListOutcome {
            id: "b".into(),
            outcome: Outcome::Unknown,
            error: None,
            evidence: vec![
                evidence(
                    "b",
                    Action::AddValues,
                    Outcome::Unknown,
                    Sent::Accepted,
                    1,
                    false,
                ),
                evidence(
                    "b",
                    Action::AddValues,
                    Outcome::Unknown,
                    Sent::Uncertain,
                    1,
                    false,
                ),
                evidence(
                    "b",
                    Action::AddValues,
                    Outcome::Unknown,
                    Sent::NotSent,
                    1,
                    false,
                ),
                read,
            ],
        },
        ListOutcome {
            id: "c".into(),
            outcome: Outcome::NotReached,
            error: None,
            evidence: vec![not_reached],
        },
    ];
    let mut plan = push(plans, outcomes);
    update_value_summary(&mut plan);
    assert_eq!(
        (
            plan.summary.value_lists_updated,
            plan.summary.values_added,
            plan.summary.values_removed,
            plan.summary.value_lists_unknown,
            plan.summary.value_lists_not_reached
        ),
        (1, 1200, 3, 1, 1)
    );
    assert_eq!(plan.summary.failed, 1);
    let entries = serde_json::to_value(&plan.report).unwrap()["entries"].clone();
    assert_eq!(entries[0]["action"], "remove_values");
    assert_eq!(entries[0]["values"].as_array().unwrap().len(), 3);
    assert_eq!(entries[2]["sent"], "accepted");
    assert_eq!(entries[3]["sent"], "uncertain");
    assert_eq!(entries[4]["sent"], "not_sent");
    assert_eq!(entries[5]["observed"], false);
    for key in ["missing", "extra", "mismatched", "values", "sent"] {
        assert!(entries[5].get(key).is_none());
    }
    assert_eq!(entries[6]["planned_adds"], 1);
    assert!(entries[6].get("values").is_none());
    assert!(
        entries
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e.get("before").is_none())
    );
}

#[test]
fn summary_counts_only_applied_changed_lists_and_verified_values_for_every_outcome() {
    for outcome in [
        Outcome::Applied,
        Outcome::Failed,
        Outcome::Unknown,
        Outcome::NotReached,
    ] {
        for action in [
            ContainerAction::None,
            ContainerAction::Create,
            ContainerAction::Update,
        ] {
            let list = list("a", action);
            let mut plan = push(
                vec![list],
                vec![ListOutcome {
                    id: "a".into(),
                    outcome,
                    error: None,
                    evidence: vec![evidence(
                        "a",
                        Action::AddValues,
                        outcome,
                        Sent::Accepted,
                        2,
                        true,
                    )],
                }],
            );
            update_value_summary(&mut plan);
            assert_eq!(
                plan.summary.value_lists_created,
                usize::from(outcome == Outcome::Applied && action == ContainerAction::Create)
            );
            assert_eq!(
                plan.summary.value_lists_updated,
                usize::from(outcome == Outcome::Applied && action != ContainerAction::Create)
            );
            assert_eq!(plan.summary.values_added, 2);
            assert_eq!(
                plan.summary.failed,
                usize::from(matches!(outcome, Outcome::Failed | Outcome::Unknown))
            );
        }
    }
    let mut unchanged = list("a", ContainerAction::None);
    unchanged.adds.clear();
    let mut plan = push(
        vec![unchanged],
        vec![ListOutcome {
            id: "a".into(),
            outcome: Outcome::Applied,
            error: None,
            evidence: vec![],
        }],
    );
    update_value_summary(&mut plan);
    assert_eq!(plan.summary.value_lists_updated, 0);
}

#[test]
fn legacy_report_and_summary_omit_all_value_list_fields() {
    let mut plan = push(vec![], vec![]);
    plan.report.entries.push(ReportEntry {
        rule_id: "r".into(),
        name: "Rule".into(),
        action: "create".into(),
        before: None,
        after: Some(json!({"rule_id": "r"})),
        applied: true,
        error: None,
        value_list: None,
    });
    assert_eq!(
        serde_json::to_string(&plan.report.entries[0]).unwrap(),
        "{\"rule_id\":\"r\",\"name\":\"Rule\",\"action\":\"create\",\"before\":null,\"after\":{\"rule_id\":\"r\"},\"applied\":true,\"error\":null}"
    );
    assert_eq!(
        serde_json::to_value(&plan.summary).unwrap(),
        json!({"applied": true, "created": 0, "updated": 0, "skipped_remote_only": 0, "failed": 0, "pending": 0, "lists_created": 0, "lists_updated": 0, "items_created": 0, "items_updated": 0, "items_removed": 0})
    );
}

#[tokio::test]
async fn apply_finishes_value_lists_before_exception_containers_items_and_rules() {
    use crate::state::values::tests::{base, fixture, mount, pair, remote, response, transport};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer};
    let flavor = "traditional-9.5.1";
    let server = MockServer::start().await;
    base(&server, flavor).await;
    let patched = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let read = patched.clone();
    Mock::given(method("GET"))
        .and(path("/api/lists"))
        .respond_with(move |_: &wiremock::Request| {
            response(
                flavor,
                if read.load(std::sync::atomic::Ordering::SeqCst) {
                    "container_patch"
                } else {
                    "container_read"
                },
                200,
            )
        })
        .mount(&server)
        .await;
    let write = patched.clone();
    Mock::given(method("PATCH"))
        .and(path("/api/lists"))
        .respond_with(move |_: &wiremock::Request| {
            write.store(true, std::sync::atomic::Ordering::SeqCst);
            response(flavor, "container_patch", 200)
        })
        .expect(1)
        .mount(&server)
        .await;
    mount(
        &server,
        flavor,
        "POST",
        "/api/lists/items/_export",
        "items_export",
        200,
    )
    .await;
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
        "POST",
        "/api/exception_lists",
        "exception_create",
        200,
    )
    .await;
    mount(
        &server,
        flavor,
        "POST",
        "/api/exception_lists/items",
        "exception_item_create",
        200,
    )
    .await;
    let rule_fixture: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/traditional-9.5.1/rules_get.json"),
        )
        .unwrap(),
    )
    .unwrap();
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&rule_fixture["response"]))
        .mount(&server)
        .await;
    let mut local = pair(flavor);
    local.container.name = fixture(flavor, "container_patch")["response"]["name"]
        .as_str()
        .unwrap()
        .into();
    let list_plan = vl::plan_list(local, Some(remote(flavor)), &[], &[]).unwrap();
    let mut plan = push(vec![list_plan], vec![]);
    let exception = crate::model::ExceptionList::from_value(
        fixture(flavor, "exception_create")["response"].clone(),
    )
    .unwrap();
    let item = crate::model::ExceptionItem::from_value(
        fixture(flavor, "exception_item_create")["response"].clone(),
    )
    .unwrap();
    let rule = Rule::from_value(json!({"rule_id":"synthetic", "name":"Synthetic", "type":"query", "exceptions_list":[{"list_id":exception.list_id().unwrap(), "type":"detection", "namespace_type":"single"}]})).unwrap();
    plan.desired.insert("synthetic".into(), rule);
    plan.report.entries.push(ReportEntry {
        rule_id: "synthetic".into(),
        name: "Synthetic".into(),
        action: "create".into(),
        before: None,
        after: None,
        applied: false,
        error: None,
        value_list: None,
    });
    plan.list_ops.push(ListOp::Create(exception));
    plan.item_ops.push(ItemOp::Create(item));
    let applied = apply_push(&transport(&server), plan).await.unwrap();
    assert_eq!(applied.summary.failed, 0);
    assert_eq!(applied.summary.value_lists_updated, 1);
    assert_eq!(
        (
            applied.summary.lists_created,
            applied.summary.items_created,
            applied.summary.created
        ),
        (1, 1, 1)
    );
    let requests = server.received_requests().await.unwrap();
    let writes: Vec<_> = requests
        .iter()
        .filter(|r| r.method != "GET" && r.url.path() != "/api/lists/items/_export")
        .map(|r| (r.method.as_str(), r.url.path()))
        .collect();
    assert_eq!(
        writes,
        [
            ("PATCH", "/api/lists"),
            ("POST", "/api/exception_lists"),
            ("POST", "/api/exception_lists/items"),
            ("POST", "/api/detection_engine/rules")
        ]
    );
    let patch = requests.iter().position(|r| r.method == "PATCH").unwrap();
    let item_write = requests
        .iter()
        .position(|r| r.url.path() == "/api/exception_lists/items")
        .unwrap();
    assert!(
        requests[patch + 1..item_write]
            .iter()
            .any(|r| r.method == "GET" && r.url.path() == "/api/lists")
    );
    let request = &requests[patch];
    assert_eq!(
        request.body_json::<Value>().unwrap()["_version"],
        fixture(flavor, "container_read")["response"]["_version"]
    );
}

#[tokio::test]
async fn injected_patch_refusal_stops_later_lists_and_all_exception_writes_with_a_report() {
    use crate::state::values::tests::{base, fixture, mount, pair, remote, transport};
    use wiremock::MockServer;
    let flavor = "traditional-9.5.1";
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
    mount(
        &server,
        flavor,
        "PATCH",
        "/api/lists",
        "container_patch_stale",
        409,
    )
    .await;
    let mut local = pair(flavor);
    local.container.name = "Synthetic change".into();
    let first = vl::plan_list(local, Some(remote(flavor)), &[], &[]).unwrap();
    let mut plan = push(vec![first], vec![]);
    plan.item_ops.push(ItemOp::Create(
        crate::model::ExceptionItem::from_value(
            fixture(flavor, "exception_item_create")["response"].clone(),
        )
        .unwrap(),
    ));
    let applied = apply_push(&transport(&server), plan).await.unwrap();
    assert_eq!(applied.summary.failed, 1);
    assert!(applied.report.applied);
    let evidence = serde_json::to_value(&applied.report.entries[0]).unwrap();
    assert_eq!(evidence["action"], "update_value_list");
    assert_eq!(evidence["sent"], "refused");
    assert_eq!(evidence["status"], 409);
    assert_eq!(evidence["outcome"], "failed");
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == "GET"
                || r.method == "PATCH"
                || r.url.path() == "/api/lists/items/_export")
    );
}

#[derive(Default)]
struct FastClock(std::sync::atomic::AtomicU64);

impl vl::Clock for FastClock {
    fn now(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
    fn pause(
        &self,
        duration: std::time::Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.0
                .fetch_add(duration.as_secs(), std::sync::atomic::Ordering::SeqCst);
        })
    }
}

#[tokio::test]
async fn injected_uncertain_patch_stops_before_later_lists_and_exceptions_and_reports_unknown() {
    use crate::state::values::tests::{base, fixture, mount, pair, remote, response, transport};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer};
    let flavor = "traditional-9.5.1";
    let server = MockServer::start().await;
    base(&server, flavor).await;
    let mut local = pair(flavor);
    local.container.name = "Synthetic change".into();
    let first = vl::plan_list(local, Some(remote(flavor)), &[], &[]).unwrap();
    Mock::given(method("GET"))
        .and(path("/api/lists"))
        .and(query_param("id", &first.local.container.id))
        .respond_with(response(flavor, "container_read", 200))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_export"))
        .and(query_param("list_id", &first.local.container.id))
        .respond_with(response(flavor, "items_export", 200))
        .mount(&server)
        .await;
    let container =
        vl::decode_remote_container(&fixture(flavor, "contain_create")["response"]).unwrap();
    let stored = vl::decode_export(
        &container.container.list_type,
        fixture(flavor, "contain_export")["response"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let second = vl::plan_list(
        vl::LocalPair {
            stem: vl::file_stem(&container.container.id),
            container: container.container.clone(),
            values: stored.set(),
        },
        Some(vl::RemoteList { container, stored }),
        &[],
        &[],
    )
    .unwrap();
    Mock::given(method("GET"))
        .and(path("/api/lists"))
        .and(query_param("id", &second.local.container.id))
        .respond_with(response(flavor, "contain_create", 200))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_export"))
        .and(query_param("list_id", &second.local.container.id))
        .respond_with(response(flavor, "contain_export", 200))
        .expect(1)
        .mount(&server)
        .await;
    mount(
        &server,
        flavor,
        "PATCH",
        "/api/lists",
        "container_patch",
        503,
    )
    .await;
    let mut plan = push(vec![first, second], vec![]);
    plan.item_ops.push(ItemOp::Create(
        crate::model::ExceptionItem::from_value(
            fixture(flavor, "exception_item_create")["response"].clone(),
        )
        .unwrap(),
    ));
    let applied = apply_push_with_clock(&transport(&server), plan, &FastClock::default())
        .await
        .unwrap();
    assert_eq!(
        applied
            .value_list_outcomes
            .iter()
            .map(|o| o.outcome)
            .collect::<Vec<_>>(),
        [Outcome::Unknown, Outcome::NotReached]
    );
    assert_eq!(
        (
            applied.summary.value_lists_unknown,
            applied.summary.value_lists_not_reached,
            applied.summary.failed
        ),
        (1, 1, 1)
    );
    let entries = serde_json::to_value(&applied.report.entries).unwrap();
    assert_eq!(entries[0]["sent"], "uncertain");
    assert_eq!(entries[1]["action"], "read_back");
    assert_eq!(entries[1]["of"], "container");
    assert_eq!(entries[1]["observed"], true);
    assert_eq!(entries[1]["mismatched"], json!(["name"]));
    assert_eq!(entries[2]["action"], "not_reached");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.iter().filter(|r| r.method == "PATCH").count(), 1);
    assert!(requests.iter().all(|r| r.method == "GET"
        || r.method == "PATCH"
        || r.url.path() == "/api/lists/items/_export"));
}
