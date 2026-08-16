//! The state engine's contract, independent of the CLI.

use elasticctl_api::rules_ops;
use elasticctl_api::state::{self, StackIdentity};
use elasticctl_api::{Change, FieldChange, Format, ListChange, RuleFilter, RuleSource};
use elasticctl_api_test_support::{
    MockStack, mock_empty_stack, mock_stack_with_colliding_namespaces,
    mock_stack_with_dangling_pointer, mock_stack_with_failing_item_create,
    mock_stack_with_list_and_items, mock_stack_with_list_id, mock_stack_with_matching_pointer,
    mock_stack_with_rule_default_list, mock_stack_with_rule_referencing,
    mock_stack_with_rule_with_two_wrong_pointers, mock_stack_with_two_list_ids,
    mock_stack_with_two_lists_one_mirrored,
};
use elasticctl_core::ErrorKind;
use serde_json::{Value, json};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

struct FirstEmptyThenMalformedSourcePage(AtomicUsize);

impl Respond for FirstEmptyThenMalformedSourcePage {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let is_custom = request.url.query_pairs().any(|(key, value)| {
            key == "filter" && value == "alert.attributes.params.immutable: false"
        });
        if is_custom && self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            ResponseTemplate::new(200).set_body_json(json!({
                "data": [], "total": 0, "page": 1, "perPage": 10000,
            }))
        } else if is_custom {
            ResponseTemplate::new(200).set_body_json(json!({
                "data": [], "page": 1, "perPage": 1,
            }))
        } else {
            ResponseTemplate::new(200).set_body_json(json!({
                "data": [], "total": 0, "page": 1, "perPage": 1,
            }))
        }
    }
}

fn identity() -> StackIdentity {
    StackIdentity {
        profile: "test".into(),
        host: "kb.example.com".into(),
        space: "default".into(),
    }
}

fn write_local_rule(dir: &Path, id: &str, body: &str) {
    let rules = dir.join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(rules.join(format!("{id}.ndjson")), body).unwrap();
}

/// A stack seeded with one remote rule that the local mirror does not contain,
/// so the test's local rule reads as a planned create.
async fn mock_stack_with_one_rule() -> MockStack {
    MockStack::with_rules(vec![json!({
        "rule_id": "seed",
        "name": "Seed",
        "type": "query",
    })])
    .await
}

/// The dry-run default is structural: planning must not mutate.
#[tokio::test]
async fn plan_push_sends_no_write_request() {
    let stack = mock_stack_with_one_rule().await;
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "a",
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\"}\n",
    );

    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();

    assert_eq!(plan.summary.pending, 1, "the create is planned");
    assert!(!plan.summary.applied, "planning is not applying");
    assert!(
        stack.write_requests().await.is_empty(),
        "plan_push must issue no POST, PUT, PATCH, or DELETE"
    );
    assert_eq!(
        plan.report.profile, "test",
        "the report carries the profile"
    );
    assert_eq!(plan.report.host, "kb.example.com");
    assert_eq!(plan.report.space, "default");
}

/// `--search` resolves to a `rule_ids` scope, so the scoped remote read is a
/// ruleId-filtered `_find` (`find_by_rule_ids`), not a corpus read (spec 5.3).
#[tokio::test]
async fn a_search_scoped_diff_reads_via_find_by_rule_ids() {
    let stack = MockStack::with_rules(vec![json!({
        "rule_id": "hit",
        "name": "Suspicious Process",
        "type": "query",
    })])
    .await;
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "hit",
        "{\"rule_id\":\"hit\",\"name\":\"Suspicious Process\",\"type\":\"query\"}\n",
    );

    let report = state::diff(
        stack.transport(),
        dir.path(),
        &[],
        None,
        Some("process"),
        RuleSource::Custom,
    )
    .await
    .unwrap();

    assert_eq!(report.selected, Some(1));
    assert_eq!(report.local, 1, "the local side is narrowed too");

    let scoped_read = stack.requests().await.into_iter().any(|r| {
        r.path.ends_with("/_find")
            && r.query
                .get("filter")
                .is_some_and(|f| f.as_str() == "alert.attributes.params.ruleId: \"hit\"")
    });
    assert!(
        scoped_read,
        "a search-scoped read must use find_by_rule_ids, not a corpus read"
    );
}

/// An Added change applies as one create request.
#[tokio::test]
async fn apply_push_issues_a_create_for_an_added_rule() {
    let stack = MockStack::with_rules(vec![]).await;
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "a",
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\"}\n",
    );

    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    assert_eq!(plan.summary.pending, 1);

    state::apply_push(stack.transport(), plan).await.unwrap();

    assert_eq!(
        stack.write_paths().await,
        vec!["POST /api/detection_engine/rules".to_string()],
        "an Added change issues one create request"
    );
}

/// A Modified change applies as one update request.
#[tokio::test]
async fn apply_push_issues_an_update_for_a_modified_rule() {
    let stack = MockStack::with_rules(vec![json!({
        "rule_id": "a",
        "name": "A",
        "type": "query",
        "risk_score": 21,
        "severity": "low",
    })])
    .await;
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "a",
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\",\"risk_score\":99,\"severity\":\"low\"}\n",
    );

    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    assert_eq!(plan.summary.pending, 1);

    state::apply_push(stack.transport(), plan).await.unwrap();

    assert_eq!(
        stack.write_paths().await,
        vec!["PUT /api/detection_engine/rules".to_string()],
        "a Modified change issues one update request"
    );
}

/// Push never deletes: a remote-only rule is reported but not written.
#[tokio::test]
async fn apply_push_issues_no_request_for_a_remote_only_rule() {
    let stack = MockStack::with_rules(vec![json!({
        "rule_id": "remote",
        "name": "Remote",
        "type": "query",
    })])
    .await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("rules")).unwrap();

    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    assert_eq!(plan.summary.skipped_remote_only, 1);

    state::apply_push(stack.transport(), plan).await.unwrap();

    assert!(
        stack.write_requests().await.is_empty(),
        "push never deletes a remote-only rule"
    );
}

/// A per-rule failure lands in that entry's error and the loop continues.
#[tokio::test]
async fn apply_push_records_a_per_rule_failure_and_continues() {
    let stack = MockStack::with_rules(vec![]).await;
    let dir = tempfile::tempdir().unwrap();
    for id in ["a", "b"] {
        write_local_rule(
            dir.path(),
            id,
            &format!("{{\"rule_id\":\"{id}\",\"name\":\"{id}\",\"type\":\"query\"}}\n"),
        );
    }

    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    assert_eq!(plan.summary.pending, 2);

    let applied = state::apply_push(stack.transport(), plan).await.unwrap();

    // The mock answers no POST, so each create fails; both must be attempted.
    assert_eq!(
        stack.write_paths().await.len(),
        2,
        "the loop must continue after a per-rule failure"
    );
    assert_eq!(applied.summary.failed, 2);
    assert!(
        applied.summary.pending == 0,
        "nothing is left pending after apply"
    );
    assert!(
        applied.report.entries.iter().all(|e| e.error.is_some()),
        "every failed create records an error"
    );
}

/// A local mirror with one rule referencing a NEW list that has one item.
fn mirror_with_rule_and_new_list() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("r.ndjson"),
        format!(
            "{}\n",
            json!({
                "rule_id": "r", "name": "R", "type": "query",
                "exceptions_list": [{
                    "list_id": "newlist", "type": "detection", "namespace_type": "single"
                }]
            })
        ),
    )
    .unwrap();
    let exceptions = dir.path().join("exceptions");
    std::fs::create_dir_all(&exceptions).unwrap();
    std::fs::write(
        exceptions.join("newlist.ndjson"),
        format!(
            "{}\n",
            json!({
                "list_id": "newlist", "type": "detection", "name": "newlist",
                "namespace_type": "single",
                "items": [{
                    "item_id": "i1", "list_id": "newlist", "type": "simple",
                    "name": "item i1", "namespace_type": "single", "entries": []
                }]
            })
        ),
    )
    .unwrap();
    dir
}

/// A local mirror with one rule whose `rule_default` list is inlined in the
/// rule file, exactly as `pull` writes it.
fn mirror_with_rule_default_list() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("r.ndjson"),
        format!(
            "{}\n{}\n",
            json!({
                "rule_id": "r", "name": "R", "type": "query",
                "exceptions_list": [{
                    "list_id": "rd", "type": "rule_default", "namespace_type": "single"
                }]
            }),
            json!({
                "list_id": "rd", "type": "rule_default", "name": "list rd",
                "namespace_type": "single",
                "items": [{
                    "item_id": "i1", "list_id": "rd", "type": "simple",
                    "name": "item i1", "namespace_type": "single", "entries": []
                }]
            })
        ),
    )
    .unwrap();
    dir
}

/// Spec 5.4: the mirror closes over the lists the scoped rules reference.
#[tokio::test]
async fn pull_writes_the_referenced_lists_and_no_others() {
    let stack = mock_stack_with_rule_referencing("shared").await;
    let dir = tempfile::tempdir().unwrap();
    let r = state::pull(
        stack.transport(),
        dir.path(),
        Format::Yaml,
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();

    assert_eq!(r.exception_lists, 1, "only the referenced list is mirrored");
    assert!(dir.path().join("exceptions/shared.yaml").exists());
    assert!(
        !dir.path().join("exceptions/orphan.yaml").exists(),
        "an unreferenced list is not part of a rules-as-code mirror"
    );
}

/// Pull reports the operator's spelling rather than the resolved lock path.
#[tokio::test]
async fn requested_pull_path_is_preserved() {
    let stack = mock_stack_with_rule_referencing("shared").await;
    let dir = tempfile::tempdir().unwrap();
    let mirror = dir.path().join("mirror");
    std::fs::create_dir(&mirror).unwrap();
    let requested = mirror.join(".");

    let report = state::pull(
        stack.transport(),
        &requested,
        Format::Yaml,
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();

    assert_eq!(report.dir, requested.join("rules").display().to_string());
}

/// Pull replaces only the planned files. A scoped update must not infer that
/// files outside its selection, local notes, or unrelated exception lists are
/// stale and delete them.
#[tokio::test]
async fn a_scoped_pull_preserves_every_unplanned_mirror_path() {
    let stack = MockStack::with_rules(vec![json!({
        "rule_id": "selected",
        "name": "Selected",
        "type": "query",
        "risk_score": 42,
    })])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules");
    let exceptions = dir.path().join("exceptions");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::create_dir_all(&exceptions).unwrap();
    std::fs::write(rules.join("selected.ndjson"), b"old selected\n").unwrap();
    std::fs::write(rules.join("unselected.ndjson"), b"keep rule\n").unwrap();
    std::fs::write(exceptions.join("unrelated.ndjson"), b"keep exception\n").unwrap();
    std::fs::write(dir.path().join("README.md"), b"operator note\n").unwrap();
    let selectors = vec!["selected".to_string()];

    state::pull(
        stack.transport(),
        dir.path(),
        Format::Ndjson,
        &selectors,
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();

    assert_ne!(
        std::fs::read(rules.join("selected.ndjson")).unwrap(),
        b"old selected\n"
    );
    assert_eq!(
        std::fs::read(rules.join("unselected.ndjson")).unwrap(),
        b"keep rule\n"
    );
    assert_eq!(
        std::fs::read(exceptions.join("unrelated.ndjson")).unwrap(),
        b"keep exception\n"
    );
    assert_eq!(
        std::fs::read(dir.path().join("README.md")).unwrap(),
        b"operator note\n"
    );
}

/// Spec 5.4: a rule_default list belongs to one rule and lives in its file.
#[tokio::test]
async fn a_rule_default_list_is_inlined_in_its_rule_file() {
    let stack = mock_stack_with_rule_default_list().await;
    let dir = tempfile::tempdir().unwrap();
    state::pull(
        stack.transport(),
        dir.path(),
        Format::Yaml,
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();
    let rule_file = std::fs::read_to_string(dir.path().join("rules/r.yaml")).unwrap();
    assert!(rule_file.contains("rule_default"), "{rule_file}");
    assert!(
        !dir.path().join("exceptions").join("rd.yaml").exists(),
        "a rule_default list gets no file of its own"
    );
}

/// A rule_default list's items are preserved inline, not dropped with the file.
#[tokio::test]
async fn pull_inlines_a_rule_default_lists_items() {
    let stack = mock_stack_with_rule_default_list().await;
    let dir = tempfile::tempdir().unwrap();
    state::pull(
        stack.transport(),
        dir.path(),
        Format::Yaml,
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();
    let rule_file = std::fs::read_to_string(dir.path().join("rules/r.yaml")).unwrap();
    assert!(
        rule_file.contains("i1"),
        "the rule_default item must be inlined, not lost: {rule_file}"
    );
}

/// Spec 5.4: the existing collision contract extends to lists, including the
/// single/agnostic pair that shares a list_id.
#[tokio::test]
async fn a_single_and_an_agnostic_list_sharing_a_list_id_are_refused() {
    let stack = mock_stack_with_colliding_namespaces("dup").await;
    let dir = tempfile::tempdir().unwrap();
    let err = state::pull(
        stack.transport(),
        dir.path(),
        Format::Yaml,
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);
    assert!(err.message.contains("dup"), "{}", err.message);
    assert!(
        !dir.path().join("exceptions").exists(),
        "no exception file is written before every filename is planned"
    );
    assert!(
        !dir.path().join("rules").exists(),
        "no rule file is written before every filename is planned"
    );
}

/// Spec 5.4: containers before items before rules, always.
#[tokio::test]
async fn push_creates_the_list_before_the_rule_that_points_at_it() {
    let stack = mock_empty_stack().await;
    let dir = mirror_with_rule_and_new_list();
    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    state::apply_push(stack.transport(), plan).await.unwrap();

    let order = stack.write_paths().await;
    let list_at = order
        .iter()
        .position(|p| p.contains("exception_lists"))
        .unwrap();
    let rule_at = order
        .iter()
        .position(|p| p.contains("detection_engine/rules"))
        .unwrap();
    assert!(
        list_at < rule_at,
        "a rule must never precede its list: {order:?}"
    );
}

/// Spec 5.4: items for a new container are written before the rule too.
#[tokio::test]
async fn push_creates_the_items_before_the_rule() {
    let stack = mock_empty_stack().await;
    let dir = mirror_with_rule_and_new_list();
    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    state::apply_push(stack.transport(), plan).await.unwrap();

    let order = stack.write_paths().await;
    let list_at = order
        .iter()
        .position(|p| p.contains("exception_lists"))
        .unwrap();
    let item_at = order
        .iter()
        .position(|p| p.contains("exception_lists/items"))
        .unwrap();
    let rule_at = order
        .iter()
        .position(|p| p.contains("detection_engine/rules"))
        .unwrap();
    assert!(
        list_at < item_at && item_at < rule_at,
        "order must be container, item, rule: {order:?}"
    );
}

/// Measured fact 3: `id` is required and unvalidated. Push must supply the
/// target stack's id, not the one the file was pulled with, for every reference
/// the rule carries.
#[tokio::test]
async fn push_injects_the_target_stacks_list_id() {
    let stack = mock_stack_with_two_list_ids().await;
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("r.ndjson"),
        "{\"rule_id\":\"r\",\"name\":\"R\",\"type\":\"query\",\"exceptions_list\":[\
         {\"list_id\":\"one\",\"type\":\"detection\",\"namespace_type\":\"single\"},\
         {\"list_id\":\"two\",\"type\":\"detection\",\"namespace_type\":\"single\"}]}\n",
    )
    .unwrap();
    let exceptions = dir.path().join("exceptions");
    std::fs::create_dir_all(&exceptions).unwrap();
    for list in ["one", "two"] {
        std::fs::write(
            exceptions.join(format!("{list}.ndjson")),
            format!(
                "{}\n",
                json!({
                    "list_id": list, "type": "detection",
                    "name": format!("list {list}"), "namespace_type": "single"
                })
            ),
        )
        .unwrap();
    }

    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    state::apply_push(stack.transport(), plan).await.unwrap();

    let body = stack.last_rule_write_body().await;
    assert_eq!(
        body["exceptions_list"][0]["id"],
        json!("id-one"),
        "every reference's pointer is resolved against the target"
    );
    assert_eq!(
        body["exceptions_list"][1]["id"],
        json!("id-two"),
        "injection must not stop after the first reference"
    );
}

/// A rule referencing a list that is neither on the stack nor in the mirror is
/// refused at plan time, before any write, never given a fabricated pointer.
#[tokio::test]
async fn push_refuses_a_rule_referencing_a_list_that_is_nowhere() {
    let stack = MockStack::with_rules(vec![]).await;
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("r.ndjson"),
        "{\"rule_id\":\"r\",\"name\":\"R\",\"type\":\"query\",\"exceptions_list\":[{\"list_id\":\"ghost\",\"type\":\"detection\",\"namespace_type\":\"single\"}]}\n",
    )
    .unwrap();

    let err = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::NotFound);
    assert!(err.message.contains("ghost"), "{}", err.message);
    assert!(
        stack.write_requests().await.is_empty(),
        "the refusal must happen before any write"
    );
}

/// When an exception write fails after earlier writes succeeded, `apply_push`
/// returns the plan with the evidence, not a bare error that discards it.
#[tokio::test]
async fn apply_push_returns_the_plan_when_an_exception_write_fails() {
    let stack = mock_stack_with_failing_item_create().await;
    let dir = mirror_with_rule_and_new_list();
    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();

    let applied = state::apply_push(stack.transport(), plan).await.unwrap();

    assert_eq!(applied.summary.lists_created, 1, "the container succeeded");
    assert_eq!(applied.summary.items_created, 0, "the item failed");
    assert_eq!(applied.summary.failed, 1, "the item failure is recorded");
    assert_eq!(
        applied.summary.pending, 1,
        "the rule was never written after the item failure"
    );
    let created_list = applied
        .report
        .entries
        .iter()
        .find(|entry| entry.action == "create_list")
        .expect("the successful container write is recorded before the item failure");
    assert!(created_list.applied);
    assert!(created_list.error.is_none());
    assert!(created_list.after.is_some());
    assert!(
        applied
            .report
            .entries
            .iter()
            .any(|e| e.action == "create_item"
                && e.error.as_deref().unwrap_or("").contains("failed")),
        "the change ticket records the failed item: {:?}",
        applied.report.entries
    );
}

/// Spec 5.4: the banner names rule, list, and item counts. A push that changed
/// exceptions while the banner spoke only of rules would defeat the guard.
#[tokio::test]
async fn the_push_preview_names_the_exception_counts() {
    let stack = mock_empty_stack().await;
    let dir = mirror_with_rule_and_new_list();
    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    assert!(
        plan.preview_action.contains("1 exception list(s)"),
        "the banner must name the list it will create: {}",
        plan.preview_action
    );
    assert!(
        plan.preview_action.contains("1 item(s)"),
        "the banner must name the item it will create: {}",
        plan.preview_action
    );
}

/// Spec 5.4: a remote-only container is reported and left alone.
#[tokio::test]
async fn push_never_deletes_a_container_absent_locally() {
    let stack = mock_stack_with_list_id("orphan", "id").await;
    let dir = tempfile::tempdir().unwrap();
    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    state::apply_push(stack.transport(), plan).await.unwrap();
    assert!(
        !stack
            .write_paths()
            .await
            .iter()
            .any(|p| p.starts_with("DELETE")),
        "push never deletes a container"
    );
}

#[tokio::test]
async fn diff_reports_an_added_exception_list() {
    let stack = mock_empty_stack().await;
    let dir = mirror_with_rule_and_new_list();

    let report = state::diff(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();

    assert!(!report.clean);
    assert_eq!(report.exceptions.local, 1);
    assert_eq!(report.exceptions.remote, 0);
    assert_eq!(
        report.exceptions.changes,
        vec![ListChange::Added {
            list_id: "newlist".into(),
            name: "newlist".into(),
        }]
    );
}

#[tokio::test]
async fn diff_reports_a_modified_exception_list() {
    let stack = mock_stack_with_rule_referencing("shared").await;
    let dir = mirror_with_rule_referencing("shared");
    let path = dir.path().join("exceptions/shared.ndjson");
    let mut local: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    local["description"] = json!("local description");
    std::fs::write(&path, format!("{local}\n")).unwrap();

    let report = state::diff(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();

    assert!(!report.clean);
    assert_eq!(
        report.exceptions.changes,
        vec![ListChange::Modified {
            list_id: "shared".into(),
            name: "list shared".into(),
            fields: vec![FieldChange {
                field: "description".into(),
                before: Value::Null,
                after: json!("local description"),
            }],
        }]
    );
}

/// A container referenced by a remote rule but absent locally is reported as
/// RemoteOnly and never deleted.
#[tokio::test]
async fn diff_reports_a_remote_only_exception_list_without_planning_a_delete() {
    let stack = mock_stack_with_rule_referencing("shared").await;
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    // The rule matches the remote one; only the list file is absent.
    std::fs::write(
        rules.join("r.ndjson"),
        "{\"rule_id\":\"r\",\"name\":\"R\",\"type\":\"query\",\"exceptions_list\":[{\"list_id\":\"shared\",\"type\":\"detection\",\"namespace_type\":\"single\"}]}\n",
    )
    .unwrap();

    let report = state::diff(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();
    assert!(!report.clean);
    assert_eq!(
        report.exceptions.changes,
        vec![ListChange::RemoteOnly {
            list_id: "shared".into(),
            name: "list shared".into(),
        }]
    );

    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    assert_eq!(plan.summary.items_removed, 0);
    assert!(stack.write_requests().await.is_empty());
}

/// A YAML pull must read back clean: the rule and its exception file round-trip
/// through `read_mirror`.
#[tokio::test]
async fn pull_then_diff_in_yaml_is_clean() {
    let stack = mock_stack_with_rule_referencing("shared").await;
    let dir = tempfile::tempdir().unwrap();
    state::pull(
        stack.transport(),
        dir.path(),
        Format::Yaml,
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();
    let d = state::diff(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();
    assert!(
        d.clean,
        "a fresh YAML pull must diff clean: {:?}",
        d.exceptions
    );
    assert_eq!(d.exceptions.local, 1, "the exception file was read back");
    assert_eq!(d.exceptions.remote, 1);
}

/// A `rule_default` list is an ordinary container: pull then diff against the
/// same stack must read clean, not report permanent fake drift.
#[tokio::test]
async fn pull_then_diff_is_clean_with_a_rule_default_list() {
    let stack = mock_stack_with_rule_default_list().await;
    let dir = tempfile::tempdir().unwrap();
    state::pull(
        stack.transport(),
        dir.path(),
        Format::Yaml,
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();
    let d = state::diff(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();
    assert!(
        d.clean,
        "a rule_default list must round-trip clean: {:?}",
        d.exceptions
    );
    assert_eq!(d.exceptions.local, 1);
    assert_eq!(d.exceptions.remote, 1);
    assert!(d.exceptions.is_clean());
    assert!(d.changes.is_empty());
}

/// A `rule_default` list is created like any other container before the rule
/// that references it.
#[tokio::test]
async fn push_creates_a_rule_default_list_on_a_fresh_stack() {
    let stack = mock_empty_stack().await;
    let dir = mirror_with_rule_default_list();
    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    state::apply_push(stack.transport(), plan).await.unwrap();

    let requests = stack.write_requests().await;
    let container_at = requests
        .iter()
        .position(|r| r.path == "/api/exception_lists")
        .unwrap();
    let rule_at = requests
        .iter()
        .position(|r| r.path == "/api/detection_engine/rules")
        .unwrap();
    assert!(
        container_at < rule_at,
        "the container is created before the rule that references it: {requests:?}"
    );
    assert_eq!(
        requests[container_at].body["type"],
        json!("rule_default"),
        "a rule_default list is created like any other container"
    );
}

/// A rule file produced by `rules export` carries a trailer; `read_mirror`
/// must tolerate it rather than hard-error.
#[tokio::test]
async fn read_mirror_tolerates_an_export_trailer_in_a_rule_file() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("r.ndjson"),
        "{\"rule_id\":\"r\",\"name\":\"R\",\"type\":\"query\"}\n\
         {\"exported_count\":1,\"exported_rules_count\":1,\"missing_rules\":[],\"missing_rules_count\":0}\n",
    )
    .unwrap();

    let mirror = state::read_mirror(dir.path()).unwrap();
    assert_eq!(mirror.rules.len(), 1, "the rule is read");
    assert_eq!(mirror.rules[0].rule_id().unwrap(), "r");
}

/// A symlinked `rules` directory could read rules from outside the mirror, so
/// it must be refused rather than followed.
#[cfg(unix)]
#[test]
fn read_mirror_refuses_a_symlinked_rules_directory() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(external.path().join("rules")).unwrap();
    std::fs::write(
        external.path().join("rules/a.ndjson"),
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\"}\n",
    )
    .unwrap();
    symlink(external.path().join("rules"), dir.path().join("rules")).unwrap();

    let err = state::read_mirror(dir.path()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Error);
    assert!(
        err.message.contains("not a real directory"),
        "{}",
        err.message
    );
}

/// A recognized rule file that is actually a symlink could escape the mirror,
/// so it must be refused rather than followed.
#[cfg(unix)]
#[test]
fn read_mirror_refuses_a_symlinked_rule_file() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    let external = tempfile::tempdir().unwrap();
    std::fs::write(
        external.path().join("a.ndjson"),
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\"}\n",
    )
    .unwrap();
    symlink(external.path().join("a.ndjson"), rules.join("a.ndjson")).unwrap();

    let err = state::read_mirror(dir.path()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Error);
    assert!(
        err.message.contains("not a regular file"),
        "{}",
        err.message
    );
}

/// An escaped mirror must fail `plan_push` before any write is issued.
#[cfg(unix)]
#[tokio::test]
async fn a_symlinked_rule_file_blocks_push_before_any_write() {
    use std::os::unix::fs::symlink;
    let stack = MockStack::with_rules(vec![]).await;
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    let external = tempfile::tempdir().unwrap();
    std::fs::write(
        external.path().join("a.ndjson"),
        "{\"rule_id\":\"a\",\"name\":\"A\",\"type\":\"query\"}\n",
    )
    .unwrap();
    symlink(external.path().join("a.ndjson"), rules.join("a.ndjson")).unwrap();

    let err = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind, ErrorKind::Error);
    assert!(
        stack.write_requests().await.is_empty(),
        "an escaped mirror must issue no POST, PUT, or DELETE"
    );
}

/// A local mirror with a rule `r` referencing `list_id` and the container file
/// itself, so the list is present on both sides of the diff.
fn mirror_with_rule_referencing(list_id: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "r",
        &format!(
            "{}\n",
            json!({
                "rule_id": "r", "name": "R", "type": "query",
                "exceptions_list": [{
                    "list_id": list_id, "type": "detection", "namespace_type": "single"
                }]
            })
        ),
    );
    let exceptions = dir.path().join("exceptions");
    std::fs::create_dir_all(&exceptions).unwrap();
    std::fs::write(
        exceptions.join(format!("{list_id}.ndjson")),
        format!(
            "{}\n",
            json!({
                "list_id": list_id, "type": "detection",
                "name": format!("list {list_id}"), "namespace_type": "single"
            })
        ),
    )
    .unwrap();
    dir
}

/// A local mirror with a rule `r` referencing `list_id` and the container
/// holding exactly `item_ids`.
fn mirror_with_list_items(list_id: &str, item_ids: &[&str]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "r",
        &format!(
            "{}\n",
            json!({
                "rule_id": "r", "name": "R", "type": "query",
                "exceptions_list": [{
                    "list_id": list_id, "type": "detection", "namespace_type": "single"
                }]
            })
        ),
    );
    let exceptions = dir.path().join("exceptions");
    std::fs::create_dir_all(&exceptions).unwrap();
    std::fs::write(
        exceptions.join(format!("{list_id}.ndjson")),
        format!(
            "{}\n",
            json!({
                "list_id": list_id, "type": "detection",
                "name": format!("list {list_id}"), "namespace_type": "single",
                "items": item_ids.iter().map(|id| json!({
                    "item_id": id, "list_id": list_id, "type": "simple",
                    "name": format!("item {id}"), "namespace_type": "single", "entries": []
                })).collect::<Vec<_>>()
            })
        ),
    )
    .unwrap();
    dir
}

/// A local mirror whose exception item references a value list, the entry type
/// that requires the value-list data streams (spec 7.7). The value list id is
/// caller-supplied and stable, so it round-trips without resolution.
fn mirror_with_item_referencing_value_list(value_list_id: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "r",
        &format!(
            "{}\n",
            json!({
                "rule_id": "r", "name": "R", "type": "query",
                "exceptions_list": [{
                    "list_id": "detect", "type": "detection", "namespace_type": "single"
                }]
            })
        ),
    );
    let exceptions = dir.path().join("exceptions");
    std::fs::create_dir_all(&exceptions).unwrap();
    std::fs::write(
        exceptions.join("detect.ndjson"),
        format!(
            "{}\n",
            json!({
                "list_id": "detect", "type": "detection", "name": "detect",
                "namespace_type": "single",
                "items": [{
                    "item_id": "i1", "list_id": "detect", "type": "simple",
                    "name": "item i1", "namespace_type": "single",
                    "entries": [{
                        "field": "source.ip", "operator": "included", "type": "list",
                        "list": {"id": value_list_id, "type": "ip"}
                    }]
                }]
            })
        ),
    )
    .unwrap();
    dir
}

/// An absent value list is reported, never silently pushed (spec 7.7).
#[tokio::test]
async fn push_reports_an_exception_entry_referencing_an_absent_value_list() {
    let stack = MockStack::with_value_lists_absent().await;
    let dir = mirror_with_item_referencing_value_list("ip-allowlist");
    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    assert!(
        plan.preview_details
            .iter()
            .any(|d| d.contains("ip-allowlist")),
        "{:?}",
        plan.preview_details
    );
}

/// The check must actually query the stack: when the data streams exist, the
/// line is absent, so a bootstrapped stack is not reported as broken.
#[tokio::test]
async fn push_is_silent_about_a_value_list_when_the_index_is_bootstrapped() {
    let stack = MockStack::with_value_lists(&["ip-allowlist"]).await;
    let dir = mirror_with_item_referencing_value_list("ip-allowlist");
    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    assert!(
        !plan
            .preview_details
            .iter()
            .any(|d| d.contains("ip-allowlist")),
        "{:?}",
        plan.preview_details
    );
}

/// A 200 index must still be validated: a missing measured field makes the
/// stack unverifiable, not silently absent.
#[tokio::test]
async fn malformed_value_list_index_response_fails_planning() {
    let stack = MockStack::with_value_list_index(json!({
        "list_index": true
    }))
    .await;
    let dir = mirror_with_item_referencing_value_list("ip-allowlist");

    let err = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind, ErrorKind::Http);
    assert!(err.message.contains("list_item_index"), "{}", err.message);
    assert!(stack.write_requests().await.is_empty());
}

/// A bootstrapped index alone does not prove that a referenced value list
/// exists; its id must be resolved through the public lookup route.
#[tokio::test]
async fn push_checks_a_missing_list_even_when_the_data_streams_exist() {
    let stack = MockStack::with_value_lists(&[]).await;
    let dir = mirror_with_item_referencing_value_list("missing");
    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();

    assert!(
        plan.preview_details
            .iter()
            .any(|line| line.contains("missing")),
        "{:?}",
        plan.preview_details
    );
}

fn mirror_with_selected_and_unselected_value_list_refs() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "r1",
        &format!(
            "{}\n",
            json!({
                "rule_id": "r1", "name": "R1", "type": "query",
                "exceptions_list": [{
                    "list_id": "detect-a", "type": "detection", "namespace_type": "single"
                }]
            })
        ),
    );
    write_local_rule(
        dir.path(),
        "r2",
        &format!(
            "{}\n",
            json!({
                "rule_id": "r2", "name": "R2", "type": "query",
                "exceptions_list": [{
                    "list_id": "detect-b", "type": "detection", "namespace_type": "single"
                }]
            })
        ),
    );
    let exceptions = dir.path().join("exceptions");
    std::fs::create_dir_all(&exceptions).unwrap();
    for (list_id, item_id, value_list_id) in [
        ("detect-a", "i1", "ip-allowlist"),
        ("detect-b", "i2", "dns-allowlist"),
    ] {
        std::fs::write(
            exceptions.join(format!("{list_id}.ndjson")),
            format!(
                "{}\n",
                json!({
                    "list_id": list_id, "type": "detection", "name": list_id,
                    "namespace_type": "single",
                    "items": [{
                        "item_id": item_id, "list_id": list_id, "type": "simple",
                        "name": item_id, "namespace_type": "single",
                        "entries": [{
                            "field": "source.ip", "operator": "included", "type": "list",
                            "list": {"id": value_list_id, "type": "ip"}
                        }]
                    }]
                })
            ),
        )
        .unwrap();
    }
    dir
}

/// Scoped planning only reads value lists reached through selected rules, so
/// an unrelated broken reference cannot block or warn on this push.
#[tokio::test]
async fn scoped_push_checks_each_reachable_value_list_once() {
    let stack = MockStack::with_value_lists(&["ip-allowlist", "dns-allowlist"]).await;
    let dir = mirror_with_selected_and_unselected_value_list_refs();
    state::plan_push(
        stack.transport(),
        dir.path(),
        &["r1".into()],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();

    assert_eq!(stack.value_list_lookups("ip-allowlist").await, 1);
    assert_eq!(stack.value_list_lookups("dns-allowlist").await, 0);
}

/// Public exception drift is part of `DiffReport`, not only the push preview.
#[tokio::test]
async fn diff_reports_an_added_exception_item() {
    let stack = mock_stack_with_list_and_items("l", &[]).await;
    let dir = mirror_with_list_items("l", &["new"]);

    let report = state::diff(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();

    assert!(!report.clean);
    assert_eq!(
        report.exceptions.changes,
        vec![
            ListChange::Unchanged {
                list_id: "l".into(),
            },
            ListChange::ItemAdded {
                list_id: "l".into(),
                item_id: "new".into(),
            },
        ]
    );
}

#[tokio::test]
async fn diff_reports_a_modified_exception_item() {
    let stack = mock_stack_with_list_and_items("l", &["keep"]).await;
    let dir = mirror_with_list_items("l", &["keep"]);
    let path = dir.path().join("exceptions/l.ndjson");
    let mut local: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let entries = json!([{
        "field": "host.name",
        "type": "match",
        "operator": "included",
        "value": ["changed"]
    }]);
    local["items"][0]["entries"] = entries.clone();
    std::fs::write(&path, format!("{local}\n")).unwrap();

    let report = state::diff(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();

    assert!(!report.clean);
    assert_eq!(
        report.exceptions.changes,
        vec![
            ListChange::Unchanged {
                list_id: "l".into(),
            },
            ListChange::ItemModified {
                list_id: "l".into(),
                item_id: "keep".into(),
                fields: vec![FieldChange {
                    field: "entries".into(),
                    before: json!([]),
                    after: entries,
                }],
            },
        ]
    );
}

#[tokio::test]
async fn diff_reports_a_removed_exception_item() {
    let stack = mock_stack_with_list_and_items("l", &["keep", "drop"]).await;
    let dir = mirror_with_list_items("l", &["keep"]);

    let report = state::diff(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();

    assert!(!report.clean);
    assert_eq!(
        report.exceptions.changes,
        vec![
            ListChange::Unchanged {
                list_id: "l".into(),
            },
            ListChange::ItemRemoved {
                list_id: "l".into(),
                item_id: "drop".into(),
            },
        ]
    );

    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    assert!(
        plan.preview_action.contains("1 item deletion(s)"),
        "{}",
        plan.preview_action
    );
    assert_eq!(plan.summary.items_removed, 0, "the plan has not applied it");
    assert!(stack.write_requests().await.is_empty());
}

/// Spec 5.4. The single delete path in the tool's state engine.
#[tokio::test]
async fn an_item_absent_locally_is_deleted() {
    let stack = mock_stack_with_list_and_items("l", &["keep", "drop"]).await;
    let dir = mirror_with_list_items("l", &["keep"]);
    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();

    assert!(
        plan.preview_details
            .iter()
            .any(|d| d.contains("drop") && d.contains("delete")),
        "the preview must name the deletion: {:?}",
        plan.preview_details
    );

    let applied = state::apply_push(stack.transport(), plan).await.unwrap();
    let deletes = stack.deleted_item_ids().await;
    assert_eq!(deletes, vec!["drop"], "only the absent item is deleted");
    let entry = applied
        .report
        .entries
        .iter()
        .find(|entry| entry.action == "delete_item")
        .expect("the successful item deletion is recorded");
    assert_eq!(entry.rule_id, "drop");
    assert!(entry.applied);
    assert!(entry.before.is_some());
    assert!(entry.after.is_none());
    assert!(entry.error.is_none());
}

/// A standalone export item without a list identity must not make the valid
/// mirrored list look empty and therefore authorize a remote item removal.
#[tokio::test]
async fn malformed_top_level_exception_item_cannot_plan_remote_deletion() {
    let stack = mock_stack_with_list_and_items("l", &["drop"]).await;
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "r",
        concat!(
            "{\"rule_id\":\"r\",\"name\":\"R\",\"type\":\"query\",\"exceptions_list\":[{\"id\":\"id-l\",\"list_id\":\"l\",\"type\":\"detection\",\"namespace_type\":\"single\"}]}\n",
            "{\"id\":\"id-l\",\"list_id\":\"l\",\"type\":\"detection\",\"name\":\"list l\",\"namespace_type\":\"single\"}\n",
            "{\"item_id\":\"orphan\",\"type\":\"simple\",\"namespace_type\":\"single\",\"entries\":[]}\n",
        ),
    );

    let error = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind, ErrorKind::Error);
    assert!(error.message.contains("list_id"), "{}", error.message);
    assert!(
        !stack
            .requests()
            .await
            .iter()
            .any(|request| request.path == "/api/exception_lists/items/_find"),
        "malformed input must stop before exception-item reconciliation"
    );
    assert!(
        stack.write_requests().await.is_empty(),
        "malformed input must issue no POST, PUT, or DELETE"
    );
}

#[tokio::test]
async fn push_refuses_a_non_array_items_field_before_any_item_delete() {
    let stack = mock_stack_with_list_and_items("l", &["keep", "drop"]).await;
    let dir = mirror_with_list_items("l", &[]);
    std::fs::write(
        dir.path().join("exceptions/l.ndjson"),
        format!(
            "{}\n",
            json!({
                "list_id": "l", "type": "detection", "name": "list l",
                "namespace_type": "single", "items": {"unexpected": true}
            })
        ),
    )
    .unwrap();

    let error = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind, ErrorKind::Error);
    assert!(error.message.contains("items"), "{}", error.message);
    assert!(error.message.contains("array"), "{}", error.message);
    assert!(stack.deleted_item_ids().await.is_empty());
    assert!(stack.write_requests().await.is_empty());
}

#[tokio::test]
async fn push_refuses_a_multi_record_exception_file_before_any_item_delete() {
    let stack = mock_stack_with_list_and_items("l", &["keep", "drop"]).await;
    let dir = mirror_with_list_items("l", &[]);
    std::fs::write(
        dir.path().join("exceptions/l.ndjson"),
        format!(
            "{}\n{}\n",
            json!({
                "list_id": "l", "type": "detection", "name": "list l",
                "namespace_type": "single", "items": []
            }),
            json!({
                "item_id": "ignored", "list_id": "l", "type": "simple",
                "namespace_type": "single", "entries": []
            })
        ),
    )
    .unwrap();

    let error = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind, ErrorKind::Error);
    assert!(error.message.contains("one"), "{}", error.message);
    assert!(stack.deleted_item_ids().await.is_empty());
    assert!(stack.write_requests().await.is_empty());
}

/// The asymmetry must hold in the same run: items reconcile, containers do not.
#[tokio::test]
async fn a_container_absent_locally_survives_a_run_that_deletes_an_item() {
    let stack = mock_stack_with_two_lists_one_mirrored().await;
    let dir = mirror_with_list_items("mirrored", &[]);
    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    state::apply_push(stack.transport(), plan).await.unwrap();

    // The fixture must actually delete an item, or the "no container deleted"
    // assertion below proves nothing: deletion has to be possible for its
    // absence to mean anything.
    assert_eq!(
        stack.deleted_item_ids().await,
        vec!["drop"],
        "the run deletes an item, so the container check is discriminating"
    );
    assert!(
        !stack
            .deleted_list_ids()
            .await
            .contains(&"unmirrored".to_string()),
        "an unmirrored container is never deleted"
    );
}

/// A dry run deletes nothing, including items.
#[tokio::test]
async fn planning_an_item_deletion_deletes_nothing() {
    let stack = mock_stack_with_list_and_items("l", &["drop"]).await;
    let dir = mirror_with_list_items("l", &[]);
    state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    assert!(stack.deleted_item_ids().await.is_empty());
}

/// Spec 4.5: the server does not catch a dangling pointer, so diff does.
/// The check runs on the RAW remote rule, because `comparable` has already
/// stripped the pointer by the time drift is computed.
#[tokio::test]
async fn diff_reports_a_rule_pointing_at_the_wrong_container_id() {
    let stack =
        mock_stack_with_dangling_pointer("r", "shared", "00000000-0000-0000-0000-000000000000")
            .await;
    let dir = mirror_with_rule_referencing("shared");
    let d = state::diff(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();

    assert_eq!(d.exceptions.dangling.len(), 1);
    assert_eq!(d.exceptions.dangling[0].rule_id, "r");
    assert_eq!(d.exceptions.dangling[0].list_id, "shared");
    assert!(!d.clean, "a dangling pointer is drift");
}

#[tokio::test]
async fn a_pointer_matching_the_live_container_is_not_reported() {
    let stack = mock_stack_with_matching_pointer("r", "shared").await;
    let dir = mirror_with_rule_referencing("shared");
    let d = state::diff(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();
    assert!(d.exceptions.dangling.is_empty());
    assert!(d.clean);
}

/// Spec 4.5: `push` repairs a dangling pointer by rewriting the rule, even when
/// its normalized form is unchanged — the one change a normalized diff cannot
/// see.
#[tokio::test]
async fn push_rewrites_a_rule_whose_pointer_is_wrong() {
    let stack =
        mock_stack_with_dangling_pointer("r", "shared", "00000000-0000-0000-0000-000000000000")
            .await;
    let dir = mirror_with_rule_referencing("shared");
    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    state::apply_push(stack.transport(), plan).await.unwrap();

    assert_eq!(
        stack.write_paths().await,
        vec!["PUT /api/detection_engine/rules".to_string()],
        "a wrong pointer is repaired with one rule update"
    );
    assert_eq!(
        stack.last_rule_write_body().await["exceptions_list"][0]["id"],
        json!("id-shared"),
        "the rewrite injects the live container id"
    );
}

/// Spec 5.4: an item added locally to an already-live container is created, so
/// a retry after a partial push re-converges instead of assuming a clean slate.
#[tokio::test]
async fn an_item_added_to_an_existing_container_is_created() {
    let stack = mock_stack_with_list_and_items("l", &[]).await;
    let dir = mirror_with_list_items("l", &["new"]);
    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    let applied = state::apply_push(stack.transport(), plan).await.unwrap();

    assert_eq!(
        applied.summary.items_created, 1,
        "the missing item is created into the existing container"
    );
    assert!(
        stack
            .write_paths()
            .await
            .contains(&"POST /api/exception_lists/items".to_string()),
        "the create is issued"
    );
    let exception_entries: Vec<_> = applied
        .report
        .entries
        .iter()
        .filter(|entry| entry.action.ends_with("_item"))
        .collect();
    assert_eq!(
        exception_entries.len(),
        1,
        "the exception-only write is evidenced"
    );
    let entry = exception_entries[0];
    assert_eq!(entry.action, "create_item");
    assert_eq!(entry.rule_id, "new");
    assert!(entry.applied);
    assert!(entry.before.is_none());
    assert!(entry.after.is_some());
    assert!(entry.error.is_none());
}

/// Spec 5.4: a modified item is updated, not left to drift.
#[tokio::test]
async fn a_modified_item_is_updated() {
    let stack = mock_stack_with_list_and_items("l", &["keep"]).await;
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "r",
        "{\"rule_id\":\"r\",\"name\":\"R\",\"type\":\"query\",\"exceptions_list\":[\
         {\"list_id\":\"l\",\"type\":\"detection\",\"namespace_type\":\"single\"}]}\n",
    );
    let exceptions = dir.path().join("exceptions");
    std::fs::create_dir_all(&exceptions).unwrap();
    std::fs::write(
        exceptions.join("l.ndjson"),
        format!(
            "{}\n",
            json!({
                "list_id": "l", "type": "detection", "name": "list l", "namespace_type": "single",
                "items": [{
                    "item_id": "keep", "list_id": "l", "type": "simple",
                    "name": "item keep", "namespace_type": "single",
                    "entries": [{"field": "host.name", "type": "match", "operator": "included", "value": ["x"]}]
                }]
            })
        ),
    )
    .unwrap();

    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    let applied = state::apply_push(stack.transport(), plan).await.unwrap();

    assert_eq!(
        applied.summary.items_updated, 1,
        "the item update succeeded"
    );
    assert!(
        stack
            .write_paths()
            .await
            .contains(&"PUT /api/exception_lists/items".to_string()),
        "a differing item is updated"
    );
    let entry = applied
        .report
        .entries
        .iter()
        .find(|entry| entry.action == "update_item")
        .expect("the successful item update is recorded");
    assert_eq!(entry.rule_id, "keep");
    assert!(entry.applied);
    assert!(entry.before.is_some());
    assert!(entry.after.is_some());
    assert!(entry.error.is_none());
}

/// A pull must refuse a missing referenced list before writing a partial
/// mirror.
#[tokio::test]
async fn pull_refuses_a_rule_referencing_a_list_that_does_not_exist() {
    let stack = MockStack::with_rules(vec![json!({
        "rule_id": "r",
        "name": "R",
        "type": "query",
        "exceptions_list": [{
            "list_id": "ghost", "type": "detection", "namespace_type": "single"
        }]
    })])
    .await;
    let dir = tempfile::tempdir().unwrap();

    let err = state::pull(
        stack.transport(),
        dir.path(),
        Format::Yaml,
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind, ErrorKind::NotFound);
    assert!(err.message.contains("ghost"), "{}", err.message);
    assert!(
        !dir.path().join("rules").exists(),
        "no mirror is written when a referenced list is missing"
    );
}

/// A rule referencing two wrong pointers is one rule, repaired once, not once
/// per pointer (spec 4.5). After a restore or stack rebuild every pointer is
/// wrong, so any multi-list rule hits this.
#[tokio::test]
async fn a_rule_with_two_wrong_pointers_is_repaired_once() {
    let stack = mock_stack_with_rule_with_two_wrong_pointers().await;
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "r",
        "{\"rule_id\":\"r\",\"name\":\"R\",\"type\":\"query\",\"exceptions_list\":[\
         {\"list_id\":\"one\",\"type\":\"detection\",\"namespace_type\":\"single\"},\
         {\"list_id\":\"two\",\"type\":\"detection\",\"namespace_type\":\"single\"}]}\n",
    );
    let exceptions = dir.path().join("exceptions");
    std::fs::create_dir_all(&exceptions).unwrap();
    for list in ["one", "two"] {
        std::fs::write(
            exceptions.join(format!("{list}.ndjson")),
            format!(
                "{}\n",
                json!({
                    "list_id": list, "type": "detection",
                    "name": format!("list {list}"), "namespace_type": "single"
                })
            ),
        )
        .unwrap();
    }

    let plan = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap();
    let applied = state::apply_push(stack.transport(), plan).await.unwrap();

    assert_eq!(applied.summary.updated, 1, "one rule, one update, not two");
    assert_eq!(
        stack.write_paths().await,
        vec!["PUT /api/detection_engine/rules".to_string()],
        "a rule with two wrong pointers is still one write"
    );
}

/// `live_id: None` is a distinct finding: no container with that `list_id`
/// exists on the stack. The pointer is reported, not collapsed onto a wrong id.
#[tokio::test]
async fn diff_reports_a_pointer_whose_container_is_missing() {
    let stack = MockStack::with_rules(vec![json!({
        "rule_id": "r",
        "name": "R",
        "type": "query",
        "exceptions_list": [{
            "id": "00000000-0000-0000-0000-000000000000",
            "list_id": "ghost", "type": "detection", "namespace_type": "single"
        }]
    })])
    .await;
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "r",
        "{\"rule_id\":\"r\",\"name\":\"R\",\"type\":\"query\",\"exceptions_list\":[\
         {\"list_id\":\"ghost\",\"type\":\"detection\",\"namespace_type\":\"single\"}]}\n",
    );

    let d = state::diff(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();

    assert_eq!(d.exceptions.dangling.len(), 1);
    assert_eq!(d.exceptions.dangling[0].list_id, "ghost");
    assert_eq!(d.exceptions.dangling[0].live_id, None);
    assert_eq!(
        d.exceptions.dangling[0].stored_id,
        json!("00000000-0000-0000-0000-000000000000")
    );
}

/// An unchanged rule referencing a list that exists nowhere now blocks the push
/// rather than being silently left dangling: the repair cannot resolve a live
/// id, so the refusal is the honest answer (spec 4.5).
#[tokio::test]
async fn push_refuses_an_unchanged_rule_referencing_a_nowhere_list() {
    let stack = MockStack::with_rules(vec![json!({
        "rule_id": "r",
        "name": "R",
        "type": "query",
        "exceptions_list": [{
            "id": "00000000-0000-0000-0000-000000000000",
            "list_id": "ghost", "type": "detection", "namespace_type": "single"
        }]
    })])
    .await;
    let dir = tempfile::tempdir().unwrap();
    write_local_rule(
        dir.path(),
        "r",
        "{\"rule_id\":\"r\",\"name\":\"R\",\"type\":\"query\",\"exceptions_list\":[\
         {\"list_id\":\"ghost\",\"type\":\"detection\",\"namespace_type\":\"single\"}]}\n",
    );

    let err = state::plan_push(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
        &identity(),
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind, ErrorKind::NotFound);
    assert!(err.message.contains("ghost"), "{}", err.message);
    assert!(
        stack.write_requests().await.is_empty(),
        "the refusal happens before any write"
    );
}

/// A corpus split by source: `custom` rules carry `immutable: false`, `prebuilt`
/// carry `immutable: true`. The mock's `_find` honors the filter, so a scoped
/// read returns only the matching slice.
async fn mock_mixed_corpus(custom: usize, prebuilt: usize) -> MockStack {
    let mut rules = Vec::with_capacity(custom + prebuilt);
    for i in 0..custom {
        rules.push(json!({
            "rule_id": format!("custom-{i}"),
            "name": format!("custom {i}"),
            "type": "query",
            "immutable": false,
        }));
    }
    for i in 0..prebuilt {
        rules.push(json!({
            "rule_id": format!("prebuilt-{i}"),
            "name": format!("prebuilt {i}"),
            "type": "query",
            "immutable": true,
        }));
    }
    MockStack::with_rules(rules).await
}

/// A mirror holding one prebuilt rule, as a 0.1 `state pull` would have written
/// it before `--source` existed.
fn mirror_holding_a_prebuilt_rule() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("prebuilt-0.ndjson"),
        "{\"rule_id\":\"prebuilt-0\",\"name\":\"prebuilt 0\",\"type\":\"query\",\"immutable\":true}\n",
    )
    .unwrap();
    dir
}

/// Spec 5.5: a `custom`-scoped pull returns only authored rules, while a
/// query with the default (all) filter hides nothing.
#[tokio::test]
async fn a_custom_pull_returns_only_authored_rules_while_the_default_filter_returns_all() {
    let stack = mock_mixed_corpus(/* custom */ 2, /* prebuilt */ 5).await;
    let dir = tempfile::tempdir().unwrap();

    let pulled = state::pull(
        stack.transport(),
        dir.path(),
        Format::Yaml,
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();
    assert_eq!(
        pulled.pulled, 2,
        "a mirror holds what the operator authored"
    );

    let listed = rules_ops::list(stack.transport(), &RuleFilter::default())
        .await
        .unwrap();
    assert_eq!(listed.total, 7, "a query command hides nothing");
}

/// Spec 5.5, the upgrade guard.
#[tokio::test]
async fn a_local_file_outside_the_scope_is_out_of_scope_not_local_only() {
    let stack = mock_mixed_corpus(0, 1).await;
    let dir = mirror_holding_a_prebuilt_rule();
    let d = state::diff(
        stack.transport(),
        dir.path(),
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();

    assert_eq!(d.out_of_scope, 1);
    assert!(
        !d.changes.iter().any(|c| matches!(c, Change::Added { .. })),
        "a prebuilt rule in an 0.1 mirror must not read as a pending create"
    );
}

/// A prebuilt-only stack has an honestly empty custom slice, so `pull` writes
/// an empty mirror rather than treating it as an unsupported old stack.
#[tokio::test]
async fn a_prebuilt_only_stack_has_a_valid_empty_custom_scope() {
    let stack = mock_mixed_corpus(0, 3).await;
    let dir = tempfile::tempdir().unwrap();

    let report = state::pull(
        stack.transport(),
        dir.path(),
        Format::Yaml,
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap();

    assert_eq!(report.pulled, 0);
}

#[tokio::test]
async fn malformed_source_partition_returns_a_typed_error_instead_of_an_empty_pull_report() {
    let server = MockServer::start().await;
    let profile = elasticctl_core::Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    };
    let transport = elasticctl_core::Transport::new(&profile).unwrap();
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.5.1", "build_flavor": "traditional"}
        })))
        .mount(&server)
        .await;
    // The first custom page is an honestly empty scope. The partition check's
    // second page is malformed and must stop the pull before it writes a report.
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(FirstEmptyThenMalformedSourcePage(AtomicUsize::new(0)))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let err = state::pull(
        &transport,
        dir.path(),
        Format::Yaml,
        &[],
        None,
        None,
        RuleSource::Custom,
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind, ErrorKind::Http, "{err}");
    assert!(
        err.message.contains("rule _find") && err.message.contains("total"),
        "{err}"
    );
}
