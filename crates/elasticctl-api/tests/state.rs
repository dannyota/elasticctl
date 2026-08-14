//! The state engine's contract, independent of the CLI.

use elasticctl_api::Format;
use elasticctl_api::state::{self, StackIdentity};
use elasticctl_api_test_support::{
    MockStack, mock_empty_stack, mock_stack_with_colliding_namespaces,
    mock_stack_with_failing_item_create, mock_stack_with_list_id,
    mock_stack_with_rule_default_list, mock_stack_with_rule_referencing,
    mock_stack_with_two_list_ids,
};
use elasticctl_core::ErrorKind;
use serde_json::json;
use std::path::Path;

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

    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
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

    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
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

    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
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

    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
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

    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
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
    let r = state::pull(stack.transport(), dir.path(), Format::Yaml, &[], None)
        .await
        .unwrap();

    assert_eq!(r.exception_lists, 1, "only the referenced list is mirrored");
    assert!(dir.path().join("exceptions/shared.yaml").exists());
    assert!(
        !dir.path().join("exceptions/orphan.yaml").exists(),
        "an unreferenced list is not part of a rules-as-code mirror"
    );
}

/// Spec 5.4: a rule_default list belongs to one rule and lives in its file.
#[tokio::test]
async fn a_rule_default_list_is_inlined_in_its_rule_file() {
    let stack = mock_stack_with_rule_default_list().await;
    let dir = tempfile::tempdir().unwrap();
    state::pull(stack.transport(), dir.path(), Format::Yaml, &[], None)
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
    state::pull(stack.transport(), dir.path(), Format::Yaml, &[], None)
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
    let err = state::pull(stack.transport(), dir.path(), Format::Yaml, &[], None)
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
    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
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
    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
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

    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
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

    let err = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
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
    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
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
    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
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
    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
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

/// A container referenced by a remote rule but absent locally is reported as
/// RemoteOnly and never deleted.
#[tokio::test]
async fn a_remote_only_list_is_reported_but_never_deleted() {
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

    let d = state::diff(stack.transport(), dir.path(), &[], None)
        .await
        .unwrap();
    assert!(
        d.exceptions
            .changes
            .iter()
            .any(|c| matches!(c, elasticctl_api::ListChange::RemoteOnly { list_id, .. } if list_id == "shared")),
        "a remote-only list must be reported: {:?}",
        d.exceptions.changes
    );

    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
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

/// A YAML pull must read back clean: the rule and its exception file round-trip
/// through `read_mirror`.
#[tokio::test]
async fn pull_then_diff_in_yaml_is_clean() {
    let stack = mock_stack_with_rule_referencing("shared").await;
    let dir = tempfile::tempdir().unwrap();
    state::pull(stack.transport(), dir.path(), Format::Yaml, &[], None)
        .await
        .unwrap();
    let d = state::diff(stack.transport(), dir.path(), &[], None)
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
    state::pull(stack.transport(), dir.path(), Format::Yaml, &[], None)
        .await
        .unwrap();
    let d = state::diff(stack.transport(), dir.path(), &[], None)
        .await
        .unwrap();
    assert!(
        d.clean,
        "a rule_default list must round-trip clean: {:?}",
        d.exceptions
    );
    assert_eq!(d.exceptions.local, 1);
    assert_eq!(d.exceptions.remote, 1);
}

/// A `rule_default` list is created like any other container before the rule
/// that references it.
#[tokio::test]
async fn push_creates_a_rule_default_list_on_a_fresh_stack() {
    let stack = mock_empty_stack().await;
    let dir = mirror_with_rule_default_list();
    let plan = state::plan_push(stack.transport(), dir.path(), &[], None, &identity())
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
