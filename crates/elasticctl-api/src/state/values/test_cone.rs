use super::*;
use crate::state::diff::ItemOp;

fn changed(flavor: &str) -> ListPlan {
    let mut local = pair(flavor);
    local.values.insert("10.0.0.9/32".into());
    let refs = item_refs(&[item(&local.container.id)]).unwrap();
    vl::plan_list(local, Some(remote(flavor)), &refs, &refs).unwrap()
}

#[test]
fn cone_refuses_added_removed_replaced_and_changed_entries() {
    let plan = changed(FLAVORS[0]);
    let installed = plan.installed.clone();
    for mode in ["add", "remove", "replace", "field", "operator", "type"] {
        let mut desired = installed.clone();
        match mode {
            "add" => {
                let mut added = desired[0].clone();
                added.item_id = "another".into();
                desired.push(added);
            }
            "remove" => desired.clear(),
            "replace" => desired[0].item_id = "replacement".into(),
            "field" => desired[0].field = "destination.ip".into(),
            "operator" => desired[0].operator = vl::ReferenceOperator::Excluded,
            "type" => desired[0].list_type = vl::ValueListType::Keyword,
            _ => unreachable!(),
        }
        let error = super::super::cone::check(
            std::slice::from_ref(&plan),
            &installed,
            &desired,
            &[],
            &[],
            &exceptions(),
        )
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict, "{mode}");
    }
}

#[test]
fn cone_refuses_another_entry_or_field_of_a_referencing_item() {
    let plan = changed(FLAVORS[0]);
    let before = item(&plan.local.container.id);
    for mode in ["entry", "name", "remove"] {
        let mut after = before.clone();
        if mode == "entry" {
            after.as_map_mut()["entries"].as_array_mut().unwrap().push(json!({"type": "match", "field": "host.name", "operator": "included", "value": "synthetic"}));
        }
        if mode == "name" {
            after.as_map_mut().insert("name".into(), json!("Changed"));
        }
        let mut exception_plan = exceptions();
        exception_plan.item_ops.push(if mode == "remove" {
            ItemOp::Remove {
                before: before.clone(),
                namespace_type: "single".into(),
            }
        } else {
            ItemOp::Update {
                before: before.clone(),
                after,
            }
        });
        assert!(
            super::super::cone::check(
                std::slice::from_ref(&plan),
                &plan.installed,
                &plan.desired,
                &[],
                &[],
                &exception_plan
            )
            .is_err(),
            "{mode}"
        );
    }
}

#[test]
fn cone_refuses_a_second_changing_list_of_the_same_item() {
    let first = changed(FLAVORS[0]);
    let mut second = first.clone();
    second.local.container.id = "second".into();
    let mut refs = first.installed.clone();
    let mut reference = refs[0].clone();
    reference.list_id = "second".into();
    reference.field = "destination.ip".into();
    refs.push(reference);
    assert!(
        super::super::cone::check(&[first, second], &refs, &refs, &[], &[], &exceptions()).is_err()
    );
}

#[test]
fn cone_refuses_a_rule_dropping_or_adding_a_shared_container() {
    let plan = changed(FLAVORS[0]);
    let bound = rule();
    let mut detached = bound.clone();
    detached.as_map_mut().remove("exceptions_list");
    for (local, remote) in [
        (detached.clone(), bound.clone()),
        (bound.clone(), detached.clone()),
    ] {
        assert!(
            super::super::cone::check(
                std::slice::from_ref(&plan),
                &plan.installed,
                &plan.desired,
                &[local],
                &[remote],
                &exceptions()
            )
            .is_err()
        );
    }
}

#[test]
fn first_creation_allows_first_references_and_bindings_but_refuses_detaching_a_rule() {
    let local = pair(FLAVORS[0]);
    let refs = item_refs(&[item(&local.container.id)]).unwrap();
    let plan = vl::plan_list(local, None, &[], &refs).unwrap();
    let mut exception_plan = exceptions();
    exception_plan
        .item_ops
        .push(ItemOp::Create(item(&plan.local.container.id)));
    let mut detached = rule();
    detached.as_map_mut().remove("exceptions_list");
    assert!(
        super::super::cone::check(
            std::slice::from_ref(&plan),
            &[],
            &refs,
            &[rule()],
            &[detached.clone()],
            &exception_plan
        )
        .is_ok()
    );
    assert!(
        super::super::cone::check(&[plan], &[], &refs, &[detached], &[rule()], &exception_plan)
            .is_err()
    );
}

#[test]
fn installed_item_referencing_a_list_twice_refuses_a_value_change() {
    let local = pair(FLAVORS[0]);
    let mut refs = item_refs(&[item(&local.container.id)]).unwrap();
    let mut second = refs[0].clone();
    second.field = "destination.ip".into();
    refs.push(second);
    let mut changed = local.clone();
    changed.values.insert("10.0.0.9/32".into());
    let error = vl::plan_list(changed, Some(remote(FLAVORS[0])), &refs, &refs).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Conflict);
}

#[test]
fn two_new_lists_allow_their_first_reference_in_the_same_new_item() {
    let first = pair(FLAVORS[0]);
    let mut second = first.clone();
    second.container.id = "second".into();
    second.stem = "second".into();
    let mut refs = item_refs(&[item(&first.container.id)]).unwrap();
    let mut other = refs[0].clone();
    other.list_id = second.container.id.clone();
    other.field = "destination.ip".into();
    refs.push(other);
    let plans = [
        vl::plan_list(first, None, &[], &refs).unwrap(),
        vl::plan_list(second, None, &[], &refs).unwrap(),
    ];
    assert!(super::super::cone::check(&plans, &[], &refs, &[rule()], &[], &exceptions()).is_ok());
}
