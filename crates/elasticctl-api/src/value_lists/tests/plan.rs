use super::super::*;
use super::reads::{FLAVORS, fixture};
use crate::model::ListKey;
use elasticctl_core::ErrorKind;

pub(super) fn remote(flavor: &str) -> RemoteList {
    RemoteList {
        container: decode_remote_container(&fixture(flavor, "container_read")["response"]).unwrap(),
        stored: decode_export(
            &ValueListType::IpRange,
            fixture(flavor, "items_export")["response"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    }
}

pub(super) fn pair(remote: &RemoteList) -> LocalPair {
    LocalPair {
        stem: file_stem(&remote.container.container.id),
        container: remote.container.container.clone(),
        values: remote.stored.set(),
    }
}

pub(super) fn reference(id: &str, operator: ReferenceOperator) -> InstalledReference {
    InstalledReference {
        container: ListKey {
            list_id: "outside-selection".into(),
            namespace_type: "agnostic".into(),
        },
        item_id: "consumer".into(),
        field: "source.ip".into(),
        operator,
        list_id: id.into(),
        list_type: ValueListType::IpRange,
    }
}

#[test]
fn d22_uses_all_installed_operators_and_keeps_a_replacement_nonempty() {
    for flavor in FLAVORS {
        let remote = remote(flavor);
        let mut local = pair(&remote);
        let removed = local.values.pop_first().unwrap();
        local.values.insert("192.0.2.0/24".into());
        let inc = reference(&local.container.id, ReferenceOperator::Included);
        let mut exc = reference(&local.container.id, ReferenceOperator::Excluded);
        exc.item_id = "other-consumer".into();
        for (refs, expected) in [
            (vec![inc.clone()], PhaseOrder::RemovesFirst),
            (vec![exc.clone()], PhaseOrder::AddsFirst),
            (vec![inc.clone(), exc], PhaseOrder::AddsFirst),
            (vec![], PhaseOrder::RemovesFirst),
        ] {
            let p = plan_list(local.clone(), Some(remote.clone()), &refs, &[]).unwrap();
            assert_eq!(p.order, expected);
            assert_eq!(p.removes, [removed.clone()].into());
            assert_eq!(p.adds, ["192.0.2.0/24".into()].into());
            assert_eq!(p.container_action, ContainerAction::None);
        }
        let mut one = remote.clone();
        one.stored = StoredValues::new(vec![removed]);
        local.values = ["192.0.2.0/24".into()].into();
        assert_eq!(
            plan_list(local, Some(one), &[inc], &[]).unwrap().order,
            PhaseOrder::AddsFirst
        );
    }
}

#[test]
fn plan_refuses_type_change_empty_referenced_and_creation_with_installed_consumers() {
    let remote = remote(FLAVORS[0]);
    let mut local = pair(&remote);
    local.container.list_type = ValueListType::Keyword;
    assert_eq!(
        plan_list(local, Some(remote.clone()), &[], &[])
            .unwrap_err()
            .kind,
        ErrorKind::Conflict
    );
    let mut local = pair(&remote);
    let consumer = reference(&local.container.id, ReferenceOperator::Included);
    local.values.clear();
    assert_eq!(
        plan_list(
            local,
            Some(remote.clone()),
            std::slice::from_ref(&consumer),
            &[]
        )
        .unwrap_err()
        .kind,
        ErrorKind::Unsupported
    );
    assert_eq!(
        plan_list(pair(&remote), None, &[consumer], &[])
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
}

#[test]
fn absent_local_meta_neither_updates_nor_checks_remote_meta() {
    let remote = remote(FLAVORS[0]);
    let mut local = pair(&remote);
    local.container.meta = None;
    let p = plan_list(local, Some(remote), &[], &[]).unwrap();
    assert_eq!(p.container_action, ContainerAction::None);
    assert!(p.adds.is_empty());
    assert!(p.removes.is_empty());
}

#[test]
fn packing_obeys_the_bound_including_lf_and_keeps_whole_lines() {
    let values: ValueSet = ["a".repeat(7_999_999), "b".into(), "c".into()].into();
    let packed = pack_imports(&values).unwrap();
    assert_eq!(packed.len(), 2);
    assert_eq!(packed[0].len(), 8_000_000);
    assert_eq!(packed[1], "b\nc\n");
    assert!(pack_imports(&["a".repeat(8_000_000)].into()).is_err());
}

#[test]
fn a_create_preview_warns_at_the_projected_keyword_size_boundary() {
    let local = LocalPair {
        stem: "large".into(),
        container: Container {
            id: "large".into(),
            list_type: ValueListType::Keyword,
            name: "large".into(),
            description: "synthetic".into(),
            meta: None,
        },
        values: (0..65_536).map(|i| format!("value-{i:05}")).collect(),
    };
    let plan = plan_list(local, None, &[], &[]).unwrap();
    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.kind == WarningKind::RuleTypeLimit)
    );
}
