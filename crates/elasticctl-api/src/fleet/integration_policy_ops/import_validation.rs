use super::common::*;
use super::import_shared::{
    IntegrationPolicyImportPlan, effective_import_spec, import_preview, planned_package_installs,
    replace_wire_body, target_name_owners_match, validate_requested_package_versions,
};
use super::metadata::{
    configured_secret_paths, validate_effective_input_materialization,
    validate_package_metadata_snapshot,
};
use super::normalization::normalize;

pub(super) fn validate_import_plan(plan: &IntegrationPolicyImportPlan) -> Result<()> {
    let invalid = |message: &str| {
        Err(Error::new(
            ErrorKind::Error,
            format!("invalid integration-policy import plan: {message}"),
        ))
    };
    if plan.overwrite && plan.skip_existing {
        return invalid("overwrite and skip-existing cannot both be set");
    }
    if plan.host.trim().is_empty() {
        return invalid("planned Kibana host is empty");
    }
    if plan.canonical.is_empty() || plan.total != plan.canonical.len() {
        return invalid("total does not equal canonical integration policies");
    }
    let mut canonical_ids = BTreeMap::new();
    let mut canonical_names = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for spec in &plan.canonical {
        if spec.validate().is_err() {
            return invalid("canonical integration policy is invalid");
        }
        if previous.is_some_and(|previous| previous >= spec.id.as_str()) {
            return invalid("canonical integration policies must be unique and sorted by id");
        }
        if !canonical_names.insert(spec.name.as_str()) {
            return invalid("canonical integration-policy names must be unique");
        }
        previous = Some(&spec.id);
        canonical_ids.insert(spec.id.as_str(), spec);
    }
    if validate_requested_package_versions(&plan.canonical).is_err() {
        return invalid("canonical package requests are inconsistent");
    }
    let canonical_id_set = canonical_ids.keys().copied().collect::<BTreeSet<_>>();
    if plan
        .existing_snapshot
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != canonical_id_set
    {
        return invalid("existence snapshots do not match canonical integration policies");
    }
    for (id, existing) in &plan.existing_snapshot {
        if let Some(item) = existing
            && required_string(item, "id", "existing integration policy")
                .ok()
                .as_deref()
                != Some(id.as_str())
        {
            return invalid("existence snapshot has an unexpected id");
        }
    }
    if plan.name_owners != plan.name_owners_snapshot {
        return invalid("name ownership snapshots do not match");
    }
    if plan
        .name_owners
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != canonical_names
    {
        return invalid("name ownership snapshots do not match canonical names");
    }
    for spec in &plan.canonical {
        let Some(owners) = plan.name_owners.get(&spec.name) else {
            return invalid("canonical name has no ownership snapshot");
        };
        if owners
            .iter()
            .any(|owner| owner.trim().is_empty() || owner != &spec.id)
        {
            return invalid("name ownership snapshot has a foreign or malformed owner");
        }
    }

    let mut target_ids = BTreeSet::new();
    let mut expected_bodies = BTreeMap::new();
    let mut expected_group_names = BTreeSet::new();
    let mut shared_parents = BTreeMap::new();
    let mut previous_target: Option<&str> = None;
    for target in &plan.targets {
        if target.effective.validate().is_err() {
            return invalid("effective integration policy is invalid");
        }
        if previous_target.is_some_and(|previous| previous >= target.effective.id.as_str()) {
            return invalid("pending integration policies must be unique and sorted by id");
        }
        previous_target = Some(&target.effective.id);
        let Some(canonical) = canonical_ids.get(target.effective.id.as_str()) else {
            return invalid("pending policy is not in the canonical artifact");
        };
        if !target_ids.insert(target.effective.id.as_str()) {
            return invalid("pending integration policies must be unique and sorted by id");
        }
        let exact_current = match (
            &target.current,
            plan.existing_snapshot.get(&target.effective.id),
        ) {
            (None, Some(None)) => true,
            (Some(current), Some(Some(item))) => current.item == *item,
            _ => false,
        };
        if !exact_current {
            return invalid("target does not match its plan-time existence snapshot");
        }
        let current_parent_ids = match &target.current {
            None => Vec::new(),
            Some(current) => {
                if current.spec.validate().is_err()
                    || current.spec.id != target.effective.id
                    || normalize(&current.item, &plan.space).ok().as_ref() != Some(&current.spec)
                {
                    return invalid("current integration snapshot does not normalize canonically");
                }
                let parent_ids = match read_parents(&target.effective.id, &current.item) {
                    Ok(parent_ids) if parent_ids == current.parent_ids => parent_ids,
                    _ => {
                        return invalid(
                            "current integration parent snapshot does not match its item",
                        );
                    }
                };
                if package_coordinate(&current.item, "integration policy").ok()
                    != Some(target.effective.package.clone())
                {
                    return invalid("current and desired package coordinates differ");
                }
                parent_ids
            }
        };
        if target.current.is_some() && !plan.overwrite {
            return invalid("existing integration target requires overwrite");
        }
        if !target_name_owners_match(target, &plan.name_owners) {
            return invalid("name ownership snapshot does not match target state");
        }
        let expected_parent_ids = current_parent_ids
            .iter()
            .chain(&target.effective.policy_ids)
            .cloned()
            .collect::<BTreeSet<_>>();
        if target.parents.keys().cloned().collect::<BTreeSet<_>>() != expected_parent_ids {
            return invalid("parent snapshots do not match current and desired parents");
        }
        for (parent_id, parent) in &target.parents {
            if !valid_parent_snapshot(parent_id, parent)
                || parent.platform_owned
                || parent.protected
            {
                return invalid("parent snapshot is unsafe or malformed");
            }
            if current_parent_ids.binary_search(parent_id).is_ok()
                && parent
                    .attached_integrations
                    .binary_search_by(|attached| attached.as_str().cmp(&target.effective.id))
                    .is_err()
            {
                return invalid("current parent snapshot is missing its integration attachment");
            }
            match shared_parents.entry(parent_id.as_str()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(parent);
                }
                std::collections::btree_map::Entry::Occupied(entry) if *entry.get() != parent => {
                    return invalid("shared parent snapshots disagree");
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
        if effective_import_spec(canonical, &target.parents)
            .ok()
            .as_ref()
            != Some(&target.effective)
        {
            return invalid("effective integration policy does not match canonical parents");
        }
        if let Some(current) = &target.current {
            if current.spec != target.effective {
                if !plan.overwrite {
                    return invalid("replacement plan requires overwrite");
                }
                let body = match replace_wire_body(&target.effective) {
                    Ok(body) => body,
                    Err(_) => return invalid("replacement body cannot be encoded"),
                };
                if target.replacement_body.as_ref() != Some(&body) {
                    return invalid("replacement body does not match its effective policy");
                }
                expected_bodies.insert(target.effective.id.as_str(), body);
            } else if target.replacement_body.is_some() {
                return invalid("unchanged integration policy carries a replacement body");
            }
        } else if target.replacement_body.is_some() {
            return invalid("planned create carries a replacement body");
        }
        expected_group_names.insert(target.effective.package.name.as_str());
    }

    if plan
        .package_groups
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_group_names
    {
        return invalid("package groups do not match pending integration policies");
    }
    let expected_parent_snapshots: BTreeMap<String, agent_policy_ops::AgentPolicyParentSnapshot> =
        shared_parents
            .iter()
            .map(|(id, parent)| ((*id).to_owned(), (*parent).clone()))
            .collect();
    if plan.parent_snapshots != expected_parent_snapshots {
        return invalid("shared parent snapshots do not match pending integrations");
    }
    for (name, group) in &plan.package_groups {
        if group.package.name != *name
            || group.package.name.trim().is_empty()
            || group.package.version.trim().is_empty()
            || group.state != group.state_snapshot
            || group.metadata != group.metadata_snapshot
            || group.state.name != group.package.name
            || !valid_package_state(&group.state)
            || validate_package_metadata_snapshot(&group.metadata, &group.package).is_err()
        {
            return invalid("package group snapshot is malformed or tampered");
        }
        if !is_exact_installed(&group.state, &group.package)
            && !matches!(group.state.state, PackageDependencyState::NotInstalled)
        {
            return invalid("package group does not hold an exact dependency state");
        }
        if matches!(group.state.state, PackageDependencyState::NotInstalled)
            && plan
                .targets
                .iter()
                .any(|target| target.effective.package.name == *name && target.current.is_some())
        {
            return invalid("existing integration cannot depend on an absent package");
        }
    }
    for target in &plan.targets {
        let Some(group) = plan.package_groups.get(&target.effective.package.name) else {
            return invalid("target has no package group");
        };
        if group.package != target.effective.package {
            return invalid("package group coordinate does not match its target");
        }
        validate_effective_input_materialization(&target.effective, &group.metadata)?;
        match configured_secret_paths(&target.effective, &group.metadata) {
            Ok(paths) if paths.is_empty() => {}
            _ => return invalid("effective integration policy has unsafe configured variables"),
        }
        if let Some(current) = &target.current {
            match configured_secret_paths(&current.spec, &group.metadata) {
                Ok(paths) if paths.is_empty() => {}
                _ => {
                    return invalid("current integration policy has unsafe configured variables");
                }
            }
        }
    }
    if expected_bodies.len()
        != plan
            .targets
            .iter()
            .filter(|target| target.replacement_body.is_some())
            .count()
    {
        return invalid("replacement body set does not match changed integration policies");
    }

    let expected_skipped_ids = plan
        .canonical
        .iter()
        .filter(|spec| {
            plan.skip_existing && matches!(plan.existing_snapshot.get(&spec.id), Some(Some(_)))
        })
        .map(|spec| spec.id.as_str())
        .collect::<BTreeSet<_>>();
    let expected_target_ids = canonical_id_set
        .iter()
        .copied()
        .filter(|id| !expected_skipped_ids.contains(id))
        .collect::<BTreeSet<_>>();
    if target_ids != expected_target_ids {
        return invalid("pending integration policies do not match plan-time existence snapshots");
    }
    let expected_skipped = plan
        .canonical
        .iter()
        .filter(|spec| expected_skipped_ids.contains(spec.id.as_str()))
        .map(|spec| json!({"id": spec.id, "reason": "exists"}))
        .collect::<Vec<_>>();
    if plan.skipped != plan.skipped_snapshot {
        return invalid("skipped rows do not match their snapshot");
    }
    if (!plan.skip_existing && !plan.skipped.is_empty()) || plan.skipped != expected_skipped {
        return invalid("skipped rows do not match the canonical artifact");
    }
    let expected_installs = planned_package_installs(&plan.package_groups);
    if plan.package_installs != expected_installs {
        return invalid("package install preview does not match package groups");
    }
    let expected_preview = import_preview(&plan.source, &plan.targets, &plan.package_installs);
    if plan.preview != expected_preview {
        return invalid("preview does not match the canonical plan");
    }
    Ok(())
}

#[cfg(test)]
mod import_plan_tests {
    use super::super::common::*;
    use super::super::import_shared::*;
    use super::*;

    fn valid_plan() -> IntegrationPolicyImportPlan {
        let effective = IntegrationPolicySpec::try_from(json!({
            "id": "fresh",
            "name": "Fresh integration",
            "namespace": "default",
            "policy_ids": ["parent-1"],
            "package": {"name": "system", "version": "2.0.0"},
            "inputs": {}
        }))
        .expect("valid test policy");
        let parent = agent_policy_ops::AgentPolicyParentSnapshot {
            id: "parent-1".into(),
            name: "Parent 1".into(),
            namespace: "default".into(),
            agents: 0,
            attached_integrations: Vec::new(),
            platform_owned: false,
            protected: false,
        };
        let targets = vec![IntegrationPolicyImportTarget {
            effective: effective.clone(),
            current: None,
            parents: BTreeMap::from([(parent.id.clone(), parent)]),
            replacement_body: None,
        }];
        let parent_snapshots = targets[0].parents.clone();
        let state = PackageDependencySnapshot {
            name: "system".into(),
            state: PackageDependencyState::NotInstalled,
        };
        let metadata = json!({
            "name": "system",
            "version": "2.0.0",
            "vars": [],
            "policy_templates": []
        })
        .as_object()
        .expect("metadata object")
        .clone();
        let package_groups = BTreeMap::from([(
            "system".into(),
            IntegrationPackageGroup {
                package: effective.package.clone(),
                state: state.clone(),
                state_snapshot: state,
                metadata_snapshot: metadata.clone(),
                metadata,
            },
        )]);
        let package_installs = vec!["system@2.0.0".into()];
        let source = PathBuf::from("fresh.json");
        let preview = import_preview(&source, &targets, &package_installs);
        IntegrationPolicyImportPlan {
            preview,
            skipped: Vec::new(),
            package_installs,
            total: 1,
            source,
            host: "https://fleet.example.invalid".into(),
            space: "default".into(),
            canonical: vec![effective.clone()],
            name_owners: BTreeMap::from([(effective.name.clone(), BTreeSet::new())]),
            name_owners_snapshot: BTreeMap::from([(effective.name.clone(), BTreeSet::new())]),
            parent_snapshots,
            skipped_snapshot: Vec::new(),
            existing_snapshot: BTreeMap::from([("fresh".into(), None)]),
            targets,
            package_groups,
            overwrite: false,
            skip_existing: false,
        }
    }

    fn existing_plan_without_overwrite() -> IntegrationPolicyImportPlan {
        let mut plan = valid_plan();
        let existing = {
            let target = plan.targets.first_mut().expect("fresh target");
            let mut item = serde_json::to_value(&target.effective)
                .expect("serialize current item")
                .as_object()
                .expect("current item object")
                .clone();
            item.insert("enabled".into(), Value::Bool(true));
            target.current = Some(IntegrationPolicyCurrentSnapshot {
                item: item.clone(),
                spec: target.effective.clone(),
                parent_ids: target.effective.policy_ids.clone(),
            });
            target
                .parents
                .get_mut("parent-1")
                .expect("parent")
                .attached_integrations
                .push(target.effective.id.clone());
            item
        };
        plan.existing_snapshot
            .insert("fresh".into(), Some(existing));

        let state = PackageDependencySnapshot {
            name: "system".into(),
            state: PackageDependencyState::Installed {
                version: "2.0.0".into(),
            },
        };
        let group = plan
            .package_groups
            .get_mut("system")
            .expect("package group");
        group.state = state.clone();
        group.state_snapshot = state;
        plan.package_installs.clear();
        plan.name_owners
            .get_mut("Fresh integration")
            .expect("name owner snapshot")
            .insert("fresh".into());
        plan.name_owners_snapshot = plan.name_owners.clone();
        plan.parent_snapshots = plan.targets[0].parents.clone();
        plan.preview = import_preview(&plan.source, &plan.targets, &plan.package_installs);
        plan
    }

    fn valid_skip_existing_plan() -> IntegrationPolicyImportPlan {
        let mut plan = existing_plan_without_overwrite();
        plan.skip_existing = true;
        plan.targets.clear();
        plan.parent_snapshots.clear();
        plan.package_groups.clear();
        plan.skipped = vec![json!({"id": "fresh", "reason": "exists"})];
        plan.skipped_snapshot = plan.skipped.clone();
        plan.package_installs.clear();
        plan.preview = import_preview(&plan.source, &plan.targets, &plan.package_installs);
        plan
    }

    fn valid_replace_plan() -> IntegrationPolicyImportPlan {
        let mut plan = existing_plan_without_overwrite();
        plan.overwrite = true;
        let desired = {
            let target = plan.targets.first_mut().expect("existing target");
            let mut desired = target.effective.clone();
            desired.description = Some("changed".into());
            target.effective = desired.clone();
            target.replacement_body = Some(replace_wire_body(&desired).expect("replace body"));
            desired
        };
        plan.canonical = vec![desired];
        plan.preview = import_preview(&plan.source, &plan.targets, &plan.package_installs);
        plan
    }

    #[test]
    fn replacement_body_omits_response_only_enabled_without_changing_input_enabled() {
        let spec = IntegrationPolicySpec::try_from(json!({
            "id": "replacement",
            "name": "Replacement integration",
            "namespace": "default",
            "policy_ids": ["parent-1"],
            "package": {"name": "system", "version": "2.0.0"},
            "inputs": {"system-log": {"enabled": true}}
        }))
        .expect("valid replacement spec");

        let body = replace_wire_body(&spec).expect("replacement wire body");
        let object = body.as_object().expect("replacement wire object");

        assert!(object.get("id").is_none());
        assert!(object.get("enabled").is_none());
        assert_eq!(object["inputs"]["system-log"]["enabled"], true);
    }

    fn valid_expanded_inputs_plan() -> IntegrationPolicyImportPlan {
        let mut plan = valid_plan();
        let inputs = json!({"system-system": {}})
            .as_object()
            .expect("inputs object")
            .clone();
        plan.canonical[0].inputs = inputs.clone();
        plan.targets[0].effective.inputs = inputs;
        let metadata = json!({
            "name": "system",
            "version": "2.0.0",
            "vars": [],
            "policy_templates": [{
                "name": "system",
                "inputs": [{"type": "system"}]
            }]
        })
        .as_object()
        .expect("metadata object")
        .clone();
        let group = plan
            .package_groups
            .get_mut("system")
            .expect("package group");
        group.metadata = metadata.clone();
        group.metadata_snapshot = metadata;
        plan.preview = import_preview(&plan.source, &plan.targets, &plan.package_installs);
        plan
    }

    #[test]
    fn import_plan_rejects_a_private_create_name_owner_tamper() {
        let mut plan = valid_plan();
        plan.name_owners
            .get_mut("Fresh integration")
            .expect("name owner snapshot")
            .insert("fresh".into());

        assert!(validate_import_plan(&plan).is_err());
    }

    #[test]
    fn import_plan_rejects_a_coherent_empty_effective_inputs_tamper() {
        let mut plan = valid_expanded_inputs_plan();
        assert!(validate_import_plan(&plan).is_ok());

        plan.canonical[0].inputs.clear();
        plan.targets[0].effective.inputs.clear();
        plan.preview = import_preview(&plan.source, &plan.targets, &plan.package_installs);

        let error = validate_import_plan(&plan)
            .expect_err("an empty effective map must not reach import requests");
        assert_eq!(error.kind, ErrorKind::Unsupported);
        assert_eq!(
            error.message,
            "integration policy 'fresh' has an empty inputs map but package system@2.0.0 declares inputs"
        );
    }

    #[test]
    fn import_plan_rejects_an_existing_target_without_overwrite() {
        let plan = existing_plan_without_overwrite();

        assert!(validate_import_plan(&plan).is_err());
    }

    #[test]
    fn import_plan_rejects_private_snapshot_body_group_and_order_tampering() {
        let replace = valid_replace_plan();
        assert!(validate_import_plan(&replace).is_ok());

        let mut tampered_body = replace.clone();
        tampered_body.targets[0].replacement_body = Some(json!({"tampered": true}));
        assert!(validate_import_plan(&tampered_body).is_err());

        let mut tampered_current = replace.clone();
        tampered_current.targets[0]
            .current
            .as_mut()
            .expect("current snapshot")
            .item
            .insert("enabled".into(), Value::Bool(false));
        assert!(validate_import_plan(&tampered_current).is_err());

        let mut tampered_group = valid_plan();
        tampered_group
            .package_groups
            .get_mut("system")
            .expect("package group")
            .metadata
            .insert("version".into(), Value::String("9.9.9".into()));
        assert!(validate_import_plan(&tampered_group).is_err());

        let mut tampered_order = valid_plan();
        tampered_order
            .targets
            .push(tampered_order.targets[0].clone());
        assert!(validate_import_plan(&tampered_order).is_err());

        let mut tampered_group_key = valid_plan();
        let group = tampered_group_key
            .package_groups
            .remove("system")
            .expect("package group");
        tampered_group_key
            .package_groups
            .insert("other".into(), group);
        assert!(validate_import_plan(&tampered_group_key).is_err());

        let mut tampered_state = valid_plan();
        tampered_state
            .package_groups
            .get_mut("system")
            .expect("package group")
            .state = PackageDependencySnapshot {
            name: "system".into(),
            state: PackageDependencyState::Installed {
                version: "2.0.0".into(),
            },
        };
        assert!(validate_import_plan(&tampered_state).is_err());

        let mut tampered_coordinate = valid_replace_plan();
        tampered_coordinate.canonical[0].package.version = "3.0.0".into();
        tampered_coordinate.targets[0].effective.package.version = "3.0.0".into();
        tampered_coordinate.targets[0].replacement_body = Some(
            replace_wire_body(&tampered_coordinate.targets[0].effective).expect("replace body"),
        );
        let group = tampered_coordinate
            .package_groups
            .get_mut("system")
            .expect("package group");
        group.package.version = "3.0.0".into();
        group.state = PackageDependencySnapshot {
            name: "system".into(),
            state: PackageDependencyState::Installed {
                version: "3.0.0".into(),
            },
        };
        group.state_snapshot = group.state.clone();
        group.metadata.insert("version".into(), json!("3.0.0"));
        group.metadata_snapshot = group.metadata.clone();
        tampered_coordinate.preview = import_preview(
            &tampered_coordinate.source,
            &tampered_coordinate.targets,
            &tampered_coordinate.package_installs,
        );
        assert!(validate_import_plan(&tampered_coordinate).is_err());
    }

    #[test]
    fn import_plan_rejects_a_private_parent_snapshot_tamper_even_with_preview_rebuilt() {
        let mut plan = valid_plan();
        plan.targets[0]
            .parents
            .get_mut("parent-1")
            .expect("parent snapshot")
            .agents = 42;
        plan.preview = import_preview(&plan.source, &plan.targets, &plan.package_installs);

        assert!(validate_import_plan(&plan).is_err());
    }

    #[test]
    fn import_plan_rejects_target_removal_rebuilt_as_a_skipped_row() {
        let mut plan = valid_plan();
        plan.skip_existing = true;
        plan.targets.clear();
        plan.parent_snapshots.clear();
        plan.package_groups.clear();
        plan.skipped = vec![json!({"id": "fresh", "reason": "exists"})];
        plan.skipped_snapshot = plan.skipped.clone();
        plan.package_installs.clear();
        plan.preview = import_preview(&plan.source, &plan.targets, &plan.package_installs);

        assert!(validate_import_plan(&plan).is_err());
    }

    #[test]
    fn import_plan_accepts_a_coherent_skip_existing_snapshot() {
        assert!(validate_import_plan(&valid_skip_existing_plan()).is_ok());
    }

    #[test]
    fn import_plan_rejects_existence_snapshot_key_and_target_mismatches() {
        let mut missing_current = valid_replace_plan();
        missing_current
            .existing_snapshot
            .insert("fresh".into(), None);
        assert!(validate_import_plan(&missing_current).is_err());

        let mut changed_current = valid_replace_plan();
        changed_current
            .existing_snapshot
            .get_mut("fresh")
            .expect("existing snapshot")
            .as_mut()
            .expect("existing item")
            .insert("description".into(), json!("tampered"));
        assert!(validate_import_plan(&changed_current).is_err());

        let mut extra_snapshot = valid_plan();
        extra_snapshot
            .existing_snapshot
            .insert("other".into(), None);
        assert!(validate_import_plan(&extra_snapshot).is_err());
    }

    #[test]
    fn import_plan_rejects_public_field_tampering_against_private_snapshots() {
        let plan = valid_plan();

        let mut total = plan.clone();
        total.total = 2;
        assert!(validate_import_plan(&total).is_err());

        let mut preview = plan.clone();
        preview.preview.preview_action = "tampered".into();
        assert!(validate_import_plan(&preview).is_err());

        let mut skipped = plan.clone();
        skipped.skipped = vec![json!({"id": "fresh", "reason": "exists"})];
        assert!(validate_import_plan(&skipped).is_err());

        let mut installs = plan;
        installs.package_installs.clear();
        assert!(validate_import_plan(&installs).is_err());
    }
}
