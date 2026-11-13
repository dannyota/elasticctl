use super::common::*;
use super::import_shared::{
    IntegrationPackageGroup, IntegrationPolicyCurrentSnapshot, IntegrationPolicyImportArtifact,
    IntegrationPolicyImportPlan, IntegrationPolicyImportTarget, effective_import_spec,
    import_preview, import_remote_error, planned_package_installs, read_import_parent_snapshots,
    relevant_name_owners, replace_wire_body, target_name_owners_match,
    validate_requested_package_versions,
};
use super::import_validation::validate_import_plan;
use super::metadata::{
    configured_secret_paths, validate_effective_input_materialization,
    validate_package_metadata_snapshot,
};
use super::normalization::normalize;

pub fn prepare_import(path: &Path) -> Result<IntegrationPolicyImportArtifact> {
    let canonical = validate(path)?;
    if canonical.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "integration-policy import needs at least one integration policy",
        ));
    }
    validate_requested_package_versions(&canonical)?;
    Ok(IntegrationPolicyImportArtifact {
        source: path.to_path_buf(),
        canonical,
    })
}

pub async fn plan_prepared_import(
    transport: &Transport,
    artifact: IntegrationPolicyImportArtifact,
    overwrite: bool,
    skip_existing: bool,
) -> Result<IntegrationPolicyImportPlan> {
    let IntegrationPolicyImportArtifact { source, canonical } = artifact;
    if overwrite && skip_existing {
        return Err(Error::new(
            ErrorKind::Error,
            "--overwrite and --skip-existing cannot be used together",
        ));
    }

    let mut existing = BTreeMap::new();
    let mut conflicts = Vec::new();
    for spec in &canonical {
        match integration_policies::get(transport, &spec.id).await {
            Ok(policy) => {
                let returned_id = required_string(&policy.item, "id", "integration policy get")?;
                if returned_id != spec.id {
                    return Err(http(
                        "decoding integration policy get: response id did not match the request",
                    ));
                }
                if !overwrite && !skip_existing {
                    conflicts.push(spec.id.clone());
                }
                existing.insert(spec.id.clone(), Some(policy.item));
            }
            Err(error) if error.kind == ErrorKind::NotFound => {
                existing.insert(spec.id.clone(), None);
            }
            Err(error) => return Err(import_remote_error(error, "planning read")),
        }
    }
    if !conflicts.is_empty() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "integration policies already exist: {}",
                conflicts.join(", ")
            ),
        ));
    }

    for spec in &canonical {
        if skip_existing && matches!(existing.get(&spec.id), Some(Some(_))) {
            continue;
        }
        let Some(Some(item)) = existing.get(&spec.id) else {
            continue;
        };
        let current = package_coordinate(item, "integration policy")
            .map_err(|error| import_remote_error(error, "planning read"))?;
        if current != spec.package {
            return unsupported(format!(
                "integration policy '{}' cannot change package {}@{} to {}@{}",
                spec.id, current.name, current.version, spec.package.name, spec.package.version
            ));
        }
    }

    let names: BTreeSet<String> = canonical.iter().map(|spec| spec.name.clone()).collect();
    let name_owners = relevant_name_owners(transport, &names)
        .await
        .map_err(|error| import_remote_error(error, "planning names read"))?;
    let mut name_conflicts = Vec::new();
    for spec in &canonical {
        let owners = name_owners
            .get(&spec.name)
            .expect("requested name has an ownership entry");
        for owner in owners.iter().filter(|owner| owner.as_str() != spec.id) {
            name_conflicts.push(format!("{} ({owner})", spec.name));
        }
    }
    if !name_conflicts.is_empty() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "integration policy names already exist: {}",
                name_conflicts.join(", ")
            ),
        ));
    }

    let mut skipped = Vec::new();
    let pending: Vec<IntegrationPolicySpec> = canonical
        .iter()
        .filter_map(|spec| match existing.get(&spec.id) {
            Some(Some(item)) if skip_existing => {
                skipped.push(json!({"id": spec.id, "reason": "exists"}));
                None
            }
            _ => Some(spec.clone()),
        })
        .collect();

    let mut targets = Vec::with_capacity(pending.len());
    let mut shared_parents = BTreeMap::new();
    for spec in pending {
        let raw = existing
            .get(&spec.id)
            .expect("every canonical id was fetched")
            .clone();
        let current_parent_ids = raw
            .as_ref()
            .map(|item| {
                read_parents(&spec.id, item)
                    .map_err(|error| import_remote_error(error, "planning read"))
            })
            .transpose()?;
        let parents = read_import_parent_snapshots(
            transport,
            &spec.id,
            current_parent_ids.as_deref().unwrap_or_default(),
            &spec.policy_ids,
        )
        .await
        .map_err(|error| import_remote_error(error, "planning parent read"))?;
        for (parent_id, parent) in &parents {
            match shared_parents.entry(parent_id.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(parent.clone());
                }
                std::collections::btree_map::Entry::Occupied(entry) if entry.get() != parent => {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        format!(
                            "agent policy '{parent_id}' changed while planning integration import"
                        ),
                    ));
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
        let effective = effective_import_spec(&spec, &parents)?;
        let current = raw
            .map(|item| {
                let normalized = normalize(&item, transport.space())
                    .map_err(|error| import_remote_error(error, "planning read"))?;
                if normalized.id != spec.id {
                    return Err(http(
                        "decoding integration policy: response id did not match the request",
                    ));
                }
                Ok(IntegrationPolicyCurrentSnapshot {
                    item,
                    spec: normalized,
                    parent_ids: current_parent_ids.expect("raw policy has parents"),
                })
            })
            .transpose()?;
        targets.push(IntegrationPolicyImportTarget {
            effective,
            current,
            parents,
            replacement_body: None,
        });
    }
    if targets
        .iter()
        .any(|target| !target_name_owners_match(target, &name_owners))
    {
        return Err(Error::new(
            ErrorKind::Conflict,
            "integration policy name ownership changed while planning",
        ));
    }

    let mut package_coordinates = BTreeMap::new();
    for target in &targets {
        package_coordinates
            .entry(target.effective.package.name.clone())
            .or_insert_with(|| target.effective.package.clone());
    }
    let mut package_groups = BTreeMap::new();
    for (name, package) in package_coordinates {
        let state = read_dependencies(transport, &package)
            .await
            .map_err(|error| import_remote_error(error, "planning package read"))?;
        match &state.state {
            PackageDependencyState::Installed { version } if version == &package.version => {}
            PackageDependencyState::Installed { .. } => {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    format!("integration package {name} has a different installed version"),
                ));
            }
            PackageDependencyState::NotInstalled => {
                if targets
                    .iter()
                    .any(|target| target.effective.package.name == name && target.current.is_some())
                {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        format!("integration package {name} is not installed"),
                    ));
                }
            }
        }
        let metadata =
            integration_policies::package_metadata(transport, &package.name, &package.version)
                .await
                .map_err(|error| import_remote_error(error, "planning package metadata read"))?
                .item;
        validate_package_metadata_snapshot(&metadata, &package)
            .map_err(|error| import_remote_error(error, "planning package metadata read"))?;
        package_groups.insert(
            name,
            IntegrationPackageGroup {
                package,
                state: state.clone(),
                state_snapshot: state,
                metadata_snapshot: metadata.clone(),
                metadata,
            },
        );
    }

    for target in &targets {
        let package = package_groups
            .get(&target.effective.package.name)
            .expect("every effective package has a group");
        validate_effective_input_materialization(&target.effective, &package.metadata)?;
    }

    let mut secret_paths = BTreeSet::new();
    for target in &targets {
        let package = package_groups
            .get(&target.effective.package.name)
            .expect("every effective package has a group");
        if let Some(current) = &target.current {
            for path in configured_secret_paths(&current.spec, &package.metadata)? {
                secret_paths.insert(format!("{}:{path}", current.spec.id));
            }
        }
        for path in configured_secret_paths(&target.effective, &package.metadata)? {
            secret_paths.insert(format!("{}:{path}", target.effective.id));
        }
    }
    if !secret_paths.is_empty() {
        return unsupported(format!(
            "integration policy import contains configured secrets: {}",
            secret_paths.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }

    for target in &mut targets {
        if let Some(current) = &target.current
            && current.spec != target.effective
        {
            target.replacement_body = Some(replace_wire_body(&target.effective)?);
        }
    }
    let package_installs = planned_package_installs(&package_groups);
    let preview = import_preview(&source, &targets, &package_installs);
    let plan = IntegrationPolicyImportPlan {
        preview,
        skipped_snapshot: skipped.clone(),
        skipped,
        package_installs,
        total: canonical.len(),
        source,
        host: transport.kibana_url().to_owned(),
        space: transport.space().to_owned(),
        canonical,
        name_owners_snapshot: name_owners.clone(),
        name_owners,
        parent_snapshots: shared_parents,
        existing_snapshot: existing.clone(),
        targets,
        package_groups,
        overwrite,
        skip_existing,
    };
    validate_import_plan(&plan)?;
    Ok(plan)
}

pub async fn plan_import(
    transport: &Transport,
    path: &Path,
    overwrite: bool,
    skip_existing: bool,
) -> Result<IntegrationPolicyImportPlan> {
    let artifact = prepare_import(path)?;
    plan_prepared_import(transport, artifact, overwrite, skip_existing).await
}

pub fn validate(path: &Path) -> Result<Vec<IntegrationPolicySpec>> {
    let body = std::fs::read_to_string(path).map_err(|error| {
        Error::new(
            ErrorKind::Error,
            format!("reading {}: {error}", path.display()),
        )
    })?;
    let mut specs = content_codec::decode_sequence::<IntegrationPolicySpec>(
        &body,
        ContentFormat::from_path(path),
        "integration policy",
    )?;
    duplicate_error(&specs, |spec| &spec.id, "ids")?;
    duplicate_error(&specs, |spec| &spec.name, "names")?;
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(specs)
}

fn duplicate_error<'a, F>(specs: &'a [IntegrationPolicySpec], key: F, noun: &str) -> Result<()>
where
    F: Fn(&'a IntegrationPolicySpec) -> &'a String,
{
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for spec in specs {
        let value = key(spec);
        if !seen.insert(value.as_str()) {
            duplicates.insert(value.as_str());
        }
    }
    if duplicates.is_empty() {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Error,
            format!(
                "duplicate integration policy {noun}: {}",
                duplicates.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ))
    }
}
