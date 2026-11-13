use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde::Serialize;

use super::scan::sort_references;
use super::validation::MAX_VALUE_BYTES_WITH_LF;
use super::{
    InstalledReference, LocalPair, PhaseOrder, ReferenceOperator, ReferenceUse, RemoteList,
    StoredValues, ValueSet, Warning, file_stem, project_states, read_list, require_bootstrapped,
    scan_references, stored_warnings, validate_additions, validate_projected,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerAction {
    Create,
    Update,
    None,
}

#[derive(Clone, Debug, Serialize)]
pub struct ListPlan {
    pub local: LocalPair,
    pub before: Option<RemoteList>,
    pub installed: Vec<InstalledReference>,
    pub desired: Vec<InstalledReference>,
    pub container_action: ContainerAction,
    pub adds: ValueSet,
    pub removes: ValueSet,
    pub order: PhaseOrder,
    pub order_reason: String,
    pub warnings: Vec<Warning>,
}

pub fn container_mismatches(
    expected: &super::Container,
    observed: &super::Container,
) -> Vec<String> {
    let mut fields = Vec::new();
    if expected.id != observed.id {
        fields.push("id".into());
    }
    if expected.list_type != observed.list_type {
        fields.push("type".into());
    }
    if expected.name != observed.name {
        fields.push("name".into());
    }
    if expected.description != observed.description {
        fields.push("description".into());
    }
    if expected.meta.is_some() && expected.meta != observed.meta {
        fields.push("meta".into());
    }
    fields
}

pub fn plan_list(
    local: LocalPair,
    before: Option<RemoteList>,
    installed: &[InstalledReference],
    desired: &[InstalledReference],
) -> Result<ListPlan> {
    super::stems::validate_id(&local.container.id)?;
    if local.stem != file_stem(&local.container.id) {
        return Err(super::invalid("value-list file stem does not match its id"));
    }
    local.container.list_type.require_supported()?;
    let id = &local.container.id;
    let container_action = match &before {
        None => ContainerAction::Create,
        Some(remote) => {
            if remote.container.container.id != *id {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "local and remote value-list ids differ",
                ));
            }
            if remote.container.container.list_type != local.container.list_type {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    format!(
                        "value list {id}: type change from {} to {} is refused",
                        remote.container.container.list_type, local.container.list_type
                    ),
                ));
            }
            if container_mismatches(&local.container, &remote.container.container).is_empty() {
                ContainerAction::None
            } else {
                ContainerAction::Update
            }
        }
    };
    let stored = before
        .as_ref()
        .map(|r| r.stored.clone())
        .unwrap_or_default();
    let current = stored.set();
    let adds: ValueSet = local.values.difference(&current).cloned().collect();
    let removes: ValueSet = current.difference(&local.values).cloned().collect();
    let additions = validate_additions(&local.container.list_type, &adds);
    if let Some(error) = additions.refusals.into_iter().next() {
        return Err(error);
    }
    let mut installed: Vec<_> = installed
        .iter()
        .filter(|r| r.list_id == *id)
        .cloned()
        .collect();
    let mut desired: Vec<_> = desired
        .iter()
        .filter(|r| r.list_id == *id)
        .cloned()
        .collect();
    sort_references(&mut installed);
    sort_references(&mut desired);
    for reference in installed.iter().chain(&desired) {
        if reference.list_type != local.container.list_type {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "{} names list {id} as {}, source type is {}",
                    reference.name(),
                    reference.list_type,
                    local.container.list_type
                ),
            ));
        }
    }
    if !adds.is_empty() || !removes.is_empty() {
        let mut items = std::collections::BTreeSet::new();
        for reference in &installed {
            if !items.insert((&reference.container, &reference.item_id)) {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    format!(
                        "list {id} is referenced more than once by {}",
                        reference.name()
                    ),
                ));
            }
        }
    }
    let removes_first = installed
        .iter()
        .all(|r| r.operator == ReferenceOperator::Included)
        && current.difference(&removes).next().is_some();
    let (order, order_reason) = if removes_first {
        (
            PhaseOrder::RemovesFirst,
            "every installed reference is included and removing values keeps the list non-empty",
        )
    } else {
        (
            PhaseOrder::AddsFirst,
            "an installed reference is excluded or removing values first would empty the list",
        )
    };
    let states = project_states(&stored, &adds, &removes, order);
    let checks = validate_projected(
        &local.container.list_type,
        &states,
        &ReferenceUse {
            installed: installed.iter().map(InstalledReference::name).collect(),
            desired: desired.iter().map(InstalledReference::name).collect(),
            creating: before.is_none(),
        },
    );
    if let Some(error) = checks.refusals.into_iter().next() {
        return Err(error);
    }
    let mut warnings = stored_warnings(&local.container.list_type, &stored);
    if let Some(warning) = super::size_warning(
        &local.container.list_type,
        states.final_values.values.iter().map(String::as_str),
    ) && !warnings.contains(&warning)
    {
        warnings.push(warning);
    }
    warnings.extend(
        checks
            .warnings
            .into_iter()
            .filter(|w| !warnings.iter().any(|existing| existing == w))
            .collect::<Vec<_>>(),
    );
    Ok(ListPlan {
        local,
        before,
        installed,
        desired,
        container_action,
        adds,
        removes,
        order,
        order_reason: order_reason.into(),
        warnings,
    })
}

pub async fn plan_import(t: &Transport, local: LocalPair, overwrite: bool) -> Result<ListPlan> {
    let validation = validate_additions(&local.container.list_type, &ValueSet::new());
    if let Some(error) = validation.refusals.into_iter().next() {
        return Err(error);
    }
    super::stems::validate_id(&local.container.id)?;
    require_bootstrapped(t).await?;
    let remote = read_list(t, &local.container.id).await?;
    if remote.is_some() && !overwrite {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "value list {} already exists; use --overwrite",
                local.container.id
            ),
        ));
    }
    let installed = scan_references(t).await?;
    plan_list(local, remote, &installed, &[])
}

pub fn pack_imports(values: &ValueSet) -> Result<Vec<String>> {
    let mut chunks = Vec::new();
    let mut chunk = String::new();
    for value in values {
        if value.len() >= MAX_VALUE_BYTES_WITH_LF {
            return Err(super::invalid(
                "one value with its LF exceeds the 8,000,000-byte import bound",
            ));
        }
        if chunk.len() + value.len() + 1 > MAX_VALUE_BYTES_WITH_LF {
            chunks.push(std::mem::take(&mut chunk));
        }
        chunk.push_str(value);
        chunk.push('\n');
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }
    Ok(chunks)
}

pub(super) fn stored_equal(a: &StoredValues, b: &StoredValues) -> bool {
    let mut a: Vec<_> = a.values.iter().collect();
    let mut b: Vec<_> = b.values.iter().collect();
    a.sort();
    b.sort();
    a == b
}
