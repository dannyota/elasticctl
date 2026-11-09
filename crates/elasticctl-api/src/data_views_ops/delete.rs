//! Data view deletion planning and apply.

use super::{
    BTreeSet, DataViewReference, DataViewSummary, DeleteOutcome, Error, ErrorKind, MutationPlan,
    Result, Transport, data_views, invalid_plan, json, resolve_from_summaries,
};

/// One stable source and the reference/default facts shown in a delete guard.
#[derive(Debug, Clone, PartialEq)]
pub struct DataViewDeleteTarget {
    pub source: DataViewSummary,
    pub references: Vec<DataViewReference>,
    pub was_default: bool,
}

/// An immutable, guard-ready data-view deletion or reference replacement.
#[derive(Debug, Clone, PartialEq)]
pub struct DataViewDeletePlan {
    pub preview: MutationPlan,
    pub targets: Vec<DataViewDeleteTarget>,
    pub replacement: Option<DataViewSummary>,
    pub default_before: Option<String>,
}
/// Resolve every delete selector and inspect all references before the guard.
pub async fn plan_delete(
    transport: &Transport,
    selectors: &[String],
    replacement_selector: Option<&str>,
) -> Result<DataViewDeletePlan> {
    if selectors.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            "data-view delete needs at least one source",
        ));
    }

    // A single stable list snapshot resolves every selector, including the
    // optional replacement, before any reference preview can observe a later
    // state.
    let views = data_views::list(transport).await?;
    let mut seen = BTreeSet::new();
    let mut sources = Vec::new();
    for selector in selectors {
        let source = resolve_from_summaries(&views, selector)?;
        if seen.insert(source.id.clone()) {
            sources.push(source);
        }
    }
    let replacement = replacement_selector
        .map(|selector| resolve_from_summaries(&views, selector))
        .transpose()?;

    if replacement.is_some() && sources.len() != 1 {
        return Err(Error::new(
            ErrorKind::Error,
            "--replace-with accepts exactly one source data view",
        ));
    }
    if let Some(replacement) = &replacement
        && sources.iter().any(|source| source.id == replacement.id)
    {
        return Err(Error::new(
            ErrorKind::Error,
            "--replace-with must differ from every source data view",
        ));
    }

    let default_before = data_views::get_default(transport).await?;
    let mut targets = Vec::with_capacity(sources.len());
    for source in sources {
        let mut references = data_views::preview_swap(transport, &source.id, &source.id).await?;
        normalize_references(&mut references)?;
        targets.push(DataViewDeleteTarget {
            was_default: default_before.as_deref() == Some(source.id.as_str()),
            source,
            references,
        });
    }

    if replacement.is_none() {
        let referenced: Vec<_> = targets
            .iter()
            .filter(|target| !target.references.is_empty())
            .map(|target| {
                format!(
                    "{}: {}",
                    target.source.id,
                    reference_names(&target.references).join(", ")
                )
            })
            .collect();
        if !referenced.is_empty() {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "data views have live references; use --replace-with: {}",
                    referenced.join("; ")
                ),
            ));
        }
        let defaults: Vec<_> = targets
            .iter()
            .filter(|target| target.was_default)
            .map(|target| target.source.id.as_str())
            .collect();
        if !defaults.is_empty() {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "data views are the current default; use data-views default unset or --replace-with: {}",
                    defaults.join(", ")
                ),
            ));
        }
    }

    Ok(DataViewDeletePlan {
        preview: delete_preview(&targets, replacement.as_ref()),
        targets,
        replacement,
        default_before,
    })
}

/// Apply a guarded data-view deletion without resolving selectors again.
pub async fn apply_delete(
    transport: &Transport,
    plan: &DataViewDeletePlan,
) -> Result<DeleteOutcome> {
    validate_delete_plan(plan)?;
    let mut deleted = Vec::new();
    let mut failed = Vec::new();

    match (&plan.replacement, plan.targets.as_slice()) {
        (None, targets) => {
            for target in targets {
                if let Err(error) =
                    check_delete_snapshot(transport, target, plan.default_before.as_deref()).await
                {
                    failed.push(json!({"id": target.source.id, "error": error.message}));
                    continue;
                }
                match data_views::delete(transport, &target.source.id).await {
                    Ok(()) => deleted.push(json!({"id": target.source.id})),
                    Err(error) => {
                        failed.push(json!({"id": target.source.id, "error": error.message}))
                    }
                }
            }
        }
        (Some(replacement), [target]) => {
            if let Err(error) =
                check_delete_snapshot(transport, target, plan.default_before.as_deref()).await
            {
                failed.push(json!({"id": target.source.id, "error": error.message}));
                return Ok(DeleteOutcome {
                    applied: true,
                    deleted,
                    failed,
                    total: plan.targets.len(),
                });
            }
            match data_views::swap(transport, &target.source.id, &replacement.id).await {
                Err(error) => failed.push(json!({"id": target.source.id, "error": error.message})),
                Ok(swap)
                    if !swap.delete_status.delete_performed
                        || swap.delete_status.remaining_refs != 0 =>
                {
                    failed.push(json!({
                        "id": target.source.id,
                        "error": "reference swap did not delete source or left references"
                    }));
                }
                Ok(_) if target.was_default => {
                    match data_views::get_default(transport).await {
                        Err(error) => failed.push(json!({
                            "id": target.source.id,
                            "error": format!("references moved and source deleted; default recheck failed: {}", error.message)
                        })),
                        Ok(Some(current)) if current == target.source.id => {
                            if let Err(error) =
                                data_views::set_default(transport, Some(&replacement.id)).await
                            {
                                failed.push(json!({
                                    "id": target.source.id,
                                    "error": format!("references moved and source deleted; default update failed: {}", error.message)
                                }));
                            } else {
                                deleted.push(json!({"id": target.source.id}));
                            }
                        }
                        Ok(Some(current)) if current == replacement.id => {
                            deleted.push(json!({"id": target.source.id}));
                        }
                        Ok(_) => failed.push(json!({
                            "id": target.source.id,
                            "error": "references moved and source deleted; default changed before update"
                        })),
                    }
                }
                Ok(_) => deleted.push(json!({"id": target.source.id})),
            }
        }
        _ => unreachable!("the public plan validator checked replacement cardinality"),
    }

    Ok(DeleteOutcome {
        applied: true,
        deleted,
        failed,
        total: plan.targets.len(),
    })
}

/// Re-read the source's guarded safety facts in the route order that leaves
/// the smallest documented check-to-write window.
async fn check_delete_snapshot(
    transport: &Transport,
    target: &DataViewDeleteTarget,
    default_before: Option<&str>,
) -> Result<()> {
    let mut references =
        data_views::preview_swap(transport, &target.source.id, &target.source.id).await?;
    normalize_references(&mut references)?;
    let default = data_views::get_default(transport).await?;
    if references != target.references {
        return Err(Error::new(
            ErrorKind::Conflict,
            "references changed since preview",
        ));
    }
    if default.as_deref() != default_before {
        return Err(Error::new(
            ErrorKind::Conflict,
            "default data view changed since preview",
        ));
    }
    Ok(())
}

fn normalize_references(references: &mut Vec<DataViewReference>) -> Result<()> {
    if references
        .iter()
        .any(|reference| reference.id.trim().is_empty() || reference.object_type.trim().is_empty())
    {
        return Err(Error::new(
            ErrorKind::Http,
            "decoding data view reference swap preview: reference id and type must not be empty",
        ));
    }
    references.sort_by(|left, right| {
        (left.object_type.as_str(), left.id.as_str())
            .cmp(&(right.object_type.as_str(), right.id.as_str()))
    });
    references.dedup_by(|left, right| left.object_type == right.object_type && left.id == right.id);
    Ok(())
}

fn reference_names(references: &[DataViewReference]) -> Vec<String> {
    references
        .iter()
        .map(|reference| format!("{}/{}", reference.object_type, reference.id))
        .collect()
}

fn delete_preview(
    targets: &[DataViewDeleteTarget],
    replacement: Option<&DataViewSummary>,
) -> MutationPlan {
    let preview_details = targets
        .iter()
        .flat_map(|target| {
            let mut details: Vec<_> = reference_names(&target.references)
                .into_iter()
                .map(|reference| format!("{}  {reference}", target.source.id))
                .collect();
            match replacement {
                None => details.push(format!("{}  direct delete", target.source.id)),
                Some(replacement) if target.was_default => details.push(format!(
                    "{}  default -> {}",
                    target.source.id, replacement.id
                )),
                Some(_) => {}
            }
            details
        })
        .collect();
    MutationPlan {
        preview_action: match replacement {
            Some(replacement) => format!(
                "Replace references and delete {} with {}",
                targets[0].source.id, replacement.id
            ),
            None => format!("Delete {} data view(s)", targets.len()),
        },
        preview_details,
        targets: targets
            .iter()
            .map(|target| target.source.id.clone())
            .collect(),
    }
}

fn validate_delete_plan(plan: &DataViewDeletePlan) -> Result<()> {
    if plan.targets.is_empty() {
        return invalid_plan("data-view delete plan needs at least one target");
    }
    let mut ids = BTreeSet::new();
    if plan
        .default_before
        .as_deref()
        .is_some_and(|id| id.trim().is_empty())
    {
        return invalid_plan("default data-view snapshot id must not be empty");
    }
    for target in &plan.targets {
        if target.source.id.trim().is_empty() || target.source.title.trim().is_empty() {
            return invalid_plan("data-view delete target identity must not be empty");
        }
        if !ids.insert(target.source.id.clone()) {
            return invalid_plan("data-view delete targets must be unique by id");
        }
        if target.was_default != (plan.default_before.as_deref() == Some(target.source.id.as_str()))
        {
            return invalid_plan("data-view delete default claims do not match its snapshot");
        }
        let mut canonical = target.references.clone();
        normalize_references(&mut canonical).map_err(|error| {
            Error::new(
                ErrorKind::Error,
                format!("invalid data-view delete plan: {}", error.message),
            )
        })?;
        if canonical != target.references {
            return invalid_plan("data-view delete references must be sorted and unique");
        }
    }
    if let Some(replacement) = &plan.replacement {
        if plan.targets.len() != 1 {
            return invalid_plan("replacement delete plan must have exactly one target");
        }
        if replacement.id.trim().is_empty() || replacement.title.trim().is_empty() {
            return invalid_plan("replacement data-view identity must not be empty");
        }
        if replacement.id == plan.targets[0].source.id {
            return invalid_plan("replacement data view must differ from its source");
        }
    } else if plan
        .targets
        .iter()
        .any(|target| target.was_default || !target.references.is_empty())
    {
        return invalid_plan("direct delete plan contains default or referenced data view");
    }

    if plan.preview != delete_preview(&plan.targets, plan.replacement.as_ref()) {
        return invalid_plan("data-view delete preview does not match guarded targets");
    }
    Ok(())
}
