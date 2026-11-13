use super::{item_refs, *};

pub(in crate::state) async fn pull_lists(
    t: &Transport,
    items: &[ExceptionItem],
) -> Result<(Vec<LocalPair>, Vec<Warning>)> {
    let refs = item_refs(items)?;
    let ids: BTreeSet<_> = refs.iter().map(|r| r.list_id.clone()).collect();
    let mut containers = Vec::new();
    let mut errors = Vec::new();
    for id in ids {
        let using: Vec<_> = refs
            .iter()
            .filter(|r| r.list_id == id)
            .map(InstalledReference::name)
            .collect();
        match vl::read_container(t, &id).await? {
            None => errors.push(format!("{id}: missing; items {}", using.join(", "))),
            Some(remote) => {
                if remote.container.list_type.require_supported().is_err() {
                    errors.push(format!(
                        "{id}: unsupported type {}; items {}",
                        remote.container.list_type,
                        using.join(", ")
                    ));
                } else if refs
                    .iter()
                    .any(|r| r.list_id == id && r.list_type != remote.container.list_type)
                {
                    errors.push(format!(
                        "{id}: container type {} differs from entry type; items {}",
                        remote.container.list_type,
                        using.join(", ")
                    ));
                } else {
                    containers.push(remote);
                }
            }
        }
    }
    if !errors.is_empty() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "cannot pull value lists: {}; fix the stack or narrow the pull to rules that do not use these lists",
                errors.join("; ")
            ),
        ));
    }
    let mut pairs = Vec::new();
    let mut warnings = Vec::new();
    for remote in containers {
        let names = vl::plan_stems([remote.container.id.as_str()])?;
        let stored =
            vl::export_values(t, &remote.container.id, &remote.container.list_type).await?;
        warnings.extend(vl::stored_warnings(&remote.container.list_type, &stored));
        pairs.push(LocalPair {
            stem: names[&remote.container.id].clone(),
            container: remote.container,
            values: stored.set(),
        });
    }
    Ok((pairs, warnings))
}
