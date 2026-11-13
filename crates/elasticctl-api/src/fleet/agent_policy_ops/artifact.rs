use super::{
    AgentPolicySpec, AgentPolicySummary, BTreeMap, BTreeSet, ContentFormat, Error, ErrorKind,
    ExportOutcome, Path, Result, Transport, collect, content_codec, is_platform_owned,
    live_from_item, read_live, resolve_item,
};

pub fn validate(path: &Path) -> Result<Vec<AgentPolicySpec>> {
    let body = std::fs::read_to_string(path).map_err(|error| {
        Error::new(
            ErrorKind::Error,
            format!("reading {}: {error}", path.display()),
        )
    })?;
    let mut specs = content_codec::decode_sequence::<AgentPolicySpec>(
        &body,
        ContentFormat::from_path(path),
        "agent policy",
    )?;
    let mut seen_ids = BTreeSet::new();
    let mut duplicate_ids = BTreeSet::new();
    let mut seen_names = BTreeSet::new();
    let mut duplicate_names = BTreeSet::new();
    for spec in &specs {
        if !seen_ids.insert(spec.id.as_str()) {
            duplicate_ids.insert(spec.id.as_str());
        }
        if !seen_names.insert(spec.name.as_str()) {
            duplicate_names.insert(spec.name.as_str());
        }
    }
    if !duplicate_ids.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            format!(
                "duplicate agent policy ids: {}",
                duplicate_ids.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    if !duplicate_names.is_empty() {
        return Err(Error::new(
            ErrorKind::Error,
            format!(
                "duplicate agent policy names: {}",
                duplicate_names.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(specs)
}

pub async fn export(
    transport: &Transport,
    selectors: &[String],
    all_custom: bool,
    format: ContentFormat,
) -> Result<ExportOutcome> {
    if selectors.is_empty() && !all_custom {
        return Err(Error::new(
            ErrorKind::Error,
            "agent-policy export needs selectors or --all-custom",
        ));
    }
    if !selectors.is_empty() && all_custom {
        return Err(Error::new(
            ErrorKind::Error,
            "--all-custom cannot be combined with selectors",
        ));
    }
    let mut resolved_items = BTreeMap::new();
    let ids: BTreeSet<String> = if all_custom {
        let mut ids = BTreeSet::new();
        for item in collect(transport).await? {
            if !is_platform_owned(&item)? {
                ids.insert(AgentPolicySummary::from_item(&item)?.id);
            }
        }
        ids
    } else {
        let mut ids = BTreeSet::new();
        for selector in selectors {
            let resolved = resolve_item(transport, selector).await?;
            ids.insert(resolved.summary.id.clone());
            resolved_items.insert(resolved.summary.id, resolved.item);
        }
        ids
    };
    let mut specs = Vec::with_capacity(ids.len());
    for id in &ids {
        let live = match resolved_items.get(id) {
            Some(item) => live_from_item(item, id, transport.space())?,
            None => read_live(transport, id).await?,
        };
        specs.push(live.spec);
    }
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    let body = content_codec::encode_sequence(&specs, format)?;
    Ok(ExportOutcome {
        body,
        exported: specs.len() as u64,
        missing: Vec::new(),
    })
}
