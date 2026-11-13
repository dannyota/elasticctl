use super::common::*;

const PORTABLE_OPTIONAL: [&str; 6] = [
    "description",
    "namespace",
    "vars",
    "var_group_selections",
    "condition",
    "additional_datastreams_permissions",
];

const REMOVED_FIELDS: [&str; 19] = [
    "agents",
    "cloud_connector_id",
    "cloud_connector_name",
    "created_at",
    "created_by",
    "elasticsearch",
    "enabled",
    "is_managed",
    "output_id",
    "package_agent_version_condition",
    "policy_id",
    "revision",
    "secret_references",
    "spaceIds",
    "supports_agentless",
    "supports_cloud_connector",
    "updated_at",
    "updated_by",
    "version",
];

pub fn normalize(item: &Map<String, Value>, active_space: &str) -> Result<IntegrationPolicySpec> {
    let id = required_string(item, "id", "integration policy")?;
    portability_check(item, &id, active_space)?;
    reject_unknown_top_level(item, &id)?;

    let mut portable = Map::new();
    for field in ["id", "name"] {
        if let Some(value) = item.get(field) {
            portable.insert(field.to_owned(), value.clone());
        }
    }
    portable.insert(
        "policy_ids".to_owned(),
        Value::Array(
            read_parents(&id, item)?
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    portable.insert("package".to_owned(), normalize_package(item, &id)?);
    portable.insert("inputs".to_owned(), normalize_inputs(item, &id)?);
    for field in PORTABLE_OPTIONAL {
        if let Some(value) = item.get(field)
            && !value.is_null()
        {
            portable.insert(field.to_owned(), value.clone());
        }
    }
    IntegrationPolicySpec::try_from(Value::Object(portable)).map_err(|error| {
        http(format!(
            "decoding integration policy '{id}': {}",
            error.message
        ))
    })
}

fn normalize_package(item: &Map<String, Value>, id: &str) -> Result<Value> {
    let package = item
        .get("package")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            http(format!(
                "decoding integration policy '{id}': package must be an object"
            ))
        })?;
    for (field, expected) in [("title", "a string")] {
        if let Some(value) = package.get(field)
            && !value.is_null()
            && !value.is_string()
        {
            return Err(http(format!(
                "decoding integration policy '{id}': package.{field} must be {expected} or null"
            )));
        }
    }
    for field in ["requires_root", "fips_compatible"] {
        if let Some(value) = package.get(field)
            && !value.is_null()
            && !value.is_boolean()
        {
            return Err(http(format!(
                "decoding integration policy '{id}': package.{field} must be a boolean or null"
            )));
        }
    }
    let mut portable = Map::new();
    for field in ["name", "version"] {
        if let Some(value) = package.get(field) {
            portable.insert(field.to_owned(), value.clone());
        }
    }
    let known: BTreeSet<&str> = [
        "name",
        "version",
        "title",
        "requires_root",
        "fips_compatible",
    ]
    .into_iter()
    .collect();
    if let Some(field) = package
        .keys()
        .map(String::as_str)
        .filter(|field| !known.contains(field))
        .min()
    {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!("integration policy '{id}' carries unknown package field '{field}'"),
        ));
    }
    Ok(Value::Object(portable))
}

fn normalize_inputs(item: &Map<String, Value>, id: &str) -> Result<Value> {
    let inputs = item
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            http(format!(
                "decoding integration policy '{id}': inputs must be an object"
            ))
        })?;
    let mut normalized = Map::new();
    for (input_id, input) in inputs {
        normalized.insert(
            input_id.clone(),
            normalize_package_map(input, "compiled_input")?,
        );
    }
    Ok(Value::Object(normalized))
}

fn normalize_package_map(value: &Value, compiled_field: &str) -> Result<Value> {
    let object = value
        .as_object()
        .ok_or_else(|| http("decoding integration policy: input must be an object"))?;
    let mut normalized = Map::new();
    for (field, value) in object {
        if field == "id" {
            if !value.is_string() {
                return Err(http(
                    "decoding integration policy: generated id must be a string",
                ));
            }
            continue;
        }
        if field == compiled_field {
            if !value.is_object() {
                return Err(http(format!(
                    "decoding integration policy: {compiled_field} must be an object"
                )));
            }
            continue;
        }
        if field == "streams" {
            let streams = value.as_object().ok_or_else(|| {
                http("decoding integration policy: input streams must be an object")
            })?;
            let mut normalized_streams = Map::new();
            for (stream_id, stream) in streams {
                normalized_streams.insert(
                    stream_id.clone(),
                    normalize_package_map(stream, "compiled_stream")?,
                );
            }
            normalized.insert(field.clone(), Value::Object(normalized_streams));
        } else {
            normalized.insert(field.clone(), value.clone());
        }
    }
    Ok(Value::Object(normalized))
}

fn portability_check(item: &Map<String, Value>, id: &str, active_space: &str) -> Result<()> {
    let mut reasons = BTreeSet::new();
    required_true(item, "enabled", id)?;
    if let Some(value) = item.get("elasticsearch")
        && !value.is_object()
    {
        return Err(http(format!(
            "decoding integration policy '{id}': elasticsearch must be an object"
        )));
    }
    if let Some(value) = item.get("package_agent_version_condition")
        && !value.is_null()
        && !value.is_string()
    {
        return Err(http(format!(
            "decoding integration policy '{id}': package_agent_version_condition must be a string or null"
        )));
    }
    for field in [
        "is_managed",
        "supports_agentless",
        "supports_cloud_connector",
    ] {
        if let Some(true) = optional_bool(item, field, id)? {
            reasons.insert(field);
        }
    }
    for field in ["output_id", "cloud_connector_id", "cloud_connector_name"] {
        match item.get(field) {
            None | Some(Value::Null) | Some(Value::Bool(false)) => {}
            Some(Value::String(_)) => {
                reasons.insert(field);
            }
            Some(_) => {
                return Err(http(format!(
                    "decoding integration policy '{id}': {field} must be a string or null"
                )));
            }
        }
    }
    match item.get("secret_references") {
        None | Some(Value::Null) => {}
        Some(Value::Array(references)) if references.is_empty() => {}
        Some(Value::Array(_)) => {
            reasons.insert("secret_references");
        }
        Some(_) => {
            return Err(http(format!(
                "decoding integration policy '{id}': secret_references must be an array or null"
            )));
        }
    }
    let active = if active_space.is_empty() {
        "default"
    } else {
        active_space
    };
    match item.get("spaceIds") {
        None | Some(Value::Null) => {}
        Some(Value::Array(spaces)) => {
            for space in spaces {
                let space = space.as_str().filter(|space| !space.is_empty()).ok_or_else(|| {
                    http(format!(
                        "decoding integration policy '{id}': spaceIds must contain non-empty strings"
                    ))
                })?;
                if space != active {
                    reasons.insert("spaceIds");
                }
            }
        }
        Some(_) => {
            return Err(http(format!(
                "decoding integration policy '{id}': spaceIds must be an array or null"
            )));
        }
    }
    if let Some(policy_id) = item.get("policy_id").filter(|value| !value.is_null()) {
        let policy_id = policy_id
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                http(format!(
                    "decoding integration policy '{id}': policy_id must be a non-empty string"
                ))
            })?;
        let policy_ids = item
            .get("policy_ids")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                http(format!(
                    "decoding integration policy '{id}': policy_ids must be an array"
                ))
            })?;
        if policy_ids.first().and_then(Value::as_str) != Some(policy_id) {
            return Err(http(format!(
                "decoding integration policy '{id}': policy_id must equal policy_ids[0]"
            )));
        }
    }
    if reasons.is_empty() {
        Ok(())
    } else {
        unsupported(format!(
            "integration policy '{id}' is not portable: {}",
            reasons.into_iter().collect::<Vec<_>>().join(", ")
        ))
    }
}

fn required_true(item: &Map<String, Value>, field: &str, id: &str) -> Result<()> {
    match item.get(field) {
        Some(Value::Bool(true)) => Ok(()),
        Some(Value::Bool(false)) => unsupported(format!(
            "integration policy '{id}' is not portable: {field}"
        )),
        _ => Err(http(format!(
            "decoding integration policy '{id}': {field} must be true"
        ))),
    }
}

fn reject_unknown_top_level(item: &Map<String, Value>, id: &str) -> Result<()> {
    let known: BTreeSet<&str> = ["id", "name", "policy_ids", "package", "inputs"]
        .into_iter()
        .chain(PORTABLE_OPTIONAL)
        .chain(REMOVED_FIELDS)
        .collect();
    if let Some(field) = item
        .keys()
        .map(String::as_str)
        .filter(|field| !known.contains(field))
        .min()
    {
        return unsupported(format!(
            "integration policy '{id}' carries unknown field '{field}'"
        ));
    }
    Ok(())
}
