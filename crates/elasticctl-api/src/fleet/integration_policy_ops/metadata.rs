use super::common::*;

/// Exact package-defined secret variables. The companion `known_*` maps are
/// deliberately private implementation detail: a configured value is safe
/// only after Fleet metadata proves it has a definition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SecretSchema {
    package_vars: BTreeSet<String>,
    input_vars: BTreeMap<String, BTreeSet<String>>,
    stream_vars: BTreeMap<(String, String), BTreeSet<String>>,
}

#[derive(Debug, Clone, Default)]
struct KnownSchema {
    package_vars: BTreeSet<String>,
    input_vars: BTreeMap<String, BTreeSet<String>>,
    stream_vars: BTreeMap<(String, String), BTreeSet<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct VariableDefinitions {
    known: BTreeSet<String>,
    secrets: BTreeSet<String>,
}

#[derive(Debug)]
struct TemplateDefinitions {
    inputs: BTreeMap<String, String>,
    datasets: BTreeSet<String>,
}

pub(super) fn configured_secret_paths(
    spec: &IntegrationPolicySpec,
    metadata: &Map<String, Value>,
) -> Result<Vec<String>> {
    let (secrets, known) = secret_schema(metadata)?;
    let mut paths = BTreeSet::new();
    configured_vars(
        spec.vars.as_ref(),
        &known.package_vars,
        &secrets.package_vars,
        &spec.id,
        "vars",
        &mut paths,
    )?;
    for (input_key, input) in &spec.inputs {
        let input = input.as_object().ok_or_else(|| {
            http(format!(
                "decoding integration policy '{}': inputs.{input_key} must be an object",
                spec.id
            ))
        })?;
        let known_vars = known.input_vars.get(input_key).ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                format!(
                    "integration policy '{}': {}:inputs.{input_key} has no matching package definition",
                    spec.id, spec.id
                ),
            )
        })?;
        let secret_vars = secrets
            .input_vars
            .get(input_key)
            .cloned()
            .unwrap_or_default();
        configured_vars(
            input.get("vars").map(expect_object).transpose()?,
            known_vars,
            &secret_vars,
            &spec.id,
            &format!("inputs.{input_key}.vars"),
            &mut paths,
        )?;
        if let Some(streams) = input.get("streams") {
            let streams = streams.as_object().ok_or_else(|| {
                http(format!(
                    "decoding integration policy '{}': inputs.{input_key}.streams must be an object",
                    spec.id
                ))
            })?;
            for (dataset, stream) in streams {
                let stream = stream.as_object().ok_or_else(|| {
                    http(format!(
                        "decoding integration policy '{}': inputs.{input_key}.streams.{dataset} must be an object",
                        spec.id
                    ))
                })?;
                let key = (input_key.clone(), dataset.clone());
                let known_vars = known.stream_vars.get(&key).ok_or_else(|| {
                    Error::new(
                        ErrorKind::Unsupported,
                        format!(
                            "integration policy '{}': {}:inputs.{input_key}.streams.{dataset} has no matching package definition",
                            spec.id, spec.id
                        ),
                    )
                })?;
                let secret_vars = secrets.stream_vars.get(&key).cloned().unwrap_or_default();
                configured_vars(
                    stream.get("vars").map(expect_object).transpose()?,
                    known_vars,
                    &secret_vars,
                    &spec.id,
                    &format!("inputs.{input_key}.streams.{dataset}.vars"),
                    &mut paths,
                )?;
            }
        }
    }
    Ok(paths.into_iter().collect())
}

fn expect_object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| http("decoding integration policy: configured vars must be an object"))
}

fn configured_vars(
    configured: Option<&Map<String, Value>>,
    known: &BTreeSet<String>,
    secret: &BTreeSet<String>,
    policy_id: &str,
    prefix: &str,
    paths: &mut BTreeSet<String>,
) -> Result<()> {
    let Some(configured) = configured else {
        return Ok(());
    };
    for name in configured.keys() {
        if !known.contains(name) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "integration policy '{policy_id}' is not portable: {policy_id}:{prefix}.{name} has no matching package definition"
                ),
            ));
        }
        if secret.contains(name) {
            paths.insert(format!("{prefix}.{name}"));
        }
    }
    Ok(())
}

fn secret_schema(metadata: &Map<String, Value>) -> Result<(SecretSchema, KnownSchema)> {
    let package_name = metadata_name(metadata, "name", "package metadata")?;
    let package_vars = parse_var_definitions(metadata.get("vars"), "package metadata vars")?;
    let modern_datasets = parse_modern_data_streams(metadata.get("data_streams"))?;

    let mut secrets = SecretSchema {
        package_vars: package_vars.secrets.clone(),
        ..SecretSchema::default()
    };
    let mut known = KnownSchema {
        package_vars: package_vars.known,
        ..KnownSchema::default()
    };
    let mut template_names = BTreeSet::new();
    let mut templates = Vec::new();
    let mut legacy_streams = BTreeMap::new();
    let policy_templates = match metadata.get("policy_templates") {
        None => &[][..],
        Some(Value::Array(value)) => value,
        Some(_) => {
            return Err(http(
                "decoding package metadata: policy_templates must be an array",
            ));
        }
    };

    for template in policy_templates {
        let template = template.as_object().ok_or_else(|| {
            http("decoding package metadata: policy_templates entry must be an object")
        })?;
        let template_name = metadata_name(template, "name", "policy_templates entry")?;
        if !template_names.insert(template_name.clone()) {
            return Err(http(format!(
                "decoding package metadata: duplicate template name '{template_name}'"
            )));
        }
        let datasets = resolve_template_datasets(
            template.get("data_streams"),
            &modern_datasets,
            &package_name,
            &template_name,
        )?;
        let inputs = match template.get("inputs") {
            None => &[][..],
            Some(Value::Array(value)) => value,
            Some(_) => {
                return Err(http(
                    "decoding package metadata: policy_templates inputs must be an array",
                ));
            }
        };
        let mut template_inputs = BTreeMap::new();
        for input in inputs {
            let input = input.as_object().ok_or_else(|| {
                http("decoding package metadata: policy_templates inputs entry must be an object")
            })?;
            let input_type = metadata_name(input, "type", "policy_templates input")?;
            let input_key = format!("{template_name}-{input_type}");
            let input_vars =
                parse_var_definitions(input.get("vars"), "package metadata input vars")?;
            if template_inputs
                .insert(input_type.clone(), input_key.clone())
                .is_some()
                || known
                    .input_vars
                    .insert(input_key.clone(), input_vars.known)
                    .is_some()
            {
                return Err(http(format!(
                    "decoding package metadata: duplicate input key '{input_key}'"
                )));
            }
            if !input_vars.secrets.is_empty() {
                secrets
                    .input_vars
                    .insert(input_key.clone(), input_vars.secrets);
            }

            let streams = match input.get("streams") {
                None => &[][..],
                Some(Value::Array(value)) => value,
                Some(_) => {
                    return Err(http(
                        "decoding package metadata: input streams must be an array",
                    ));
                }
            };
            for stream in streams {
                let stream = stream.as_object().ok_or_else(|| {
                    http("decoding package metadata: input streams entry must be an object")
                })?;
                let data_stream = stream
                    .get("data_stream")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        http("decoding package metadata: stream data_stream must be an object")
                    })?;
                let dataset = metadata_name(data_stream, "dataset", "stream data_stream")?;
                let definition =
                    parse_var_definitions(stream.get("vars"), "package metadata stream vars")?;
                let key = (input_key.clone(), dataset);
                if legacy_streams.insert(key.clone(), definition).is_some() {
                    return Err(http(format!(
                        "decoding package metadata: duplicate stream key '{}:{}'",
                        key.0, key.1
                    )));
                }
            }
        }
        templates.push(TemplateDefinitions {
            inputs: template_inputs,
            datasets,
        });
    }

    let mut modern_streams = BTreeMap::new();
    for (dataset, streams) in &modern_datasets {
        for (input_type, definition) in streams {
            let candidates = templates
                .iter()
                .filter(|template| template.datasets.contains(dataset))
                .filter_map(|template| template.inputs.get(input_type))
                .cloned()
                .collect::<Vec<_>>();
            let input_key = match candidates.as_slice() {
                [input_key] => input_key.clone(),
                [] => {
                    return Err(http(format!(
                        "decoding package metadata: stream '{dataset}:{input_type}' has no matching template input"
                    )));
                }
                _ => {
                    return Err(http(format!(
                        "decoding package metadata: stream '{dataset}:{input_type}' has multiple matching template inputs"
                    )));
                }
            };
            let key = (input_key, dataset.clone());
            if modern_streams
                .insert(key.clone(), definition.clone())
                .is_some()
            {
                return Err(http(format!(
                    "decoding package metadata: duplicate stream key '{}:{}'",
                    key.0, key.1
                )));
            }
        }
    }

    for (key, definition) in legacy_streams {
        match modern_streams.get(&key) {
            Some(modern) if modern != &definition => {
                return Err(http(format!(
                    "decoding package metadata: conflicting modern and legacy stream definition '{}:{}'",
                    key.0, key.1
                )));
            }
            Some(_) => {}
            None => {
                modern_streams.insert(key, definition);
            }
        }
    }
    for (key, definition) in modern_streams {
        if !definition.secrets.is_empty() {
            secrets.stream_vars.insert(key.clone(), definition.secrets);
        }
        known.stream_vars.insert(key, definition.known);
    }
    Ok((secrets, known))
}

fn parse_modern_data_streams(
    value: Option<&Value>,
) -> Result<BTreeMap<String, BTreeMap<String, VariableDefinitions>>> {
    let data_streams = match value {
        None => &[][..],
        Some(Value::Array(value)) => value,
        Some(_) => {
            return Err(http(
                "decoding package metadata: data_streams must be an array",
            ));
        }
    };
    let mut datasets = BTreeMap::new();
    for data_stream in data_streams {
        let data_stream = data_stream.as_object().ok_or_else(|| {
            http("decoding package metadata: data_streams entry must be an object")
        })?;
        let dataset = metadata_name(data_stream, "dataset", "data_streams entry")?;
        let streams = match data_stream.get("streams") {
            None => &[][..],
            Some(Value::Array(value)) => value,
            Some(_) => {
                return Err(http(
                    "decoding package metadata: data_streams streams must be an array",
                ));
            }
        };
        let mut stream_definitions = BTreeMap::new();
        for stream in streams {
            let stream = stream.as_object().ok_or_else(|| {
                http("decoding package metadata: data_streams streams entry must be an object")
            })?;
            let input = metadata_name(stream, "input", "data_streams stream")?;
            let definition =
                parse_var_definitions(stream.get("vars"), "package metadata stream vars")?;
            if stream_definitions
                .insert(input.clone(), definition)
                .is_some()
            {
                return Err(http(format!(
                    "decoding package metadata: duplicate stream input '{input}' for dataset '{dataset}'"
                )));
            }
        }
        if datasets
            .insert(dataset.clone(), stream_definitions)
            .is_some()
        {
            return Err(http(format!(
                "decoding package metadata: duplicate data stream dataset '{dataset}'"
            )));
        }
    }
    Ok(datasets)
}

fn resolve_template_datasets(
    value: Option<&Value>,
    datasets: &BTreeMap<String, BTreeMap<String, VariableDefinitions>>,
    package_name: &str,
    template_name: &str,
) -> Result<BTreeSet<String>> {
    let Some(value) = value else {
        return Ok(datasets.keys().cloned().collect());
    };
    let selectors = value
        .as_array()
        .ok_or_else(|| http("decoding package metadata: template data_streams must be an array"))?;
    let mut selected = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for selector in selectors {
        let selector = selector
            .as_str()
            .filter(|selector| !selector.trim().is_empty())
            .ok_or_else(|| {
                http("decoding package metadata: template data_streams selector must be a non-empty string")
            })?;
        if !seen.insert(selector) {
            return Err(http(format!(
                "decoding package metadata: duplicate data_streams selector '{selector}' in template '{template_name}'"
            )));
        }
        let short_name = format!("{package_name}.{selector}");
        let candidates = datasets
            .keys()
            .filter(|dataset| dataset.as_str() == selector || dataset.as_str() == short_name)
            .collect::<Vec<_>>();
        match candidates.as_slice() {
            [dataset] => {
                if !selected.insert((**dataset).clone()) {
                    return Err(http(format!(
                        "decoding package metadata: duplicate data_streams dataset '{}' in template '{template_name}'",
                        dataset
                    )));
                }
            }
            [] => {
                return Err(http(format!(
                    "decoding package metadata: data_streams selector '{selector}' in template '{template_name}' does not match a dataset"
                )));
            }
            _ => {
                return Err(http(format!(
                    "decoding package metadata: data_streams selector '{selector}' in template '{template_name}' matches multiple datasets"
                )));
            }
        }
    }
    Ok(selected)
}

fn parse_var_definitions(value: Option<&Value>, context: &str) -> Result<VariableDefinitions> {
    let values = match value {
        None => return Ok(VariableDefinitions::default()),
        Some(Value::Array(values)) => values,
        Some(_) => return Err(http(format!("decoding {context}: vars must be an array"))),
    };
    let mut definitions = VariableDefinitions::default();
    for value in values {
        let definition = value
            .as_object()
            .ok_or_else(|| http(format!("decoding {context}: variable must be an object")))?;
        let name = metadata_name(definition, "name", context)?;
        if !definitions.known.insert(name.clone()) {
            return Err(http(format!(
                "decoding {context}: duplicate variable name '{name}'"
            )));
        }
        match definition.get("secret") {
            None => {}
            Some(Value::Bool(true)) => {
                definitions.secrets.insert(name);
            }
            Some(Value::Bool(false)) => {}
            Some(_) => {
                return Err(http(format!(
                    "decoding {context}: secret must be a boolean"
                )));
            }
        }
    }
    Ok(definitions)
}

fn metadata_name(object: &Map<String, Value>, field: &str, context: &str) -> Result<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            http(format!(
                "decoding package metadata: {context} {field} must be a non-empty string"
            ))
        })
}

pub(super) fn validate_package_metadata_snapshot(
    metadata: &Map<String, Value>,
    package: &IntegrationPackageSpec,
) -> Result<()> {
    let name = metadata_name(metadata, "name", "package metadata")?;
    let version = metadata_name(metadata, "version", "package metadata")?;
    if name != package.name || version != package.version {
        return Err(http(format!(
            "decoding package metadata: expected {}@{}, got {name}@{version}",
            package.name, package.version
        )));
    }
    secret_schema(metadata).map(|_| ())
}

pub(super) fn validate_effective_input_materialization(
    spec: &IntegrationPolicySpec,
    metadata: &Map<String, Value>,
) -> Result<()> {
    let (_, known) = secret_schema(metadata)?;
    if spec.inputs.is_empty() && !known.input_vars.is_empty() {
        return unsupported(format!(
            "integration policy '{}' has an empty inputs map but package {}@{} declares inputs",
            spec.id, spec.package.name, spec.package.version
        ));
    }
    Ok(())
}
