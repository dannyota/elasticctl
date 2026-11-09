//! Metadata helpers.

use crate::diagnostics::recording_error;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

type MetadataVariables = BTreeMap<String, bool>;

struct ReducedMetadataInput {
    key: String,
    vars: MetadataVariables,
    streams: BTreeMap<String, MetadataVariables>,
}

struct ReducedMetadataTemplate {
    name: String,
    data_streams: Option<Vec<String>>,
    selected_datasets: BTreeSet<String>,
    inputs: BTreeMap<String, ReducedMetadataInput>,
}

/// The package registry exposes a broad, deployment-specific document. The
/// recorder accepts its schema only after reducing it to the exact fields the
/// integration-policy secret classifier needs. The structural checks mirror
/// the production secret parser so an ambiguous public fixture never becomes
/// a more permissive test input than a live package response.
pub(crate) fn reduce_integration_package_metadata(
    body: &Value,
    expected_name: &str,
    expected_version: &str,
) -> elasticctl_core::Result<Value> {
    let item = body
        .get("item")
        .and_then(Value::as_object)
        .ok_or_else(|| recording_error("package metadata must contain an item object"))?;
    let name = metadata_nonempty_string(item, "name", "package metadata")?;
    let version = metadata_nonempty_string(item, "version", "package metadata")?;
    if name != expected_name || version != expected_version {
        return Err(recording_error(
            "package metadata did not preserve the requested exact coordinate",
        ));
    }
    let status = metadata_nonempty_string(item, "status", "package metadata")?;
    if !matches!(status.as_str(), "installed" | "not_installed") {
        return Err(recording_error(
            "package metadata status must be installed or not_installed",
        ));
    }

    let vars = reduce_metadata_variables(item.get("vars"), "package metadata vars")?;
    let modern_datasets = reduce_metadata_data_streams(item.get("data_streams"))?;
    let templates = match item.get("policy_templates") {
        None => &[][..],
        Some(Value::Array(templates)) => templates.as_slice(),
        Some(_) => {
            return Err(recording_error(
                "package metadata policy_templates must be an array",
            ));
        }
    };

    let mut template_names = BTreeSet::new();
    let mut input_keys = BTreeSet::new();
    let mut legacy_streams = BTreeMap::new();
    let mut reduced_templates = Vec::with_capacity(templates.len());
    for template in templates {
        let template = template.as_object().ok_or_else(|| {
            recording_error("package metadata policy_templates entries must be objects")
        })?;
        let template_name = metadata_nonempty_string(template, "name", "policy template")?;
        if !template_names.insert(template_name.clone()) {
            return Err(recording_error(
                "package metadata contains duplicate policy template names",
            ));
        }
        let (data_streams, selected_datasets) = reduce_metadata_template_data_streams(
            template.get("data_streams"),
            &modern_datasets,
            &name,
        )?;
        let inputs = match template.get("inputs") {
            None => &[][..],
            Some(Value::Array(inputs)) => inputs.as_slice(),
            Some(_) => {
                return Err(recording_error(
                    "package metadata policy template inputs must be an array",
                ));
            }
        };
        let mut reduced_inputs = BTreeMap::new();
        for input in inputs {
            let input = input.as_object().ok_or_else(|| {
                recording_error("package metadata policy template inputs must be objects")
            })?;
            let input_type = metadata_nonempty_string(input, "type", "policy template input")?;
            let input_key = format!("{template_name}-{input_type}");
            if !input_keys.insert(input_key.clone()) {
                return Err(recording_error(
                    "package metadata contains duplicate template input definitions",
                ));
            }
            let input_vars =
                reduce_metadata_variables(input.get("vars"), "package metadata input vars")?;
            let streams = match input.get("streams") {
                None => &[][..],
                Some(Value::Array(streams)) => streams.as_slice(),
                Some(_) => {
                    return Err(recording_error(
                        "package metadata input streams must be an array",
                    ));
                }
            };
            let mut reduced_streams = BTreeMap::new();
            for stream in streams {
                let stream = stream.as_object().ok_or_else(|| {
                    recording_error("package metadata input streams must be objects")
                })?;
                let data_stream = stream
                    .get("data_stream")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        recording_error("package metadata stream data_stream must be an object")
                    })?;
                let dataset = metadata_nonempty_string(
                    data_stream,
                    "dataset",
                    "package metadata stream data_stream",
                )?;
                let stream_vars =
                    reduce_metadata_variables(stream.get("vars"), "package metadata stream vars")?;
                if reduced_streams
                    .insert(dataset.clone(), stream_vars.clone())
                    .is_some()
                    || legacy_streams
                        .insert((input_key.clone(), dataset), stream_vars)
                        .is_some()
                {
                    return Err(recording_error(
                        "package metadata contains duplicate legacy stream definitions",
                    ));
                }
            }
            if reduced_inputs
                .insert(
                    input_type,
                    ReducedMetadataInput {
                        key: input_key,
                        vars: input_vars,
                        streams: reduced_streams,
                    },
                )
                .is_some()
            {
                return Err(recording_error(
                    "package metadata contains duplicate policy template input types",
                ));
            }
        }
        reduced_templates.push(ReducedMetadataTemplate {
            name: template_name,
            data_streams,
            selected_datasets,
            inputs: reduced_inputs,
        });
    }
    reduced_templates.sort_by(|left, right| left.name.cmp(&right.name));

    let mut modern_streams = BTreeMap::new();
    for (dataset, streams) in &modern_datasets {
        for (input_type, stream_vars) in streams {
            let candidates = reduced_templates
                .iter()
                .filter(|template| template.selected_datasets.contains(dataset))
                .filter_map(|template| template.inputs.get(input_type))
                .map(|input| input.key.clone())
                .collect::<Vec<_>>();
            let input_key = match candidates.as_slice() {
                [input_key] => input_key.clone(),
                [] => {
                    return Err(recording_error(
                        "package metadata modern stream has no matching template input",
                    ));
                }
                _ => {
                    return Err(recording_error(
                        "package metadata modern stream has multiple matching template inputs",
                    ));
                }
            };
            if modern_streams
                .insert((input_key, dataset.clone()), stream_vars.clone())
                .is_some()
            {
                return Err(recording_error(
                    "package metadata contains duplicate modern stream definitions",
                ));
            }
        }
    }
    for (key, legacy_vars) in legacy_streams {
        match modern_streams.get(&key) {
            Some(modern_vars) if modern_vars != &legacy_vars => {
                return Err(recording_error(
                    "package metadata has conflicting modern and legacy stream definitions",
                ));
            }
            Some(_) => {}
            None => {
                modern_streams.insert(key, legacy_vars);
            }
        }
    }

    let policy_templates = Value::Array(
        reduced_templates
            .into_iter()
            .map(|template| {
                let inputs = Value::Array(
                    template
                        .inputs
                        .into_iter()
                        .map(|(input_type, input)| {
                            let streams = Value::Array(
                                input
                                    .streams
                                    .into_iter()
                                    .map(|(dataset, vars)| {
                                        json!({
                                            "data_stream": {"dataset": dataset},
                                            "vars": metadata_variables_value(&vars),
                                        })
                                    })
                                    .collect(),
                            );
                            json!({
                                "type": input_type,
                                "vars": metadata_variables_value(&input.vars),
                                "streams": streams,
                            })
                        })
                        .collect(),
                );
                let mut reduced = json!({"name": template.name, "inputs": inputs});
                if let Some(data_streams) = template.data_streams {
                    reduced
                        .as_object_mut()
                        .expect("reduced template is an object")
                        .insert(
                            "data_streams".into(),
                            Value::Array(data_streams.into_iter().map(Value::String).collect()),
                        );
                }
                reduced
            })
            .collect(),
    );
    let data_streams = Value::Array(
        modern_datasets
            .into_iter()
            .map(|(dataset, streams)| {
                let streams = Value::Array(
                    streams
                        .into_iter()
                        .map(|(input, vars)| {
                            json!({
                                "input": input,
                                "vars": metadata_variables_value(&vars),
                            })
                        })
                        .collect(),
                );
                json!({"dataset": dataset, "streams": streams})
            })
            .collect(),
    );

    Ok(json!({
        "item": {
            "name": name,
            "version": version,
            "status": status,
            "vars": metadata_variables_value(&vars),
            "policy_templates": policy_templates,
            "data_streams": data_streams,
        }
    }))
}

pub(crate) fn metadata_nonempty_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
    context: &str,
) -> elasticctl_core::Result<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| recording_error(format!("{context} {field} must be a non-empty string")))
}

fn reduce_metadata_variables(
    value: Option<&Value>,
    context: &str,
) -> elasticctl_core::Result<MetadataVariables> {
    let values = match value {
        None => return Ok(MetadataVariables::new()),
        Some(Value::Array(values)) => values,
        Some(_) => return Err(recording_error(format!("{context} must be an array"))),
    };
    let mut reduced = MetadataVariables::new();
    for value in values {
        let variable = value
            .as_object()
            .ok_or_else(|| recording_error(format!("{context} entries must be objects")))?;
        let name = metadata_nonempty_string(variable, "name", context)?;
        let secret = match variable.get("secret") {
            None => false,
            Some(Value::Bool(secret)) => *secret,
            Some(_) => {
                return Err(recording_error(format!(
                    "{context} secret must be a boolean"
                )));
            }
        };
        if reduced.insert(name, secret).is_some() {
            return Err(recording_error(format!(
                "{context} contains duplicate variable definitions"
            )));
        }
    }
    Ok(reduced)
}

fn metadata_variables_value(vars: &MetadataVariables) -> Value {
    Value::Array(
        vars.iter()
            .map(|(name, secret)| json!({"name": name, "secret": secret}))
            .collect(),
    )
}

fn reduce_metadata_data_streams(
    value: Option<&Value>,
) -> elasticctl_core::Result<BTreeMap<String, BTreeMap<String, MetadataVariables>>> {
    let data_streams = match value {
        None => &[][..],
        Some(Value::Array(data_streams)) => data_streams.as_slice(),
        Some(_) => {
            return Err(recording_error(
                "package metadata data_streams must be an array",
            ));
        }
    };
    let mut reduced = BTreeMap::new();
    for data_stream in data_streams {
        let data_stream = data_stream.as_object().ok_or_else(|| {
            recording_error("package metadata data_streams entries must be objects")
        })?;
        let dataset =
            metadata_nonempty_string(data_stream, "dataset", "package metadata data_stream")?;
        let streams = match data_stream.get("streams") {
            None => &[][..],
            Some(Value::Array(streams)) => streams.as_slice(),
            Some(_) => {
                return Err(recording_error(
                    "package metadata data_streams streams must be an array",
                ));
            }
        };
        let mut reduced_streams = BTreeMap::new();
        for stream in streams {
            let stream = stream.as_object().ok_or_else(|| {
                recording_error("package metadata data_streams streams entries must be objects")
            })?;
            let input =
                metadata_nonempty_string(stream, "input", "package metadata data_streams stream")?;
            let vars =
                reduce_metadata_variables(stream.get("vars"), "package metadata stream vars")?;
            if reduced_streams.insert(input, vars).is_some() {
                return Err(recording_error(
                    "package metadata data_streams contains duplicate stream inputs",
                ));
            }
        }
        if reduced.insert(dataset, reduced_streams).is_some() {
            return Err(recording_error(
                "package metadata contains duplicate data stream datasets",
            ));
        }
    }
    Ok(reduced)
}

fn reduce_metadata_template_data_streams(
    value: Option<&Value>,
    datasets: &BTreeMap<String, BTreeMap<String, MetadataVariables>>,
    package_name: &str,
) -> elasticctl_core::Result<(Option<Vec<String>>, BTreeSet<String>)> {
    let Some(value) = value else {
        return Ok((None, datasets.keys().cloned().collect()));
    };
    let selectors = value.as_array().ok_or_else(|| {
        recording_error("package metadata template data_streams must be an array")
    })?;
    let mut raw_selectors = BTreeSet::new();
    let mut selected_datasets = BTreeSet::new();
    for selector in selectors {
        let selector = selector
            .as_str()
            .filter(|selector| !selector.trim().is_empty())
            .ok_or_else(|| {
                recording_error(
                    "package metadata template data_streams selector must be a non-empty string",
                )
            })?;
        if !raw_selectors.insert(selector.to_owned()) {
            return Err(recording_error(
                "package metadata template contains duplicate data_streams selectors",
            ));
        }
        let short_name = format!("{package_name}.{selector}");
        let candidates = datasets
            .keys()
            .filter(|dataset| dataset.as_str() == selector || dataset.as_str() == short_name)
            .collect::<Vec<_>>();
        let dataset = match candidates.as_slice() {
            [dataset] => *dataset,
            [] => {
                return Err(recording_error(
                    "package metadata template data_streams selector does not match a dataset",
                ));
            }
            _ => {
                return Err(recording_error(
                    "package metadata template data_streams selector matches multiple datasets",
                ));
            }
        };
        if !selected_datasets.insert(dataset.clone()) {
            return Err(recording_error(
                "package metadata template contains duplicate selected data streams",
            ));
        }
    }
    Ok((Some(raw_selectors.into_iter().collect()), selected_datasets))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::test_support::integration_package_metadata_fixture;
    use serde_json::json;

    #[test]
    fn integration_package_reducer_keeps_only_the_secret_schema() {
        let raw = json!({
            "item": {
                "name": "system",
                "version": "2.0.0",
                "status": "installed",
                "vars": [{
                    "name": "package_token",
                    "secret": true,
                    "value": "package-secret-value",
                    "id": "private-variable-id"
                }],
                "policy_templates": [{
                    "name": "system",
                    "inputs": [{
                        "type": "system",
                        "vars": [{"name": "input_token", "secret": false, "value": "input-value"}],
                        "streams": [{
                            "data_stream": {"dataset": "system.cpu", "type": "logs"},
                            "vars": [{"name": "stream_token", "secret": true, "value": "stream-value"}],
                            "compiled_stream": {"private": true}
                        }],
                        "compiled_input": {"private": true}
                    }],
                    "assets": [{"id": "private-asset"}]
                }],
                "secret_references": [{"id": "private-secret-reference"}],
                "created_by": "private-user",
                "spaceIds": ["private-space"],
                "readme": "https://private.example/docs"
            },
            "metadata": {"private": true}
        });

        let reduced = reduce_integration_package_metadata(&raw, "system", "2.0.0")
            .expect("a complete package schema is reducible");

        assert_eq!(
            reduced,
            json!({
                "item": {
                    "name": "system",
                    "version": "2.0.0",
                    "status": "installed",
                    "vars": [{"name": "package_token", "secret": true}],
                    "policy_templates": [{
                        "name": "system",
                        "inputs": [{
                            "type": "system",
                            "vars": [{"name": "input_token", "secret": false}],
                            "streams": [{
                                "data_stream": {"dataset": "system.cpu"},
                                "vars": [{"name": "stream_token", "secret": true}]
                            }]
                        }]
                    }],
                    "data_streams": []
                }
            })
        );
        let encoded = reduced.to_string();
        for private in [
            "package-secret-value",
            "input-value",
            "stream-value",
            "private-secret-reference",
            "private-user",
            "private-space",
            "private.example",
        ] {
            assert!(!encoded.contains(private), "reducer leaked {private}");
        }

        for malformed in [
            json!({"item": {"name": "system", "version": "2.0.0", "status": "installed", "vars": {}, "policy_templates": []}}),
            json!({"item": {"name": "system", "version": "2.0.0", "status": "installed", "vars": [], "policy_templates": [{"name": "system", "inputs": [{"type": "", "vars": [], "streams": []}]}]}}),
            json!({"item": {"name": "system", "version": "2.0.0", "status": "installed", "vars": [], "policy_templates": [{"name": "system", "inputs": [{"type": "system", "vars": [], "streams": [{"data_stream": {"dataset": ""}, "vars": []}]}]}]}}),
            json!({"item": {"name": "system", "version": "2.0.0", "status": "installed", "vars": [{"name": "token", "secret": "true"}], "policy_templates": []}}),
        ] {
            let error = reduce_integration_package_metadata(&malformed, "system", "2.0.0")
                .expect_err("malformed package schema must not be recorded");
            assert!(
                !error.message.contains("private"),
                "reducer error must not expose raw metadata"
            );
        }
    }

    #[test]
    fn integration_package_reducer_records_bounded_measured_system_metadata() {
        // A bounded copy of the measured System 2.23.4 shape: package vars
        // are absent, all five measured input types are present, template
        // selectors distinguish absent from empty, and stream schemas live in
        // top-level data_streams rather than legacy input streams.
        let raw = json!({
            "item": {
                "name": "system",
                "version": "2.23.4",
                "status": "installed",
                "policy_templates": [
                    {
                        "name": "system",
                        "inputs": [
                            {"type": "winlog", "vars": [], "streams": []},
                            {"type": "metrics", "vars": [
                                {"name": "zebra", "value": "input-value"},
                                {"name": "alpha", "secret": true, "value": "private-input"}
                            ], "streams": []},
                            {"type": "system", "streams": []},
                            {"type": "logfile", "streams": []},
                            {"type": "journald", "vars": [], "streams": []}
                        ],
                        "assets": [{"id": "private-template-asset"}]
                    },
                    {
                        "name": "empty-selector",
                        "data_streams": [],
                        "inputs": []
                    }
                ],
                "data_streams": [
                    {
                        "dataset": "system.syslog",
                        "streams": [{"input": "logfile"}]
                    },
                    {
                        "dataset": "system.cpu",
                        "streams": [{
                            "input": "metrics",
                            "vars": [
                                {"name": "zeta", "value": "stream-value"},
                                {"name": "beta"}
                            ]
                        }]
                    }
                ],
                "secret_references": [{"id": "private-secret-reference"}],
                "created_by": "private-user",
                "spaceIds": ["private-space"],
                "readme": "https://private.example/docs"
            },
            "metadata": {"private": true}
        });

        let reduced = reduce_integration_package_metadata(&raw, "system", "2.23.4")
            .expect("the measured System shape is reducible");

        assert_eq!(
            reduced,
            json!({
                "item": {
                    "name": "system",
                    "version": "2.23.4",
                    "status": "installed",
                    "vars": [],
                    "policy_templates": [
                        {
                            "name": "empty-selector",
                            "data_streams": [],
                            "inputs": []
                        },
                        {
                            "name": "system",
                            "inputs": [
                                {"type": "journald", "vars": [], "streams": []},
                                {"type": "logfile", "vars": [], "streams": []},
                                {
                                    "type": "metrics",
                                    "vars": [
                                        {"name": "alpha", "secret": true},
                                        {"name": "zebra", "secret": false}
                                    ],
                                    "streams": []
                                },
                                {"type": "system", "vars": [], "streams": []},
                                {"type": "winlog", "vars": [], "streams": []}
                            ]
                        }
                    ],
                    "data_streams": [
                        {
                            "dataset": "system.cpu",
                            "streams": [{
                                "input": "metrics",
                                "vars": [
                                    {"name": "beta", "secret": false},
                                    {"name": "zeta", "secret": false}
                                ]
                            }]
                        },
                        {
                            "dataset": "system.syslog",
                            "streams": [{"input": "logfile", "vars": []}]
                        }
                    ]
                }
            })
        );

        let encoded = reduced.to_string();
        for private in [
            "input-value",
            "private-input",
            "stream-value",
            "private-template-asset",
            "private-secret-reference",
            "private-user",
            "private-space",
            "private.example",
        ] {
            assert!(!encoded.contains(private), "reducer leaked {private}");
        }
    }

    #[test]
    fn integration_package_reducer_preserves_azure_short_selectors() {
        let raw = json!({
            "item": {
                "name": "azure",
                "version": "1.40.0",
                "status": "installed",
                "vars": [],
                "policy_templates": [
                    {
                        "name": "audit",
                        "data_streams": ["audit"],
                        "inputs": [{"type": "azure", "streams": []}]
                    },
                    {
                        "name": "all",
                        "data_streams": ["audit", "activitylogs"],
                        "inputs": [{"type": "shared", "vars": [], "streams": []}]
                    },
                    {
                        "name": "activity",
                        "data_streams": ["activitylogs"],
                        "inputs": [{"type": "azure", "vars": [], "streams": []}]
                    }
                ],
                "data_streams": [
                    {
                        "dataset": "azure.audit",
                        "streams": [
                            {"input": "shared", "vars": []},
                            {"input": "azure", "vars": []}
                        ]
                    },
                    {
                        "dataset": "azure.activitylogs",
                        "streams": [
                            {"input": "shared", "vars": []},
                            {"input": "azure", "vars": []}
                        ]
                    }
                ]
            }
        });

        assert_eq!(
            reduce_integration_package_metadata(&raw, "azure", "1.40.0")
                .expect("short selectors resolve to full Azure datasets"),
            json!({
                "item": {
                    "name": "azure",
                    "version": "1.40.0",
                    "status": "installed",
                    "vars": [],
                    "policy_templates": [
                        {
                            "name": "activity",
                            "data_streams": ["activitylogs"],
                            "inputs": [{"type": "azure", "vars": [], "streams": []}]
                        },
                        {
                            "name": "all",
                            "data_streams": ["activitylogs", "audit"],
                            "inputs": [{"type": "shared", "vars": [], "streams": []}]
                        },
                        {
                            "name": "audit",
                            "data_streams": ["audit"],
                            "inputs": [{"type": "azure", "vars": [], "streams": []}]
                        }
                    ],
                    "data_streams": [
                        {
                            "dataset": "azure.activitylogs",
                            "streams": [
                                {"input": "azure", "vars": []},
                                {"input": "shared", "vars": []}
                            ]
                        },
                        {
                            "dataset": "azure.audit",
                            "streams": [
                                {"input": "azure", "vars": []},
                                {"input": "shared", "vars": []}
                            ]
                        }
                    ]
                }
            })
        );
    }

    #[test]
    fn integration_package_reducer_accepts_identical_modern_and_legacy_streams() {
        let raw = json!({
            "item": {
                "name": "package",
                "version": "1.0.0",
                "status": "installed",
                "policy_templates": [{
                    "name": "all",
                    "inputs": [{
                        "type": "input",
                        "streams": [{"data_stream": {"dataset": "package.dataset"}}]
                    }]
                }],
                "data_streams": [{
                    "dataset": "package.dataset",
                    "streams": [{"input": "input"}]
                }]
            }
        });

        assert_eq!(
            reduce_integration_package_metadata(&raw, "package", "1.0.0")
                .expect("identical modern and legacy schemas are compatible"),
            json!({
                "item": {
                    "name": "package",
                    "version": "1.0.0",
                    "status": "installed",
                    "vars": [],
                    "policy_templates": [{
                        "name": "all",
                        "inputs": [{
                            "type": "input",
                            "vars": [],
                            "streams": [{
                                "data_stream": {"dataset": "package.dataset"},
                                "vars": []
                            }]
                        }]
                    }],
                    "data_streams": [{
                        "dataset": "package.dataset",
                        "streams": [{"input": "input", "vars": []}]
                    }]
                }
            })
        );
    }

    #[test]
    fn integration_package_reducer_rejects_ambiguous_or_malformed_metadata() {
        let mut non_boolean_secret =
            integration_package_metadata_fixture("package", json!([]), json!([]));
        non_boolean_secret["item"]["vars"] = json!([{
            "name": "password",
            "secret": "not-a-boolean",
            "value": "must-not-leak"
        }]);

        let malformed = vec![
            (
                "duplicate template name",
                integration_package_metadata_fixture(
                    "package",
                    json!([
                        {"name": "same", "inputs": []},
                        {"name": "same", "inputs": []}
                    ]),
                    json!([]),
                ),
            ),
            (
                "duplicate composite input key",
                integration_package_metadata_fixture(
                    "package",
                    json!([
                        {"name": "a", "inputs": [{"type": "b-c", "vars": [], "streams": []}]},
                        {"name": "a-b", "inputs": [{"type": "c", "vars": [], "streams": []}]}
                    ]),
                    json!([]),
                ),
            ),
            (
                "duplicate dataset",
                integration_package_metadata_fixture(
                    "package",
                    json!([]),
                    json!([
                        {"dataset": "package.dataset", "streams": []},
                        {"dataset": "package.dataset", "streams": []}
                    ]),
                ),
            ),
            (
                "duplicate stream input",
                integration_package_metadata_fixture(
                    "package",
                    json!([{
                        "name": "all",
                        "inputs": [{"type": "input", "vars": [], "streams": []}]
                    }]),
                    json!([{
                        "dataset": "package.dataset",
                        "streams": [
                            {"input": "input", "vars": []},
                            {"input": "input", "vars": []}
                        ]
                    }]),
                ),
            ),
            (
                "duplicate legacy stream key",
                integration_package_metadata_fixture(
                    "package",
                    json!([{
                        "name": "all",
                        "inputs": [{
                            "type": "input",
                            "vars": [],
                            "streams": [
                                {"data_stream": {"dataset": "package.dataset"}, "vars": []},
                                {"data_stream": {"dataset": "package.dataset"}, "vars": []}
                            ]
                        }]
                    }]),
                    json!([]),
                ),
            ),
            (
                "raw and normalized duplicate selector",
                integration_package_metadata_fixture(
                    "azure",
                    json!([{
                        "name": "one",
                        "data_streams": ["audit", "azure.audit"],
                        "inputs": []
                    }]),
                    json!([{ "dataset": "azure.audit", "streams": [] }]),
                ),
            ),
            (
                "unresolved selector",
                integration_package_metadata_fixture(
                    "azure",
                    json!([{
                        "name": "one",
                        "data_streams": ["missing"],
                        "inputs": []
                    }]),
                    json!([{ "dataset": "azure.audit", "streams": [] }]),
                ),
            ),
            (
                "ambiguous selector",
                integration_package_metadata_fixture(
                    "azure",
                    json!([{
                        "name": "one",
                        "data_streams": ["audit"],
                        "inputs": []
                    }]),
                    json!([
                        {"dataset": "audit", "streams": []},
                        {"dataset": "azure.audit", "streams": []}
                    ]),
                ),
            ),
            (
                "stream with no matching input",
                integration_package_metadata_fixture(
                    "package",
                    json!([{
                        "name": "all",
                        "inputs": [{"type": "present", "vars": [], "streams": []}]
                    }]),
                    json!([{
                        "dataset": "package.dataset",
                        "streams": [{"input": "missing", "vars": []}]
                    }]),
                ),
            ),
            (
                "stream with multiple matching inputs",
                integration_package_metadata_fixture(
                    "package",
                    json!([
                        {"name": "first", "inputs": [{"type": "shared", "vars": [], "streams": []}]},
                        {"name": "second", "inputs": [{"type": "shared", "vars": [], "streams": []}]}
                    ]),
                    json!([{
                        "dataset": "package.dataset",
                        "streams": [{"input": "shared", "vars": []}]
                    }]),
                ),
            ),
            (
                "conflicting modern and legacy variables",
                integration_package_metadata_fixture(
                    "package",
                    json!([{
                        "name": "all",
                        "inputs": [{
                            "type": "input",
                            "vars": [],
                            "streams": [{
                                "data_stream": {"dataset": "package.dataset"},
                                "vars": [{"name": "token", "secret": true}]
                            }]
                        }]
                    }]),
                    json!([{
                        "dataset": "package.dataset",
                        "streams": [{
                            "input": "input",
                            "vars": [{"name": "token", "secret": false}]
                        }]
                    }]),
                ),
            ),
            ("non-boolean secret", non_boolean_secret),
        ];

        for (case, raw) in malformed {
            let error = reduce_integration_package_metadata(
                &raw,
                raw["item"]["name"].as_str().unwrap(),
                "1.0.0",
            )
            .expect_err("malformed metadata must not be recorded");
            assert!(
                !error.message.contains("must-not-leak"),
                "{case} leaked a variable value in its error"
            );
        }
    }
}
