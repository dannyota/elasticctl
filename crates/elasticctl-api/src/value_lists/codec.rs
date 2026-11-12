use std::path::Path;

use elasticctl_core::Result;
use serde_json::Value;

use super::address::rewrite_bare_range;
use super::{Container, LocalPair, ValueListType, ValueSet, canonical_value, invalid};

/// Read only the stable container keys, without YAML's string coercions.
pub fn decode_container(yaml: &str) -> Result<Container> {
    // The YAML value visitor also rejects duplicate mapping keys.
    let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(yaml)
        .map_err(|e| invalid(format!("invalid container YAML: {e}")))?;
    let value = serde_json::to_value(value)
        .map_err(|e| invalid(format!("invalid container object: {e}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("container must be an object"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "id" | "type" | "name" | "description" | "meta"
        ) {
            return Err(invalid(format!("unknown container key {key:?}")));
        }
    }
    for key in ["id", "type", "name", "description"] {
        if !object.get(key).is_some_and(Value::is_string) {
            return Err(invalid(format!(
                "container key {key:?} is required and must be a string"
            )));
        }
    }
    if object.get("meta").is_some_and(|meta| !meta.is_object()) {
        return Err(invalid("container key \"meta\" must be an object"));
    }
    serde_json::from_value(value).map_err(|e| invalid(format!("invalid container: {e}")))
}

pub fn encode_container(container: &Container) -> Result<String> {
    serde_yaml_ng::to_string(container).map_err(|e| invalid(format!("encode container: {e}")))
}

/// Process each physical line in order, preserving every readable spelling
/// except a bare `ip_range` address, which becomes a single-host CIDR.
pub fn decode_values(kind: &ValueListType, text: &str) -> Result<ValueSet> {
    kind.require_supported()?;
    let mut values = ValueSet::new();
    for (index, line) in text.split_terminator('\n').enumerate() {
        let value = line
            .strip_suffix('\r')
            .unwrap_or(line)
            .trim_matches([' ', '\t']);
        let fail = |message| invalid(format!("line {}: value {value:?}: {message}", index + 1));
        if value.is_empty() {
            return Err(fail("empty value".to_owned()));
        }
        if value.chars().any(char::is_control) {
            return Err(fail("control character".to_owned()));
        }
        canonical_value(kind, value).map_err(|e| fail(e.message))?;
        values.insert(rewrite_bare_range(kind, value));
    }
    Ok(values)
}

pub fn encode_values(values: &ValueSet) -> String {
    let mut text = String::new();
    for value in values {
        text.push_str(value);
        text.push('\n');
    }
    text
}

/// Read either half of a local `.yaml`/`.txt` pair. Refuse symlinks and
/// non-regular files, including the parent directory when it is a symlink.
pub fn read_pair(path: &Path) -> Result<LocalPair> {
    if !matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yaml" | "txt")
    ) {
        return Err(invalid("value-list pair path must end in .yaml or .txt"));
    }
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| invalid("value-list file stem must be UTF-8"))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|e| invalid(format!("read directory {}: {e}", parent.display())))?;
    if !metadata.is_dir() {
        return Err(invalid(format!(
            "{} must be a real directory",
            parent.display()
        )));
    }
    let read = |extension: &str| -> Result<Vec<u8>> {
        let file = path.with_extension(extension);
        let metadata = std::fs::symlink_metadata(&file)
            .map_err(|e| invalid(format!("read {}: {e}", file.display())))?;
        if !metadata.is_file() {
            return Err(invalid(format!(
                "{} must be a regular file",
                file.display()
            )));
        }
        std::fs::read(&file).map_err(|e| invalid(format!("read {}: {e}", file.display())))
    };
    let (yaml, values) = (read("yaml")?, read("txt")?);
    let result = super::validate_local_pair(stem, &yaml, Some(&values));
    match result.pair {
        Some(pair) => Ok(pair),
        None => Err(result
            .findings
            .refusals
            .into_iter()
            .next()
            .unwrap_or_else(|| invalid("invalid value-list pair"))),
    }
}
