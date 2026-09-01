//! Portable JSON and YAML sequence codecs.

use elasticctl_core::{Error, ErrorKind, Result};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::path::Path;

/// The portable content artifact format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentFormat {
    Json,
    Yaml,
}

impl ContentFormat {
    /// YAML is selected only by its conventional filename extensions.
    pub fn from_path(path: &Path) -> Self {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("yaml") | Some("yml") => Self::Yaml,
            _ => Self::Json,
        }
    }
}

/// Encode portable content as a reviewable sequence.
pub fn encode_sequence<T: Serialize>(values: &[T], format: ContentFormat) -> Result<String> {
    match format {
        ContentFormat::Json => serde_json::to_string_pretty(values)
            .map_err(|error| Error::new(ErrorKind::Error, format!("encoding JSON: {error}"))),
        ContentFormat::Yaml => serde_yaml_ng::to_string(values)
            .map_err(|error| Error::new(ErrorKind::Error, format!("encoding YAML: {error}"))),
    }
}

/// Decode a portable JSON or YAML sequence.
///
/// Callers decide whether an empty artifact is meaningful. Element failures
/// name both the content kind and the zero-based element index.
pub fn decode_sequence<T: DeserializeOwned>(
    body: &str,
    format: ContentFormat,
    item_name: &str,
) -> Result<Vec<T>> {
    let values: Vec<Value> = match format {
        ContentFormat::Json => serde_json::from_str(body).map_err(|error| {
            Error::new(
                ErrorKind::Error,
                format!("parsing JSON {item_name} sequence: {error}"),
            )
        })?,
        ContentFormat::Yaml => serde_yaml_ng::from_str(body).map_err(|error| {
            Error::new(
                ErrorKind::Error,
                format!("parsing YAML {item_name} sequence: {error}"),
            )
        })?,
    };

    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            serde_json::from_value(value).map_err(|error| {
                Error::new(
                    ErrorKind::Error,
                    format!("{item_name} at index {index}: {error}"),
                )
            })
        })
        .collect()
}
